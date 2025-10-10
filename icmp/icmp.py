#!/usr/bin/env python3
import json
import sys
import os
import time
import argparse
from collections import defaultdict

# === CONFIG ===
FLOOD_WINDOW = 5  # seconds
THRESHOLDS = {
    'echo_flood': 50,
    'smurf': 20,
    'timestamp_flood': 20,
    'mask_flood': 15,
    'fragment_flood': 10
}

# === ARGUMENT PARSING ===
parser = argparse.ArgumentParser(description="ICMP Flood/Attack Detector")
parser.add_argument("json_file", help="Path to Wireshark JSON export")
parser.add_argument("--log", dest="log_file", default="icmp_alerts.log", help="Path for alert logs")
parser.add_argument("--json-out", dest="json_output", default="icmp_alerts.json", help="JSON output file for alerts")
args = parser.parse_args()

LOG_FILE = args.log_file
JSON_FILE = args.json_output

# Track only one alert per (type, src_ip) per run
alerted_ips = set()
all_alerts = []  # store alerts for JSON

# === ALERT FUNCTION ===

def log_icmp_alert(alert_type, src_ip, description, times, dst_ip, src_mac):
    key = (alert_type, src_ip)
    if key in alerted_ips:
        return  # already alerted
    alerted_ips.add(key)

    start_time = time.ctime(min(times)) if times else "N/A"
    duration = max(times) - min(times) if len(times) > 1 else 0.0
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # <-- FIX

    # --- Consistent ICMP alert format (same as ARP/Nmap style) ---
    alert_str = (
        f"{timestamp} - {alert_type.upper()} ALERT from {src_ip} | "
        f"Target_IP: {dst_ip} | "
        f"SRC_MAC: {src_mac if src_mac else 'N/A'} | "
        f"Claimed_MAC: N/A | "
        f"Previous_MAC: N/A | "
        f"Ports:  | "
        f"Ports Scanned: 0 | "
        f"Start: {start_time} | "
        f"Duration: {duration:.1f}s"
    )

    # Console (red)
    print(f"\033[91m{alert_str}\033[0m")

    # Log to file
    with open(LOG_FILE, "a") as log_f:
        log_f.write(alert_str + "\n")

    # Save JSON (for structured analysis)
    all_alerts.append({
        "timestamp": timestamp,
        "type": alert_type,
        "source_ip": src_ip,
        "target_ip": dst_ip,
        "src_mac": src_mac if src_mac else "N/A",
        "claimed_mac": "N/A",
        "previous_mac": "N/A",
        "ports": "",
        "ports_scanned": 0,
        "start_time": start_time,
        "duration_seconds": round(duration, 1),
        "description": description
    })


# === LOAD FILE ===
if not os.path.exists(args.json_file):
    print(f"Error: File '{args.json_file}' not found.")
    sys.exit(1)

with open(args.json_file, "r") as f:
    try:
        packets = json.load(f)
    except json.JSONDecodeError:
        print("Invalid JSON format.")
        sys.exit(1)

# === TIME TRACKERS ===
times = {
    'echo_flood': defaultdict(list),
    'smurf': defaultdict(list),
    'timestamp_flood': defaultdict(list),
    'mask_flood': defaultdict(list),
    'fragment_flood': defaultdict(list)
}

# === PROCESS PACKETS ===
for pkt in packets:
    layers = pkt.get("_source", {}).get("layers", {})
    frame = layers.get("frame", {})
    ip_layer = layers.get("ip", {})
    icmp = layers.get("icmp", {})
    eth_layer = layers.get("eth", {})

    icmp_type = icmp.get("icmp.type", '')
    ts = float(frame.get("frame.time_epoch", 0))
    src_ip = ip_layer.get("ip.src", "")
    dst_ip = ip_layer.get("ip.dst", "")
    src_mac = eth_layer.get("eth.src", "N/A")

    if not src_ip or not ts:
        continue

    # ICMP Echo Request Flood
    if icmp_type == "8":
        times['echo_flood'][src_ip].append(ts)
        times['echo_flood'][src_ip] = [t for t in times['echo_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
        if len(times['echo_flood'][src_ip]) >= THRESHOLDS['echo_flood']:
             log_icmp_alert("ICMP Echo Request Flood", src_ip,
                      f"{len(times['echo_flood'][src_ip])} pings in {FLOOD_WINDOW}s",
                      times['echo_flood'][src_ip], dst_ip, src_mac)

    # Smurf Attack (ICMP Echo to broadcast)
    if icmp_type == "8" and dst_ip.endswith(".255"):
        times['smurf'][src_ip].append(ts)
        times['smurf'][src_ip] = [t for t in times['smurf'][src_ip] if ts - t <= FLOOD_WINDOW]
        if len(times['smurf'][src_ip]) >= THRESHOLDS['smurf']:
             log_icmp_alert("Smurf Attack", src_ip,
                      f"{len(times['smurf'][src_ip])} broadcasts in {FLOOD_WINDOW}s to {dst_ip}",
                      times['smurf'][src_ip], dst_ip, src_mac)

    # Timestamp Request Flood
    if icmp_type == "13":
        times['timestamp_flood'][src_ip].append(ts)
        times['timestamp_flood'][src_ip] = [t for t in times['timestamp_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
        if len(times['timestamp_flood'][src_ip]) >= THRESHOLDS['timestamp_flood']:
             log_icmp_alert("ICMP Timestamp Request Flood", src_ip,
                      f"{len(times['timestamp_flood'][src_ip])} in {FLOOD_WINDOW}s",
                      times['timestamp_flood'][src_ip], dst_ip, src_mac)

    # Address Mask Request Flood
    if icmp_type == "17":
        times['mask_flood'][src_ip].append(ts)
        times['mask_flood'][src_ip] = [t for t in times['mask_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
        if len(times['mask_flood'][src_ip]) >= THRESHOLDS['mask_flood']:
          log_icmp_alert("ICMP Address Mask Request Flood", src_ip,
                      f"{len(times['mask_flood'][src_ip])} in {FLOOD_WINDOW}s",
                      times['mask_flood'][src_ip], dst_ip, src_mac)

    # ICMP Fragmentation Flood
    ip_flags = ip_layer.get("ip.flags_tree", {})
    frag_offset = int(ip_layer.get("ip.frag_offset", '0'))
    more_frag = ip_flags.get("ip.flags.mf", '0')

    if icmp_type and (more_frag == '1' or frag_offset > 0):
        key = (src_ip, dst_ip)
        times['fragment_flood'][key].append(ts)
        times['fragment_flood'][key] = [t for t in times['fragment_flood'][key] if ts - t <= FLOOD_WINDOW]
        if len(times['fragment_flood'][key]) >= THRESHOLDS['fragment_flood']:
             log_icmp_alert("ICMP Fragmentation Flood", src_ip,
                      f"{len(times['fragment_flood'][key])} fragments to {dst_ip} in {FLOOD_WINDOW}s",
                      times['fragment_flood'][key], dst_ip, src_mac)

# === SAVE JSON ALERTS ===
if all_alerts:
    with open(JSON_FILE, "w") as jf:
        json.dump(all_alerts, jf, indent=4)

print("\nDetection complete.")
print(f"Alerts saved to {LOG_FILE} and {JSON_FILE}")

