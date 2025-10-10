#!/usr/bin/env python3
"""
ARP Attack Detector (Realistic & Unified Format)
- Detects: Spoofing, Gratuitous, Broadcast, Flood, MITM, Cache Override, MAC Conflict
- Alerts follow same format as Nmap detector
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict, deque

# --- Arguments ---
parser = argparse.ArgumentParser(description="ARP Attack Detector (Realistic)")
parser.add_argument("json_file", help="Path to Wireshark JSON export")
parser.add_argument("--log", dest="log_file", help="Path for alert logs")
parser.add_argument("--json-out", dest="json_output", help="JSON output file for alerts")
args = parser.parse_args()

# --- Validate input ---
if not os.path.exists(args.json_file):
    print(f"Error: File not found: {args.json_file}")
    sys.exit(1)

# --- Load packets ---
try:
    with open(args.json_file, "r") as f:
        packets = json.load(f)
except Exception as e:
    print(f"JSON Error: {str(e)}")
    sys.exit(1)

# --- Logging setup ---
logger = logging.getLogger("arp_detector")
logger.setLevel(logging.INFO)
if args.log_file:
    handler = logging.FileHandler(args.log_file)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(handler)

alerts = []
timestamps = defaultdict(list)
arp_table = {}             # IP -> MAC mapping
mac_to_ips = defaultdict(set)
alerted_set = set()
flood_window = defaultdict(lambda: deque(maxlen=20))  # sliding window of times

# --- Unified Alert Function ---
def log_alert(alert_type, src_ip, src_mac=None, start_time="N/A", duration=0,
              target_ip="", claimed_mac="", previous_mac=""):

    # Dedup
    unique_key = (alert_type, src_ip, target_ip, src_mac, claimed_mac, str(previous_mac))
    if unique_key in alerted_set:
        return
    alerted_set.add(unique_key)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Fixed order message
    message = f"- {alert_type.upper()} ALERT from {src_ip}"
    if target_ip:
        message += f" | Target_IP: {target_ip}"
    if src_mac:
        message += f" | SRC_MAC: {src_mac}"
    if claimed_mac:
        message += f" | Claimed_MAC: {claimed_mac}"
    if previous_mac:
        message += f" | Previous_MAC: {previous_mac}"

    message += f" | Ports: "
    message += f" | Ports Scanned: 0"
    message += f" | Start: {start_time}"
    message += f" | Duration: {int(duration)}s"

    # Console red
    print(f"\033[91m{message}\033[0m")

    # Log file
    logger.info(message)

    # Save JSON
    alerts.append({
        
        "type": alert_type,
        "src_ip": src_ip,
        "details": {
            "target_ip": target_ip,
            "src_mac": src_mac if src_mac else "",
            "claimed_mac": claimed_mac,
            "previous_mac": previous_mac,
            "ports": "",
            "total_ports": 0,
            "start_time": start_time,
            "duration": int(duration)
        }
    })

# --- Detection Logic ---
for packet in packets:
    try:
        layers = packet.get("_source", {}).get("layers", {})
        eth = layers.get("eth", {})
        arp = layers.get("arp", {})
        frame = layers.get("frame", {})

        src_mac = eth.get("eth.src", "")
        src_ip = arp.get("arp.src.proto_ipv4", "")
        dst_ip = arp.get("arp.dst.proto_ipv4", "")
        claimed_mac = arp.get("arp.dst.hw_mac", "")
        epoch = float(frame.get("frame.time_epoch", 0))

        if not src_ip:
            continue

        # Track timestamps
        if epoch:
            timestamps[src_ip].append(epoch)
            flood_window[src_ip].append(epoch)

        start_time = time.ctime(min(timestamps[src_ip])) if timestamps[src_ip] else "N/A"
        duration = (max(timestamps[src_ip]) - min(timestamps[src_ip])) if len(timestamps[src_ip]) > 1 else 0

        # --- ARP Spoof ---
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            log_alert("ARP_SPOOF", src_ip, src_mac, start_time, duration,
                      target_ip=dst_ip, claimed_mac=claimed_mac, previous_mac=arp_table[src_ip])

        # --- Gratuitous ARP ---
        if src_ip == dst_ip and claimed_mac:
            log_alert("GRATUITOUS_ARP", src_ip, src_mac, start_time, duration,
                      target_ip=dst_ip, claimed_mac=claimed_mac)

        # --- Broadcast Spoof ---
        if claimed_mac.lower() == "ff:ff:ff:ff:ff:ff" or dst_ip == "255.255.255.255":
            log_alert("BROADCAST_SPOOF", src_ip, src_mac, start_time, duration,
                      target_ip=dst_ip, claimed_mac=claimed_mac)

        # --- ARP Flood ---
        if len(flood_window[src_ip]) >= 5:  # at least 5 packets
            if flood_window[src_ip][-1] - flood_window[src_ip][0] < 3:  # within 3s
                log_alert("ARP_FLOOD", src_ip, src_mac, start_time, duration,
                          target_ip=dst_ip)

        # --- MAC Conflict ---
        if src_mac:
            mac_to_ips[src_mac].add(src_ip)
            if len(mac_to_ips[src_mac]) > 1:
                log_alert("MAC_CONFLICT", src_ip, src_mac, start_time, duration,
                          target_ip=dst_ip, claimed_mac=claimed_mac)

        # --- Cache Override / MITM ---
        if src_ip == dst_ip and arp_table.get(dst_ip) and arp_table[dst_ip] != src_mac:
            log_alert("CACHE_OVERRIDE", src_ip, src_mac, start_time, duration,
                      target_ip=dst_ip, claimed_mac=claimed_mac, previous_mac=arp_table[dst_ip])

        if dst_ip in arp_table and arp_table[dst_ip] != src_mac:
            log_alert("ARP_MITM", src_ip, src_mac, start_time, duration,
                      target_ip=dst_ip, claimed_mac=claimed_mac, previous_mac=arp_table[dst_ip])

        # Update table
        if src_ip not in arp_table:
            arp_table[src_ip] = src_mac

    except Exception as e:
        logger.error(f"Processing error: {str(e)}")

# --- Save JSON ---
if args.json_output:
    try:
        with open(args.json_output, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"\nAlerts saved to {args.json_output}")
    except Exception as e:
        logger.error(f"Failed to save JSON: {str(e)}")

print("\nARP analysis complete. Detected Threats Logged")
print(f"  Total Alerts: {len(alerts)}")

