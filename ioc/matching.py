#!/usr/bin/env python3
import json
import os
import time
import uuid
import re
from collections import defaultdict

# --- Load whitelist if available ---
def load_whitelist(file="whitelist.json"):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {"ip_addresses": [], "mac_addresses": []}


# --- Extract IOCs from .log files ---
def extract_iocs_from_logs(folder="."):
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    mac_regex = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"

    iocs = {"ip_addresses": set(), "mac_addresses": set()}
    log_files = [f for f in os.listdir(folder) if f.endswith(".log")]

    for log_file in log_files:
        with open(os.path.join(folder, log_file), "r") as f:
            text = f.read()
            iocs["ip_addresses"].update(re.findall(ip_regex, text))
            iocs["mac_addresses"].update(re.findall(mac_regex, text))

    return {k: list(v) for k, v in iocs.items()}


# --- Parse Alerts from .log files ---
def parse_alerts(folder="."):
    alerts = []
    log_files = [f for f in os.listdir(folder) if f.endswith(".log")]

    for log_file in log_files:
        with open(os.path.join(folder, log_file), "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Capture alert type correctly (e.g., ARP_MITM ALERT)
                alert_type_match = re.search(r"-\s+(\w+)\s+ALERT", line)
                alert_type = alert_type_match.group(1) if alert_type_match else "Unknown"

                src_ip = re.search(r"from\s+([\d\.]+)", line)
                ports = re.search(r"Ports:\s*([\d,\s]*)", line)
                duration = re.search(r"Duration:\s+([\d\.]+)s", line)

                alerts.append({
                    "type": alert_type,
                    "src_ip": src_ip.group(1) if src_ip else None,
                    "details": {
                        "ports": ports.group(1).strip() if ports else "",
                        "duration": duration.group(1) if duration else "0",
                        "raw_log": line  # 🟢 Raw log stored
                    }
                })
    return alerts


# --- Load data ---
whitelist = load_whitelist("whitelist.json")
iocs = extract_iocs_from_logs(".")
alerts = parse_alerts(".")

# --- Match IOCs and organize by IP ---
matched = defaultdict(lambda: {"types": set(), "details": [], "macs": set()})

for alert in alerts:
    ip = alert.get("src_ip", "")
    macs = iocs.get("mac_addresses", [])
    alert_type = alert.get("type", "Unknown")
    details = alert.get("details", {})

    # --- Whitelist check ---
    if ip in whitelist.get("ip_addresses", []):
        continue

    # Match by IP
    if ip in iocs.get("ip_addresses", []):
        matched[ip]["types"].add(alert_type)
        matched[ip]["details"].append(details)

    # Match by MAC address
    for mac in macs:
        if mac in str(details) and mac not in whitelist.get("mac_addresses", []):
            matched[ip]["macs"].add(mac)

# --- Create STIX bundles per IP ---
timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
os.makedirs("stix_output", exist_ok=True)

for ip, info in matched.items():
    ports = set()
    total_duration = 0.0
    raw_logs = set()  # 🟢 Dedup raw logs

    for d in info["details"]:
        if isinstance(d, dict):
            if d.get("ports"):
                ports.update([p.strip() for p in d.get("ports", "").split(",") if p.strip()])
            try:
                total_duration += float(d.get("duration", 0))
            except ValueError:
                pass
            if d.get("raw_log"):
                raw_logs.add(d["raw_log"])

    pattern = f"[ipv4-addr:value = '{ip}']"
    for mac in info["macs"]:
        pattern += f" AND [mac-addr:value = '{mac}']"

    indicator = {
        "type": "indicator",
        "id": "indicator--" + str(uuid.uuid4()),
        "created": timestamp,
        "modified": timestamp,
        "name": f"Malicious IP",   # 🟢 Name is now malicious IP
        "ip_address": ip,              # 🟢 New field for IP address
        "description": (
            f"Threats from {ip} | Ports: {', '.join(sorted(ports)) if ports else 'None'} "
            f"| Duration: {total_duration:.1f}s  "
            f"| Raw Logs: {len(raw_logs)} entries attached"
        ),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        # 🔥 YAHAN IMPORTANT CHANGE HAI - labels field add kiya
        "labels": ["malicious-activity"],  # 🟢 REQUIRED FIELD for STIX indicators
        "x_raw_logs": list(raw_logs)  # 🟢 Custom field with raw log evidence
    }

    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": [indicator]
    }

    # --- Make filename unique by adding timestamp ---
    run_time = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    outname = f"stix_output/stix_bundle_{ip.replace('.', '_')}_{run_time}.json"

    with open(outname, "w") as f:
        json.dump(bundle, f, indent=4)

print("✅ STIX Bundles generated per IP in: stix_output/ (Unique files each run)")
