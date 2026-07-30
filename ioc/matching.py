#!/usr/bin/env python3
import json
import os
import time
import uuid
import re
from collections import defaultdict


def load_whitelist(file="whitelist.json"):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {"ip_addresses": [], "mac_addresses": []}


def load_latest_iocs(iocs_file="extracted_iocs/latest_iocs.json"):
    if os.path.exists(iocs_file):
        with open(iocs_file, "r") as f:
            return json.load(f)
    return {"ip_addresses": [], "mac_addresses": [], "domains": [], "urls": [], "hashes": []}


def parse_alerts(log_file):
    alerts = []
    try:
        with open(log_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("[ALERT]"):
                    continue


                alert_type_match = re.search(r"\[ALERT\]\s+([^\s]+)", line)
                alert_type = alert_type_match.group(1) if alert_type_match else "Unknown"
                
                src_ip_match = re.search(r"from\s+([\d\.]+)", line)
                src_ip = src_ip_match.group(1) if src_ip_match else None
                
                target_ip_match = re.search(r"Target_IP:\s*([^\s|]+)", line)
                target_ip = target_ip_match.group(1) if target_ip_match else "N/A"
                
                ports_match = re.search(r"Ports:\s*([^\s|]+)", line)
                ports = ports_match.group(1) if ports_match else ""
                
                duration_match = re.search(r"Duration:\s*([^\s|]+)", line)
                duration = duration_match.group(1) if duration_match else "0"
                

                mac_match = re.search(r"SRC_MAC:\s*([^\s|]+)", line)
                src_mac = mac_match.group(1) if mac_match else None

                alerts.append({
                    "type": alert_type,
                    "src_ip": src_ip,
                    "target_ip": target_ip,
                    "src_mac": src_mac,
                    "details": {
                        "ports": ports,
                        "duration": duration,
                        "raw_log": line
                    }
                })
    except Exception as e:
        print(f"[x] Error parsing alerts: {e}")
    
    return alerts


def check_existing_bundle(ip, stix_folder="stix_output"):

    if not os.path.exists(stix_folder):
        return False
    
    ip_pattern = ip.replace('.', '_')
    for filename in os.listdir(stix_folder):
        if ip_pattern in filename and filename.endswith('.json'):
            return True
    return False


def generate_stix_bundles():

    DETECTION_FOLDER = "/home/defender/Desktop/new_detection"
    LOG_FILE = f"{DETECTION_FOLDER}/alerts.log"
    IOC_FILE = "extracted_iocs/latest_iocs.json"
    

    whitelist = load_whitelist("whitelist.json")
    iocs = load_latest_iocs(IOC_FILE)
    alerts = parse_alerts(LOG_FILE)
    
    if not alerts:
        print("[!] No alerts found to process")
        return
    

    matched = defaultdict(lambda: {"types": set(), "details": [], "macs": set()})
    
    for alert in alerts:
        ip = alert.get("src_ip", "")
        alert_type = alert.get("type", "Unknown")
        details = alert.get("details", {})
        src_mac = alert.get("src_mac")
        

        if ip in whitelist.get("ip_addresses", []):
            continue
        if src_mac and src_mac in whitelist.get("mac_addresses", []):
            continue
        

        if ip in iocs.get("ip_addresses", []):
            matched[ip]["types"].add(alert_type)
            matched[ip]["details"].append(details)
            

        if src_mac and src_mac != "N/A":
            matched[ip]["macs"].add(src_mac)
    
    # Create STIX bundles for new IPs only
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    os.makedirs("stix_output", exist_ok=True)
    new_bundles = 0
    
    for ip, info in matched.items():
        # Skip if bundle already exists
        if check_existing_bundle(ip):
            print(f"[>] Skipping existing STIX bundle for IP: {ip}")
            continue
        
        ports = set()
        total_duration = 0.0
        raw_logs = set()

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

        # Build pattern
        pattern = f"[ipv4-addr:value = '{ip}']"
        for mac in info["macs"]:
            pattern += f" AND [mac-addr:value = '{mac}']"

        # Create indicator with IP address field
        indicator = {
            "type": "indicator",
            "id": "indicator--" + str(uuid.uuid4()),
            "created": timestamp,
            "modified": timestamp,
            "name": "Malicious IP",
            "ip_address": ip,  
            "description": (
                f"Threats from {ip} | Ports: {', '.join(sorted(ports)) if ports else 'None'} | "
                f"Duration: {total_duration:.1f}s | "
                f"Raw Logs: {len(raw_logs)} entries attached"
            ),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": timestamp,
            "labels": ["malicious-activity"],
            "x_raw_logs": list(raw_logs)
        }

        # Create bundle
        bundle_id = "bundle--" + str(uuid.uuid4())
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "bundle_id": bundle_id,  
            "objects": [indicator]
        }

        # Create unique filename
        run_time = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        outname = f"stix_output/stix_bundle_{ip.replace('.', '_')}_{run_time}.json"

        with open(outname, "w") as f:
            json.dump(bundle, f, indent=4)
        
        new_bundles += 1
        print(f"[+] Created new STIX bundle for IP: {ip} → {outname}")
    
    if new_bundles == 0:
        print("[-] No new STIX bundles needed (all IPs already processed)")

def monitor_and_generate():
    """Continuously monitor for new alerts and generate STIX bundles"""
    print(" Monitoring for new alerts to generate STIX bundles every 30 seconds...")
    
    while True:
        generate_stix_bundles()
        time.sleep(30)

if __name__ == "__main__":
    monitor_and_generate()
