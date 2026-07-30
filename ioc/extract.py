#!/usr/bin/env python3
import os
import re
import uuid
import json
import time
from pathlib import Path

def extract_iocs_from_text(text):
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    mac_regex = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    domain_regex = r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
    url_regex = r"https?://[^\s]+"
    hash_regex = r"\b[a-fA-F0-9]{64}\b"

    return {
        "ip_addresses": list(set(re.findall(ip_regex, text))),  # Remove duplicates
        "mac_addresses": list(set(re.findall(mac_regex, text))),
        "domains": list(set(re.findall(domain_regex, text))),
        "urls": list(set(re.findall(url_regex, text))),
        "hashes": list(set(re.findall(hash_regex, text)))
    }

def update_iocs_from_log(log_file, output_file):

    try:

        with open(log_file, "r") as f:
            text = f.read()
        

        new_iocs = extract_iocs_from_text(text)
        

        existing_iocs = {"ip_addresses": [], "mac_addresses": [], "domains": [], "urls": [], "hashes": []}
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                existing_iocs = json.load(f)
        

        merged_iocs = {}
        for key in new_iocs.keys():
            merged = list(set(existing_iocs.get(key, []) + new_iocs[key]))
            merged_iocs[key] = merged
        

        with open(output_file, "w") as f:
            json.dump(merged_iocs, f, indent=2)
        
        print(f"[+] Updated IOCs from {log_file} → {output_file}")
        return True
        
    except Exception as e:
        print(f"[x] Error processing {log_file}: {e}")
        return False

def monitor_alerts_log():

    DETECTION_FOLDER = "/home/defender/Desktop/new_detection"
    LOG_FILE = f"{DETECTION_FOLDER}/alerts.log"
    OUTPUT_FILE = "extracted_iocs/latest_iocs.json"
    

    os.makedirs("extracted_iocs", exist_ok=True)
    
    print(f"[!] Monitoring {LOG_FILE} for IOC extraction every 30 seconds...")
    last_modified = 0
    
    while True:
        try:
            if os.path.exists(LOG_FILE):
                current_modified = os.path.getmtime(LOG_FILE)
                

                if current_modified > last_modified:
                    update_iocs_from_log(LOG_FILE, OUTPUT_FILE)
                    last_modified = current_modified
                else:
                    print("[x] No changes in alerts.log")
            else:
                print(f"[!]  Log file not found: {LOG_FILE}")
                
        except Exception as e:
            print(f"[x] Monitoring error: {e}")
        
        time.sleep(30)

if __name__ == "__main__":
    monitor_alerts_log()
