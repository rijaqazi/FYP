#!/usr/bin/env python3
import os, re, uuid, json

def extract_iocs_from_text(text):
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    mac_regex = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    domain_regex = r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
    url_regex = r"https?://[^\s]+"
    hash_regex = r"\b[a-fA-F0-9]{64}\b"

    return {
        "ip_addresses": re.findall(ip_regex, text),
        "mac_addresses": re.findall(mac_regex, text),
        "domains": re.findall(domain_regex, text),
        "urls": re.findall(url_regex, text),
        "hashes": re.findall(hash_regex, text)
    }

# Input folder = current directory (iocs/)
log_files = [f for f in os.listdir(".") if f.endswith(".log")]
os.makedirs("extracted_iocs", exist_ok=True)

for log_file in log_files:
    with open(log_file, "r") as f:
        text = f.read()

    ioc_data = extract_iocs_from_text(text)
    filename = f"extracted_iocs/{log_file}_{uuid.uuid4().hex[:8]}.json"
    with open(filename, "w") as f:
        json.dump(ioc_data, f, indent=2)

    print(f"✅ Extracted IOCs from {log_file} → {filename}")

print("🎯 All IOCs saved in 'extracted_iocs/' folder.")

