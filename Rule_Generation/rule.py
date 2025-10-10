#!/usr/bin/env python3
import os
import json
import uuid
from datetime import datetime
from pymongo import MongoClient

# ---- CONFIG ----
MONGO_URI = "mongodb://localhost:27017"
ALERTS_DB = "Alerts"
CVSS_DB = "CVSS"
RULES_DIR = "rules_repository"

# Ensure rules directory exists
os.makedirs(RULES_DIR, exist_ok=True)

# Connect to MongoDB
client = MongoClient(MONGO_URI)
alerts_col = client[ALERTS_DB]["Alerts"]
cvss_col = client[CVSS_DB]["cvss"]

print("[DEBUG] Alerts collection:", alerts_col.name)
print("[DEBUG] CVSS collection:", cvss_col.name)

# Fetch alerts
alerts = list(alerts_col.find({}))
print("[DEBUG] Total alerts fetched:", len(alerts))

for alert in alerts:
    alert_id = str(alert.get("_id"))
    src_ip = alert.get("src_ip")
    alert_type = alert.get("alert_type")
    duration = alert.get("duration_sec", 0)

    # Skip if no src_ip or duration too small
    if not src_ip or duration == 0.02:
        continue

    # Match with CVSS using src_ip ↔ ip_address
    cvss_entry = cvss_col.find_one({
        "ip_address": src_ip,
        "attack_type": alert_type
    })

    if not cvss_entry:
        continue  # skip if no CVSS mapping

    cvss_score = float(cvss_entry.get("cvss_score", 0))
    priority = cvss_entry.get("priority", "N/A")

    # Skip if priority is Low (we only want Medium/High)
    if priority.lower() not in ["medium", "high"]:
        continue

    # Generate unique rule ID
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"

    # Rule JSON
    rule_json = {
        "rule_id": rule_id,
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_alert_id": alert_id,
        "signature": alert_type,
        "src_ip": src_ip,
        "dst_ip": alert.get("target_ip", "unknown"),
        "protocol": alert.get("protocol", "unknown"),
        "ports": alert.get("ports", []),
        "ports_scanned_count": alert.get("ports_scanned_count", 0),
        "duration": duration,
        "cvss_score": cvss_score,
        "priority": priority,
        "decision": {
            "action": "block_ip",
            "target": src_ip,
            "reason": f"{alert_type} detected with CVSS {cvss_score} ({priority})",
            "confidence": "high",
            "expiry_seconds": 86400
        },
        "suggested_commands": [
            f"iptables -I INPUT -s {src_ip} -j DROP  # temp block",
            f"netsh advfirewall firewall add rule name=\"Block_{src_ip}\" "
            f"dir=in action=block remoteip={src_ip}"
        ]
    }

    # Save JSON rule file
    rule_path = os.path.join(RULES_DIR, f"{rule_id}.json")
    with open(rule_path, "w") as f:
        json.dump(rule_json, f, indent=4)

    print(f"[+] Rule saved: {rule_path}")

