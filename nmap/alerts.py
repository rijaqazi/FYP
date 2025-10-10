from pymongo import MongoClient
import re

# MongoDB connect
client = MongoClient("mongodb://localhost:27017/")
db = client["Alerts"]
collection = db["nmap"]

with open("alerts.log", "r") as f:
    lines = f.readlines()

alerts = []
for line in lines:
    line = line.strip()
    if not line:
        continue

    alert_type = re.search(r"^(?:-|\[)?(.*?)\s+ALERT", line)
    src_ip = re.search(r"from\s+([\d\.]+)", line)
    target_ip = re.search(r"Target_IP:\s+([\d\.]+)", line)
    src_mac = re.search(r"SRC_MAC:\s+([\w:]+)", line)
    claimed_mac = re.search(r"Claimed_MAC:\s+([\w:]+)", line)
    prev_mac = re.search(r"Previous_MAC:\s+([\w:]+)", line)
    ports = re.search(r"Ports:\s+([\d,\s]*)", line)
    ports_scanned = re.search(r"Ports Scanned:\s+(\d+)", line)
    start_time = re.search(r"Start:\s+(.*?)\s+\|", line)
    duration = re.search(r"Duration:\s+([\d\.]+)s", line)

    alerts.append({
        "alert_type": alert_type.group(1).strip() if alert_type else None,
        "src_ip": src_ip.group(1) if src_ip else None,
        "target_ip": target_ip.group(1) if target_ip else None,
        "src_mac": src_mac.group(1) if src_mac else None,
        "claimed_mac": claimed_mac.group(1) if claimed_mac else None,
        "previous_mac": prev_mac.group(1) if prev_mac else None,
        "ports": [p.strip() for p in ports.group(1).split(",")] if ports and ports.group(1).strip() else [],
        "ports_scanned_count": int(ports_scanned.group(1)) if ports_scanned else None,
        "start_time": start_time.group(1) if start_time else None,
        "duration_sec": float(duration.group(1)) if duration else None
    })

if alerts:
    collection.insert_many(alerts)
    print(f"✅ Inserted {len(alerts)} structured alerts into MongoDB.")
else:
    print("⚠ No alerts found.")

