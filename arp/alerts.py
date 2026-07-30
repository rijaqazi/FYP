from pymongo import MongoClient
import re, time

client = MongoClient("mongodb://localhost:27017/")
db = client["myDatabase"]
collection = db["Alerts2"]

with open("alerts_arp.log", "r") as f:
    lines = f.readlines()

alerts = []
for line in lines:
    line = line.strip()
    if not line:
        continue

    # --- Regex parsing (follow same sequence as log_alert) ---
    timestamp = re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    scan_type = re.search(r"\- (.*?) ALERT", line)
    src_ip = re.search(r"from\s+([\d\.]+)", line)
    src_mac = re.search(r"SRC_MAC:\s+([\w:]+|N/A)", line)
    target_ip = re.search(r"Target_IP:\s+([\d\.]+|N/A)", line)
    claimed_mac = re.search(r"Claimed_MAC:\s+([\w:]+|N/A)", line)
    previous_mac = re.search(r"Previous_MAC:\s+([\w:]+|N/A)", line)
    ports = re.search(r"Ports:\s+([\d,\s]*)", line)
    total_ports = re.search(r"Ports Scanned:\s+(\d+)", line)
    start_time = re.search(r"Start:\s+([\w:\- ]+)", line)
    duration = re.search(r"Duration:\s+([\d\.]+)s", line)

    alerts.append({
        "timestamp": timestamp.group(1) if timestamp else None,
        "type": scan_type.group(1) if scan_type else None,
        "src_ip": src_ip.group(1) if src_ip else None,
        "src_mac": src_mac.group(1) if src_mac else "N/A",
        "target_ip": target_ip.group(1) if target_ip else "N/A",
        "claimed_mac": claimed_mac.group(1) if claimed_mac else "N/A",
        "previous_mac": previous_mac.group(1) if previous_mac else "N/A",
        "ports": [p.strip() for p in ports.group(1).split(",")] if ports and ports.group(1) else [],
        "ports_scanned_count": int(total_ports.group(1)) if total_ports else 0,
        "start_time": start_time.group(1) if start_time else "N/A",
	"duration_sec": float(duration.group(1)) if duration else 0.0

    })

if alerts:
    collection.insert_many(alerts)
    print(f"✅ Inserted {len(alerts)} structured alerts into MongoDB with all fields.")
else:
    print("⚠ No alerts found.")

