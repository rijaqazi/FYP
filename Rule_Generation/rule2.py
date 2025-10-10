import os
import json
import uuid
import re
from datetime import datetime
from pymongo import MongoClient

# ---- CONFIG ----
MONGO_URI = "mongodb://localhost:27017"
ALERTS_DB = "Alerts"
CVSS_DB = "CVSS"
RULES_DIR = "rules_repository"

# Ensure rules directory exists
os.makedirs(RULES_DIR, exist_ok=True)


# ---- Decision logic (uses uppercased text for matching but preserves original alert_type) ----
def decide_action(alert, cvss_entry):
    alert_type_orig = alert.get("alert_type", "") or ""
    norm_attack_upper = alert_type_orig.upper()
    src_ip = alert.get("src_ip")
    src_mac = alert.get("src_mac", "N/A")

    # Default decision
    action, target, reason, confidence, expiry = "notify", src_ip, "Monitoring only", "low", 14400

    # ARP-based
    if "ARP" in norm_attack_upper:
        if "SPOOF" in norm_attack_upper or "MITM" in norm_attack_upper:
            action, target, reason, confidence = "quarantine_mac", src_mac, "ARP spoofing / MITM detected", "high"
        elif "FLOOD" in norm_attack_upper or "BROADCAST" in norm_attack_upper:
            action, target, reason, confidence = "block_ip", src_ip, "ARP flood detected", "high"
        else:
            action, target, reason, confidence = "notify", src_ip, "ARP anomaly detected", "medium"

    # ICMP-based
    elif "ICMP ADDRESS MASK" in norm_attack_upper or "ADDRESS MASK" in norm_attack_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Address Mask Request Flood", "high"
    elif "ICMP TIMESTAMP" in norm_attack_upper or "TIMESTAMP" in norm_attack_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Timestamp Request Flood", "high"
    elif "ICMP ECHO" in norm_attack_upper or "ECHO REQUEST" in norm_attack_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Echo Request Flood (Ping Flood)", "high"
    elif "ICMP FRAGMENT" in norm_attack_upper or "FRAGMENT" in norm_attack_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Fragmentation Flood", "high"
    elif "ICMP" in norm_attack_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP anomaly detected", "medium"

    # Nmap/recon scans
    elif any(x in norm_attack_upper for x in [
        "SYN SCAN", "NULL SCAN", "FIN SCAN", "XMAS SCAN", "ACK SCAN", "UDP SCAN",
        "FULL_PORT_SCAN", "FULL PORT", "FULLPORT", "ACK_SCAN", "ACK-SCAN", "ACKSCAN", "SCK SCAN"
    ]):
        action, target, reason, confidence = "block_ip", src_ip, f"{alert_type_orig} detected", "medium"

    elif any(x in norm_attack_upper for x in ["SERVICE PROBE", "OS FINGERPRINT", "OS-FINGERPRINT", "OS_FINGERPRINT"]):
        action, target, reason, confidence = "notify", src_ip, "Reconnaissance detected", "medium"

    # Floods
    elif any(x in norm_attack_upper for x in ["RST_FLOOD", "SPOOFED_SYN_FLOOD", "RST FLOOD", "SPOOFED SYN FLOOD"]):
        action, target, reason, confidence = "block_ip", src_ip, "Flood attack", "high"

    return {
        "normalized_attack": alert_type_orig,  # preserve original
        "action": action,
        "target": target,
        "reason": reason,
        "confidence": confidence,
        "expiry_seconds": expiry
    }


# ---- Helper: forgiving CVSS lookup ----
def find_cvss_entry(cvss_col, src_ip, alert_type):
    if not alert_type:
        return None

    # 1) exact match
    entry = cvss_col.find_one({"ip_address": src_ip, "attack_type": alert_type})
    if entry:
        return entry

    # 2) replace spaces <-> underscores
    alt1 = alert_type.replace(" ", "_")
    entry = cvss_col.find_one({"ip_address": src_ip, "attack_type": alt1})
    if entry:
        return entry

    alt2 = alert_type.replace("_", " ")
    entry = cvss_col.find_one({"ip_address": src_ip, "attack_type": alt2})
    if entry:
        return entry

    # 3) regex
    try:
        pat = re.compile(re.escape(alert_type), re.IGNORECASE)
        entry = cvss_col.find_one({"ip_address": src_ip, "attack_type": {"$regex": pat}})
        if entry:
            return entry
    except Exception:
        pass

    # 4) substring matching
    tokens = re.split(r"[\s,_-]+", alert_type)
    tokens = [t for t in tokens if t and len(t) > 1]
    for n in (3, 2, 1):
        if len(tokens) >= n:
            part = " ".join(tokens[:n])
            try:
                pat2 = re.compile(re.escape(part), re.IGNORECASE)
                entry = cvss_col.find_one({"ip_address": src_ip, "attack_type": {"$regex": pat2}})
                if entry:
                    return entry
            except Exception:
                pass

    # 5) fallback: pick highest cvss_score
    fallback = list(cvss_col.find({"ip_address": src_ip}))
    if fallback:
        fallback_sorted = sorted(fallback, key=lambda x: float(x.get("cvss_score", 0)), reverse=True)
        return fallback_sorted[0]

    return None


# ---- Connect to MongoDB ----
client = MongoClient(MONGO_URI)
alerts_col = client[ALERTS_DB]["Alerts"]
cvss_col = client[CVSS_DB]["cvss"]

print("[DEBUG] Alerts collection:", alerts_col.name)
print("[DEBUG] CVSS collection:", cvss_col.name)


# ---- Fetch alerts ----
alerts = list(alerts_col.find({}))
print("[DEBUG] Total alerts fetched:", len(alerts))

generated = 0
skipped_no_cvss = 0
skipped_low_priority = 0
skipped_fp = 0

for alert in alerts:
    alert_id = str(alert.get("_id"))
    src_ip = alert.get("src_ip")
    alert_type = alert.get("alert_type") or ""
    duration = alert.get("duration_sec", 0)

    # Skip false positives
    if not src_ip:
        skipped_fp += 1
        continue
    if duration in [0.0, 0.02]:
        skipped_fp += 1
        continue

    # Find CVSS entry
    cvss_entry = find_cvss_entry(cvss_col, src_ip, alert_type)
    if not cvss_entry:
        skipped_no_cvss += 1
        continue

    cvss_score = float(cvss_entry.get("cvss_score", 0))
    priority = cvss_entry.get("priority", "N/A")
    # ab "critical" bhi allow hoga
    if priority.lower() not in ["medium", "high", "critical"]:
        skipped_low_priority += 1
        continue


    # Generate unique rule ID
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"

    # Decide action
    decision = decide_action(alert, cvss_entry)

    # Protocol derivation
    protocol = alert.get("protocol")
    if not protocol or protocol == "unknown":
        at = (alert_type or "").upper()
        if "ARP" in at:
            protocol = "ARP"
        elif "ICMP" in at:
            protocol = "ICMP"
        elif "UDP" in at or "UDP SCAN" in at:
            protocol = "UDP"
        elif "FULL_PORT" in at or "FULL PORT" in at or "FULLPORT" in at:
            protocol = "TCP/UDP"
        elif any(x in at for x in [
            "SYN", "FIN", "NULL", "XMAS", "ACK", "RST", "SERVICE PROBE", "OS FINGERPRINT", "SCK"
        ]):
            protocol = "TCP"
        else:
            protocol = "unknown"

    # Build rule JSON
    rule_json = {
        "rule_id": rule_id,
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_alert_id": alert_id,
        "alert_type": alert_type,
        "src_ip": src_ip,
        "dst_ip": alert.get("target_ip", "unknown"),
        "protocol": protocol,
        "ports": alert.get("ports", []),
        "ports_scanned_count": alert.get("ports_scanned_count", 0),
        "duration": duration,
        "cvss_score": float(cvss_entry.get("cvss_score", 0)) if cvss_entry else None,
        "priority": cvss_entry.get("priority", "Unknown") if cvss_entry else "Unknown",
        "decision": {
            "action": decision["action"],
            "target": decision["target"],
            "reason": decision["reason"],
            "confidence": decision["confidence"],
            "expiry_seconds": decision["expiry_seconds"]
        },
        "suggested_commands": [
            f"iptables -I INPUT -s {src_ip} -j DROP # temp block",
            f"netsh advfirewall firewall add rule name=\"Block_{src_ip}\" dir=in action=block remoteip={src_ip}"
        ]
    }

    # Save rule JSON separately
    rule_path = os.path.join(RULES_DIR, f"{rule_id}.json")
    with open(rule_path, "w") as f:
        json.dump(rule_json, f, indent=4)

    generated += 1
    print(f"[+] Rule saved: {rule_path} ({alert_type}, priority={rule_json['priority']})")


# ---- Summary ----
print("---- Summary ----")
print(f"Total alerts processed: {len(alerts)}")
print(f"Rules generated: {generated}")
print(f"Skipped - false positives (no src/duration): {skipped_fp}")
print(f"Skipped - no CVSS match found: {skipped_no_cvss}")
print(f"Skipped - low priority: {skipped_low_priority}")

