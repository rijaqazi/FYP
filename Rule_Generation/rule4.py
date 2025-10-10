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


# --------------------
# Decision logic
# --------------------
def decide_action(alert, cvss_entry):
    alert_type_orig = alert.get("alert_type", "") or ""
    norm_upper = alert_type_orig.upper()
    src_ip = alert.get("src_ip")
    src_mac = alert.get("src_mac", "N/A")

    # Default decision
    action, target, reason, confidence, expiry = "notify", src_ip, "Monitoring only", "low", 14400

    # ARP-based
    if "ARP" in norm_upper:
        if "SPOOF" in norm_upper or "MITM" in norm_upper:
            action, target, reason, confidence = "quarantine_mac", src_mac, "ARP spoofing / MITM detected", "high"
        elif "FLOOD" in norm_upper or "BROADCAST" in norm_upper:
            action, target, reason, confidence = "block_ip", src_ip, "ARP flood detected", "high"
        elif "GRATUITOUS" in norm_upper:
            action, target, reason, confidence = "notify", src_ip, "Gratuitous ARP detected", "medium"
        elif "MAC_CONFLICT" in norm_upper or "MAC DUPLICATE" in norm_upper:
            action, target, reason, confidence = "notify", src_ip, "MAC conflict / duplicate detected", "medium"
        else:
            action, target, reason, confidence = "notify", src_ip, "ARP anomaly detected", "medium"

    # ICMP-based
    elif "ICMP ADDRESS MASK" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Address Mask Request Flood", "high"
    elif "ICMP TIMESTAMP" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Timestamp Request Flood", "high"
    elif "ICMP ECHO" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Echo Request Flood", "high"
    elif "ICMP FRAGMENT" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Fragmentation Flood", "high"
    elif "SMURF" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP Smurf Attack detected", "high"
    elif "ICMP" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ICMP anomaly", "medium"

    # Nmap/recon scans
    elif "NULL_SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "NULL Scan detected", "medium"
    elif "FIN_SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "FIN Scan detected", "medium"
    elif "XMAS_SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "XMAS Scan detected", "medium"
    elif "SYN_SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "SYN Scan detected", "medium"
    elif "UDP_SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "UDP Scan detected", "medium"
    elif "FULL_PORT_SCAN" in norm_upper or "FULLPORT" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "Full Port Scan detected", "medium"
    elif "OS_FINGERPRINT" in norm_upper:
        action, target, reason, confidence = "notify", src_ip, "OS Fingerprinting detected", "medium"
    elif "ACK_SCAN" in norm_upper or "ACK-SCAN" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "ACK Scan detected", "medium"
    elif "SPOOFED_SYN_FLOOD" in norm_upper:
        action, target, reason, confidence = "block_ip", src_ip, "Spoofed SYN Flood detected", "high"

    return {
        "normalized_attack": alert_type_orig,
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

    entry = cvss_col.find_one({"source_ip": src_ip, "attack_type": alert_type})
    if entry:
        return entry

    alt1 = alert_type.replace(" ", "_")
    if alt1 != alert_type:
        entry = cvss_col.find_one({"source_ip": src_ip, "attack_type": alt1})
        if entry:
            return entry

    alt2 = alert_type.replace("_", " ")
    if alt2 != alert_type:
        entry = cvss_col.find_one({"source_ip": src_ip, "attack_type": alt2})
        if entry:
            return entry

    fallback = list(cvss_col.find({"source_ip": src_ip}))
    if fallback:
        return sorted(fallback, key=lambda x: float(x.get("cvss_score", 0)), reverse=True)[0]

    return None


# ---- Main ----
def main():
    client = MongoClient(MONGO_URI)
    alerts_col = client[ALERTS_DB]["Alerts"]
    cvss_col = client[CVSS_DB]["cvss"]

    alerts = list(alerts_col.find({}))
    print(f"[INFO] Total alerts fetched: {len(alerts)}")

    generated = 0
    skipped_no_cvss = 0
    skipped_fp = 0
    skipped_low_priority = 0
    skipped_duration_na = 0

    for alert in alerts:
        alert_id = str(alert.get("_id"))
        src_ip = alert.get("src_ip")
        alert_type = alert.get("alert_type") or ""
        duration_sec = alert.get("duration_sec", None)
        alert_upper = alert_type.upper()  # Added missing assignment

        # ✅ Skip if duration is null, None, or "N/A"
        if duration_sec in [None, "N/A", "null", "NULL"]:
            skipped_duration_na += 1
            continue

        # Skip false positives
        if not src_ip:
            skipped_fp += 1
            continue

        # Find CVSS entry
        cvss_entry = find_cvss_entry(cvss_col, src_ip, alert_type)
        if not cvss_entry:
            skipped_no_cvss += 1
            continue

        cvss_score = float(cvss_entry.get("cvss_score", 0))
        priority = (cvss_entry.get("priority", "None") or "").lower()

        # Decision making
        if priority in ["critical", "high", "medium"]:
            decision = decide_action(alert, cvss_entry)
        else:
            decision = {
                "normalized_attack": alert_type,
                "action": "notify",
                "target": src_ip,
                "reason": f"{alert_type} detected (low priority - monitoring)",
                "confidence": "low",
                "expiry_seconds": 14400
            }
            skipped_low_priority += 1

        # Generate unique rule ID
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"

        # Detect protocol
        protocol = alert.get("protocol")
        if not protocol or protocol == "unknown":
            at = alert_upper  # Use the defined alert_upper
            if "ARP" in at:
                protocol = "ARP"
            elif "ICMP" in at:
                protocol = "ICMP"
            elif "UDP" in at:
                protocol = "UDP"
            elif "FULL_PORT" in at:
                protocol = "TCP/UDP"
            elif any(x in at for x in ["SYN", "FIN", "NULL", "XMAS", "ACK", "RST", "SERVICE", "FINGERPRINT"]):
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
            "duration_": duration_sec,
            "cvss_score": cvss_score,
            "priority": cvss_entry.get("priority", "Unknown"),
            "decision": decision,
            "suggested_commands": [
                f"iptables -I INPUT -s {src_ip} -j DROP # temp block",
                f"netsh advfirewall firewall add rule name=\"Block_{src_ip}\" dir=in action=block remoteip={src_ip}"
            ]
        }

        # Save to file
        rule_path = os.path.join(RULES_DIR, f"{rule_id}.json")
        with open(rule_path, "w") as f:
            json.dump(rule_json, f, indent=4)

        generated += 1
        print(f"[+] Rule saved: {rule_path} ({alert_type}, priority={rule_json['priority']})")

    # ---- Summary ----
    print("---- Summary ----")
    print(f"Total alerts processed: {len(alerts)}")
    print(f"Rules generated: {generated}")
    print(f"Skipped - duration null/'N/A': {skipped_duration_na}")
    print(f"Skipped - false positives (no src_ip): {skipped_fp}")
    print(f"Skipped - no CVSS match: {skipped_no_cvss}")
    print(f"Skipped - low priority alerts: {skipped_low_priority}")


if __name__ == "__main__":
    main()
