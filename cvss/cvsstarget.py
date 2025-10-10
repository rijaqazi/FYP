#!/usr/bin/env python3
import json
import re
from pathlib import Path

# ------------------------------
# CVSS v3.1 Vector Mapping
# ------------------------------
cvss_vectors = {
    # ARP Attacks
    "ARP_MITM": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ARP_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ARP_SPOOFING": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MAC_CONFLICT": "AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ARP_GRATUITOUS": "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L",
    "ARP_BROADCAST": "AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",

    # ICMP Attacks
    "ICMP_ECHO_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ICMP_TIMESTAMP_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
    "ICMP_ADDRESS_MASK_REQUEST_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    "ICMP_SMURF_ATTACK": "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",

    # Nmap Attacks
    "SYN_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "NULL_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "FIN_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "XMAS_SCAN": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "UDP_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "OS_FINGERPRINT": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "FULLPORT_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ACK_SCAN": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "SERVICE_PROBE": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",

    # Flood attacks
    "SPOOFED_SYN_FLOOD": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
}

# ------------------------------
# Attack Type Mapping
# ------------------------------
attack_mapping = {
    "ARP MITM": "ARP_MITM",
    "ARP FLOOD": "ARP_FLOOD",
    "ARP SPOOFING": "ARP_SPOOFING",
    "MAC CONFLICT": "MAC_CONFLICT",
    "GRATUITOUS_ARP": "ARP_GRATUITOUS",
    "BROADCAST_SPOOF": "ARP_BROADCAST",

    "ICMP ECHO REQUEST FLOOD": "ICMP_ECHO_REQUEST_FLOOD",
    "ICMP TIMESTAMP REQUEST FLOOD": "ICMP_TIMESTAMP_REQUEST_FLOOD",
    "ICMP ADDRESS MASK REQUEST FLOOD": "ICMP_ADDRESS_MASK_REQUEST_FLOOD",
    "SMURF ATTACK": "ICMP_SMURF_ATTACK",

    "SYN SCAN": "SYN_SCAN",
    "NULL SCAN": "NULL_SCAN",
    "FIN SCAN": "FIN_SCAN",
    "XMAS SCAN": "XMAS_SCAN",
    "UDP SCAN": "UDP_SCAN",
    "OS FINGERPRINT": "OS_FINGERPRINT",
    "FULL PORT SCAN": "FULLPORT_SCAN",
    "ACK SCAN": "ACK_SCAN",
    "SERVICE_PROBE": "SERVICE_PROBE",
    "SPOOFED_SYN_FLOOD": "SPOOFED_SYN_FLOOD",
}

# ------------------------------
# CVSS Score Calculator
# ------------------------------
def calculate_cvss_score(vector):
    metrics = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": {"U": 0.85, "C": 0.85}, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.5}},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 6.42, "C": 7.52},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0}
    }
    try:
        parts = dict([m.split(":") for m in vector.split("/")])
        iss = 1 - ((1 - metrics["C"][parts["C"]]) * (1 - metrics["I"][parts["I"]]) * (1 - metrics["A"][parts["A"]]))
        impact = metrics["S"][parts["S"]] * iss
        exploitab = 8.22 * metrics["AV"][parts["AV"]] * metrics["AC"][parts["AC"]] * metrics["PR"][parts["PR"]][parts["S"]] * metrics["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        if parts["S"] == "U":
            score = min(impact + exploitab, 10)
        else:
            score = min(1.08 * (impact + exploitab), 10)
        return round(score, 1)
    except Exception:
        return 0.0

# ------------------------------
# Priority Function
# ------------------------------
def get_priority(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "None"

# ------------------------------
# Process Log File (alerts.log)
# ------------------------------
def process_log_file(file_path):
    alerts = []
    with open(file_path, "r") as f:
        for line in f:
            match = re.search(
                r"\[ALERT\]\s+([A-Z0-9_ ]+)\s+from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*?(?:Target_IP:|to)\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|N/A)?",
                line, re.IGNORECASE
            )
            if match:
                raw_type = match.group(1).strip().upper()
                src_ip = match.group(2).strip()
                dst_ip = match.group(3).strip() if match.group(3) else src_ip

                # If Target_IP is N/A or same as src, try to extract it again from "Target_IP" field
                if dst_ip.upper() == "N/A" or dst_ip == src_ip:
                    m2 = re.search(r"Target_IP:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                    if m2:
                        dst_ip = m2.group(1).strip()

                mapped_type = attack_mapping.get(raw_type, raw_type)
                vector = cvss_vectors.get(mapped_type, None)
                score = calculate_cvss_score(vector) if vector else 0.0
                priority = get_priority(score)

                alerts.append({
                    "attack_type": mapped_type,
                    "cvss_vector": vector,
                    "cvss_score": score,
                    "priority": priority,
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "raw_alert": line.strip()
                })
    return alerts

# ------------------------------
# Main Execution
# ------------------------------
if __name__ == "__main__":
    path = Path("/home/rijaqazi/Desktop/detection/alerts.log")

    if not path.exists():
        print("-- File not found: alerts.log")
        exit()

    all_alerts = process_log_file(path)

    output_file = "classified_alerts.json"
    with open(output_file, "w") as f:
        json.dump(all_alerts, f, indent=4)

    print(f"\n✅ Processing complete! {len(all_alerts)} alerts saved to {output_file}\n")

