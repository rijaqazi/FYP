#!/usr/bin/env python3
from pymongo import MongoClient
from datetime import datetime
import time
import re


ATLAS_URI = "mongodb+srv://fatimazareen889_db_user:ccicCyFyFELe6mEt@threatsentinel.0cfaybg.mongodb.net/?appName=threatsentinel"


from pymongo import MongoClient
client = MongoClient(ATLAS_URI)



security_db = client["security_db"]  
alerts_db = client["Alerts"]         
ioc_db = client["ioc_database"]      
org_db = client["organization1-infosec"]  



security_ip_tracking = security_db["ip_tracking"]
security_heartbeat = security_db["heartbeat_logs"]


alerts_collection = alerts_db["Alerts"] 


cvss_db = client["CVSS"]  
cvss_collection = cvss_db["cvss"] if "CVSS" in client.list_database_names() else None

# Organization collections (organization1-infosec database से)
org_iocs = org_db["iocs"]
org_alerts = org_db["alerts"]
org_cvss = org_db["cvss"]

# IOC collection
ioc_collection = ioc_db["Indicator_of_Compromise"]


print("Available databases:", client.list_database_names())


def get_active_local_ips():
    #Return active local IPs only
    active_ips = []
    cursor = security_db.ip_tracking.find({"status": "active"})
    for doc in cursor:
        ip = doc.get("ip_address") or doc.get("local_ip")
        if ip:
            active_ips.append(ip)
    return active_ips


def get_all_alerts():
    possible_collections = ['alerts', 'Alerts', 'threats', 'alert', 'incidents']
    found_alerts = []
    for coll_name in possible_collections:
        if coll_name in alerts_db.list_collection_names():
            data = list(alerts_db[coll_name].find())
            if data:
                print(f"[+] Found {len(data)} alerts in '{coll_name}'")
                found_alerts.extend(data)
    return found_alerts


def get_all_cvss_entries():
    found_cvss = []
    if 'cvss' in cvss_db.list_collection_names():
        data = list(cvss_db['cvss'].find())
        if data:
            print(f"[+] Found {len(data)} CVSS entries in 'cvss'")
            found_cvss.extend(data)
    return found_cvss


def get_all_ioc_entries():
    """Get all IOC entries from ioc_database."""
    found_iocs = []
    if 'Indicator_of_Compromise' in ioc_db.list_collection_names():
        data = list(ioc_db['Indicator_of_Compromise'].find())
        if data:
            print(f"[+] Found {len(data)} IOC entries in 'Indicator_of_Compromise'")
            found_iocs.extend(data)
    return found_iocs


def extract_source_ip_from_raw_alert(raw_alert):
    if not raw_alert:
        return None
    match = re.search(r"\|?\s*from\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\|?", raw_alert)
    return match.group(1) if match else None


def extract_target_ip_from_raw_alert(raw_alert):
   
    if not raw_alert:
        return None
    match = re.search(r"\|?\s*Target_IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\|?", raw_alert)
    return match.group(1) if match else None


def save_alert_to_org(alert_doc):
    existing = org_db.alerts.find_one({"_id": alert_doc["_id"]})
    if not existing:
        org_db.alerts.insert_one(alert_doc)
        print(f"[+] ALERT SAVED → {alert_doc.get('alert_type', 'Unknown')} | Target: {alert_doc.get('target_ip', 'N/A')}")
    else:
        print(f"[-] ALERT SKIPPED (already exists) | {alert_doc.get('target_ip', 'N/A')}")


def save_cvss_to_org(cvss_doc):
    existing = org_db.cvss.find_one({"_id": cvss_doc["_id"]})
    if not existing:
        org_db.cvss.insert_one(cvss_doc)
        print(f"[+] CVSS SAVED → {cvss_doc.get('attack_type', 'Unknown')} | Source IP: {cvss_doc.get('source_ip', 'N/A')}, Target IP: {cvss_doc.get('target_ip', 'N/A')}")
    else:
        print(f"[-] CVSS SKIPPED (already exists) | {cvss_doc.get('source_ip', 'N/A')}")


def save_ioc_to_org(ioc_doc):
    existing = org_db.iocs.find_one({"_id": ioc_doc["_id"]})
    if not existing:
        org_db.iocs.insert_one(ioc_doc)
        print(f"[+] IOC SAVED → IP: {ioc_doc.get('ip_address', 'N/A')}")
    else:
        print(f"[-] IOC SKIPPED (already exists) | {ioc_doc.get('ip_address', 'N/A')}")


def match_and_transfer():
    active_ips = get_active_local_ips()
    print(f"\n Active Local IPs: {', '.join(active_ips) if active_ips else 'None'}")

    if not active_ips:
        print(" No active local IPs found. Retrying...")
        return

    found_alerts = get_all_alerts()
    found_cvss = get_all_cvss_entries()
    found_iocs = get_all_ioc_entries()

    matched_alerts_count = 0
    matched_cvss_count = 0
    matched_ioc_count = 0

   
    for alert in found_alerts:
        target_ip = alert.get("target_ip")  # Directly get target_ip from alert document
        if target_ip and target_ip in active_ips:
            save_alert_to_org(alert)
            matched_alerts_count += 1
            # Match and save IOC for the target IP
            for ioc in found_iocs:
                if ioc.get("ip_address") == target_ip:
                    save_ioc_to_org(ioc)
                    matched_ioc_count += 1
                    break

    for cvss in found_cvss:
        source_ip = cvss.get("source_ip")
        target_ip = cvss.get("target_ip") or extract_target_ip_from_raw_alert(cvss.get("raw_alert"))
        if target_ip and target_ip in active_ips:
            save_cvss_to_org(cvss)
            matched_cvss_count += 1
            for ioc in found_iocs:
                if ioc.get("ip_address") == source_ip:
                    save_ioc_to_org(ioc)
                    matched_ioc_count += 1
                    break

    print(f"\n [!] Summary of this cycle:")
    print(f"   • Alerts matched: {matched_alerts_count}")
    print(f"   • CVSS matched: {matched_cvss_count}")
    print(f"   • IOCs matched: {matched_ioc_count}")

def show_database_overview():
    print("\n" + "=" * 60)
    print(" DATABASE OVERVIEW")
    print("=" * 60)

    print("\n Security DB Collections:")
    for coll in security_db.list_collection_names():
        count = security_db[coll].count_documents({})
        print(f"   • {coll}: {count} docs")

    print("\n Alerts DB Collections:")
    for coll in alerts_db.list_collection_names():
        count = alerts_db[coll].count_documents({})
        print(f"   • {coll}: {count} docs")

    print("\n CVSS DB Collections:")
    for coll in cvss_db.list_collection_names():
        count = cvss_db[coll].count_documents({})
        print(f"   • {coll}: {count} docs")

    print("\n Organization DB Collections:")
    for coll in org_db.list_collection_names():
        count = org_db[coll].count_documents({})
        print(f"   • {coll}: {count} docs")

    print("\n IOC DB Collections:")
    for coll in ioc_db.list_collection_names():
        count = ioc_db[coll].count_documents({})
        print(f"   • {coll}: {count} docs")



if __name__ == "__main__":
    print("[+] Starting MatchAlert Agent for organization1-infosec...")
    show_database_overview()

    while True:
        try:
            match_and_transfer()
            print("\n Waiting 15 seconds before next scan...\n" + "-" * 60)
            time.sleep(15)
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(15)
