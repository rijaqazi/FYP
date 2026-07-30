#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import time
from datetime import datetime
import re


SERVER_URL = "http://127.0.0.1:5002/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"
USERNAME = "admin"
PASSWORD = "password123"
OUTPUT_DIR = "Indicator_of_Compromise"

def create_safe_filename(name):
    """Create safe filename from indicator name"""
    safe_name = re.sub(r'[^\w\s-]', '', name)   # remove special chars
    safe_name = re.sub(r'[-\s]+', '_', safe_name)  # replace spaces
    return safe_name[:50]   # limit length

def check_server_connection():
    """Check if TAXII server is running"""
    try:
        response = requests.get(
            SERVER_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={'Accept': 'application/taxii+json;version=2.1'},
            timeout=5
        )
        return response.status_code == 200
    except:
        return False

def get_existing_ioc_ids():
    """Get IDs of all IOCs already saved in the output folder"""
    existing_ids = set()
    if os.path.exists(OUTPUT_DIR):
        for filename in os.listdir(OUTPUT_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(OUTPUT_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        ioc_data = json.load(f)
                        ioc_id = ioc_data.get('id')
                        if ioc_id:
                            existing_ids.add(ioc_id)
                except:
                    continue
    return existing_ids

def pull_iocs():
    print(" Starting IOC Pull from TAXII Server...")
    print(f" Server: {SERVER_URL}")
    
    # Check if server is running
    if not check_server_connection():
        print("[x] TAXII server is not running or not accessible!")
        print(" Please start your TAXII server first:")
        print("   cd ~/Desktop/ioc && python3 taxii_server.py")
        return
    
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Get existing IOC IDs to avoid duplicates
        existing_ids = get_existing_ioc_ids()
        print(f"[!] Found {len(existing_ids)} existing IOCs in {OUTPUT_DIR}/")
        
        headers = {
            'Accept': 'application/taxii+json;version=2.1'
        }
        
        # Pull IOCs from server
        response = requests.get(
            SERVER_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            bundles = data.get('objects', [])
            
            success_count = 0
            skipped_count = 0
            indicator_count = 0
            
            for bundle in bundles:
                if bundle.get("type") == "bundle":
                    for ioc in bundle.get("objects", []):
                        if ioc.get('type') == 'indicator':
                            indicator_count += 1
                            ioc_id = ioc.get('id')
                            
                            # Skip if IOC already exists in output folder
                            if ioc_id in existing_ids:
                                skipped_count += 1
                                print(f"[>] Skipping duplicate IOC: {ioc_id}")
                                continue
                                
                            try:
                                # Generate filename
                                ioc_name = ioc.get('name', 'unknown_ioc')
                                short_id = ioc_id.replace('indicator--', '') if ioc_id else 'unknown_id'
                                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', ioc.get('pattern', ''))
                                ip_address = ip_match.group(0) if ip_match else 'unknown_ip'
                                
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                safe_name = create_safe_filename(ioc_name)
                                filename = f"IOC_{ip_address}_{safe_name}_{short_id}_{timestamp}.json"
                                filepath = os.path.join(OUTPUT_DIR, filename)
                                
                                with open(filepath, 'w') as f:
                                    json.dump(ioc, f, indent=2, ensure_ascii=False)
                                
                                print(f"[+] Saved: {filename}")
                                success_count += 1
                                
                                # Add to existing IDs to prevent duplicates in same run
                                if ioc_id:
                                    existing_ids.add(ioc_id)
                                
                            except Exception as e:
                                print(f"[x] Error saving IOC: {e}")
            
            print(f"\n📊 PULL SUMMARY:")
            print(f"   [total] Total indicators found: {indicator_count}")
            print(f"   [new] New IOCs saved: {success_count}")
            print(f"   [duplicate] Duplicates skipped: {skipped_count}")
            print(f"    Location: {OUTPUT_DIR}/")
                    
        else:
            print(f"[x] Failed to pull IOCs. Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"[x] Error: {e}")

def monitor_and_pull():
    """Continuously monitor and pull IOCs every 30 seconds"""
    print(" Starting continuous IOC pull monitor (every 30 seconds)...")
    print(" This will only save NEW IOCs, skipping existing ones.")
    
    while True:
        pull_iocs()
        print(" Waiting 30 seconds for next pull...")
        time.sleep(30)

if __name__ == "__main__":
    # You can choose between one-time pull or continuous monitoring
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        monitor_and_pull()
    else:
        pull_iocs()
