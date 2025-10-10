#!/usr/bin/env python3
# client_pull_iocs.py
import requests
from requests.auth import HTTPBasicAuth
import json
import os
from datetime import datetime
import re

# ---- CONFIG ----
SERVER_URL = "http://127.0.0.1:5000/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"
USERNAME = "admin"
PASSWORD = "password123"
OUTPUT_DIR = "Indicator_of_Compromise"

def create_safe_filename(name):
    """Create safe filename from indicator name"""
    safe_name = re.sub(r'[^\w\s-]', '', name)   # remove special chars
    safe_name = re.sub(r'[-\s]+', '_', safe_name)  # replace spaces
    return safe_name[:50]   # limit length

def pull_iocs():
    print("🚀 Starting IOC Pull from TAXII Server...")
    print(f"📡 Server: {SERVER_URL}")
    
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
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
            indicator_count = 0
            
            for bundle in bundles:
                if bundle.get("type") == "bundle":
                    for ioc in bundle.get("objects", []):
                        if ioc.get('type') == 'indicator':
                            indicator_count += 1
                            try:
                                # Generate filename
                                ioc_name = ioc.get('name', 'unknown_ioc')
                                ioc_id = ioc.get('id', 'unknown_id').replace('indicator--', '')
                                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', ioc.get('pattern', ''))
                                ip_address = ip_match.group(0) if ip_match else 'unknown_ip'
                                
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                safe_name = create_safe_filename(ioc_name)
                                filename = f"IOC_{ip_address}_{safe_name}_{ioc_id}_{timestamp}.json"
                                filepath = os.path.join(OUTPUT_DIR, filename)
                                
                                with open(filepath, 'w') as f:
                                    json.dump(ioc, f, indent=2, ensure_ascii=False)
                                
                                print(f"💾 Saved: {filename}")
                                success_count += 1
                                
                            except Exception as e:
                                print(f"❌ Error saving IOC: {e}")
            
            print(f"\n✅ Pulled {indicator_count} indicators, saved {success_count} files in {OUTPUT_DIR}")
                    
        else:
            print(f"❌ Failed to pull IOCs. Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    pull_iocs()

