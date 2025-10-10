#!/usr/bin/env python3
import os
import json
import requests
from requests.auth import HTTPBasicAuth

# ---- CONFIG ----
API_URL = "http://127.0.0.1:5000/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"
USERNAME = "admin"
PASSWORD = "password123"
BUNDLES_DIR = "/home/rijaqazi/Desktop/ioc/stix_output/"

# ---- Upload function ----
def upload_bundles():
    uploaded_count = 0
    failed_count = 0
    
    for file_name in sorted(os.listdir(BUNDLES_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(BUNDLES_DIR, file_name)
            print(f"\n📤 Uploading {file_name} ...")

            try:
                with open(file_path, "r") as f:
                    bundle_data = json.load(f)

                # Ensure indicator has required fields
                for obj in bundle_data.get("objects", []):
                    if obj.get("type") == "indicator":
                        obj.setdefault("labels", ["malicious-activity"])
                        obj.setdefault("pattern_type", "stix")

                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/taxii+json;version=2.1'
                }
                
                response = requests.post(
                    API_URL,
                    auth=HTTPBasicAuth(USERNAME, PASSWORD),
                    json=bundle_data,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code in [200, 202]:
                    print(f"   ✅ Upload successful! Status: {response.status_code}")
                    uploaded_count += 1
                else:
                    print(f"   ❌ Upload failed: {response.status_code} - {response.text}")
                    failed_count += 1

            except Exception as e:
                print(f"   ❌ Upload failed: {e}")
                failed_count += 1

    # ---- Summary only ----
    print(f"\n{'='*50}")
    print("📊 UPLOAD SUMMARY:")
    print(f"   ✅ Successful: {uploaded_count}")
    print(f"   ❌ Failed: {failed_count}")
    print(f"{'='*50}")

if __name__ == "__main__":
    upload_bundles()

