#!/usr/bin/env python3
import os
import json
import requests
import time
from requests.auth import HTTPBasicAuth



PRIMARY_API_URL = "http://127.0.0.1:5002/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"


TAXII_API_URL = "http://127.0.0.1:5002/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects"

USERNAME = "admin"
PASSWORD = "password123"
BUNDLES_DIR = "/home/defender/Desktop/ioc/stix_output/"


uploaded_files = set()


def load_uploaded_files():
    """Load already uploaded files from a local state file"""
    global uploaded_files
    state_file = os.path.join(BUNDLES_DIR, ".uploaded_files.txt")
    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                uploaded_files = set(line.strip() for line in f if line.strip())
            print(f" Loaded {len(uploaded_files)} previously uploaded files")
    except Exception as e:
        print(f"  Error loading uploaded files state: {e}")
        uploaded_files = set()


def save_uploaded_files():
    """Save uploaded files state"""
    state_file = os.path.join(BUNDLES_DIR, ".uploaded_files.txt")
    try:
        with open(state_file, "w") as f:
            for filename in uploaded_files:
                f.write(filename + "\n")
    except Exception as e:
        print(f"  Error saving uploaded files state: {e}")


def send_bundle(bundle_data):
    """
    Try uploading to PRIMARY (old endpoint).
    If that fails, try the new TAXII 2.1 endpoint.
    """
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/taxii+json;version=2.1'
    }

    # ---- Try OLD ENDPOINT first ----
    try:
        response = requests.post(
            PRIMARY_API_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            json=bundle_data,
            headers=headers,
            timeout=10
        )
        if response.status_code in [200, 202]:
            return True, response
        else:
            print(f"   [!] Primary endpoint rejected: {response.status_code}")
    except Exception as e:
        print(f"   [!] Primary endpoint error: {e}")

   
    try:
        print("   [>] Trying TAXII 2.1 endpoint...")
        response = requests.post(
            TAXII_API_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            json=bundle_data,
            headers=headers,
            timeout=10
        )
        if response.status_code in [200, 202]:
            return True, response
        else:
            return False, response
    except Exception as e:
        return False, str(e)


def upload_bundles():
    """Upload new STIX bundles to TAXII server"""
    global uploaded_files

    uploaded_count = 0
    failed_count = 0

    os.makedirs(BUNDLES_DIR, exist_ok=True)

    all_files = [f for f in os.listdir(BUNDLES_DIR) if f.endswith(".json")]

    for file_name in sorted(all_files):

        if file_name in uploaded_files:
            continue

        file_path = os.path.join(BUNDLES_DIR, file_name)
        print(f"\n[!] Uploading {file_name} ...")

        try:
            with open(file_path, "r") as f:
                bundle_data = json.load(f)

            # Ensure minimal compliance for indicators
            for obj in bundle_data.get("objects", []):
                if obj.get("type") == "indicator":
                    obj.setdefault("labels", ["malicious-activity"])
                    obj.setdefault("pattern_type", "stix")

            success, response = send_bundle(bundle_data)

            if success:
                print(f"   [+] Upload successful! Status: {response.status_code}")
                uploaded_files.add(file_name)
                uploaded_count += 1
            else:
                print(f"   [x] Upload failed: {response}")
                failed_count += 1

        except Exception as e:
            print(f"   [x] Upload failed: {e}")
            failed_count += 1

    if uploaded_count > 0:
        save_uploaded_files()

    return uploaded_count, failed_count


def monitor_and_upload():
    print(" Monitoring for new STIX bundles every 30 seconds...")
    print(f" Watching folder: {BUNDLES_DIR}")
    print(f" Primary Server: {PRIMARY_API_URL}")
    print(f" TAXII 2.1 Fallback: {TAXII_API_URL}")

    load_uploaded_files()

    while True:
        try:
            uploaded_count, failed_count = upload_bundles()

            if uploaded_count > 0 or failed_count > 0:
                print("\n==================================================")
                print("[UPLOAD SUMMARY]")
                print(f"   [+] Successful: {uploaded_count}")
                print(f"   [x] Failed: {failed_count}")
                print("==================================================")
            else:
                print("[!] No new STIX bundles found to upload")

        except Exception as e:
            print(f"[x] Error: {e}")

        print("Waiting 30 seconds for next check...")
        time.sleep(30)


if __name__ == "__main__":
    monitor_and_upload()
