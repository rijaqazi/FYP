#!/usr/bin/env python3
"""
rule_sharing.py

Scan local reports/zip and extracted_rules_zip for .zip files and upload them to secure Flask server.
Does deduplication by comparing filename + sha256 with server /discover output for reports/zip.
For extracted_rules_zip, removes existing file on server and uploads regardless of session or server state.
All done in Python (requests).
"""

import os
import sys
import hashlib
import getpass
import argparse
import requests
import time
from requests.auth import HTTPBasicAuth
import re


DEFAULT_REPORTS_DIR = os.path.abspath("reports/zip")
DEFAULT_EXTRACTED_RULES_DIR = os.path.abspath("extracted_rules_zip")
DEFAULT_SERVER = "http://127.0.1.1:5005"
CHECK_INTERVAL = 30  # Check every 30 seconds


uploaded_files = set()

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def fetch_remote_index(server_url, auth):
    url = server_url.rstrip("/") + "/discover"
    r = requests.get(url, auth=auth, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to call discover: {r.status_code} {r.text}")
    j = r.json()
    if j.get("status") != "ok":
        raise RuntimeError(f"Discover returned error: {j}")
   
    idx = {}
    print(f"[DEBUG] Server files: {', '.join(f['filename'] for f in j.get('files', []))}")
    for item in j.get("files", []):
        idx[item["filename"]] = item.get("sha256")
    return idx

def remove_file_from_server(server_url, auth, filename):
    url = server_url.rstrip("/") + f"/delete/{filename}"
    print(f"[REMOVE] Attempting to remove {filename} from server...")
    r = requests.delete(url, auth=auth, timeout=10)
 
    if r.status_code == 200:
        print(f"[REMOVE] Successfully removed {filename} from server")
        return True

    return False


def upload_file(server_url, auth, local_path):
    url = server_url.rstrip("/") + "/upload"
    with open(local_path, "rb") as fh:
        files = {"file": (os.path.basename(local_path), fh)}
        r = requests.post(url, files=files, auth=auth, timeout=30)
    return r

def load_uploaded_files():
    """Load already uploaded files from local tracking (only for reports/zip)"""
    global uploaded_files
    uploaded_files = set()

def upload_new_files(reports_dir, extracted_rules_dir, server_url, auth, dry_run=False):
    """Upload new files; remove and upload for extracted_rules_zip regardless of state"""
   
    if not os.path.exists(reports_dir):
        print(f"[x] Reports directory not found: {reports_dir}")
        return []
    if not os.path.exists(extracted_rules_dir):
        print(f"[x] Extracted rules directory not found: {extracted_rules_dir}")
        return []

    print("[*] Fetching remote index...")
    try:
        remote_index = fetch_remote_index(server_url, auth)
    except Exception as e:
        print(f"[x] Could not fetch remote index: {e}")
        return []

    print(f"[length] Remote server has {len(remote_index)} files already")
   
    # Find all zip files in both directories
    to_upload = []
    for root_dir, dir_name in [(reports_dir, "reports"), (extracted_rules_dir, "extracted_rules")]:
        for root, _, files in os.walk(root_dir):
            for f in files:
                if not f.lower().endswith(".zip"):
                    continue
               
                local_path = os.path.join(root, f)
                local_sha = sha256_file(local_path)
               
                # Handle deduplication only for reports/zip
                if dir_name == "reports":
                    if f in uploaded_files:
                        print(f"[!] {f} (already uploaded in this session)")
                        continue
                    # Check all server filenames for a match, not just exact name
                    for server_file, server_sha in remote_index.items():
                        if f in server_file and server_sha == local_sha:
                            print(f"[!] {f} (already on server as {server_file})")
                            uploaded_files.add(f)
                            break
                    else:
                        to_upload.append((local_path, f, local_sha, False))
                else:  # extracted_rules_zip
                    # For extracted rules, check if this exact file exists on server with same SHA
                    exact_match = f in remote_index and remote_index[f] == local_sha
                    if exact_match:
                        print(f"[!] {f} (already on server with same content)")
                        continue
                   
                    # Check for any variants of this file (with different numbering)
                    has_variant = False
                    for server_file, server_sha in remote_index.items():
                        # Extract base name without extensions and numbering
                        base_name = f.replace('.zip', '')
                        server_base = server_file.replace('.zip', '')
                       
                        # Check if this is a variant of the same rule file
                        # Remove trailing -number patterns for comparison
                        base_clean = re.sub(r'-\d+$', '', base_name)
                        server_clean = re.sub(r'-\d+$', '', server_base)
                       
                        if base_clean == server_clean and server_sha == local_sha:
                            print(f"[!] {f} (variant already on server as {server_file})")
                            has_variant = True
                            break
                   
                    if not has_variant:
                        to_upload.append((local_path, f, local_sha, True))

    if not to_upload:
        print("[- ] No new files to upload")
        return []

    print(f"[+] Found {len(to_upload)} new file(s) to upload")
   
    uploaded_results = []
    for local_path, fname, sha, is_extracted_rule in to_upload:
        print(f"[Processing] Processing {fname} (sha={sha[:8]}...)")
       
        if dry_run:
            print("   (dry-run)")
            if not is_extracted_rule:
                uploaded_files.add(fname)
            uploaded_results.append({"file": fname, "status": "dry_run"})
            continue
           
        try:
            if is_extracted_rule:
                # Remove existing variants of this file from server
                base_name = fname.replace('.zip', '')
                base_clean = re.sub(r'-\d+$', '', base_name)
                files_to_remove = []
               
                for server_file in remote_index.keys():
                    server_base = server_file.replace('.zip', '')
                    server_clean = re.sub(r'-\d+$', '', server_base)
                   
                    # Check if this server file is a variant of our current file
                    if base_clean == server_clean:
                        files_to_remove.append(server_file)
               
                # Remove all variants that actually exist
                removed_count = 0
                for server_file in files_to_remove:
                    if remove_file_from_server(server_url, auth, server_file):
                        removed_count += 1
               
                if removed_count > 0:
                    print(f"   [x] Removed {removed_count} variant(s)")
           
            r = upload_file(server_url, auth, local_path)
        except Exception as e:
            print(f"   [x] FAILED: {e}")
            continue
           
        try:
            jr = r.json()
        except Exception:
            jr = {"status": "error", "text": r.text}
           
        if r.status_code in (200, 201):
            print("   [+] SUCCESS")
            if not is_extracted_rule:
                uploaded_files.add(fname)  # Track only reports/zip uploads
            uploaded_results.append({"file": fname, "status": "success", "response": jr})
        else:
            print(f"   [x] FAILED: {r.status_code} {jr}")
            uploaded_results.append({"file": fname, "status": "failed", "response": jr})

    return uploaded_results
def monitor_and_upload(reports_dir, extracted_rules_dir, server_url, auth, dry_run=False):
    """Continuously monitor for new zip files in both directories and upload them"""
    print("[start] Starting continuous upload monitoring...")
    print(f"[watch] Watching: {reports_dir}")
    print(f"[watch] Watching: {extracted_rules_dir}")
    print(f"[server] Server: {server_url}")
    print(f" Check interval: {CHECK_INTERVAL} seconds")
   
    # Load initial state
    load_uploaded_files()
   
    while True:
        try:
            results = upload_new_files(reports_dir, extracted_rules_dir, server_url, auth, dry_run)
           
            if results:
                success_count = sum(1 for r in results if r["status"] == "success")
                failed_count = sum(1 for r in results if r["status"] == "failed")
                dry_run_count = sum(1 for r in results if r["status"] == "dry_run")
               
                print(f"[upload] Upload Summary: {success_count} successful, {failed_count} failed")
                if dry_run:
                    print(f"    Dry-run: {dry_run_count} files would be uploaded")
            else:
                print(" No new files to upload")
               
        except Exception as e:
            print(f"Error in monitoring loop: {e}")
       
        # Wait before next check
        print(f" Waiting {CHECK_INTERVAL} seconds for next check...")
        time.sleep(CHECK_INTERVAL)

def main():
    parser = argparse.ArgumentParser(description="Upload reports/zip and extracted_rules_zip/*.zip to secure Flask server")
    parser.add_argument("--reports", default=DEFAULT_REPORTS_DIR, help="Reports root directory")
    parser.add_argument("--extracted-rules", default=DEFAULT_EXTRACTED_RULES_DIR, help="Extracted rules root directory")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Server base URL (e.g. http://127.0.0.1:5000)")
    parser.add_argument("--user", help="Username (will prompt if not provided)")
    parser.add_argument("--dry-run", action="store_true", help="Do not actually upload, just show what would happen")
    parser.add_argument("--monitor", action="store_true", help="Continuous monitoring mode")
   
    args = parser.parse_args()

    reports_dir = os.path.abspath(args.reports)
    extracted_rules_dir = os.path.abspath(args.extracted_rules)
   
    username = args.user or input("Server username: ").strip()
    password = getpass.getpass("Server password: ")

    auth = HTTPBasicAuth(username, password)

    if args.monitor:
        # Continuous monitoring mode
        monitor_and_upload(reports_dir, extracted_rules_dir, args.server, auth, args.dry_run)
    else:
        # One-time upload
        print("[RUN] Running one-time upload...")
        load_uploaded_files()
        results = upload_new_files(reports_dir, extracted_rules_dir, args.server, auth, args.dry_run)
       
        if results:
            success_count = sum(1 for r in results if r["status"] == "success")
            failed_count = sum(1 for r in results if r["status"] == "failed")
            print(f"\n FINAL SUMMARY:")
            print(f"   Successful: {success_count}")
            print(f"   Failed: {failed_count}")
            if args.dry_run:
                dry_run_count = sum(1 for r in results if r["status"] == "dry_run")
                print(f"    Dry-run files: {dry_run_count}")
       
        print("\n To run in continuous monitoring mode, use: python3 uploader.py --monitor")

if __name__ == "__main__":
    main()
