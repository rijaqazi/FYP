#!/usr/bin/env python3
"""
rule_sharing.py

Scan local reports/zip for .zip files and upload them to secure Flask server.
Does deduplication by comparing filename + sha256 with server /discover output.
All done in Python (requests).
"""

import os
import sys
import hashlib
import getpass
import argparse
import requests
from requests.auth import HTTPBasicAuth

# ---- CONFIG ----
DEFAULT_REPORTS_DIR = os.path.abspath("reports/zip")
DEFAULT_SERVER = "http://192.168.44.128:5000"

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
    # build dict filename -> sha
    idx = {}
    for item in j.get("files", []):
        idx[item["filename"]] = item.get("sha256")
    return idx

def upload_file(server_url, auth, local_path):
    url = server_url.rstrip("/") + "/upload"
    with open(local_path, "rb") as fh:
        files = {"file": (os.path.basename(local_path), fh)}
        r = requests.post(url, files=files, auth=auth, timeout=30)
    return r

def main():
    parser = argparse.ArgumentParser(description="Upload reports/zip/*.zip to secure Flask server")
    parser.add_argument("--reports", default=DEFAULT_REPORTS_DIR, help="Reports root directory")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Server base URL (e.g. http://127.0.0.1:5000)")
    parser.add_argument("--user", help="Username (will prompt if not provided)")
    parser.add_argument("--dry-run", action="store_true", help="Do not actually upload, just show what would happen")
    args = parser.parse_args()

    reports_dir = os.path.abspath(args.reports)
    if not os.path.exists(reports_dir):
        print(f"[ERROR] reports dir not found: {reports_dir}")
        sys.exit(1)

    username = args.user or input("Server username: ").strip()
    password = getpass.getpass("Server password: ")

    auth = HTTPBasicAuth(username, password)

    print("[*] Fetching remote index...")
    try:
        remote_index = fetch_remote_index(args.server, auth)
    except Exception as e:
        print(f"[ERROR] Could not fetch remote index: {e}")
        sys.exit(1)

    print(f"[*] Remote has {len(remote_index)} files already.")
    # Walk reports dir
    to_upload = []
    for root, _, files in os.walk(reports_dir):
        for f in files:
            if not f.lower().endswith(".zip"):
                continue
            local_path = os.path.join(root, f)
            local_sha = sha256_file(local_path)
            remote_sha = remote_index.get(f)
            if remote_sha and remote_sha == local_sha:
                print(f"[SKIP] {f} (already uploaded, sha matches)")
                continue
            # otherwise plan to upload
            to_upload.append((local_path, f, local_sha, remote_sha))

    if not to_upload:
        print("[OK] Nothing to upload.")
        return

    print(f"[*] {len(to_upload)} file(s) to upload.")
    for local_path, fname, sha, remote_sha in to_upload:
        print(f"[UPLOAD] {fname} (sha={sha[:8]}...)", end=" ")
        if args.dry_run:
            print("(dry-run)")
            continue
        try:
            r = upload_file(args.server, auth, local_path)
        except Exception as e:
            print(f"FAILED: {e}")
            continue
        try:
            jr = r.json()
        except Exception:
            jr = {"status": "error", "text": r.text}
        if r.status_code in (200, 201):
            print("OK ->", jr)
        else:
            print("FAILED ->", r.status_code, jr)

if __name__ == "__main__":
    main()
