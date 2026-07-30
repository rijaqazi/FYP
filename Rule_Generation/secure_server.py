#!/usr/bin/env python3
"""
secure_server.py

Flask server with simple HTTP Basic Auth and file upload + discovery endpoints.

- On first run, prompts to create username & password and saves creds to creds.json (PBKDF2).
- Uploads saved to ./uploads
- /upload  POST: multipart form file -> saves file and calculates sha256
- /discover GET: returns JSON list of uploaded files with metadata (filename, size, mtime, sha256)
- /download/<filename> GET: download file (auth required)
"""
import os
import json
import hashlib
import time
import getpass
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort, redirect, url_for

# CONFIG
UPLOAD_DIR = os.path.abspath("uploads")
CREDS_FILE = os.path.abspath("creds.json")
PBKDF2_ROUNDS = 200_000

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

# ----- credential utilities -----
def save_creds(username, salt_hex, hash_hex):
    data = {"username": username, "salt": salt_hex, "hash": hash_hex}
    with open(CREDS_FILE, "w") as fh:
        json.dump(data, fh)
    os.chmod(CREDS_FILE, 0o600)

def load_creds():
    if not os.path.exists(CREDS_FILE):
        return None
    with open(CREDS_FILE, "r") as fh:
        return json.load(fh)

def make_hash(password, salt):
    # returns hex digest
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return dk.hex()

def ensure_creds():
    creds = load_creds()
    if creds:
        return creds
    print("No credentials found. Let's create an admin user for the server.")
    username = input("Choose username: ").strip()
    while not username:
        username = input("Choose username (non-empty): ").strip()
    password = getpass.getpass("Choose password: ")
    password2 = getpass.getpass("Confirm password: ")
    if password != password2:
        print("Passwords did not match. Aborting.")
        raise SystemExit(1)
    salt = os.urandom(16)
    hash_hex = make_hash(password, salt)
    save_creds(username, salt.hex(), hash_hex)
    print(f"Credentials saved to {CREDS_FILE} (file permission restricted).")
    return load_creds()


def check_auth(username, password):
    creds = load_creds()
    if not creds:
        return False
    if username != creds.get("username"):
        return False
    salt = bytes.fromhex(creds["salt"])
    expected = creds["hash"]
    got = make_hash(password, salt)
    return got == expected

def authenticate():
    return jsonify({"status": "error", "message": "Authentication required"}), 401, \
           {"WWW-Authenticate": 'Basic realm="Login Required"'}

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ----- file helpers -----
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def list_uploaded_files():
    out = []
    for fname in sorted(os.listdir(UPLOAD_DIR)):
        fpath = os.path.join(UPLOAD_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        st = os.stat(fpath)
        out.append({
            "filename": fname,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "sha256": file_sha256(fpath)
        })
    return out


@app.route("/")
@requires_auth
def root():
    return redirect(url_for("discover"))

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "uploads_dir": UPLOAD_DIR})

@app.route("/discover", methods=["GET"])
@requires_auth
def discover():
    files = list_uploaded_files()
    return jsonify({"status": "ok", "files": files})

@app.route("/upload", methods=["POST"])
@requires_auth
def upload():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "no file part"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"status": "error", "message": "empty filename"}), 400
    filename = os.path.basename(f.filename)
    dest_path = os.path.join(UPLOAD_DIR, filename)

    
    data = f.read()
    sha = hashlib.sha256(data).hexdigest()

    
    if os.path.exists(dest_path):
        existing_sha = file_sha256(dest_path)
        if existing_sha == sha:
            return jsonify({"status": "duplicate", "message": "file already exists with same content", "filename": filename, "sha256": sha}), 200
       
        base, ext = os.path.splitext(filename)
        i = 1
        while True:
            newname = f"{base}-{i}{ext}"
            newpath = os.path.join(UPLOAD_DIR, newname)
            if not os.path.exists(newpath):
                dest_path = newpath
                filename = newname
                break
            i += 1

    # write file
    with open(dest_path, "wb") as out:
        out.write(data)
    os.chmod(dest_path, 0o640)
    return jsonify({"status": "ok", "filename": filename, "sha256": sha}), 201

@app.route("/download/<path:filename>", methods=["GET"])
@requires_auth
def download(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    # ensure creds exist (or create)
    try:
        ensure_creds()
    except SystemExit:
        print("Credential creation aborted.")
        raise

    print("Starting secure Flask upload server on http://127.0.0.1:5005")
    app.run(host="0.0.0.0", port=5005, debug=False)
