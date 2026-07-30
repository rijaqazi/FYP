from flask import Flask, request, jsonify, Response
from functools import wraps
import os
import json
import uuid
from datetime import datetime

app = Flask(__name__)

BUNDLES_DIR = "/home/defender/Desktop/ioc/stix_output/"


def check_auth(username, password):
    return username == 'admin' and password == 'password123'

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def load_existing_bundles():
    """Load existing STIX bundles from disk into taxii_objects memory"""
    print("[+] Loading existing STIX bundles into TAXII memory...")
    
    if not os.path.exists(BUNDLES_DIR):
        print("[!] Bundles directory does not exist, skipping load.")
        return

    count = 0

    for file_name in sorted(os.listdir(BUNDLES_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(BUNDLES_DIR, file_name)
            try:
                with open(file_path, "r") as f:
                    bundle = json.load(f)

                # Extract objects from bundle
                for obj in bundle.get("objects", []):
                    taxii_objects[collection_id].append(obj)
                    count += 1

            except Exception as e:
                print(f"[x] Failed to load {file_name}: {e}")

    print(f"[+] Loaded {count} STIX objects from disk.")



@app.route("/", methods=["GET"])
def index():
    summaries = []
    for file_name in sorted(os.listdir(BUNDLES_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(BUNDLES_DIR, file_name)
            try:
                with open(file_path, "r") as f:
                    bundle = json.load(f)
                for obj in bundle.get("objects", []):
                    summaries.append({
                        "file": file_name,
                        "id": obj.get("id"),
                        "type": obj.get("type"),
                        "created": obj.get("created"),
                        "description": obj.get("description", "N/A"),
                        "raw_logs": obj.get("raw_logs", [])
                    })
            except Exception as e:
                summaries.append({"file": file_name, "error": str(e)})
    return jsonify({"bundles": summaries})



@app.route("/full", methods=["GET"])
def full_iocs():
    all_iocs = []
    for file_name in sorted(os.listdir(BUNDLES_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(BUNDLES_DIR, file_name)
            try:
                with open(file_path, "r") as f:
                    bundle = json.load(f)
                for obj in bundle.get("objects", []):
                    obj["file"] = file_name
                    all_iocs.append(obj)
            except Exception as e:
                all_iocs.append({"file": file_name, "error": str(e)})
    return jsonify({"iocs": all_iocs})



@app.route('/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/', methods=['POST', 'GET'])
@requires_auth
def handle_stix_bundles():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            print("[!] Received STIX data")
            return jsonify({"message": "STIX bundle received successfully!"}), 202
        else:
            return jsonify({"error": "Request must be JSON"}), 400

    elif request.method == 'GET':
        all_bundles = []
        for file_name in sorted(os.listdir(BUNDLES_DIR)):
            if file_name.endswith(".json"):
                file_path = os.path.join(BUNDLES_DIR, file_name)
                try:
                    with open(file_path, "r") as f:
                        bundle = json.load(f)
                    all_bundles.append(bundle)
                except Exception as e:
                    all_bundles.append({"file": file_name, "error": str(e)})
        return jsonify({
            "collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "objects": all_bundles
        })




TAXII_CONFIG = {
    "title": "IOC TAXII Server",
    "description": "TAXII 2.1 Server for IOC Sharing",
    "contact": "admin@localhost",
    "default_url": "http://127.0.0.1:5002/",
    "api_roots": [{
        "id": "api1",
        "title": "IOC API Root",
        "description": "Primary API Root for IOC Collections",
        "url": "http://127.0.0.1:5002/api1/"
    }]
}

collection_id = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
taxii_objects = {}
taxii_objects[collection_id] = []


def taxii_response(data, status=200):
    return Response(
        json.dumps(data),
        status=status,
        mimetype='application/taxii+json; version=2.1'
    )



@app.route("/taxii2/", methods=["GET"])
def discovery():
    data = {
        "title": TAXII_CONFIG["title"],
        "description": TAXII_CONFIG["description"],
        "contact": TAXII_CONFIG["contact"],
        "default": TAXII_CONFIG["api_roots"][0]["url"],
        "api_roots": [root["url"] for root in TAXII_CONFIG["api_roots"]]
    }
    return taxii_response(data)



@app.route("/api1/", methods=["GET"])
def api_root():
    data = {
        "title": TAXII_CONFIG["api_roots"][0]["title"],
        "description": TAXII_CONFIG["api_roots"][0]["description"],
        "versions": ["taxii-2.1"],
        "max_content_length": 104857600
    }
    return taxii_response(data)



@app.route("/api1/collections/", methods=["GET"])
@requires_auth
def collections():
    data = {
        "collections": [{
            "id": collection_id,
            "title": "IOC Collection",
            "description": "Collection for sharing IOCs",
            "can_read": True,
            "can_write": True,
            "media_types": ["application/stix+json; version=2.1"],
            "url": f"http://127.0.0.1:5002/api1/collections/{collection_id}/"
        }]
    }
    return taxii_response(data)



@app.route('/api1/collections/<collection_id>/objects', methods=['GET', 'POST'])
@requires_auth
def taxii_objects_handler(collection_id):
    if collection_id != "91a7b528-80eb-42ed-a74d-c6fbd5a26116":
        return taxii_response({"error": "Collection not found"}, 404)

    # GET
    if request.method == 'GET':
        return taxii_response({"objects": taxii_objects[collection_id], "more": False})

    # POST
    if request.is_json:
        bundle = request.get_json()
        if bundle.get("type") == "bundle":
            for obj in bundle["objects"]:
                taxii_objects[collection_id].append(obj)
        return taxii_response({"message": "STIX received"}, 202)

    return taxii_response({"error": "Bad JSON"}, 400)



@app.route('/api1/collections/<collection_id>/objects/<object_id>/', methods=['GET'])
@requires_auth
def get_single(collection_id, object_id):
    if collection_id != "91a7b528-80eb-42ed-a74d-c6fbd5a26116":
        return taxii_response({"error": "Collection not found"}, 404)

    for obj in taxii_objects[collection_id]:
        if obj.get("id") == object_id:
            return taxii_response(obj)

    return taxii_response({"error": "Object not found"}, 404)


if __name__ == '__main__':
    
    load_existing_bundles()

    print("\n================= TAXII 2.1 SERVER STARTING =================")
    
    print("\n[+] Public Endpoints (No Authentication Required):")
    print("  • Discovery Endpoint:           http://127.0.0.1:5002/taxii2/")
    print("  • API Root:                     http://127.0.0.1:5002/api1/")
    print("  • Summary Page:                 http://127.0.0.1:5002/")
    print("  • Full IOC List:                http://127.0.0.1:5002/full")

    print("\n[+] Protected Endpoints (Requires admin/password123):")
    print("  • Collections:                  http://127.0.0.1:5002/api1/collections/")
    print("  • Objects (Main Collection):    http://127.0.0.1:5002/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/")

    print("\n==============================================================")
    print(" Server is running...\n")

    app.run(host='127.0.0.1', port=5002, debug=True)

