from flask import Flask, request, jsonify
from functools import wraps
import os
import json

app = Flask(__name__)

BUNDLES_DIR = "/home/rijaqazi/Desktop/ioc/stix_output/"

# ---- Authentication ----
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


# ---- SUMMARY ROUTE (with raw logs) ----
@app.route("/", methods=["GET"])
def index():
    """
    Shows summary of all bundles (id, type, description, created, raw_logs).
    """
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
                        "raw_logs": obj.get("raw_logs", [])  # added
                    })
            except Exception as e:
                summaries.append({"file": file_name, "error": str(e)})
    return jsonify({"bundles": summaries})


# ---- FULL ROUTE (all fields, including raw logs) ----
@app.route("/full", methods=["GET"])
def full_iocs():
    """
    Shows complete IOC objects from all bundles (raw logs included).
    """
    all_iocs = []
    for file_name in sorted(os.listdir(BUNDLES_DIR)):
        if file_name.endswith(".json"):
            file_path = os.path.join(BUNDLES_DIR, file_name)
            try:
                with open(file_path, "r") as f:
                    bundle = json.load(f)
                for obj in bundle.get("objects", []):
                    obj["file"] = file_name  # add filename for reference
                    all_iocs.append(obj)
            except Exception as e:
                all_iocs.append({"file": file_name, "error": str(e)})
    return jsonify({"iocs": all_iocs})


# ---- UPLOAD + GET ROUTE ----
@app.route('/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/', methods=['POST', 'GET'])
@requires_auth
def handle_stix_bundles():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            print("📥 Received STIX data")
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
        return jsonify({"collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "objects": all_bundles})


if __name__ == '__main__':
    print("🚀 TAXII Server starting...")
    app.run(host='127.0.0.1', port=5000, debug=True)

