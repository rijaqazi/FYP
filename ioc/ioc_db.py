import os
import json
from pymongo import MongoClient

# --- MongoDB Connection ---
client = MongoClient("mongodb://localhost:27017/")
db = client["ioc_database"]              # Database name
collection = db["Indicator_of_Compromise"]          # New collection for flat objects

# --- Path to your stix_output folder ---
stix_folder = os.path.expanduser("~/Desktop/ioc/stix_output")

# --- Iterate over JSON files and push objects individually ---
for filename in os.listdir(stix_folder):
    if filename.endswith(".json"):
        file_path = os.path.join(stix_folder, filename)
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

                # bundle level id (for reference)
                bundle_id = data.get("id", "")

                # iterate over objects array
                for obj in data.get("objects", []):
                    flat_obj = {
                        "bundle_id": bundle_id,
                        **obj   # unpack all object fields into top level
                    }

                    # insert into MongoDB
                    collection.insert_one(flat_obj)

                print(f"[+] Inserted objects from: {filename}")

        except Exception as e:
            print(f"[!] Error with {filename}: {e}")

print("✅ All STIX objects pushed as flat documents to MongoDB!")

