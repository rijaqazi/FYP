#!/usr/bin/env python3
import json
from pymongo import MongoClient

# === CONFIG ===
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "CVSS"
COLLECTION_NAME = "cvss"
INPUT_FILE = "classified_alerts.json"

def push_to_mongo():
    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    # Load JSON file
    try:
        with open(INPUT_FILE, "r") as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print(f"-- File not found: {INPUT_FILE}")
        return
    except json.JSONDecodeError:
        print("-- Invalid JSON format.")
        return

    if not isinstance(alerts, list):
        print("-- JSON format invalid, expected a list of alerts.")
        return

    if not alerts:
        print(" No alerts to insert.")
        return

    


    # Insert into MongoDB
    result = collection.insert_many(alerts)
    print(f"--Inserted {len(result.inserted_ids)} alerts into MongoDB collection '{COLLECTION_NAME}'")

if __name__ == "__main__":
    push_to_mongo()

