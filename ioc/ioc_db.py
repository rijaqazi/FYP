#!/usr/bin/env python3
import os
import json
import time
from pymongo import MongoClient


client = MongoClient("mongodb+srv://fatimazareen889_db_user:ccicCyFyFELe6mEt@threatsentinel.0cfaybg.mongodb.net/?appName=threatsentinel")
db = client["ioc_database"]            
collection = db["Indicator_of_Compromise"]          


stix_folder = os.path.expanduser("~/Desktop/ioc/stix_output")


processed_files = set()

def load_processed_files():

    global processed_files
    try:
        # Get all bundle_ids from MongoDB to track what's already processed
        existing_bundles = collection.distinct("bundle_id")
        for bundle_id in existing_bundles:
            processed_files.add(bundle_id)
        print(f" Found {len(processed_files)} existing bundles in database")
    except Exception as e:
        print(f"  Error loading processed files: {e}")
        processed_files = set()

def bundle_exists_in_db(bundle_id):
    """Check if a bundle already exists in the database"""
    try:
        existing = collection.find_one({"bundle_id": bundle_id})
        return existing is not None
    except Exception as e:
        print(f"  Error checking if bundle exists: {e}")
        return False

def push_stix_bundles_to_mongodb():
    """Check for new STIX bundles and push them to MongoDB"""
    global processed_files
    
    # Create stix_output folder if it doesn't exist
    os.makedirs(stix_folder, exist_ok=True)
    
    new_files_count = 0
    new_objects_count = 0
    skipped_files_count = 0
    
    # Check all JSON files in stix_output folder
    for filename in os.listdir(stix_folder):
        if filename.endswith(".json"):
            file_path = os.path.join(stix_folder, filename)
            
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)

                # Extract bundle level id
                bundle_id = data.get("id", "")
                
                # Skip if bundle is already in database
                if bundle_exists_in_db(bundle_id):
                    skipped_files_count += 1
                    print(f"[>] Skipping duplicate bundle: {filename} (bundle_id: {bundle_id})")
                    continue
                
                # Skip if we've already processed this bundle_id
                if bundle_id in processed_files:
                    skipped_files_count += 1
                    print(f"[>]Skipping already processed bundle: {filename}")
                    continue

                file_objects_count = 0
                
                # Iterate over objects array and insert all objects
                for obj in data.get("objects", []):
                    flat_obj = {
                        "bundle_id": bundle_id,
                        **obj   # unpack all object fields into top level
                    }

                    # Insert into MongoDB
                    collection.insert_one(flat_obj)
                    file_objects_count += 1
                    new_objects_count += 1

                # Mark bundle as processed
                processed_files.add(bundle_id)
                new_files_count += 1
                print(f"[+] Inserted {file_objects_count} objects from: {filename}")

            except Exception as e:
                print(f"[x]Error processing {filename}: {e}")
    
    return new_files_count, new_objects_count, skipped_files_count

def monitor_and_push():
    """Continuously monitor for new STIX bundles and push to MongoDB"""
    print(" Monitoring for new STIX bundles to push to MongoDB every 30 seconds...")
    print(f" Watching folder: {stix_folder}")
    
    # Load already processed files on startup
    load_processed_files()
    
    while True:
        try:
            new_files, new_objects, skipped_files = push_stix_bundles_to_mongodb()
            
            if new_files > 0:
                print(f"[+] Successfully pushed {new_objects} new objects from {new_files} bundles to MongoDB")
            if skipped_files > 0:
                print(f"[>] Skipped {skipped_files} duplicate bundles")
            if new_files == 0 and skipped_files == 0:
                print("[!] No new STIX bundles found")
                
        except Exception as e:
            print(f"[x] Error in monitoring loop: {e}")
        
        # Wait 30 seconds before checking again
        print("[!!] Waiting 30 seconds for next check...")
        time.sleep(30)

if __name__ == "__main__":
    monitor_and_push()
