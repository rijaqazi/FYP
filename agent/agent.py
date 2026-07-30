#!/usr/bin/env python3
import requests
import time
import socket
from datetime import datetime
from pymongo import MongoClient
import json

#Databse
MONGO_URI = "mongodb+srv://fatimazareen889_db_user:ccicCyFyFELe6mEt@threatsentinel.0cfaybg.mongodb.net/?appName=threatsentinel"
DB_NAME = "security_db"
COLLECTION_NAME = "ip_tracking"

# Server Configuration 
SERVER_URL = "http://localhost:5001"  
COMPANY_ID = "alpha_corp"
COMPUTER_NAME = socket.gethostname()

# MongoDB Client Setup
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    ip_collection = db[COLLECTION_NAME]
    print("[+] MongoDB connected successfully!")
except Exception as e:
    print(f"[-] MongoDB connection failed: {e}")

def get_local_ip_address():
    try:
        # Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        try:
            # Hostname 
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"

def get_public_ip_address():

    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return None

def update_mongodb_tracking():
    try:
        local_ip = get_local_ip_address()
        public_ip = get_public_ip_address()
        current_time = datetime.now()
        
        tracking_data = {
            "company_id": COMPANY_ID,
            "computer_name": COMPUTER_NAME,
            "local_ip": local_ip,  
            "public_ip": public_ip,  
            "start_time": current_time,
            "end_time": None,
            "last_updated": current_time,
            "status": "active"
        }
        
        # Previous active records update 
        ip_collection.update_many(
            {
                "company_id": COMPANY_ID,
                "status": "active",
                "local_ip": {"$ne": local_ip}
            },
            {
                "$set": {
                    "end_time": current_time,
                    "status": "inactive",
                    "last_updated": current_time
                }
            }
        )
        
        
        existing_active = ip_collection.find_one({
            "company_id": COMPANY_ID,
            "local_ip": local_ip,
            "status": "active"
        })
        
        if existing_active:
            ip_collection.update_one(
                {"_id": existing_active["_id"]},
                {"$set": {"last_updated": current_time}}
            )
            print(f"[!] IP updated in MongoDB - Local: {local_ip}, Public: {public_ip}")
            return local_ip, public_ip, "updated"
        else:
            ip_collection.insert_one(tracking_data)
            print(f"[!] New IP added to MongoDB - Local: {local_ip}, Public: {public_ip}")
            return local_ip, public_ip, "added"
            
    except Exception as e:
        print(f"[x] MongoDB update error: {e}")
        return None, None, "error"

def send_heartbeat_to_server(local_ip, public_ip):
    try:
        data = {
            "company_id": COMPANY_ID,
            "computer_name": COMPUTER_NAME,
            "ip_address": local_ip, 
            "public_ip": public_ip,   
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "mongodb_agent"
        }
        
        response = requests.post(f"{SERVER_URL}/api/heartbeat", json=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"[!] Heartbeat sent to server - Local IP: {local_ip}")
            return True
        else:
            print(f"[x] Server response error: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectTimeout:
        print(f"[x] Server not available (timeout) - Is server running on port 5001?")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[x] Server not available (connection error) - Start heartbeat_server.py on port 5001")
        return False
    except Exception as e:
        print(f"[x] Server heartbeat error: {e}")
        return False

def check_mongodb_connection():
    try:
        client.admin.command('ismaster')
        return True
    except Exception as e:
        print(f"[x] MongoDB connection check failed: {e}")
        return False


if __name__ == "__main__":
    print("[+] Starting MongoDB IP Tracking Agent...")
    print(f"[+] Server URL: {SERVER_URL}")
    
    # Pehle hi local IP show karo
    local_ip = get_local_ip_address()
    public_ip = get_public_ip_address()
    print(f"[L] Local IP: {local_ip}")
    print(f"[P] Public IP: {public_ip}")
    
    if not check_mongodb_connection():
        print("[x] Please start MongoDB service first!")
        exit(1)
    
    print("[!] Agent started successfully. Press Ctrl+C to stop.")
    
    try:
        while True:
            local_ip, public_ip, status = update_mongodb_tracking()
            
            if local_ip and status in ["added", "updated"]:
                send_heartbeat_to_server(local_ip, public_ip)
            else:
                print("[!] Skipping server heartbeat due to MongoDB error")
            
            time.sleep(120)  # 2 minutes wait
            
    except KeyboardInterrupt:
        print("\n !!! Agent stopped by user")
    except Exception as e:
        print(f"[x] Unexpected error: {e}")
    finally:
        client.close()
