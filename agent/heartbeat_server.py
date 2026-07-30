from flask import Flask, request, jsonify
from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId
import json

app = Flask(__name__)

MONGO_URI = "mongodb+srv://fatimazareen889_db_user:ccicCyFyFELe6mEt@threatsentinel.0cfaybg.mongodb.net/?appName=threatsentinel"
DB_NAME = "security_db"


try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    ip_tracking = db['ip_tracking']
    alerts = db['alerts']
    heartbeat_logs = db['heartbeat_logs']  
    print("[+] MongoDB connected successfully!")
except Exception as e:
    print(f"[-] MongoDB connection failed: {e}")


def update_ip_tracking(company_id, ip_address, computer_name, timestamp):
    try:
        current_time = datetime.now()
        public_ip = request.json.get('public_ip', 'unknown')  
        
        print(f"[+] Heartbeat received: {company_id} - {computer_name}")
        print(f"[+] Local IP: {ip_address}, Public IP: {public_ip}")
        
        
        ip_tracking.update_many(
            {
                "company_id": company_id,
                "status": "active",
                "ip_address": {"$ne": ip_address}
            },
            {
                "$set": {
                    "end_time": current_time,
                    "status": "inactive", 
                    "last_updated": current_time
                }
            }
        )
        
       
        existing_active = ip_tracking.find_one({
            "company_id": company_id, 
            "ip_address": ip_address,
            "status": "active"
        })
        
        if existing_active:
            ip_tracking.update_one(
                {"_id": existing_active["_id"]},
                {
                    "$set": {
                        "last_updated": current_time,
                        "public_ip": public_ip 
                    }
                }
            )
            action = "updated"
        else:
            new_entry = {
                "company_id": company_id,
                "computer_name": computer_name,
                "ip_address": ip_address,
                "public_ip": public_ip,  
                "start_time": current_time,
                "end_time": None,
                "last_updated": current_time,
                "status": "active",
                "first_seen": current_time
            }
            ip_tracking.insert_one(new_entry)
            action = "added"
        
        
        heartbeat_logs.insert_one({
            "company_id": company_id,
            "computer_name": computer_name, 
            "local_ip": ip_address,
            "public_ip": public_ip,
            "timestamp": current_time,
            "action": action,
            "received_at": datetime.now()
        })
            
        return True, action
    except Exception as e:
        print(f"[x] IP tracking update error: {e}")
        return False, "error"

# Routes
@app.route('/')
def home():
    return '''
    <h1> Heartbeat Server Running!</h1>
    <p>Port: 5001</p>
    <p>Endpoints:</p>
    <ul>
        <li><a href="/api/heartbeat">POST /api/heartbeat</a></li>
        <li><a href="/api/status">GET /api/status</a></li>
        <li><a href="/api/heartbeats">GET /api/heartbeats</a></li>
        <li><a href="/api/active_ips">GET /api/active_ips</a></li>
    </ul>
    '''

@app.route('/api/heartbeat', methods=['POST', 'GET'])
def heartbeat():
    try:
        if request.method == 'GET':
            return jsonify({
                "status": "success", 
                "message": "Heartbeat endpoint is working! Use POST method to send data.",
                "example_post_data": {
                    "company_id": "alpha_corp",
                    "computer_name": "your-pc-name", 
                    "ip_address": "192.168.1.100",
                    "timestamp": "2024-01-15 12:00:00"
                }
            })
        
        
        data = request.json
        company_id = data.get('company_id')
        ip_address = data.get('ip_address')
        computer_name = data.get('computer_name', 'unknown')
        timestamp = data.get('timestamp')
        
        print(f" Received heartbeat from: {company_id} - {computer_name}")
        
        if not all([company_id, ip_address]):
            return jsonify({
                "status": "error", 
                "message": "Missing required fields: company_id and ip_address"
            }), 400
        
        success, action = update_ip_tracking(company_id, ip_address, computer_name, timestamp)
        
        if success:
            return jsonify({
                "status": "success", 
                "message": f"Heartbeat received - IP {action}",
                "data": {
                    "company_id": company_id,
                    "computer_name": computer_name,
                    "ip_address": ip_address,
                    "action": action,
                    "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            })
        else:
            return jsonify({
                "status": "error", 
                "message": "Database update failed"
            }), 500
            
    except Exception as e:
        print(f"[x] Heartbeat error: {e}")
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route('/api/status')
def status():
    try:
        client.admin.command('ismaster')
        mongo_status = "connected"
    except:
        mongo_status = "disconnected"
    
    active_ips_count = ip_tracking.count_documents({"status": "active"})
    total_heartbeats = heartbeat_logs.count_documents({})
    
    return jsonify({
        "server": "running",
        "port": 5001,
        "mongodb": mongo_status,
        "active_ips": active_ips_count,
        "total_heartbeats": total_heartbeats,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/heartbeats')
def get_heartbeats():
    recent_heartbeats = list(heartbeat_logs.find().sort("timestamp", -1).limit(20))
    
    # ObjectId to string 
    for hb in recent_heartbeats:
        hb['_id'] = str(hb['_id'])
        hb['timestamp'] = hb['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
        if 'received_at' in hb:
            hb['received_at'] = hb['received_at'].strftime("%Y-%m-%d %H:%M:%S")
    
    return jsonify({
        "count": len(recent_heartbeats),
        "heartbeats": recent_heartbeats
    })

@app.route('/api/active_ips')
def get_active_ips():
  
    active_ips = list(ip_tracking.find({"status": "active"}).sort("last_updated", -1))
    
    for ip in active_ips:
        ip['_id'] = str(ip['_id'])
        ip['start_time'] = ip['start_time'].strftime("%Y-%m-%d %H:%M:%S")
        ip['last_updated'] = ip['last_updated'].strftime("%Y-%m-%d %H:%M:%S")
        if ip.get('first_seen'):
            ip['first_seen'] = ip['first_seen'].strftime("%Y-%m-%d %H:%M:%S")
    
    return jsonify({
        "active_count": len(active_ips),
        "active_ips": active_ips
    })

if __name__ == '__main__':
    print(" Starting Heartbeat Server on Port 5001...")
    print(" Access URLs:")
    print("   http://localhost:5001/")
    print("   http://localhost:5001/api/status")
    print("   http://localhost:5001/api/heartbeats")
    app.run(host='0.0.0.0', port=5001, debug=True)
