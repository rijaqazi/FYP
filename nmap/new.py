#!/usr/bin/env python3
import json
import sys
import os
import time
import logging
import argparse
from collections import defaultdict

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Advanced Nmap Attack Detector")
parser.add_argument("json_file", help="Path to Wireshark JSON export")
parser.add_argument("--log", dest="log_file", help="Path for alert logs")
parser.add_argument("--json-out", dest="json_output", help="JSON output file for alerts")
args = parser.parse_args()

# --- Validate input file ---
if not os.path.exists(args.json_file):
    print(f"Error: File not found: {args.json_file}")
    sys.exit(1)

# --- Load packet data ---
try:
    with open(args.json_file, "r") as f:
        packets = json.load(f)
except Exception as e:
    print(f"JSON Error: {str(e)}")
    sys.exit(1)

# --- Configure logging ---
logger = logging.getLogger('nmap_detector')
logger.setLevel(logging.INFO)

if args.log_file:
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger.addHandler(file_handler)

# --- Alert management ---
alerts = []
SCAN_WINDOW = 10  # Seconds for scan detection
MAX_PORTS_IN_ALERT = 15

# Detection thresholds - updated for better detection
THRESHOLDS = {
    'tcp': 15,
    'udp': 10,
    'syn': 5,             # Lowered for stealth detection
    'fin': 5,
    'xmas': 5,
    'null': 5,
    'ack': 10,
    'os_fingerprint': 2, # Lowered for better detection
    'service_probe': 3,  # Lowered for better detection
    'full_port': 50,
    'icmp': 5
}

# --- Detection structures ---
detectors = {
    'tcp': defaultdict(set),
    'udp': defaultdict(set),
    'syn': defaultdict(set),
    'fin': defaultdict(set),
    'xmas': defaultdict(set),
    'null': defaultdict(set),
    'ack': defaultdict(set),
    'service_probe': defaultdict(lambda: defaultdict(int)),
    'icmp': defaultdict(list),
    'os_fingerprint': defaultdict(int)
}

timestamps = {scan_type: defaultdict(list) for scan_type in detectors.keys()}
alerted_ips = defaultdict(set)  # Combined alert tracking

# --- Enhanced alert function ---
def log_alert(scan_type, src_ip, details=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    message = f"{timestamp} - {scan_type.upper()} ALERT from {src_ip}"
    
    if details:
        if 'ports' in details:
            message += f" | Ports: {details['ports']}"
        if 'start_time' in details:
            message += f" | Start: {details['start_time']}"
        if 'duration' in details:
            message += f" | Duration: {details['duration']:.1f}s"
        if 'os_count' in details:
            message += f" | OS Probes: {details['os_count']}"
        if 'service_count' in details:
            message += f" | Service Probes: {details['service_count']}"
        if 'total_ports' in details:
            message += f" | Ports Scanned: {details['total_ports']}"
    
    # Terminal alert (red text)
    print(f"\033[91m{message}\033[0m")
    
    # Log to file
    logger.info(message)
    
    # Store for JSON output
    alerts.append({
        "timestamp": time.time(),
        "type": scan_type,
        "src_ip": src_ip,
        "details": details or {}
    })
    alerted_ips[src_ip].add(scan_type) # Track which alerts have been fired for this IP

# --- Packet Processing ---
for packet in packets:
    try:
        layers = packet.get('_source', {}).get('layers', {})
        frame = layers.get('frame', {})
        ip_layer = layers.get('ip', {})
        
        src_ip = ip_layer.get('ip.src', '')
        timestamp = float(frame.get('frame.time_epoch', 0))
        
        if not src_ip or not timestamp:
            continue

        # --- TCP Scan Detection ---
        if 'tcp' in layers:
            tcp = layers['tcp']
            flags = tcp.get('tcp.flags_tree', {})
            dst_port = tcp.get('tcp.dstport', '')
            
            # SYN Scan (Stealth Scan) - Most common
            if flags.get('tcp.flags.syn') == '1' and flags.get('tcp.flags.ack') == '0':
                detectors['syn'][src_ip].add(dst_port)
                timestamps['syn'][src_ip].append(timestamp)
            
            # XMAS Scan - Check before FIN because it's more specific
            elif (int(flags.get('tcp.flags.fin', 0 )) + 
                  int(flags.get('tcp.flags.psh', 0 )) +
                  int(flags.get('tcp.flags.urg', 0 )) >= 2 and 
                  flags.get('tcp.flags.syn') == '0' and # Crucial: ensure SYN is NOT set
                  flags.get('tcp.flags.ack') == '0'):  # Crucial: ensure ACK is NOT set
                detectors['xmas'][src_ip].add(dst_port)
                timestamps['xmas'][src_ip].append(timestamp)
                
            # FIN Scan - Now checked after Xmas to avoid false positives
            elif (flags.get('tcp.flags.fin') == '1' and 
                  flags.get('tcp.flags.syn') == '0' and
                  flags.get('tcp.flags.ack') == '0' ): # Ensure it's purely FIN
      
                detectors['fin'][src_ip].add(dst_port)
                timestamps['fin'][src_ip].append(timestamp)
            
            # NULL Scan
            elif all(flags.get(f'tcp.flags.{flag}', '0') == '0' 
                     for flag in ['syn', 'ack', 'fin', 'psh', 'urg', 'rst']):
                detectors['null'][src_ip].add(dst_port)
                timestamps['null'][src_ip].append(timestamp)
            
            # ACK Scan (Firewall Detection) - Ensure it's not a SYN-ACK or part of handshake
            elif flags.get('tcp.flags.ack') == '1' and flags.get('tcp.flags.syn') == '0':
                detectors['ack'][src_ip].add(dst_port)
                timestamps['ack'][src_ip].append(timestamp)
            
            # Service Version Detection
            if int(tcp.get('tcp.len', 0)) > 0 and dst_port:
                detectors['service_probe'][src_ip][dst_port] += 1
                timestamps['service_probe'][src_ip].append(timestamp)
            
            # OS Fingerprinting
            if 'tcp.options' in tcp:
                detectors['os_fingerprint'][src_ip] += 1
                timestamps['os_fingerprint'][src_ip].append(timestamp)
        
        # --- UDP Scan Detection ---
        elif 'udp' in layers:
            udp = layers['udp']
            dst_port = udp.get('udp.dstport', '')
            if dst_port:
                detectors['udp'][src_ip].add(dst_port)
                timestamps['udp'][src_ip].append(timestamp)
        
        # --- ICMP Scan Detection ---
        elif 'icmp' in layers:
            icmp = layers['icmp']
            if icmp.get('icmp.type') == '8':  # Echo Request
                detectors['icmp'][src_ip].append(timestamp)
        
        # --- Clean old timestamps using packet time ---
        for scan_type in timestamps:
            if src_ip in timestamps[scan_type]:
                timestamps[scan_type][src_ip] = [
                    ts for ts in timestamps[scan_type][src_ip]  
                    if (timestamp - ts) <= SCAN_WINDOW
                ]
        
    except Exception as e:
        logger.error(f"Processing error: {str(e)}")

# --- Scan Detection Logic ---
for src_ip in set(ip for detector in detectors.values() for ip in detector):
    # Retrieve relevant data for current IP
    syn_ports = detectors['syn'].get(src_ip, set())
    syn_count = len(syn_ports)
    syn_ts_list = timestamps['syn'].get(src_ip, [])
    
    os_count = detectors['os_fingerprint'].get(src_ip, 0)
    service_count = sum(detectors['service_probe'].get(src_ip, {}).values())

    start_time = time.ctime(min(syn_ts_list)) if syn_ts_list else "N/A"
    syn_duration = max(syn_ts_list) - min(syn_ts_list) if len(syn_ts_list) > 1 else 0

    # --- ENHANCED STEALTH SCAN DETECTION ---
    # Only trigger stealth scan if ALL THREE components are present
    has_syn_scan = syn_count >= THRESHOLDS['syn']
    has_os_fingerprinting = os_count >= THRESHOLDS['os_fingerprint']
    has_service_probes = service_count >= THRESHOLDS['service_probe']
    
    # Check if we have a true stealth scan (all 3 components)
    if (has_syn_scan and has_os_fingerprinting and has_service_probes and
        'STEALTH_SCAN' not in alerted_ips[src_ip]):
        
        port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
        
        log_alert("STEALTH_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": syn_count,
            "start_time": start_time,
            "duration": syn_duration,
            "os_count": os_count,
            "service_count": service_count
        })
        
        # Mark individual components as alerted to prevent duplicate alerts
        alerted_ips[src_ip].update(['SYN_SCAN', 'OS_FINGERPRINT', 'SERVICE_PROBE'])
    
    # --- Full Port Scan Detection ---
    elif syn_count > THRESHOLDS['full_port'] and 'FULL_PORT_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
        
        log_alert("FULL_PORT_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": syn_count,
            "start_time": start_time,
            "duration": syn_duration
        })

    # --- Individual Scan Detections ---
    # Only trigger these if they haven't been covered by stealth scan
    
    # SYN Scan Detection
    if (syn_count > THRESHOLDS['syn'] and 
        'SYN_SCAN' not in alerted_ips[src_ip] and
        'STEALTH_SCAN' not in alerted_ips[src_ip]):
        
        port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
        start_time = time.ctime(min(syn_ts_list)) if syn_ts_list else "N/A"
        duration = max(syn_ts_list) - min(syn_ts_list) if len(syn_ts_list) > 1 else 0
        
        log_alert("SYN_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": syn_count,
            "start_time": start_time,
            "duration": duration
        })
    
    # FIN Scan Detection
    fin_ports = detectors['fin'].get(src_ip, set())
    if len(fin_ports) > THRESHOLDS['fin'] and 'FIN_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(fin_ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['fin'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("FIN_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": len(fin_ports),
            "start_time": start_time,
            "duration": duration
        })
    
    # XMAS Scan Detection
    xmas_ports = detectors['xmas'].get(src_ip, set())
    if len(xmas_ports) > THRESHOLDS['xmas'] and 'XMAS_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(xmas_ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['xmas'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("XMAS_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": len(xmas_ports),
            "start_time": start_time,
            "duration": duration
        })
    
    # NULL Scan Detection
    null_ports = detectors['null'].get(src_ip, set())
    if len(null_ports) > THRESHOLDS['null'] and 'NULL_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(null_ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['null'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("NULL_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": len(null_ports),
            "start_time": start_time,
            "duration": duration
        })
    
    # ACK Scan Detection
    ack_ports = detectors['ack'].get(src_ip, set())
    if len(ack_ports) > THRESHOLDS['ack'] and 'ACK_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(ack_ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['ack'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("ACK_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": len(ack_ports),
            "start_time": start_time,
            "duration": duration
        })
    
    # UDP Scan Detection
    udp_ports = detectors['udp'].get(src_ip, set())
    if len(udp_ports) > THRESHOLDS['udp'] and 'UDP_SCAN' not in alerted_ips[src_ip]:
        port_list = sorted(udp_ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['udp'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("UDP_SCAN", src_ip, {
            "ports": ", ".join(port_list),
            "total_ports": len(udp_ports),
            "start_time": start_time,
            "duration": duration
        })
    
    # Service Detection
    service_count = sum(detectors['service_probe'].get(src_ip, {}).values())
    if (service_count > THRESHOLDS['service_probe'] and 
        'SERVICE_PROBE' not in alerted_ips[src_ip] and
        'STEALTH_SCAN' not in alerted_ips[src_ip]):
        
        ports = list(detectors['service_probe'][src_ip].keys())
        port_list = sorted(ports)[:MAX_PORTS_IN_ALERT]
        ts_list = timestamps['service_probe'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("SERVICE_PROBE", src_ip, {
            "ports": ", ".join(port_list),
            "probe_count": service_count,
            "start_time": start_time,
            "duration": duration
        })
    
    # OS Fingerprinting Detection
    os_count = detectors['os_fingerprint'].get(src_ip, 0)
    if (os_count > THRESHOLDS['os_fingerprint'] and 
        'OS_FINGERPRINT' not in alerted_ips[src_ip] and
        'STEALTH_SCAN' not in alerted_ips[src_ip]):
        
        ts_list = timestamps['os_fingerprint'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("OS_FINGERPRINT", src_ip, {
            "probe_count": os_count,
            "start_time": start_time,
            "duration": duration
        })
    
    # ICMP Ping Scan Detection
    icmp_count = len(detectors['icmp'].get(src_ip, []))
    if icmp_count > THRESHOLDS['icmp'] and 'ICMP_PING_SCAN' not in alerted_ips[src_ip]:
        ts_list = detectors['icmp'].get(src_ip, [])
        start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
        duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
        
        log_alert("ICMP_PING_SCAN", src_ip, {
            "ping_count": icmp_count,
            "start_time": start_time,
            "duration": duration
        })

# --- Save JSON output ---
if args.json_output:
    try:
        with open(args.json_output, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"\nAlerts saved to {args.json_output}")
    except Exception as e:
        logger.error(f"Failed to save JSON: {str(e)}")

print("\nScan analysis complete.Detected Threats Logged ")
print(f"  Total Alerts: {len(alerts)}")
