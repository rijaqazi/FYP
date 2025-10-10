#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import logging
from collections import defaultdict, deque

# -------------------------
# Shared utilities & config
# -------------------------
def unified_log_alert(alerts_list, alerted_set, log_file_handle, alert_type, src_ip,
                      dst_ip="N/A", src_mac="N/A", claimed_mac="N/A", previous_mac="N/A",
                      ports="", total_ports=0, start_time="N/A", duration=0.0):
    
 
    key = (alert_type, src_ip, dst_ip, src_mac, claimed_mac, str(previous_mac))
    if key in alerted_set:
        return
    alerted_set.add(key)

    # format floating duration to 1 decimal as in your icmp style
    duration_f = float(duration)
    start_time_str = start_time if start_time else "N/A"

    alert_str = (
        f"[ALERT] {alert_type.upper()} from {src_ip}"
        f" | Target_IP: {dst_ip}"
        f" | SRC_MAC: {src_mac}"
        f" | Claimed_MAC: {claimed_mac if claimed_mac else 'N/A'}"
        f" | Previous_MAC: {previous_mac if claimed_mac else 'N/A'}"
        f" | Ports: {ports}"
        f" | Ports Scanned: {total_ports}"
        f" | Start: {start_time_str}"
        f" | Duration: {duration_f:.1f}s"
    )

    # print red
    print(f"\033[91m{alert_str}\033[0m")

    # write to file if provided
    if log_file_handle:
        try:
            log_file_handle.write(alert_str + "\n")
            log_file_handle.flush()
        except Exception:
            pass

    # append to alerts_list (json-friendly)
    alerts_list.append({
        "timestamp": time.time(),
        "type": alert_type,
        "source_ip": src_ip,
        "target_ip": dst_ip,
        "src_mac": src_mac,
        "claimed_mac": claimed_mac if claimed_mac else "N/A",
        "previous_mac": previous_mac if previous_mac else "N/A",
        "ports": ports,
        "ports_scanned": total_ports,
        "start_time": start_time_str,
        "duration_seconds": round(duration_f, 1)
    })


# -------------------------
# Packet Filtering Functions
# -------------------------
def filter_packets_by_protocol(packets, protocols):
    """
    Filter packets to only include those with the specified protocols
    """
    filtered_packets = []
    
    for packet in packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            
            # Check if packet contains any of the requested protocols
            for protocol in protocols:
                if protocol in layers:
                    filtered_packets.append(packet)
                    break
                    
        except Exception:
            continue
            
    return filtered_packets


def filter_nmap_packets(packets):
    """Filter packets relevant for Nmap detection"""
    return filter_packets_by_protocol(packets, ['tcp', 'udp', 'icmp'])


def filter_arp_packets(packets):
    """Filter packets relevant for ARP detection"""
    return filter_packets_by_protocol(packets, ['arp'])


def filter_icmp_packets(packets):
    """Filter packets relevant for ICMP detection"""
    return filter_packets_by_protocol(packets, ['icmp'])


# -------------------------
# NMAP detection (EXACTLY as in your separate nmap.py)
# -------------------------
def detect_nmap(packets, alerts_list, alerted_set, log_file_handle):
    # First filter packets to only those relevant for Nmap detection
    nmap_packets = filter_nmap_packets(packets)
    print(f"Processing {len(nmap_packets)} packets for Nmap detection")
    
    import logging as _logging
    logger = _logging.getLogger('nmap_detector')
    logger.setLevel(_logging.INFO)

    SCAN_WINDOW = 10  # Seconds for scan detection
    MAX_PORTS_IN_ALERT = 15

    THRESHOLDS = {
        'tcp': 15, 'udp': 10, 'syn': 5, 'fin': 5, 'xmas': 5, 'null': 5,
        'ack': 10, 'os_fingerprint': 2, 'service_probe': 3,
        'full_port': 50, 'icmp': 5
    }

    detectors = {
        'tcp': defaultdict(set), 'udp': defaultdict(set), 'syn': defaultdict(set),
        'fin': defaultdict(set), 'xmas': defaultdict(set), 'null': defaultdict(set),
        'ack': defaultdict(set),
        'service_probe': defaultdict(lambda: defaultdict(int)),
        'icmp': defaultdict(list),
        'os_fingerprint': defaultdict(int)
    }

    timestamps = {scan_type: defaultdict(list) for scan_type in detectors.keys()}
    mac_addresses = {}
    alerted_ips = defaultdict(set)

    # Packet Processing
    for packet in nmap_packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            frame = layers.get('frame', {})
            ip_layer = layers.get('ip', {})
            eth_layer = layers.get('eth', {})

            src_ip = ip_layer.get('ip.src', '')
            src_mac = eth_layer.get('eth.src', '')
            timestamp = float(frame.get('frame.time_epoch', 0))

            if not src_ip or not timestamp:
                continue

            if 'tcp' in layers:
                tcp = layers['tcp']
                flags = tcp.get('tcp.flags_tree', {})
                dst_port = tcp.get('tcp.dstport', '')
                
                if flags.get('tcp.flags.syn') == '1' and flags.get('tcp.flags.ack') == '0':
                    detectors['syn'][src_ip].add(dst_port)
                    timestamps['syn'][src_ip].append(timestamp)
                
                elif (int(flags.get('tcp.flags.fin', 0 )) + 
                      int(flags.get('tcp.flags.psh', 0 )) +
                      int(flags.get('tcp.flags.urg', 0 )) >= 2 and 
                      flags.get('tcp.flags.syn') == '0' and 
                      flags.get('tcp.flags.ack') == '0'):
                    detectors['xmas'][src_ip].add(dst_port)
                    timestamps['xmas'][src_ip].append(timestamp)
                    
                elif (flags.get('tcp.flags.fin') == '1' and 
                      flags.get('tcp.flags.syn') == '0' and
                      flags.get('tcp.flags.ack') == '0'):
                    detectors['fin'][src_ip].add(dst_port)
                    timestamps['fin'][src_ip].append(timestamp)
                
                elif all(flags.get(f'tcp.flags.{flag}', '0') == '0' 
                         for flag in ['syn', 'ack', 'fin', 'psh', 'urg', 'rst']):
                    detectors['null'][src_ip].add(dst_port)
                    timestamps['null'][src_ip].append(timestamp)
                
                elif flags.get('tcp.flags.ack') == '1' and flags.get('tcp.flags.syn') == '0':
                    detectors['ack'][src_ip].add(dst_port)
                    timestamps['ack'][src_ip].append(timestamp)
                
                if int(tcp.get('tcp.len', 0)) > 0 and dst_port:
                    detectors['service_probe'][src_ip][dst_port] += 1
                    timestamps['service_probe'][src_ip].append(timestamp)
                
                if 'tcp.options' in tcp:
                    detectors['os_fingerprint'][src_ip] += 1
                    timestamps['os_fingerprint'][src_ip].append(timestamp)
            
            elif 'udp' in layers:
                udp = layers['udp']
                dst_port = udp.get('udp.dstport', '')
                if dst_port:
                    detectors['udp'][src_ip].add(dst_port)
                    timestamps['udp'][src_ip].append(timestamp)
            
            elif 'icmp' in layers:
                icmp = layers['icmp']
                if icmp.get('icmp.type') == '8':
                    detectors['icmp'][src_ip].append(timestamp)
            
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
        syn_ports = detectors['syn'].get(src_ip, set())
        syn_count = len(syn_ports)
        syn_ts_list = timestamps['syn'].get(src_ip, [])
        
        os_count = detectors['os_fingerprint'].get(src_ip, 0)
        service_count = sum(detectors['service_probe'].get(src_ip, {}).values())

        start_time = time.ctime(min(syn_ts_list)) if syn_ts_list else "N/A"
        syn_duration = max(syn_ts_list) - min(syn_ts_list) if len(syn_ts_list) > 1 else 0

        has_syn_scan = syn_count >= THRESHOLDS['syn']
        has_os_fingerprinting = os_count >= THRESHOLDS['os_fingerprint']
        has_service_probes = service_count >= THRESHOLDS['service_probe']
        
        if (has_syn_scan and has_os_fingerprinting and has_service_probes and
            'STEALTH_SCAN' not in alerted_ips[src_ip]):
            port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "STEALTH_SCAN", src_ip, dst_ip="N/A", src_mac=src_mac,
                              claimed_mac="N/A", previous_mac="N/A",
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=syn_duration)
            alerted_ips[src_ip].update(['SYN_SCAN', 'OS_FINGERPRINT', 'SERVICE_PROBE'])
        
        elif syn_count > THRESHOLDS['full_port'] and 'FULL_PORT_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "FULL_PORT_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=syn_duration)

        # --- Individual Scan Detections ---
        if syn_count > THRESHOLDS['syn'] and 'SYN_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
            duration = max(syn_ts_list) - min(syn_ts_list) if len(syn_ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "SYN_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        fin_ports = detectors['fin'].get(src_ip, set())
        if len(fin_ports) > THRESHOLDS['fin'] and 'FIN_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(fin_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['fin'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "FIN_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        xmas_ports = detectors['xmas'].get(src_ip, set())
        if len(xmas_ports) > THRESHOLDS['xmas'] and 'XMAS_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(xmas_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['xmas'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "XMAS_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        null_ports = detectors['null'].get(src_ip, set())
        if len(null_ports) > THRESHOLDS['null'] and 'NULL_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(null_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['null'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "NULL_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        ack_ports = detectors['ack'].get(src_ip, set())
        if len(ack_ports) > THRESHOLDS['ack'] and 'ACK_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(ack_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['ack'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "ACK_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        udp_ports = detectors['udp'].get(src_ip, set())
        if len(udp_ports) > THRESHOLDS['udp'] and 'UDP_SCAN' not in alerted_ips[src_ip]:
            port_list = sorted(udp_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['udp'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "UDP_SCAN", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        service_count = sum(detectors['service_probe'].get(src_ip, {}).values())
        if service_count > THRESHOLDS['service_probe'] and 'SERVICE_PROBE' not in alerted_ips[src_ip]:
            ports = list(detectors['service_probe'][src_ip].keys())
            port_list = sorted(ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['service_probe'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "SERVICE_PROBE", src_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration)
        
        if os_count > THRESHOLDS['os_fingerprint'] and 'OS_FINGERPRINT' not in alerted_ips[src_ip]:
            ts_list = timestamps['os_fingerprint'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "OS_FINGERPRINT", src_ip, src_mac=src_mac,
                              ports="", total_ports=0,
                              start_time=start_time, duration=duration)
        
        icmp_count = len(detectors['icmp'].get(src_ip, []))
        if icmp_count > THRESHOLDS['icmp'] and 'ICMP_PING_SCAN' not in alerted_ips[src_ip]:
            ts_list = detectors['icmp'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "ICMP_PING_SCAN", src_ip, src_mac=src_mac,
                              ports="", total_ports=0, start_time=start_time, duration=duration)

    return

# -------------------------
# ARP detection (EXACTLY as in your separate arp.py)
# -------------------------
def detect_arp(packets, alerts_list, alerted_set, log_file_handle):
    # First filter packets to only ARP packets
    arp_packets = filter_arp_packets(packets)
    print(f"Processing {len(arp_packets)} packets for ARP detection")
    
    import logging as _logging
    logger = _logging.getLogger("arp_detector")
    logger.setLevel(_logging.INFO)

    timestamps = defaultdict(list)
    arp_table = {}             # IP -> MAC mapping
    mac_to_ips = defaultdict(set)
    flood_window = defaultdict(lambda: deque(maxlen=20))

    for packet in arp_packets:
        try:
            layers = packet.get("_source", {}).get("layers", {})
            eth = layers.get("eth", {})
            arp = layers.get("arp", {})
            frame = layers.get("frame", {})

            src_mac = eth.get("eth.src", "")
            src_ip = arp.get("arp.src.proto_ipv4", "")
            dst_ip = arp.get("arp.dst.proto_ipv4", "")
            claimed_mac = arp.get("arp.dst.hw_mac", "")
            epoch = float(frame.get("frame.time_epoch", 0))

            if not src_ip:
                continue

            if epoch:
                timestamps[src_ip].append(epoch)
                flood_window[src_ip].append(epoch)

            start_time = time.ctime(min(timestamps[src_ip])) if timestamps[src_ip] else "N/A"
            duration = (max(timestamps[src_ip]) - min(timestamps[src_ip])) if len(timestamps[src_ip]) > 1 else 0

            # ARP Spoof
            if src_ip in arp_table and arp_table[src_ip] != src_mac:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ARP_SPOOF", src_ip, dst_ip, src_mac, claimed_mac,
                                  previous_mac=arp_table[src_ip],
                                  ports="", total_ports=0, start_time=start_time, duration=duration)

            # Gratuitous ARP
            if src_ip == dst_ip and claimed_mac:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "GRATUITOUS_ARP", src_ip, dst_ip, src_mac, claimed_mac,
                                  ports="", total_ports=0, start_time=start_time, duration=duration)

            # Broadcast Spoof
            if src_ip == dst_ip and claimed_mac:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "BROADCAST_SPOOF", src_ip, dst_ip, src_mac, claimed_mac,
                                  ports="", total_ports=0, start_time=start_time, duration=duration)

            # ARP Flood
            if len(flood_window[src_ip]) >= 5:
                if flood_window[src_ip][-1] - flood_window[src_ip][0] < 3:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "ARP_FLOOD", src_ip, dst_ip, src_mac,
                                      ports="", total_ports=0, start_time=start_time, duration=duration)

            # MAC Conflict
            if src_mac:
                mac_to_ips[src_mac].add(src_ip)
                if len(mac_to_ips[src_mac]) > 1:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "MAC_CONFLICT", src_ip, dst_ip, src_mac, claimed_mac,
                                      ports="", total_ports=0, start_time=start_time, duration=duration)

            
		#MITM
            if dst_ip in arp_table and arp_table[dst_ip] != src_mac:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ARP_MITM", src_ip, dst_ip, src_mac, claimed_mac,
                                  previous_mac=arp_table[dst_ip], ports="", total_ports=0,
                                  start_time=start_time, duration=duration)

            if src_ip not in arp_table:
                arp_table[src_ip] = src_mac

        except Exception as e:
            logger.error(f"Processing error: {str(e)}")

    return

# -------------------------
# ICMP detection (EXACTLY as in your separate icmp.py)
# -------------------------
def detect_icmp(packets, alerts_list, alerted_set, log_file_handle):
    # First filter packets to only ICMP packets
    icmp_packets = filter_icmp_packets(packets)
    print(f"Processing {len(icmp_packets)} packets for ICMP detection")
    
    FLOOD_WINDOW = 5  # seconds
    THRESHOLDS = {
        'echo_flood': 50,
        'smurf': 20,
        'timestamp_flood': 20,
        'mask_flood': 15,
        'fragment_flood': 10
    }

    alerted_ips = set()  # to mimic original behavior (one alert per type,src per run)

    times = {
        'echo_flood': defaultdict(list),
        'smurf': defaultdict(list),
        'timestamp_flood': defaultdict(list),
        'mask_flood': defaultdict(list),
        'fragment_flood': defaultdict(list)
    }

    for pkt in icmp_packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        ip_layer = layers.get("ip", {})
        icmp = layers.get("icmp", {})
        eth_layer = layers.get("eth", {})

        icmp_type = icmp.get("icmp.type", '')
        ts = float(frame.get("frame.time_epoch", 0))
        src_ip = ip_layer.get("ip.src", "")
        dst_ip = ip_layer.get("ip.dst", "")
        src_mac = eth_layer.get("eth.src", "N/A")

        if not src_ip or not ts:
            continue

        # ICMP Echo Request Flood
        if icmp_type == "8":
            times['echo_flood'][src_ip].append(ts)
            times['echo_flood'][src_ip] = [t for t in times['echo_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
            if len(times['echo_flood'][src_ip]) >= THRESHOLDS['echo_flood']:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ICMP Echo Request Flood", src_ip,
                                  dst_ip, src_mac, ports="", total_ports=0,
                                  start_time=time.ctime(min(times['echo_flood'][src_ip])),
                                  duration=max(times['echo_flood'][src_ip]) - min(times['echo_flood'][src_ip]))

        # Smurf Attack (ICMP Echo to broadcast)
        if icmp_type == "8" and dst_ip.endswith(".255"):
            times['smurf'][src_ip].append(ts)
            times['smurf'][src_ip] = [t for t in times['smurf'][src_ip] if ts - t <= FLOOD_WINDOW]
            if len(times['smurf'][src_ip]) >= THRESHOLDS['smurf']:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "Smurf Attack", src_ip, dst_ip, src_mac,
                                  ports="", total_ports=0,
                                  start_time=time.ctime(min(times['smurf'][src_ip])),
                                  duration=max(times['smurf'][src_ip]) - min(times['smurf'][src_ip]))

        # Timestamp Request Flood
        if icmp_type == "13":
            times['timestamp_flood'][src_ip].append(ts)
            times['timestamp_flood'][src_ip] = [t for t in times['timestamp_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
            if len(times['timestamp_flood'][src_ip]) >= THRESHOLDS['timestamp_flood']:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ICMP Timestamp Request Flood", src_ip, dst_ip, src_mac,
                                  ports="", total_ports=0,
                                  start_time=time.ctime(min(times['timestamp_flood'][src_ip])),
                                  duration=max(times['timestamp_flood'][src_ip]) - min(times['timestamp_flood'][src_ip]))

        # Address Mask Request Flood
        if icmp_type == "17":
            times['mask_flood'][src_ip].append(ts)
            times['mask_flood'][src_ip] = [t for t in times['mask_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
            if len(times['mask_flood'][src_ip]) >= THRESHOLDS['mask_flood']:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ICMP Address Mask Request Flood", src_ip, dst_ip, src_mac,
                                  ports="", total_ports=0,
                                  start_time=time.ctime(min(times['mask_flood'][src_ip])),
                                  duration=max(times['mask_flood'][src_ip]) - min(times['mask_flood'][src_ip]))

        # ICMP Fragmentation Flood
        ip_flags = ip_layer.get("ip.flags_tree", {})
        frag_offset = int(ip_layer.get("ip.frag_offset", '0') or 0)
        more_frag = ip_flags.get("ip.flags.mf", '0')

        if icmp_type and (more_frag == '1' or frag_offset > 0):
            key = (src_ip, dst_ip)
            times['fragment_flood'][key].append(ts)
            times['fragment_flood'][key] = [t for t in times['fragment_flood'][key] if ts - t <= FLOOD_WINDOW]
            if len(times['fragment_flood'][key]) >= THRESHOLDS['fragment_flood']:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ICMP Fragmentation Flood", src_ip, dst_ip, src_mac,
                                  ports="", total_ports=0,
                                  start_time=time.ctime(min(times['fragment_flood'][key])),
                                  duration=max(times['fragment_flood'][key]) - min(times['fragment_flood'][key]))

    return


# -------------------------
# RST Attack Detection
# -------------------------
def detect_rst_attack(packets, alerts_list, alerted_set, log_file_handle):
    """
    Detect RST flood attacks (hping3 -R -p 80 --flood)
    """
    import logging as _logging
    logger = _logging.getLogger('rst_detector')
    logger.setLevel(_logging.INFO)
    
    # Thresholds - adjust these based on your network
    RST_WINDOW = 5  # seconds for detection window
    RST_THRESHOLD = 100  # number of RST packets to trigger alert
    
    rst_detectors = defaultdict(list)
    rst_timestamps = defaultdict(list)
    
    # Filter only TCP packets
    tcp_packets = filter_packets_by_protocol(packets, ['tcp'])
    
    for packet in tcp_packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            frame = layers.get('frame', {})
            ip_layer = layers.get('ip', {})
            eth_layer = layers.get('eth', {})
            tcp_layer = layers.get('tcp', {})

            src_ip = ip_layer.get('ip.src', '')
            dst_ip = ip_layer.get('ip.dst', '')
            src_mac = eth_layer.get('eth.src', '')
            timestamp = float(frame.get('frame.time_epoch', 0))
            dst_port = tcp_layer.get('tcp.dstport', '')

            if not src_ip or not timestamp:
                continue

            # Check for RST flag
            flags = tcp_layer.get('tcp.flags_tree', {})
            rst_flag = flags.get('tcp.flags.rst', '0') == '1'
            
            if rst_flag and dst_port:
                rst_detectors[src_ip].append((timestamp, dst_port))
                rst_timestamps[src_ip].append(timestamp)
                
                # Clean up old timestamps
                rst_timestamps[src_ip] = [
                    ts for ts in rst_timestamps[src_ip] 
                    if (timestamp - ts) <= RST_WINDOW
                ]
                
        except Exception as e:
            logger.error(f"RST detection error: {str(e)}")
    
    # Check for RST flood
    for src_ip, timestamps in rst_timestamps.items():
        if len(timestamps) >= RST_THRESHOLD:
            # Get target ports
            target_ports = set()
            for ts, port in rst_detectors[src_ip]:
                if max(timestamps) - ts <= RST_WINDOW:
                    target_ports.add(port)
            
            start_time = time.ctime(min(timestamps)) if timestamps else "N/A"
            duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
            
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                            "RST_FLOOD", src_ip, dst_ip="Multiple", src_mac=src_mac,
                            ports=", ".join(sorted(target_ports)), 
                            total_ports=len(target_ports),
                            start_time=start_time, duration=duration)


# -------------------------
# Spoofed SYN Flood Detection
# -------------------------
def detect_spoofed_syn_flood(packets, alerts_list, alerted_set, log_file_handle):
    """
    Detect spoofed SYN flood attacks (hping3 -S -p 80 --flood --rand-source)
    """
    import logging as _logging
    logger = _logging.getLogger('spoofed_syn_detector')
    logger.setLevel(_logging.INFO)
    
    # Thresholds - adjust these based on your network
    SYN_WINDOW = 5  # seconds for detection window
    UNIQUE_IP_THRESHOLD = 50  # number of unique source IPs to trigger alert
    TOTAL_SYN_THRESHOLD = 500  # total SYN packets to trigger alert
    
    syn_detectors = defaultdict(list)
    source_ips = defaultdict(set)
    target_ports = defaultdict(set)
    
    # Filter only TCP packets
    tcp_packets = filter_packets_by_protocol(packets, ['tcp'])
    
    for packet in tcp_packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            frame = layers.get('frame', {})
            ip_layer = layers.get('ip', {})
            eth_layer = layers.get('eth', {})
            tcp_layer = layers.get('tcp', {})

            src_ip = ip_layer.get('ip.src', '')
            dst_ip = ip_layer.get('ip.dst', '')
            src_mac = eth_layer.get('eth.src', '')
            timestamp = float(frame.get('frame.time_epoch', 0))
            dst_port = tcp_layer.get('tcp.dstport', '')

            if not src_ip or not timestamp or not dst_ip:
                continue

            # Check for SYN flag (SYN without ACK)
            flags = tcp_layer.get('tcp.flags_tree', {})
            syn_flag = flags.get('tcp.flags.syn', '0') == '1'
            ack_flag = flags.get('tcp.flags.ack', '0') == '1'
            
            if syn_flag and not ack_flag and dst_port:
                # Track by destination IP
                syn_detectors[dst_ip].append(timestamp)
                source_ips[dst_ip].add(src_ip)
                target_ports[dst_ip].add(dst_port)
                
                # Clean up old timestamps
                syn_detectors[dst_ip] = [
                    ts for ts in syn_detectors[dst_ip] 
                    if (timestamp - ts) <= SYN_WINDOW
                ]
                
        except Exception as e:
            logger.error(f"Spoofed SYN detection error: {str(e)}")
    
    # Check for spoofed SYN flood
    for dst_ip, timestamps in syn_detectors.items():
        unique_ips_count = len(source_ips.get(dst_ip, set()))
        total_syn_count = len(timestamps)
        
        if (unique_ips_count >= UNIQUE_IP_THRESHOLD and 
            total_syn_count >= TOTAL_SYN_THRESHOLD):
            
            start_time = time.ctime(min(timestamps)) if timestamps else "N/A"
            duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
            
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                            "SPOOFED_SYN_FLOOD", src_ip="Multiple", dst_ip=dst_ip, 
                            src_mac="N/A",
                            ports=", ".join(sorted(target_ports.get(dst_ip, set()))), 
                            total_ports=len(target_ports.get(dst_ip, set())),
                            start_time=start_time, duration=duration)


# -------------------------
# Parse args with --mode option
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Unified Detection Engine")
    parser.add_argument("json_file", help="Path to parsed JSON packet file")
    parser.add_argument("--mode", choices=["nmap", "arp", "icmp", "all"], default="all",
                        help="Detection mode: nmap, arp, icmp, or all (default)")
    parser.add_argument("--log", help="Path to log file", default=None)
    parser.add_argument("--json-out", dest="json_out", help="Path to save alerts in JSON", default=None)
    return parser.parse_args()

# -------------------------
# Main: parse args and run
# -------------------------
def main():
    args = parse_args()

    if not os.path.exists(args.json_file):
        print(f"Error: File not found: {args.json_file}")
        sys.exit(1)

    try:
        with open(args.json_file, "r") as f:
            packets = json.load(f)
    except Exception as e:
        print(f"JSON Error: {str(e)}")
        sys.exit(1)

    # open log file if provided (append mode)
    log_fh = None
    if args.log:
        try:
            log_fh = open(args.log, "a")
        except Exception as e:
            print(f"Could not open log file {args.log}: {e}")
            log_fh = None

    alerts = []
    alerted_set = set()  # dedup across all detectors

    # run detectors based on mode
    if args.mode in ["nmap", "all"]:
        print("Running Nmap detection...")
        detect_nmap(packets, alerts, alerted_set, log_fh)
    
    if args.mode in ["arp", "all"]:
        print("Running ARP detection...")
        detect_arp(packets, alerts, alerted_set, log_fh)
    
    if args.mode in ["icmp", "all"]:
        print("Running ICMP detection...")
        detect_icmp(packets, alerts, alerted_set, log_fh)

    # save combined json if requested
    if args.json_out:
        try:
            with open(args.json_out, "w") as jf:
                json.dump(alerts, jf, indent=2)
            print(f"\nAlerts saved to {args.json_out}")
        except Exception as e:
            print(f"Failed to save JSON: {str(e)}")

    if log_fh:
        log_fh.close()

    print(f"\n{args.mode.upper()} analysis complete. Detected Threats Logged")
    print(f"  Total Alerts: {len(alerts)}")

if __name__ == "__main__":
    main()
