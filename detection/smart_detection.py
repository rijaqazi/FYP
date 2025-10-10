import argparse
import sys
import os
import json
import time
from collections import defaultdict, deque
import logging as _logging

# -------------------------
# Packet Filtering Functions
# -------------------------
def get_packet_protocol(packet):
    """Determine the primary protocol of a packet."""
    try:
        layers = packet.get('_source', {}).get('layers', {})
        if 'arp' in layers:
            return 'arp'
        elif 'icmp' in layers:
            return 'icmp'
        elif 'tcp' in layers:
            return 'tcp'
        elif 'udp' in layers:
            return 'udp'
        return None
    except Exception:
        return None

def filter_packets_by_protocol(packets, protocols):
    """Filter packets to only include those with the specified protocols."""
    filtered_packets = []
    for packet in packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            for protocol in protocols:
                if protocol in layers:
                    filtered_packets.append(packet)
                    break
        except Exception:
            continue
    return filtered_packets

def filter_nmap_packets(packets):
    """Filter packets relevant for Nmap detection (TCP, UDP only)."""
    return filter_packets_by_protocol(packets, ['tcp', 'udp'])

def filter_arp_packets(packets):
    """Filter packets relevant for ARP detection."""
    return filter_packets_by_protocol(packets, ['arp'])

def filter_icmp_packets(packets):
    """Filter packets relevant for ICMP detection."""
    return filter_packets_by_protocol(packets, ['icmp'])

# -------------------------
# Alert Function
# -------------------------
def unified_log_alert(alerts_list, alerted_set, log_file_handle, alert_type, src_ip,
                      dst_ip="N/A", src_mac="N/A", claimed_mac="N/A", previous_mac="N/A",
                      ports="", total_ports=0, start_time="N/A", duration=0.0, packet_count=0):
    """
    Produce the same '[ALERT] ...' string format, write to log file, and append to alerts_list.
    Dedup by (alert_type, src_ip, dst_ip, src_mac, claimed_mac, previous_mac).
    """
    logger = _logging.getLogger('alert_logger')
    key = (alert_type, src_ip, dst_ip, src_mac, claimed_mac, str(previous_mac))
    if key in alerted_set:
        return

    alerted_set.add(key)

    try:
        duration_f = float(duration)
    except Exception:
        duration_f = 0.0

    duration_str = "N/A" if duration_f == 0.0 else f"{duration_f:.6f}s"
    start_time_str = start_time if start_time else "N/A"
    count_str = f" | Count: {packet_count}" if packet_count > 0 else ""

    alert_str = (
        f"[ALERT] {alert_type.upper()} from {src_ip}"
        f" | Target_IP: {dst_ip}"
        f" | SRC_MAC: {src_mac}"
        f" | Claimed_MAC: {claimed_mac if claimed_mac else 'N/A'}"
        f" | Previous_MAC: {previous_mac if previous_mac else 'N/A'}"
        f" | Ports: {ports}"
        f" | Ports Scanned: {total_ports}"
        f"{count_str}"
        f" | Start: {start_time_str}"
        f" | Duration: {duration_str}"
    )

    print(f"\033[91m{alert_str}\033[0m")
    if log_file_handle:
        try:
            log_file_handle.write(alert_str + "\n")
            log_file_handle.flush()
        except Exception:
            pass

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
        "packet_count": packet_count,
        "start_time": start_time_str,
        "duration_seconds": None if duration_str == "N/A" else round(duration_f, 6)
    })

# -------------------------
# Nmap Detection
# -------------------------
def detect_nmap(packets, alerts_list, alerted_set, log_file_handle):
    nmap_packets = filter_nmap_packets(packets)
    logger = _logging.getLogger('nmap_detector')
    logger.setLevel(_logging.INFO)
    logger.info(f"Processing {len(nmap_packets)} packets for Nmap detection")

    SCAN_WINDOW = 10
    MAX_PORTS_IN_ALERT = 15
    THRESHOLDS = {
        'tcp': 15, 'udp': 10, 'syn': 5, 'fin': 5, 'xmas': 5, 'null': 5,
        'ack': 10, 'os_fingerprint': 15, 'full_port': 50, 'rst_flood': 30, 'spoofed_syn_flood': 50
    }

    detectors = {
        'tcp': defaultdict(set), 'udp': defaultdict(set), 'syn': defaultdict(set),
        'fin': defaultdict(set), 'xmas': defaultdict(set), 'null': defaultdict(set),
        'ack': defaultdict(set), 'os_fingerprint': defaultdict(int)
    }
    timestamps = {scan_type: defaultdict(list) for scan_type in detectors.keys()}
    mac_addresses = {}
    dst_ips = defaultdict(set)
    alerted_ips = defaultdict(set)
    rst_packets = defaultdict(list)
    spoofed_syn_packets = defaultdict(list)

    for packet in nmap_packets:
        try:
            layers = packet.get('_source', {}).get('layers', {})
            frame = layers.get('frame', {})
            ip_layer = layers.get('ip', {})
            eth_layer = layers.get('eth', {})

            src_ip = ip_layer.get('ip.src', '')
            dst_ip = ip_layer.get('ip.dst', '')
            src_mac = eth_layer.get('eth.src', '')
            timestamp = float(frame.get('frame.time_epoch', 0))

            if not src_ip or not timestamp:
                continue

            if src_mac:
                mac_addresses[src_ip] = src_mac
            if dst_ip:
                dst_ips[src_ip].add(dst_ip)

            if 'tcp' in layers:
                tcp = layers['tcp']
                flags = tcp.get('tcp.flags_tree', {})
                dst_port = tcp.get('tcp.dstport', '')

                if flags.get('tcp.flags.syn') == '1' and flags.get('tcp.flags.ack') == '0':
                    detectors['syn'][src_ip].add(dst_port)
                    timestamps['syn'][src_ip].append(timestamp)
                elif (int(flags.get('tcp.flags.fin', 0)) +
                      int(flags.get('tcp.flags.psh', 0)) +
                      int(flags.get('tcp.flags.urg', 0)) >= 2 and
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
                if 'tcp.options' in tcp:
                    detectors['os_fingerprint'][src_ip] += 1
                    timestamps['os_fingerprint'][src_ip].append(timestamp)
                if flags.get('tcp.flags.rst') == '1':
                    rst_packets[src_ip].append(timestamp)
                    rst_packets[src_ip] = [t for t in rst_packets[src_ip] if timestamp - t <= SCAN_WINDOW]
                    if len(rst_packets[src_ip]) >= THRESHOLDS['rst_flood'] and rst_packets[src_ip]:
                        unified_log_alert(
                            alerts_list, alerted_set, log_file_handle,
                            "RST_FLOOD", src_ip,
                            dst_ip=list(dst_ips[src_ip])[-1] if dst_ips[src_ip] else "N/A",
                            src_mac=src_mac, ports="", total_ports=0,
                            start_time=time.ctime(min(rst_packets[src_ip])),
                            duration=max(rst_packets[src_ip]) - min(rst_packets[src_ip]),
                            packet_count=len(rst_packets[src_ip])
                        )
                if flags.get('tcp.flags.syn') == '1' and flags.get('tcp.flags.ack') == '0':
                    key = (src_ip, dst_ip)
                    spoofed_syn_packets[key].append(timestamp)
                    spoofed_syn_packets[key] = [t for t in spoofed_syn_packets[key] if timestamp - t <= SCAN_WINDOW]
                    if len(spoofed_syn_packets[key]) >= THRESHOLDS['spoofed_syn_flood'] and spoofed_syn_packets[key]:
                        unified_log_alert(
                            alerts_list, alerted_set, log_file_handle,
                            "SPOOFED_SYN_FLOOD", src_ip,
                            dst_ip=dst_ip, src_mac=src_mac,
                            ports="", total_ports=0,
                            start_time=time.ctime(min(spoofed_syn_packets[key])),
                            duration=max(spoofed_syn_packets[key]) - min(spoofed_syn_packets[key]),
                            packet_count=len(spoofed_syn_packets[key])
                        )
            elif 'udp' in layers:
                udp = layers['udp']
                dst_port = udp.get('udp.dstport', '')
                if dst_port:
                    detectors['udp'][src_ip].add(dst_port)
                    timestamps['udp'][src_ip].append(timestamp)

            for scan_type in timestamps:
                if src_ip in timestamps[scan_type]:
                    timestamps[scan_type][src_ip] = [
                        ts for ts in timestamps[scan_type][src_ip]
                        if (timestamp - ts) <= SCAN_WINDOW
                    ]

        except Exception as e:
            logger.error(f"Processing error: {str(e)}")

    for src_ip in set(ip for detector in detectors.values() for ip in detector):
        src_mac = mac_addresses.get(src_ip, "N/A")
        dst_ip = list(dst_ips[src_ip])[-1] if dst_ips[src_ip] else "N/A"

        syn_ports = detectors['syn'].get(src_ip, set())
        syn_count = len(syn_ports)
        syn_ts_list = timestamps['syn'].get(src_ip, [])

        os_count = detectors['os_fingerprint'].get(src_ip, 0)

        start_time = time.ctime(min(syn_ts_list)) if syn_ts_list else "N/A"
        syn_duration = max(syn_ts_list) - min(syn_ts_list) if len(syn_ts_list) > 1 else 0

        if syn_count > THRESHOLDS['full_port'] and 'FULL_PORT_SCAN' not in alerted_ips[src_ip] and syn_ts_list:
            port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "FULL_PORT_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=syn_duration,
                              packet_count=len(syn_ts_list))
            alerted_ips[src_ip].add('FULL_PORT_SCAN')

        if syn_count > THRESHOLDS['syn'] and 'SYN_SCAN' not in alerted_ips[src_ip] and timestamps['syn'].get(src_ip, []):
            port_list = sorted(syn_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['syn'].get(src_ip, [])
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "SYN_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('SYN_SCAN')

        fin_ports = detectors['fin'].get(src_ip, set())
        if len(fin_ports) > THRESHOLDS['fin'] and 'FIN_SCAN' not in alerted_ips[src_ip] and timestamps['fin'].get(src_ip, []):
            port_list = sorted(fin_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['fin'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "FIN_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('FIN_SCAN')

        xmas_ports = detectors['xmas'].get(src_ip, set())
        if len(xmas_ports) > THRESHOLDS['xmas'] and 'XMAS_SCAN' not in alerted_ips[src_ip] and timestamps['xmas'].get(src_ip, []):
            port_list = sorted(xmas_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['xmas'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "XMAS_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('XMAS_SCAN')

        null_ports = detectors['null'].get(src_ip, set())
        if len(null_ports) > THRESHOLDS['null'] and 'NULL_SCAN' not in alerted_ips[src_ip] and timestamps['null'].get(src_ip, []):
            port_list = sorted(null_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['null'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "NULL_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('NULL_SCAN')

        ack_ports = detectors['ack'].get(src_ip, set())
        if len(ack_ports) > THRESHOLDS['ack'] and 'ACK_SCAN' not in alerted_ips[src_ip] and timestamps['ack'].get(src_ip, []):
            port_list = sorted(ack_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['ack'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "ACK_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('ACK_SCAN')

        udp_ports = detectors['udp'].get(src_ip, set())
        if len(udp_ports) > THRESHOLDS['udp'] and 'UDP_SCAN' not in alerted_ips[src_ip] and timestamps['udp'].get(src_ip, []):
            port_list = sorted(udp_ports)[:MAX_PORTS_IN_ALERT]
            ts_list = timestamps['udp'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "UDP_SCAN", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports=", ".join(port_list), total_ports=len(port_list),
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('UDP_SCAN')

        if os_count > THRESHOLDS['os_fingerprint'] and 'OS_FINGERPRINT' not in alerted_ips[src_ip] and timestamps['os_fingerprint'].get(src_ip, []):
            ts_list = timestamps['os_fingerprint'].get(src_ip, [])
            start_time = time.ctime(min(ts_list)) if ts_list else "N/A"
            duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0
            unified_log_alert(alerts_list, alerted_set, log_file_handle,
                              "OS_FINGERPRINT", src_ip, dst_ip=dst_ip, src_mac=src_mac,
                              ports="", total_ports=0,
                              start_time=start_time, duration=duration,
                              packet_count=len(ts_list))
            alerted_ips[src_ip].add('OS_FINGERPRINT')

# -------------------------
# ARP Detection
# -------------------------
def detect_arp(packets, alerts_list, alerted_set, log_file_handle):
    from collections import defaultdict, deque
    import time
    import logging as _logging

    arp_packets = filter_arp_packets(packets)
    logger = _logging.getLogger("arp_detector")
    logger.setLevel(_logging.INFO)
    logger.info(f"Processing {len(arp_packets)} packets for ARP detection")

    # === Ignore very low ARP traffic ===
    if len(arp_packets) < 10:
        logger.info("Skipping ARP detection (less than 10 packets)")
        return

    timestamps = defaultdict(list)
    arp_table = {}
    mac_to_ips = defaultdict(set)
    flood_window = defaultdict(lambda: deque(maxlen=50))  # Store timestamps for flood detection

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
            opcode = arp.get("arp.opcode", "")
            epoch = float(frame.get("frame.time_epoch", 0))

            if not src_ip:
                continue

            # === Handle missing destination IP (common in Gratuitous ARP) ===
            if not dst_ip:
                dst_ip = src_ip

            # Track packet timings
            if epoch:
                timestamps[src_ip].append(epoch)
                flood_window[src_ip].append(epoch)

            start_time = time.ctime(min(timestamps[src_ip])) if timestamps[src_ip] else "N/A"
            duration = (max(timestamps[src_ip]) - min(timestamps[src_ip])) if len(timestamps[src_ip]) > 1 else 0
            packet_count = len(timestamps[src_ip])

            # === Update MAC-to-IP Mapping early (important for MAC Conflict) ===
            mac_to_ips[src_mac].add(src_ip)

            # === MAC Conflict Detection ===
            if src_mac and len(mac_to_ips[src_mac]) > 1 and timestamps[src_ip]:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "MAC_CONFLICT", src_ip, dst_ip, src_mac, claimed_mac,
                                  ports="", total_ports=0, start_time=start_time, duration=duration,
                                  packet_count=len(mac_to_ips[src_mac]))

            # === Ignore infrequent ARP sources ===
            if packet_count < 5 or (duration > 10 and packet_count / max(duration, 1) < 1):
                continue

            # === ARP Spoof Detection ===
            if src_ip in arp_table and arp_table[src_ip] != src_mac and timestamps[src_ip]:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ARP_SPOOF", src_ip, dst_ip, src_mac, claimed_mac,
                                  previous_mac=arp_table[src_ip],
                                  ports="", total_ports=0, start_time=start_time, duration=duration,
                                  packet_count=packet_count)

            # === Fixed Gratuitous ARP Detection ===
            # Detects when a host announces itself, even if dst_ip is empty or claimed_mac is broadcast
            if (src_ip == dst_ip or dst_ip == "" or dst_ip is None) and timestamps[src_ip]:
                if claimed_mac.lower() in [src_mac.lower(), "ff:ff:ff:ff:ff:ff"]:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "GRATUITOUS_ARP", src_ip, dst_ip, src_mac, claimed_mac,
                                      ports="", total_ports=0, start_time=start_time, duration=duration,
                                      packet_count=packet_count)

            # === Broadcast Spoof Detection ===
            if claimed_mac and (claimed_mac.lower() == "ff:ff:ff:ff:ff:ff" or dst_ip == "255.255.255.255") and timestamps[src_ip]:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "BROADCAST_SPOOF", src_ip, dst_ip, src_mac, claimed_mac,
                                  ports="", total_ports=0, start_time=start_time, duration=duration,
                                  packet_count=packet_count)

            # === ARP Flood Detection (10+ packets in <5 sec) ===
            if len(flood_window[src_ip]) >= 10 and flood_window[src_ip][-1] - flood_window[src_ip][0] < 5:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ARP_FLOOD", src_ip, dst_ip, src_mac,
                                  ports="", total_ports=0, start_time=start_time, duration=duration,
                                  packet_count=len(flood_window[src_ip]))
                logger.info(f"ARP flood detected: {len(flood_window[src_ip])} packets from {src_ip}")

            # === ARP MITM Detection ===
            if opcode == "2" and dst_ip in arp_table and arp_table[dst_ip] != src_mac and timestamps[src_ip]:
                unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                  "ARP_MITM", src_ip, dst_ip, src_mac, claimed_mac,
                                  previous_mac=arp_table[dst_ip],
                                  ports="", total_ports=0, start_time=start_time, duration=duration,
                                  packet_count=packet_count)

            # === Update ARP Table ===
            if src_ip not in arp_table:
                arp_table[src_ip] = src_mac

        except Exception as e:
            logger.error(f"Processing error: {str(e)}")

# -------------------------
# ICMP Detection
# -------------------------
def detect_icmp(packets, alerts_list, alerted_set, log_file_handle):
    icmp_packets = filter_icmp_packets(packets)
    logger = _logging.getLogger("icmp_detector")
    logger.setLevel(_logging.INFO)
    logger.info(f"Processing {len(icmp_packets)} packets for ICMP detection")

    FLOOD_WINDOW = 5
    THRESHOLDS = {
        'echo_flood': 50, 'smurf': 20, 'timestamp_flood': 20, 'mask_flood': 15, 
    }
    times = {
        'echo_flood': defaultdict(list), 'smurf': defaultdict(list),
        'timestamp_flood': defaultdict(list), 'mask_flood': defaultdict(list),
        'fragment_flood': defaultdict(list)
    }
    ip_to_mac = defaultdict(lambda: "N/A")
    fragment_packets = defaultdict(list)
    alerted_ips = defaultdict(set)

    

    for pkt in icmp_packets:
        try:
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

            if src_mac != "N/A":
                ip_to_mac[src_ip] = src_mac

            if icmp_type == "8":
                times['echo_flood'][src_ip].append(ts)
                times['echo_flood'][src_ip] = [t for t in times['echo_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
                if len(times['echo_flood'][src_ip]) >= THRESHOLDS['echo_flood'] and 'ICMP ECHO REQUEST FLOOD' not in alerted_ips[src_ip] and times['echo_flood'][src_ip]:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "ICMP ECHO REQUEST FLOOD", src_ip, dst_ip, src_mac,
                                      ports="", total_ports=0,
                                      start_time=time.ctime(min(times['echo_flood'][src_ip])),
                                      duration=max(times['echo_flood'][src_ip]) - min(times['echo_flood'][src_ip]),
                                      packet_count=len(times['echo_flood'][src_ip]))
                    alerted_ips[src_ip].add('ICMP ECHO REQUEST FLOOD')
                    logger.info(f"Echo flood detected: {len(times['echo_flood'][src_ip])} packets from {src_ip}")

            if icmp_type == "8" and dst_ip.endswith(".255"):
                times['smurf'][src_ip].append(ts)
                times['smurf'][src_ip] = [t for t in times['smurf'][src_ip] if ts - t <= FLOOD_WINDOW]
                if len(times['smurf'][src_ip]) >= THRESHOLDS['smurf'] and 'SMURF ATTACK' not in alerted_ips[src_ip] and times['smurf'][src_ip]:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "SMURF ATTACK", src_ip, dst_ip, src_mac,
                                      ports="", total_ports=0,
                                      start_time=time.ctime(min(times['smurf'][src_ip])),
                                      duration=max(times['smurf'][src_ip]) - min(times['smurf'][src_ip]),
                                      packet_count=len(times['smurf'][src_ip]))
                    alerted_ips[src_ip].add('SMURF ATTACK')
                    logger.info(f"Smurf attack detected: {len(times['smurf'][src_ip])} packets from {src_ip}")

            # --- Improved ICMP Timestamp Flood Detection ---
            if icmp_type == "13":  # ICMP Timestamp Request
                current_time = ts
                times['timestamp_flood'][src_ip].append(current_time)

                # Keep only recent timestamps within window
                times['timestamp_flood'][src_ip] = [
                    t for t in times['timestamp_flood'][src_ip]
                    if current_time - t <= FLOOD_WINDOW
                ]

                pkt_count = len(times['timestamp_flood'][src_ip])

                # Calculate rate = packets per second (helps in adaptive detection)
                duration = max(1e-6, current_time - min(times['timestamp_flood'][src_ip]))  # prevent div/0
                rate = pkt_count / duration  # packets per second

                # Adaptive thresholds (both count and rate)
                if (
                    pkt_count >= THRESHOLDS['timestamp_flood']
                    and rate > 10  # customizable rate threshold
                    and 'ICMP TIMESTAMP REQUEST FLOOD' not in alerted_ips[src_ip]
                ):
                    unified_log_alert(
                        alerts_list, alerted_set, log_file_handle,
                        "ICMP TIMESTAMP REQUEST FLOOD", src_ip, dst_ip, src_mac,
                        ports="", total_ports=0,
                        start_time=time.ctime(min(times['timestamp_flood'][src_ip])),
                        duration=duration,
                        packet_count=pkt_count,
                    )

                    alerted_ips[src_ip].add('ICMP TIMESTAMP REQUEST FLOOD')

                    logger.info(
                        f"Timestamp flood detected: {pkt_count} packets from {src_ip} "
                        f"within {duration:.2f}s ({rate:.2f} pkt/s)"
                    )

            if icmp_type == "17":
                times['mask_flood'][src_ip].append(ts)
                times['mask_flood'][src_ip] = [t for t in times['mask_flood'][src_ip] if ts - t <= FLOOD_WINDOW]
                if len(times['mask_flood'][src_ip]) >= THRESHOLDS['mask_flood'] and 'ICMP ADDRESS MASK REQUEST FLOOD' not in alerted_ips[src_ip] and times['mask_flood'][src_ip]:
                    unified_log_alert(alerts_list, alerted_set, log_file_handle,
                                      "ICMP ADDRESS MASK REQUEST FLOOD", src_ip, dst_ip, src_mac,
                                      ports="", total_ports=0,
                                      start_time=time.ctime(min(times['mask_flood'][src_ip])),
                                      duration=max(times['mask_flood'][src_ip]) - min(times['mask_flood'][src_ip]),
                                      packet_count=len(times['mask_flood'][src_ip]))
                    alerted_ips[src_ip].add('ICMP ADDRESS MASK REQUEST FLOOD')
                    logger.info(f"Mask flood detected: {len(times['mask_flood'][src_ip])} packets from {src_ip}")

        except Exception as e:
            logger.error(f"Processing error: {str(e)}")

# -------------------------
# Main Detection Logic
# -------------------------
def smart_detect(packets, alerts_list, alerted_set, log_file_handle):
    """Route packets to the appropriate detection function based on protocol."""
    logger = _logging.getLogger("smart_detector")
    logger.setLevel(_logging.INFO)

    # Count packets by protocol
    packet_counts = {'tcp': 0, 'udp': 0, 'arp': 0, 'icmp': 0}
    nmap_packets = []
    arp_packets = []
    icmp_packets = []

    for packet in packets:
        protocol = get_packet_protocol(packet)
        if protocol in ['tcp', 'udp']:
            nmap_packets.append(packet)
            packet_counts[protocol] += 1
        elif protocol == 'arp':
            arp_packets.append(packet)
            packet_counts['arp'] += 1
        elif protocol == 'icmp':
            icmp_packets.append(packet)
            packet_counts['icmp'] += 1

    logger.info(f"Packet distribution: {packet_counts['tcp'] + packet_counts['udp']} TCP/UDP "
                f"({packet_counts['tcp']} TCP, {packet_counts['udp']} UDP), "
                f"{packet_counts['arp']} ARP, {packet_counts['icmp']} ICMP")

    # Run detection functions only on relevant packets
    if nmap_packets:
        detect_nmap(nmap_packets, alerts_list, alerted_set, log_file_handle)
    if arp_packets:
        detect_arp(arp_packets, alerts_list, alerted_set, log_file_handle)
    if icmp_packets:
        detect_icmp(packets, alerts_list, alerted_set, log_file_handle)

# -------------------------
# Parse Arguments
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Smart Detection Engine")
    parser.add_argument("json_file", help="Path to parsed JSON packet file")
    parser.add_argument("--log", default="smart_alerts.log", help="Log file path")
    parser.add_argument("--json-out", dest="json_out", help="Path to save alerts in JSON", default=None)
    return parser.parse_args()

# -------------------------
# Main
# -------------------------
def main():
    args = parse_args()

    # Setup logging
    _logging.basicConfig(level=_logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Load packets
    try:
        with open(args.json_file, "r") as f:
            packets = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.json_file} - {str(e)}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: File not found - {str(e)}")
        sys.exit(1)

    alerts = []
    alerted_set = set()

    # Open log file
    with open(args.log, "a") as log_fh:
        print("Running smart detection...")
        smart_detect(packets, alerts, alerted_set, log_fh)

        # Save JSON output if specified
        if args.json_out:
            try:
                with open(args.json_out, "w") as json_fh:
                    json.dump(alerts, json_fh, indent=2)
            except Exception as e:
                print(f"Error writing JSON output: {str(e)}")

    print(f"\nTotal Alerts: {len(alerts)}")
    if len(alerts) > 1:
        _logging.getLogger('main').warning(f"Multiple alerts generated: {[a['type'] for a in alerts]}")

if __name__ == "__main__":
    main()
