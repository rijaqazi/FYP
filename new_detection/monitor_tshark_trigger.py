#!/usr/bin/env python3
"""
monitor_tshark_trigger.py (protocol-aware monitor)
- Streams selected tshark fields (tcp flags, icmp type, arp opcode, ports).
- Maintains protocol-specific sliding windows and detectors.
- When a detector threshold is exceeded for a source, starts a 200-packet tshark capture
  (non-blocking thread) and saves to CAPTURE_DIR.
- Continues monitoring while captures run in background.
"""

import subprocess, time, os, sys, shutil, json, threading, signal
from collections import deque, defaultdict


INTERFACE = "wlp2s0"   

DISPLAY_FILTER = '(tcp.flags.syn==1 && tcp.flags.ack==0) || icmp.type==8 || arp.opcode==2 || tcp || udp || arp || icmp'

WINDOW = 10                 # sliding window (seconds) for counting events per-src
THRESHOLD_DEFAULT = 50      
PACKET_LIMIT = 200          
CAPTURE_DIR = os.path.expanduser("/home/defender/Desktop/new_detection/tshark_captures")
CAPTURE_PREFIX = "auto_"
COOLDOWN = 5   
WEBHOOK_URL = None
POST_CAPTURE_CMD = None

THRESHOLDS = {
    # TCP Scan thresholds
    'SYN': 5,              # SYN scan threshold
    'FIN': 5,              # FIN scan threshold  
    'XMAS': 5,             # XMAS scan threshold
    'NULL': 5,             # NULL scan threshold
    'ACK': 10,             # ACK scan threshold
    'FULL_PORT': 50,       # full port scan threshold
    'RST_FLOOD': 30,       # RST flood threshold
    'SPOOFED_SYN_FLOOD': 50, # spoofed SYN flood
    
    # UDP Scan thresholds
    'UDP_PORTS': 10,       # UDP scan threshold
    
    # ICMP thresholds
    'ICMP_ECHO': 50,       # ICMP echo flood
    'ICMP_TIMESTAMP': 20,  # ICMP timestamp flood
    'ICMP_MASK': 15,       # ICMP address mask flood
    'SMURF_ATTACK': 20,    # Smurf attack threshold
    
    # ARP thresholds
    'ARP_FLOOD': 10,       # ARP flood in short time
    'ARP_MITM': 3,         # ARP MITM detection sensitivity
    'MAC_CONFLICT': 2,     # MAC conflict detection
    'GRATUITOUS_ARP': 3,   # Gratuitous ARP detection
    'BROADCAST_SPOOF': 3,  # Broadcast spoof detection
    
    # OS Fingerprinting
    'OS_FINGERPRINT': 15,  # OS fingerprinting detection
}
# ----------------------------

def check_env():
    if not shutil.which("tshark"):
        print("ERROR: tshark not found. Install with: sudo apt install tshark")
        sys.exit(1)
    # prefer running without sudo if dumpcap capability is set
    if os.geteuid() == 0:
        print("WARNING: Running as root. Consider enabling dumpcap capabilities and run as normal user.")

# ensure capture folder exists and owned by current user
os.makedirs(CAPTURE_DIR, exist_ok=True)
try:
    import getpass
    user = getpass.getuser()
    subprocess.run(["sudo", "chown", f"{user}:{user}", CAPTURE_DIR], check=False)
except Exception:
    pass

# state
counts = defaultdict(lambda: deque())        # simple timing events per src (generic)
syn_ports = defaultdict(lambda: set())       # per-src set of dst ports seen with SYN
fin_ports = defaultdict(lambda: set())       # per-src set of dst ports seen with FIN
xmas_ports = defaultdict(lambda: set())      # per-src set of dst ports seen with XMAS
null_ports = defaultdict(lambda: set())      # per-src set of dst ports seen with NULL
ack_ports = defaultdict(lambda: set())       # per-src set of dst ports seen with ACK
udp_ports = defaultdict(lambda: set())       # per-src set of dst ports seen with UDP
icmp_times = defaultdict(lambda: deque())    # ICMP echo request times
icmp_timestamp_times = defaultdict(lambda: deque())  # ICMP timestamp request times
icmp_mask_times = defaultdict(lambda: deque())       # ICMP mask request times
arp_window = defaultdict(lambda: deque())    # ARP packet times
rst_times = defaultdict(lambda: deque())     # RST packet times
spoofed_syn_packets = defaultdict(lambda: defaultdict(lambda: deque()))  # spoofed SYN tracking
os_fingerprint_count = defaultdict(int)      # OS fingerprinting attempts
arp_table = {}                               # IP to MAC mapping for ARP spoof detection
mac_to_ips = defaultdict(set)                # MAC to IPs mapping for MAC conflict
last_trigger = {}                            # cooldown bookkeeping
active_captures = {}                         # src -> {"proc":p,"file":fname}
stop_flag = False
lock = threading.Lock()

def send_webhook(alert):
    if not WEBHOOK_URL:
        return
    try:
        import urllib.request
        data = json.dumps(alert).encode('utf-8')
        req = urllib.request.Request(WEBHOOK_URL, data=data, headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        with open(os.path.join(CAPTURE_DIR, "webhook_errors.log"), "a") as fh:
            fh.write(f"{time.time()}: webhook error: {e}\n")

def start_full_capture(src, when, bpf=None):
 
    safe_src = str(src).replace(":", "").replace("/", "_")
    fname = f"{CAPTURE_DIR}/{CAPTURE_PREFIX}{safe_src}_{int(when)}.pcap"
    if not bpf:
        if ":" in str(src):
            bpf = f"ether host {src}"
        else:
            bpf = f"host {src}"
    cmd = ["tshark", "-i", INTERFACE, "-f", bpf, "-c", str(PACKET_LIMIT), "-w", fname]

    print(f"\n[!] Suspicious activity detected from {src}")
    print(f"[+] TShark capturing started... (saving {PACKET_LIMIT} packets to {fname})")

    with open(f"{fname}.log", "w") as flog:
        try:
            p = subprocess.Popen(cmd, stdout=flog, stderr=flog)
            with lock:
                active_captures[src] = {"proc": p, "file": fname}
            p.wait()
        except Exception as e:
            with open(os.path.join(CAPTURE_DIR, "monitor_errors.log"), "a") as fe:
                fe.write(f"{time.time()}: capture error for {src}: {e}\n")
        finally:
            with lock:
                active_captures.pop(src, None)

    print(f"[✓] Capture completed for {src}, saved: {fname}\n")


    if POST_CAPTURE_CMD:
        try:
            cmd_str = POST_CAPTURE_CMD.format(pcap=fname, src=src)
            print(f"[i] Running post-capture command: {cmd_str}")
            subprocess.Popen(cmd_str, shell=True)
        except Exception as e:
            with open(os.path.join(CAPTURE_DIR, "monitor_errors.log"), "a") as fe:
                fe.write(f"{time.time()}: post-capture command failed for {fname}: {e}\n")

    # write an alert line for bookkeeping
    alert = {
        "time": int(when),
        "src": src,
        "reason": "protocol_threshold_exceeded",
        "capture_file": fname
    }
    try:
        with open(os.path.join(CAPTURE_DIR, "alerts.jsonl"), "a") as fa:
            fa.write(json.dumps(alert) + "\n")
    except Exception:
        pass
    send_webhook(alert)

def stop_all():
    global stop_flag
    stop_flag = True
    with lock:
        for srcinfo in list(active_captures.values()):
            try:
                proc = srcinfo.get("proc")
                if proc and proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass

def monitor_loop():
    check_env()

    # we need: time, ip.src, ip.dst, eth.src, tcp.flags, tcp.dstport, udp.dstport, icmp.type, arp.opcode
    stream_cmd = [
        "tshark", "-i", INTERFACE, "-Y", DISPLAY_FILTER,
        "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "eth.src", "-e", "tcp.flags", "-e", "tcp.dstport",
        "-e", "udp.dstport", "-e", "icmp.type", "-e", "arp.opcode",
        "-E", "separator=|", "-E", "quote=n", "-l"
    ]

    try:
        p = subprocess.Popen(stream_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as e:
        print("ERROR: starting tshark streaming failed:", e)
        sys.exit(1)

    try:
        for rawline in p.stdout:
            if stop_flag:
                break
            line = rawline.strip()
            if not line:
                continue
            # fields are separated by '|' as set above
            parts = line.split("|")
            # normalize fields safely
            try:
                ts = float(parts[0]) if len(parts) > 0 and parts[0] else time.time()
            except Exception:
                ts = time.time()
            ip_src = parts[1] if len(parts) > 1 and parts[1] else ""
            ip_dst = parts[2] if len(parts) > 2 and parts[2] else ""
            eth_src = parts[3] if len(parts) > 3 and parts[3] else ""
            tcp_flags = parts[4] if len(parts) > 4 and parts[4] else ""
            tcp_dport = parts[5] if len(parts) > 5 and parts[5] else ""
            udp_dport = parts[6] if len(parts) > 6 and parts[6] else ""
            icmp_type = parts[7] if len(parts) > 7 and parts[7] else ""
            arp_opcode = parts[8] if len(parts) > 8 and parts[8] else ""

            src = ip_src or eth_src or None
            if not src:
                continue

            now = ts

            # Generic timing queue (not used for all detectors but kept)
            q = counts[src]
            q.append(now)
            while q and q[0] < now - WINDOW:
                q.popleft()

            # TCP flag handling
            if tcp_flags:
                flag_str = tcp_flags.lower()
                is_syn = ('0x02' in flag_str) or ('s' in flag_str and 'a' not in flag_str)
                is_fin = ('0x01' in flag_str) or ('f' in flag_str)
                is_rst = ('0x04' in flag_str) or ('r' in flag_str)
                is_ack = ('0x10' in flag_str) or ('a' in flag_str)
                is_psh = ('0x08' in flag_str) or ('p' in flag_str)
                is_urg = ('0x20' in flag_str) or ('u' in flag_str)
                
                # SYN packets
                if is_syn and tcp_dport:
                    syn_ports[src].add(tcp_dport)
                    # Track spoofed SYN (same src->dst multiple SYNs)
                    if ip_dst:
                        key = (src, ip_dst)
                        spoofed_syn_packets[src][key].append(now)
                        spoofed_syn_packets[src][key] = [t for t in spoofed_syn_packets[src][key] if now - t <= WINDOW]
                
                # FIN packets
                if is_fin and tcp_dport and not is_syn and not is_ack:
                    fin_ports[src].add(tcp_dport)
                
                # XMAS packets (FIN + PSH + URG)
                if is_fin and is_psh and is_urg and tcp_dport and not is_syn and not is_ack:
                    xmas_ports[src].add(tcp_dport)
                
                # NULL packets (no flags set)
                if not any([is_syn, is_ack, is_fin, is_rst, is_psh, is_urg]) and tcp_dport:
                    null_ports[src].add(tcp_dport)
                
                # ACK packets
                if is_ack and tcp_dport and not is_syn:
                    ack_ports[src].add(tcp_dport)
                
                # RST packets
                if is_rst:
                    rst_times[src].append(now)
                    rst_times[src] = deque([t for t in rst_times[src] if now - t <= WINDOW])
                
                # OS fingerprinting detection (TCP options present)
                if 'tcp.options' in tcp_flags.lower():
                    os_fingerprint_count[src] += 1

            # UDP port tracking
            if udp_dport:
                udp_ports[src].add(udp_dport)

            # ICMP type handling
            if icmp_type == "8":  # Echo request
                icmp_times[src].append(now)
                icmp_times[src] = deque([t for t in icmp_times[src] if now - t <= WINDOW])
            elif icmp_type == "13":  # Timestamp request
                icmp_timestamp_times[src].append(now)
                icmp_timestamp_times[src] = deque([t for t in icmp_timestamp_times[src] if now - t <= WINDOW])
            elif icmp_type == "17":  # Address mask request
                icmp_mask_times[src].append(now)
                icmp_mask_times[src] = deque([t for t in icmp_mask_times[src] if now - t <= WINDOW])

            # ARP opcode handling
            if arp_opcode:
                try:
                    if arp_opcode.strip() == "2":  # ARP reply
                        arp_window[src].append(now)
                        arp_window[src] = deque([t for t in arp_window[src] if now - t <= WINDOW])
                        
                        # ARP spoof detection
                        if ip_src and eth_src:
                            if ip_src in arp_table and arp_table[ip_src] != eth_src:
                                # Potential ARP spoof detected
                                pass
                            arp_table[ip_src] = eth_src
                            
                        # MAC conflict detection
                        if eth_src:
                            mac_to_ips[eth_src].add(ip_src)
                except Exception:
                    pass

            # Now check ALL protocol-specific thresholds and trigger capture if exceeded
            triggered = False
            reason = None
            bpf = None

            # TCP Scan detections
            syn_count = len(syn_ports[src])
            if syn_count >= THRESHOLDS['SYN']:
                if syn_count >= THRESHOLDS['FULL_PORT']:
                    reason = f"FULL_PORT_SCAN ({syn_count} ports)"
                else:
                    reason = f"SYN_SCAN ({syn_count} ports)"
                triggered = True

            # FIN scan
            if not triggered and len(fin_ports[src]) >= THRESHOLDS['FIN']:
                reason = f"FIN_SCAN ({len(fin_ports[src])} ports)"
                triggered = True

            # XMAS scan
            if not triggered and len(xmas_ports[src]) >= THRESHOLDS['XMAS']:
                reason = f"XMAS_SCAN ({len(xmas_ports[src])} ports)"
                triggered = True

            # NULL scan
            if not triggered and len(null_ports[src]) >= THRESHOLDS['NULL']:
                reason = f"NULL_SCAN ({len(null_ports[src])} ports)"
                triggered = True

            # ACK scan
            if not triggered and len(ack_ports[src]) >= THRESHOLDS['ACK']:
                reason = f"ACK_SCAN ({len(ack_ports[src])} ports)"
                triggered = True

            # RST flood
            if not triggered and len(rst_times[src]) >= THRESHOLDS['RST_FLOOD']:
                reason = f"RST_FLOOD ({len(rst_times[src])})"
                triggered = True

            # Spoofed SYN flood
            if not triggered:
                for dst_key in spoofed_syn_packets[src]:
                    if len(spoofed_syn_packets[src][dst_key]) >= THRESHOLDS['SPOOFED_SYN_FLOOD']:
                        reason = f"SPOOFED_SYN_FLOOD ({len(spoofed_syn_packets[src][dst_key])})"
                        triggered = True
                        break

            # OS fingerprinting
            if not triggered and os_fingerprint_count[src] >= THRESHOLDS['OS_FINGERPRINT']:
                reason = f"OS_FINGERPRINT ({os_fingerprint_count[src]} attempts)"
                triggered = True

            # UDP scan
            if not triggered and len(udp_ports[src]) >= THRESHOLDS['UDP_PORTS']:
                reason = f"UDP_SCAN ({len(udp_ports[src])} ports)"
                triggered = True

            # ICMP detections
            if not triggered and len(icmp_times[src]) >= THRESHOLDS['ICMP_ECHO']:
                reason = f"ICMP_ECHO_FLOOD ({len(icmp_times[src])})"
                triggered = True

            if not triggered and len(icmp_timestamp_times[src]) >= THRESHOLDS['ICMP_TIMESTAMP']:
                reason = f"ICMP_TIMESTAMP_FLOOD ({len(icmp_timestamp_times[src])})"
                triggered = True

            if not triggered and len(icmp_mask_times[src]) >= THRESHOLDS['ICMP_MASK']:
                reason = f"ICMP_MASK_FLOOD ({len(icmp_mask_times[src])})"
                triggered = True

            # Smurf attack (ICMP echo to broadcast)
            if not triggered and icmp_type == "8" and ip_dst and ip_dst.endswith(".255"):
                if len(icmp_times[src]) >= THRESHOLDS['SMURF_ATTACK']:
                    reason = f"SMURF_ATTACK ({len(icmp_times[src])})"
                    triggered = True

            # ARP detections
            if not triggered and len(arp_window[src]) >= THRESHOLDS['ARP_FLOOD']:
                reason = f"ARP_FLOOD ({len(arp_window[src])})"
                triggered = True

            # MAC conflict
            if not triggered and eth_src and len(mac_to_ips[eth_src]) >= THRESHOLDS['MAC_CONFLICT']:
                reason = f"MAC_CONFLICT ({len(mac_to_ips[eth_src])} IPs)"
                triggered = True

            # Set BPF filter based on attack type
            if triggered:
                if ":" in str(src):
                    bpf = f"ether host {src}"
                else:
                    bpf = f"host {src}"

            # If triggered, check cooldown and start capture in background
            if triggered:
                last = last_trigger.get(src, 0)
                if now - last >= COOLDOWN:
                    last_trigger[src] = now
                    print(f"[!] Triggering capture for {src} -> {reason}")
                    thr = threading.Thread(target=start_full_capture, args=(src, now, bpf))
                    thr.daemon = True
                    thr.start()
                else:
                    # cooldown active
                    pass

            # Periodic cleanup: free sets for srcs that haven't been seen recently
            if q and (now - q[-1] > WINDOW * 3):
                syn_ports.pop(src, None)
                fin_ports.pop(src, None)
                xmas_ports.pop(src, None)
                null_ports.pop(src, None)
                ack_ports.pop(src, None)
                udp_ports.pop(src, None)
                icmp_times.pop(src, None)
                icmp_timestamp_times.pop(src, None)
                icmp_mask_times.pop(src, None)
                arp_window.pop(src, None)
                rst_times.pop(src, None)
                spoofed_syn_packets.pop(src, None)
                os_fingerprint_count.pop(src, None)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            p.terminate()
        except Exception:
            pass

if __name__ == "__main__":
    def _sigterm(signum, frame):
        stop_all()
        sys.exit(0)
    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    print("===========================================")
    print("TShark Protocol-Aware Auto-Capture Monitor is Running...")
    print(f" Interface: {INTERFACE}")
    print(f" Saving Captures in: {CAPTURE_DIR}")
    print(f" Packet limit per capture: {PACKET_LIMIT}")
    print("===========================================\n")


    monitor_thread = threading.Thread(target=monitor_loop)
    monitor_thread.daemon = True
    monitor_thread.start()

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped manually.")
        os._exit(0)

