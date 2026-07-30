#!/usr/bin/env python3
import time
import os
import subprocess
import shutil

# Paths
WATCH_FOLDER = "/home/defender/Desktop/new_detection/tshark_captures"
OUTPUT_FOLDER = "/home/defender/Desktop/new_detection"
PARSE_SCRIPT = "/home/defender/Desktop/new_detection/tshark_captures/parse_pcap.py"

print("===========================================")
print(" Auto Parser Monitor is Running...")
print(f" Watching folder: {WATCH_FOLDER}")
print(f" Check interval: 30 seconds")
print("===========================================\n")

def get_parsed_pcaps():
    """Get list of PCAPs that have already been parsed (have _parsed.json files in output folder)"""
    parsed_pcaps = set()
    
    # Check for _parsed.json files in output folder
    if os.path.exists(OUTPUT_FOLDER):
        for file in os.listdir(OUTPUT_FOLDER):
            if file.endswith('_parsed.json'):
                # Extract PCAP name from _parsed.json filename
                pcap_name = file.replace('_parsed.json', '.pcap')
                parsed_pcaps.add(pcap_name)
    
    return parsed_pcaps

def get_unparsed_pcaps():
    """Get list of PCAP files that haven't been parsed yet"""
    parsed_pcaps = get_parsed_pcaps()
    unparsed_pcaps = []
    
    # Check all PCAP files in watch folder
    if os.path.exists(WATCH_FOLDER):
        for file in os.listdir(WATCH_FOLDER):
            if file.endswith('.pcap') and file not in parsed_pcaps:
                unparsed_pcaps.append(file)
    
    return unparsed_pcaps

while True:
    try:
        # Find unparsed PCAP files
        unparsed_files = get_unparsed_pcaps()
        
        if unparsed_files:
            print(f"[+] Found {len(unparsed_files)} unparsed PCAP file(s)")
            
            for file in unparsed_files:
                full_path = os.path.join(WATCH_FOLDER, file)
                print(f"[→] Parsing {file} ...")

                # Run parse_pcap.py on the unparsed PCAP
                result = subprocess.run(["python3", PARSE_SCRIPT, full_path], check=False, capture_output=True, text=True)
                
                if result.returncode == 0:
                    print(f"[✓] Parser completed successfully for {file}")
                    
                    # Move generated _parsed.json report to detection2 folder
                    json_file = file.replace('.pcap', '_parsed.json')
                    json_src = os.path.join(WATCH_FOLDER, json_file)
                    json_dest = os.path.join(OUTPUT_FOLDER, json_file)
                    
                    if os.path.exists(json_src):
                        shutil.move(json_src, json_dest)
                        print(f"[✓] Parsed report saved: {json_dest}")
                    else:
                        print(f"[!] JSON output not found for {file}")
                        # Also check for .json without _parsed suffix
                        json_file_alt = file.replace('.pcap', '.json')
                        json_src_alt = os.path.join(WATCH_FOLDER, json_file_alt)
                        if os.path.exists(json_src_alt):
                            shutil.move(json_src_alt, json_dest)
                            print(f"[✓] Found and moved alternative JSON: {json_dest}")
                        
                else:
                    print(f"[!] Parser failed for {file}: {result.stderr}")
                
                print()
        else:
            print(f"[i] No unparsed PCAP files found. Waiting... ({time.strftime('%H:%M:%S')})")

        # Wait for 30 seconds before next check
        time.sleep(30)

    except KeyboardInterrupt:
        print("\n Monitor stopped by user.")
        break
    except Exception as e:
        print(f"[!] Error: {e}")
        time.sleep(30)
