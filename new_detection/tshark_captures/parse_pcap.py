#!/usr/bin/env python3

import json
import subprocess
import sys
import os




if len(sys.argv) != 2:
    print("Usage: python3 parse_pcap.py <filename.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]


if not os.path.exists(pcap_file):
    print(f"Error: File '{pcap_file}' not found.")
    sys.exit(1)

try:
    tshark_cmd = [
        "tshark", "-r", pcap_file, "-T", "json"
    ]
    result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
    json_output = result.stdout

   
    output_file = os.path.splitext(pcap_file)[0] + "_parsed.json"
    with open(output_file, "w") as f:
        f.write(json_output)

    print(f"Parsed data saved to '{output_file}'")

except subprocess.CalledProcessError as e:
    print("Error while running tshark:", e)
    sys.exit(1)
