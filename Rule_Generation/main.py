import tkinter as tk
from tkinter import ttk, messagebox
import json, zipfile, os, shutil, glob
import requests
import hashlib
from datetime import datetime


REPORTS_DIR = "/home/defender/Desktop/Rule_Generation/reports"
RULES_REPO_DIR = "/home/defender/Desktop/Rule_Generation/rules_repository"
OUTPUT_DIR = os.path.join(os.getcwd(), "exported_rules")
ZIP_OUTPUT_DIR = os.path.join(os.getcwd(), "extracted_rules_zip")
SERVER_URL = "http://127.0.0.1:5000"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ZIP_OUTPUT_DIR, exist_ok=True)


rules_dict = {
    # Nmap Detection
    "syn_scan": "Syn Scan",
    "spoof_syn_scan": "Spoof Syn Scan",
    "full_port_scan": "Full Port Scan",
    "fin_scan": "Fin Scan",
    "xmas_scan": "Xmas Scan",
    "null_scan": "Null Scan",
    "ack_scan": "Ack Scan",
    "udp_scan": "UDP Scan",
    "os_fingerprint_scan": "OS Fingerprint Scan",
    
    # ARP Attacks
    "arp_mitm": "ARP MITM",
    "gratuitous": "Gratuitous",
    "broadcast": "Broadcast",
    "macc_conflict": "Macc Conflict",
    "arp_flood": "ARP Flood",
    
    # ICMP Attacks
    "icmp_timestamp_flood": "ICMP Timestamp Flood",
    "icmp_address_mask": "ICMP Address Mask",
    "icmp_echo_request": "ICMP Echo Request",
    "smurf_attack": "Smurf Attack"
}


def sha256_file(path):
    """Calculate SHA256 hash of a file"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def remove_file_from_server(rule_id):
    """Remove file from server if it exists"""
    try:
        filename = f"{rule_id}.zip"
        url = SERVER_URL.rstrip("/") + f"/delete/{filename}"
        print(f"[REMOVE] Attempting to remove {filename} from server...")
        r = requests.delete(url, timeout=10)
        
        if r.status_code == 200:
            print(f"[REMOVE] Successfully removed {filename} from server")
            return True
        elif r.status_code == 404:
            print(f"[REMOVE] File {filename} not found on server (nothing to remove)")
            return True
        else:
            print(f"[REMOVE] Failed to remove {filename}: {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"[REMOVE] Error removing file: {e}")
        return False


def upload_file_with_remove_upload(zip_file_path, rule_id):
    """
    Remove existing file from server (if exists) and upload new file
    Returns True if successful, False otherwise
    """
    try:
        filename = f"{rule_id}.zip"
        
        # Step 1: Remove existing file from server
        print(f"[UPLOAD] Step 1: Removing existing {filename} from server...")
        remove_success = remove_file_from_server(rule_id)
        
        if not remove_success:
            print(f"[WARNING] Failed to remove existing file, but continuing with upload...")
        
        # Step 2: Upload new file
        print(f"[UPLOAD] Step 2: Uploading new {filename}...")
        url = SERVER_URL.rstrip("/") + "/upload"
        with open(zip_file_path, "rb") as fh:
            files = {"file": (filename, fh, "application/zip")}
            data = {
                "rule_id": rule_id,
                "timestamp": datetime.now().isoformat()
            }
            
            r = requests.post(url, files=files, data=data, timeout=30)
        
        # Check response
        if r.status_code in (200, 201):
            try:
                response_data = r.json()
                print(f"[SUCCESS] Uploaded {filename} -> {response_data}")
                messagebox.showinfo("Upload Successful", 
                                  f"Rule '{rule_id}' uploaded to server successfully!")
                return True
            except:
                print(f"[SUCCESS] Uploaded {filename} -> {r.text}")
                messagebox.showinfo("Upload Successful", f"Rule '{rule_id}' uploaded to server!")
                return True
        else:
            print(f"[ERROR] Upload failed: {r.status_code} -> {r.text}")
            messagebox.showerror("Upload Failed", 
                               f"Failed to upload rule '{rule_id}'!\n\nServer returned: {r.status_code}\n{r.text}")
            return False
    except Exception as e:
        print(f"[ERROR] Upload error: {e}")
        messagebox.showerror("Upload Error", f"Error uploading rule '{rule_id}': {str(e)}")
        return False

def scan_and_map_rules():
    """
    Scan RULES_REPO_DIR for JSON files and categorize them by attack type
    Returns categorized rules dictionary
    """
    categories = {
        'nmap': {},
        'arp': {},
        'icmp': {}
    }
    
    # Initialize with empty arrays for all predefined rules
    for rule_name in rules_dict:
        if rule_name in ["syn_scan", "spoof_syn_scan", "full_port_scan", "fin_scan", "xmas_scan", 
                         "null_scan", "ack_scan", "udp_scan", "os_fingerprint_scan"]:
            categories['nmap'][rule_name] = []
        elif rule_name in ["arp_mitm", "gratuitous", "broadcast", "macc_conflict", "arp_flood"]:
            categories['arp'][rule_name] = []
        elif rule_name in ["icmp_timestamp_flood", "icmp_address_mask", "icmp_echo_request", "smurf_attack"]:
            categories['icmp'][rule_name] = []
    
    if not os.path.isdir(RULES_REPO_DIR):
        return categories

    # Scan all JSON files in RULES_REPO_DIR
    for json_file in glob.glob(os.path.join(RULES_REPO_DIR, "*.json")):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
                alert_type = data.get("alert_type", "").upper()
                rule_id = os.path.splitext(os.path.basename(json_file))[0]
                
                # Map to predefined rule names based on alert_type
                # Nmap Detection Rules
                if "SYN_SCAN" in alert_type or "SYN" in alert_type:
                    categories['nmap']['syn_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "SPOOF_SYN_SCAN" in alert_type:
                    categories['nmap']['spoof_syn_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "FULL_PORT_SCAN" in alert_type:
                    categories['nmap']['full_port_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "FIN_SCAN" in alert_type:
                    categories['nmap']['fin_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "XMAS_SCAN" in alert_type:
                    categories['nmap']['xmas_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "NULL_SCAN" in alert_type:
                    categories['nmap']['null_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "ACK_SCAN" in alert_type:
                    categories['nmap']['ack_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "UDP_SCAN" in alert_type:
                    categories['nmap']['udp_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "OS_FINGERPRINT" in alert_type:
                    categories['nmap']['os_fingerprint_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                
                # ARP Attack Rules
                elif "ARP_MITM" in alert_type:
                    categories['arp']['arp_mitm'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "GRATUITOUS" in alert_type:
                    categories['arp']['gratuitous'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "BROADCAST" in alert_type:
                    categories['arp']['broadcast'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "MACC_CONFLICT" in alert_type:
                    categories['arp']['macc_conflict'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "ARP_FLOOD" in alert_type:
                    categories['arp']['arp_flood'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                
                # ICMP Attack Rules
                elif "ICMP_TIMESTAMP_FLOOD" in alert_type:
                    categories['icmp']['icmp_timestamp_flood'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "ICMP_ADDRESS_MASK" in alert_type:
                    categories['icmp']['icmp_address_mask'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "ICMP_ECHO_REQUEST" in alert_type:
                    categories['icmp']['icmp_echo_request'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                elif "SMURF_ATTACK" in alert_type:
                    categories['icmp']['smurf_attack'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
                else:
                    # Default to syn_scan for unknown types
                    categories['nmap']['syn_scan'].append({
                        'rule_id': rule_id, 'data': data, 'json_path': json_file
                    })
        except Exception as e:
            print(f"Failed to load {json_file}: {e}")
            continue
    
    return categories


def generate_files_for_rule(rule_id, rule_content):
    """
    Create folder for rule in OUTPUT_DIR, save JSON and copy PDFs
    Then create individual zip file in ZIP_OUTPUT_DIR and upload to server
    """
    out_folder = os.path.join(OUTPUT_DIR, rule_id)
    os.makedirs(out_folder, exist_ok=True)

    
    if isinstance(rule_content, str):
        try:
            rule_content = json.loads(rule_content)
        except Exception:
            rule_content = {"raw": rule_content}

    # Write JSON file
    out_json_path = os.path.join(out_folder, f"{rule_id}.json")
    with open(out_json_path, "w") as f:
        json.dump(rule_content, f, indent=4)

  
    src_folder = os.path.join(REPORTS_DIR, rule_id)
    if os.path.isdir(src_folder):
        for pdf in glob.glob(os.path.join(src_folder, "*.pdf")):
            try:
                shutil.copy2(pdf, out_folder)
            except Exception as e:
                print(f"Failed to copy PDF {pdf}: {e}")

   
    zip_file_path = os.path.join(ZIP_OUTPUT_DIR, f"{rule_id}.zip")
    
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add all files from the rule folder to zip
        for root, dirs, files in os.walk(out_folder):
            for file in files:
                file_path = os.path.join(root, file)
                # Add file to zip with relative path
                zipf.write(file_path, os.path.relpath(file_path, OUTPUT_DIR))
    
    print(f"[INFO] Zip file created: {zip_file_path}")
    
    
    upload_success = upload_file_with_remove_upload(zip_file_path, rule_id)
    
    return out_json_path, upload_success


def save_rule():
    """Save the currently selected rule with zip creation and server upload"""
    # Get the current tab
    current_tab = notebook.index(notebook.select())
    tab_name = notebook.tab(current_tab, "text").lower()
    
    # Get the selected rule from the combobox
    if tab_name == "nmap":
        rule_id = nmap_combobox.get()
    elif tab_name == "arp":
        rule_id = arp_combobox.get()
    elif tab_name == "icmp":
        rule_id = icmp_combobox.get()
    else:
        messagebox.showerror("Error", "Invalid tab selected!")
        return

    if not rule_id:
        messagebox.showerror("Error", "Please select a rule first!")
        return

    rule_text = text_area.get("1.0", tk.END).strip()
    if not rule_text:
        messagebox.showerror("Error", "Rule content is empty.")
        return

    try:
        parsed = json.loads(rule_text)
    except Exception:
        parsed = rule_text

    # Generate files, create zip and upload to server
    out_json, upload_success = generate_files_for_rule(rule_id, parsed)
    
    if upload_success:
        messagebox.showinfo("Success", 
                          f"Rule '{rule_id}' processed successfully!\n\n"
                          f"Local: {out_json}\n"
                          f"Zip: {ZIP_OUTPUT_DIR}/{rule_id}.zip\n"
                          f"Status: Uploaded to server")
    else:
        messagebox.showwarning("Partial Success", 
                             f"Rule '{rule_id}' saved locally but upload failed!\n\n"
                             f"Local: {out_json}\n"
                             f"Zip: {ZIP_OUTPUT_DIR}/{rule_id}.zip\n"
                             f"Status: Not uploaded to server")

def update_rule():
    """Update rule - same as save for now"""
    save_rule()

def show_rule(event, category, combobox):
    """Display selected rule in text area"""
    rule_id = combobox.get()
    if not rule_id:
        return

    # Find rule in categorized data
    for rule_type, rules_list in categorized_rules[category].items():
        for rule_data in rules_list:
            if rule_data['rule_id'] == rule_id:
                rule_label.config(text=f"📋 Rule: {rule_id}")
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, json.dumps(rule_data['data'], indent=2))
                return
    
    # If not found in scanned data, check exported rules
    maybe_path = os.path.join(OUTPUT_DIR, f"{rule_id}", f"{rule_id}.json")
    if os.path.exists(maybe_path):
        with open(maybe_path) as f:
            try:
                data = json.load(f)
                rule_label.config(text=f"📋 Rule: {rule_id}")
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, json.dumps(data, indent=2))
            except:
                rule_label.config(text=f"📋 {rule_id}")
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, f"Error loading {rule_id}")
    else:
        rule_label.config(text=f"📋 {rule_id}")
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, f"No data found for {rule_id}")


def search_rule():
    """Search for rules by Rule ID"""
    search_term = search_entry.get().strip()
    if not search_term:
        messagebox.showinfo("Search", "Please enter a Rule ID to search")
        return
    
    # Search in all categories
    found_rule = None
    for category_name, category in categorized_rules.items():
        for rule_type, rules_list in category.items():
            for rule_data in rules_list:
                if search_term.lower() in rule_data['rule_id'].lower():
                    found_rule = rule_data
                    break
            if found_rule:
                break
        if found_rule:
            break
    
    if found_rule:
        # Display the found rule
        rule_label.config(text=f"📋 Rule: {found_rule['rule_id']}")
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, json.dumps(found_rule['data'], indent=2))
        
        # Select in appropriate combobox
        if found_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['nmap'].values(), [])]:
            notebook.select(nmap_tab)
            nmap_combobox.set(found_rule['rule_id'])
        elif found_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['arp'].values(), [])]:
            notebook.select(arp_tab)
            arp_combobox.set(found_rule['rule_id'])
        elif found_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['icmp'].values(), [])]:
            notebook.select(icmp_tab)
            icmp_combobox.set(found_rule['rule_id'])
        
        messagebox.showinfo("Search Result", f"Rule found: {found_rule['rule_id']}")
    else:
        messagebox.showinfo("Search Result", f"No rule found with ID: {search_term}")

# === Enhanced GUI Setup ===
root = tk.Tk()
root.title("🔒 Advanced Rule Editor - Network Security")
root.geometry("1400x900")
root.configure(bg="#0d1117")

# Modern styling
style = ttk.Style()
style.theme_use("clam")

# Configure colors for dark theme
style.configure("Custom.Treeview", 
                background="#1e1e2f",
                foreground="white",
                fieldbackground="#1e1e2f",
                borderwidth=0)

style.configure("Custom.Treeview.Heading",
                background="#161b22",
                foreground="white",
                relief="flat")

# Configure combobox style
style.configure("Custom.TCombobox",
                fieldbackground="#1e1e2f",
                background="#1e1e2f",
                foreground="white",
                selectbackground="#ff6b35",
                selectforeground="white")

# Single ORANGE style for all buttons
style.configure("Orange.TButton",
                font=("Arial", 12, "bold"),
                padding=(20, 12),
                foreground="white",
                background="#ff6b35",
                borderwidth=0,
                focuscolor="none")
style.map("Orange.TButton",
          foreground=[("active", "white")],
          background=[("active", "#ff8533")])

# Main container with modern gradient background
main_container = tk.Frame(root, bg="#0d1117")
main_container.pack(fill="both", expand=True, padx=20, pady=20)

# Header with modern design
header_frame = tk.Frame(main_container, bg="#0d1117", height=100)
header_frame.pack(fill="x", pady=(0, 20))

header_bg = tk.Frame(header_frame, bg="#161b22", height=80)
header_bg.pack(fill="x", padx=10, pady=10)

heading = tk.Label(header_bg, 
                   text="⚡ ADVANCED RULE EDITOR ⚡", 
                   font=("Arial", 32, "bold"), 
                   fg="#ff6b35", 
                   bg="#161b22")
heading.pack(pady=20)

subheading = tk.Label(header_bg, 
                      text="Network Security Rule Management System", 
                      font=("Arial", 14), 
                      fg="#8b949e", 
                      bg="#161b22")
subheading.pack(pady=(0, 10))

# Search Frame
search_frame = tk.Frame(main_container, bg="#0d1117")
search_frame.pack(fill="x", pady=(0, 15))

search_label = tk.Label(search_frame, 
                        text="🔍 Search Rule by ID:", 
                        font=("Arial", 12, "bold"), 
                        fg="white", 
                        bg="#0d1117")
search_label.pack(side="left", padx=(0, 10))

search_entry = tk.Entry(search_frame, 
                        font=("Arial", 12), 
                        bg="#1e1e2f", 
                        fg="white", 
                        insertbackground="white",
                        relief="flat",
                        width=30)
search_entry.pack(side="left", padx=(0, 10))

# Search button with same orange style
search_btn = ttk.Button(search_frame, text="Search", style="Orange.TButton", command=search_rule)
search_btn.pack(side="left", padx=(0, 10))

# Bind Enter key to search
def search_on_enter(event):
    search_rule()
search_entry.bind("<Return>", search_on_enter)

# Content area with modern card design
content_card = tk.Frame(main_container, bg="#161b22", relief="flat", bd=0)
content_card.pack(fill="both", expand=True)

# Left sidebar - Rules Navigation with Tabs
sidebar_frame = tk.Frame(content_card, bg="#1e1e2f", width=400, relief="flat")
sidebar_frame.pack(side="left", fill="y", padx=(0, 2))

# Sidebar header
sidebar_header = tk.Frame(sidebar_frame, bg="#161b22", height=60)
sidebar_header.pack(fill="x", pady=(0, 10))

sidebar_title = tk.Label(sidebar_header, 
                         text="📁 SECURITY RULES", 
                         font=("Arial", 16, "bold"), 
                         fg="white", 
                         bg="#161b22")
sidebar_title.pack(pady=20)

# Notebook for tabs
notebook = ttk.Notebook(sidebar_frame)
notebook.pack(fill="both", expand=True, padx=15, pady=10)

# Create tabs
nmap_tab = tk.Frame(notebook, bg="#1e1e2f")
arp_tab = tk.Frame(notebook, bg="#1e1e2f")
icmp_tab = tk.Frame(notebook, bg="#1e1e2f")

notebook.add(nmap_tab, text="Nmap")
notebook.add(arp_tab, text="ARP")
notebook.add(icmp_tab, text="ICMP")

# === Populate Tabs with Comboboxes ===
categorized_rules = scan_and_map_rules()

# Nmap Tab
nmap_label = tk.Label(nmap_tab, 
                      text="Nmap Detection Rules", 
                      font=("Arial", 14, "bold"), 
                      fg="white", 
                      bg="#1e1e2f")
nmap_label.pack(pady=10)

nmap_comboboxes = {}
for rule_name, display_name in rules_dict.items():
    if rule_name in categorized_rules['nmap']:
        if categorized_rules['nmap'][rule_name]:
            label = tk.Label(nmap_tab, 
                             text=display_name, 
                             font=("Arial", 12), 
                             fg="#8b949e", 
                             bg="#1e1e2f")
            label.pack(anchor="w", padx=10)
            
            combobox = ttk.Combobox(nmap_tab, 
                                    values=[rule['rule_id'] for rule in categorized_rules['nmap'][rule_name]],
                                    style="Custom.TCombobox",
                                    width=30)
            combobox.pack(pady=5, padx=10)
            combobox.bind("<<ComboboxSelected>>", lambda e: show_rule(e, 'nmap', combobox))
            nmap_comboboxes[rule_name] = combobox

# ARP Tab
arp_label = tk.Label(arp_tab, 
                     text="ARP Attack Rules", 
                     font=("Arial", 14, "bold"), 
                     fg="white", 
                     bg="#1e1e2f")
arp_label.pack(pady=10)

arp_comboboxes = {}
for rule_name, display_name in rules_dict.items():
    if rule_name in categorized_rules['arp']:
        if categorized_rules['arp'][rule_name]:
            label = tk.Label(arp_tab, 
                             text=display_name, 
                             font=("Arial", 12), 
                             fg="#8b949e", 
                             bg="#1e1e2f")
            label.pack(anchor="w", padx=10)
            
            combobox = ttk.Combobox(arp_tab, 
                                    values=[rule['rule_id'] for rule in categorized_rules['arp'][rule_name]],
                                    style="Custom.TCombobox",
                                    width=30)
            combobox.pack(pady=5, padx=10)
            combobox.bind("<<ComboboxSelected>>", lambda e: show_rule(e, 'arp', combobox))
            arp_comboboxes[rule_name] = combobox

# ICMP Tab
icmp_label = tk.Label(icmp_tab, 
                      text="ICMP Attack Rules", 
                      font=("Arial", 14, "bold"), 
                      fg="white", 
                      bg="#1e1e2f")
icmp_label.pack(pady=10)

icmp_comboboxes = {}
for rule_name, display_name in rules_dict.items():
    if rule_name in categorized_rules['icmp']:
        if categorized_rules['icmp'][rule_name]:
            label = tk.Label(icmp_tab, 
                             text=display_name, 
                             font=("Arial", 12), 
                             fg="#8b949e", 
                             bg="#1e1e2f")
            label.pack(anchor="w", padx=10)
            
            combobox = ttk.Combobox(icmp_tab, 
                                    values=[rule['rule_id'] for rule in categorized_rules['icmp'][rule_name]],
                                    style="Custom.TCombobox",
                                    width=30)
            combobox.pack(pady=5, padx=10)
            combobox.bind("<<ComboboxSelected>>", lambda e: show_rule(e, 'icmp', combobox))
            icmp_comboboxes[rule_name] = combobox

# Right content area - Rule Editor
editor_frame = tk.Frame(content_card, bg="#0d1117")
editor_frame.pack(side="right", fill="both", expand=True, padx=2)

# Editor header
editor_header = tk.Frame(editor_frame, bg="#161b22", height=60)
editor_header.pack(fill="x", pady=(0, 10))

rule_label = tk.Label(editor_header, 
                      text="🔍 Select a rule to edit", 
                      font=("Arial", 18, "bold"), 
                      fg="white", 
                      bg="#161b22")
rule_label.pack(pady=20)

# Text area with enhanced styling
text_container = tk.Frame(editor_frame, bg="#161b22")
text_container.pack(fill="both", expand=True, padx=15, pady=10)

text_label = tk.Label(text_container, 
                      text="Rule Content (JSON Format):", 
                      font=("Arial", 12, "bold"), 
                      fg="#8b949e", 
                      bg="#161b22")
text_label.pack(anchor="w", pady=(0, 10))

text_area = tk.Text(text_container, 
                    width=80, 
                    height=20, 
                    font=("Consolas", 12), 
                    bg="#1e1e2f", 
                    fg="white", 
                    insertbackground="white",
                    relief="flat",
                    padx=15,
                    pady=15,
                    wrap=tk.WORD)
text_area.pack(fill="both", expand=True)

# Buttons with modern design - ALL ORANGE
btn_container = tk.Frame(editor_frame, bg="#0d1117", height=80)
btn_container.pack(fill="x", pady=20)

btn_frame = tk.Frame(btn_container, bg="#0d1117")
btn_frame.pack(expand=True)

# All buttons ORANGE
save_btn = ttk.Button(btn_frame, text="💾 SAVE RULE", style="Orange.TButton", command=save_rule)
save_btn.grid(row=0, column=0, padx=15)

update_btn = ttk.Button(btn_frame, text="🔄 UPDATE RULE", style="Orange.TButton", command=update_rule)
update_btn.grid(row=0, column=1, padx=15)

exit_btn = ttk.Button(btn_frame, text="🚪 EXIT", style="Orange.TButton", command=root.destroy)
exit_btn.grid(row=0, column=2, padx=15)

# Status bar
status_frame = tk.Frame(main_container, bg="#161b22", height=40)
status_frame.pack(fill="x", pady=(10, 0))

status_label = tk.Label(status_frame, 
                        text=f"Ready | Rules will be zipped to: {ZIP_OUTPUT_DIR} | Server: {SERVER_URL}", 
                        font=("Arial", 10), 
                        fg="#8b949e", 
                        bg="#161b22")
status_label.pack(side="left", padx=15, pady=10)

# Auto-load first rule if available
def auto_load_first_rule():
    for category in categorized_rules.values():
        for rule_type, rules_list in category.items():
            if rules_list:
                first_rule = rules_list[0]
                rule_label.config(text=f"📋 Rule: {first_rule['rule_id']}")
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, json.dumps(first_rule['data'], indent=2))
                # Select in appropriate combobox
                if first_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['nmap'].values(), [])]:
                    notebook.select(nmap_tab)
                    for rule_name, combobox in nmap_comboboxes.items():
                        if first_rule['rule_id'] in [rule['rule_id'] for rule in categorized_rules['nmap'][rule_name]]:
                            combobox.set(first_rule['rule_id'])
                            break
                elif first_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['arp'].values(), [])]:
                    notebook.select(arp_tab)
                    for rule_name, combobox in arp_comboboxes.items():
                        if first_rule['rule_id'] in [rule['rule_id'] for rule in categorized_rules['arp'][rule_name]]:
                            combobox.set(first_rule['rule_id'])
                            break
                elif first_rule['rule_id'] in [rule['rule_id'] for rule in sum(categorized_rules['icmp'].values(), [])]:
                    notebook.select(icmp_tab)
                    for rule_name, combobox in icmp_comboboxes.items():
                        if first_rule['rule_id'] in [rule['rule_id'] for rule in categorized_rules['icmp'][rule_name]]:
                            combobox.set(first_rule['rule_id'])
                            break
                return

# Start auto-load after GUI is ready
root.after(100, auto_load_first_rule)

# Start the main GUI loop
root.mainloop()
