
	

#!/usr/bin/env python3
"""
Advanced Rule Editor - Updated for New Folder Structure with Actual Rule Filenames
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json, zipfile, os, shutil, glob
import hashlib
from datetime import datetime

RULES_REPO_DIR = "/home/defender/Desktop/Rule_Generation/rules_repository"
REPORTS_DIR = "/home/defender/Desktop/Rule_Generation/reports/REPORT"
OUTPUT_DIR = os.path.join(os.getcwd(), "exported_rules")
ZIP_OUTPUT_DIR = os.path.join(os.getcwd(), "extracted_rules_zip")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ZIP_OUTPUT_DIR, exist_ok=True)

rules_dict = {
    # Nmap Detection 
    "SYN_SCAN": "SYN Scan",
    "FULL_PORT_SCAN": "Full Port Scan", 
    "FIN_SCAN": "FIN Scan",
    "XMAS_SCAN": "XMAS Scan",
    "NULL_SCAN": "NULL Scan",
    "ACK_SCAN": "ACK Scan",
    "UDP_SCAN": "UDP Scan",
    "OS_FINGERPRINT": "OS Fingerprint",
    "RST_FLOOD": "RST Flood",
    "SPOOFED_SYN_FLOOD": "Spoofed SYN Flood",
    
    # ARP Attacks 
    "ARP_SPOOF": "ARP Spoofing",
    "GRATUITOUS_ARP": "Gratuitous ARP", 
    "BROADCAST_SPOOF": "Broadcast Spoof",
    "ARP_FLOOD": "ARP Flood",
    "MAC_CONFLICT": "MAC Conflict",
    "ARP_MITM": "ARP MITM",
    
    # ICMP Attacks 
    "ICMP_ECHO_REQUEST_FLOOD": "ICMP Echo Request Flood",
    "SMURF_ATTACK": "Smurf Attack",
    "ICMP_TIMESTAMP_REQUEST_FLOOD": "ICMP Timestamp Request Flood",
    "ICMP_ADDRESS_MASK_REQUEST_FLOOD": "ICMP Address Mask Request Flood"
}


def sha256_file(path):
    """Calculate SHA256 hash of a file"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def find_report_pdf(rule_id):
    """Find the corresponding PDF report for a rule"""
    # Look for report with pattern rule-{id}-report.pdf
    report_pattern = os.path.join(REPORTS_DIR, f"{rule_id}-report.pdf")
    if os.path.exists(report_pattern):
        return report_pattern
    
    
    report_pattern2 = os.path.join(REPORTS_DIR, f"{rule_id}.pdf")
    if os.path.exists(report_pattern2):
        return report_pattern2
    
    
    for filename in os.listdir(REPORTS_DIR):
        if filename.startswith(rule_id) and filename.endswith('.pdf'):
            return os.path.join(REPORTS_DIR, filename)
    
    return None


def scan_and_map_rules():
    """
    Scan RULES_REPO_DIR for rule JSON files and categorize them by attack type
    Returns categorized rules dictionary with actual filenames
    """
    categories = {
        'nmap': {},
        'arp': {},
        'icmp': {}
    }
    
    if not os.path.isdir(RULES_REPO_DIR):
        print(f" Rules repository directory not found: {RULES_REPO_DIR}")
        return categories

    # Scan all JSON files in rules_repository
    for filename in os.listdir(RULES_REPO_DIR):
        if not filename.endswith('.json'):
            continue
            
        file_path = os.path.join(RULES_REPO_DIR, filename)
        rule_id = filename.replace('.json', '')  # This gives us the actual filename like 'rule-3fb8b2ae'
        
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                alert_type = data.get("alert_type", "").upper()  # Read alert_type from JSON
                print(f"Processing {file_path}: alert_type = {alert_type}")  # Debugging print
                
                # Normalize alert_type by replacing spaces with underscores
                normalized_attack_type = alert_type.replace(" ", "_")
                print(f"Normalized to: {normalized_attack_type}")  # Debugging print
                
                # Find corresponding PDF report
                report_path = find_report_pdf(rule_id)
                
                # Map to the appropriate category based on normalized_attack_type
                if normalized_attack_type in ["SYN_SCAN", "FULL_PORT_SCAN", "FIN_SCAN", "XMAS_SCAN",
                                            "NULL_SCAN", "ACK_SCAN", "UDP_SCAN", "OS_FINGERPRINT",
                                            "RST_FLOOD", "SPOOFED_SYN_FLOOD"]:
                    if normalized_attack_type not in categories['nmap']:
                        categories['nmap'][normalized_attack_type] = []
                    categories['nmap'][normalized_attack_type].append({
                        'rule_id': rule_id,
                        'data': data,
                        'file_path': file_path,
                        'report_path': report_path
                    })
                elif normalized_attack_type in ["ARP_SPOOF", "GRATUITOUS_ARP", "BROADCAST_SPOOF",
                                              "ARP_FLOOD", "MAC_CONFLICT", "ARP_MITM"]:
                    if normalized_attack_type not in categories['arp']:
                        categories['arp'][normalized_attack_type] = []
                    categories['arp'][normalized_attack_type].append({
                        'rule_id': rule_id,
                        'data': data,
                        'file_path': file_path,
                        'report_path': report_path
                    })
                elif normalized_attack_type in ["ICMP_ECHO_REQUEST_FLOOD", "SMURF_ATTACK",
                                              "ICMP_TIMESTAMP_REQUEST_FLOOD", "ICMP_ADDRESS_MASK_REQUEST_FLOOD"]:
                    if normalized_attack_type not in categories['icmp']:
                        categories['icmp'][normalized_attack_type] = []
                    categories['icmp'][normalized_attack_type].append({
                        'rule_id': rule_id,
                        'data': data,
                        'file_path': file_path,
                        'report_path': report_path
                    })
                else:
                    # Default to SYN_SCAN for unknown types
                    print(f"Unknown attack type {normalized_attack_type}, defaulting to SYN_SCAN")
                    if "SYN_SCAN" not in categories['nmap']:
                        categories['nmap']["SYN_SCAN"] = []
                    categories['nmap']["SYN_SCAN"].append({
                        'rule_id': rule_id,
                        'data': data,
                        'file_path': file_path,
                        'report_path': report_path
                    })
                        
        except Exception as e:
            print(f"Failed to load {file_path}: {e}")
            continue
    
    return categories

# === File generation function ===
def generate_files_for_rule(rule_id, rule_content):
    """
    Create folder for rule in OUTPUT_DIR, save JSON 
    Then create individual zip file in ZIP_OUTPUT_DIR with JSON and PDF report
    """
    out_folder = os.path.join(OUTPUT_DIR, rule_id)
    os.makedirs(out_folder, exist_ok=True)

    # Convert string to JSON if needed
    if isinstance(rule_content, str):
        try:
            rule_content = json.loads(rule_content)
        except Exception:
            rule_content = {"raw": rule_content}

    # Write JSON file
    out_json_path = os.path.join(out_folder, f"{rule_id}.json")
    with open(out_json_path, "w") as f:
        json.dump(rule_content, f, indent=4)

    # Find the corresponding PDF report
    report_path = None
    for category_name, category in categorized_rules.items():
        for rule_type, rules_list in category.items():
            for rule_data in rules_list:
                if rule_data['rule_id'] == rule_id:
                    report_path = rule_data.get('report_path')
                    break
            if report_path:
                break
        if report_path:
            break

    zip_file_path = os.path.join(ZIP_OUTPUT_DIR, f"{rule_id}.zip")
    
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
       
        zipf.write(out_json_path, os.path.basename(out_json_path))
        
       
        if report_path and os.path.exists(report_path):
            zipf.write(report_path, os.path.basename(report_path))
            print(f"[INFO] Added PDF report to zip: {os.path.basename(report_path)}")
        else:
            print(f"[WARNING] No PDF report found for rule: {rule_id}")
    
    print(f"[INFO] Zip file created: {zip_file_path}")
    
    return out_json_path, True  # Return True as upload is skipped

def search_rule():
    """Search for rules by Rule ID (actual filename)"""
    search_term = search_entry.get().strip()
    if not search_term:
        messagebox.showinfo("Search", "Please enter a Rule ID to search")
        return
 
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
      
        rule_label.config(text=f"📋 Rule: {found_rule['rule_id']}")
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, json.dumps(found_rule['data'], indent=2))
        
      
        expand_and_select_rule(found_rule['rule_id'])
        messagebox.showinfo("Search Result", f"Rule found: {found_rule['rule_id']}")
    else:
        messagebox.showinfo("Search Result", f"No rule found with ID: {search_term}")

def expand_and_select_rule(rule_id):
    """Expand treeview and select the specified rule"""
    # Collapse all first
    for item in tree.get_children():
        tree.item(item, open=False)
    
    # Search for the rule in treeview
    for category_item in tree.get_children():
        for rule_type_item in tree.get_children(category_item):
            for rule_item in tree.get_children(rule_type_item):
                if tree.item(rule_item)["text"] == rule_id:
                    # Expand category and rule type
                    tree.item(category_item, open=True)
                    tree.item(rule_type_item, open=True)
                    # Select and focus the rule
                    tree.selection_set(rule_item)
                    tree.focus(rule_item)
                    tree.see(rule_item)  # Scroll to make it visible
                    return


def save_rule():
    """Save the currently selected rule with zip creation"""
    selected_item = tree.focus()
    if not selected_item:
        messagebox.showerror("Error", "Please select a rule first!")
        return

    selected_text = tree.item(selected_item)["text"]
    if selected_text.startswith("📂") or selected_text.startswith("📄"):
        messagebox.showerror("Error", "Please select a specific rule file!")
        return

    rule_id = selected_text  # This is the actual filename like 'rule-3fb8b2ae'
    rule_text = text_area.get("1.0", tk.END).strip()
    if not rule_text:
        messagebox.showerror("Error", "Rule content is empty.")
        return

    try:
        parsed = json.loads(rule_text)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid JSON format: {e}")
        return

    # Generate files and create zip
    out_json, _ = generate_files_for_rule(rule_id, parsed)
    
    messagebox.showinfo("Success", 
                        f"Rule '{rule_id}' processed successfully!\n\n"
                        f"Local: {out_json}\n"
                        f"Zip: {ZIP_OUTPUT_DIR}/{rule_id}.zip")

def update_rule():
    """Update rule - same as save for now"""
    save_rule()

def show_rule(event):
    """Display selected rule in text area"""
    selected = tree.item(tree.focus())["text"]
    if not selected or selected.startswith("📂") or selected.startswith("📄"):
        return

    rule_id = selected  # This is the actual filename like 'rule-3fb8b2ae'
    
    # Find rule in categorized data
    for category_name, category in categorized_rules.items():
        for rule_type, rules_list in category.items():
            for rule_data in rules_list:
                if rule_data['rule_id'] == rule_id:
                    rule_label.config(text=f"📋 Rule: {rule_id}")
                    text_area.delete("1.0", tk.END)
                    text_area.insert(tk.END, json.dumps(rule_data['data'], indent=2))
                    
                    # Show report status
                    report_status = "📄 PDF Report: Available" if rule_data.get('report_path') else "❌ PDF Report: Not found"
                    status_label.config(text=f"Ready | {report_status}")
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

# Left sidebar - Rules Navigation
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

# Treeview with modern styling
tree_container = tk.Frame(sidebar_frame, bg="#1e1e2f")
tree_container.pack(fill="both", expand=True, padx=15, pady=10)

tree_scroll = ttk.Scrollbar(tree_container)
tree_scroll.pack(side="right", fill="y")

tree = ttk.Treeview(tree_container, 
                    show="tree", 
                    yscrollcommand=tree_scroll.set,
                    style="Custom.Treeview",
                    height=25)
tree.pack(side="left", fill="both", expand=True)
tree_scroll.config(command=tree.yview)

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
                        text=f"Ready | Rules from: {RULES_REPO_DIR}", 
                        font=("Arial", 10), 
                        fg="#8b949e", 
                        bg="#161b22")
status_label.pack(side="left", padx=15, pady=10)

# === Populate Tree with Categorized Rules ===
categorized_rules = scan_and_map_rules()

# Create main category nodes
nmap_node = tree.insert("", "end", text="🛡️ Nmap Attacks", open=True)
arp_node = tree.insert("", "end", text="🔗 ARP Attacks", open=True)  
icmp_node = tree.insert("", "end", text="📡 ICMP Attacks", open=True)

# Add rules to tree - showing actual filenames like 'rule-3fb8b2ae' under each specific rule type
for category_name, category in categorized_rules.items():
    parent_node = nmap_node if category_name == 'nmap' else arp_node if category_name == 'arp' else icmp_node
    for rule_name, rules_list in category.items():
        display_name = rules_dict.get(rule_name, rule_name)
        rule_node = tree.insert(parent_node, "end", text=f"📄 {display_name}")
        for rule_data in rules_list:
            # Show actual filename like 'rule-3fb8b2ae'
            tree.insert(rule_node, "end", text=rule_data['rule_id'])

# Bind selection event
tree.bind("<<TreeviewSelect>>", show_rule)

# Auto-load first rule if available
def auto_load_first_rule():
    for category_name, category in categorized_rules.items():
        for rule_type, rules_list in category.items():
            if rules_list:
                first_rule = rules_list[0]
                rule_label.config(text=f"📋 Rule: {first_rule['rule_id']}")
                text_area.delete("1.0", tk.END)
                text_area.insert(tk.END, json.dumps(first_rule['data'], indent=2))
                
                # Show report status
                report_status = " PDF Report: Available" if first_rule.get('report_path') else " PDF Report: Not found"
                status_label.config(text=f"Ready | {report_status}")
                
                for item in tree.get_children():
                    for child in tree.get_children(item):
                        if tree.item(child)["text"] == f"📄 {rules_dict.get(rule_type, rule_type)}":
                            for grandchild in tree.get_children(child):
                                if tree.item(grandchild)["text"] == first_rule['rule_id']:
                                    tree.selection_set(grandchild)
                                    tree.focus(grandchild)
                                    return
                return


root.after(100, auto_load_first_rule)


root.mainloop()


