#!/usr/bin/env python3
"""
Usage:
    python3 report.py --json rules_repository/rule-xxxx.json \
        --out reports --hours 24 --ipinfo TOKEN
"""

import os, io, json, zipfile, base64, argparse, hashlib, requests, math
from datetime import datetime, timedelta
from collections import Counter
from shutil import copy2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from jinja2 import Template
from weasyprint import HTML
from pymongo import MongoClient
from bson import ObjectId
from dateutil import parser as dtparser

# --------------------
# CONFIG
# --------------------
MONGO_URI = "mongodb://localhost:27017"
ALERTS_DB = "Alerts"
ALERTS_COLLECTION = "Alerts"

# --------------------
# Helpers
# --------------------
def load_rule_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def get_related_alerts(client, src_ip, hours=24):
    db = client[ALERTS_DB]
    col = db[ALERTS_COLLECTION]
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    docs = list(col.find({"src_ip": src_ip}))
    ids, type_counts, timestamps = [], Counter(), []
    for d in docs:
        ids.append(str(d.get("_id")))
        t = d.get("start_time") or d.get("created") or d.get("timestamp")
        parsed = None
        if t:
            try:
                parsed = dtparser.parse(t)
            except:
                parsed = None
        atk = (d.get("attack_type") or d.get("alert_type") or "UNKNOWN").upper()
        if parsed and parsed >= cutoff:
            timestamps.append(parsed)
        type_counts[atk] += 1
    return len(docs), ids, dict(type_counts), timestamps


def get_raw_alert(client, alert_id):
    db = client[ALERTS_DB]
    col = db[ALERTS_COLLECTION]
    doc = None
    try:
        doc = col.find_one({"_id": ObjectId(alert_id)})
    except:
        doc = col.find_one({"_id": alert_id})
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc

def compute_risk(cvss_score, related_count, reputation_score=0.5, asset_criticality=0.5):
    cvss_norm = (cvss_score or 0) / 10.0
    freq_norm = min(related_count, 10) / 10.0
    r = (cvss_norm * 0.50 + freq_norm * 0.30 +
         reputation_score * 0.15 + asset_criticality * 0.05) * 100.0
    return round(r, 1)

def risk_category(score):
    if score >= 85: return "Critical"
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    if score > 0: return "Low"
    return "None"

def make_pie_chart(counts_dict, title="", top_n=8):
    if not counts_dict:
        return None

    # Sort and pick top_n, aggregate rest as "Other"
    items_sorted = sorted(counts_dict.items(), key=lambda x: x[1], reverse=True)
    if len(items_sorted) > top_n:
        top = items_sorted[:top_n]
        others = items_sorted[top_n:]
        other_sum = sum(v for _, v in others)
        items_processed = top + [("Other", other_sum)] if other_sum > 0 else top
    else:
        items_processed = items_sorted

    labels = [k if len(k) <= 30 else k[:27] + "..." for k, _ in items_processed]
    values = [v for _, v in items_processed]
    colors = ['#FF9999', '#66B2FF', '#99FF99', '#FFCC99', '#FF99CC', '#CC99FF', '#99CCFF', '#FFFF99', '#FF6666']

    fig, ax = plt.subplots(figsize=(6, 6))
    patches = ax.pie(values, colors=colors[:len(values)], startangle=140, wedgeprops={'linewidth': 0.5, 'edgecolor': 'white'})[0]

    # Create a legend-like box with colored labels
    legend_elements = [plt.Line2D([0], [0], marker='s', color='w', label=f'{label} ({value})', markerfacecolor=color, markersize=10)
                      for label, value, color in zip(labels, values, colors[:len(values)])]
    ax.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0.5), title="Alert Distribution")

    ax.axis('equal')
    plt.tight_layout(pad=0.1)  # Reduced padding from default to minimize space
    bio = io.BytesIO()
    fig.savefig(bio, format="png", dpi=140, bbox_inches='tight')
    plt.close(fig)
    bio.seek(0)
    return base64.b64encode(bio.read()).decode("ascii")

def fetch_ipinfo(ip, token=None):
    if not token:
        return None
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json",
                            params={"token": token}, timeout=6)
        if resp.status_code == 200:
            return resp.json()
    except:
        return None
    return None

def normalize_ipinfo(ipinfo_data):
    if not ipinfo_data:
        return None
    if "bogon" in ipinfo_data:
        return {
            "country": "Private Network",
            "city": "Internal",
            "org": None,
            "raw": ipinfo_data
        }
    ipinfo_data["raw"] = ipinfo_data
    return ipinfo_data

# --------------------
# HTML Template
# --------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Rule Report - {{ rule_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 10px; page-break-inside: avoid; } /* Reduced margin from 20px to 10px */
        h1 { color: black; margin: 5px 0; } /* Reduced margin */
        .threat-level { color: {{ color }}; }
        hr { border: 0; height: 1px; background: {{ color }}; margin: 5px 0; } /* Reduced margin */
        h2 { color: black; font-size: 16px; margin: 5px 0; } /* Reduced margin */
        table { border-collapse: collapse; width: auto; margin: 5px 0; font-size: 12px; page-break-inside: avoid; } /* Reduced margin */
        th, td { border: 1px solid #ddd; padding: 4px; text-align: left; }
        th { background-color: #f2f2f2; }
        .section { margin: 5px 0; page-break-inside: avoid; } /* Reduced margin */
        img { max-width: 350px; height: auto; margin: 0; } /* Removed margin to reduce space around image */
        .footer { font-size: 10px; position: fixed; bottom: 0; width: 100%; margin: 0; } /* Removed margin */
        p { margin: 2px 0; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Rule Report &mdash; {{ rule_id }}</h1>
    <p>Created: {{ created }} | Threat Level: <span class="threat-level">{{ risk_category }}</span></p>
    <p>Executive summary: {{ executive_summary }}</p>
    <hr />
    <div class="section">
        <h2>Technical summary</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><th>Rule ID</th><td>{{ rule_id }}</td></tr>
            <tr><th>Alert Type</th><td>{{ rule.alert_type or 'N/A' }}</td></tr>
            <tr><th>Src IP</th><td>{{ rule.src_ip or 'N/A' }}</td></tr>
            <tr><th>Target IP</th><td>{{ rule.target_ip or 'N/A' }}</td></tr>
            <tr><th>Ports</th><td>{{ rule_ports or 'None' }}</td></tr>
            <tr><th>CVSS</th><td>{{ cvss_score or 'N/A' }}</td></tr>
            <tr><th>Risk score</th><td>{{ risk_score }} ({{ risk_category }})</td></tr>
            <tr><th>Decision</th><td>{{ rule.decision.action }} &mdash; {{ rule.decision.reason }}</td></tr>
        </table>
    </div>
    <div class="section">
        <h2>Correlation / Related alerts</h2>
        <p>Related alerts (last {{ hours }}h): {{ related_count }}</p>
        {% if pie_b64 %}
            <p>Alert distribution</p>
            <img src="data:image/png;base64,{{ pie_b64 }}" alt="Alert Distribution Pie Chart" />
        {% endif %}
    </div>
    <div class="section">
        <h2>Enrichment</h2>
        <table>
            <tr><th>Country</th><td>{{ ipinfo.country or 'N/A' }}</td></tr>
            <tr><th>City</th><td>{{ ipinfo.city or 'N/A' }}</td></tr>
            {% if ipinfo.org %}
            <tr><th>Organization</th><td>{{ ipinfo.org or 'N/A' }}</td></tr>
            {% endif %}
            <tr><th>Reputation Score</th><td>{{ reputation_score }}</td></tr>
            <tr><th>IP Info Raw</th><td>{{ ipinfo_simple or 'N/A' }}</td></tr>
        </table>
    </div>
    <div class="section">
        <h2>Evidence</h2>
        <p>Raw alert: {{ rule.raw_alert }}</p>
        <p>Capture Time: {{ rule.start_time or 'N/A' }}</p>
    </div>
    <div class="footer">
        <p>Created by: rule-generator | Reviewed by: N/A | SHA256: 0c912439d26ae97b6aabfe622de0724318ce44d855fdad4808a8bcfce9809554</p>
    </div>
</body>
</html>
"""

def generate_report(rule_json_path, outdir="reports", hours=24, ipinfo_token=None):
    rule = load_rule_json(rule_json_path)
    rule_id = rule.get("rule_id") or os.path.splitext(os.path.basename(rule_json_path))[0]

    rule.setdefault("target_ip", None)
    rule.setdefault("duration", rule.get("duration_sec", 0))
    rule.setdefault("ports", [])
    rule.setdefault("ports_scanned_count", 0)
    rule.setdefault("start_time", None)
    rule.setdefault("decision", {"action": "N/A", "reason": "N/A"})

    # Create REPORTS and zip folders
    reports_dir = os.path.join(outdir, "REPORT")
    zip_dir = os.path.join(outdir, "zip")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(zip_dir, exist_ok=True)

    client = MongoClient(MONGO_URI)
    related_count, related_ids, type_counts, timestamps = get_related_alerts(
        client, rule.get("src_ip"), hours=hours)

    if rule.get("source_alert_id"):
        raw_alert = get_raw_alert(client, rule["source_alert_id"])
        if raw_alert:
            compact = {k: raw_alert.get(k) for k in ["alert_type", "src_ip", "target_ip", "ports", "start_time", "duration"]}
            rule["raw_alert"] = ", ".join(f"{k}: {v if v is not None else 'null'}" for k,v in compact.items())

            # Map missing fields from Mongo alert
            rule["start_time"] = rule.get("start_time") or raw_alert.get("start_time")
            rule["target_ip"] = rule.get("target_ip") or raw_alert.get("target_ip")
            rule["ports"] = raw_alert.get("ports", []) if not rule.get("ports") else rule["ports"]

    ipinfo_data = None
    ipinfo_simple = 'N/A'
    if rule.get("src_ip"):
        raw_ipinfo = fetch_ipinfo(rule.get("src_ip"), token=ipinfo_token)
        ipinfo_data = normalize_ipinfo(raw_ipinfo)
        if ipinfo_data and "raw" in ipinfo_data:
            ipinfo_simple = ", ".join(f"{k}: {v if v is not None else 'null'}" for k,v in ipinfo_data["raw"].items())

    cvss_score = float(rule.get("cvss_score") or 0)
    reputation_score = 0.5
    if ipinfo_data and ipinfo_data.get("org"):
        org = ipinfo_data.get("org", "").lower()
        reputation_score = 1.0 if any(x in org for x in ["bad","malware","spam","abuse"]) else 0.6

    risk = compute_risk(cvss_score, related_count, reputation_score, 0.5)
    rcat = risk_category(risk)
    pie_b64 = make_pie_chart(type_counts)
    signature = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()
    executive_summary = f"Detected {rule.get('alert_type')} from {rule.get('src_ip')} targeting {rule.get('target_ip') or 'N/A'}."
    color = "#f39c12" if rcat in ("Medium","High") else ("#e74c3c" if rcat=="Critical" else "#2ecc71")
    created = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    rule_ports = ", ".join(map(str, rule["ports"])) if rule["ports"] else 'None'

    tmpl = Template(HTML_TEMPLATE)
    html = tmpl.render(
        rule=rule, rule_id=rule_id,
        risk_score=risk, risk_category=rcat,
        related_count=related_count,
        pie_b64=pie_b64, hours=hours,
        ipinfo=ipinfo_data,
        reputation_score=reputation_score,
        created_by=rule.get("created_by","rule-generator"),
        reviewed_by=rule.get("reviewed_by"),
        signature_hash=signature,
        executive_summary=executive_summary,
        color=color,
        created=created,
        cvss_score=cvss_score,
        ipinfo_simple=ipinfo_simple,
        rule_ports=rule_ports
    )

    pdf_path = os.path.join(reports_dir, f"{rule_id}-report.pdf")
    HTML(string=html).write_pdf(pdf_path)

    # Create zip file with RULE.json and REPORT.pdf
    zip_path = os.path.join(zip_dir, f"{rule_id}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(rule_json_path, arcname=f"{rule_id}.json")
        zf.write(pdf_path, arcname=f"{rule_id}-report.pdf")

    print(f"[+] PDF report created: {pdf_path}")
    return {"pdf": pdf_path, "zip": zip_path}

def main():
    parser = argparse.ArgumentParser(description="Generate compact PDF report from a rule JSON")
    parser.add_argument("--json", required=True)
    parser.add_argument("--out", default="reports")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--ipinfo", help="ipinfo.io token (required)")
    args = parser.parse_args()
    generate_report(args.json, outdir=args.out, hours=args.hours,
                    ipinfo_token=args.ipinfo)

if __name__ == "__main__":
    main()
