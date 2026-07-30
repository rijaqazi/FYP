# Proactive Defense Mechanism Using AIS-Based Threat Intelligence

A centralized web platform for post-threat analysis, automated firewall rule generation, and secure Indicator of Compromise (IOC) sharing between organizations — built on Automated Indicator Sharing (AIS) principles.

## Overview

Traditional security systems are largely reactive and operate in silos, updating manually and responding only after damage is done. This project addresses that gap by providing a centralized system where organizations can submit threat data (or have it collected from logs), automatically analyze it using CVSS scoring, extract IOCs, generate actionable firewall rules, and securely share verified intelligence with trusted partners — enabling faster, more collaborative, proactive defense.

## Key Features

- **User Authentication & Role-Based Access** — secure login/signup with roles for analysts, administrators, etc.
- **Threat Data Input & Analysis** — organizations submit threat data, evaluated against CVSS scoring to determine severity.
- **IOC Extraction** — automatic identification of Indicators of Compromise from submitted/collected data.
- **Rule Generation Engine** — automatically produces implementable firewall rules based on threat analysis.
- **IOC Sharing Mechanism** — distributes verified IOCs and rules to affiliated organizations using STIX/TAXII standards.
- **Interactive Dashboard** — real-time threat analytics, notifications, and visualizations per organization.
- **Report Generation & Sharing** — downloadable or securely transmitted threat analysis reports for stakeholders.

## System Architecture

The system is composed of the following core modules:

- **User Interface (UI)** — web interface for registration/login, threat data entry, and access to dashboards, alerts, rules, and reports.
- **Threat Analysis Engine** — evaluates submitted threat data using CVSS-based vulnerability assessment and IOC recognition.
- **Rule Generation Module** — automatically produces firewall rules from analyzed threat patterns for administrator review.
- **IOC Sharing System** — securely transmits authorized IOCs and rules to registered entities, following the AIS framework.
- **Database** — centralized storage for threat reports, organization data, user roles, and sharing logs.
- **Reporting Module** — aggregates threat data, severity ratings, and actions into shareable/downloadable reports.

## System Diagram
<img width="1607" height="979" alt="ChatGPT Image Jul 30, 2026, 06_33_06 PM" src="https://github.com/user-attachments/assets/626037ed-3968-452f-a6a8-0828054571b3" />


## Deployment Diagram
<img width="1567" height="1004" alt="ChatGPT Image Jul 30, 2026, 06_39_38 PM" src="https://github.com/user-attachments/assets/0812f6f6-243e-45f4-a920-4ba0e3c09967" />

## User Interface
### Dashboard

### Alerts
<img width="1698" height="873" alt="ChatGPT Image Jul 30, 2026, 06_46_48 PM" src="https://github.com/user-attachments/assets/5e3facb8-61f6-4349-b73b-2d7245fe6a25" />

### Alert Notification
<img width="1706" height="922" alt="ChatGPT Image Jul 30, 2026, 06_43_03 PM" src="https://github.com/user-attachments/assets/33b6b369-2027-460f-a0fe-649358a564a5" />



## Tech Stack

| Layer | Technology |
|---|---|
| Analysis / Backend | Python |
| Packet Capture & Protocol Dissection | Wireshark, TShark |
| Database | MongoDB Atlas (cloud) + flat JSON files for raw logs |
| Frontend | HTML, CSS, JavaScript |
| Threat Intelligence Standards | STIX/TAXII, CVSS |
| Test Environment | Ubuntu (defender), Kali Linux (attacker simulation) |

## Usage

1. Register/log in as an organization.
2. Submit threat data manually, or let the system ingest it from captured logs.
3. View CVSS-scored analysis and extracted IOCs on the dashboard.
4. Review auto-generated firewall rules.
5. Share verified IOCs with trusted partner organizations via STIX/TAXII.
6. Generate and download/share threat reports.

