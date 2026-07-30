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
<img width="581" height="358" alt="image" src="https://github.com/user-attachments/assets/e9c8b05d-818a-4170-a0f3-b0f40e213f87" />
## Component Diagram
<img width="464" height="532" alt="image" src="https://github.com/user-attachments/assets/104708b2-edd0-472d-b90d-f154eea1b34e" />
## Deployment Diagram
<img width="6608" height="4148" alt="image" src="https://github.com/user-attachments/assets/46081cba-c8b4-43cf-aa59-34eec5a62bee" />


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

