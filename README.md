# Armis Centrix™ for Splunk App

---

## Overview

The **Armis Centrix™ for Splunk App** integrates Armis telemetry directly into Splunk, enabling security teams, analysts, and executives to analyze exposure risk, vulnerabilities, alerts, and asset intelligence from a centralized analytics platform.

The application uses the **Armis Centrix REST API** to ingest operational telemetry, asset inventory, vulnerabilities, alerts, and exposure intelligence into Splunk.

All data is ingested into a user-defined Splunk index and stored in **raw JSON format**, preserving the original structure of the Armis platform data.

This enables Splunk users to:

- Investigate security events
- Monitor device exposure
- Analyze vulnerabilities
- Track asset posture
- Generate reports
- Correlate Armis telemetry with other enterprise security data

- asset identification across ICS and OT environments
- monitoring industrial protocols
- behavioral anomaly detection
- network segmentation analysis


---

![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active%20development-yellow.svg)

---

# ⚠️ Disclaimer

This application is **not an official Armis product**.

This integration is developed independently using publicly available Armis documentation and APIs.

Use of this software is **not covered by any Armis license, warranty, or support agreement**.

---

# Dashboards

| Dashboard | Description |
|-----------|-------------|
| 🧭 Overview | Global cyber exposure posture across all discovered assets |
| 🖥️ Assets | Complete asset inventory discovered by Armis across IT, OT, IoT, IoMT, and cloud |
| 🧠 Asset Intelligence | Device classification, behavioral fingerprinting, and asset context |
| 🌐 Asset Communications | Device-to-device communication analysis and network interaction mapping |
| 🚨 Alerts | Active Armis alerts and threat detections |
| 🔥 Alerts — By Severity | Alerts grouped by severity for rapid triage |
| 🧬 Vulnerabilities | Vulnerabilities detected across discovered assets |
| 🎯 VIPR Prioritization | Vulnerabilities prioritized by Armis VIPR exploitability intelligence |
| 📊 Exposure Analytics | Cyber exposure metrics and attack surface analysis |
| 📈 Exposure Trends | Exposure posture changes over time |
| 🏷️ Asset Tags | Asset tagging and classification metadata |
| 🧠 Threat Intelligence | Armis threat intelligence insights and exploit context |
| 👤 Users | Platform users and access visibility |
| ⏳ User Activity | User login activity and access history |
| 🔐 Roles | Role definitions and privilege assignments |
| 🛡️ Permissions | Role-to-permission mappings |
| 🔑 API Keys | API credential inventory |
| 🔗 Integrations | External security platform integrations |
| ⚙️ Configuration | Platform configuration telemetry |
| 📄 Reports | Armis-generated reports and exposure summaries |
| 📜 Audit Logs | Administrative audit events |
| ⚠️ Error Logs | Ingestion and API error logs |
| ❤️ System Health | Platform operational health indicators |
| 🏷️ Version | Armis Centrix platform version information |
| 📚 Documentation | Embedded product documentation |
| 🛟 Support | Support resources and troubleshooting |
| ℹ️ About | Application integration information |

---

### Collector Operational Telemetry

Armis collectors provide operational telemetry related to sensor deployment,
network configuration, and collector lifecycle status.

- Collector ID
- Name
- Creation Date (GMT -4)
- Last Seen (GMT -4)
- Status
- IP Address
- MAC Address
- Default Gateway
- Subnet
- DNS Servers
- NTP Servers
- Https Proxy
- System Vendor
- Product Serial

---

# Supported Environments

Armis Centrix supports monitoring across a broad range of environments including:

- Enterprise IT networks
- IoT deployments
- Operational Technology (OT)
- Medical device environments
- Industrial environments
- Cloud infrastructure
- Hybrid enterprise networks

---

# Device Categories Supported

Armis identifies and classifies a wide range of device types including:

- Servers
- Workstations
- Networking equipment
- IoT devices
- Industrial control systems
- Medical devices
- Printers
- Security cameras
- Smart building systems
- Cloud workloads
- Virtual machines
- Mobile devices

---

# Data Collected

## Asset Inventory

- asset_id
- device_name
- device_type
- ip_address
- mac_address
- manufacturer
- model
- operating_system
- firmware
- first_seen
- last_seen
- network_zone
- risk_score

---

## Alerts

- alert_id
- severity
- category
- description
- impacted_assets
- attack_vector
- recommended_action
- timestamps

---

## Vulnerabilities

- vulnerability_id
- cve
- severity
- cvss_score
- affected_assets
- exploitability
- remediation
- discovery_timestamp

---

## Exposure Intelligence

- exposure_score
- risk_level
- attack_surface
- device_risk_rating
- vulnerability_count

---

# Data Ingestion Model

The **Armis Centrix for Splunk App** retrieves data from Armis using the **Armis Centrix REST API**.

Data is ingested on a scheduled polling basis and stored as raw JSON events in Splunk.

Each dataset is mapped to a dedicated Splunk **sourcetype** for analytics and dashboard use.

---

# UI → API → Splunk Data Mapping

| Armis UI Area | API Endpoint | Splunk Sourcetype |
|---------------|-------------|------------------|
| Assets | `/api/v1/assets` | `armis:assets` |
| Alerts | `/api/v1/alerts` | `armis:alerts` |
| Vulnerabilities | `/api/v1/vulnerabilities` | `armis:vulnerabilities` |
| Device Communications | `/api/v1/communications` | `armis:network` |
| Exposure Intelligence | `/api/v1/exposure` | `armis:exposure` |
| Users | `/api/v1/users` | `armis:users` |
| Audit Logs | `/api/v1/audit` | `armis:audit` |
| Reports | `/api/v1/reports` | `armis:reports` |
| System Information | `/api/v1/version` | `armis:meta` |

---

# Installation

## Step 1 — Install the App

1. Download the **Armis Centrix™ for Splunk App**
2. In Splunk Web navigate to:

Apps → Manage Apps

3. Select **Install app from file**
4. Upload the application package
5. Restart Splunk if prompted

---

## Step 2 — Configure the App

1. Open the **Armis Centrix™** Splunk App
2. Navigate to **Settings → Configuration**
3. Configure:

- Armis API URL
- API credentials
- Splunk index
- Polling interval
- Proxy settings (optional)

4. Save configuration

---

## Step 3 — Verify Data Collection

Run a Splunk search:




---

# Directory Structure

```
Armis_Centrix_For_Splunk_App/
├── app.manifest
├── LICENSE
├── README.md
├── default/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
│   ├── macros.conf
│   ├── restmap.conf
│   ├── savedsearches.conf
│   ├── web.conf
│   └── data/
│       └── ui/
│           ├── nav/
│           │   └── default.xml
│           └── views/
│               ├── setup.xml
│               ├── armis_overview.xml
│               ├── armis_assets.xml
│               ├── armis_alerts.xml
│               ├── armis_vulnerabilities.xml
│               ├── armis_exposure.xml
│               ├── armis_reports.xml
│               ├── armis_logs.xml
│               ├── armis_documentation.xml
│               ├── armis_support.xml
│               └── armis_about.xml
├── bin/
│   ├── armis_input.py
│   ├── armis_setup_handler.py
│   └── armis_validation.py
├── metadata/
│   ├── default.meta
│   └── local.meta
└── static/
├── appIcon.png
└── appIcon_2x.png

```

---

# Requirements

- Splunk Enterprise or Splunk Cloud
- Network connectivity to Armis Centrix platform
- Valid Armis API credentials
- Python 3.10+

---

# AppInspect Compliance

- Standard Splunk app directory structure
- Inputs disabled by default
- Secure credential handling
- No hardcoded secrets
- JSON-based ingestion
- MIT License

---

# References

Armis Centrix documentation  
https://www.armis.com

Splunk documentation  
https://docs.splunk.com

---

# MIT License

Copyright (c) 2026 Mark Teicher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files to deal in the Software
without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.


-  
