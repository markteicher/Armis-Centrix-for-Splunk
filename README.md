# Armis Centrix for Splunk App


---


## Overview

**Armis Centrix™** is an **AI-powered, cloud-native cyber exposure management platform** designed to provide real-time visibility, security posture analysis, and threat detection across an organization's entire **attack surface**.

Unlike traditional security tools that focus on a limited set of device categories, Armis Centrix is built to discover and secure **everything connected to a network**, including:

- Traditional IT infrastructure
- Internet of Things (IoT)
- Operational Technology (OT)
- Industrial Control Systems (ICS)
- Medical devices (IoMT)
- Cloud workloads
- Virtual infrastructure
- Unmanaged or unknown devices

The platform continuously discovers, profiles, and monitors assets across enterprise environments to eliminate security blind spots and provide organizations with a **single source of truth for cyber exposure**.

The **Armis Centrix™ for Splunk App** integrates Armis telemetry directly into Splunk using the **Armis Centrix REST APIs**, allowing organizations to analyze device intelligence, exposure risk, vulnerabilities, alerts, and security posture directly within the Splunk analytics platform.

All telemetry is ingested into a user-specified Splunk index and stored in **raw JSON format**, preserving the original structure of Armis platform data.

This enables security teams, analysts, and executives to:

- Monitor enterprise device exposure
- Investigate security alerts
- Analyze vulnerabilities and exploitability
- Track asset posture and behavior
- Generate security and exposure reports
- Correlate Armis intelligence with other security telemetry in Splunk

---

## Key Capabilities

Armis Centrix is built as a **modular cyber exposure management platform**. Organizations can deploy specific capabilities depending on operational requirements.

### Asset Management & Security

Armis acts as a **single source of truth for asset inventory** by discovering and classifying every connected asset across the environment.

Assets discovered include:

- managed devices
- unmanaged devices
- IT systems
- IoT devices
- OT equipment
- medical devices
- cloud workloads
- virtual machines

This eliminates visibility gaps and ensures organizations understand **what is actually connected to their networks**.

---

### Vulnerability Management (VIPR)

Armis Centrix includes **Vulnerability Intelligence Prioritization and Remediation (VIPR)**.

Instead of overwhelming teams with thousands of vulnerability alerts, VIPR:

- prioritizes vulnerabilities based on exploitability
- identifies which vulnerabilities are actually **reachable within your environment**
- evaluates **real-world threat intelligence and exploit trends**
- reduces alert noise so security teams can focus on **high-risk exposures**

---

### OT / IoT Security

Armis Centrix provides dedicated protection for **industrial and operational technology environments**.

Capabilities include:

- asset identification across ICS and OT environments
- monitoring industrial protocols
- behavioral anomaly detection
- network segmentation analysis

The platform operates **agentlessly**, ensuring sensitive operational equipment is **not disrupted**.

---

### Medical Device Security

Armis provides specialized security for **healthcare environments and clinical devices**.

Capabilities include:

- discovery of medical and IoMT devices
- device risk assessment
- vulnerability analysis
- regulatory compliance support

This helps healthcare organizations maintain **patient safety and operational reliability**.

---

### Application Security

Armis Centrix also supports **application security analysis**, including:

- vulnerability scanning of application codebases
- CI/CD pipeline security analysis
- detection of vulnerabilities introduced by **AI-generated code**
- software supply chain risk visibility

---

## How Armis Centrix Works

### AI-Driven Intelligence

The platform is powered by the **Armis Asset Intelligence Engine**, a global knowledge base tracking **billions of devices worldwide**.

This intelligence enables Armis to:

- identify device types
- detect abnormal behavior
- recognize attack patterns
- understand normal communication baselines

---

### Agentless Architecture

Armis Centrix operates without requiring agents on devices.

Instead it uses:

- passive network monitoring
- behavioral analytics
- safe active queries

This allows the platform to discover devices **without installing software or disrupting production systems**.

---

### Early Threat Detection

Armis Centrix provides an **early warning system for emerging threats**.

The platform analyzes:

- exploit development trends
- threat actor behavior
- dark web activity
- vulnerability weaponization patterns

This enables organizations to respond to threats **before public disclosure or widespread exploitation**.

---

Armis discovers and analyzes assets across networks without requiring agents. The platform continuously monitors device behavior, communication patterns, and vulnerabilities to identify risks and potential attack paths.

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
|----------|-------------|
| ✅ Overview | Global Armis exposure and platform posture |
| 🖥️ Assets | Discovered device inventory across IT, IoT, OT, and medical |
| 🌐 Asset Communications | Device-to-device communication analysis |
| 🚨 Alerts | Active Armis alerts and security events |
| 🔥 Alerts — By Severity | Alerts grouped by severity |
| 🧬 Vulnerabilities | Vulnerability intelligence across devices |
| 📊 Exposure Analytics | Risk and exposure scoring |
| 📈 Asset Exposure Trends | Device exposure trends over time |
| 🏷️ Asset Tags | Device classification and tagging |
| 🧠 Threat Intelligence | Armis threat intelligence context |
| 👤 Users | Platform user accounts |
| ⏳ User Activity | User login activity and access monitoring |
| 🔐 Roles | Role definitions and privilege structure |
| 🛡️ Permissions | Permission mapping and access control |
| 🔑 API Keys | API access credentials |
| 🔗 Integrations | External platform integrations |
| ⚙️ Configuration | Platform configuration telemetry |
| 📄 Reports | Armis platform reporting data |
| 📊 Exposure Reports | Executive exposure summaries |
| 📜 Audit Logs | Administrative audit events |
| ⚠️ Error Logs | Data ingestion and API error logs |
| ❤️ System Health | Platform operational health |
| 🏷️ Version | Armis platform version information |
| 📚 Documentation | Embedded product documentation |
| 🛟 Support | Support and troubleshooting resources |
| ℹ️ About | Application information |

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


## Dashboards

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

## Data Collected

### Asset Inventory

Armis continuously discovers and profiles all devices connected to the network.

- asset_id  
- device_name  
- device_type  
- device_category  
- ip_address  
- mac_address  
- manufacturer  
- model  
- operating_system  
- firmware_version  
- asset_risk_level  
- asset_tags  
- network_zone  
- location  
- first_seen  
- last_seen  

---

### Alerts & Security Events

Armis generates alerts when abnormal device behavior, policy violations, or known threat patterns are detected.

- alert_id  
- alert_type  
- severity  
- category  
- description  
- impacted_assets  
- detection_source  
- attack_vector  
- recommended_action  
- status  
- timestamps  

---

### Vulnerabilities

Armis identifies vulnerabilities associated with assets and prioritizes them using VIPR.

- vulnerability_id  
- cve  
- severity  
- cvss_score  
- exploitability_score  
- affected_assets  
- remediation  
- discovery_timestamp  

---

### Exposure Intelligence

Exposure analytics evaluates risk across the entire attack surface.

- exposure_score  
- risk_level  
- attack_surface_size  
- asset_risk_rating  
- vulnerability_count  
- exploitable_vulnerabilities  

---

### Asset Communications

Armis analyzes communication patterns between devices.

- source_asset  
- destination_asset  
- protocol  
- communication_frequency  
- anomalous_behavior  

---

## Data Ingestion Model

The **Armis Centrix™ for Splunk App** retrieves telemetry from the Armis Centrix platform using the **Armis REST APIs**.

The integration performs scheduled polling of platform datasets including:

- asset inventory
- alerts
- vulnerabilities
- exposure intelligence
- communications telemetry
- audit logs
- platform metadata

Each dataset is ingested into Splunk and preserved in **raw JSON format** to maintain complete fidelity with the source platform.

### Ingestion Characteristics

- Polling-based REST API ingestion
- Raw JSON event storage
- Dataset-specific sourcetypes
- User-configurable Splunk index
- Secure credential storage
- API pagination support
- Fault-tolerant ingestion

---

## UI → API → Splunk Data Mapping

| Armis UI Area | API Endpoint | HTTP Method | Splunk Sourcetype |
|----------------|--------------|-------------|-------------------|
| Assets | `/api/v1/assets` | GET | `armis:assets` |
| Asset Intelligence | `/api/v1/assets/{id}` | GET | `armis:assets` |
| Alerts | `/api/v1/alerts` | GET | `armis:alerts` |
| Vulnerabilities | `/api/v1/vulnerabilities` | GET | `armis:vulnerabilities` |
| Exposure Intelligence | `/api/v1/exposure` | GET | `armis:exposure` |
| Communications | `/api/v1/communications` | GET | `armis:network` |
| Users | `/api/v1/users` | GET | `armis:users` |
| Audit Logs | `/api/v1/audit` | GET | `armis:audit` |
| Reports | `/api/v1/reports` | GET | `armis:reports` |
| Platform Version | `/api/v1/version` | GET | `armis:meta` |
| System Health | `/api/v1/status` | GET | `armis:meta` |

---

## Splunk Data Structure

The integration assigns each dataset a dedicated **Splunk sourcetype**.

| Dataset | Sourcetype |
|--------|-------------|
| Asset Inventory | `armis:assets` |
| Alerts | `armis:alerts` |
| Vulnerabilities | `armis:vulnerabilities` |
| Exposure Intelligence | `armis:exposure` |
| Communications | `armis:network` |
| Users | `armis:users` |
| Audit Logs | `armis:audit` |
| Reports | `armis:reports` |
| Platform Metadata | `armis:meta` |

All events are stored as **raw JSON** allowing Splunk users to perform flexible analytics, correlation, and reporting.

---

## Splunk Integration Benefits

Using Armis telemetry inside Splunk enables organizations to:

- correlate Armis data with SIEM events  
- enrich threat investigations with device intelligence  
- monitor cyber exposure across the enterprise  
- generate executive exposure reports  
- track vulnerabilities and exploitability trends  
- analyze device communications and behavior

  
