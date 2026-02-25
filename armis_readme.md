# Armis Collectors – Product Listing and Aging View

This dashboard provides centralized operational visibility into deployed Armis Collectors, combining inventory, lifecycle age, network configuration posture, and proxy compliance into a single view.

---

## What This View Provides Visibility Into

### Collector Inventory
- Total number of collectors
- Identification of the oldest and newest collector
- Creation date and last seen timestamp
- Hardware vendor and product serial number
- MAC address and IP address
- Subnet and default gateway

This enables lifecycle tracking and validation of reporting collectors.

---

### Collector Aging
- Exact age (years, months, weeks, days, minutes)
- Aging comparison across all deployed collectors

This supports lifecycle management and identification of outdated deployments.

---

### Network Configuration Posture
- Collectors using APIPA (169.254.x.x)
- Collectors with blank default gateways
- DNS configuration visibility
- NTP configuration visibility
- Percentage distribution of common DNS/NTP settings

This identifies misconfigurations and configuration drift.

---

### Proxy Configuration Compliance
- Number of collectors using the approved proxy
- Percentage using approved proxy
- Percentage using non-approved proxy
- Count of collectors with proxy misconfiguration

This validates outbound network policy compliance.

---

### Operational Status Distribution
- Active
- Collector Received
- Inactive
- In Shipping

This provides operational deployment state visibility.

---

### Detailed Collector Listing
A full table view including:
- Collector ID
- Hostname
- Vendor
- Serial number
- MAC address
- IP address
- Subnet
- Default gateway
- DNS servers
- NTP servers
- Calculated age

This enables direct operational troubleshooting and configuration validation.
