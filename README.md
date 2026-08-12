# Multi-Vendor Firewall & Network Audit Tool

A client-side web application designed to parse and audit configuration files from major network security vendors. This tool processes configurations entirely in the browser, ensuring sensitive infrastructure data never leaves your local machine.

## Features

*   **Security Policy Auditing:** Extracts and reviews firewall rules, access control lists (ACLs), and permit/deny statements.
*   **Routing Analysis:** Identifies BGP and OSPF routing parameters, as well as static route configurations.
*   **SD-WAN Validation:** Parses complex SD-WAN rule structures (supporting FortiGate and Versa specific contexts).
*   **VPN Parameter Checks:** Extracts IPsec (ISAKMP/IKE) and SSL/WebVPN configurations for security compliance review.

## Supported Platforms

*   Fortinet FortiGate (FortiOS)
*   Versa Networks (SD-WAN)
*   Cisco (ASA / IOS Generic)

## Usage

1. Launch `index.html` in any modern web browser.
2. Select your target vendor from the dropdown menu.
3. Toggle the specific audit modules you wish to run.
4. Upload a `.txt`, `.cfg`, or `.conf` configuration file.
5. Review the categorized JSON output on the dashboard.

## Security

This tool runs 100% locally using Vanilla JavaScript. No data is transmitted to external servers.
