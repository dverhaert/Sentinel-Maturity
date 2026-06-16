# Azure WAF (Application Gateway / Front Door)

**Tier:** 2 (Extended Visibility) · **Connector type:** Microsoft first-party · **Free ingestion:** No (paid ingestion)

---

## Contents

- [Azure WAF (Application Gateway / Front Door)](#azure-waf-application-gateway--front-door)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
  - [Tables and Rationale](#tables-and-rationale)
  - [Example Detections](#example-detections)
    - [Application-Layer Attacks](#application-layer-attacks)
    - [Reconnaissance and Abuse](#reconnaissance-and-abuse)
  - [MITRE Detection Strategies](#mitre-detection-strategies)
  - [MCSB Control Mapping](#mcsb-control-mapping)
  - [Important Considerations](#important-considerations)
    - [Application Gateway vs. Front Door](#application-gateway-vs-front-door)
    - [OWASP Core Rule Set Versions](#owasp-core-rule-set-versions)
  - [Notes](#notes)
  - [Tools](#tools)
  - [References](#references)
    - [Official Documentation](#official-documentation)
    - [Admin portal](#admin-portal)
    - [Community \& Third-Party Resources](#community--third-party-resources)

---

## Overview

Azure Web Application Firewall (WAF) protects web applications from common exploits and vulnerabilities at Layer 7. It can be deployed on **Azure Application Gateway** (regional) or **Azure Front Door** (global CDN/edge). WAF logs record every request that triggers a rule evaluation — including OWASP Top 10 attacks like SQL injection, cross-site scripting, and remote code execution attempts.

These logs are critical for detecting application-layer attacks that network firewalls (L3/L4) cannot see, and for meeting the ACSC logging priority for internet-facing services.

### Licensing Benefits

| Sentinel cost classification | Microsoft Sentinel benefit |
|:-----------------------------|:---------------------------|
| **No (paid ingestion)** | No built-in Sentinel ingestion benefit is documented for this connector; ingestion is billed based on enabled data types and volume. |

> [!NOTE]
> This is a connector-level Sentinel classification used for cost planning.

---

## Tables and Rationale

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **AzureDiagnostics** (ApplicationGatewayFirewallLog) | WAF rule matches — triggered rules, action (allow/block/log), request URI, source IP | Analytics: 90d / Lake: 365d | **Core web application security table.** Detects OWASP Top 10 attacks, bot activity, and application abuse. MCSB LT-3, LT-4. | Proves which application-layer attacks were attempted against your web applications, from which IPs, and whether they were blocked. Essential for investigating web application breaches. | SQL injection attempt on login form, XSS payload in URL parameter |
| **AzureDiagnostics** (ApplicationGatewayAccessLog) | Access log — all requests passing through Application Gateway (including those not triggering WAF rules) | Analytics: 90d / Lake: 365d | Provides baseline traffic context and identifies requests that bypassed WAF rules. | Complete request audit trail — proves every HTTP request to your web applications including source IP, URI, response code, and latency | Unusual request volume from single IP — potential reconnaissance or brute-force |
| **AzureDiagnostics** (FrontDoorWebApplicationFirewallLog) | Front Door WAF rule matches — same structure as Application Gateway WAF | Analytics: 90d / Lake: 365d | Global edge WAF visibility — detects attacks before they reach the origin. | Evidence of attacks blocked at the edge — proves your global attack surface and the geographic distribution of attack sources | SQL injection blocked at edge before reaching origin |

> [!TIP]
> If you migrate to **resource-specific tables**, Application Gateway exposes `AGWFirewallLogs` and `AGWAccessLogs` as structured alternatives to `AzureDiagnostics`. Use resource-specific mode where available.

---

## Example Detections

### Application-Layer Attacks

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| SQL injection attempt | ApplicationGatewayFirewallLog | [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) — Exploit Public-Facing Application | WAF rule 942xxx triggered — SQL injection patterns in request body or query string |
| Cross-site scripting (XSS) | ApplicationGatewayFirewallLog | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | [DET0264](https://attack.mitre.org/detectionstrategies/DET0264/) — JavaScript Execution Abuse | WAF rule 941xxx triggered — script injection in URL or form data |
| Remote code execution attempt | ApplicationGatewayFirewallLog | [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) — Exploit Public-Facing Application | WAF rule detecting command injection, path traversal, or RFI/LFI |
| Directory traversal | ApplicationGatewayFirewallLog | [T1083](https://attack.mitre.org/techniques/T1083/) | [DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) — File and Directory Discovery | Path traversal patterns (../) in request URI |

### Reconnaissance and Abuse

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Web scanning / enumeration | ApplicationGatewayAccessLog | [T1595](https://attack.mitre.org/techniques/T1595/) | [DET0830](https://attack.mitre.org/detectionstrategies/DET0830/) — Active Scanning | High volume of 404 responses from single source — automated scanning |
| Credential brute-force on login endpoint | ApplicationGatewayAccessLog | [T1110](https://attack.mitre.org/techniques/T1110/) | [DET0463](https://attack.mitre.org/detectionstrategies/DET0463/) — Brute Force | High volume of POST requests to authentication endpoints |
| Bot activity | ApplicationGatewayFirewallLog | [T1595](https://attack.mitre.org/techniques/T1595/) | [DET0830](https://attack.mitre.org/detectionstrategies/DET0830/) — Active Scanning | Bot protection rules triggered — known bad bots or scrapers |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) &mdash; Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress) |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | [DET0264](https://attack.mitre.org/detectionstrategies/DET0264/) &mdash; Cross-Platform Detection of JavaScript Execution Abuse |
| [T1083](https://attack.mitre.org/techniques/T1083/) | [DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) &mdash; Recursive Enumeration of Files and Directories Across Privilege Contexts |
| [T1595](https://attack.mitre.org/techniques/T1595/) | [DET0830](https://attack.mitre.org/detectionstrategies/DET0830/) &mdash; Detection of Active Scanning |
| [T1110](https://attack.mitre.org/techniques/T1110/) | [DET0463](https://attack.mitre.org/detectionstrategies/DET0463/) &mdash; Brute Force Authentication Failures with Multi-Platform Log Correlation |

> [!NOTE]
> This page intentionally omits the third MITRE-evidence column. For broad platform-family strategies, MITRE may cite provider-specific source names that do not map 1:1 to Azure WAF tables; keeping this section as Technique + Detection Strategy avoids a brittle translation layer.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-3** Enable logging for security investigation | WAF logs provide the application-layer audit trail for web workloads |
| **LT-4** Enable network logging for security investigation | Layer 7 attack logging that network firewalls cannot provide |
| **NS-2** Secure cloud native services with network controls | WAF is a key network security control for internet-facing services |
| **NS-6** Deploy web application firewall | Direct implementation of this control — logs prove enforcement |

> [!NOTE]
> **Other framework alignment:** This data supports NIST SP 800-53 SC-7 (boundary protection) and SI-4 (system monitoring), CIS Controls v8 13.10 (web application firewall), and ASD ACSC enterprise network logging priority #2 (internet-facing services).

---

## Important Considerations

### Application Gateway vs. Front Door

| Feature | Application Gateway WAF | Front Door WAF |
|:--------|:----------------------|:---------------|
| Scope | Regional (single VNet) | Global (edge locations worldwide) |
| Use case | Backend web apps, internal APIs | Public-facing web applications, CDN |
| Diagnostic tables | ApplicationGatewayFirewallLog, ApplicationGatewayAccessLog | FrontDoorWebApplicationFirewallLog, FrontDoorAccessLog |
| Resource-specific tables | AGWFirewallLogs, AGWAccessLogs | Not yet available — use AzureDiagnostics |

If you use **both** Application Gateway and Front Door, configure diagnostic settings on both. Front Door blocks attacks at the edge; Application Gateway logs show what reaches the backend.

### OWASP Core Rule Set Versions

Ensure your WAF policy uses **CRS 3.2** or later. Older CRS versions generate more false positives and fewer structured log fields.

---

## Notes

- WAF logs are **not** free — volume scales with request rate to your web applications
- Consider using the **Data Lake** tier for access logs if you only need firewall (WAF rule match) logs for active detection
- WAF logs complement Azure Firewall logs — the firewall handles L3/L4 traffic; WAF handles L7 application-layer attacks
- If you have no internet-facing web applications behind Application Gateway or Front Door, this connector may not apply to your environment

---

## Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor WAF log ingestion volumes | Sentinel Content Hub | [Walkthrough](../procedures/workspace-usage-report.md) |
| **Network Session Essentials** | Solution | 2 workbooks, 10 analytic rules, 6 hunting queries — ASIM-based network session analytics; WAF logs can feed ASIM-normalised detections | Sentinel Content Hub | — |

---

## References

### Official Documentation

| Title | Description | Link |
|:------|:------------|:-----|
| Connect Azure WAF to Microsoft Sentinel | Connector setup guide — Application Gateway and Front Door diagnostic settings | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/azure-web-application-firewall) |
| Azure WAF monitoring and logging | Diagnostic logs, metrics, and best practices for Azure WAF | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-metrics) |

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — configure Application Gateway / Front Door WAF diagnostic settings to route logs to Log Analytics (`AzureDiagnostics` today; resource-specific tables where available).
  - Quick links via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azwaf.cmd.ms`](https://azwaf.cmd.ms/) (WAF policies), [`azappgw.cmd.ms`](https://azappgw.cmd.ms/) (Application Gateways), [`azfdcdn.cmd.ms`](https://azfdcdn.cmd.ms/) (Azure Front Door & CDN).

### Community & Third-Party Resources

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| Sentinel Ninja — Azure WAF connector | Ofer Shezaf (Microsoft) | Auto-generated reference: tables ingested, related solutions, and content items | [github.com](https://github.com/oshezaf/sentinelninja/blob/main/Solutions%20Docs/connectors/waf.md) |
| Best practices for event logging and threat detection | ASD ACSC | International joint guidance — internet-facing services are Enterprise Networks priority #2 | [cyber.gov.au](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-for-event-logging-and-threat-detection) |
| Public preview — collect Azure resource platform logs at scale with DCRs | Azure Observability blog (Microsoft) | New DCR-based approach that replaces per-resource diagnostic settings, with ingestion-time filtering/transformation and ARM/Bicep/Terraform/Policy deployment | [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/AzureObservabilityBlog/public-preview---azure-monitor---collect-azure-resource-platform-logs-at-scale-w/4525296) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
