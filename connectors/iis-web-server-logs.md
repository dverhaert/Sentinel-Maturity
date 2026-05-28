# IIS / Web Server Logs

**Tier:** 3 (Advanced) · **Connector type:** Microsoft first-party (AMA) · **Free ingestion:** No (paid ingestion)

---

## Contents

- [Overview](#overview)
- [Tables and Rationale](#tables-and-rationale)
- [Example Detections](#example-detections)
- [MITRE Detection Strategies](#mitre-detection-strategies)
- [MCSB Control Mapping](#mcsb-control-mapping)
- [Important Considerations](#important-considerations)
- [Notes](#notes)
- [Tools](#tools)
- [References](#references)

---

## Overview

IIS (Internet Information Services) logs record HTTP request activity on Windows web servers — every request, response code, client IP, user agent, and URI. These logs provide **application-layer visibility** for internally hosted web applications and APIs that may not sit behind Azure WAF or a reverse proxy.

For organisations hosting custom web applications, internal portals, or APIs on IIS, these logs are the primary source for detecting web-based attacks: brute-force against login pages, directory traversal, SQL injection attempts, and suspicious scanning. Unlike network firewalls that see connections, IIS logs see the full HTTP request path.

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
| **W3CIISLog** | Standard IIS access logs — HTTP method, URI, status code, client IP, user agent, bytes transferred | Analytics: 90d / Lake: 365d | Primary source for web application attack detection and user activity auditing on Windows web servers | During investigations, recreates attacker request patterns — which pages were accessed, what payloads were sent, and from which IPs | SQL injection attempts via URI parameters |

---

## Example Detections

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Excessive 401/403 responses | W3CIISLog | [T1110](https://attack.mitre.org/techniques/T1110/) | [DET0463](https://attack.mitre.org/detectionstrategies/DET0463/) — Brute Force Authentication Failures | Brute-force or credential stuffing against web application login endpoints |
| Directory traversal attempts | W3CIISLog | [T1083](https://attack.mitre.org/techniques/T1083/) | [DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) — Recursive File Enumeration | Requests containing `../` path traversal sequences targeting file system access |
| SQL injection patterns in URI | W3CIISLog | [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) — Exploit Public-Facing Application | Requests containing SQL keywords (`UNION SELECT`, `OR 1=1`, `DROP TABLE`) in query strings |
| Web shell access patterns | W3CIISLog | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | [DET0394](https://attack.mitre.org/detectionstrategies/DET0394/) — Web Shell Detection | Repeated requests to unusual file paths (.aspx, .ashx) from a single IP — indicates web shell deployment |
| Anomalous user agent strings | W3CIISLog | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | [DET0027](https://attack.mitre.org/detectionstrategies/DET0027/) — Web Protocol-Based C2 | Requests with known malicious or tool-specific user agents (sqlmap, Nikto, Cobalt Strike) |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page. The **MITRE Log Sources (Windows)** column lists the exact log channels and event codes referenced by the analytic of each strategy on the relevant platform — taken verbatim from the strategy's published `log_sources` field in the [ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data).

| Technique | Detection Strategy | MITRE Log Sources (Windows) |
|:----------|:-------------------|:-----------|
| [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) &mdash; Exploit Public-Facing Application – multi-signal correlation (request &rarr; error &rarr; post-exploit process/egress) | `ApplicationLog:IIS`: IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns) &middot; `WinEventLog:Sysmon`: EventCode=1, EventCode=3, 22, EventCode=7 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | [DET0463](https://attack.mitre.org/detectionstrategies/DET0463/) &mdash; Brute Force Authentication Failures with Multi-Platform Log Correlation | `WinEventLog:Security`: EventCode=4776, 4625 |
| [T1083](https://attack.mitre.org/techniques/T1083/) | [DET0370](https://attack.mitre.org/detectionstrategies/DET0370/) &mdash; Recursive Enumeration of Files and Directories Across Privilege Contexts | `WinEventLog:Security`: EventCode=4688 &middot; `WinEventLog:Sysmon`: EventCode=11 |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | [DET0394](https://attack.mitre.org/detectionstrategies/DET0394/) &mdash; Web Shell Detection via Server Behavior and File Execution Chains | `NSM:Flow`: Inbound HTTP POST with suspicious payload size or user-agent &middot; `WinEventLog:Security`: EventCode=4624, 4648 &middot; `WinEventLog:Sysmon`: EventCode=1, EventCode=11 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | [DET0027](https://attack.mitre.org/detectionstrategies/DET0027/) &mdash; Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets | `NSM:Flow`: http.log, ssl.log &middot; `WinEventLog:Sysmon`: EventCode=3, 22 |

> [!NOTE]
> **Log sources are verbatim from MITRE.** The third column is generated directly from each strategy's published `x_mitre_log_source_references` field in the [ATT&CK STIX 2.1 bundle](https://github.com/mitre-attack/attack-stix-data) — it is **not** a hand-picked list of "events that look related on this connector page". MITRE's published analytics for these techniques rely on Security/Sysmon channels in addition to IIS logs themselves; pair this connector with Windows Security Events to cover the full strategy.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-1** Enable threat detection capabilities | IIS logs enable application-layer threat detection for web workloads |
| **LT-3** Enable logging for security investigation | Web server access logs are foundational for investigating web application compromises |
| **NS-6** Deploy web application firewall | IIS logs complement WAF by providing visibility even when WAF is not deployed |

---

## Important Considerations

- **Volume management:** High-traffic web servers can generate gigabytes of logs per day. Use DCR transformations to exclude health probes (`/health`, `/ready`), static assets (`.css`, `.js`, `.png`), and monitoring endpoints
- **AMA configuration:** Requires Azure Monitor Agent with a Data Collection Rule targeting `Microsoft-W3CIISLog`
- **Log format:** Ensure IIS is configured for W3C Extended Log Format with all fields enabled (client IP, user agent, cookie, referrer)
- **Sensitive data:** URI parameters may contain sensitive data (tokens, session IDs). Consider DCR transformations to sanitise query strings

---

## Notes

- IIS logs are particularly valuable for organisations hosting internal portals, SharePoint on-premises, or custom LOB applications on Windows Server
- Complements Azure WAF (Tier 2) — WAF protects internet-facing apps; IIS logs cover internal applications and apps without WAF
- Consider pairing with Windows Security Events (Tier 1) for correlation between web requests and process execution

### Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| [Workspace Usage Report](../procedures/workspace-usage-report.md) | Workbook | Verify IIS log volumes and ingestion | Sentinel Maturity Model | [Procedure guide](../procedures/workspace-usage-report.md) |

---

## References

| Source | Link |
|:-------|:-----|
| Collect IIS logs with Azure Monitor Agent | [Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/data-collection-iis) |
| W3CIISLog table reference | [Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/w3ciislog) |
| IIS log file formats | [Learn](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525807(v=vs.90)) |
| Create a transformation in Azure Monitor DCR | [Learn](https://learn.microsoft.com/azure/azure-monitor/data-collection/data-collection-transformations-create) |

---

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
