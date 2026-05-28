# Windows Forwarded Events (Advanced)

**Tier:** 3 (Advanced) · **Connector type:** Microsoft first-party (AMA) · **Free ingestion:** No (paid ingestion)

---

## Contents

- [Windows Forwarded Events (Advanced)](#windows-forwarded-events-advanced)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
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

While the Tier 1 Windows Security Events connector focuses on the **Security event log** (authentication, process creation, group management), advanced Windows monitoring extends collection to other critical event channels: **PowerShell ScriptBlock logging**, **WMI events**, **AppLocker/WDAC enforcement**, **Sysmon**, and **Windows Firewall** events.

These additional event sources are essential for detecting sophisticated attacks that operate beyond the Security log: fileless malware using PowerShell, living-off-the-land (LOTL) techniques through WMI, application control bypass attempts, and advanced persistence mechanisms. Security researchers and red teams consistently identify these channels as the most valuable for threat detection.

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
| **WindowsEvent** (PowerShell) | PowerShell ScriptBlock logging (Event ID 4104) — full script content for all executed scripts | Analytics: 90d / Lake: 365d | PowerShell is the most commonly abused tool in modern attacks — ScriptBlock logging captures the actual code executed | Provides the exact malicious script content — the most valuable single event source for investigating fileless attacks | Encoded PowerShell command execution |
| **WindowsEvent** (WMI) | WMI activity events — WMI subscriptions, queries, and method executions | Analytics: 90d / Lake: 365d | WMI is a primary LOTL technique for persistence, lateral movement, and reconnaissance | Identifies WMI-based persistence mechanisms and remote execution — common in APT tradecraft | WMI event subscription created for persistence |
| **WindowsEvent** (AppLocker/WDAC) | Application control enforcement events — allowed, blocked, and audit mode events | Analytics: 90d / Lake: 365d | Application control is the strongest preventive control — monitoring enforcement events detects bypass attempts | Proves which applications were blocked or audited — identifies attack attempts against application control | Application blocked by AppLocker but bypassed via alternate binary |
| **WindowsEvent** (Sysmon) | Sysmon events — process creation with hashes, network connections, file creation, registry modification | Analytics: 90d / Lake: 365d | Sysmon provides the richest endpoint telemetry for threat detection — process lineage, file hashes, network connections | Complete process tree reconstruction with file hashes — definitive endpoint forensic data | Parent-child process chain indicating Cobalt Strike beacon |
| **WindowsEvent** (Firewall) | Windows Filtering Platform events — firewall rule changes and blocked connections | Analytics: 30d / Lake: 180d | Detects firewall tampering and blocked connection attempts from malware | Identifies firewall changes made by attackers to enable communication — proves connectivity attempts | Windows Firewall rule disabled or modified |

---

## Example Detections

| Detection | Table(s) / Event ID(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:-----------------------|:-------------|:-------------------|:------------|
| Base64-encoded PowerShell execution | WindowsEvent (4104) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [DET0455](https://attack.mitre.org/detectionstrategies/DET0455/) — Abuse of PowerShell for Arbitrary Execution | PowerShell ScriptBlock containing encoded commands — common obfuscation technique |
| PowerShell download cradle | WindowsEvent (4104) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1105](https://attack.mitre.org/techniques/T1105/) | [DET0455](https://attack.mitre.org/detectionstrategies/DET0455/) — Abuse of PowerShell · [DET0060](https://attack.mitre.org/detectionstrategies/DET0060/) — Ingress Tool Transfers | ScriptBlock containing `Invoke-WebRequest`, `Net.WebClient`, or `DownloadString` — payload staging |
| WMI persistence subscription | WindowsEvent (WMI) | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | [DET0086](https://attack.mitre.org/detectionstrategies/DET0086/) — WMI Event Subscription for Persistence | `__EventFilter` and `__EventConsumer` WMI objects created — classic persistence mechanism |
| LOLBAS execution via AppLocker bypass | WindowsEvent (AppLocker) | [T1218](https://attack.mitre.org/techniques/T1218/) | [DET0081](https://attack.mitre.org/detectionstrategies/DET0081/) — Proxy Execution via Trusted Signed Binaries | Living-off-the-land binary execution blocked or audited — indicates bypass attempt |
| Sysmon — process injection detected | WindowsEvent (Sysmon 8/10) | [T1055](https://attack.mitre.org/techniques/T1055/) | [DET0508](https://attack.mitre.org/detectionstrategies/DET0508/) — Behavioral Detection of Process Injection | Sysmon CreateRemoteThread or ProcessAccess events indicating process injection |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page. The **MITRE Log Sources (Windows)** column lists the exact log channels and event codes referenced by the analytic of each strategy on the relevant platform — taken verbatim from the strategy's published `log_sources` field in the [ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data).

> [!TIP]
> This page covers the *advanced* Windows event channels (PowerShell, WMI, AppLocker/WDAC, Sysmon, Firewall). The Tier 1 [Windows Security Events](windows-security-events.md#mitre-detection-strategies) page enumerates the broader catalogue of strategies that depend on the `Security` channel — start there for foundational coverage, then use the table below to extend into the advanced channels.

| Technique | Detection Strategy | MITRE Log Sources (Windows) |
|:----------|:-------------------|:-----------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [DET0455](https://attack.mitre.org/detectionstrategies/DET0455/) &mdash; Abuse of PowerShell for Arbitrary Execution | `WinEventLog:PowerShell`: EventCode=400, 403, EventCode=4103, 4104, 4105, 4106 &middot; `WinEventLog:Sysmon`: EventCode=1, EventCode=7 |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | [DET0086](https://attack.mitre.org/detectionstrategies/DET0086/) &mdash; Detect WMI Event Subscription for Persistence via WmiPrvSE Process and MOF Compilation | `WinEventLog:Sysmon`: EventCode=1, EventCode=7 &middot; `WinEventLog:WMI`: EventCode=5857, 5858, 5860, 5861 |
| [T1218](https://attack.mitre.org/techniques/T1218/) | [DET0081](https://attack.mitre.org/detectionstrategies/DET0081/) &mdash; Detection of Proxy Execution via Trusted Signed Binaries Across Platforms | `WinEventLog:Sysmon`: EventCode=1, EventCode=3, 22, EventCode=7 |
| [T1562.004](https://attack.mitre.org/techniques/T1562/004/) *(revoked &rarr; [T1686](https://attack.mitre.org/techniques/T1686/))* | [DET0145](https://attack.mitre.org/detectionstrategies/DET0145/) &mdash; Detection of Disabled or Modified System Firewalls across OS Platforms. | `WinEventLog:Security`: EventCode=4688 &middot; `WinEventLog:Sysmon`: EventCode=13, 14 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | [DET0060](https://attack.mitre.org/detectionstrategies/DET0060/) &mdash; Detect Ingress Tool Transfers via Behavioral Chain | `WinEventLog:Sysmon`: EventCode=1, EventCode=11, EventCode=3, 22 |
| [T1055](https://attack.mitre.org/techniques/T1055/) | [DET0508](https://attack.mitre.org/detectionstrategies/DET0508/) &mdash; Behavioral Detection of Process Injection Across Platforms | `etw:Microsoft-Windows-Kernel-Process`: API calls &middot; `WinEventLog:Sysmon`: EventCode=1, EventCode=10, EventCode=7 |

> [!NOTE]
> **Log sources are verbatim from MITRE.** The third column is generated directly from each strategy's published `x_mitre_log_source_references` field in the [ATT&CK STIX 2.1 bundle](https://github.com/mitre-attack/attack-stix-data) — it is **not** a hand-picked list of "events that look related on this connector page". Where MITRE has not published an analytic on the relevant platform, the cell says so explicitly.

> [!NOTE]
> **MITRE legacy technique IDs.** Some technique IDs cited on this page are *legacy* IDs that MITRE has revoked and remapped: T1562.004 &rarr; T1686. Published Detection Strategies are attached to the current technique IDs only; the table above follows the `revoked-by` chain so each strategy still applies to the legacy ID cited above.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-1** Enable threat detection capabilities | Advanced event channels enable detection of sophisticated attacks that bypass Security log-only monitoring |
| **LT-3** Enable logging for security investigation | PowerShell ScriptBlock and Sysmon provide the richest forensic data for endpoint investigations |
| **ES-2** Use modern anti-malware software | AppLocker/WDAC enforcement monitoring validates application control effectiveness |
| **AM-2** Use only approved services | Application control monitoring tracks execution of unapproved software |

---

## Important Considerations

- **Group Policy prerequisites:** PowerShell ScriptBlock logging must be enabled via GPO (`Module Logging` and `Script Block Logging`). AppLocker requires enforcement or audit mode configuration. Sysmon requires separate deployment
- **Sysmon deployment:** Sysmon is highly recommended but requires a custom configuration file. Use community configurations like [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) as a baseline
- **DCR configuration:** Use separate DCR rules or XPath queries to collect specific event channels. Example XPath: `Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4104)]]`
- **Volume management:** PowerShell ScriptBlock logging can generate significant volume on servers running PowerShell-heavy automation. Filter by event level or use DCR transformations
- **MDE integration:** If Defender for Endpoint (via XDR, Tier 1) is deployed, some of this telemetry overlaps with MDE's `DeviceProcessEvents` and `DeviceFileEvents`. The raw Windows events provide additional detail and longer retention control

---

## Notes

- PowerShell ScriptBlock logging (Event ID 4104) is considered the single most valuable event channel for detecting modern attacks after standard Security events
- Sysmon provides the most comprehensive endpoint telemetry available — but requires deployment and maintenance of the Sysmon agent and configuration
- These advanced channels build directly on the Tier 1 Windows Security Events foundation — deploy Tier 1 first, then extend to Tier 3

### Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| [Workspace Usage Report](../procedures/workspace-usage-report.md) | Workbook | Verify advanced Windows event log volumes | Sentinel Maturity Model | [Procedure guide](../procedures/workspace-usage-report.md) |
| [Defender AMA Coverage](../procedures/defender-ama-coverage.md) | Workbook | Validate AMA deployment and DCR coverage for advanced channels | [GitHub — mathijsvermaat/Defender-AMA-coverage](https://github.com/mathijsvermaat/Defender-AMA-coverage) | [Procedure guide](../procedures/defender-ama-coverage.md) · [Blog](https://www.linkedin.com/pulse/closing-telemetry-gap-how-we-built-kql-query-workbook-mathijs-vermaat-rzfbe/) |

---

## References

| Source | Link |
|:-------|:-----|
| PowerShell ScriptBlock logging | [Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) |
| Sysmon overview | [Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| AppLocker overview | [Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview) |
| WDAC overview | [Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac) |
| AMA Windows Event collection | [Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/data-collection-windows-events) |
| Sentinel — Windows agent-based connectors (WEF prerequisite) | [Learn](https://learn.microsoft.com/azure/sentinel/connect-services-windows-based) |

---

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
