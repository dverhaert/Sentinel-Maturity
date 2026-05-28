# Microsoft Defender XDR

**Tier:** 1 (Bare Minimum) · **Connector type:** Microsoft first-party · **Free ingestion:** Ingestion benefit only (conditional) — Analytics tier grant via eligible E5 Security entitlement ([Microsoft Sentinel benefit for M365 E5 customers](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer))

---

## Contents

- [Overview](#overview)
- [Tables and Rationale](#tables-and-rationale)
- [Example Detections](#example-detections)
- [MITRE Detection Strategies](#mitre-detection-strategies)
- [MCSB Control Mapping](#mcsb-control-mapping)
- [Notes](#notes)
  - [Estimating Data Lake Retention Cost](#estimating-data-lake-retention-cost)
- [Tools](#tools)
- [References](#references)

---

## Overview

The Microsoft Defender XDR connector ingests advanced hunting data from Microsoft Defender for Endpoint (MDE), Microsoft Defender for Office 365 (MDO), Microsoft Defender for Identity (MDI), and Microsoft Defender for Cloud Apps (MDA) into Microsoft Sentinel. This is the **single most valuable connector** for organisations with Microsoft 365 E5 or equivalent licensing, as it provides deep endpoint, email, identity, and cloud application telemetry — all at **zero additional ingestion cost** when ingested to the **Analytics tier** via the security data grant.

### Licensing Benefits

| Sentinel cost classification | Microsoft Sentinel benefit |
|:-----------------------------|:---------------------------|
| **Ingestion benefit only (conditional)** | Entitlement-based Analytics-tier ingestion benefit applies for eligible data types; verify current scope in [Microsoft Sentinel benefit for M365 E5 customers](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer). |

> [!NOTE]
> This classification is Sentinel-centric and connector-level. Coverage can change over time.

---

## Tables and Rationale

### Endpoint Tables (Microsoft Defender for Endpoint)

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **DeviceInfo** | Device inventory, OS, health state, onboarding status | Analytics: 90d / Lake: 365d | Asset inventory is foundational for incident scoping. Knowing which devices were in scope at any point in time is critical for forensic reconstruction. | Reconstruct which devices existed, their OS versions, and health state at any point during an investigation — answers "what was the attack surface?" | Asset inventory drift — device OS not updated or health state degraded |
| **DeviceNetworkInfo** | Network adapter configuration, IPs, MAC addresses, DNS, DHCP | Analytics: 90d / Lake: 365d | Network context for lateral movement investigation. Helps correlate network-based detections with device identities. | Map device-to-IP relationships historically — critical when correlating network IOCs with specific endpoints weeks after an incident | Device network configuration change correlating with lateral movement |
| **DeviceProcessEvents** | Process creation events with command lines | Analytics: 90d / Lake: 365d | **Core forensic table.** Process execution chains are the backbone of threat hunting and incident response. | Reconstruct full execution chains — what ran, with which arguments, by which user, and in what parent-child relationship. The single most important table for root cause analysis. | Suspicious PowerShell with encoded commands, LSASS credential dumping |
| **DeviceNetworkEvents** | Outbound/inbound network connections per process | Analytics: 90d / Lake: 365d | C2 detection, data exfiltration hunting, lateral movement. Essential for correlating process execution with network activity. | Correlate process execution with network behaviour — proves which process made a C2 connection or moved data laterally. Essential for exfiltration scoping. | Outbound connection to known C2 infrastructure, SMB lateral movement |
| **DeviceFileEvents** | File creation, modification, deletion | Analytics: 90d / Lake: 365d | Malware delivery, staging, and exfiltration forensics. Tracks ransomware file encryption patterns and data staging. | Track file drops, staging, and encryption patterns — determines exactly which files were accessed, modified, or exfiltrated during a breach | Ransomware mass file rename/extension change pattern |
| **DeviceRegistryEvents** | Registry key/value changes | Analytics: 90d / Lake: 365d | Persistence mechanism detection (Run keys, services, scheduled tasks registered via registry). | Identify persistence mechanisms installed by the attacker — Run keys, service registrations, and security product tampering via registry | New Run key persistence entry |
| **DeviceLogonEvents** | Local and network logon events on endpoints | Analytics: 90d / Lake: 365d | Lateral movement detection, credential abuse. Complements IdentityLogonEvents with endpoint-side visibility. | Reconstruct lateral movement path from the endpoint perspective — which accounts logged onto which machines and when | Unusual network logon (Type 3/10) from unexpected source — lateral movement |
| **DeviceImageLoadEvents** | DLL and driver loading events | Analytics: 90d / Lake: 365d | DLL side-loading, living-off-the-land detection. | Identify DLL hijacking and side-loading — proves which unsigned or malicious library was loaded into a legitimate process | Unsigned DLL loaded from unusual path by legitimate process |
| **DeviceEvents** | Miscellaneous events (exploit guard, tamper protection, USB, etc.) | Analytics: 90d / Lake: 365d | Catch-all for attack surface reduction, exploit protection, and peripheral device events. | Provides evidence of security control tampering, ASR rule triggers, and physical device connections that may be relevant to insider threat or data theft investigations | ASR rule triggered, tamper protection event, USB device connected |
| **DeviceFileCertificateInfo** | Certificate information for signed files | Analytics: 90d / Lake: 365d | Validates file authenticity, detects unsigned or suspiciously signed binaries. Supports software integrity verification. | Verify the trust chain of executables present during an incident — identifies supply chain compromise via revoked or fraudulent certificates | Executable signed with revoked or untrusted certificate |

### Alert Tables

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **AlertInfo** | Alerts from all Defender workloads | Analytics: 90d / Lake: 365d | Core incident response data. Every alert is a potential incident starting point. | Historical alert timeline — reconstruct which detections fired and when, enabling post-incident review of detection gaps | Alert trend analysis, alert-to-incident correlation |
| **AlertEvidence** | Entities (files, processes, IPs, users) associated with alerts | Analytics: 90d / Lake: 365d | Investigation context — links alerts to actionable evidence. Essential for automated enrichment and SOAR playbooks. | Links alerts to specific entities — enables historical investigation into which processes, IPs, and users were involved across multiple related incidents | Automated entity enrichment for incident triage |

### Email Tables (Microsoft Defender for Office 365)

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **EmailEvents** | Email delivery events, sender, recipient, subject, verdict | Analytics: 90d / Lake: 365d | Phishing and BEC detection. Email is the #1 initial access vector. Retention beyond 90 days supports investigation of slow-burn phishing campaigns. | Reconstruct the full delivery chain of a phishing campaign — who received what, when, and what was the verdict at delivery time. Critical for scoping BEC blast radius. | Phishing email from newly registered domain |
| **EmailUrlInfo** | URLs contained in emails | Analytics: 90d / Lake: 365d | Phishing URL analysis and retroactive hunting when new IOCs emerge. | Retroactive IOC matching — when a new malicious URL is discovered, search months of historical email to find all recipients who were exposed | Retroactive IOC match on URL found in historical email |
| **EmailAttachmentInfo** | Attachment metadata, file hashes | Analytics: 90d / Lake: 365d | Malware delivery tracking. Enables retroactive hash lookups when new malware campaigns are identified. | Retroactive hash lookup — when a new malware sample is identified, trace all historical delivery to identify every affected user | Malware hash match on .iso/.vhd/.lnk attachment |
| **EmailPostDeliveryEvents** | Post-delivery actions (ZAP, user-reported, admin actions) | Analytics: 90d / Lake: 365d | Tracks remediation effectiveness and identifies emails that bypassed initial filters. | Audit the remediation timeline — proves when a malicious email was removed vs. when it was first delivered, quantifying user exposure window | Email delivered then ZAP'd — measure detection gap |

### Identity Tables (Microsoft Defender for Identity)

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **IdentityLogonEvents** | Authentication events from on-premises AD and cloud | Analytics: 90d / Lake: 365d | **Core identity security table.** Detects brute-force, password spray, pass-the-hash, pass-the-ticket attacks. Bridges the gap between on-premises AD and Entra ID. | Reconstruct the complete authentication timeline across hybrid identity — proves when and how an attacker obtained access, which protocol was used, and lateral movement via AD | Password spray — multiple failed logons across many accounts |
| **IdentityQueryEvents** | LDAP, DNS, and SAMR queries against Active Directory | Analytics: 90d / Lake: 365d | Reconnaissance detection. Attackers enumerate users, groups, and computers before lateral movement. | Evidence of pre-attack reconnaissance — proves that an account was used to enumerate AD before privilege escalation or lateral movement occurred | Unusual LDAP query enumerating Domain Admins |
| **IdentityDirectoryEvents** | Changes to AD objects (group membership, password resets, etc.) | Analytics: 90d / Lake: 365d | Privilege escalation and persistence detection. Tracks changes to sensitive groups like Domain Admins. | Audit trail of AD modifications — proves exactly when privilege was escalated, by whom, and which objects were changed | User added to Domain Admins group |

### Cloud App Tables (Microsoft Defender for Cloud Apps)

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **CloudAppEvents** | Activities in cloud applications (Office 365, third-party SaaS) | Analytics: 90d / Lake: 365d | Shadow IT detection, impossible travel, mass download/sharing detection. Provides visibility into SaaS application usage beyond Office 365. | Reconstruct cloud application activity during a compromise — proves which SaaS applications were accessed, what data was downloaded, and from which locations | Impossible travel to cloud app, mass file download from SharePoint |
### Incident and Alert Sync Tables

These tables are automatically populated when you enable the **"Connect incidents & alerts"** toggle on the Defender XDR connector. They are not individually configurable — they flow as part of incident synchronisation between Defender XDR and Sentinel.

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:-------------------|
| **SecurityAlert** | Alerts from all Defender workloads (MDE, MDO, MDI, MDCA) synchronised to Sentinel | Analytics: 90d / Lake: 365d | Centralises all Defender alerts in Sentinel for cross-source correlation and SOAR automation. | Historical alert timeline — enables post-incident review of which detections fired and correlation with non-Microsoft data sources in Sentinel | Cross-workload alert correlation — endpoint alert + identity alert on same entity |
| **SecurityIncident** | Defender XDR incidents (groups of related alerts) synchronised to Sentinel | Analytics: 90d / Lake: 365d | Enables unified incident management across Sentinel and Defender XDR. Incidents remain synchronised bi-directionally. | Unified incident timeline — proves when incidents were created, triaged, and resolved across both platforms | Incident severity escalation — automated triage based on incident metadata |
### Other Tables

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **UrlClickEvents** | Safe Links click events (user clicks on URLs in emails) | Analytics: 90d / Lake: 365d | Identifies users who clicked on malicious links despite warnings. Critical for BEC and phishing response workflows. | Proves which users interacted with a malicious link and when — essential for scoping phishing impact and determining which accounts need remediation | User clicked Safe Links warning override on phishing URL |

---

## Example Detections

### Endpoint

| Detection | Table(s) | MITRE ATT&CK | Description |
|:----------|:---------|:-------------|:------------|
| Suspicious PowerShell execution | DeviceProcessEvents | T1059.001 | Encoded commands, download cradles, AMSI bypass attempts |
| Lateral movement via PsExec / SMB | DeviceProcessEvents, DeviceNetworkEvents | T1021.002 | Remote service execution combined with SMB connections |
| Ransomware file encryption pattern | DeviceFileEvents | T1486 | Mass file rename/extension changes in short timeframes |
| Credential dumping (LSASS access) | DeviceProcessEvents, DeviceEvents | T1003.001 | Process access to LSASS memory |
| Persistence via registry Run key | DeviceRegistryEvents | T1547.001 | New entries in common autostart registry locations |
| Suspicious DLL side-loading | DeviceImageLoadEvents | T1574.002 | Unsigned DLLs loaded from unusual paths by legitimate processes |

### Email

| Detection | Table(s) | MITRE ATT&CK | Description |
|:----------|:---------|:-------------|:------------|
| Phishing email with suspicious URL | EmailEvents, EmailUrlInfo | T1566.002 | Emails containing newly registered domains or known phishing infrastructure |
| Malware delivery via attachment | EmailEvents, EmailAttachmentInfo | T1566.001 | High-risk file types (.iso, .vhd, .lnk) delivered to users |
| Business Email Compromise (BEC) | EmailEvents, IdentityLogonEvents | T1534 | Emails from compromised accounts combined with unusual sign-in patterns |

### Identity

| Detection | Table(s) | MITRE ATT&CK | Description |
|:----------|:---------|:-------------|:------------|
| Password spray attack | IdentityLogonEvents | T1110.003 | Multiple failed logons across many accounts from limited sources |
| AD reconnaissance (LDAP enumeration) | IdentityQueryEvents | T1087 | Unusual LDAP queries enumerating users, groups, or computers |
| Privilege escalation (group add) | IdentityDirectoryEvents | T1098 | User added to Domain Admins or other sensitive groups |

### Cloud Apps

| Detection | Table(s) | MITRE ATT&CK | Description |
|:----------|:---------|:-------------|:------------|
| Impossible travel | CloudAppEvents | T1078 | Same user accessing cloud apps from geographically impossible locations |
| Mass file download from SharePoint | CloudAppEvents | T1530 | Unusual volume of file downloads indicating potential data exfiltration |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page. Each strategy links to its MITRE page, where the published pseudo-code analytic, correlation logic, and required telemetry are documented in full.

> [!NOTE]
> **Why no log-source column on this page?** Defender XDR exposes telemetry through abstracted Advanced Hunting tables (`DeviceProcessEvents`, `IdentityLogonEvents`, `EmailEvents`, `CloudAppEvents`) — not the raw Windows/macOS/Linux/SaaS channels that MITRE's analytics reference. Listing MITRE's raw `log_sources` here would imply a one-to-one mapping that doesn't exist: MDE/MDI/MDO/MDCA do not surface raw Sysmon, auditd, m365 unified audit, or Okta events. Use the strategy pages to understand **what** to correlate; then implement the correlation against the Advanced Hunting tables listed in the [Tables and Rationale](#tables-and-rationale) section above.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | [DET0363](https://attack.mitre.org/detectionstrategies/DET0363/) &mdash; Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | [DET0530](https://attack.mitre.org/detectionstrategies/DET0530/) &mdash; Multi-Event Detection for SMB Admin Share Lateral Movement |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [DET0455](https://attack.mitre.org/detectionstrategies/DET0455/) &mdash; Abuse of PowerShell for Arbitrary Execution |
| [T1069](https://attack.mitre.org/techniques/T1069/) | [DET0179](https://attack.mitre.org/detectionstrategies/DET0179/) &mdash; Behavioral Detection of Permission Groups Discovery |
| [T1078](https://attack.mitre.org/techniques/T1078/) | [DET0560](https://attack.mitre.org/detectionstrategies/DET0560/) &mdash; Detection of Valid Account Abuse Across Platforms |
| [T1087](https://attack.mitre.org/techniques/T1087/) | [DET0587](https://attack.mitre.org/detectionstrategies/DET0587/) &mdash; Enumeration of User or Account Information Across Platforms |
| [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) &mdash; Account Manipulation Behavior Chain Detection |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | [DET0487](https://attack.mitre.org/detectionstrategies/DET0487/) &mdash; Distributed Password Spraying via Authentication Failures Across Multiple Accounts |
| [T1486](https://attack.mitre.org/techniques/T1486/) | [DET0215](https://attack.mitre.org/detectionstrategies/DET0215/) &mdash; Detection of Multi-Platform File Encryption for Impact |
| [T1530](https://attack.mitre.org/techniques/T1530/) | [DET0484](https://attack.mitre.org/detectionstrategies/DET0484/) &mdash; Multi-Platform Cloud Storage Exfiltration Behavior Chain |
| [T1534](https://attack.mitre.org/techniques/T1534/) | [DET0054](https://attack.mitre.org/detectionstrategies/DET0054/) &mdash; Internal Spearphishing via Trusted Accounts |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | [DET0365](https://attack.mitre.org/detectionstrategies/DET0365/) &mdash; Detect Registry and Startup Folder Persistence (Windows) |
| [T1566](https://attack.mitre.org/techniques/T1566/) | [DET0070](https://attack.mitre.org/detectionstrategies/DET0070/) &mdash; Detection Strategy for Phishing across platforms |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | [DET0236](https://attack.mitre.org/detectionstrategies/DET0236/) &mdash; Detection Strategy for Spearphishing Attachment across OS Platforms |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | [DET0107](https://attack.mitre.org/detectionstrategies/DET0107/) &mdash; Detection Strategy for Spearphishing Links |
| [T1574](https://attack.mitre.org/techniques/T1574/) | [DET0218](https://attack.mitre.org/detectionstrategies/DET0218/) &mdash; Detection Strategy for Hijack Execution Flow across OS platforms |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) *(revoked &rarr; [T1574.001](https://attack.mitre.org/techniques/T1574/001/))* | [DET0201](https://attack.mitre.org/detectionstrategies/DET0201/) &mdash; Detection Strategy for Hijack Execution Flow for DLLs |

> [!NOTE]
> **MITRE legacy technique IDs.** Some technique IDs cited on this page are *legacy* IDs that MITRE has revoked and remapped: T1574.002 &rarr; T1574.001. Published Detection Strategies are attached to the current technique IDs only; the table above follows the `revoked-by` chain so each strategy still applies to the legacy ID cited above.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries (against Advanced Hunting tables) cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-1** Enable threat detection | Defender XDR provides native threat detection across endpoint, email, identity, and cloud apps |
| **LT-3** Enable logging for security investigation | Advanced hunting tables provide deep forensic telemetry |
| **LT-4** Enable network logging | DeviceNetworkEvents provides process-level network visibility |
| **LT-6** Configure log storage retention | Retention recommendations ensure forensic readiness while managing cost |
| **IR-4** Detection and analysis | Alert tables feed directly into incident response workflows |
| **IM-1** Centralise identity management | IdentityLogonEvents bridges on-premises AD and cloud identity |
| **PA-1** Protect privileged users | IdentityDirectoryEvents tracks changes to privileged groups |

> [!NOTE]
> **Other framework alignment:** This data supports NIST SP 800-53 SI-4 (system monitoring) and IR-4 (incident handling), CIS Controls v8 8.2 and 13.1 (security event alerting), and ASD ACSC enterprise network logging priority #1 (critical systems) and #10 (user computers).

---

## Notes

- The free data grant applies to ingestion into the **Analytics tier only** — ingesting directly to the Sentinel Data Lake (Lake) is not covered by the E5 grant
- Consider using the **Data Lake** tier for high-volume tables like `DeviceNetworkEvents` and `DeviceFileEvents` if cost becomes a concern beyond the free grant
- The free data grant applies to **advanced hunting tables only** — custom logs or additional enrichment pipelines may incur cost
- Enable **Incident creation rules** to automatically create Sentinel incidents from Defender XDR alerts

### Estimating Data Lake Retention Cost

To calculate the cost of retaining XDR data in the Sentinel Data Lake (365 days), you need to know the daily ingestion volume per table. There are two scenarios:

**Scenario 1 — Already ingesting to the Analytics tier**

If you are already streaming Defender XDR tables to Sentinel, use the **Workspace Usage Report** workbook (available in [Sentinel Content Hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-content-hub)) to review daily ingestion volumes per table. See the [Workspace Usage Report walkthrough](../procedures/workspace-usage-report.md) for step-by-step instructions. Use the resulting daily GB values with [Sentinel Data Lake pricing](https://learn.microsoft.com/en-us/azure/sentinel/billing?tabs=simplified%2Ccommitment-tiers) to calculate annual retention cost.

**Scenario 2 — Not yet ingesting to Sentinel**

If you have **not** enabled the Defender XDR connector in Sentinel, there is no ingestion data to query. Use the [XDR tables to Sentinel ingestion calculator](https://github.com/mathijsvermaat/DefenderIngestToSentinel) script to estimate volumes directly from the Defender Advanced Hunting API. The script samples actual records from each table, measures their size, and extrapolates daily/monthly ingestion in GB — giving you a data-driven cost estimate before committing. See the [XDR Ingestion Calculator walkthrough](../procedures/xdr-ingestion-calculator.md) for setup and usage instructions.

---

## Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor Defender XDR table ingestion volumes and validate the E5 data grant | Sentinel Content Hub | [Walkthrough](../procedures/workspace-usage-report.md) |
| **XDR tables to Sentinel ingestion calculator** | Script | Estimate Defender XDR ingestion volumes from the Advanced Hunting API before enabling the Sentinel connector (see [Scenario 2](#estimating-data-lake-retention-cost) above) | [GitHub — mathijsvermaat/DefenderIngestToSentinel](https://github.com/mathijsvermaat/DefenderIngestToSentinel) | [Walkthrough](../procedures/xdr-ingestion-calculator.md) |
| **XDR Data Volume Insights** | KQL Query | Measure Defender XDR and Entra ID table sizes, daily averages, and event counts to inform Analytics vs Data Lake tier decisions | Run in Advanced Hunting | [Walkthrough](../procedures/xdr-data-volume-insights.md) |
| **Microsoft Defender XDR** | Solution | 3 workbooks, 40 analytic rules, 330 hunting queries, 1 playbook — covers incident correlation, advanced hunting, and identity threat detection | Sentinel Content Hub | — |

---

## References

### Official Documentation

| Title | Description | Link |
|:------|:------------|:-----|
| Connect Microsoft Defender XDR to Microsoft Sentinel | Connector setup guide — incidents & alerts, UEBA entities, and advanced hunting tables | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender) |
| Microsoft Defender XDR integration with Microsoft Sentinel | Architecture overview of the XDR-Sentinel integration | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-365-defender-sentinel-integration) |
| Advanced hunting schema reference | Table-by-table schema documentation for all Defender XDR advanced hunting tables (DeviceEvents, EmailEvents, IdentityLogonEvents, etc.) | [learn.microsoft.com](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) |

### Admin portal

- [Microsoft Defender portal](https://security.microsoft.com/) — enable the Sentinel data connector for Defender XDR, run Advanced Hunting, and configure Lake-tier ingestion for advanced-hunting tables.
  - Quick links via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`defender.cmd.ms`](https://defender.cmd.ms/) (Defender root), [`th.cmd.ms`](https://th.cmd.ms/) (Threat Hunting), [`xdranalytics.cmd.ms`](https://xdranalytics.cmd.ms/) (Analytic rules), [`desettings.cmd.ms`](https://desettings.cmd.ms/) (Defender settings).

### Community & Third-Party Resources

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| Sentinel Ninja — Microsoft Defender XDR connector | Ofer Shezaf (Microsoft) | Auto-generated reference: tables ingested, related solutions, and content items | [github.com](https://github.com/oshezaf/sentinelninja/blob/main/Solutions%20Docs/connectors/microsoftthreatprotection.md) |
| How to natively archive Defender XDR logs for up to 12 years | Jeffrey Appel | Explains how to use the Sentinel Data Lake tier for long-term retention of Defender XDR advanced hunting tables — directly relevant to the Data Lake retention cost discussion on this page | [jeffreyappel.nl](https://jeffreyappel.nl/how-to-archive-defender-logs-natively-in-defender-xdr-up-to-12-years/) |
| Data lake tier ingestion for Microsoft Defender Advanced Hunting tables is now GA | Microsoft Sentinel Blog | Announcement of GA for ingesting Defender XDR advanced hunting tables into the Sentinel data lake tier | [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/data-lake-tier-ingestion-for-microsoft-defender-advanced-hunting-tables-is-now-g/4494206) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
