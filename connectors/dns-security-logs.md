# DNS Security Logs

**Tier:** 2 (Extended Visibility) · **Connector type:** Microsoft first-party · **Free ingestion:** No (paid ingestion)

---

## Contents

- [DNS Security Logs](#dns-security-logs)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
  - [Tables and Rationale](#tables-and-rationale)
    - [Endpoint DNS](#endpoint-dns)
    - [Azure DNS](#azure-dns)
  - [Example Detections](#example-detections)
    - [C2 and Tunnelling](#c2-and-tunnelling)
    - [Reputation and Threat Intel](#reputation-and-threat-intel)
  - [MITRE Detection Strategies](#mitre-detection-strategies)
  - [MCSB Control Mapping](#mcsb-control-mapping)
  - [Important Considerations](#important-considerations)
    - [Three DNS Vantage Points](#three-dns-vantage-points)
    - [Volume Management](#volume-management)
  - [Notes](#notes)
  - [Tools](#tools)
  - [References](#references)
    - [Official Documentation](#official-documentation)
    - [Admin portal](#admin-portal)
    - [Community \& Third-Party Resources](#community--third-party-resources)

---

## Overview

DNS is one of the most forensically valuable and tactically underutilised data sources in security operations. Every network connection starts with a DNS query — logging DNS gives you visibility into what every device is trying to communicate with, **before the connection is established**.

This page covers two complementary DNS data sources:

1. **Endpoint DNS logging** — DNS queries from Windows endpoints collected via Azure Monitor Agent (AMA) and the DNS extension
2. **Azure DNS diagnostic logs** — queries to Azure Private DNS zones and Azure DNS Resolver

For Azure Firewall DNS proxy logs, see the [Azure Firewall](azure-firewall.md) page (`AZFWDnsQuery`). All three sources are complementary and provide different vantage points.

### Licensing Benefits

| Sentinel cost classification | Microsoft Sentinel benefit |
|:-----------------------------|:---------------------------|
| **No (paid ingestion)** | No built-in Sentinel ingestion benefit is documented for this connector; ingestion is billed based on enabled data types and volume. |

> [!NOTE]
> This is a connector-level Sentinel classification used for cost planning.

---

## Tables and Rationale

### Endpoint DNS

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **DnsEvents** | DNS query events from Windows endpoints — queried domain, query type, result, client IP | Analytics: 90d / Lake: 365d | **Core DNS forensics table.** Detects C2 over DNS, DNS tunnelling, DGA, and domain reputation matches. | Proves exactly which endpoint queried which domain — the definitive source for tracking C2 beaconing, phishing domain resolution, and data exfiltration attempts via DNS. | DNS tunnelling — high query volume to single domain, DGA detection — algorithmically generated subdomains |
| **DnsInventory** | DNS server inventory — zones, records, configuration | Analytics: 90d / Lake: 365d | Infrastructure context for DNS investigations. | Understanding of DNS infrastructure state — which zones existed and which records were configured at the time of an incident | Rogue DNS zone created on internal DNS server |

### Azure DNS

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **AzureDiagnostics** (Azure DNS) | Queries to Azure Private DNS zones and DNS Resolver | Analytics: 90d / Lake: 365d | Cloud-side DNS visibility — detects query patterns from Azure resources (VMs, containers, PaaS). | Proves which Azure resources queried which domains — essential for investigating compromised Azure workloads | Azure VM querying known C2 domain via Private DNS |

---

## Example Detections

### C2 and Tunnelling

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| DNS tunnelling | DnsEvents | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [DET0400](https://attack.mitre.org/detectionstrategies/DET0400/) — DNS Tunneling | High-entropy or excessively long subdomain queries to a single domain — data exfiltration via DNS |
| DGA domain resolution | DnsEvents | [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | [DET0419](https://attack.mitre.org/detectionstrategies/DET0419/) — Domain Generation Algorithms | Algorithmically generated domain names — characteristic of malware families using DGA for C2 |
| DNS beaconing | DnsEvents | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [DET0400](https://attack.mitre.org/detectionstrategies/DET0400/) — DNS Tunneling | Regular, periodic DNS queries to a single domain — C2 beacon pattern |
| Rare domain query | DnsEvents | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [DET0400](https://attack.mitre.org/detectionstrategies/DET0400/) — DNS Tunneling | DNS query for a domain seen by only one endpoint — potential unique C2 infrastructure |

### Reputation and Threat Intel

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Known malicious domain query | DnsEvents + ThreatIntelligenceIndicator | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [DET0400](https://attack.mitre.org/detectionstrategies/DET0400/) — DNS Tunneling | DNS query matching a known bad domain from threat intelligence feeds |
| Newly registered domain | DnsEvents | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | [DET0892](https://attack.mitre.org/detectionstrategies/DET0892/) — Detection of Domains | DNS query for a domain registered within the last 14 days — common for phishing and C2 |
| Dynamic DNS domain | DnsEvents | [T1568.001](https://attack.mitre.org/techniques/T1568/001/) | [DET0485](https://attack.mitre.org/detectionstrategies/DET0485/) — Fast Flux DNS | DNS query for a domain on dynamic DNS providers (duckdns.org, no-ip.com, etc.) |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page. The **MITRE Log Sources (Windows)** column lists the exact log channels and event codes referenced by the analytic of each strategy on the relevant platform — taken verbatim from the strategy's published `log_sources` field in the [ATT&CK STIX bundle](https://github.com/mitre-attack/attack-stix-data).

| Technique | Detection Strategy | MITRE Log Sources (Windows) |
|:----------|:-------------------|:-----------|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | [DET0400](https://attack.mitre.org/detectionstrategies/DET0400/) &mdash; Behavioral Detection of DNS Tunneling and Application Layer Abuse | `NSM:Flow`: dns.log &middot; `WinEventLog:Sysmon`: EventCode=3, 22 |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | [DET0419](https://attack.mitre.org/detectionstrategies/DET0419/) &mdash; Detection Strategy for Dynamic Resolution using Domain Generation Algorithms. | `WinEventLog:Security`: EventCode=4688 &middot; `WinEventLog:Sysmon`: EventCode=3, 22 |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | [DET0892](https://attack.mitre.org/detectionstrategies/DET0892/) &mdash; Detection of Domains | *MITRE has not published a Windows analytic for this strategy* |
| [T1568.001](https://attack.mitre.org/techniques/T1568/001/) | [DET0485](https://attack.mitre.org/detectionstrategies/DET0485/) &mdash; Detection Strategy for Dynamic Resolution using Fast Flux DNS | `WinEventLog:Security`: EventCode=1 &middot; `WinEventLog:Sysmon`: EventCode=3, 22 |

> [!NOTE]
> **Log sources are verbatim from MITRE.** The third column is generated directly from each strategy's published `x_mitre_log_source_references` field in the [ATT&CK STIX 2.1 bundle](https://github.com/mitre-attack/attack-stix-data) — it is **not** a hand-picked list of "events that look related on this connector page". MITRE's published analytics for DNS techniques rely on Sysmon network events and `NSM:Flow` dns.log; the connector's own `DnsEvents` table is the primary detection surface in Sentinel.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-4** Enable network logging for security investigation | DNS logging provides network-layer visibility into domain resolution |
| **LT-1** Enable threat detection | DNS anomaly detection identifies C2, tunnelling, and DGA patterns |
| **NS-2** Secure cloud native services with network controls | DNS logging supports enforcement visibility for DNS-based security policies |

> [!NOTE]
> **Other framework alignment:** This data supports NIST SP 800-53 AU-12 (audit generation) and SC-20 (secure name resolution), CIS Controls v8 9.2 (DNS filtering) and 8.2 (collect audit logs), and ASD ACSC enterprise network logging priority #13 (DNS services).

---

## Important Considerations

### Three DNS Vantage Points

| Source | What It Captures | Complements |
|:-------|:-----------------|:------------|
| **DnsEvents** (endpoint) | DNS queries from Windows endpoints | Process-to-DNS correlation with DeviceNetworkEvents (Defender XDR) |
| **AZFWDnsQuery** (firewall) | DNS queries passing through Azure Firewall DNS proxy | Network-level DNS for Azure resources |
| **AzureDiagnostics** (Azure DNS) | Queries to Azure Private DNS zones | Cloud DNS infrastructure events |

For maximum DNS visibility, enable all three where applicable.

### Volume Management

DNS logs are **high-volume**. Strategies to manage cost:
- Use the **Data Lake** tier for `DnsEvents` if full KQL capability is not needed for all queries
- Filter DNS queries in the DCR to exclude known-safe domains (e.g., Windows Update, CDN domains) — but exercise caution to avoid filtering out C2 hiding behind legitimate services
- Start with a small pilot group before deploying DNS collection to all endpoints

---

## Notes

- DNS logging provides the **earliest signal** for C2 detection — the DNS query happens before the connection is established
- Combine DNS data with [Threat Intelligence](threat-intelligence.md) for maximum detection value — TI domain matching against DNS queries is one of the highest-confidence detections
- For Azure Firewall DNS proxy logs, see the [Azure Firewall](azure-firewall.md) page
- Consider the JSCU (Dutch AIVD/MIVD) [logging-essentials](https://github.com/JSCU-NL/logging-essentials) repository for Windows event logging baselines including DNS

---

## Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor DNS table ingestion volumes | Sentinel Content Hub | [Walkthrough](../procedures/workspace-usage-report.md) |
| **DNS Essentials** | Solution | ASIM-based DNS analytics — detections for tunnelling, DGA domains, and excessive NXDOMAIN queries | Sentinel Content Hub | — |

---

## References

### Official Documentation

| Title | Description | Link |
|:------|:------------|:-----|
| Connect your DNS servers to Microsoft Sentinel | Connector setup guide — Windows DNS Events via AMA | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/dns) |
| Windows DNS Events via AMA (Sentinel data connectors reference) | Official Sentinel data connector entry — `ASimDnsActivityLogs` table and ASIM normalisation | [learn.microsoft.com](https://learn.microsoft.com/azure/sentinel/data-connectors-reference#windows-dns-events-via-ama) |

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — configure Azure Private DNS / DNS Resolver diagnostic settings to route queries into `AzureDiagnostics`.
  - Quick link via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azdns.cmd.ms`](https://azdns.cmd.ms/) (DNS zones).

### Community & Third-Party Resources

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| Sentinel Ninja — DNS connector | Ofer Shezaf (Microsoft) | Auto-generated reference: tables ingested, related solutions, and content items | [github.com](https://github.com/oshezaf/sentinelninja/blob/main/Solutions%20Docs/connectors/dns.md) |
| Best practices for event logging and threat detection | ASD ACSC | International joint guidance — DNS services are Enterprise Networks priority #13 | [cyber.gov.au](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-for-event-logging-and-threat-detection) |
| JSCU Logging Essentials | AIVD / MIVD (Netherlands) | Dutch intelligence services' baseline for Windows event logging including DNS — developed by the Joint SIGINT Cyber Unit | [GitHub](https://github.com/JSCU-NL/logging-essentials) |
| Public preview — collect Azure resource platform logs at scale with DCRs | Azure Observability blog (Microsoft) | New DCR-based approach that replaces per-resource diagnostic settings, with ingestion-time filtering/transformation and ARM/Bicep/Terraform/Policy deployment | [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/AzureObservabilityBlog/public-preview---azure-monitor---collect-azure-resource-platform-logs-at-scale-w/4525296) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
