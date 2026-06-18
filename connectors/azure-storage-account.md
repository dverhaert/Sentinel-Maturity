# Azure Storage Account

**Tier:** 3 (Advanced) · **Connector type:** Microsoft first-party (Diagnostic Settings) · **Free ingestion:** No (paid ingestion)

> [!NOTE]
> Microsoft Sentinel lists this connector as **Azure Storage Account** in the data connectors reference. It was previously referred to in this guide as "Azure Storage Analytics" — only the name changed; the underlying diagnostic settings and tables are the same.

---

## Contents

- [Azure Storage Account](#azure-storage-account)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
  - [Enabling Visibility and Detection](#enabling-visibility-and-detection)
  - [Tables and Rationale](#tables-and-rationale)
  - [Example Detections](#example-detections)
  - [MITRE Detection Strategies](#mitre-detection-strategies)
  - [MCSB Control Mapping](#mcsb-control-mapping)
  - [Important Considerations](#important-considerations)
  - [Notes](#notes)
    - [Tools](#tools)
  - [References](#references)
    - [Admin portal](#admin-portal)

---

## Overview

Azure Storage diagnostic logs capture **data-plane operations** on Blob, File, Queue, and Table storage: every read, write, delete, and list operation with the calling identity, client IP, and operation context. While Azure Activity Logs (Tier 1) capture storage account management operations, storage analytics logs capture *who accessed which data, when, and how*.

For organisations storing sensitive documents, backups, application data, or data lake contents in Azure Storage, these logs are critical for detecting data exfiltration, unauthorized access, and SAS token abuse. Storage accounts are one of the most common Azure resources targeted in attacks — leaked SAS tokens and misconfigured anonymous access are frequent root causes.

### Licensing Benefits

| Sentinel cost classification | Microsoft Sentinel benefit |
|:-----------------------------|:---------------------------|
| **No (paid ingestion)** | No built-in Sentinel ingestion benefit is documented for this connector; ingestion is billed based on enabled data types and volume. |

> [!NOTE]
> This is a connector-level Sentinel classification used for cost planning.

---

## Enabling Visibility and Detection

Azure resources do **not** generate data-plane (diagnostic) logs by default. Unlike an on-premises system that writes to a local event log — which at least buffers and rolls over — an Azure Storage account produces **no audit trail at all** until you explicitly route its logs somewhere. The only way to retain evidence of what happened is to send the diagnostic logs to Azure Monitor / Log Analytics (or Storage / Event Hubs) **before** an incident occurs. If diagnostic settings (or a Data Collection Rule) are not in place at the time, that telemetry is never produced and **cannot be recovered retroactively**.

This makes deliberate log configuration a **forensic-readiness prerequisite**, not a cost optimisation — see [Forensic Readiness](../guidance/forensic-readiness.md) and the [Layered Detection Approach](../guidance/layered-detection.md). You have three options to gain visibility and detections for Azure Storage:

| Option | What you get | Detections available |
|:-------|:-------------|:---------------------|
| **A — Defender for Storage only** | Out-of-the-box Defender for Cloud alerts (malware uploads via hash-reputation and on-upload scanning, anomalous access, data exfiltration, sensitive-data exposure) surfaced in `SecurityAlert` and the Defender portal via the [Microsoft Defender for Cloud](microsoft-defender-for-cloud.md) connector. Fast to enable; no raw audit trail. | Microsoft-maintained Defender alerts only — no raw log for custom hunting or forensics |
| **B — Defender for Storage + diagnostic logs** *(recommended)* | Both the out-of-the-box Defender alerts **and** the full data-plane audit trail (`StorageBlobLogs`, `StorageFileLogs`, etc.) in Sentinel for correlation, custom analytics, threat hunting, and long-term forensic retention. | Defender alerts **+** custom KQL analytics **+** full forensic trail |
| **C — Diagnostic logs only** | The full storage data-plane audit trail in Sentinel, but **no** Defender for Storage out-of-the-box detections — every detection is one you build and maintain yourself. | Custom KQL analytics + forensic trail; no out-of-the-box Defender alerts |

> [!TIP]
> Option **B** is the recommended baseline: Defender for Cloud provides immediate, Microsoft-maintained detections, while the diagnostic logs preserve the underlying evidence those alerts are derived from — plus everything an alert cannot anticipate.

---

## Tables and Rationale

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **AzureMetrics** | Storage account-level metrics — transaction counts, capacity, availability, end-to-end latency | Analytics: 30d / Lake: 90d | Baseline activity signal for anomaly detection — sudden transaction spikes or capacity changes can indicate exfiltration or destruction | Quantifies access volume even when individual `Storage*Logs` are filtered for cost; complements operational alerting | Sudden 10× spike in egress transactions outside business hours |
| **StorageBlobLogs** | Blob storage operations — read, write, delete, list, copy, and snapshot operations with caller identity and IP | Analytics: 90d / Lake: 365d | Primary data-plane audit trail for blob storage — the most commonly used Azure storage service | Proves exactly which blobs were accessed, by whom, and from which IP — essential for determining data exfiltration scope | Mass blob download from unusual IP |
| **StorageFileLogs** | Azure Files operations — file share read, write, delete, and permission changes | Analytics: 90d / Lake: 365d | Audit trail for Azure Files — commonly used for lift-and-shift file shares and application data | Identifies unauthorized file access and share-level operations during investigations | Bulk file copy from Azure Files to external location |
| **StorageQueueLogs** | Queue storage operations — send, receive, peek, and delete messages | Analytics: 30d / Lake: 180d | Queue operations can reveal application workflow manipulation or message injection | Identifies queue manipulation that could affect application behavior and data processing | Unauthorized message injection into processing queue |
| **StorageTableLogs** | Table storage operations — query, insert, update, delete on table entities | Analytics: 30d / Lake: 180d | Table storage audit trail — relevant for applications using Table storage for state or configuration | Proves data access patterns for Table storage-based applications | Mass entity enumeration from unusual source |

---

## Example Detections

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Mass blob download via SAS token | StorageBlobLogs | [T1530](https://attack.mitre.org/techniques/T1530/) | [DET0484](https://attack.mitre.org/detectionstrategies/DET0484/) — Cloud Storage Exfiltration | Large volume of blob read operations authenticated with a SAS token from an unusual IP |
| Anonymous access to private container | StorageBlobLogs | [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) — Exploit Public-Facing Application | Access to storage blobs with anonymous authentication — indicates misconfigured container access level |
| SAS token usage from suspicious geography | StorageBlobLogs | [T1528](https://attack.mitre.org/techniques/T1528/) | [DET0515](https://attack.mitre.org/detectionstrategies/DET0515/) — Steal Application Access Token | SAS token authenticated operations from a geographic region outside the organisation's normal range |
| Bulk deletion of storage data | StorageBlobLogs, StorageFileLogs | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Mass delete operations across blobs or files — potential destructive attack or evidence destruction |
| Storage account accessed via compromised identity | StorageBlobLogs | [T1078](https://attack.mitre.org/techniques/T1078/) | [DET0560](https://attack.mitre.org/detectionstrategies/DET0560/) — Valid Accounts | Storage operations from an identity flagged as risky in Entra ID Protection |
| Azure Files bulk copy | StorageFileLogs | [T1039](https://attack.mitre.org/techniques/T1039/) | [DET0410](https://attack.mitre.org/detectionstrategies/DET0410/) — Data from Network Shared Drive | Bulk file copy from Azure Files to external location |
| Queue message injection | StorageQueueLogs | [T1565](https://attack.mitre.org/techniques/T1565/) | [DET0059](https://attack.mitre.org/detectionstrategies/DET0059/) — Data Manipulation | Unauthorized message injection into processing queue |
| Table mass entity enumeration | StorageTableLogs | [T1213](https://attack.mitre.org/techniques/T1213/) | [DET0413](https://attack.mitre.org/detectionstrategies/DET0413/) — Data from Information Repositories | Mass entity enumeration from unusual source |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1530](https://attack.mitre.org/techniques/T1530/) | [DET0484](https://attack.mitre.org/detectionstrategies/DET0484/) &mdash; Multi-Platform Cloud Storage Exfiltration Behavior Chain |
| [T1039](https://attack.mitre.org/techniques/T1039/) | [DET0410](https://attack.mitre.org/detectionstrategies/DET0410/) &mdash; Detection Strategy for Data from Network Shared Drive |
| [T1565](https://attack.mitre.org/techniques/T1565/) | [DET0059](https://attack.mitre.org/detectionstrategies/DET0059/) &mdash; Detection Strategy for Data Manipulation |
| [T1213](https://attack.mitre.org/techniques/T1213/) | [DET0413](https://attack.mitre.org/detectionstrategies/DET0413/) &mdash; Abuse of Information Repositories for Data Collection |
| [T1190](https://attack.mitre.org/techniques/T1190/) | [DET0080](https://attack.mitre.org/detectionstrategies/DET0080/) &mdash; Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress) |
| [T1528](https://attack.mitre.org/techniques/T1528/) | [DET0515](https://attack.mitre.org/detectionstrategies/DET0515/) &mdash; Detection Strategy for T1528 - Steal Application Access Token |
| [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) &mdash; Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns |
| [T1078](https://attack.mitre.org/techniques/T1078/) | [DET0560](https://attack.mitre.org/detectionstrategies/DET0560/) &mdash; Detection of Valid Account Abuse Across Platforms |

> [!NOTE]
> This page intentionally omits the third MITRE-evidence column. For cloud platform-family strategies, MITRE may cite provider-specific source names that do not map 1:1 to Azure Storage tables; keeping this section as Technique + Detection Strategy avoids a brittle translation layer.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **DP-2** Monitor anomalies and threats targeting sensitive data | Direct monitoring of data access patterns on Azure Storage — the primary cloud data store |
| **DP-3** Encrypt sensitive data in transit | Storage logs record operation protocol (HTTPS vs HTTP) — detects unencrypted access |
| **LT-3** Enable logging for security investigation | Storage access logs provide the data-plane investigation trail for data breach scenarios |

---

## Important Considerations

- **Volume management is critical:** Storage analytics on high-traffic storage accounts can generate terabytes of log data. Enable selectively on accounts containing sensitive data
- **Resource-specific mode:** Use resource-specific diagnostic settings to get dedicated tables (`StorageBlobLogs`, etc.) instead of the generic `AzureDiagnostics` table
- **SAS token monitoring:** Pay special attention to SAS token authenticated operations — leaked SAS tokens are a common attack vector. Correlate with Azure Activity Logs to detect SAS token generation
- **Defender for Storage:** If you have Defender for Cloud (Tier 2), storage threat detection alerts already flow through `SecurityAlert`. These audit logs add the detailed operation-level trail

---

## Notes

- Prioritise logging on storage accounts classified as containing sensitive data or backup data — not all storage accounts need logging
- Consider pairing with Azure Key Vault (Tier 2) — storage account keys and SAS tokens may be stored in Key Vault
- Azure Data Lake Storage Gen2 uses the same `StorageBlobLogs` table — data lake operations are captured automatically

### Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| [Workspace Usage Report](../procedures/workspace-usage-report.md) | Workbook | Verify storage log volumes and ingestion | Sentinel Maturity Model | [Procedure guide](../procedures/workspace-usage-report.md) |

---

## References

| Source | Link |
|:-------|:-----|
| Azure Storage analytics logging | [Learn](https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging) |
| Storage diagnostic settings | [Learn](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage) |
| Defender for Storage overview | [Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction) |
| StorageBlobLogs table reference | [Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs) |
| Public preview — collect Azure resource platform logs at scale with DCRs | [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/AzureObservabilityBlog/public-preview---azure-monitor---collect-azure-resource-platform-logs-at-scale-w/4525296) |

---

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — configure Storage account diagnostic settings (use **resource-specific** mode to route to `StorageBlobLogs` etc., not legacy `AzureDiagnostics`).
  - Quick link via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azsa.cmd.ms`](https://azsa.cmd.ms/) (Storage accounts).

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
