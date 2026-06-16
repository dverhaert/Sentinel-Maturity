# Azure Key Vault

**Tier:** 2 (Extended Visibility) · **Connector type:** Microsoft first-party · **Free ingestion:** No (paid ingestion)

---

## Contents

- [Azure Key Vault](#azure-key-vault)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
  - [Tables and Rationale](#tables-and-rationale)
  - [Example Detections](#example-detections)
    - [Secret Access](#secret-access)
    - [Administrative Changes](#administrative-changes)
  - [MITRE Detection Strategies](#mitre-detection-strategies)
  - [MCSB Control Mapping](#mcsb-control-mapping)
  - [Important Considerations](#important-considerations)
    - [Resource-Specific vs. Azure Diagnostics](#resource-specific-vs-azure-diagnostics)
    - [Coverage](#coverage)
    - [Defender for Key Vault](#defender-for-key-vault)
  - [Notes](#notes)
  - [Tools](#tools)
  - [References](#references)
    - [Official Documentation](#official-documentation)
    - [Admin portal](#admin-portal)
    - [Community \& Third-Party Resources](#community--third-party-resources)

---

## Overview

Azure Key Vault stores and manages cryptographic keys, secrets (connection strings, API keys, passwords), and certificates. The diagnostic logs record **every access operation** — who accessed which secret, when, and from which IP. This makes Key Vault one of the most forensically valuable data-plane audit sources in Azure.

In a breach scenario, the first question after *"which accounts were compromised?"* is often *"could they access secrets?"*. Key Vault logs answer this definitively.

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
| **AKVAuditLogs** (resource-specific) | All Key Vault operations — secret get/set/delete, key operations, certificate operations, access policy changes | Analytics: 90d / Lake: 365d | **Core secrets audit trail.** Detects unauthorized secret access, bulk secret enumeration, and access policy tampering. MCSB DP-6, LT-3. | Proves exactly which secrets were accessed, by which identity, from which IP, and when. The definitive evidence for determining whether an attacker obtained secret material during a breach. | Mass secret retrieval from unusual IP — potential credential theft |
| **AzureDiagnostics** (KeyVault) | Legacy diagnostic mode — same data in unstructured format | Analytics: 90d / Lake: 365d | Fallback for Key Vaults not yet migrated to resource-specific mode. | Same forensic value as AKVAuditLogs but harder to query | Same as above |

> [!TIP]
> Use **resource-specific** diagnostic settings to route logs to `AKVAuditLogs` instead of `AzureDiagnostics`. Resource-specific tables are structured, cheaper to query, and easier to write detections against.

---

## Example Detections

### Secret Access

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Mass secret retrieval | AKVAuditLogs | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | [DET0549](https://attack.mitre.org/detectionstrategies/DET0549/) — Private Key Access | Single identity retrieving many secrets in a short timeframe — bulk credential theft |
| Secret access from unusual IP | AKVAuditLogs | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | [DET0549](https://attack.mitre.org/detectionstrategies/DET0549/) — Private Key Access | Secret retrieval from an IP not seen in baseline vault access patterns |
| Secret access from unexpected identity | AKVAuditLogs | [T1078](https://attack.mitre.org/techniques/T1078/) | [DET0560](https://attack.mitre.org/detectionstrategies/DET0560/) — Valid Accounts | Service principal or user accessing secrets they have not accessed before |
| Access denied spike | AKVAuditLogs | [T1087](https://attack.mitre.org/techniques/T1087/) | [DET0587](https://attack.mitre.org/detectionstrategies/DET0587/) — Account Discovery | Sudden increase in 403 responses — may indicate reconnaissance or misconfigured stolen credentials |

### Administrative Changes

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Key Vault access policy modified | AKVAuditLogs + AzureActivity | [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) — Account Manipulation | Access policy change granting new identities access to secrets |
| Soft-delete disabled | AKVAuditLogs | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Disabling soft-delete on a Key Vault — potential preparation for destructive action |
| Key Vault purged | AKVAuditLogs + AzureActivity | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Deletion of a Key Vault containing cryptographic keys or secrets |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | [DET0549](https://attack.mitre.org/detectionstrategies/DET0549/) &mdash; Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms |
| [T1078](https://attack.mitre.org/techniques/T1078/) | [DET0560](https://attack.mitre.org/detectionstrategies/DET0560/) &mdash; Detection of Valid Account Abuse Across Platforms |
| [T1087](https://attack.mitre.org/techniques/T1087/) | [DET0587](https://attack.mitre.org/detectionstrategies/DET0587/) &mdash; Enumeration of User or Account Information Across Platforms |
| [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) &mdash; Account Manipulation Behavior Chain Detection |
| [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) &mdash; Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns |

> [!NOTE]
> This page intentionally omits the third MITRE-evidence column. For cloud platform-family strategies, MITRE may cite provider-specific source names that do not map 1:1 to Azure Key Vault tables; keeping this section as Technique + Detection Strategy avoids a brittle translation layer.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **DP-6** Use a secure key management process | Key Vault is the primary Azure key management service — audit logs track key lifecycle |
| **DP-7** Use a secure certificate management process | Certificate operations are logged in the same audit trail |
| **LT-3** Enable logging for security investigation | Key Vault logs are the data-plane audit trail for secret access |
| **IM-4** Authenticate server and services | Service principal and managed identity access to secrets is tracked |
| **PA-7** Follow just enough administration | Access policy audit trail supports least-privilege enforcement for secrets |

> [!NOTE]
> **Other framework alignment:** This data supports NIST SP 800-53 SC-12 (cryptographic key management) and AU-2 (audit events), CIS Controls v8 3.11 (encrypt sensitive data at rest), and ASD ACSC enterprise network logging priority #7 (privileged systems and secret management).

---

## Important Considerations

### Resource-Specific vs. Azure Diagnostics

| Mode | Table | Recommendation |
|:-----|:------|:---------------|
| **Resource-specific** (recommended) | `AKVAuditLogs` | Structured, cheaper, better performance |
| Azure Diagnostics (legacy) | `AzureDiagnostics` with `ResourceType == "VAULTS"` | Legacy — migrate when possible |

### Coverage

- Configure diagnostic settings on **every Key Vault** in your environment, including development and test vaults
- Use Azure Policy to enforce diagnostic settings: `Microsoft.Insights/diagnosticSettings — deployIfNotExists`
- Key Vaults in dev/test environments are often less protected and may be the first target

### Defender for Key Vault

If you have Defender for Key Vault enabled, anomalous access alerts (unusual IP, unusual volume, Tor access) flow through `SecurityAlert` — see the [Defender for Cloud](microsoft-defender-for-cloud.md) page. The diagnostic logs provide the raw audit trail underneath those alerts.

---

## Notes

- Key Vault log volume is typically low compared to network or endpoint logs — cost is usually manageable
- The combination of Key Vault audit logs + Azure Activity Logs (control plane) provides full vault lifecycle visibility
- For HSM-backed keys, `AzureDiagnostics` may include additional Managed HSM operations
- Key Vault is frequently targeted in cloud-native attacks — after compromising an identity, attackers enumerate accessible Key Vaults for connection strings and API keys

---

## Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor Key Vault table ingestion volumes | Sentinel Content Hub | [Walkthrough](../procedures/workspace-usage-report.md) |
| **Azure Key Vault** | Solution | Provides the Azure Key Vault connector and diagnostic settings for monitoring secret, key, and certificate operations | Sentinel Content Hub | — |

---

## References

### Official Documentation

| Title | Description | Link |
|:------|:------------|:-----|
| Connect Azure Key Vault to Microsoft Sentinel | Connector setup guide — diagnostic settings for key, secret, and certificate audit events | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/azure-key-vault) |
| Azure Key Vault logging | Overview of Key Vault diagnostic logging and log categories | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/key-vault/general/logging) |

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — configure Key Vault diagnostic settings (use **resource-specific** mode to route to `AKVAuditLogs`, not legacy `AzureDiagnostics`).
  - Quick link via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azkv.cmd.ms`](https://azkv.cmd.ms/) (Key Vaults).

### Community & Third-Party Resources

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| Sentinel Ninja — Azure Key Vault connector | Ofer Shezaf (Microsoft) | Auto-generated reference: tables ingested, related solutions, and content items | [github.com](https://github.com/oshezaf/sentinelninja/blob/main/Solutions%20Docs/connectors/azurekeyvault.md) |
| Best practices for event logging and threat detection | ASD ACSC | International joint guidance — secret and privilege management is Enterprise Networks priority #7 | [cyber.gov.au](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/best-practices-for-event-logging-and-threat-detection) |
| Public preview — collect Azure resource platform logs at scale with DCRs | Azure Observability blog (Microsoft) | New DCR-based approach that replaces per-resource diagnostic settings, with ingestion-time filtering/transformation and ARM/Bicep/Terraform/Policy deployment | [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/AzureObservabilityBlog/public-preview---azure-monitor---collect-azure-resource-platform-logs-at-scale-w/4525296) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
