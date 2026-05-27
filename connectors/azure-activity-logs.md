# Azure Activity Logs

**Tier:** 1 (Bare Minimum) · **Connector type:** Microsoft first-party · **Free ingestion:** Yes (free data source)

---

## Contents

- [Azure Activity Logs](#azure-activity-logs)
  - [Contents](#contents)
  - [Overview](#overview)
    - [Licensing Benefits](#licensing-benefits)
  - [Tables and Rationale](#tables-and-rationale)
  - [Example Detections](#example-detections)
    - [Resource-Based](#resource-based)
    - [Identity / RBAC](#identity--rbac)
    - [Key Vault](#key-vault)
  - [MITRE Detection Strategies](#mitre-detection-strategies)
  - [MCSB Control Mapping](#mcsb-control-mapping)
  - [Important Considerations](#important-considerations)
    - [Log Categories to Enable](#log-categories-to-enable)
    - [Deployment](#deployment)
  - [Notes](#notes)
  - [Tools](#tools)
  - [References](#references)
    - [Official Documentation](#official-documentation)
    - [Community \& Third-Party Resources](#community--third-party-resources)

---

## Overview

Azure Activity Logs capture **subscription-level events** across all your Azure resources. This includes resource creation and deletion, role assignments, policy changes, service health events, and autoscale operations. It is the **control plane audit trail** for your Azure environment and is indispensable for detecting unauthorized infrastructure changes, privilege escalation via Azure RBAC, and resource abuse (e.g., crypto-mining VMs).

### Licensing Benefits

| License | What it unlocks |
|:--------|:----------------|
| **Any Azure subscription** | Full activity log data — no additional license required |

> [!NOTE]
> Azure Activity Logs are a **free data source** in Sentinel. Every Azure subscription generates these logs. Connect all subscriptions.

---

## Tables and Rationale

| Table | Category | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:---------|:------------|:------------------------|:----------|:---------------|:------------------|
| **AzureActivity** | Administrative | Resource creation, modification, deletion (PUT, PATCH, DELETE operations) | Analytics: 90d / Lake: 365d | Detects unauthorized resource deployment (crypto-mining VMs, exfiltration infrastructure), resource deletion (sabotage), and configuration changes. MCSB AM-2 (Use only approved services), LT-3. | Complete audit trail of every Azure control plane operation — proves who created, modified, or deleted which resource, when, and from which IP. The authoritative evidence for Azure infrastructure investigations. | Crypto-mining VM deployment in unusual region, Mass resource group deletion |
| **AzureActivity** | Security | Security Center / Defender for Cloud alerts and recommendations | Analytics: 90d / Lake: 365d | Provides a secondary view of Defender for Cloud alerts at the platform level. | Correlate security alerts with resource changes — proves whether a Defender for Cloud alert was followed by remediation or further malicious activity | Defender for Cloud alert correlation with resource changes |
| **AzureActivity** | ServiceHealth | Azure service incidents, planned maintenance | Analytics: 90d / Lake: 365d | Operational context — helps distinguish between attacker activity and platform issues during investigations. | Rule out platform issues as root cause — proves whether an outage was due to an Azure incident or an attacker's actions | Rule out platform issue during incident investigation |
| **AzureActivity** | Alert | Azure Monitor alert events | Analytics: 90d / Lake: 365d | Operational alerting correlated with security context. | Correlate operational alerts with security events — shows whether infrastructure alerts preceded or followed suspicious activity | Azure Monitor alert correlated with suspicious activity |
| **AzureActivity** | Policy | Azure Policy evaluation results (compliance/non-compliance) | Analytics: 90d / Lake: 365d | Tracks policy violations that may indicate security drift. | Compliance audit trail — proves which resources were non-compliant, when policy was bypassed, and whether exemptions were created to circumvent controls | Non-compliant resource deployed bypassing policy |
| **AzureActivity** | Autoscale | Autoscale engine events | Analytics: 90d / Lake: 365d | Can indicate unusual resource consumption patterns potentially triggered by an attacker. | Detect resource abuse — abnormal autoscale events may indicate crypto-mining or other compute abuse triggering scale-out | Unexpected autoscale triggered by resource abuse |
| **AzureActivity** | ResourceHealth | Resource health status changes | Analytics: 90d / Lake: 365d | Operational context for resource availability investigations. | Timeline correlation — resource health degradation events help establish whether an attacker impacted availability | Resource health degradation correlated with attack activity |

---

## Example Detections

### Resource-Based

| Detection | Operation(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:-------------|:-------------|:-------------------|:------------|
| Crypto-mining VM deployment | Microsoft.Compute/virtualMachines/write | [T1496](https://attack.mitre.org/techniques/T1496/) | [DET0267](https://attack.mitre.org/detectionstrategies/DET0267/) — Resource Hijacking | Creation of GPU-optimised or high-CPU VMs in unusual regions or resource groups |
| Resource group deletion | Microsoft.Resources/subscriptions/resourceGroups/delete | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Mass deletion of resource groups — potential sabotage or destructive attack |
| Storage account public access enabled | Microsoft.Storage/storageAccounts/write | [T1530](https://attack.mitre.org/techniques/T1530/) | [DET0484](https://attack.mitre.org/detectionstrategies/DET0484/) — Cloud Storage Exfiltration | Storage account configured with public blob/container access |
| Network Security Group rule modified | Microsoft.Network/networkSecurityGroups/securityRules/write | [T1562.007](https://attack.mitre.org/techniques/T1562/007/) *(revoked &rarr; [T1686.001](https://attack.mitre.org/techniques/T1686/001/))* | [DET0424](https://attack.mitre.org/detectionstrategies/DET0424/) — Modify Cloud Firewall | NSG rules opened to allow inbound traffic from any source (0.0.0.0/0) |
| Virtual Network modification | Microsoft.Network/virtualNetworks/write | [T1599](https://attack.mitre.org/techniques/T1599/) | [DET0006](https://attack.mitre.org/detectionstrategies/DET0006/) — Network Boundary Bridging | Unauthorized changes to network topology (peering, subnets) |

### Identity / RBAC

| Detection | Operation(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:-------------|:-------------|:-------------------|:------------|
| Owner/Contributor role assigned | Microsoft.Authorization/roleAssignments/write | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | [DET0531](https://attack.mitre.org/detectionstrategies/DET0531/) — Additional Cloud Credentials | Privilege escalation via RBAC — assigning Owner or Contributor role at subscription level |
| Custom role created with elevated permissions | Microsoft.Authorization/roleDefinitions/write | [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) — Account Manipulation | Creation of custom roles that include wildcard (*) actions |
| Diagnostic settings deleted | Microsoft.Insights/diagnosticSettings/delete | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) *(revoked &rarr; [T1685.002](https://attack.mitre.org/techniques/T1685/002/))* | [DET0289](https://attack.mitre.org/detectionstrategies/DET0289/) — Disable or Modify Cloud Log | Attacker disabling logging to cover tracks — anti-forensic activity |
| Policy exemption created | Microsoft.Authorization/policyExemptions/write | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) *(revoked &rarr; [T1685](https://attack.mitre.org/techniques/T1685/))* | [DET0497](https://attack.mitre.org/detectionstrategies/DET0497/) — Defense Impairment | Exempting resources from security policies to bypass controls |

### Key Vault

| Detection | Operation(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:-------------|:-------------|:-------------------|:------------|
| Key Vault access policy modified | Microsoft.KeyVault/vaults/write | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | [DET0549](https://attack.mitre.org/detectionstrategies/DET0549/) — Private Key Access | Unauthorized changes to Key Vault access policies — potential secret exfiltration setup |
| Key Vault deleted / purged | Microsoft.KeyVault/vaults/delete | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Deletion of key vaults containing cryptographic keys or secrets |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1496](https://attack.mitre.org/techniques/T1496/) | [DET0267](https://attack.mitre.org/detectionstrategies/DET0267/) &mdash; Resource Hijacking Detection Strategy |
| [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) &mdash; Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns |
| [T1530](https://attack.mitre.org/techniques/T1530/) | [DET0484](https://attack.mitre.org/detectionstrategies/DET0484/) &mdash; Multi-Platform Cloud Storage Exfiltration Behavior Chain |
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) *(revoked &rarr; [T1686.001](https://attack.mitre.org/techniques/T1686/001/))* | [DET0424](https://attack.mitre.org/detectionstrategies/DET0424/) &mdash; Detection Strategy for Disable or Modify Cloud Firewall |
| [T1599](https://attack.mitre.org/techniques/T1599/) | [DET0006](https://attack.mitre.org/detectionstrategies/DET0006/) &mdash; Detection Strategy for Network Boundary Bridging |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | [DET0531](https://attack.mitre.org/detectionstrategies/DET0531/) &mdash; Detection Strategy for Additional Cloud Credentials in IaaS/IdP/SaaS |
| [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) &mdash; Account Manipulation Behavior Chain Detection |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) *(revoked &rarr; [T1685.002](https://attack.mitre.org/techniques/T1685/002/))* | [DET0289](https://attack.mitre.org/detectionstrategies/DET0289/) &mdash; Detection Strategy for Disable or Modify Cloud Log |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) *(revoked &rarr; [T1685](https://attack.mitre.org/techniques/T1685/))* | [DET0497](https://attack.mitre.org/detectionstrategies/DET0497/) &mdash; Detection of Defense Impairment through Disabled or Modified Tools across OS Platforms. |
| [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | [DET0549](https://attack.mitre.org/detectionstrategies/DET0549/) &mdash; Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms |

> [!NOTE]
> This page intentionally omits the third MITRE-evidence column. For cloud platform-family strategies, MITRE may cite provider-specific source names that do not map 1:1 to `AzureActivity`; keeping this section as Technique + Detection Strategy avoids a brittle translation layer.

> [!NOTE]
> **MITRE legacy technique IDs.** Some technique IDs cited on this page are *legacy* IDs that MITRE has revoked and remapped: T1562.007 &rarr; T1686.001; T1562.008 &rarr; T1685.002; T1562.001 &rarr; T1685. Published Detection Strategies are attached to the current technique IDs only; the table above follows the `revoked-by` chain so each strategy still applies to the legacy ID cited above.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **AM-2** Use only approved services | Activity logs detect deployment of unapproved resource types |
| **LT-1** Enable threat detection | Platform-level threat detection for Azure resource abuse |
| **LT-3** Enable logging for security investigation | Activity logs are the primary audit trail for Azure control plane operations |
| **LT-6** Configure log storage retention | Azure retains activity logs for 90 days natively — Sentinel extends this |
| **PA-7** Follow just enough administration | RBAC assignment tracking ensures least-privilege adherence |
| **GS-3** Align roles and responsibilities | Policy events track security governance compliance |
| **IR-4** Detection and analysis | Activity logs are critical for investigating Azure-based incidents |

> [!NOTE]
> **Other framework alignment:** This data supports NIST SP 800-53 AU-2 (audit events) and AC-6 (least privilege), CIS Controls v8 8.2 (collect audit logs), and ASD ACSC cloud logging priority #4 (administrative configuration changes) and #7 (cloud service logs).

---

## Important Considerations

### Log Categories to Enable

Enable **all categories** via the diagnostic settings:

| Category | Priority | Rationale |
|:---------|:---------|:----------|
| Administrative | **Critical** | All resource CRUD operations |
| Security | High | Defender for Cloud alerts at platform level |
| Policy | High | Compliance drift detection |
| ServiceHealth | Medium | Operational context |
| Alert | Medium | Azure Monitor alert correlation |
| Autoscale | Low | Resource consumption anomalies |
| ResourceHealth | Low | Availability context |

### Deployment

> [!WARNING]
> Connect **every Azure subscription** to Sentinel via diagnostic settings. Attackers frequently target development or sandbox subscriptions that have weaker monitoring.

Use Azure Policy to **enforce** diagnostic settings across all subscriptions:

```
Microsoft.Insights/diagnosticSettings — deployIfNotExists
```

This ensures new subscriptions are automatically connected to your Sentinel workspace.

> [!TIP]
> To verify coverage after deployment, run the community [Azure Activity Log Sentinel Audit](https://github.com/mathijsvermaat/azure-activity-log-sentinel-audit) script. It compares the list of subscriptions you can read against AzureActivity ingestion in the workspace and flags any subscription not sending logs.

---

## Notes

- Azure natively retains activity logs for **90 days** — Sentinel extends this to your configured retention period
- Activity logs cover the **control plane** only — for data plane operations (e.g., blob access, SQL queries), you need resource-specific diagnostic logs (Tier 2+)
- Consider combining with **Azure Resource Graph** snapshots for point-in-time infrastructure state during investigations
- High-value operations to watchlist: role assignments at subscription/management group scope, diagnostic settings changes, policy exemptions

---

## Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor AzureActivity ingestion volumes and retention | Sentinel Content Hub | [Walkthrough](../procedures/workspace-usage-report.md) |
| **Azure Activity** | Solution | 2 workbooks (Azure Activity, Azure Service Health), 14 analytic rules, 15 hunting queries — covers suspicious resource deployments, role assignments, and service health events | Sentinel Content Hub | — |
| **Azure Activity Log Sentinel Audit** | PowerShell script | Enumerates every Azure subscription the caller can read and compares it against AzureActivity ingestion in the workspace — surfaces subscriptions missing diagnostic settings so no control-plane blind spots go unnoticed | Community (Mathijs Vermaat) | [github.com/mathijsvermaat/azure-activity-log-sentinel-audit](https://github.com/mathijsvermaat/azure-activity-log-sentinel-audit) |

---

## References

### Official Documentation

| Title | Description | Link |
|:------|:------------|:-----|
| Connect Azure Activity to Microsoft Sentinel | Connector setup guide — diagnostic settings for Azure management plane events | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/azure-activity) |
| Azure Activity log event schema | Schema reference for all Azure Activity log categories | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema) |
| Create diagnostic settings at scale with built-in Azure Policy | Built-in policies to enforce diagnostic settings on resources across a subscription or management group — list of supported resource types and example deployment | [learn.microsoft.com](https://learn.microsoft.com/azure/azure-monitor/platform/diagnostic-settings-policy-built-in) |

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — configure subscription-level Activity log diagnostic settings (`Subscriptions → Activity log → Export Activity Logs`) and use Azure Policy to deploy the diagnostic setting at scale.
  - Quick links via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azsubs.cmd.ms`](https://azsubs.cmd.ms/) (Subscriptions), [`azmonitor.cmd.ms`](https://azmonitor.cmd.ms/) (Monitor), [`azpolicy.cmd.ms`](https://azpolicy.cmd.ms/) (Azure Policy).

### Community & Third-Party Resources

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| Sentinel Ninja — Azure Activity connector | Ofer Shezaf (Microsoft) | Auto-generated reference: tables ingested, related solutions, and content items | [github.com](https://github.com/oshezaf/sentinelninja/blob/main/Solutions%20Docs/connectors/azureactivity.md) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
