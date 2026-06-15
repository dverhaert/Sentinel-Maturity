# Azure Kubernetes Service (AKS) Audit

**Tier:** 3 (Advanced) · **Connector type:** Microsoft first-party (Diagnostic Settings) · **Free ingestion:** No (paid ingestion)

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

AKS audit logs capture **Kubernetes API server operations**: pod creation, deployment changes, RBAC modifications, secrets access, and namespace management. For organisations running containerised workloads on AKS, these logs are essential for detecting container escape, lateral movement within the cluster, privilege escalation through RBAC, and supply chain attacks via malicious container images.

While Azure Activity Logs (Tier 1) capture AKS cluster-level operations (create, delete, scale), the Kubernetes audit logs capture the *data plane* — what's happening **inside** the cluster. Defender for Containers (Tier 2, via Defender for Cloud) provides alerts; these audit logs provide the detailed investigation trail.

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
| **AKSAudit** | Kubernetes API server audit events (resource-specific mode) — create, update, delete operations for all Kubernetes resources | Analytics: 90d / Lake: 365d | Primary Kubernetes security audit trail — captures all cluster operations including RBAC changes, secret access, and workload modifications | Reconstructs attacker actions within the Kubernetes cluster — which pods were created, what secrets were accessed, what RBAC changes were made | Privileged pod created in default namespace |
| **AKSAuditAdmin** | Filtered view of AKS audit events — excludes read-only (GET/LIST) operations, reducing volume significantly | Analytics: 90d / Lake: 365d | Same security value as full audit with dramatically reduced volume — ideal for most security monitoring use cases | Same forensic value for write operations — all mutations are captured | ClusterRoleBinding created granting cluster-admin |
| **AKSControlPlane** | AKS control plane component logs — API server, controller manager, scheduler, admission webhooks | Analytics: 30d / Lake: 180d | Operational health and debugging data for the control plane — less security-focused but valuable for troubleshooting | Identifies control plane issues that may indicate compromise — failed admission webhooks, scheduler anomalies | API server admission webhook disabled |

---

## Example Detections

| Detection | Table(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:---------|:-------------|:-------------------|:------------|
| Privileged container created | AKSAudit, AKSAuditAdmin | [T1610](https://attack.mitre.org/techniques/T1610/) | [DET0249](https://attack.mitre.org/detectionstrategies/DET0249/) — Deploy Container | Pod created with privileged security context or host namespace access — potential container escape |
| Secret accessed from unusual pod | AKSAudit | [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | [DET0198](https://attack.mitre.org/detectionstrategies/DET0198/) — Container API Credential Access | Kubernetes Secret read by a pod that doesn't normally access secrets |
| ClusterRole or ClusterRoleBinding modified | AKSAuditAdmin | [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) — Account Manipulation | RBAC escalation — new ClusterRoleBinding granting cluster-admin or broad permissions |
| Container image from untrusted registry | AKSAudit | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | [DET0309](https://attack.mitre.org/detectionstrategies/DET0309/) — Compromise Software Supply Chain | Pod created with a container image from an unapproved registry — supply chain risk |
| Exec into running container | AKSAudit | [T1609](https://attack.mitre.org/techniques/T1609/) | [DET0065](https://attack.mitre.org/detectionstrategies/DET0065/) — Container Administration Command | `kubectl exec` into a running container — interactive shell access to a workload |
| Namespace deletion | AKSAuditAdmin | [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) — Data Destruction | Kubernetes namespace deleted — could indicate destructive attack or cleanup after compromise |
| Admission webhook disabled | AKSControlPlane | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) *(revoked &rarr; [T1685](https://attack.mitre.org/techniques/T1685/))* | [DET0497](https://attack.mitre.org/detectionstrategies/DET0497/) — Defense Impairment | API server admission webhook disabled or patched |

---

## MITRE Detection Strategies

Curated list of MITRE [Detection Strategies](https://attack.mitre.org/detectionstrategies/) relevant to the techniques referenced on this page.

| Technique | Detection Strategy |
|:----------|:-------------------|
| [T1610](https://attack.mitre.org/techniques/T1610/) | [DET0249](https://attack.mitre.org/detectionstrategies/DET0249/) &mdash; Behavior-chain detection for T1610 Deploy Container across Docker & Kubernetes control/node planes |
| [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | [DET0198](https://attack.mitre.org/detectionstrategies/DET0198/) &mdash; Detect Abuse of Container APIs for Credential Access |
| [T1098](https://attack.mitre.org/techniques/T1098/) | [DET0096](https://attack.mitre.org/detectionstrategies/DET0096/) &mdash; Account Manipulation Behavior Chain Detection |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | [DET0309](https://attack.mitre.org/detectionstrategies/DET0309/) &mdash; Compromised software/update chain (installer/write → first-run/child → egress/signature anomaly) |
| [T1609](https://attack.mitre.org/techniques/T1609/) | [DET0065](https://attack.mitre.org/detectionstrategies/DET0065/) &mdash; Detection Strategy for Container Administration Command Abuse |
| [T1485](https://attack.mitre.org/techniques/T1485/) | [DET0146](https://attack.mitre.org/detectionstrategies/DET0146/) &mdash; Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) *(revoked &rarr; [T1685](https://attack.mitre.org/techniques/T1685/))* | [DET0497](https://attack.mitre.org/detectionstrategies/DET0497/) &mdash; Detection of Defense Impairment through Disabled or Modified Tools across OS Platforms. |

> [!NOTE]
> This page intentionally omits the third MITRE-evidence column. For broad platform-family strategies, MITRE may cite runtime- or orchestrator-specific source names that do not map 1:1 to AKS tables; keeping this section as Technique + Detection Strategy avoids a brittle translation layer.

> [!NOTE]
> **MITRE legacy technique IDs.** Some technique IDs cited on this page are *legacy* IDs that MITRE has revoked and remapped: T1562.001 &rarr; T1685. Published Detection Strategies are attached to the current technique IDs only; the table above follows the `revoked-by` chain so each strategy still applies to the legacy ID cited above.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they tell you **what** to correlate across data sources. Use them to validate that your Sentinel analytic rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **LT-1** Enable threat detection capabilities | AKS audit logs enable Kubernetes-specific threat detection for container workloads |
| **LT-3** Enable logging for security investigation | Kubernetes audit trail is essential for investigating container compromise and lateral movement |
| **NS-2** Secure cloud services with network controls | Monitors network policy changes within the Kubernetes cluster |
| **CT-1** Manage image vulnerabilities | Monitors which container images are deployed — detects untrusted or vulnerable images |

---

## Important Considerations

- **Use kube-audit-admin:** The `kube-audit-admin` diagnostic category excludes GET/LIST operations, reducing volume by ~80% while retaining all security-relevant (create/update/delete) events
- **Resource-specific mode:** Enable resource-specific mode in diagnostic settings to use the dedicated `AKSAudit` / `AKSAuditAdmin` tables instead of the generic `AzureDiagnostics` table
- **Legacy mode still exists:** Some clusters still send AKS categories to `AzureDiagnostics`. Treat this as a valid legacy path, but prefer resource-specific mode for cleaner schema and table-level planning
- **Container Insights is supplemental:** `ContainerInventory` and `KubeEvents` provide operational/container telemetry and complement (but do not replace) AKS audit and control-plane security logs
- **Volume management:** Active clusters with many workloads can generate significant audit volume. Consider filtering by namespace in DCR transformations
- **Defender for Containers:** If you have Defender for Cloud (Tier 2), container threat detection alerts already flow through `SecurityAlert`. The audit logs in this Tier 3 connector add the detailed investigation trail

---

## Notes

- AKS audit logs are essential for organisations running production workloads on Kubernetes — container escape and lateral movement within clusters are increasingly common attack patterns
- Pair with VNet Flow Logs (Tier 2) for network-level visibility alongside Kubernetes-level audit data
- The Defender for Containers runtime sensor provides complementary telemetry — process-level events within containers

### Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| [Workspace Usage Report](../procedures/workspace-usage-report.md) | Workbook | Verify AKS audit log volumes and ingestion | Sentinel Maturity Model | [Procedure guide](../procedures/workspace-usage-report.md) |

---

## References

| Source | Link |
|:-------|:-----|
| AKS monitoring with diagnostics | [Learn](https://learn.microsoft.com/en-us/azure/aks/monitor-aks) |
| AKS diagnostic settings categories | [Learn](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference) |
| Enable control plane logs on an AKS cluster | [Learn](https://learn.microsoft.com/azure/azure-monitor/containers/kubernetes-monitoring-enable#enable-control-plane-logs-on-an-aks-cluster) |
| Defender for Containers overview | [Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction) |
| Kubernetes threat matrix (MITRE) | [Microsoft](https://www.microsoft.com/en-us/security/blog/2020/04/02/attack-matrix-kubernetes/) |

---

### Admin portal

- [Microsoft Azure portal](https://portal.azure.com/) — enable AKS diagnostic settings (use **resource-specific** mode for `AKSAudit` / `AKSAuditAdmin`, not legacy `AzureDiagnostics`).
  - Quick link via [cmd.ms](https://cmd.ms/) (see [References §14.6](../references.md#14-admin-portals)): [`azaks.cmd.ms`](https://azaks.cmd.ms/) (Kubernetes services).

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
