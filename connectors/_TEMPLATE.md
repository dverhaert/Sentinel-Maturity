# [Connector Name]

**Tier:** [1/2/3] · **Connector type:** [Microsoft first-party / Third-party] · **Free ingestion:** [Yes/No — details]

---

## Overview

[Brief description of the connector, what data it provides, and why it matters for security monitoring.]

### Licensing Benefits

| License | What it unlocks |
|:--------|:----------------|
| **[License name]** | [What tables/features become available] |
| **[License name]** | [What tables/features become available] |

> [!NOTE]
> [Key licensing or cost note — e.g., free data source, E5 data grant, P2 ingestion benefit.]

---

## Tables and Rationale

<!-- 
  Use H3 subsections to group tables by category if the connector has many tables.
  Example: ### Authentication Tables, ### Alert Tables, etc.
  For connectors with few tables (e.g., Office 365, Azure Activity), a single table is fine.
  
  Every table row MUST include an Example Detection column.
-->

### [Table Category Name] (optional grouping)

| Table | Description | Retention Recommendation | Rationale | Forensic Value | Example Detection |
|:------|:------------|:------------------------|:----------|:---------------|:------------------|
| **[TableName]** | [What data this table contains] | Analytics: 90d / Lake: 365d | [Why this data matters — reference MCSB controls, forensic readiness, MITRE ATT&CK coverage] | [What this data proves during an investigation — describe how it supports incident response and forensic analysis] | [Specific detection example with MITRE technique ID] |
| **[TableName]** | [What data this table contains] | Analytics: 90d / Lake: 365d | [Rationale] | [Forensic value] | [Detection example] |

---

## Example Detections

<!--
  Detailed detection rules beyond the one-liner in the table.
  Use H3 subsections to group by category if needed.
  Example: ### Authentication-Based, ### Endpoint, ### Email, etc.

  Each row should include the **MITRE ATT&CK technique** and, where available,
  the matching **MITRE Detection Strategy** (DET####). See the section below.
-->

### [Detection Category]

| Detection | Table(s) / Event ID(s) | MITRE ATT&CK | Detection Strategy | Description |
|:----------|:-----------------------|:-------------|:-------------------|:------------|
| [Detection name] | [Table or Event ID] | [Txxxx.xxx](https://attack.mitre.org/techniques/Txxxx/xxx/) | [DET####](https://attack.mitre.org/detectionstrategies/DET####/) — [Strategy name] | [What this detection catches and how] |
| [Detection name] | [Table or Event ID] | [Txxxx.xxx](https://attack.mitre.org/techniques/Txxxx/xxx/) | — *(no published strategy)* | [Description] |

---

## MITRE Detection Strategies

<!--
  Curated list of MITRE Detection Strategies (https://attack.mitre.org/detectionstrategies/)
  relevant to the techniques referenced on this page. Each strategy publishes
  pseudo-code analytics keyed to ATT&CK data sources — use them as a blueprint
  for writing or reviewing Sentinel analytic rules against this connector's
  table(s).

  IMPORTANT — legacy / revoked technique IDs:
  MITRE periodically revokes technique IDs and reorganises them under new IDs
  (e.g. in April 2026 T1070.001, T1562, T1562.002, T1562.004 were revoked and
  moved into the T1685 / T1686 family). Published Detection Strategies are only
  attached to the *current* technique IDs. When building this section:

    1. For each technique cited on the page, look it up in the MITRE STIX
       enterprise-attack bundle.
    2. If the technique has `revoked = true`, follow the `revoked-by`
       relationship to the current technique and look up the strategy under
       that current ID.
    3. Show the legacy ID in the first column with "*(revoked → Txxxx.xxx)*"
       so the reader can still match it against connector docs / Sentinel
       rules that cite the legacy ID.
    4. Only include the "no published strategy" note for techniques where
       neither the legacy nor the current (post-revoked-by) technique has a
       Detection Strategy.

  The mapping CSV (`tech_to_det_v2.csv` in C:\Temp) already follows
  `revoked-by` chains. Use it as the source of truth.
-->

| Technique | Detection Strategy | Relevant Event IDs / Tables |
|:----------|:-------------------|:----------------------------|
| [Txxxx.xxx](https://attack.mitre.org/techniques/Txxxx/xxx/) — [Name] | [DET####](https://attack.mitre.org/detectionstrategies/DET####/) — [Strategy name] | [Event IDs or tables on this page that map to this strategy] |
| [Txxxx.xxx](https://attack.mitre.org/techniques/Txxxx/xxx/) — [Name] *(revoked → [Tyyyy.yyy](https://attack.mitre.org/techniques/Tyyyy/yyy/))* | [DET####](https://attack.mitre.org/detectionstrategies/DET####/) — [Strategy name] | [Event IDs or tables] |

> [!NOTE]
> *(Include only if the page cites any revoked techniques)* **MITRE legacy technique IDs.** Some technique IDs cited on this page are *legacy* IDs that MITRE later revoked and moved to a new family. Detection Strategies are attached to the current technique IDs — the parenthetical *(revoked → Txxxx.xxx)* in each row shows the current ID. Pages may continue to cite legacy IDs because that is what Microsoft Sentinel docs and built-in analytic rules still reference.

> [!TIP]
> Detection Strategies are MITRE-published *pseudo-code analytics*, not vendor rules — they describe **what** to correlate across data sources. Use them to validate that your Sentinel analytics rules and KQL hunting queries cover the published correlation logic.

---

## MCSB Control Mapping

| MCSB Control | Relevance |
|:-------------|:----------|
| **[XX-N]** [Control name] | [How this connector's data supports this control] |
| **[XX-N]** [Control name] | [Relevance] |

---

<!--
  OPTIONAL SECTIONS — Add any of the below between MCSB Control Mapping and Notes 
  if relevant for this connector:
  
  ## [Connector-specific comparison]
     Example: "## OfficeActivity vs CloudAppEvents" (Office 365 page)
  
  ## Important Considerations
     Example: Log categories to enable, deployment guidance (Azure Activity page)
  
  ## Recommended Configuration
     Example: Audit policy GPO, DCR facility settings (Windows Security Events, Syslog pages)
  
  ## Key Events to Monitor
     Example: Specific log patterns to watch for (Syslog page)
-->

## Notes

- [Key operational note — e.g., migration guidance, configuration tips]
- [Additional note]
- [Additional note]

<!--
  OPTIONAL: Add "### Why Layered Logging Matters" subsection for connectors 
  where native OS logging complements EDR (Windows Security Events, Syslog).
  Include 2-3 blog/article references in a table.
-->

### Tools

| Tool | Type | Purpose | Source | Guide |
|:-----|:-----|:--------|:-------|:------|
| **Workspace Usage Report** | Workbook | Monitor ingestion volumes for this connector's tables | [Sentinel Content Hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-content-hub) | [Walkthrough](../procedures/workspace-usage-report.md) |
| **[Additional tool]** | [Workbook / Script / ...] | [Purpose] | [Source link] | [Walkthrough](../procedures/[guide].md) |

---

## References

Community and third-party resources that support the guidance on this page.

<!--
  Add community blog posts, third-party articles, and other external resources
  that underpin the advice on this page. Use the table format below.
-->

| Title | Author | Description | Link |
|:------|:-------|:------------|:-----|
| [Blog/article title] | [Author name] | [Brief description of relevance to this connector] | [Source](https://example.com) |

[← Back to Connectors](README.md) · [← Back to Sentinel Maturity Model](../README.md)
