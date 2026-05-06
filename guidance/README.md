# Guidance

This section provides the strategic rationale and design principles behind the Sentinel Maturity Model. Before diving into specific data connectors and tables, it is important to understand **why** certain logging decisions are made and what drives retention, prioritisation, and cost trade-offs.

> [!TIP]
> The guidance below is the **rationale layer** behind the [Sentinel Maturity Model](../README.md) and the interactive [Assessment Checklist](https://mathijsvermaat.github.io/sentinel-maturity-assessment.html). The maturity model defines *what* to ingest per tier, the assessment tracks *how far* an organisation has implemented it, and this guidance explains *why* each decision is made — risk, retention, cost, and compliance. Read the topic that matches the question you are trying to answer; every page ties back to the connector pages and the assessment checks they cover.

---

## Topics

| Topic | Description |
|:------|:------------|
| [Risk Considerations](risk-considerations.md) | Why there is no one-size-fits-all logging configuration and how to apply a risk-based approach to data source selection |
| [Input/Output Strategy](input-output-strategy.md) | Gartner's SIEM input/output strategy — tiering telemetry for cost-effective, high-value security operations |
| [Forensic Readiness](forensic-readiness.md) | Designing logging and retention for incident investigation from day one, including why centralised logging is critical |
| [Layered Detection Approach](layered-detection.md) | Why EDR alone is not sufficient and how combining EDR with SIEM-based logging provides defence in depth |
| [Frameworks and Compliance](frameworks-and-compliance.md) | Relevant security frameworks (MCSB, SFI) and regulatory requirements (NIS2) that inform logging decisions |
| [Budget and Cost Planning](budget-and-cost-planning.md) | How to plan and sustain SOC data collection budgets, including Microsoft Sentinel pricing considerations |
| [Retention](retention.md) | Industry best practices for log retention periods — MCSB, NIST, CIS, NIS2, and GDPR mapped to Microsoft Sentinel storage tiers |

---

[← Back to Sentinel Maturity Model](../README.md)
