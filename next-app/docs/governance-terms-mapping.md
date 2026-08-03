# Integrated 18‑Point Glossary → Phase Mapping

This table anchors each concept to: phase, artefacts, risk hooks, roles, dependencies, and notes. Use alongside docs/roadmap.md.

| # | Term | Phase | Artefacts | Risk Hooks | Roles | Dependencies | Notes |
| - | ---- | ----- | --------- | ---------- | ----- | ------------ | ----- |
| 1 | Framework | 1 | Architecture docs, standards charter | Vendor lock‑in check | Architects, Standards | → Model, System | Validate enterprise fit |
| 2 | Architecture | 1 | System diagrams, dependency maps | Scalability & vuln scans | Architects, Security | All | Ensure adaptive access |
| 3 | Dataset | 1 | Governance policy, audit trails | Contamination detection | Data Gov, Legal | → Model, Metrics | Privacy by design |
| 4 | Model | 2 | Review board records, training logs | Drift detection | ML Eng, Ethics | Framework, Dataset | Thresholds trigger reviews |
| 5 | Algorithm | 2 | Ethics panel reviews | Fairness monitoring | Ethics, Auditors | Model | Baseline fairness & cycles |
| 6 | Pipeline | 2 | Dashboards, audit trails | Failure recovery | DevOps, SRE | Dataset→Model | Escalation on fail |
| 7 | System | 3 | Integration board docs | Rollback procedures | Integration, Arch | 1–2 | Gate before deploy |
| 8 | Agent | 3 | Behavior logs, autonomy limits | Anomaly detection | Oversight, Auditors | 4–6 | Enforce boundaries |
| 9 | Environment | 3 | Safety assessments | Boundary monitoring | Safety, Ops | Agent | Pre‑defined protocols |
|10 | Interface | 3 | Accessibility & UX records | Access control checks | UX, A11y | System | Transparency by default |
|11 | Module | 3 | Integration docs | Isolation & impact checks | Module Arch | All | Define clear contracts |
|12 | Controller | 4 | Oversight logs | Authority validation | Oversight | Agent, Policy | Escalation paths |
|13 | Policy | 4 | Compliance monitoring | Constraint enforcement | Policy, Compliance | Agent, Controller | Adaptive policies |
|14 | Knowledge Base | 4 | Accuracy validation | Integrity checks | Info Arch | Memory | Build from ops history |
|15 | Memory | 4 | Retention docs | Corruption detection | Mgmt Board | Knowledge Base | Audit continuously |
|16 | Reward Function | 4 | Alignment validation | Reward hacking detection | Alignment | Agent | Sandbox validation |
|17 | Evaluation Metrics | 4 | Benchmarks | Manipulation detection | Validation | All | Prevent gaming |
|18 | Safety Layer | 4 | Incident logs | Escalation & enforcement | Safety | All | Rapid response integration |
