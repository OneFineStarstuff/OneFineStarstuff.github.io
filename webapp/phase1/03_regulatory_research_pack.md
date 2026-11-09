# 03 — Regulatory Research Pack

One-pagers for the six priority real-world regimes and the fictional treaty layer. Each real-regime page follows the same contract: scope, key obligations, the evidence the application must display, and the crosswalk seed controls. Summaries are informational, not legal advice; the timing-sensitive entries cite current sources.

---

## EU AI Act (Reg. (EU) 2024/1689)

**Scope:** Prohibited-practice, high-risk, GPAI/model, and transparency obligations for AI systems placed or used in the EU; extraterritorial reach via the market-access principle.
**Timing note:** The Digital Omnibus package has deferred key high-risk application deadlines into December 2026–August 2028 ([FPF — AI Act implementation timeline](https://fpf.org/blog/the-ai-act-implementation-timeline-what-changes-under-the-ai-omnibus/), [Orrick — Digital Omnibus finalizes 8 compliance changes](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes), [Cooley — Digital AI Omnibus delays key deadlines](https://cdp.cooley.com/digital-ai-omnibus-delays-key-deadlines-introduces-new-rules/)). Track Article 6 classification and the Annex III list per the omnibus revisions.
**App must display:** risk classification per system, technical documentation and logging readiness, human-oversight evidence, conformity/registration status, post-market monitoring plan.
**Seed controls:** GOV-01 (accountability), RISK-01 (classification), AUDIT-01 (logging/traceability), HUMAN-01 (oversight).

## NIST AI RMF 1.0 (+ AI 600-1 profile)

**Scope:** Voluntary framework: GOVERN, MAP, MEASURE, MANAGE functions; the Generative AI Profile (NIST AI 600-1) adds GAI-specific practices (training-data transparency, incident reporting, harmful-content controls).
**App must display:** function-mapped control coverage, measurement results (fairness, robustness), RMF profile alignment, gap register.
**Seed controls:** GOV-02, MEAS-01 (fairness measurement), MEAS-02 (telemetry), MANAGE-01 (incident response).

## ISO/IEC 42001:2023

**Scope:** AI management system (AIMS) requirements + Annex A controls; certifiable; the natural certifiable backbone for institutions that need a management-system story across regimes.
**App must display:** AIMS clause coverage, Annex A control mapping, internal-audit and continual-improvement records.
**Seed controls:** GOV-03 (AIMS), COMP-01 (crosswalk), AUDIT-02 (internal audit).

## GDPR

**Scope:** Art. 22 automated decision-making, Art. 35 DPIA linkage, transparency and data-subject rights where governance telemetry or model decisions process personal data.
**App must display:** DPIA references per high-risk use, Art. 22 safeguards, retention rules for telemetry (align with WORM ledger retention markers).
**Seed controls:** PRIV-01 (DPIA linkage), PRIV-02 (retention), HUMAN-02 (contestation rights).

## Basel III/IV (+ SR 11-7-style model risk)

**Scope:** Operational-risk governance for AI systems used in decisioning; model risk management expectations in the SR 11-7 tradition (development, validation, independent review, ongoing monitoring).
**App must display:** model inventory and validation status, effective challenge records, ongoing-monitoring telemetry, escalation thresholds.
**Seed controls:** MODEL-01 (inventory), MODEL-02 (independent validation), RISK-02 (ongoing monitoring).

## DORA (Reg. (EU) 2022/2554)

**Scope:** ICT risk management, incident reporting, resilience testing (TLPT), and third-party oversight for EU financial entities; applies since January 2025 ([Mitratech — What is DORA](https://mitratech.com/resource-hub/blog/what-is-dora/)).
**App must display:** ICT incident register linkage, resilience-test results, third-party register with concentration indicators, oversight-contract evidence.
**Seed controls:** RESIL-01 (resilience testing), INC-01 (incident reporting), THIRD-01 (third-party oversight).

---

## Fictional treaty layer (simulation — always labelled)

| Instrument | Role in the simulation |
| --- | --- |
| CFE-1.0 | Constitutional framework encoding treaty-grade invariants; verified by the TLA+ suite (rev. per window) |
| Protocol SGR-028 | Standing verification-key regime over constitutional proofs |
| Interstellar AI Governance Accord | Multi-stakeholder accord driving the supervisory-college choreography |
| Galactic Treaty Framework | Phase VII readiness instrument (G-SRI-VII band) |
| GIEN Phase VI-δ → Phase VII → Ω-GAR | Phase ladder: planetary supervision → galactic readiness → Omega-GAR long-horizon stewardship (epochs 2026–2035, 2035–2100+; CESI/UCSI/UCI/CDS/Infinity Pillar) |

**Rule:** treaty-layer controls appear in the same crosswalk matrix but are tagged `"layer": "simulation"`, so exports can filter real-only, simulation-only, or combined views per audience.

---

## Regime-priority guidance for the MVP

1. **EU AI Act + DORA** — timing-sensitive, financial-institution-relevant; build first.
2. **ISO/IEC 42001 + NIST AI RMF** — certifiable backbone and measurement vocabulary; build second.
3. **GDPR + Basel III/IV (SR 11-7 tradition)** — linkage and model-risk evidence; build third.
4. Treaty layer ships in parallel, tagged, as the simulation differentiator.

*Real-framework summaries are informational and not legal advice. The treaty layer is a fictional governance simulation.*
