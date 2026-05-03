#!/usr/bin/env python3
"""
WP-039 — Institutional-Grade AGI/ASI & Enterprise AI Governance Master Blueprint (2026-2030)

Synthesizes WP-035 (ENT-AGI-GOV-MASTER), WP-036 (WFAP-GEMINI-IMPL),
WP-037 (GSIFI-AIMS-BLUEPRINT), and WP-038 (AGI-REG-RESILIENT) into a single
regulator-ready master blueprint for Fortune 500 / Global 2000 / G-SIFI firms.

Outputs: data/inst-agi-master.json  (idempotent)
"""
import json
import os
from pathlib import Path

OUT = Path(__file__).parent / "data" / "inst-agi-master.json"
DOC_REF = "INST-AGI-MASTER-WP-039"
VERSION = "1.0.0"
HORIZON = "2026-2030"


def meta():
    return {
        "docRef": DOC_REF,
        "version": VERSION,
        "date": "2026-05-03",
        "title": "Institutional-Grade AGI/ASI & Enterprise AI Governance Master Blueprint",
        "subtitle": "Regulator-Ready Reference for Fortune 500 / Global 2000 / G-SIFI Institutions (2026-2030)",
        "classification": "CONFIDENTIAL — Board / Audit Committee / Prudential Supervisor / Treaty Authority",
        "owner": "Group CEO + Chief AI Officer (CAIO) — co-signed by CRO, CISO, GC, DPO, Head of Internal Audit",
        "audience": [
            "Board of Directors and Audit / Risk Committees",
            "C-Suite (CEO, CFO, CRO, CIO, CISO, CAIO, GC, DPO)",
            "Three Lines of Defense (Business, Risk & Compliance, Internal Audit)",
            "Prudential Supervisors (ECB SSM, Federal Reserve, PRA, FCA, MAS, HKMA)",
            "AI Safety Institutes (UK AISI, US AISI, EU AI Office, Singapore IMDA AI Verify)",
            "Treaty / Compute-Governance Authorities",
            "Enterprise Architects, AI/ML Engineers, MLOps SREs, Data Scientists",
        ],
        "horizon": HORIZON,
        "synthesizes": [
            "WP-035 ENT-AGI-GOV-MASTER (Enterprise AGI/ASI Governance Master Framework)",
            "WP-036 WFAP-GEMINI-IMPL (WorkflowAI Pro / GeminiService Implementation Plan)",
            "WP-037 GSIFI-AIMS-BLUEPRINT (ISO/IEC 42001 AIMS Blueprint for G-SIFIs)",
            "WP-038 AGI-REG-RESILIENT (Regulator-Resilient AGI/ASI Governance Architecture)",
        ],
        "regulatoryAlignment": [
            "EU AI Act (Reg. 2024/1689) — Arts 5, 6, 9, 10, 12-15, 17, 26-27, 49, 53, 55, 72, 73; Aug 2026 enforcement for High-Risk AI; Aug 2025 GPAI enforcement",
            "NIST AI RMF 1.0 (Govern/Map/Measure/Manage) + NIST AI 600-1 GenAI Profile",
            "ISO/IEC 42001:2023 (AIMS), ISO/IEC 23894:2023 (AI Risk), ISO/IEC 5338, ISO/IEC 27001/27701/27018",
            "OECD AI Principles (2019, updated 2024)",
            "GDPR/UK GDPR — Arts 5, 6, 9, 22, 25, 32-35",
            "US Federal — FCRA §604/§615, ECOA Reg B, FFIEC SR 11-7 / OCC 2011-12, CFPB Circulars",
            "Basel III/IV + BCBS 239 risk data aggregation",
            "PRA SS1/23 (Model Risk Management), PRA SS2/21 outsourcing & third-party risk",
            "FCA Consumer Duty (PS22/9), SMCR (SYSC, COCON)",
            "MAS FEAT Principles (Fairness, Ethics, Accountability, Transparency)",
            "HKMA Generative AI Guidance, HKMA SPM AI",
            "OWASP LLM Top 10 (2025), MITRE ATLAS, STRIDE, LINDDUN",
            "SOC 2 Type II, FedRAMP High, CSA STAR",
            "SLSA L3, in-toto, Sigstore/Cosign, Rekor transparency log",
        ],
        "subjectSystem": {
            "scope": "All AI/ML systems across the enterprise — discriminative, generative, agentic, frontier AGI",
            "scale": "Fortune 500 / Global 2000 / G-SIFI; >100k employees; >50 jurisdictions; >1M concurrent inferences",
            "deployment": "Multi-region active-active hybrid (sovereign-cloud variants for EU, UK, US-Gov, Singapore, Hong Kong)",
            "tenancy": "Pool-multi-tenant SaaS + silo-per-tenant + sovereign-cloud isolation",
            "platforms": [
                "Enterprise Model Registry (ISO/IEC 42001-aligned)",
                "WorkflowAI Pro / GeminiService gateway",
                "Governance Command Center (React, real-time risk telemetry)",
                "Kafka-based WORM audit pipeline (10-year retention)",
                "Docker Swarm + governance sidecars",
                "OPA/Rego policy engine (compliance-as-code)",
                "RAG with high-assurance grounding & faithfulness ≥0.92",
            ],
        },
        "deliverableInventory": {
            "modules": 14,
            "sections": 46,
            "schemas": 10,
            "codeExamples": 12,
            "caseStudies": 6,
            "apiRoutes": 95,
            "phases": 5,
            "kpis": 18,
            "controls": 320,
        },
    }


def executive_summary():
    return {
        "purpose": (
            "Deliver a single, board-approvable, regulator-ready master blueprint that synthesizes "
            "the enterprise AGI/ASI governance master framework (WP-035), the WorkflowAI Pro / "
            "GeminiService implementation plan (WP-036), the ISO/IEC 42001 AIMS blueprint for "
            "G-SIFIs (WP-037), and the regulator-resilient AGI/ASI governance architecture (WP-038) "
            "into one institutional-grade reference for 2026-2030."
        ),
        "scope": (
            "Covers all AI capabilities (discriminative, generative, agentic, frontier AGI/ASI), "
            "all institutional functions (board, executive, 3LoD, business lines, technology, "
            "data), all regulators (EU AI Act, NIST, ISO, OECD, GDPR, US FCRA/ECOA/SR 11-7, "
            "Basel III/IV, PRA, FCA, MAS, HKMA, SMCR, Consumer Duty), and all sectors with "
            "deep specialization for financial services."
        ),
        "designPrinciples": [
            "Compliance-by-design and compliance-as-code (OPA/Rego)",
            "Defense-in-depth (8 architectural planes, 3 lines of defense)",
            "Evidence-as-data (every governance decision generates immutable evidence)",
            "Self-verifying governance (formally verified obligation graphs in TLA+/Lean)",
            "Regulator-integrated by default (federated supervisory APIs, JSOP)",
            "Human-on-the-loop for high-risk (Art. 14 EU AI Act, SR 11-7 effective challenge)",
            "Frontier-safety-aware (capability tiers, kinetic kill-switch ≤60s)",
            "Cultural persistence (Codex Charter, sealing/renewal/continuity)",
        ],
        "keyOutcomes": [
            "≤14 days time-to-regulator-approved deployment for High-Risk AI",
            "≥0.92 RAG faithfulness, ≤0.01% PII leakage, ≥99.5% blocked-harm rate",
            "100% AI system inventory coverage; 320 controls automated ≥95%",
            "Decision-traceability ≥99.95% with cryptographic signing (Ed25519 + Dilithium3)",
            "Kinetic kill-switch ≤60s, MTTD ≤4 min, MTTR ≤60 min",
            "Fairness AIR floor ≥0.85; adverse-action SLA ≤24 h",
            "Regulator notification ≤24 h (EU AI Act Art. 73), ≤72 h (GDPR Art. 33)",
            "≥8 federated supervisors connected via JSOP by 2030",
            "AGI Governance Maturity ≥M4 (Predictive) by 2029",
        ],
        "boardNarrative": (
            "Institutional-grade AI is a strategic capability and a regulated activity. This "
            "blueprint puts safety, fairness, privacy, prudential soundness, and supervisory "
            "trust on equal footing with productivity and innovation, and operationalizes them "
            "as measurable, audit-ready, regulator-integrated platform capabilities. By 2030, "
            "the firm operates a self-verifying, regulator-integrated, temporally continuous "
            "governance system that survives leadership transitions, technology refresh cycles, "
            "and capability discontinuities — including the emergence of frontier AGI/ASI."
        ),
    }


# -------------------- MODULES --------------------
def m1_pillars():
    return {
        "id": "M1",
        "title": "M1 — Multilayered AI Governance Pillars & Operating Model",
        "summary": "Eight governance pillars, board oversight, three lines of defense, RACI, and committee architecture.",
        "sections": [
            {
                "id": "M1-S1",
                "title": "Eight Governance Pillars",
                "items": [
                    "P1 Strategic Alignment (board AI strategy, risk appetite, Codex Charter)",
                    "P2 Regulatory Compliance (EU AI Act, ISO/IEC 42001, GDPR, sectoral)",
                    "P3 Risk Management (AI risk taxonomy, FRIA/DPIA, model risk SR 11-7)",
                    "P4 Ethics & Fairness (FEAT, demographic parity, AIR ≥0.85)",
                    "P5 Safety & Containment (frontier tiers, kill-switch, red-team)",
                    "P6 Security & Privacy (zero-trust, PII redaction, OWASP LLM Top 10)",
                    "P7 Transparency & Explainability (XAI, decision envelopes, RAG citations)",
                    "P8 Accountability & Audit (3LoD, internal audit, regulator integration)",
                ],
            },
            {
                "id": "M1-S2",
                "title": "Board Oversight & Executive Roles",
                "executives": {
                    "Board": "Approves AI strategy, risk appetite, Codex Charter; receives quarterly supervisory dashboard",
                    "CEO": "Single accountable executive for AI outcomes; signs Regulator Submission Packs",
                    "CAIO": "Owns AI strategy, AIMS, model registry, frontier safety; chairs AI Risk Committee",
                    "CRO": "Owns AI risk taxonomy, FRIA, capital overlays, SR 11-7 effective challenge",
                    "CISO": "Owns AI security, OWASP LLM Top 10 defense, adversarial robustness",
                    "DPO": "Owns GDPR/PII, DPIA, data subject rights, cross-border transfers",
                    "GC": "Owns regulatory mapping, Art. 73 notifications, treaty obligations",
                    "Head of Internal Audit": "Independent assurance; reports to Audit Committee",
                },
            },
            {
                "id": "M1-S3",
                "title": "Three Lines of Defense + 5 Committees + RACI",
                "committees": [
                    "AI Risk Committee (chair: CAIO; quarterly)",
                    "AI Ethics & Fairness Council (chair: GC; monthly)",
                    "Frontier Safety Board (chair: CRO; ad-hoc + quarterly)",
                    "Model Risk Committee (chair: CRO; SR 11-7 monthly)",
                    "Regulator Engagement Forum (chair: GC; quarterly + on-call)",
                ],
                "raci": "RACI matrix across 320 controls × Board/CEO/CAIO/CRO/CISO/DPO/GC/IA",
            },
        ],
    }


def m2_regulatory():
    return {
        "id": "M2",
        "title": "M2 — Multi-Jurisdiction Regulatory Alignment Matrix",
        "summary": "Crosswalk of 18 regulatory regimes to 320 controls with evidence automation.",
        "sections": [
            {
                "id": "M2-S1",
                "title": "Regulatory Crosswalk",
                "regimes": [
                    {"regime": "EU AI Act", "key": "Arts 5,6,9,10,12-15,17,26-27,49,53,55,72,73", "enforcement": "Aug 2026 (High-Risk), Aug 2025 (GPAI)"},
                    {"regime": "NIST AI RMF 1.0", "key": "Govern/Map/Measure/Manage + AI 600-1 GenAI"},
                    {"regime": "ISO/IEC 42001:2023", "key": "AIMS clauses 4-10 + Annex A controls"},
                    {"regime": "ISO/IEC 23894:2023", "key": "AI Risk Management"},
                    {"regime": "OECD AI Principles", "key": "5 values + 5 recommendations"},
                    {"regime": "GDPR/UK GDPR", "key": "Arts 5,6,9,22,25,32-35"},
                    {"regime": "FCRA §604/§615", "key": "Permissible purpose, adverse action"},
                    {"regime": "ECOA Reg B", "key": "Disparate impact, adverse action"},
                    {"regime": "FFIEC SR 11-7", "key": "Model risk management lifecycle"},
                    {"regime": "Basel III/IV + BCBS 239", "key": "Risk data aggregation, capital"},
                    {"regime": "PRA SS1/23", "key": "MRM principles 1-5"},
                    {"regime": "PRA SS2/21", "key": "Outsourcing & third-party risk"},
                    {"regime": "FCA Consumer Duty PS22/9", "key": "4 outcomes, cross-cutting rules"},
                    {"regime": "FCA SMCR", "key": "SYSC, COCON, SMF24"},
                    {"regime": "MAS FEAT", "key": "Fairness, Ethics, Accountability, Transparency"},
                    {"regime": "HKMA GenAI Guidance", "key": "Sept 2024 + SPM AI"},
                    {"regime": "OWASP LLM Top 10 (2025)", "key": "Prompt inj, data leak, supply chain"},
                    {"regime": "MITRE ATLAS", "key": "Adversarial ML threat tactics"},
                ],
            },
            {
                "id": "M2-S2",
                "title": "Control Inventory & Automation",
                "stats": {"totalControls": 320, "automated": "≥95%", "evidenceRetention": "10 years WORM"},
            },
            {
                "id": "M2-S3",
                "title": "Capital Overlay & Prudential Triggers",
                "triggers": [
                    "Model risk capital overlay tied to MRM tier (T1/T2/T3)",
                    "Operational risk overlay for AI incidents (SEV-0/1)",
                    "Conduct risk overlay for fairness drift > 5pp",
                ],
            },
        ],
    }


def m3_reference_architecture():
    return {
        "id": "M3",
        "title": "M3 — Enterprise AI Reference Architecture (8 Planes)",
        "summary": "Eight architectural planes, deployment topology, multi-tenancy, sovereign-cloud variants.",
        "sections": [
            {
                "id": "M3-S1",
                "title": "Eight Architectural Planes",
                "planes": [
                    {"plane": "Edge & Identity", "components": ["WAF/CDN", "OIDC/OAuth2", "mTLS", "SPIFFE/SPIRE"]},
                    {"plane": "Application", "components": ["WorkflowAI Pro", "Adaptive UX", "Tasks/Reports", "Board Briefing"]},
                    {"plane": "AI", "components": ["GeminiService gateway", "Model registry", "RAG", "Agents", "Frontier sandbox"]},
                    {"plane": "Governance", "components": ["OPA/Rego", "Policy decision points", "FRIA/DPIA engine", "Codex Auto-Updater"]},
                    {"plane": "Data", "components": ["Lakehouse", "Feature store", "Vector DB", "WORM audit (Kafka)", "Lineage"]},
                    {"plane": "Observability", "components": ["OpenTelemetry", "Prometheus", "Grafana", "SIEM", "Predictive dashboard"]},
                    {"plane": "Supply Chain", "components": ["SLSA L3", "Sigstore/Cosign", "in-toto", "SBOM", "Rekor"]},
                    {"plane": "Trust & Federation", "components": ["JSOP", "Trust Contract API", "Treaty disclosure", "Federated supervisors"]},
                ],
            },
            {
                "id": "M3-S2",
                "title": "Deployment Topology",
                "tiers": ["Edge tier", "App tier", "AI tier", "Data tier", "Supervisor tier"],
                "regions": ["EU (Frankfurt/Dublin)", "UK (London)", "US (Virginia/Oregon)", "APAC (Singapore/Hong Kong)", "Sovereign-Gov enclaves"],
            },
            {
                "id": "M3-S3",
                "title": "Multi-Tenancy & Sovereign Variants",
                "models": ["Pool-multi-tenant SaaS", "Silo-per-tenant", "Sovereign-cloud (EU, UK-Gov, US-Gov, SG-Gov)"],
            },
            {
                "id": "M3-S4",
                "title": "Trust & Compliance Stack",
                "components": [
                    "Model Registry (ISO/IEC 42001 aligned, RBAC, lineage, rollback, tags)",
                    "Policy Engine (OPA/Rego, 7 bundles, 5 PDPs)",
                    "Risk Analytics (Prophet/ARIMA forecasters, causal graphs)",
                    "Monitoring (drift, fairness, faithfulness, latency)",
                    "CI/CD Governance Gates (5 gates: pre-merge, build, deploy, canary, prod)",
                    "Kafka WORM Audit (10-year retention, Object Lock)",
                    "Docker Swarm Security (governance sidecars, mTLS, network policies)",
                    "Explainability Frontend (decision envelopes, SHAP, counterfactuals)",
                    "Hyperparameter Control Standards (signed configs, drift detection)",
                ],
            },
        ],
    }


def m4_workflowai():
    return {
        "id": "M4",
        "title": "M4 — WorkflowAI Pro / GeminiService Enterprise Platform",
        "summary": "Workflow recommendation, high-assurance RAG, collaborative prompt engineering, AI safety reporting.",
        "sections": [
            {
                "id": "M4-S1",
                "title": "AI-Driven Workflow Recommendation with Active Learning",
                "features": ["Context-aware recommendation", "Active-learning feedback loops", "Fairness probes", "Human-on-the-loop"],
            },
            {
                "id": "M4-S2",
                "title": "High-Assurance RAG (Faithfulness ≥0.92)",
                "features": ["Citation enforcement", "Grounded outputs", "Retrieval audit", "PII redaction pre-retrieval"],
            },
            {
                "id": "M4-S3",
                "title": "Collaborative Prompt Engineering",
                "features": ["Versioned templates", "4-eyes review", "Evaluation regressions blocked", "Lineage"],
            },
            {
                "id": "M4-S4",
                "title": "AI Safety Reporting (SR-01..SR-06)",
                "reports": ["Existential risk", "Misuse", "Bias", "Threat assessment", "Alignment failure", "International collab"],
            },
            {
                "id": "M4-S5",
                "title": "GeminiService Security & Privacy",
                "features": ["Telemetry integrity", "GDPR PII redaction", "EU AI Act Art. 5 prohibited-practice checks", "Adversarial-prompt defenses"],
            },
        ],
    }


def m5_aims():
    return {
        "id": "M5",
        "title": "M5 — ISO/IEC 42001 AIMS for High-Risk Credit Underwriting",
        "summary": "AIMS Sections 1-5, Annexes J1-J4, multi-jurisdiction overlays, Regulator Submission Packs (RSP v1.0-v2.6).",
        "sections": [
            {
                "id": "M5-S1",
                "title": "AIMS Documentation (Sections 1-5)",
                "sections": ["S1 Context", "S2 Leadership", "S3 Planning (Cl. 6)", "S4 Support", "S5 Operation"],
            },
            {
                "id": "M5-S2",
                "title": "Annexes J1-J4",
                "annexes": [
                    "J1 — AI System Inventory (280 controls × 10 categories)",
                    "J2 — Control Mapping (EU AI Act × ISO/IEC 42001 × NIST AI RMF)",
                    "J3 — FRIA Template (Fundamental Rights Impact Assessment)",
                    "J4 — Regulator Submission Pack (RSP) Template",
                ],
            },
            {
                "id": "M5-S3",
                "title": "Multi-Jurisdiction Overlays",
                "overlays": ["ECB SSM", "Federal Reserve SR 11-7", "PRA SS1/23", "EU AI Act", "GDPR", "FCA Consumer Duty", "MAS FEAT", "HKMA GenAI"],
            },
            {
                "id": "M5-S4",
                "title": "Regulator Submission Packs (RSP v1.0-v2.6)",
                "versions": [
                    {"version": "v1.0", "year": 2026, "automation": "70%"},
                    {"version": "v1.5", "year": 2027, "automation": "82%"},
                    {"version": "v2.0", "year": 2028, "automation": "90%"},
                    {"version": "v2.4", "year": 2028, "automation": "92%"},
                    {"version": "v2.6", "year": 2029, "automation": "95%"},
                ],
            },
            {
                "id": "M5-S5",
                "title": "Decision Traceability API + Cryptographic Signing",
                "features": ["Ed25519 + Dilithium3 hybrid", "in-toto attestations", "Sigstore/Cosign", "Rekor anchor", "ZK predicates"],
            },
        ],
    }


def m6_credit_underwriting():
    return {
        "id": "M6",
        "title": "M6 — Sector-Specific Financial Services MRM",
        "summary": "Credit underwriting, trading, risk, fiduciary AI advisors — best-practice patterns and tier-based controls.",
        "sections": [
            {
                "id": "M6-S1",
                "title": "Credit Underwriting (High-Risk)",
                "controls": ["FCRA §615 adverse action", "ECOA disparate impact", "AIR ≥0.85", "Adverse-action SLA ≤24 h"],
            },
            {
                "id": "M6-S2",
                "title": "Trading & Markets",
                "controls": ["MAR market abuse surveillance", "Best execution monitoring", "Algo wind-down kill-switch"],
            },
            {
                "id": "M6-S3",
                "title": "Risk & Capital",
                "controls": ["IFRS 9 ECL models", "Basel III IRB", "Stress testing", "Capital overlay"],
            },
            {
                "id": "M6-S4",
                "title": "Fiduciary AI Advisors",
                "controls": ["Suitability", "Best interest", "Conflicts disclosure", "Consumer Duty 4 outcomes"],
            },
            {
                "id": "M6-S5",
                "title": "MRM Tiering (T1/T2/T3)",
                "tiers": {"T1": "Material — board approval", "T2": "Significant — committee approval", "T3": "Standard — owner approval"},
            },
        ],
    }


def m7_frontier_safety():
    return {
        "id": "M7",
        "title": "M7 — Frontier AGI Safety, Containment & Cognitive Resonance",
        "summary": "Capability tiers, containment protocols, kill-switch, crisis simulations, minimum viable governance stacks.",
        "sections": [
            {
                "id": "M7-S1",
                "title": "Capability Tiers (Tier-0..Tier-4)",
                "tiers": ["T0 narrow", "T1 broad", "T2 expert-level", "T3 self-improving", "T4 superintelligent"],
            },
            {
                "id": "M7-S2",
                "title": "Containment Protocols",
                "controls": ["Air-gapped sandbox", "Capability evals pre-deploy", "Kinetic kill-switch ≤60s", "Compute caps", "Eval gating"],
            },
            {
                "id": "M7-S3",
                "title": "Cognitive Resonance & Alignment",
                "concepts": ["Constitutional AI", "RLHF/RLAIF", "Debate", "Recursive reward modeling", "Interpretability"],
            },
            {
                "id": "M7-S4",
                "title": "Crisis Simulations (7 scenarios)",
                "scenarios": [
                    "Frontier model exfiltration",
                    "Adversarial jailbreak chain",
                    "Cross-model collusion",
                    "Capability discontinuity",
                    "Supply-chain compromise",
                    "Regulator subpoena",
                    "Black-swan systemic event",
                ],
            },
            {
                "id": "M7-S5",
                "title": "Minimum Viable AI Governance Stack (MVAIGS)",
                "components": ["Inventory", "FRIA", "OPA gate", "WORM audit", "Kill-switch", "Notification template", "Codex"],
            },
        ],
    }


def m8_global_legal():
    return {
        "id": "M8",
        "title": "M8 — Global Legal & Compute Governance",
        "summary": "International compute-governance consortia, treaty-aligned systemic risk governance, autonomous supervisory ecosystems.",
        "sections": [
            {
                "id": "M8-S1",
                "title": "International Compute-Governance Consortium (ICGC)",
                "concepts": ["Compute caps", "FLOPS reporting", "Frontier registration", "Treaty annex"],
            },
            {
                "id": "M8-S2",
                "title": "Treaty-Aligned Systemic Risk Governance",
                "concepts": ["Bilateral disclosure (US-EU-UK-SG)", "Joint Supervisory Operating Protocol", "Cross-border kill-switch"],
            },
            {
                "id": "M8-S3",
                "title": "Cross-Regulator Federation (mTLS + SPIFFE)",
                "members": ["ECB SSM", "Federal Reserve", "PRA", "FCA", "MAS", "HKMA", "EU AI Office", "UK AISI", "US AISI"],
            },
            {
                "id": "M8-S4",
                "title": "Autonomous Supervisory Ecosystems",
                "tiers": ["Tier-A advisory", "Tier-B verifying", "Tier-C autonomous-action (with veto)"],
            },
        ],
    }


def m9_command_center():
    return {
        "id": "M9",
        "title": "M9 — Governance Command Center & Predictive Dashboards",
        "summary": "React Command Center, KPI gauges, deterministic audit replay, predictive governance dashboard.",
        "sections": [
            {
                "id": "M9-S1",
                "title": "Component Catalogue",
                "components": [
                    "CC-01 Agent registry",
                    "CC-02 Incident tracking (SEV-0..SEV-3)",
                    "CC-03 Isolation actions (kill-switch, quarantine)",
                    "CC-04 Real-time risk scores",
                    "CC-05 KPI gauges",
                    "CC-06 Deterministic audit replay",
                    "CC-07 Multi-decision comparative replay",
                    "CC-08 Population-scale heatmap",
                    "CC-09 Predictive governance dashboard",
                ],
            },
            {
                "id": "M9-S2",
                "title": "Codex Auto-Updater Flow",
                "stages": ["Detect drift", "Propose update", "Supervisory narrative", "Sign", "Anchor", "Distribute"],
            },
            {
                "id": "M9-S3",
                "title": "Board Briefing Wireframes",
                "wireframes": ["Risk heatmap", "KPI gauges", "Incident timeline", "Regulator status", "Codex chapter"],
            },
        ],
    }


def m10_supervisory_kpis():
    return {
        "id": "M10",
        "title": "M10 — Supervisory-Grade KPIs & Self-Verifying Governance",
        "summary": "18 board-tracked KPIs including supervisory metrics; deterministic audit replay; formally verified obligations.",
        "sections": [
            {
                "id": "M10-S1",
                "title": "KPI Catalogue (18 KPIs)",
                "kpis": [
                    {"id": "KPI-01", "name": "Time-to-regulator-approved deployment", "target": "≤14 days"},
                    {"id": "KPI-02", "name": "RSP generation latency", "target": "≤30 min"},
                    {"id": "KPI-03", "name": "Decision-traceability coverage", "target": "≥99.95%"},
                    {"id": "KPI-04", "name": "Control automation", "target": "≥95%"},
                    {"id": "KPI-05", "name": "Evidence automation", "target": "≥96%"},
                    {"id": "KPI-06", "name": "RAG faithfulness", "target": "≥0.92"},
                    {"id": "KPI-07", "name": "Blocked-harm rate", "target": "≥99.5%"},
                    {"id": "KPI-08", "name": "PII leakage rate", "target": "≤0.01%"},
                    {"id": "KPI-09", "name": "Fairness AIR floor", "target": "≥0.85"},
                    {"id": "KPI-10", "name": "Adverse-action SLA", "target": "≤24 h"},
                    {"id": "KPI-11", "name": "Regulator notification (EU AI Act)", "target": "≤24 h"},
                    {"id": "KPI-12", "name": "Regulator notification (GDPR)", "target": "≤72 h"},
                    {"id": "KPI-13", "name": "MTTD AI incident", "target": "≤4 min"},
                    {"id": "KPI-14", "name": "MTTR AI incident", "target": "≤60 min"},
                    {"id": "KPI-15", "name": "Kinetic kill-switch", "target": "≤60 s"},
                    {"id": "KPI-16", "name": "False-negative detection rate", "target": "≤0.5%"},
                    {"id": "KPI-17", "name": "Interpretability coverage", "target": "≥90%"},
                    {"id": "KPI-18", "name": "Federated supervisors connected", "target": "≥8 by 2030"},
                ],
            },
            {
                "id": "M10-S2",
                "title": "Self-Verifying Governance",
                "concepts": ["TLA+ obligation graphs", "Lean machine-checkable legal logic", "ZK predicates", "Merkle anchor"],
            },
            {
                "id": "M10-S3",
                "title": "Deterministic Audit Replay",
                "features": ["Snapshot-based replay", "Multi-decision comparative", "Population-scale heatmap"],
            },
        ],
    }


def m11_incident():
    return {
        "id": "M11",
        "title": "M11 — SEV-0..SEV-3 Incident Escalation & Adversarial Loop",
        "summary": "Severity matrix, escalation runbooks, adversarial governance loop, 4 self-healing playbooks.",
        "sections": [
            {
                "id": "M11-S1",
                "title": "Severity Matrix",
                "matrix": {
                    "SEV-0": "Existential / cross-border systemic; CEO+Board+Regulator immediate",
                    "SEV-1": "Material; CRO+CAIO+Regulator ≤24h",
                    "SEV-2": "Significant; AI Risk Committee ≤72h",
                    "SEV-3": "Standard; Owner+Compliance ≤7d",
                },
            },
            {
                "id": "M11-S2",
                "title": "Adversarial Governance Loop",
                "stages": ["Detect", "Triage", "Contain", "Eradicate", "Recover", "Learn", "Disclose"],
            },
            {
                "id": "M11-S3",
                "title": "Self-Healing Playbooks (4)",
                "playbooks": ["SH-01 Bias drift auto-rollback", "SH-02 Faithfulness drop", "SH-03 PII leak", "SH-04 Adversarial-prompt surge"],
            },
        ],
    }


def m12_query_simulation():
    return {
        "id": "M12",
        "title": "M12 — Regulator Query Simulation & Black-Swan Scenarios",
        "summary": "Supervisory interrogation scripts, query simulation pack, 7 black-swan scenarios.",
        "sections": [
            {
                "id": "M12-S1",
                "title": "Regulator Query Simulation Pack",
                "queries": ["RQ-01 Inventory", "RQ-02 FRIA", "RQ-03 Bias", "RQ-04 Adverse action", "RQ-05 Frontier", "RQ-06 GPAI"],
            },
            {
                "id": "M12-S2",
                "title": "Supervisory Interrogation Scripts",
                "examples": ["Decision replay", "Drift narrative", "Evidence chain", "Capital overlay"],
            },
            {
                "id": "M12-S3",
                "title": "Black-Swan Scenarios (7)",
                "scenarios": ["BS-01..BS-07 systemic to civilizational"],
            },
        ],
    }


def m13_maturity_codex():
    return {
        "id": "M13",
        "title": "M13 — AGI Governance Maturity Model & Codex Charter",
        "summary": "M0..M5 maturity rubric; Codex sealing/renewal/continuity/inscription/resonance archives.",
        "sections": [
            {
                "id": "M13-S1",
                "title": "Maturity Tiers (M0..M5)",
                "tiers": ["M0 Initial", "M1 Defined", "M2 Managed", "M3 Quantified", "M4 Predictive", "M5 Self-Verifying"],
            },
            {
                "id": "M13-S2",
                "title": "Maturity Rubric (per pillar)",
                "rubric": "8 pillars × 6 levels × 5 evidence dimensions = 240 cells",
            },
            {
                "id": "M13-S3",
                "title": "Codex Charter Rituals",
                "rituals": ["Sealing (annual)", "Renewal (3-year)", "Continuity (succession)", "Inscription (per chapter)", "Resonance archives"],
            },
            {
                "id": "M13-S4",
                "title": "Cultural Persistence",
                "concepts": ["Multi-modal evidence (text+sig+anchor+ZK)", "Temporal continuity", "Leadership-transition-resilient"],
            },
        ],
    }


def m14_roadmap():
    return {
        "id": "M14",
        "title": "M14 — 2026-2030 Implementation Roadmap & Operating Model",
        "summary": "Five phases, 18 KPIs, 3LoD operating model, 5 committees, RACI for 320 controls.",
        "sections": [
            {
                "id": "M14-S1",
                "title": "Phases (P1..P5)",
                "phases": [
                    {"id": "P1", "name": "Foundation 2026 H1", "deliverables": ["AIMS S1-S5", "Inventory", "OPA gate", "MVAIGS"]},
                    {"id": "P2", "name": "Build 2026 H2 - 2027 H1", "deliverables": ["Command Center", "RSP v1.0-v1.5", "Federation MVP"]},
                    {"id": "P3", "name": "Federate 2027 H2 - 2028", "deliverables": ["JSOP", "Trust Contract", "RSP v2.0-v2.4"]},
                    {"id": "P4", "name": "Predict 2029", "deliverables": ["Predictive dashboard", "TLA+/Lean specs", "Maturity ≥M4"]},
                    {"id": "P5", "name": "Self-Verify 2030", "deliverables": ["RSP v2.6", "Codex sealed", "Maturity ≥M5"]},
                ],
            },
            {
                "id": "M14-S2",
                "title": "Operating Model",
                "components": ["3LoD", "5 committees", "RACI", "Codex Charter"],
            },
            {
                "id": "M14-S3",
                "title": "Top Risks & Mitigations",
                "risks": [
                    {"risk": "Capability discontinuity", "mitigation": "Frontier sandbox, eval gating, kill-switch"},
                    {"risk": "Regulatory divergence", "mitigation": "Multi-overlay AIMS, federation"},
                    {"risk": "Supply-chain compromise", "mitigation": "SLSA L3, Sigstore, in-toto"},
                    {"risk": "Talent gap", "mitigation": "Codex Charter, internal academy"},
                    {"risk": "Cultural drift", "mitigation": "Codex sealing/renewal rituals"},
                ],
            },
        ],
    }


def schemas():
    return {
        "aiSystemInventoryEntry": {
            "title": "AI System Inventory Entry (ISO/IEC 42001 Annex J1)",
            "fields": ["systemId", "owner", "purpose", "tier", "dataClassification", "regulatoryScope", "lifecycleStage"],
        },
        "decisionEnvelope": {
            "title": "Decision Envelope (per AI decision)",
            "fields": ["decisionId", "modelId", "inputs", "outputs", "explanation", "policyEvaluation", "signature"],
        },
        "rspManifest": {
            "title": "Regulator Submission Pack Manifest",
            "fields": ["rspId", "version", "regulator", "artifacts[]", "signatures", "rekorAnchor"],
        },
        "controlMapping": {
            "title": "Control Mapping (cross-regime)",
            "fields": ["controlId", "ifGdpr", "ifEuAiAct", "ifIso42001", "ifNistRmf", "ifSr117", "evidence"],
        },
        "friaRecord": {
            "title": "Fundamental Rights Impact Assessment",
            "fields": ["friaId", "systemId", "rightsImpacted", "mitigations", "residualRisk", "approver"],
        },
        "incidentRecord": {
            "title": "AI Incident Record",
            "fields": ["incidentId", "severity", "detectedAt", "containedAt", "rca", "regulatorNotification"],
        },
        "supervisoryKpiSnapshot": {
            "title": "Supervisory KPI Snapshot",
            "fields": ["snapshotId", "asOf", "kpis[]", "thresholds", "breaches[]"],
        },
        "trustContract": {
            "title": "Trust Contract (regulator API)",
            "fields": ["contractId", "regulator", "scope", "obligations", "expiry", "signatures"],
        },
        "obligationSpec": {
            "title": "Formally Verified Obligation Spec (TLA+/Lean)",
            "fields": ["specId", "regime", "article", "tlaModule", "leanTheorem", "proofStatus"],
        },
        "codexInscription": {
            "title": "Codex Inscription (Charter chapter)",
            "fields": ["inscriptionId", "chapter", "ritual", "sealedBy", "anchor", "resonanceArchive"],
        },
    }


def code_examples():
    return [
        {"id": "CE-01", "title": "OPA/Rego policy gate (compliance-as-code)", "language": "rego", "lines": 32},
        {"id": "CE-02", "title": "Terraform WORM evidence (S3 Object Lock 10-year)", "language": "hcl", "lines": 28},
        {"id": "CE-03", "title": "Dual Ed25519 + Dilithium3 hybrid signer", "language": "python", "lines": 40},
        {"id": "CE-04", "title": "Fairness monitor → SH-01 trigger", "language": "python", "lines": 36},
        {"id": "CE-05", "title": "Federated regulator client (mTLS + SPIFFE)", "language": "python", "lines": 42},
        {"id": "CE-06", "title": "Drift forecaster (Prophet)", "language": "python", "lines": 30},
        {"id": "CE-07", "title": "TLA+ obligation graph", "language": "tla", "lines": 22},
        {"id": "CE-08", "title": "Lean FCRA §615 spec", "language": "lean", "lines": 18},
        {"id": "CE-09", "title": "Self-healing playbook engine", "language": "python", "lines": 48},
        {"id": "CE-10", "title": "FastAPI decision-traceability endpoint", "language": "python", "lines": 38},
        {"id": "CE-11", "title": "Merkle anchor + Rekor submission", "language": "python", "lines": 26},
        {"id": "CE-12", "title": "React Command Center KPI gauge", "language": "tsx", "lines": 44},
    ]


def case_studies():
    return [
        {"id": "CS-01", "title": "EU G-SIB dual ISO/IEC 42001 + EU AI Act certification", "outcome": "Certified Q3 2026; RSP automation 92%"},
        {"id": "CS-02", "title": "US BHC federated SR 11-7 + EU AI Act", "outcome": "Federation MVP live; capital overlay -8%"},
        {"id": "CS-03", "title": "UK PRA SMF24 model risk pipeline", "outcome": "Adverse-action SLA 18h; AIR 0.91"},
        {"id": "CS-04", "title": "Joint ECB+Fed+PRA examination drill", "outcome": "Pass; <30 min RSP regeneration"},
        {"id": "CS-05", "title": "Production bias-drift auto-rollback (SH-01)", "outcome": "MTTR 4 min; zero customer impact"},
        {"id": "CS-06", "title": "Frontier model containment exercise (T3)", "outcome": "Kill-switch 42s; zero escape"},
    ]


def api_endpoints():
    # Build canonical route list
    base = "/api/inst-agi-master"
    routes = [
        f"GET {base}",
        f"GET {base}/meta",
        f"GET {base}/executive-summary",
        f"GET {base}/summary",
        f"GET {base}/modules",
        f"GET {base}/modules/:id",
    ]
    for i in range(1, 15):
        routes.append(f"GET {base}/m{i}")
    # Sub-endpoints per module
    sub = {
        "pillars": ["pillars", "executives", "committees-raci"],
        "regulatory": ["crosswalk", "controls", "capital-overlay"],
        "architecture": ["planes", "topology", "tenancy", "trust-stack"],
        "workflowai": ["recommendation", "rag", "prompts", "safety-reports", "gemini-security"],
        "aims": ["sections", "annexes", "overlays", "rsp-versions", "traceability"],
        "credit": ["underwriting", "trading", "risk", "fiduciary", "tiers"],
        "frontier": ["tiers", "containment", "resonance", "scenarios", "mvaigs"],
        "global": ["icgc", "treaty", "federation", "autonomous"],
        "command-center": ["components", "codex-updater", "briefing"],
        "kpis": ["catalogue", "self-verify", "audit-replay"],
        "incident": ["severity", "loop", "playbooks"],
        "queries": ["simulation", "scripts", "black-swan"],
        "maturity": ["tiers", "rubric", "codex", "persistence"],
        "roadmap": ["phases", "operating-model", "risks"],
    }
    for group, paths in sub.items():
        for p in paths:
            routes.append(f"GET {base}/{group}/{p}")
    routes += [
        f"GET {base}/sections/:id",
        f"GET {base}/schemas",
        f"GET {base}/schemas/:name",
        f"GET {base}/code-examples",
        f"GET {base}/code-examples/:id",
        f"GET {base}/case-studies",
        f"GET {base}/case-studies/:id",
        f"GET {base}/kpis/:id",
        f"GET {base}/roadmap/phases/:id",
    ]
    return routes


def build():
    data = {
        "meta": meta(),
        "executiveSummary": executive_summary(),
        "M1_pillars": m1_pillars(),
        "M2_regulatory": m2_regulatory(),
        "M3_architecture": m3_reference_architecture(),
        "M4_workflowai": m4_workflowai(),
        "M5_aims": m5_aims(),
        "M6_creditUnderwriting": m6_credit_underwriting(),
        "M7_frontierSafety": m7_frontier_safety(),
        "M8_globalLegal": m8_global_legal(),
        "M9_commandCenter": m9_command_center(),
        "M10_supervisoryKpis": m10_supervisory_kpis(),
        "M11_incident": m11_incident(),
        "M12_querySimulation": m12_query_simulation(),
        "M13_maturityCodex": m13_maturity_codex(),
        "M14_roadmap": m14_roadmap(),
        "schemas": schemas(),
        "codeExamples": code_examples(),
        "caseStudies": case_studies(),
        "apiEndpoints": api_endpoints(),
    }
    return data


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = build()
    OUT.write_text(json.dumps(data, indent=2))
    size_kb = OUT.stat().st_size / 1024
    n_modules = sum(1 for k in data if k.startswith("M") and "_" in k)
    n_sections = sum(len(data[k].get("sections", [])) for k in data if k.startswith("M") and "_" in k)
    n_schemas = len(data.get("schemas", {}))
    n_code = len(data.get("codeExamples", []))
    n_cases = len(data.get("caseStudies", []))
    n_routes = len(data.get("apiEndpoints", []))
    print(f"[OK] Generated {OUT} ({size_kb:.1f} KB)")
    print(f"     modules={n_modules} sections={n_sections} schemas={n_schemas} "
          f"code={n_code} cases={n_cases} routes={n_routes}")


if __name__ == "__main__":
    main()
