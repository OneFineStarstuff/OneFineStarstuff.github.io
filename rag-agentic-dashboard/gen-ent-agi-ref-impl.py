#!/usr/bin/env python3
"""
WP-040 — Enterprise AGI/ASI Governance Master Reference & Implementation
Blueprint (2026-2030) for Fortune 500 / Global 2000 / G-SIFI institutions.

Outputs: data/ent-agi-ref-impl.json (idempotent)
"""
import json
from pathlib import Path

OUT = Path(__file__).parent / "data" / "ent-agi-ref-impl.json"
DOC_REF = "ENT-AGI-REF-IMPL-WP-040"
VERSION = "1.0.0"
HORIZON = "2026-2030"


def meta():
    return {
        "docRef": DOC_REF,
        "version": VERSION,
        "date": "2026-05-04",
        "title": "Enterprise AGI/ASI Governance Master Reference & Implementation Blueprint",
        "subtitle": "Regulator-Ready Reference Architectures, Platform Specs & Phased Roadmap for Fortune 500 / Global 2000 / G-SIFI Institutions (2026-2030)",
        "classification": "CONFIDENTIAL — Board / Audit Committee / CRO / CISO / Prudential Supervisor",
        "owner": "Group CEO + Chief AI Officer (CAIO) — co-signed by CRO, CISO, GC, DPO, Head of Internal Audit",
        "audience": [
            "C-Suite (CEO, CFO, CRO, CIO, CISO, CAIO, GC, DPO)",
            "Board of Directors and Audit / Risk Committees",
            "Prudential supervisors and AI safety regulators",
            "Enterprise architects",
            "AI platform engineers and MLOps SREs",
            "AI safety researchers",
        ],
        "horizon": HORIZON,
        "buildsOn": [
            "WP-035 ENT-AGI-GOV-MASTER",
            "WP-036 WFAP-GEMINI-IMPL",
            "WP-037 GSIFI-AIMS-BLUEPRINT",
            "WP-038 AGI-REG-RESILIENT",
            "WP-039 INST-AGI-MASTER",
        ],
        "regulatoryAlignment": [
            "EU AI Act (Reg. 2024/1689) — Aug 2026 High-Risk + Aug 2025 GPAI; Arts 5,6,9,10,12-15,17,26-27,49,53,55,72,73",
            "NIST AI RMF 1.0 (Govern/Map/Measure/Manage) + AI 600-1 GenAI Profile",
            "ISO/IEC 42001:2023 (AIMS); ISO/IEC 23894 (AI Risk); ISO/IEC 5338, 27001, 27701, 27018",
            "OECD AI Principles (2019, updated 2024)",
            "GDPR/UK GDPR — Arts 5, 6, 9, 22, 25, 32-35",
            "US — FCRA §604/§615, ECOA Reg B, FFIEC SR 11-7, OCC 2011-12, CFPB Circulars",
            "US Executive Order 14110 (Safe, Secure, Trustworthy AI) — agency obligations & red-team disclosure",
            "Basel III/IV + BCBS 239 risk data aggregation",
            "PRA SS1/23 (MRM), PRA SS2/21 (third-party risk)",
            "FCA Consumer Duty PS22/9; FCA SMCR (SYSC, COCON, SMF24)",
            "MAS FEAT Principles; MAS Veritas",
            "HKMA GenAI Guidance (Sept 2024); HKMA SPM AI",
            "OWASP LLM Top 10 (2025); MITRE ATLAS; STRIDE; LINDDUN",
            "SLSA L3, in-toto, Sigstore/Cosign, Rekor; SOC 2 Type II; FedRAMP High",
        ],
        "subjectSystem": {
            "scope": "All AI/ML systems across the enterprise — discriminative, generative, agentic, frontier AGI/ASI",
            "scale": "Fortune 500 / Global 2000 / G-SIFI; >100k staff; >50 jurisdictions; >1M concurrent inferences",
            "deployment": "Multi-region active-active hybrid + sovereign-cloud variants (EU, UK-Gov, US-Gov, SG-Gov)",
            "platforms": [
                "Sentinel AI Governance Platform v2.4",
                "WorkflowAI Pro / GeminiService",
                "EAIP (Enterprise AI Implementation Platform)",
                "Enterprise AI Governance Hub",
            ],
        },
        "deliverableInventory": {
            "modules": 14,
            "sections": 50,
            "schemas": 10,
            "codeExamples": 12,
            "caseStudies": 6,
            "apiRoutes": 90,
            "phases": 5,
            "kpis": 18,
            "controls": 320,
        },
    }


def executive_summary():
    return {
        "purpose": (
            "Deliver a single, regulator-ready, board-approvable Enterprise AGI/ASI Governance "
            "Master Reference & Implementation Blueprint for Fortune 500 / Global 2000 / G-SIFI "
            "institutions, integrating reference architectures, sector MRM, AGI/ASI safety, "
            "global compute governance, four flagship platforms, and a phased 2026-2030 roadmap."
        ),
        "scope": (
            "Covers regulator-ready governance architectures; cross-jurisdiction alignment "
            "(EU AI Act 2026 High-Risk + GPAI, NIST AI RMF, ISO/IEC 42001, OECD, GDPR, FCRA/ECOA, "
            "Basel III, SR 11-7, PRA, FCA, MAS, HKMA, SMCR, Consumer Duty, US EO 14110); "
            "enterprise AI reference & compliance architectures (Kafka WORM with ACL governance, "
            "Docker Swarm security, Node.js/Python governance sidecars, Next.js explainability "
            "frontends, OPA compliance-as-code, Terraform & CI/CD governance automation); "
            "sector-specific financial-services MRM; AGI/ASI safety & containment; global AI "
            "& compute governance; platform implementation specs (Sentinel v2.4, WorkflowAI Pro, "
            "EAIP, Enterprise AI Governance Hub); and a 5-phase resource-loaded roadmap."
        ),
        "designPrinciples": [
            "Compliance-by-design and compliance-as-code (OPA/Rego)",
            "Defense-in-depth across 8 architectural planes + 3 lines of defense",
            "Evidence-as-data (every governance event generates immutable, signed evidence)",
            "Self-verifying governance (TLA+ / Lean machine-checkable obligations)",
            "Regulator-integrated by default (federated supervisors, JSOP)",
            "Human-on-the-loop for high-risk (Art. 14 EU AI Act, SR 11-7 effective challenge)",
            "Frontier-safety-aware (capability tiers, kinetic kill-switch ≤60s)",
            "Platform-first delivery (Sentinel + WorkflowAI Pro + EAIP + Hub)",
        ],
        "keyOutcomes": [
            "≤14 days time-to-regulator-approved deployment",
            "≥0.92 RAG faithfulness · ≤0.01% PII leakage · ≥99.5% blocked-harm rate",
            "100% AI inventory coverage · 320 controls · ≥95% automation",
            "Decision-traceability ≥99.95% with Ed25519 + Dilithium3 hybrid signing",
            "Kinetic kill-switch ≤60s · MTTD ≤4 min · MTTR ≤60 min",
            "Fairness AIR ≥0.85 · adverse-action SLA ≤24 h",
            "Reg notification ≤24 h (EU AI Act Art. 73) / ≤72 h (GDPR Art. 33)",
            "≥8 federated supervisors connected via JSOP by 2030",
            "AGI Governance Maturity ≥M4 (Predictive) by 2029, ≥M5 by 2030",
        ],
        "boardNarrative": (
            "AI is now both a strategic capability and a regulated activity. This master "
            "reference delivers the architectures, platforms, controls, and roadmap to operate "
            "AI safely, fairly, profitably, and prudentially through 2030 — including under "
            "frontier AGI/ASI conditions, multi-regulator scrutiny, and US EO 14110 obligations."
        ),
    }


# ---------------- MODULES ----------------
def m1_governance_architecture():
    return {
        "id": "M1",
        "title": "M1 — Regulator-Ready AI Governance Architectures",
        "summary": "Board-to-engineer governance stack with 8 pillars, 3LoD, executive accountability, and regulator integration.",
        "sections": [
            {
                "id": "M1-S1",
                "title": "Eight Governance Pillars",
                "pillars": [
                    "P1 Strategic Alignment (board AI strategy, risk appetite)",
                    "P2 Regulatory Compliance (multi-jurisdiction)",
                    "P3 Risk Management (FRIA/DPIA, MRM)",
                    "P4 Ethics & Fairness (FEAT, AIR ≥0.85)",
                    "P5 Safety & Containment (frontier tiers, kill-switch)",
                    "P6 Security & Privacy (zero-trust, OWASP LLM Top 10)",
                    "P7 Transparency & Explainability (XAI, decision envelopes)",
                    "P8 Accountability & Audit (3LoD, IA, regulator-integrated)",
                ],
            },
            {
                "id": "M1-S2",
                "title": "Executive Accountability & Three Lines of Defense",
                "executives": {
                    "Board": "Approves AI strategy, risk appetite, Codex Charter",
                    "CEO": "Single accountable executive; signs Regulator Submission Packs",
                    "CAIO": "Owns AIMS, model registry, frontier safety; chairs AI Risk Committee",
                    "CRO": "Owns AI risk taxonomy, FRIA, capital overlays, SR 11-7 effective challenge",
                    "CISO": "Owns AI security, OWASP LLM Top 10 defense",
                    "DPO": "Owns GDPR/PII, DPIA, data subject rights",
                    "GC": "Owns regulatory mapping, Art. 73 notifications, EO 14110 disclosure",
                    "IA": "Independent assurance",
                },
                "lod": ["1LoD Business owners", "2LoD Risk & Compliance", "3LoD Internal Audit"],
            },
            {
                "id": "M1-S3",
                "title": "Committees & RACI",
                "committees": [
                    "AI Risk Committee (CAIO, quarterly)",
                    "AI Ethics & Fairness Council (GC, monthly)",
                    "Frontier Safety Board (CRO, ad-hoc + quarterly)",
                    "Model Risk Committee (CRO, monthly SR 11-7)",
                    "Regulator Engagement Forum (GC, on-call + quarterly)",
                ],
                "raci": "320 controls × Board/CEO/CAIO/CRO/CISO/DPO/GC/IA",
            },
        ],
    }


def m2_regulatory():
    return {
        "id": "M2",
        "title": "M2 — Multi-Jurisdiction Regulatory Alignment Matrix",
        "summary": "20 regulatory regimes mapped to 320 controls including US EO 14110.",
        "sections": [
            {
                "id": "M2-S1",
                "title": "Crosswalk (20 regimes)",
                "regimes": [
                    {"regime": "EU AI Act", "key": "Aug 2026 High-Risk + Aug 2025 GPAI; Arts 5-15, 26-27, 49, 53, 55, 72-73"},
                    {"regime": "NIST AI RMF 1.0 + AI 600-1", "key": "Govern/Map/Measure/Manage + GenAI Profile"},
                    {"regime": "ISO/IEC 42001", "key": "AIMS clauses 4-10 + Annex A"},
                    {"regime": "ISO/IEC 23894", "key": "AI Risk Management"},
                    {"regime": "OECD AI Principles", "key": "5 values + 5 recs"},
                    {"regime": "GDPR/UK GDPR", "key": "Arts 5, 6, 9, 22, 25, 32-35"},
                    {"regime": "FCRA §604/§615", "key": "Adverse action, permissible purpose"},
                    {"regime": "ECOA Reg B", "key": "Disparate impact"},
                    {"regime": "FFIEC SR 11-7 / OCC 2011-12", "key": "MRM lifecycle"},
                    {"regime": "Basel III/IV + BCBS 239", "key": "Risk data, capital"},
                    {"regime": "PRA SS1/23", "key": "MRM principles 1-5"},
                    {"regime": "PRA SS2/21", "key": "Outsourcing & 3rd-party"},
                    {"regime": "FCA Consumer Duty PS22/9", "key": "4 outcomes, cross-cutting"},
                    {"regime": "FCA SMCR", "key": "SYSC, COCON, SMF24"},
                    {"regime": "MAS FEAT + Veritas", "key": "Fairness, Ethics, Accountability, Transparency"},
                    {"regime": "HKMA GenAI Sept 2024", "key": "SPM AI"},
                    {"regime": "US EO 14110", "key": "Safe/Secure/Trustworthy AI; red-team disclosure for dual-use foundation models"},
                    {"regime": "OWASP LLM Top 10 (2025)", "key": "Prompt inj, data leak, supply chain"},
                    {"regime": "MITRE ATLAS", "key": "Adversarial ML tactics"},
                    {"regime": "SLSA L3 / Sigstore / in-toto", "key": "Supply-chain integrity"},
                ],
            },
            {
                "id": "M2-S2",
                "title": "Control Inventory",
                "stats": {"controls": 320, "automation": "≥95%", "WORM": "10 years"},
            },
            {
                "id": "M2-S3",
                "title": "US EO 14110 Specifics",
                "obligations": [
                    "Dual-use foundation model reporting (compute thresholds)",
                    "Red-team results disclosure to USG",
                    "Watermarking & content provenance",
                    "AI Safety Institute coordination",
                    "Critical-infrastructure AI risk reporting",
                ],
            },
            {
                "id": "M2-S4",
                "title": "Capital Overlay Triggers",
                "triggers": [
                    "MRM tier T1 → Pillar 2 model risk overlay",
                    "AI incidents SEV-0/1 → operational risk overlay",
                    "Fairness drift > 5pp → conduct overlay",
                ],
            },
        ],
    }


def m3_reference_architecture():
    return {
        "id": "M3",
        "title": "M3 — Enterprise AI Reference & Compliance Architectures",
        "summary": "8 architectural planes + concrete compliance stack: Kafka WORM, Docker Swarm, sidecars, Next.js XAI, OPA, Terraform/CI-CD.",
        "sections": [
            {
                "id": "M3-S1",
                "title": "Eight Architectural Planes",
                "planes": [
                    {"plane": "Edge & Identity", "components": ["WAF/CDN", "OIDC/OAuth2", "mTLS", "SPIFFE/SPIRE"]},
                    {"plane": "Application", "components": ["WorkflowAI Pro", "Adaptive UX", "Tasks/Reports", "Board Briefing"]},
                    {"plane": "AI", "components": ["GeminiService gateway", "Model registry", "RAG", "Agents", "Frontier sandbox"]},
                    {"plane": "Governance", "components": ["OPA/Rego", "PDPs", "FRIA/DPIA engine", "Codex Auto-Updater"]},
                    {"plane": "Data", "components": ["Lakehouse", "Feature store", "Vector DB", "Kafka WORM", "Lineage"]},
                    {"plane": "Observability", "components": ["OpenTelemetry", "Prometheus", "Grafana", "SIEM"]},
                    {"plane": "Supply Chain", "components": ["SLSA L3", "Sigstore/Cosign", "in-toto", "SBOM", "Rekor"]},
                    {"plane": "Trust & Federation", "components": ["JSOP", "Trust Contract API", "Treaty disclosure"]},
                ],
            },
            {
                "id": "M3-S2",
                "title": "Kafka WORM Audit with ACL Governance",
                "design": [
                    "Confluent Kafka with tiered storage; 10-year retention via S3 Object Lock (Compliance mode)",
                    "ACLs scoped per topic per principal; SPIFFE-based service identity",
                    "Schema Registry with Avro evolution & compatibility = FULL_TRANSITIVE",
                    "Idempotent producers, exactly-once semantics on critical topics (audit, decisions)",
                    "Cluster-wide encryption-at-rest (KMS) + TLS 1.3 in-flight",
                    "Audit topics: gov.audit.decisions, gov.audit.policy, gov.audit.incidents",
                    "External anchoring: hourly Merkle root → Rekor transparency log",
                ],
            },
            {
                "id": "M3-S3",
                "title": "Docker Swarm Security Posture",
                "controls": [
                    "Manager nodes encrypted Raft logs; autolock enabled",
                    "Service-level secrets (no env-var secrets); Vault CSI driver",
                    "Network: encrypted overlay (IPSec) for inter-node traffic",
                    "Read-only root FS; user namespace remap; seccomp + AppArmor profiles",
                    "No --privileged; capability drops (CAP_DROP=ALL + minimal allow-list)",
                    "Image policy: signed (Cosign) + SBOM-attested (in-toto)",
                    "Network policies enforced at sidecar (Envoy)",
                ],
            },
            {
                "id": "M3-S4",
                "title": "Governance Sidecars (Node.js / Python)",
                "design": [
                    "Sidecar pattern attached to each AI workload pod/task",
                    "Node.js sidecar: high-throughput gateway functions (telemetry, mTLS, request shaping)",
                    "Python sidecar: heavy governance logic (FRIA evaluation, fairness probes, PII redaction)",
                    "Both sidecars expose unix-domain-socket APIs to the workload",
                    "Both publish to Kafka audit topics with idempotent producers",
                    "Health checks on /healthz; metrics on /metrics (Prometheus)",
                ],
            },
            {
                "id": "M3-S5",
                "title": "Next.js Explainability Frontend",
                "design": [
                    "Next.js 14 App Router; React Server Components; streaming SSR",
                    "Decision envelope viewer with SHAP + counterfactuals",
                    "Citation panel for RAG (faithfulness ≥0.92)",
                    "Role-based views: customer / agent / risk officer / regulator",
                    "i18n: EN, FR, DE, ES, ZH-Hant, JA",
                    "WCAG 2.2 AA + EAA 2025 accessibility",
                ],
            },
            {
                "id": "M3-S6",
                "title": "OPA Compliance-as-Code",
                "design": [
                    "Single source of truth: 7 policy bundles (privacy, fairness, model-tier, supply-chain, GenAI, frontier, regulator)",
                    "Distributed via OPA bundle server + signed bundles (Cosign)",
                    "5 PDPs: pre-merge gate, build gate, deploy gate, runtime sidecar, audit replay",
                    "Decision logs streamed to Kafka gov.audit.policy",
                    "Unit tests with OPA test; coverage ≥85%",
                ],
            },
            {
                "id": "M3-S7",
                "title": "Terraform + CI/CD Governance Automation",
                "design": [
                    "Terraform Cloud with VCS-backed workspaces; Sentinel + OPA policies",
                    "GitHub Actions / GitLab CI gates: SCA, SAST, IaC scan, SBOM, Cosign sign, OPA gate",
                    "Promotion: dev → stage → canary → prod with policy verdict at each step",
                    "Drift detection nightly; auto-remediation for tier-3 drift, ticket for tier-1/2",
                    "Audit: tf-state versioning + signed plans archived to S3 Object Lock",
                ],
            },
        ],
    }


def m4_sector_mrm():
    return {
        "id": "M4",
        "title": "M4 — Sector-Specific Financial Services MRM",
        "summary": "Credit, trading, risk, fiduciary AI; T1/T2/T3 model tiers under SR 11-7 + PRA SS1/23.",
        "sections": [
            {
                "id": "M4-S1",
                "title": "Credit Underwriting (High-Risk under EU AI Act)",
                "controls": ["FCRA §615 adverse action ≤24h SLA", "ECOA Reg B disparate impact", "AIR ≥0.85", "FRIA + DPIA"],
            },
            {
                "id": "M4-S2",
                "title": "Trading & Markets",
                "controls": ["MAR market abuse surveillance", "Best-execution monitoring", "Algo wind-down kill-switch ≤5s"],
            },
            {
                "id": "M4-S3",
                "title": "Risk & Capital",
                "controls": ["IFRS 9 ECL", "Basel IRB", "Stress testing", "Pillar 2 model overlay"],
            },
            {
                "id": "M4-S4",
                "title": "Fiduciary AI Advisors",
                "controls": ["Suitability", "Best interest", "Conflicts disclosure", "FCA Consumer Duty 4 outcomes"],
            },
            {
                "id": "M4-S5",
                "title": "Model Tiering (T1/T2/T3)",
                "tiers": {"T1": "Material — board approval", "T2": "Significant — committee approval", "T3": "Standard — owner approval"},
            },
        ],
    }


def m5_safety_containment():
    return {
        "id": "M5",
        "title": "M5 — AGI/ASI Safety & Containment Protocols",
        "summary": "Capability tiers T0..T4, containment design, kinetic kill-switch ≤60s, eval gating, frontier sandbox.",
        "sections": [
            {
                "id": "M5-S1",
                "title": "Capability Tiers (T0..T4)",
                "tiers": ["T0 narrow", "T1 broad", "T2 expert-level", "T3 self-improving", "T4 superintelligent"],
            },
            {
                "id": "M5-S2",
                "title": "Containment Design",
                "controls": [
                    "Air-gapped frontier sandbox (no egress)",
                    "Compute caps + cumulative FLOPS ledger",
                    "Eval gating pre-deploy (CBRN, cyber, autonomy, persuasion, deception)",
                    "Kinetic kill-switch ≤60s (validated quarterly)",
                    "Red-team disclosure obligations (US EO 14110)",
                ],
            },
            {
                "id": "M5-S3",
                "title": "Alignment Techniques",
                "concepts": ["Constitutional AI", "RLHF/RLAIF", "Debate", "Recursive reward modeling", "Mechanistic interpretability"],
            },
            {
                "id": "M5-S4",
                "title": "Crisis Simulations (7 scenarios)",
                "scenarios": [
                    "Frontier model exfiltration",
                    "Adversarial jailbreak chain",
                    "Cross-model collusion",
                    "Capability discontinuity",
                    "Supply-chain compromise",
                    "Regulator subpoena (joint ECB+Fed+PRA)",
                    "Black-swan systemic event",
                ],
            },
        ],
    }


def m6_global_compute():
    return {
        "id": "M6",
        "title": "M6 — Global AI & Compute Governance",
        "summary": "International compute-governance consortium, treaty-aligned systemic-risk governance, federated supervisors.",
        "sections": [
            {
                "id": "M6-S1",
                "title": "International Compute-Governance Consortium (ICGC)",
                "concepts": ["Compute caps (FLOPS thresholds)", "Frontier model registration", "Treaty annex"],
            },
            {
                "id": "M6-S2",
                "title": "Treaty-Aligned Systemic-Risk Governance",
                "concepts": ["Bilateral disclosure (US-EU-UK-SG)", "JSOP cross-border", "Cross-border kill-switch"],
            },
            {
                "id": "M6-S3",
                "title": "Federated Supervisor Mesh",
                "members": ["ECB SSM", "Federal Reserve", "PRA", "FCA", "MAS", "HKMA", "EU AI Office", "UK AISI", "US AISI"],
                "transport": "mTLS + SPIFFE, Trust Contract APIs",
            },
        ],
    }


def m7_sentinel_v24():
    return {
        "id": "M7",
        "title": "M7 — Sentinel AI Governance Platform v2.4",
        "summary": "Flagship governance platform: real-time risk telemetry, agent registry, isolation, audit replay, predictive dashboard.",
        "sections": [
            {
                "id": "M7-S1",
                "title": "Capabilities",
                "capabilities": [
                    "Real-time risk telemetry (drift, fairness, faithfulness, latency)",
                    "Agent registry (every AI agent inventoried)",
                    "Isolation actions (kill-switch, quarantine, freeze)",
                    "Deterministic audit replay (snapshot-based)",
                    "Predictive governance dashboard (Prophet/ARIMA)",
                    "Codex Auto-Updater",
                ],
            },
            {
                "id": "M7-S2",
                "title": "Integration Surface",
                "interfaces": [
                    "Webhooks from CI/CD gates",
                    "OPA decision-log subscription",
                    "Kafka audit-topic consumer",
                    "Federated supervisor APIs",
                    "WorkflowAI Pro & GeminiService telemetry",
                ],
            },
            {
                "id": "M7-S3",
                "title": "Deployment Profile",
                "profile": ["Multi-region active-active", "Sovereign-cloud variants", "HA Kafka, HA Postgres, HA Vector-DB"],
            },
        ],
    }


def m8_workflowai_pro():
    return {
        "id": "M8",
        "title": "M8 — WorkflowAI Pro / GeminiService",
        "summary": "Enterprise platform for AI workflow recommendation, high-assurance RAG, prompt collaboration, AI safety reporting.",
        "sections": [
            {
                "id": "M8-S1",
                "title": "Workflow Recommendation w/ Active Learning",
                "features": ["Context-aware", "Active-learning loops", "Fairness probes", "Human-on-the-loop"],
            },
            {
                "id": "M8-S2",
                "title": "High-Assurance RAG",
                "features": ["Faithfulness ≥0.92", "Citation enforcement", "PII redaction pre-retrieval", "Retrieval audit"],
            },
            {
                "id": "M8-S3",
                "title": "Collaborative Prompt Engineering",
                "features": ["Versioned templates", "4-eyes review", "Eval-regression blocking", "Lineage"],
            },
            {
                "id": "M8-S4",
                "title": "AI Safety Reports (SR-01..SR-06)",
                "reports": ["Existential risk", "Misuse", "Bias", "Threat assessment", "Alignment failure", "Intl collab"],
            },
            {
                "id": "M8-S5",
                "title": "GeminiService Security & Privacy",
                "features": ["Telemetry integrity", "GDPR PII redaction", "EU AI Act Art. 5 prohibited-practice checks", "Adversarial-prompt defenses"],
            },
        ],
    }


def m9_eaip():
    return {
        "id": "M9",
        "title": "M9 — EAIP (Enterprise AI Implementation Platform)",
        "summary": "Implementation platform binding governance to delivery: model registry, CI/CD gates, evidence pipeline, RSP generator.",
        "sections": [
            {
                "id": "M9-S1",
                "title": "Model Registry",
                "features": ["ISO/IEC 42001-aligned", "RBAC", "Lineage", "Rollback", "Tags", "ModelCards"],
            },
            {
                "id": "M9-S2",
                "title": "CI/CD Governance Gates",
                "gates": ["pre-merge", "build", "deploy", "canary", "prod"],
            },
            {
                "id": "M9-S3",
                "title": "Evidence Pipeline",
                "design": ["Signed evidence (Cosign + Dilithium3)", "Hourly Merkle anchor → Rekor", "10-year WORM"],
            },
            {
                "id": "M9-S4",
                "title": "RSP Generator (v1.0..v2.6)",
                "automation": "≤30 min per RSP; ≥95% automated by 2029",
            },
        ],
    }


def m10_governance_hub():
    return {
        "id": "M10",
        "title": "M10 — Enterprise AI Governance Hub",
        "summary": "Single executive workspace: KPIs, incidents, regulator queries, board briefings, Codex Charter.",
        "sections": [
            {
                "id": "M10-S1",
                "title": "Hub Surfaces",
                "surfaces": [
                    "KPI Cockpit (18 supervisory-grade KPIs)",
                    "Incident Tracker (SEV-0..SEV-3)",
                    "Regulator Engagement (queries + RSP delivery)",
                    "Board Briefing Studio",
                    "Codex Charter Library",
                ],
            },
            {
                "id": "M10-S2",
                "title": "Personas & Views",
                "personas": ["Board director", "CEO", "CRO", "CISO", "CAIO", "Regulator (read-only)", "Auditor"],
            },
            {
                "id": "M10-S3",
                "title": "Embedded Analytics",
                "components": ["Predictive dashboard", "Population-scale heatmap", "Comparative replay"],
            },
        ],
    }


def m11_kpis_self_verifying():
    return {
        "id": "M11",
        "title": "M11 — Supervisory KPIs & Self-Verifying Governance",
        "summary": "18 board-tracked KPIs; TLA+/Lean obligation graphs; deterministic audit replay; ZK predicates.",
        "sections": [
            {
                "id": "M11-S1",
                "title": "KPI Catalogue (18)",
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
                    {"id": "KPI-11", "name": "Reg notification (EU AI Act)", "target": "≤24 h"},
                    {"id": "KPI-12", "name": "Reg notification (GDPR)", "target": "≤72 h"},
                    {"id": "KPI-13", "name": "MTTD AI incident", "target": "≤4 min"},
                    {"id": "KPI-14", "name": "MTTR AI incident", "target": "≤60 min"},
                    {"id": "KPI-15", "name": "Kinetic kill-switch", "target": "≤60 s"},
                    {"id": "KPI-16", "name": "False-negative detection rate", "target": "≤0.5%"},
                    {"id": "KPI-17", "name": "Interpretability coverage", "target": "≥90%"},
                    {"id": "KPI-18", "name": "Federated supervisors connected", "target": "≥8 by 2030"},
                ],
            },
            {
                "id": "M11-S2",
                "title": "Self-Verifying Governance",
                "concepts": ["TLA+ obligation graphs", "Lean machine-checkable legal logic (FCRA §615, GDPR Art. 22, EU AI Act Art. 73)", "ZK predicates", "Merkle anchoring → Rekor"],
            },
            {
                "id": "M11-S3",
                "title": "Deterministic Audit Replay",
                "features": ["Snapshot-based replay", "Multi-decision comparative", "Population-scale heatmap"],
            },
        ],
    }


def m12_incident_adversarial():
    return {
        "id": "M12",
        "title": "M12 — Incident Escalation & Adversarial Loop",
        "summary": "SEV-0..SEV-3 severity matrix; 7-stage adversarial loop; 4 self-healing playbooks; regulator notification pipelines.",
        "sections": [
            {
                "id": "M12-S1",
                "title": "Severity Matrix",
                "matrix": {
                    "SEV-0": "Existential / cross-border systemic; CEO+Board+Regulator immediate",
                    "SEV-1": "Material; CRO+CAIO+Regulator ≤24h",
                    "SEV-2": "Significant; AI Risk Committee ≤72h",
                    "SEV-3": "Standard; Owner+Compliance ≤7d",
                },
            },
            {
                "id": "M12-S2",
                "title": "Adversarial Governance Loop",
                "stages": ["Detect", "Triage", "Contain", "Eradicate", "Recover", "Learn", "Disclose"],
            },
            {
                "id": "M12-S3",
                "title": "Self-Healing Playbooks",
                "playbooks": ["SH-01 Bias-drift auto-rollback", "SH-02 Faithfulness drop", "SH-03 PII leak", "SH-04 Adversarial-prompt surge"],
            },
            {
                "id": "M12-S4",
                "title": "Regulator Notification Pipelines",
                "pipelines": [
                    "EU AI Act Art. 73: ≤24h to authority + EU AI Office",
                    "GDPR Art. 33: ≤72h to DPA",
                    "FCA / PRA: SUP 15 + SS1/23",
                    "US EO 14110: red-team disclosure to USG",
                ],
            },
        ],
    }


def m13_roadmap_resources():
    return {
        "id": "M13",
        "title": "M13 — Phased Roadmap & Resource Plan (2026-2030)",
        "summary": "Five phases with deliverables, FTE/cost envelopes, dependencies, exit criteria.",
        "sections": [
            {
                "id": "M13-S1",
                "title": "Phases (P1..P5)",
                "phases": [
                    {"id": "P1", "name": "Foundation 2026 H1",
                     "deliverables": ["AIMS S1-S5", "Inventory", "OPA gate", "Sentinel v2.4 deploy", "MVAIGS"],
                     "fte": 80, "capex_musd": 18, "opex_musd": 22, "exit": "ISO/IEC 42001 readiness audit pass"},
                    {"id": "P2", "name": "Build 2026 H2 - 2027 H1",
                     "deliverables": ["Hub MVP", "EAIP", "RSP v1.0-v1.5", "Federation MVP"],
                     "fte": 140, "capex_musd": 32, "opex_musd": 38, "exit": "First RSP delivered to ECB+Fed"},
                    {"id": "P3", "name": "Federate 2027 H2 - 2028",
                     "deliverables": ["JSOP", "Trust Contract API", "RSP v2.0-v2.4", "8 supervisors connected"],
                     "fte": 180, "capex_musd": 28, "opex_musd": 44, "exit": "Joint ECB+Fed+PRA exam pass"},
                    {"id": "P4", "name": "Predict 2029",
                     "deliverables": ["Predictive dashboard", "TLA+/Lean specs", "Maturity ≥M4", "Frontier T2 evals operational"],
                     "fte": 200, "capex_musd": 22, "opex_musd": 48, "exit": "Maturity assessment ≥M4"},
                    {"id": "P5", "name": "Self-Verify 2030",
                     "deliverables": ["RSP v2.6", "Codex sealed", "Maturity ≥M5", "EO 14110 reporting fully automated"],
                     "fte": 210, "capex_musd": 18, "opex_musd": 50, "exit": "Maturity ≥M5; full EO 14110 + EU AI Act compliance"},
                ],
                "totals": {"fte_peak": 210, "capex_musd": 118, "opex_musd_5y": 202},
            },
            {
                "id": "M13-S2",
                "title": "Resource Plan & Skill Mix",
                "skills": [
                    "AI safety researchers (alignment, interpretability)",
                    "Enterprise architects",
                    "AI platform engineers (MLOps, SRE)",
                    "Governance engineers (OPA, Terraform)",
                    "Risk quants (SR 11-7, IRB)",
                    "Privacy & legal (DPO, GC office)",
                    "Regulator liaison",
                ],
            },
            {
                "id": "M13-S3",
                "title": "Top Risks & Mitigations",
                "risks": [
                    {"risk": "Capability discontinuity", "mitigation": "Frontier sandbox, eval gating, kill-switch"},
                    {"risk": "Regulatory divergence", "mitigation": "Multi-overlay AIMS + federation"},
                    {"risk": "Supply-chain compromise", "mitigation": "SLSA L3 + Sigstore + in-toto"},
                    {"risk": "Talent gap", "mitigation": "Internal academy + Codex Charter"},
                    {"risk": "Cultural drift", "mitigation": "Codex sealing/renewal rituals"},
                ],
            },
        ],
    }


def m14_audience_artifacts():
    return {
        "id": "M14",
        "title": "M14 — Audience-Tailored Deliverables & Artifacts",
        "summary": "Per-audience artifacts: C-suite, regulators, enterprise architects, AI platform engineers, AI safety researchers.",
        "sections": [
            {
                "id": "M14-S1",
                "title": "C-Suite Pack",
                "items": ["Board narrative", "KPI cockpit", "Risk heatmap", "Capital overlay summary", "Codex Charter ceremony brief"],
            },
            {
                "id": "M14-S2",
                "title": "Regulator Pack",
                "items": ["RSP v1.0-v2.6", "Trust Contract API doc", "JSOP spec", "Federated query simulation", "Decision envelope viewer (read-only)"],
            },
            {
                "id": "M14-S3",
                "title": "Enterprise Architect Pack",
                "items": ["8-plane reference architecture diagrams", "Kafka WORM ACL spec", "Docker Swarm hardening checklist", "Sidecar contract", "Next.js XAI design system"],
            },
            {
                "id": "M14-S4",
                "title": "AI Platform Engineer Pack",
                "items": ["EAIP repo templates", "OPA policy bundles", "Terraform modules", "CI/CD gate scripts", "Sentinel v2.4 SDK"],
            },
            {
                "id": "M14-S5",
                "title": "AI Safety Researcher Pack",
                "items": ["Frontier eval suite", "Red-team playbooks", "Alignment artifacts", "TLA+/Lean specs", "EO 14110 disclosure templates"],
            },
        ],
    }


def schemas():
    return {
        "aiSystemInventoryEntry": {"title": "AI System Inventory Entry (ISO/IEC 42001 Annex J1)",
                                    "fields": ["systemId", "owner", "purpose", "tier", "dataClassification", "regulatoryScope", "lifecycleStage"]},
        "decisionEnvelope": {"title": "Decision Envelope (per AI decision)",
                             "fields": ["decisionId", "modelId", "inputs", "outputs", "explanation", "policyEvaluation", "signature"]},
        "rspManifest": {"title": "Regulator Submission Pack Manifest",
                        "fields": ["rspId", "version", "regulator", "artifacts[]", "signatures", "rekorAnchor"]},
        "controlMapping": {"title": "Control Mapping (cross-regime)",
                           "fields": ["controlId", "ifGdpr", "ifEuAiAct", "ifIso42001", "ifNistRmf", "ifSr117", "ifEo14110", "evidence"]},
        "friaRecord": {"title": "Fundamental Rights Impact Assessment",
                       "fields": ["friaId", "systemId", "rightsImpacted", "mitigations", "residualRisk", "approver"]},
        "incidentRecord": {"title": "AI Incident Record",
                           "fields": ["incidentId", "severity", "detectedAt", "containedAt", "rca", "regulatorNotification"]},
        "supervisoryKpiSnapshot": {"title": "Supervisory KPI Snapshot",
                                    "fields": ["snapshotId", "asOf", "kpis[]", "thresholds", "breaches[]"]},
        "trustContract": {"title": "Trust Contract (regulator API)",
                          "fields": ["contractId", "regulator", "scope", "obligations", "expiry", "signatures"]},
        "obligationSpec": {"title": "Formally Verified Obligation Spec (TLA+/Lean)",
                           "fields": ["specId", "regime", "article", "tlaModule", "leanTheorem", "proofStatus"]},
        "kafkaAclEntry": {"title": "Kafka WORM ACL Entry",
                          "fields": ["principal", "host", "operation", "resource", "permission", "expiry"]},
    }


def code_examples():
    return [
        {"id": "CE-01", "title": "OPA/Rego policy gate", "language": "rego", "lines": 32},
        {"id": "CE-02", "title": "Terraform Kafka WORM module (Object Lock 10y)", "language": "hcl", "lines": 38},
        {"id": "CE-03", "title": "Docker Swarm hardened service stack", "language": "yaml", "lines": 46},
        {"id": "CE-04", "title": "Node.js governance sidecar (Express + Kafka producer)", "language": "javascript", "lines": 52},
        {"id": "CE-05", "title": "Python governance sidecar (FastAPI + FRIA evaluator)", "language": "python", "lines": 48},
        {"id": "CE-06", "title": "Next.js decision-envelope viewer (RSC + SHAP)", "language": "tsx", "lines": 60},
        {"id": "CE-07", "title": "Federated regulator client (mTLS + SPIFFE)", "language": "python", "lines": 42},
        {"id": "CE-08", "title": "GitHub Actions governance gate (SAST + SBOM + Cosign + OPA)", "language": "yaml", "lines": 56},
        {"id": "CE-09", "title": "TLA+ obligation graph (EU AI Act Art. 73)", "language": "tla", "lines": 24},
        {"id": "CE-10", "title": "Lean FCRA §615 spec", "language": "lean", "lines": 18},
        {"id": "CE-11", "title": "Self-healing playbook engine", "language": "python", "lines": 50},
        {"id": "CE-12", "title": "Merkle anchor + Rekor submission", "language": "python", "lines": 28},
    ]


def case_studies():
    return [
        {"id": "CS-01", "title": "EU G-SIB dual ISO/IEC 42001 + EU AI Act 2026 cert",
         "outcome": "Certified Q3 2026; RSP automation 92%; Sentinel v2.4 + EAIP live"},
        {"id": "CS-02", "title": "US BHC US EO 14110 dual-use foundation model reporting",
         "outcome": "First quarterly red-team disclosure delivered; AISI engagement live"},
        {"id": "CS-03", "title": "UK PRA SS1/23 + FCA Consumer Duty integrated MRM",
         "outcome": "Adverse-action SLA 18h; AIR 0.91; SMF24 sign-off automated"},
        {"id": "CS-04", "title": "MAS FEAT + HKMA GenAI APAC roll-out",
         "outcome": "8-region active-active live; Veritas alignment report delivered"},
        {"id": "CS-05", "title": "Joint ECB+Fed+PRA examination drill",
         "outcome": "Pass; <30 min RSP regen; deterministic replay across 3 supervisors"},
        {"id": "CS-06", "title": "Frontier T3 containment exercise",
         "outcome": "Kill-switch 42s; zero-egress sandbox; red-team disclosure to USG/UK AISI"},
    ]


def api_endpoints():
    base = "/api/ent-agi-ref-impl"
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
    sub = {
        "governance": ["pillars", "executives", "committees-raci"],
        "regulatory": ["crosswalk", "controls", "eo14110", "capital-overlay"],
        "architecture": ["planes", "kafka-worm", "docker-swarm", "sidecars", "nextjs-xai", "opa", "terraform-cicd"],
        "sector-mrm": ["credit", "trading", "risk", "fiduciary", "tiers"],
        "safety": ["tiers", "containment", "alignment", "scenarios"],
        "global": ["icgc", "treaty", "federation"],
        "sentinel": ["capabilities", "integration", "deployment"],
        "workflowai": ["recommendation", "rag", "prompts", "safety-reports", "gemini-security"],
        "eaip": ["registry", "cicd-gates", "evidence", "rsp-generator"],
        "hub": ["surfaces", "personas", "analytics"],
        "kpis": ["catalogue", "self-verify", "audit-replay"],
        "incident": ["severity", "loop", "playbooks", "notification"],
        "roadmap": ["phases", "resources", "risks"],
        "audience": ["c-suite", "regulator", "architect", "engineer", "researcher"],
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
    return {
        "meta": meta(),
        "executiveSummary": executive_summary(),
        "M1_governance": m1_governance_architecture(),
        "M2_regulatory": m2_regulatory(),
        "M3_architecture": m3_reference_architecture(),
        "M4_sectorMrm": m4_sector_mrm(),
        "M5_safety": m5_safety_containment(),
        "M6_global": m6_global_compute(),
        "M7_sentinel": m7_sentinel_v24(),
        "M8_workflowai": m8_workflowai_pro(),
        "M9_eaip": m9_eaip(),
        "M10_hub": m10_governance_hub(),
        "M11_kpis": m11_kpis_self_verifying(),
        "M12_incident": m12_incident_adversarial(),
        "M13_roadmap": m13_roadmap_resources(),
        "M14_audience": m14_audience_artifacts(),
        "schemas": schemas(),
        "codeExamples": code_examples(),
        "caseStudies": case_studies(),
        "apiEndpoints": api_endpoints(),
    }


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
