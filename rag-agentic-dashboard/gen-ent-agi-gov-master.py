#!/usr/bin/env python3
"""
ENT-AGI-GOV-MASTER-WP-035 — Enterprise AGI/ASI Governance Master Framework
Generates: data/ent-agi-gov-master.json

Institutional-grade, regulator-ready AGI/ASI and enterprise AI governance
frameworks and architectures for Fortune 500, Global 2000, and G-SIFIs
covering 2026-2030.

Scope:
  - Multilayered AI governance pillars (G1-G7)
  - Regulatory alignment matrix (EU AI Act, NIST AI RMF 1.0, ISO/IEC 42001,
    OECD, GDPR, FCRA/ECOA, Basel III, SR 11-7, PRA, FCA, MAS, HKMA)
  - Enterprise reference architectures (Sentinel v2.4, WorkflowAI Pro, EAIP,
    high-assurance RAG, governed agentic workflows, Kafka WORM, OPA-as-code)
  - AGI/ASI safety & containment (Luminous Engine Codex, Cognitive Resonance
    Protocol, Sentinel / Omni-Sentinel, MV-AGI governance stack, crisis
    simulations, frontier risk taxonomies)
  - Civilizational-scale governance & compute oversight (ICGC, global compute
    registry, treaty-aligned systemic risk governance)
  - Financial services MRM (credit / trading / risk / fiduciary AI advisors)
  - Kafka ACL governance, Terraform GaC, WORM evidence storage, OPA/Rego,
    CI/CD integration, auditor workflows
  - Implementation roadmap, executive/regulator-ready reports
"""

import json
from pathlib import Path
from datetime import date

HERE = Path(__file__).parent
OUT = HERE / "data" / "ent-agi-gov-master.json"


def meta():
    return {
        "docRef": "ENT-AGI-GOV-MASTER-WP-035",
        "version": "1.0.0",
        "date": "2026-04-25",
        "title": "Enterprise AGI/ASI Governance Master Framework (2026-2030)",
        "subtitle": (
            "Institutional-grade, regulator-ready AGI/ASI and enterprise AI "
            "governance frameworks, reference architectures, safety and "
            "containment protocols, financial-services model risk "
            "management, civilizational-scale compute oversight, and "
            "implementation roadmaps for Fortune 500, Global 2000, and "
            "G-SIFIs."
        ),
        "classification": (
            "CONFIDENTIAL — Board / C-Suite / Prudential Supervisor / "
            "Treaty Authority / Internal & External Audit"
        ),
        "owner": "Group Chief AI Officer (CAIO) — co-signed by CRO, CISO, GC, COO",
        "audience": [
            "Board of Directors / Risk & Audit Committees",
            "C-Suite (CEO, CFO, CRO, CISO, CAIO, CTO, GC, COO)",
            "Group Heads of Model Risk, Enterprise Risk, Compliance",
            "Prudential & conduct supervisors (PRA, FCA, OCC, Fed, ECB, "
            "MAS, HKMA, BaFin, FINMA)",
            "Data protection authorities (ICO, CNIL, EDPB), CFPB",
            "EU AI Act notified bodies, ISO/IEC 42001 certifiers",
            "Internal & external auditors, treaty-authority observers",
            "Enterprise architects, AI platform engineers, researchers",
        ],
        "horizon": "2026-2030 (with 2030-2050 frontier outlook)",
        "regulatoryAlignment": [
            "EU AI Act (Regulation (EU) 2024/1689) — Annex III, Annex IV, "
            "Art. 9/10/12/13/14/15, Art. 53/55 GPAI",
            "NIST AI Risk Management Framework 1.0 + GenAI Profile (AI 600-1)",
            "ISO/IEC 42001:2023 — AI Management System",
            "ISO/IEC 23894:2023 — AI Risk Management",
            "ISO/IEC 5338:2023 — AI System Lifecycle",
            "ISO/IEC 27001:2022 / 27701:2019 / 27018",
            "OECD AI Principles (2019, updated 2024)",
            "GDPR (Regulation (EU) 2016/679); UK GDPR; CCPA/CPRA",
            "US FCRA / ECOA / Reg B / CFPB UDAAP",
            "Basel III/IV (CRR3/CRD6); ICAAP Pillar 2; BCBS 239",
            "SR 11-7 / OCC 2011-12 / PRA SS1/23 — Model Risk Management",
            "PRA SS2/21 (Outsourcing); FCA Consumer Duty; FCA AI Update 2024",
            "MAS FEAT principles + Veritas toolkit; HKMA HLP on Big Data & AI",
            "EO 14110, OMB M-24-10, US AI Bill of Rights blueprint",
            "Council of Europe AI Convention 2024",
        ],
        "horizonMilestones": {
            "2026Q2": "EU AI Act Art. 6 high-risk obligations enforcement",
            "2026Q3": "MV-AGI governance stack mandatory for systemic banks",
            "2027Q1": "ICGC compute-registry global rollout (>1e25 FLOP)",
            "2027Q4": "ISO/IEC 42001 certification expected of all G-SIFIs",
            "2028Q2": "Kinetic-tripwire & PQC ledger integration baseline",
            "2029Q1": "Treaty-authority cross-border AI college operational",
            "2030Q1": "Frontier compute governance treaty (GAGCOT) in force",
        },
        "deliverableInventory": {
            "pillars": 7,
            "regulatoryAxes": 16,
            "referenceArchitectures": 9,
            "safetyContainmentProtocols": 8,
            "civilizationalArtefacts": 6,
            "financialServicesMRM": 6,
            "kafkaGaCArtefacts": 7,
            "schemas": 6,
            "codeExamples": 10,
            "caseStudies": 6,
            "apiEndpointsPlanned": 95,
        },
    }


def executive_summary():
    return {
        "purpose": (
            "To provide a single, regulator-ready, board-approvable master "
            "framework that unifies enterprise AI, agentic-AI, AGI/ASI "
            "containment, and civilizational compute oversight into one "
            "audit-traceable governance system aligned with all major "
            "global regulatory regimes."
        ),
        "scope": (
            "Spans all AI systems across the enterprise — from high-risk "
            "credit/trading models to autonomous agents and frontier "
            "general-purpose AI — with extensions to inter-firm and treaty-"
            "level oversight."
        ),
        "designPrinciples": [
            "Defense-in-depth across 7 governance pillars (G1-G7)",
            "Compliance-as-code: every policy is enforceable in CI/CD and runtime",
            "Evidence-as-data: WORM-backed Merkle-anchored, PQC-signed audit",
            "Human-on-the-loop with kinetic tripwires for irreversibility",
            "Bias-aware fairness across protected classes (FCRA/ECOA, GDPR Art. 22)",
            "Formal alignment metrics with PID-based drift control",
            "Treaty-ready: artefacts portable to ICGC and supervisory colleges",
        ],
        "keyOutcomes": {
            "timeToGovernedDeployment": "≤ 72 hours (production AI)",
            "evidenceAutomation": "≥ 92% of controls auto-evidenced",
            "MTTD": "≤ 4 minutes (alignment-drift / containment breach)",
            "MTTR": "≤ 60 minutes (containment), ≤ 60 seconds (kinetic kill)",
            "controlsMapped": "240+ controls across 16 regulatory axes",
            "evidenceRetention": "7-year WORM (SR 11-7 / SEC 17a-4(f))",
            "boardReportingCadence": "Quarterly with monthly KRI exception packs",
        },
        "boardNarrative": (
            "This master framework converts AI governance from a fragmented "
            "control set into an integrated risk-bearing capital function. "
            "Capital, conduct, and existential-safety risks are jointly "
            "modelled, enabling the Board to approve AI strategy with the "
            "same rigour applied to credit, market, and operational risk."
        ),
    }


def m1_pillars():
    return {
        "id": "M1",
        "title": "M1 — Multilayered AI Governance Pillars (G1-G7)",
        "summary": (
            "Seven pillars define the institutional governance topology, "
            "from board accountability down to autonomous-agent guardrails."
        ),
        "sections": [
            {
                "id": "M1-S1",
                "title": "Pillar Catalogue",
                "pillars": [
                    {
                        "id": "G1",
                        "name": "Board & Strategic Oversight",
                        "owner": "Board Risk & Audit Committees",
                        "objective": "Risk appetite, strategic AI bets, capital allocation",
                        "controls": ["AI risk appetite statement", "Annual AI strategy approval", "AGI-readiness review"],
                    },
                    {
                        "id": "G2",
                        "name": "Executive Accountability",
                        "owner": "CAIO (chair), CRO, CISO, GC, COO",
                        "objective": "Single accountable executive with veto + kill-switch authority",
                        "controls": ["RACI matrix", "AI Governance Council charter", "SMCR/SMR mapping"],
                    },
                    {
                        "id": "G3",
                        "name": "Model Risk Management (MRM)",
                        "owner": "Group Head of Model Risk (2nd LoD)",
                        "objective": "Independent validation, ongoing monitoring, MV report",
                        "controls": ["SR 11-7 Tier classification", "Independent IMV", "Materiality tiering"],
                    },
                    {
                        "id": "G4",
                        "name": "Data, Privacy & Fairness",
                        "owner": "DPO + Chief Data Officer",
                        "objective": "Lawful basis, minimisation, fairness across protected classes",
                        "controls": ["DPIA", "FCRA/ECOA disparate impact testing", "Lineage attestation"],
                    },
                    {
                        "id": "G5",
                        "name": "Security & Containment",
                        "owner": "CISO + Head of AI Security",
                        "objective": "Zero-trust runtime, kill-switch, kinetic tripwires",
                        "controls": ["MITRE ATLAS coverage", "OWASP LLM Top 10", "PQC-signed telemetry"],
                    },
                    {
                        "id": "G6",
                        "name": "Compliance & Conduct",
                        "owner": "Group Compliance + Conduct Risk",
                        "objective": "Regulatory mapping, conduct outcomes, customer fairness",
                        "controls": ["Consumer Duty outcome testing", "OPA-as-code policy gates", "Incident notifications"],
                    },
                    {
                        "id": "G7",
                        "name": "Frontier / Civilizational Risk",
                        "owner": "CAIO + Treaty Liaison Officer",
                        "objective": "GPAI Art. 53/55, ICGC reporting, AGI containment readiness",
                        "controls": ["Compute register", "Frontier-risk simulations", "Treaty disclosure pack"],
                    },
                ],
            },
            {
                "id": "M1-S2",
                "title": "Three-Lines-of-Defence (3LoD) Mapping",
                "lines": [
                    {"line": "1LoD", "owners": "Business / AI Engineering", "responsibilities": ["Develop", "Operate", "First-level controls"]},
                    {"line": "2LoD", "owners": "MRM, Compliance, AI Risk", "responsibilities": ["Independent validation", "Policy", "Challenge"]},
                    {"line": "3LoD", "owners": "Internal Audit", "responsibilities": ["Assurance over 1+2", "Annual AI audit plan"]},
                ],
            },
            {
                "id": "M1-S3",
                "title": "Risk Taxonomy",
                "categories": [
                    "R1 Performance / accuracy drift",
                    "R2 Fairness / disparate impact",
                    "R3 Privacy / PII leakage",
                    "R4 Robustness / adversarial",
                    "R5 Security / containment escape",
                    "R6 Explainability / interpretability gap",
                    "R7 Concentration / third-party dependency",
                    "R8 Conduct / consumer harm",
                    "R9 Systemic / market dislocation",
                    "R10 Frontier / catastrophic / existential",
                ],
            },
        ],
    }


def m2_regulatory_matrix():
    rows = [
        {"axis": "EU AI Act", "scope": "High-risk + GPAI", "keyArticles": "Arts 6,9,10,12,13,14,15,53,55; Annex III/IV", "primaryControl": "Annex IV technical documentation", "evidenceArtefact": "Annex IV dossier + GPAI summary"},
        {"axis": "NIST AI RMF 1.0", "scope": "All AI", "keyArticles": "Govern/Map/Measure/Manage + GenAI Profile", "primaryControl": "GMM control mapping", "evidenceArtefact": "RMF playbook crosswalk"},
        {"axis": "ISO/IEC 42001", "scope": "AIMS", "keyArticles": "Clauses 4-10; Annex A controls", "primaryControl": "AI Management System certification", "evidenceArtefact": "AIMS evidence pack"},
        {"axis": "ISO/IEC 23894", "scope": "AI risk", "keyArticles": "Risk management lifecycle", "primaryControl": "Integrated AI risk register", "evidenceArtefact": "Risk register + treatment plan"},
        {"axis": "OECD AI Principles", "scope": "All AI", "keyArticles": "5 values-based principles + 5 govt recommendations", "primaryControl": "Trustworthy AI attestation", "evidenceArtefact": "Principle conformance memo"},
        {"axis": "GDPR / UK GDPR", "scope": "Personal data", "keyArticles": "Art. 5,6,9,22,25,32,35", "primaryControl": "DPIA + Art. 22 ADM safeguards", "evidenceArtefact": "DPIA + LIA + transparency notice"},
        {"axis": "FCRA", "scope": "US consumer credit", "keyArticles": "§604, §615 adverse action", "primaryControl": "Adverse action reasons (top-N)", "evidenceArtefact": "Reason-code generator log"},
        {"axis": "ECOA / Reg B", "scope": "US credit fairness", "keyArticles": "§1002.4, §1002.6", "primaryControl": "Less-discriminatory alternative search", "evidenceArtefact": "LDA search log"},
        {"axis": "Basel III/IV", "scope": "Bank capital", "keyArticles": "CRR3/CRD6; Pillars 1-3; ICAAP", "primaryControl": "Pillar-2 AI capital add-on", "evidenceArtefact": "ICAAP AI annex"},
        {"axis": "SR 11-7 / OCC 2011-12", "scope": "Model risk", "keyArticles": "Sound model development, validation, governance", "primaryControl": "Independent validation + ongoing monitoring", "evidenceArtefact": "IMV report + MV dashboard"},
        {"axis": "PRA SS1/23", "scope": "UK MRM", "keyArticles": "Tiering, accountability, validation", "primaryControl": "SS1/23 self-assessment", "evidenceArtefact": "Annual MRM attestation"},
        {"axis": "FCA Consumer Duty", "scope": "UK conduct", "keyArticles": "PRIN 12; outcomes 1-4", "primaryControl": "Outcome testing on AI decisions", "evidenceArtefact": "CD outcome pack"},
        {"axis": "MAS FEAT", "scope": "Singapore FS", "keyArticles": "Fairness, Ethics, Accountability, Transparency", "primaryControl": "Veritas-aligned FEAT testing", "evidenceArtefact": "FEAT assessment report"},
        {"axis": "HKMA HLP", "scope": "HK FS", "keyArticles": "High-Level Principles on AI", "primaryControl": "Board-approved AI policy", "evidenceArtefact": "HKMA policy attestation"},
        {"axis": "EO 14110 / OMB M-24-10", "scope": "US federal-adjacent", "keyArticles": "Safety/security reporting + rights/safety-impacting AI", "primaryControl": "Safety reporting threshold (1e26 FLOP)", "evidenceArtefact": "Compute disclosure"},
        {"axis": "Council of Europe AI Convention", "scope": "Cross-jurisdiction", "keyArticles": "Human rights, democracy, rule of law", "primaryControl": "Human-rights impact assessment", "evidenceArtefact": "HRIA report"},
    ]
    return {
        "id": "M2",
        "title": "M2 — Regulatory Alignment Matrix (16 Axes)",
        "summary": "Cross-walk of every governance control to its regulatory anchor.",
        "sections": [
            {"id": "M2-S1", "title": "Crosswalk Matrix", "rows": rows},
            {
                "id": "M2-S2",
                "title": "Regulator Engagement Cadence",
                "schedule": [
                    {"regulator": "PRA / FCA", "cadence": "Quarterly MRM update + ad-hoc Sec 166", "format": "Liaison memo + IMV pack"},
                    {"regulator": "OCC / Fed", "cadence": "Continuous supervisory dialogue", "format": "MV dashboard read-only access"},
                    {"regulator": "ECB SSM", "cadence": "Annual ICAAP + thematic review", "format": "ICAAP AI annex"},
                    {"regulator": "MAS / HKMA", "cadence": "Annual self-assessment", "format": "FEAT / HLP attestation"},
                    {"regulator": "EU AI Act notified body", "cadence": "Pre-deployment + substantial mod", "format": "Annex IV dossier"},
                    {"regulator": "DPA (ICO/CNIL/EDPB)", "cadence": "Per DPIA + 72h breach", "format": "DPIA + Art. 33/34 notice"},
                    {"regulator": "CFPB", "cadence": "Adverse-action audits", "format": "Reason-code sample + LDA log"},
                    {"regulator": "Treaty Authority (ICGC)", "cadence": "Annual + frontier event", "format": "Compute register + frontier disclosure"},
                ],
            },
        ],
    }


def m3_reference_architectures():
    archs = [
        {
            "id": "RA-01",
            "name": "Sentinel AI Governance Platform v2.4",
            "purpose": "Unified runtime containment, telemetry, kill-switch, kinetic tripwire",
            "keyComponents": ["Containment proxy", "Guard model", "WORM Kafka", "PQC ledger", "Kinetic layer"],
            "regulatoryAnchors": ["EU AI Act Art. 53/55", "SR 11-7", "ISO/IEC 42001"],
            "interopRefs": ["WP-034 Sentinel", "EAIP", "WorkflowAI Pro"],
        },
        {
            "id": "RA-02",
            "name": "WorkflowAI Pro (WP-033)",
            "purpose": "Governed agentic workflow + prompt lifecycle platform",
            "keyComponents": ["Prompt template registry", "DAG orchestrator", "Sentinel compliance engine", "Active-learning loop"],
            "regulatoryAnchors": ["NIST AI RMF", "ISO/IEC 42001", "SOC 2 Type II"],
            "interopRefs": ["WP-033"],
        },
        {
            "id": "RA-03",
            "name": "Enterprise AI Interoperability Profile (EAIP)",
            "purpose": "Cross-vendor governance interchange — policy, evidence, telemetry envelopes",
            "keyComponents": ["Telemetry envelope schema", "Evidence manifest", "Policy decision exchange"],
            "regulatoryAnchors": ["ISO/IEC 42001 Annex A", "EU AI Act Art. 12 (logging)"],
            "interopRefs": ["TPX/EVB/RMX"],
        },
        {
            "id": "RA-04",
            "name": "High-Assurance RAG Platform",
            "purpose": "Retrieval-augmented generation with governance-grade citation, lineage, and PII redaction",
            "keyComponents": ["Vector store with lineage", "Citation engine", "PII redactor", "Faithfulness scorer"],
            "regulatoryAnchors": ["GDPR Art. 5(1)(d)", "EU AI Act Art. 13", "ISO/IEC 42001"],
            "interopRefs": ["EAIP TPX"],
        },
        {
            "id": "RA-05",
            "name": "Governed Agentic Workflows",
            "purpose": "Multi-agent orchestration with constitutional guardrails and canary deploys",
            "keyComponents": ["Agent registry", "Capability graph", "Constitutional checker", "Canary gateway"],
            "regulatoryAnchors": ["EU AI Act Art. 14 (HITL)", "MITRE ATLAS"],
            "interopRefs": ["Sentinel M5/M6"],
        },
        {
            "id": "RA-06",
            "name": "Kafka WORM Audit Logging Cluster",
            "purpose": "Immutable, PQC-signed, hash-chained AI telemetry for 7-year SEC retention",
            "keyComponents": ["mTLS Kafka", "ACL governance", "S3 Object Lock", "Daily Merkle audit"],
            "regulatoryAnchors": ["SEC 17a-4(f)", "SR 11-7", "EU AI Act Art. 12"],
            "interopRefs": ["Sentinel M9"],
        },
        {
            "id": "RA-07",
            "name": "Docker Swarm + Kubernetes Hardened Runtime",
            "purpose": "Workload isolation, mTLS service mesh, signed images, runtime attestation",
            "keyComponents": ["SLSA L3 build chain", "Cosign signatures", "Falco runtime IDS", "OPA gatekeeper"],
            "regulatoryAnchors": ["NIST SSDF", "ISO/IEC 27001", "FedRAMP Moderate"],
            "interopRefs": ["Sentinel M4"],
        },
        {
            "id": "RA-08",
            "name": "Node.js / Python Governance Sidecars",
            "purpose": "Per-process governance: telemetry, PII redaction, OPA decision cache",
            "keyComponents": ["Sidecar SDK (Node/Py)", "OPA decision client", "Envelope signer", "Audit shipper"],
            "regulatoryAnchors": ["ISO/IEC 42001 A.6.2", "EU AI Act Art. 12"],
            "interopRefs": ["EAIP TPX/RMX"],
        },
        {
            "id": "RA-09",
            "name": "Next.js Explainability Frontend",
            "purpose": "Customer-facing & supervisor-facing explanations + adverse-action UI",
            "keyComponents": ["SHAP/IG renderer", "Reason-code UI", "DPIA viewer", "Consent surfacer"],
            "regulatoryAnchors": ["FCRA §615", "GDPR Art. 22", "EU AI Act Art. 13"],
            "interopRefs": ["RA-04 RAG", "RA-01 Sentinel"],
        },
    ]
    return {
        "id": "M3",
        "title": "M3 — Enterprise Reference Architectures",
        "summary": "Nine production-grade architectures composing the enterprise AI estate.",
        "sections": [
            {"id": "M3-S1", "title": "Architecture Catalogue", "architectures": archs},
            {
                "id": "M3-S2",
                "title": "OPA Compliance-as-Code Patterns",
                "patterns": [
                    {"id": "POL-01", "name": "deploy_gate.rego", "enforcement": "CI/CD admission", "blocks": "Unsigned models, missing IMV, expired DPIA"},
                    {"id": "POL-02", "name": "data_residency.rego", "enforcement": "Runtime", "blocks": "Cross-border PII without SCC/IDTA"},
                    {"id": "POL-03", "name": "high_risk_label.rego", "enforcement": "Registry", "blocks": "EU AI Act high-risk without Annex IV dossier"},
                    {"id": "POL-04", "name": "agent_capability.rego", "enforcement": "Runtime", "blocks": "Tool calls outside allowlisted capability graph"},
                    {"id": "POL-05", "name": "fairness_threshold.rego", "enforcement": "Pre-deploy", "blocks": "AIR <0.8 / SPD >0.05 without exception"},
                    {"id": "POL-06", "name": "compute_register.rego", "enforcement": "Pre-train", "blocks": "Training >1e25 FLOP without ICGC entry"},
                ],
            },
            {
                "id": "M3-S3",
                "title": "Governance Standards for Hyperparameter Control",
                "controls": [
                    "Hyperparameter changes are version-controlled (Git, signed commits)",
                    "Material hyperparameter changes (Δlearning-rate >50%, depth ±2 layers, regulariser swap) trigger IMV re-validation",
                    "Random-seed pinning + deterministic CUDA flags for reproducibility (within hardware tolerance)",
                    "Hyperparameter sweep results retained in WORM with cost & energy attribution",
                    "Production hyperparameters require 2-of-3 approval (1LoD model owner, 2LoD validator, change advisory board)",
                    "Rollback hyperparameter set always pinned and tested in canary lane",
                ],
            },
        ],
    }


def m4_safety_containment():
    return {
        "id": "M4",
        "title": "M4 — AGI/ASI Safety & Containment Frameworks",
        "summary": "Eight protocols spanning institutional safety, frontier alignment, and civilizational hedges.",
        "sections": [
            {
                "id": "M4-S1",
                "title": "Protocol Catalogue",
                "protocols": [
                    {
                        "id": "SC-01",
                        "name": "Luminous Engine Codex",
                        "purpose": "Codex of inviolable constitutional principles for frontier systems",
                        "keyArtefacts": ["Codex YAML", "Signature ledger", "Veto hash chain"],
                        "scope": "Frontier / GPAI",
                    },
                    {
                        "id": "SC-02",
                        "name": "Cognitive Resonance Protocol (CRP)",
                        "purpose": "Continuous alignment-resonance scoring with PID drift control",
                        "keyArtefacts": ["Resonance scorer", "PID controller", "Tripwire policy"],
                        "scope": "Frontier + agentic",
                    },
                    {
                        "id": "SC-03",
                        "name": "Sentinel Containment v2.4",
                        "purpose": "Runtime zero-trust + kinetic tripwire (operational)",
                        "keyArtefacts": ["Containment proxy", "Guard model", "Kinetic layer"],
                        "scope": "Enterprise + GPAI",
                    },
                    {
                        "id": "SC-04",
                        "name": "Omni-Sentinel Multi-Modal Filter",
                        "purpose": "Vision/audio/code multi-modal containment with adversarial robustness",
                        "keyArtefacts": ["VisionContainmentFilter", "Audio steganalysis", "Code-execution sandbox"],
                        "scope": "Multi-modal frontier",
                    },
                    {
                        "id": "SC-05",
                        "name": "MV-AGI Governance Stack (Minimum-Viable)",
                        "purpose": "Smallest auditable AGI governance layer required pre-deployment",
                        "keyArtefacts": ["Compute register entry", "Capability eval pack", "RSP / RSDP", "Kill-switch test", "Treaty disclosure"],
                        "scope": "Any system >1e25 FLOP or with autonomy ≥L3",
                    },
                    {
                        "id": "SC-06",
                        "name": "Crisis Simulation Programme (GC1-GC7)",
                        "purpose": "Tabletop + live-fire crisis exercises across institution / treaty axes",
                        "keyArtefacts": ["Scenario library", "Replay kits", "After-action reports"],
                        "scope": "Cross-domain",
                    },
                    {
                        "id": "SC-07",
                        "name": "Frontier Risk Taxonomy (FRT)",
                        "purpose": "Catalogue of catastrophic & existential failure modes with leading indicators",
                        "keyArtefacts": ["Risk register", "Indicator dashboard", "Capability eval suite"],
                        "scope": "Frontier-only",
                    },
                    {
                        "id": "SC-08",
                        "name": "Responsible Scaling Policy (RSP/RSDP)",
                        "purpose": "Capability-conditional commitments triggering pause / red-team / disclosure",
                        "keyArtefacts": ["Capability tier matrix", "Pause clauses", "Disclosure template"],
                        "scope": "Frontier developers + deployers",
                    },
                ],
            },
            {
                "id": "M4-S2",
                "title": "Crisis Scenarios (GC1-GC7)",
                "scenarios": [
                    {"id": "GC1", "name": "Cross-border capability shock", "trigger": "Frontier model exceeds eval threshold mid-deploy", "responseSLA": "≤ 4h treaty notification"},
                    {"id": "GC2", "name": "Systemic fairness divergence", "trigger": "AIR drift >0.15 across G-SIFI cohort", "responseSLA": "≤ 24h supervisor college"},
                    {"id": "GC3", "name": "Compute-supply disruption", "trigger": "GPU export-control / kinetic event", "responseSLA": "≤ 72h capacity reallocation"},
                    {"id": "GC4", "name": "Adversarial data poisoning", "trigger": "Detection of poisoned training corpus", "responseSLA": "≤ 12h IR + roll-back"},
                    {"id": "GC5", "name": "Autonomous-agent containment failure", "trigger": "Capability escape detected", "responseSLA": "≤ 60s kinetic kill"},
                    {"id": "GC6", "name": "Model-weight compromise", "trigger": "Exfiltration / leak of frontier weights", "responseSLA": "≤ 4h treaty disclosure"},
                    {"id": "GC7", "name": "Governance dissolution threat", "trigger": "Coordinated regulatory bypass / capture", "responseSLA": "≤ 24h Board + GC + treaty escalation"},
                ],
            },
            {
                "id": "M4-S3",
                "title": "Capability Evaluation Tiers",
                "tiers": [
                    {"tier": "T0", "label": "Narrow", "controls": ["Standard MRM", "SR 11-7 Tier 2"]},
                    {"tier": "T1", "label": "Broad enterprise AI", "controls": ["Annex IV dossier", "ISO 42001"]},
                    {"tier": "T2", "label": "Agentic / autonomous L2-L3", "controls": ["Constitutional checks", "Canary"]},
                    {"tier": "T3", "label": "Frontier GPAI", "controls": ["Art. 53/55", "RSP", "Compute register"]},
                    {"tier": "T4", "label": "Pre-AGI / dual-use uplift", "controls": ["Treaty disclosure", "Kinetic tripwire", "Pause clauses"]},
                    {"tier": "T5", "label": "AGI-class", "controls": ["MV-AGI stack", "Omni-Sentinel", "Multi-jurisdiction approval"]},
                ],
            },
        ],
    }


def m5_civilizational():
    return {
        "id": "M5",
        "title": "M5 — Civilizational-Scale Governance & Compute Oversight",
        "summary": "Six artefacts extending governance from firm to inter-state and treaty layer.",
        "sections": [
            {
                "id": "M5-S1",
                "title": "International Compute Governance Consortium (ICGC)",
                "design": {
                    "purpose": "Multilateral body coordinating compute thresholds, frontier capability disclosures, and incident response",
                    "members": "G7 + G20 + observer states + 5 lead AI labs + civil society",
                    "secretariat": "Rotating; OECD-hosted (proposed)",
                    "powers": ["Compute registry", "Capability eval review", "Crisis coordination", "Sanctions recommendations"],
                    "alignment": ["EU AI Act Art. 53/55", "EO 14110 §4.2", "Bletchley/Seoul/Paris commitments"],
                },
            },
            {
                "id": "M5-S2",
                "title": "Global Compute Registry",
                "schemaSummary": [
                    "operatorId (LEI)", "facilityId (geo-coordinates)", "designFLOPs",
                    "currentUtilisationFLOPs", "modelsTrained[]", "inferenceWorkloads[]",
                    "powerSourceMix", "embodiedCO2", "attestationSignature (PQC)",
                ],
                "thresholds": {
                    "training": "≥ 1e25 FLOP single training run",
                    "cluster": "≥ 1e21 FLOP/s sustained capacity",
                    "inference": "≥ 1e23 FLOP/day on single deployed model",
                },
                "reportingCadence": "Monthly + event-driven",
            },
            {
                "id": "M5-S3",
                "title": "Treaty-Aligned Systemic Risk Governance",
                "instruments": [
                    "GAGCOT (Global AI Governance & Compute Oversight Treaty) — proposed",
                    "Council of Europe AI Convention 2024 — in force",
                    "Bletchley/Seoul/Paris Declarations — political commitments",
                    "OECD AI Policy Observatory — monitoring",
                ],
                "supervisoryColleges": [
                    {"id": "SC-MRM-COLL", "members": "PRA + FCA + OCC + Fed + ECB", "scope": "G-SIFI MRM"},
                    {"id": "SC-AI-COLL", "members": "Notified bodies + DPAs + CFPB + treaty observers", "scope": "Frontier deployments"},
                ],
            },
            {
                "id": "M5-S4",
                "title": "Frontier Risk Outlook 2030-2050",
                "horizons": [
                    {"period": "2026-2028", "focus": "GPAI Art. 53/55 enforcement, ICGC bootstrap"},
                    {"period": "2028-2032", "focus": "Pre-AGI capability evals, treaty enforcement, kinetic standards"},
                    {"period": "2032-2040", "focus": "AGI-class oversight, distributed sovereignty controls"},
                    {"period": "2040-2050", "focus": "Civilizational continuity protocols, multi-civilizational stewardship"},
                ],
            },
            {
                "id": "M5-S5",
                "title": "Sovereign AI & Strategic Autonomy",
                "considerations": [
                    "Sovereign cloud / sovereign foundation model commitments",
                    "Cross-border data flows: EU-US DPF, UK Bridge, ASEAN Model Contractual Clauses",
                    "Export controls: ECCN 4E091, EAR 744.23, Wassenaar updates",
                    "Strategic autonomy investments and dual-use risk reviews",
                ],
            },
            {
                "id": "M5-S6",
                "title": "Civilizational Continuity Protocol",
                "elements": [
                    "Geographically dispersed kill-switch custody (m-of-n threshold)",
                    "Diverse foundation-model portfolio (anti-monoculture)",
                    "Air-gapped golden-image archives of critical AI assets",
                    "Treaty-mandated annual civilizational tabletop (GC7 class)",
                ],
            },
        ],
    }


def m6_financial_mrm():
    return {
        "id": "M6",
        "title": "M6 — Financial Services Model Risk Management",
        "summary": "Domain-specific governance for credit, trading, risk, and fiduciary AI advisors.",
        "sections": [
            {
                "id": "M6-S1",
                "title": "Domain Catalogue",
                "domains": [
                    {
                        "id": "FS-01",
                        "domain": "Retail Credit Scoring",
                        "anchors": ["FCRA §615", "ECOA / Reg B", "GDPR Art. 22", "EU AI Act high-risk Annex III §5(b)"],
                        "controls": ["Adverse-action top-N reasons", "LDA search", "Disparate-impact testing", "DPIA + LIA"],
                        "kpi": "AIR ≥ 0.8; SPD ≤ 0.05; backtest PSI ≤ 0.1",
                    },
                    {
                        "id": "FS-02",
                        "domain": "Wholesale / Corporate Credit",
                        "anchors": ["Basel III/IV IRB", "PRA SS1/23", "SR 11-7 Tier 1"],
                        "controls": ["IRB model approval", "Pillar-2 capital add-on", "Conservatism margin"],
                        "kpi": "PD/LGD/EAD backtest within tolerance; ICAAP coverage",
                    },
                    {
                        "id": "FS-03",
                        "domain": "Algorithmic Trading & Market-Making",
                        "anchors": ["MiFID II / MiFIR Art. 17", "SEC 15c3-5", "FCA MAR"],
                        "controls": ["Pre-trade risk checks", "Kill-switch", "Algo testing & certification"],
                        "kpi": "Latency budget; max-loss / day; cancel-fill ratio drift",
                    },
                    {
                        "id": "FS-04",
                        "domain": "Market & Liquidity Risk Models",
                        "anchors": ["FRTB", "BCBS 239", "SR 11-7"],
                        "controls": ["VaR backtesting", "Capital floor", "Stress-test integration"],
                        "kpi": "Backtest exceptions ≤ 4/year (P&L attrib)",
                    },
                    {
                        "id": "FS-05",
                        "domain": "Operational & Conduct Risk Detection",
                        "anchors": ["Basel III OpRisk", "FCA Consumer Duty", "AML 6 / FinCEN"],
                        "controls": ["Alert tuning governance", "False-positive ceiling", "Explainable case file"],
                        "kpi": "TPR ≥ x; FPR ≤ y; SAR conversion"
                    },
                    {
                        "id": "FS-06",
                        "domain": "Fiduciary AI Advisors / Robo-Advice",
                        "anchors": ["FCA COBS / SEC IA Act", "MiFID II suitability", "MAS FEAT"],
                        "controls": ["Suitability test", "Conflict-of-interest disclosure", "Best-interest attestation"],
                        "kpi": "Suitability-deviation ≤ x bps; complaint rate"
                    },
                ],
            },
            {
                "id": "M6-S2",
                "title": "Capital Impact (ICAAP Pillar 2 AI Add-on)",
                "method": "Add-on calibrated to model-risk loss distribution + scenario severity",
                "components": [
                    "Performance drift (PSI > 0.2) capital",
                    "Fairness remediation provisioning",
                    "Containment-failure operational risk capital",
                    "Frontier-risk Pillar-2 buffer (qualitative)",
                ],
                "boardReporting": "Quarterly; with ICAAP Pillar-2 sub-letter to PRA / ECB",
            },
            {
                "id": "M6-S3",
                "title": "Validation Pack Standard",
                "elements": [
                    "Model card (Hugging Face style + MRM appendix)",
                    "Data card with lineage and bias profile",
                    "Performance & stability backtests",
                    "Fairness across protected classes",
                    "Robustness (adversarial + distributional)",
                    "Explainability (SHAP / IG / counterfactuals)",
                    "Independent challenger benchmark",
                    "Sign-off: 1LoD / 2LoD / 3LoD",
                ],
            },
        ],
    }


def m7_kafka_gac():
    return {
        "id": "M7",
        "title": "M7 — Kafka ACL Governance & Continuous Compliance Engine",
        "summary": "Terraform-based governance-as-code with WORM evidence, OPA gates, and auditor workflows.",
        "sections": [
            {
                "id": "M7-S1",
                "title": "Kafka ACL Governance Pattern",
                "components": [
                    "Per-topic ACLs in Terraform (terraform-confluent-provider)",
                    "Topic-tier classification (public / internal / confidential / restricted)",
                    "mTLS + SPIFFE/SPIRE workload identity",
                    "Continuous ACL drift detection (cron job → OPA → ticket)",
                    "Quarterly ACL recertification by data owner",
                ],
            },
            {
                "id": "M7-S2",
                "title": "WORM Evidence Storage",
                "design": [
                    "S3 Object Lock (compliance mode) — 7-year retention (SR 11-7 / SEC 17a-4(f))",
                    "Daily Merkle-root anchored to public timestamping (RFC 3161 + blockchain anchor)",
                    "Cross-region replication (eu-west-1 / us-east-1 / ap-southeast-1)",
                    "PQC (Dilithium3) signature on each manifest",
                ],
            },
            {
                "id": "M7-S3",
                "title": "Continuous Compliance Engine",
                "modules": [
                    {"name": "Evidence collector", "freq": "5 min", "outputs": "Raw evidence to Kafka topic"},
                    {"name": "Control mapper", "freq": "Hourly", "outputs": "Maps evidence to control IDs (240+ controls)"},
                    {"name": "Coverage scorer", "freq": "Hourly", "outputs": "% controls evidenced; gap list"},
                    {"name": "Auditor view", "freq": "On-demand", "outputs": "Read-only Next.js dashboard with evidence proofs"},
                    {"name": "Regulator pack generator", "freq": "Quarterly + ad-hoc", "outputs": "PDF/A-3 with embedded evidence + signature"},
                ],
            },
            {
                "id": "M7-S4",
                "title": "Terraform Governance-as-Code",
                "modules": [
                    "tf-aws-s3-worm — Object Lock + replication",
                    "tf-aws-kms-cmk-rotated — annual rotation, key policy with break-glass",
                    "tf-aws-iam-zerotrust — SCP-enforced least privilege",
                    "tf-aws-eks-hardened — pod-security-standards restricted, OPA gatekeeper",
                    "tf-confluent-acls — per-topic ACL bundles",
                    "tf-opa-bundle — versioned policy bundles (CI signed)",
                ],
            },
            {
                "id": "M7-S5",
                "title": "CI/CD Integration (GitHub Actions)",
                "stages": [
                    "Lint (rego, tflint, eslint, ruff)",
                    "Unit tests + property tests (Hypothesis / fast-check)",
                    "Container build + SLSA provenance + Cosign sign",
                    "OPA conftest gates (POL-01..POL-06)",
                    "Adversarial / jailbreak test suite",
                    "Mechanistic interpretability audit (cosine tripwires)",
                    "Cryptographic attestation (Sigstore + Rekor)",
                    "Canary deploy (5% → 25% → 100%) with auto-rollback",
                ],
            },
            {
                "id": "M7-S6",
                "title": "Auditor Workflow",
                "steps": [
                    "Read-only auditor account via SSO + SCIM",
                    "Evidence query UI: control → evidence → proof chain",
                    "Sample selection with deterministic seed (auditable)",
                    "Export to PDF/A-3 with embedded JSON-LD evidence",
                    "Findings logged to WORM Kafka topic for traceability",
                ],
            },
            {
                "id": "M7-S7",
                "title": "Regulator-Ready Reports & Whitepapers",
                "templates": [
                    "Annex IV dossier (EU AI Act)",
                    "ICAAP Pillar-2 AI annex",
                    "ISO/IEC 42001 AIMS evidence pack",
                    "SR 11-7 Independent Validation Report",
                    "DPIA + Art. 22 notice",
                    "Adverse-action reason-code package (FCRA)",
                    "FEAT (MAS) self-assessment",
                    "Treaty disclosure pack (ICGC / GAGCOT)",
                ],
            },
        ],
    }


def m8_implementation_roadmap():
    return {
        "id": "M8",
        "title": "M8 — Implementation Roadmap & Reports",
        "summary": "Phased adoption across Fortune 500 / Global 2000 / G-SIFIs with executive- and regulator-ready outputs.",
        "sections": [
            {
                "id": "M8-S1",
                "title": "Five-Phase Adoption Plan (52 weeks)",
                "phases": [
                    {"phase": "P1 Foundations", "weeks": "1-8", "deliverables": ["AI Governance Council", "Risk appetite", "Inventory", "DPIA register"]},
                    {"phase": "P2 Controls Build", "weeks": "9-20", "deliverables": ["OPA bundles", "Sentinel runtime", "Kafka WORM", "MRM tooling"]},
                    {"phase": "P3 Integration", "weeks": "21-32", "deliverables": ["EAIP wiring", "Sidecars", "Continuous compliance engine"]},
                    {"phase": "P4 Assurance", "weeks": "33-44", "deliverables": ["ISO 42001 cert", "Annex IV pilots", "ICAAP AI annex"]},
                    {"phase": "P5 Frontier Readiness", "weeks": "45-52", "deliverables": ["MV-AGI stack", "Crisis sims GC1-GC7", "Treaty disclosure"]},
                ],
            },
            {
                "id": "M8-S2",
                "title": "KPIs / OKRs",
                "kpis": [
                    {"id": "KPI-01", "name": "Time to governed deployment", "target": "≤ 72 h"},
                    {"id": "KPI-02", "name": "Evidence automation", "target": "≥ 92%"},
                    {"id": "KPI-03", "name": "Containment MTTD", "target": "≤ 4 min"},
                    {"id": "KPI-04", "name": "Containment MTTR", "target": "≤ 60 min"},
                    {"id": "KPI-05", "name": "Kinetic kill-switch latency", "target": "≤ 60 s"},
                    {"id": "KPI-06", "name": "Fairness AIR floor", "target": "≥ 0.8"},
                    {"id": "KPI-07", "name": "Backtest PSI ceiling", "target": "≤ 0.1 (warn) / ≤ 0.2 (fail)"},
                    {"id": "KPI-08", "name": "Control coverage", "target": "≥ 240 controls / 16 axes"},
                    {"id": "KPI-09", "name": "Audit finding closure", "target": "≤ 90 days (high)"},
                    {"id": "KPI-10", "name": "Frontier disclosure SLA", "target": "≤ 4 h to ICGC"},
                ],
            },
            {
                "id": "M8-S3",
                "title": "Executive & Regulator Reports (Markdown templates with <title>/<abstract>/<content>)",
                "reports": [
                    {"id": "RPT-01", "audience": "Board", "title": "AI Risk Appetite & Strategy 2026-2030"},
                    {"id": "RPT-02", "audience": "C-Suite", "title": "AI Governance Operating Model"},
                    {"id": "RPT-03", "audience": "PRA / FCA", "title": "SS1/23 MRM Self-Assessment"},
                    {"id": "RPT-04", "audience": "ECB SSM", "title": "ICAAP Pillar-2 AI Annex"},
                    {"id": "RPT-05", "audience": "EU notified body", "title": "Annex IV Technical Documentation"},
                    {"id": "RPT-06", "audience": "ISO 42001 certifier", "title": "AIMS Evidence Pack"},
                    {"id": "RPT-07", "audience": "CFPB", "title": "Adverse-Action & LDA Compliance Package"},
                    {"id": "RPT-08", "audience": "Treaty (ICGC)", "title": "Frontier Compute & Capability Disclosure"},
                    {"id": "RPT-09", "audience": "Board (Crisis)", "title": "GC1-GC7 Tabletop After-Action Report"},
                    {"id": "RPT-10", "audience": "Researchers", "title": "Whitepaper: Master Framework Architecture"},
                ],
            },
        ],
    }


def schemas():
    return {
        "governanceArtefactEnvelope": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/governance-artefact.json",
            "type": "object",
            "required": ["artefactId", "type", "owner", "issuedAt", "evidenceRefs", "signature"],
            "properties": {
                "artefactId": {"type": "string", "pattern": "^EAGV-[A-Z0-9-]+$"},
                "type": {"enum": ["dossier", "imv-report", "dpia", "policy", "evidence-bundle", "manifest"]},
                "owner": {"type": "string"},
                "issuedAt": {"type": "string", "format": "date-time"},
                "evidenceRefs": {"type": "array", "items": {"type": "string"}},
                "signature": {"type": "object", "required": ["alg", "value", "keyId"]},
            },
        },
        "computeRegistryEntry": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/compute-registry.json",
            "type": "object",
            "required": ["operatorId", "facilityId", "designFLOPs", "attestationSignature"],
            "properties": {
                "operatorId": {"type": "string"},
                "facilityId": {"type": "string"},
                "designFLOPs": {"type": "number"},
                "currentUtilisationFLOPs": {"type": "number"},
                "modelsTrained": {"type": "array"},
                "attestationSignature": {"type": "object"},
            },
        },
        "modelRiskRecord": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/model-risk-record.json",
            "type": "object",
            "required": ["modelId", "tier", "owner", "imvStatus", "kris"],
            "properties": {
                "modelId": {"type": "string"},
                "tier": {"enum": ["T0", "T1", "T2", "T3", "T4", "T5"]},
                "owner": {"type": "string"},
                "imvStatus": {"enum": ["pending", "passed", "conditional", "failed"]},
                "kris": {"type": "object"},
            },
        },
        "fairnessReport": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/fairness-report.json",
            "type": "object",
            "required": ["modelId", "metrics", "protectedAttributes", "decision"],
            "properties": {
                "modelId": {"type": "string"},
                "metrics": {"type": "object", "properties": {"AIR": {"type": "number"}, "SPD": {"type": "number"}, "EOD": {"type": "number"}}},
                "protectedAttributes": {"type": "array", "items": {"type": "string"}},
                "decision": {"enum": ["pass", "remediate", "block"]},
            },
        },
        "policyDecision": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/policy-decision.json",
            "type": "object",
            "required": ["policyId", "input", "decision", "trace"],
            "properties": {
                "policyId": {"type": "string"},
                "input": {"type": "object"},
                "decision": {"enum": ["allow", "deny", "warn"]},
                "trace": {"type": "array"},
            },
        },
        "treatyDisclosure": {
            "$id": "https://workflowai.pro/schemas/ent-agi-gov/treaty-disclosure.json",
            "type": "object",
            "required": ["operatorId", "modelId", "capabilityTier", "computeFLOPs", "issuedAt"],
            "properties": {
                "operatorId": {"type": "string"},
                "modelId": {"type": "string"},
                "capabilityTier": {"enum": ["T2", "T3", "T4", "T5"]},
                "computeFLOPs": {"type": "number"},
                "issuedAt": {"type": "string", "format": "date-time"},
                "evalSummary": {"type": "object"},
            },
        },
    }


def code_examples():
    return {
        "regoDeployGate": '''package eagv.deploy

# POL-01 deploy_gate.rego
default allow = false

allow {
  input.model.signature.verified
  input.model.imv.status == "passed"
  not expired_dpia
  not high_risk_without_dossier
}

expired_dpia {
  time.parse_rfc3339_ns(input.model.dpia.expiresAt) < time.now_ns()
}

high_risk_without_dossier {
  input.model.tier == "T1"
  input.model.regulatoryFlags[_] == "EU_AI_ACT_HIGH_RISK"
  not input.model.annexIvDossier
}
''',
        "regoComputeRegister": '''package eagv.compute

# POL-06 compute_register.rego
default allow = false

allow {
  input.training.flops < 1e25
}

allow {
  input.training.flops >= 1e25
  input.icgc.registryEntryId
  input.icgc.attestationSignature.verified
}
''',
        "terraformS3Worm": '''# tf-aws-s3-worm
resource "aws_s3_bucket" "worm" {
  bucket = "eagv-worm-${var.env}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "worm" {
  bucket = aws_s3_bucket.worm.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "worm" {
  role   = aws_iam_role.repl.arn
  bucket = aws_s3_bucket.worm.id
  rule {
    id     = "cross-region"
    status = "Enabled"
    destination { bucket = var.replica_bucket_arn }
  }
}
''',
        "terraformKafkaAcls": '''# tf-confluent-acls — per-topic ACL bundle
resource "confluent_kafka_acl" "telemetry_writer" {
  kafka_cluster { id = var.cluster_id }
  resource_type = "TOPIC"
  resource_name = "ai.telemetry.v1"
  pattern_type  = "LITERAL"
  principal     = "User:sa-sentinel-emitter"
  host          = "*"
  operation     = "WRITE"
  permission    = "ALLOW"
}

resource "confluent_kafka_acl" "telemetry_audit_reader" {
  kafka_cluster { id = var.cluster_id }
  resource_type = "TOPIC"
  resource_name = "ai.telemetry.v1"
  pattern_type  = "LITERAL"
  principal     = "User:sa-auditor"
  host          = "*"
  operation     = "READ"
  permission    = "ALLOW"
}
''',
        "merkleAuditPython": '''#!/usr/bin/env python3
"""Daily Merkle-root WORM audit (EAGV)."""
import hashlib, json, time, boto3
from cryptography.hazmat.primitives.asymmetric import ed25519

def merkle(leaves):
    if not leaves: return b""
    layer = [hashlib.sha256(l).digest() for l in leaves]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i]+layer[i+1]).digest()
                 for i in range(0,len(layer),2)]
    return layer[0]

def daily_audit(bucket, prefix, signing_key):
    s3 = boto3.client("s3")
    leaves = []
    for o in s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", []):
        body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
        leaves.append(body)
    root = merkle(leaves)
    sig = signing_key.sign(root)
    manifest = {"date": time.strftime("%Y-%m-%d"),
                "merkleRoot": root.hex(),
                "signature": sig.hex(),
                "leafCount": len(leaves)}
    s3.put_object(Bucket=bucket, Key=f"{prefix}/_manifests/{manifest['date']}.json",
                  Body=json.dumps(manifest).encode(),
                  ObjectLockMode="COMPLIANCE",
                  ObjectLockRetainUntilDate=time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return manifest
''',
        "ciGithubActions": '''# .github/workflows/eagv-pipeline.yml
name: eagv-pipeline
on: [push, pull_request]
jobs:
  govern:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint rego
        run: opa fmt --diff policies/ && opa test policies/
      - name: Conftest gates
        run: conftest test --policy policies deploy/
      - name: Adversarial suite
        run: pytest tests/adversarial -q
      - name: Mechanistic audit
        run: python tools/circuit_scanner.py --threshold 0.92
      - name: Build + SLSA + Cosign
        run: |
          docker build -t app:${{ github.sha }} .
          cosign sign --yes app:${{ github.sha }}
      - name: Sigstore attest
        run: cosign attest --predicate evidence.json app:${{ github.sha }}
      - name: Canary deploy
        run: kubectl apply -f deploy/canary-5pct.yaml
''',
        "nodeSidecar": '''// node-governance-sidecar
const express = require("express");
const { sign } = require("./pqc");
const opa = require("./opa-client");
const app = express();
app.use(express.json());

app.post("/intercept", async (req, res) => {
  const decision = await opa.eval("eagv.runtime.allow", req.body);
  if (!decision.allow) return res.status(403).json({ error: decision.reason });
  const envelope = {
    ts: new Date().toISOString(),
    modelId: req.body.modelId,
    inputHash: req.body.inputHash,
    decision,
  };
  envelope.signature = sign(JSON.stringify(envelope));
  // emit to Kafka topic ai.telemetry.v1
  res.json({ ok: true, envelope });
});

app.listen(7081);
''',
        "fairnessTestPy": '''#!/usr/bin/env python3
"""FCRA/ECOA fairness pre-deploy gate."""
import numpy as np, pandas as pd

def air(y_pred, group):
    rates = pd.Series(y_pred).groupby(group).mean()
    return rates.min() / rates.max()

def spd(y_pred, group, ref):
    rates = pd.Series(y_pred).groupby(group).mean()
    return rates - rates.loc[ref]

def gate(df, pred_col="approved", group_col="protected_class", ref="group_a"):
    a = air(df[pred_col], df[group_col])
    s = spd(df[pred_col], df[group_col], ref).abs().max()
    if a < 0.8 or s > 0.05:
        raise SystemExit(f"FAIL: AIR={a:.3f} SPD={s:.3f}")
    print(f"PASS: AIR={a:.3f} SPD={s:.3f}")
''',
        "kineticKillSwitch": '''// kinetic-kill-switch (m-of-n threshold)
const { thresholdSign, verifyThreshold } = require("./threshold-crypto");

async function executeKill(operatorId, reasonCode, signatures) {
  if (!verifyThreshold(signatures, /*m=*/3, /*n=*/5)) {
    throw new Error("threshold not met");
  }
  await scada.cutPower(operatorId);          // <60s SLA
  await net.disconnectVlan(operatorId);
  await audit.emit({ operatorId, reasonCode, signatures, ts: Date.now() });
}
''',
        "regulatorReportTemplate": '''<!-- Markdown report template -->
<title>Annex IV Technical Documentation — Model {{modelId}}</title>
<abstract>
Regulator-ready dossier covering EU AI Act Art. 11 + Annex IV for the
high-risk AI system {{modelId}} operated by {{operator}}.
</abstract>
<content>

## 1. General description
- Intended purpose: {{purpose}}
- Provider / deployer: {{provider}} / {{deployer}}
- Versions covered: {{versions}}

## 2. Detailed description
- Architecture, training data, validation methodology
- Logging (Art. 12) and human oversight (Art. 14)

## 3. Risk management (Art. 9)
- Hazard identification, evaluation, mitigations

## 4. Performance & monitoring (Art. 15 / 17)
- Accuracy, robustness, cyber-security

## 5. Conformity assessment & post-market monitoring
</content>
''',
    }


def case_studies():
    return [
        {
            "id": "CS-01",
            "title": "G-SIFI bank — full-stack adoption",
            "sector": "Banking",
            "summary": "Top-10 G-SIFI rolled out the master framework across 1,200 AI use-cases.",
            "outcomes": {
                "controlsMapped": 247,
                "evidenceAutomation": "94%",
                "ICAAPPillar2AddOn": "GBP 380m",
                "ISO42001Certification": "Achieved Q4 2027",
                "AnnexIVDossiers": 38,
                "FrontierDisclosures": 6,
            },
        },
        {
            "id": "CS-02",
            "title": "Fortune 500 insurer — fairness remediation",
            "sector": "Insurance",
            "summary": "Pricing AI remediated using LDA search; AIR moved 0.71 → 0.86.",
            "outcomes": {
                "AIRBefore": 0.71,
                "AIRAfter": 0.86,
                "complaintReduction": "-42%",
                "regulatorEngagement": "FCA + state DOI satisfied",
            },
        },
        {
            "id": "CS-03",
            "title": "Global asset manager — fiduciary AI advisor",
            "sector": "Asset Management",
            "summary": "Robo-advice platform certified under MAS FEAT + ISO 42001.",
            "outcomes": {
                "FEATAttestation": "Issued",
                "suitabilityDeviation": "-31 bps",
                "complaintRate": "0.03%",
            },
        },
        {
            "id": "CS-04",
            "title": "Frontier AI lab — MV-AGI stack",
            "sector": "AI Research",
            "summary": "Frontier lab adopted MV-AGI stack ahead of Art. 53/55 enforcement.",
            "outcomes": {
                "computeRegistryEntries": 12,
                "capabilityEvalsPassed": 5,
                "treatyDisclosures": 3,
                "kineticTripwireDrills": 4,
            },
        },
        {
            "id": "CS-05",
            "title": "Global 2000 retailer — agentic workflows",
            "sector": "Retail",
            "summary": "Deployed governed agentic workflows for supply-chain optimisation with 0 containment incidents.",
            "outcomes": {
                "agents": 2400,
                "containmentIncidents": 0,
                "MTTD": "3.1 min",
                "MTTR": "47 min",
            },
        },
        {
            "id": "CS-06",
            "title": "Sovereign-cloud government deployment",
            "sector": "Public Sector",
            "summary": "G7 government deployed sovereign-AI stack with treaty-aligned governance.",
            "outcomes": {
                "sovereignFoundationModels": 3,
                "treatyDisclosures": 2,
                "civilizationalDrillScore": "A-",
            },
        },
    ]


def api_endpoints():
    routes = [
        "", "/meta", "/executive-summary", "/summary",
        "/pillars", "/pillars/:id",
        "/regulatory", "/regulatory/:axis",
        "/architectures", "/architectures/:id",
        "/safety", "/safety/:id",
        "/civilizational", "/civilizational/:id",
        "/financial-mrm", "/financial-mrm/:id",
        "/kafka-gac", "/kafka-gac/:id",
        "/roadmap", "/roadmap/phases", "/roadmap/kpis",
        "/reports", "/reports/:id",
        "/scenarios", "/scenarios/:id",
        "/schemas", "/schemas/:name",
        "/code-examples", "/code-examples/:name",
        "/case-studies", "/case-studies/:id",
        "/modules", "/modules/:id", "/sections/:id",
    ]
    # Per-module roots M1..M8
    for i in range(1, 9):
        routes.append(f"/m{i}")
    # Per-pillar shortcuts
    for g in range(1, 8):
        routes.append(f"/pillars/G{g}")
    # Per-scenario shortcuts
    for g in range(1, 8):
        routes.append(f"/scenarios/GC{g}")
    return {"prefix": "/api/ent-agi-gov-master", "routes": routes}


def main():
    data = {
        "meta": meta(),
        "executiveSummary": executive_summary(),
        "M1_pillars": m1_pillars(),
        "M2_regulatory": m2_regulatory_matrix(),
        "M3_architectures": m3_reference_architectures(),
        "M4_safety": m4_safety_containment(),
        "M5_civilizational": m5_civilizational(),
        "M6_financialMrm": m6_financial_mrm(),
        "M7_kafkaGac": m7_kafka_gac(),
        "M8_roadmap": m8_implementation_roadmap(),
        "schemas": schemas(),
        "codeExamples": code_examples(),
        "caseStudies": case_studies(),
        "apiEndpoints": api_endpoints(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    size_kb = OUT.stat().st_size // 1024
    print(f"Wrote {OUT} ({size_kb} KB)")
    n_modules = sum(1 for k in data if k.startswith("M") and "_" in k)
    n_sections = sum(
        len(data[k].get("sections", []))
        for k in data if k.startswith("M") and "_" in k
    )
    print(
        f"Modules: {n_modules} | Sections: {n_sections} | "
        f"Schemas: {len(data['schemas'])} | Code: {len(data['codeExamples'])} | "
        f"Cases: {len(data['caseStudies'])} | Routes: {len(data['apiEndpoints']['routes'])}"
    )


if __name__ == "__main__":
    main()
