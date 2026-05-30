#!/usr/bin/env python3
"""
WP-062: Comprehensive 2026-2030 Enterprise & Civilizational AGI/ASI Governance,
Architecture, Safety & Implementation Master Synthesis Blueprint for Fortune 500,
Global 2000, and G-SIFI Financial Institutions and Regulators.

This is the definitive synthesis blueprint unifying the full programme corpus
(WP-035 .. WP-061) plus the Luminous Engine Codex, Omni-Sentinel, and the
civilizational compute/legal governance proposals into a single, machine-readable,
regulator-submission-grade reference covering:

  M1  Governance Foundations & Operating Model (board → control room)
  M2  Multi-Framework Regulatory Compliance (EU AI Act + Annex IV, NIST AI RMF 1.0
      + NIST AI 600-1, ISO/IEC 42001, OECD, GDPR, FCRA/ECOA, Basel III/IV, SR 11-7,
      NIS2, FCA Consumer Duty/SMCR, MAS/HKMA FEAT)
  M3  Enterprise AI Reference Architectures (Sentinel v2.4, WorkflowAI Pro, EAIP,
      high-assurance RAG, governed agentic workflows, K8s/Kafka/OPA, WORM audit,
      sidecars, Next.js explainability, compliance-as-code, Terraform/CI-CD)
  M4  AGI/ASI Safety & Containment (Luminous Engine Codex, Cognitive Resonance
      Protocol, Sentinel/Omni-Sentinel, MVGS, containment labs, crisis sims,
      frontier-risk taxonomy, systemic-risk controls)
  M5  Civilizational-Scale Governance (ICGC, global compute registry, treaty-aligned
      systemic-risk governance; GACRA/GASO/GFMCF/GAICS/GAIVS/GACP/GATI/GACMO/FTEWS/
      GAI-SOC/GAIGA/GACRLS/GFCO/GAID/GASCF mechanisms)
  M6  Financial-Services Model Risk Management (credit, trading, risk, fiduciary
      AI advisors, systemic-risk-sensitive advisors; SR 11-7 + Basel + FEAT)
  M7  Continuous Compliance & Audit Engine (Kafka ACL governance, Terraform GaC,
      WORM evidence, OPA/Rego, CI/CD, auditor workflows, deterministic replay,
      PQC audit logs, zk-SNARK access control, red teaming, CRP monitoring, IR)
  M8  Platforms, Tooling & Delivery (Governance Hub, AI Safety Report Generator,
      advanced prompt engineering, regulator-ready report sections, phased
      2026-2030 roadmap + research agenda + rollout plans)
"""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "data", "civ-agi-master-synthesis-2030.json")

DOC = {
    "docRef": "CIV-AGI-MASTER-SYNTHESIS-2030-WP-062",
    "version": "1.0.0",
    "title": "Comprehensive 2026-2030 Enterprise & Civilizational AGI/ASI Governance, Architecture, Safety & Implementation Master Synthesis Blueprint for Fortune 500, Global 2000, and G-SIFI Financial Institutions and Regulators",
    "horizon": "2026-2030+",
    "apiPrefix": "/api/civ-agi-master-synthesis-2030",
    "buildsOn": ["WP-035", "WP-040", "WP-045", "WP-050", "WP-054", "WP-055",
                 "WP-056", "WP-057", "WP-058", "WP-059", "WP-060", "WP-061"],
    "status": "regulator-submission-grade-civilizational-agi-master-synthesis",
    "classification": "Confidential / Restricted — Board, CEO, CRO, CCO, CISO, CDAO, General Counsel, Group Internal Audit, External Regulators, AI Safety Institutes (AISIs), Cryptographic & Compute Supervisory Authorities, Treaty Bodies",
    "audiences": [
        "Boards & Board Risk/Technology Committees",
        "C-Suite (CEO, CRO, CCO, CISO, CDAO, CTO, General Counsel)",
        "Enterprise Architects & AI Platform Engineers",
        "Model Risk Management & Validation",
        "Group Internal Audit & External Auditors",
        "Financial-Services & Prudential Regulators (FCA, PRA, Fed, OCC, ECB, EU AI Office, MAS, HKMA, BaFin)",
        "AI Safety Institutes (US/UK AISI, EU AI Office)",
        "Researchers & Frontier-Safety Labs",
        "Compute & Treaty Governance Bodies (proposed ICGC)"
    ],
    "directive": {
        "scope": "Single master synthesis blueprint for Fortune 500 / Global 2000 / G-SIFI enterprises and their regulators covering: (1) institutional AI governance operating model from board to control room; (2) multi-framework regulatory compliance across EU AI Act (incl. Annex IV), NIST AI RMF 1.0 + NIST AI 600-1, ISO/IEC 42001, OECD AI Principles, GDPR, FCRA/ECOA, Basel III/IV, SR 11-7, NIS2, FCA Consumer Duty/SMCR, MAS/HKMA FEAT; (3) enterprise AI reference architectures (Sentinel AI Governance Platform v2.4, WorkflowAI Pro, EAIP, high-assurance RAG, governed agentic workflows, Kubernetes/Kafka/OPA control stacks, Kafka WORM audit, container security, governance sidecars, Next.js explainability frontends, OPA/Rego compliance-as-code, Terraform/CI-CD governance automation, hyperparameter and drift standards); (4) AGI/ASI safety & containment frameworks (Luminous Engine Codex, Cognitive Resonance Protocol, Sentinel/Omni-Sentinel, minimum viable AGI governance stack, containment labs, crisis simulations, frontier-risk taxonomy, systemic-risk controls); (5) civilizational-scale governance (International Compute Governance Consortium, global compute registry, treaty-aligned systemic-risk governance and the GACRA/GASO/GFMCF/GAICS/GAIVS/GACP/GATI/GACMO/FTEWS/GAI-SOC/GAIGA/GACRLS/GFCO/GAID/GASCF mechanisms); (6) financial-services model risk management for credit, trading, risk, fiduciary and systemic-risk-sensitive AI advisors; (7) continuous compliance & audit engine (Kafka ACL governance, Terraform governance-as-code, WORM evidence, OPA/Rego, CI/CD, auditor workflows, deterministic audit replay, PQC-secured logs, zk-SNARK access control, adversarial red teaming, Cognitive Resonance monitoring, incident response); (8) platforms/tooling/delivery (Enterprise AI Governance Hub, AI Safety Report Generator, advanced prompt engineering, regulator-ready report sections, and a phased dependency-aware 2026-2030 implementation + research roadmap with rollout plans and machine-readable artifacts).",
        "outcomes": [
            "ISO/IEC 42001-certified AIMS with a 30+-regime crosswalk and EU AI Act Annex IV conformity dossiers per high-risk system by 2028",
            "NIST AI RMF 1.0 GOVERN/MAP/MEASURE/MANAGE functions operationalized with NIST AI 600-1 GenAI profile across all material systems by 2027",
            "Sentinel AI Governance Platform v2.4 + WorkflowAI Pro deployed across all material AI/AGI systems with governance sidecars and Kafka WORM audit by 2028",
            "SR 11-7-aligned model risk management with independent validation across all credit, trading, risk and advisory models by 2027",
            "AGI containment labs (T3/T4) operational with Luminous Engine Codex invariants, Cognitive Resonance Protocol monitoring and multi-prover verification by 2027",
            "Continuous compliance engine live: OPA/Rego compliance-as-code + Terraform governance-as-code + deterministic audit replay + PQC + zk-SNARK access control by 2028",
            "Enterprise AI Governance Hub + AI Safety Report Generator producing regulator-ready dossiers on demand by 2027",
            "International Compute Governance Consortium engagement + global compute registry submissions piloted by 2029",
            "Civilizational readiness indices: CGI >=0.80, GTI >=0.85, RCI = 1.0 by 2030"
        ],
        "doNot": [
            "Do NOT deploy any AI/AGI/ASI capability outside the Luminous Engine Codex invariant set + verified governance kernel + Sentinel v2.4 attestation",
            "Do NOT promote a model to production without independent SR 11-7 validation, an EU AI Act risk classification, and (for high-risk) an Annex IV dossier",
            "Do NOT issue a regulator submission without WORM-anchored evidence, PQC signature and (where applicable) zk-attestation",
            "Do NOT operate T3/T4 containment labs without 3-of-5 quorum, kinetic override, time-lock, AISI notification windows, and a Cognitive Resonance Protocol baseline",
            "Do NOT bypass EAIP for cross-agent/cross-system integration; ad-hoc protocols are blocked at OPA admission",
            "Do NOT process any data/prompt/weight/decision without lineage emission to the Kafka audit bus + WORM"
        ]
    },
    "regimes": [
        "EU AI Act 2024/1689 (risk tiers, GPAI Art. 53/55, Annex IV technical documentation)",
        "NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE)",
        "NIST AI 600-1 (Generative AI Profile)",
        "ISO/IEC 42001:2023 (AI Management System)",
        "ISO/IEC 23894:2023 (AI risk management)",
        "ISO/IEC 23053 / 22989 (AI/ML framework & concepts)",
        "OECD AI Principles (2019, updated 2024)",
        "GDPR (Arts. 5, 22, 35 DPIA; automated decision-making)",
        "EU Data Act / Data Governance Act",
        "FCRA (Fair Credit Reporting Act)",
        "ECOA / Regulation B (adverse action, disparate impact)",
        "Basel III / IV (model risk, capital, operational risk)",
        "Federal Reserve SR 11-7 (Model Risk Management)",
        "OCC 2011-12 / Bulletin 2021-31 (model risk)",
        "EU NIS2 Directive (cybersecurity)",
        "DORA (Digital Operational Resilience Act)",
        "FCA Consumer Duty (PRIN 2A)",
        "FCA/PRA SMCR (Senior Managers & Certification Regime)",
        "MAS FEAT Principles (Fairness, Ethics, Accountability, Transparency)",
        "HKMA High-level Principles on AI / GenAI guidance",
        "EU AI Act Codes of Practice for GPAI",
        "ISO/IEC 27001 / 27701 (ISMS / PIMS)",
        "SOC 2 Type II (Trust Services Criteria)",
        "EU AI Liability Directive (proposed)",
        "US EO 14110 / OMB M-24-10 (federal AI use)",
        "Colorado AI Act / EU member-state transpositions",
        "Bletchley/Seoul/Paris AI Safety Summit commitments",
        "G7 Hiroshima AI Process Code of Conduct",
        "Frontier Model Forum safety frameworks",
        "Basel Committee principles for operational resilience (BCBS 239 data aggregation)",
    ],
    "indices": {
        "AIMS-Coverage": ">=0.95 (ISO/IEC 42001 control coverage across in-scope systems)",
        "CCS": ">=0.95 (Control Coverage Score across 30+ regimes)",
        "MRGI": ">=0.95 (Model Risk Governance Index, SR 11-7 aligned)",
        "DRI": ">=0.95 (Decision Reproducibility Index, n=10 deterministic replays)",
        "AnnexIV-Completeness": ">=0.98 (Annex IV dossier completeness for high-risk systems)",
        "RMF-Maturity": ">=4/5 (NIST AI RMF function maturity, GOVERN/MAP/MEASURE/MANAGE)",
        "ER": ">=0.90 (Explainability Rate for adverse decisions)",
        "FDR": "<=0.02 (Fairness Disparity Ratio violation rate, ECOA/FEAT)",
        "ALC": "100% (Audit Log Completeness, WORM-anchored)",
        "PQC-Coverage": "100% (PQC-signed audit and attestation artifacts)",
        "ZK-AccessCoverage": ">=0.90 (zk-SNARK-gated privileged access)",
        "CRP-Stability": ">=0.95 (Cognitive Resonance Protocol stability score)",
        "ContainmentReadiness": "1.0 (T3/T4 quorum + kill-switch + time-lock verified)",
        "RTC": ">=8/quarter (Red-Team Campaigns executed)",
        "MTTD": "<=15 min (Mean Time To Detect governance violation)",
        "MTTR": "<=4 h (Mean Time To Respond to AI incident)",
        "DriftAlertSLA": "<=24 h (data/concept drift triage SLA)",
        "CGI": ">=0.80 by 2030 (Civilizational Governance Index)",
        "GTI": ">=0.85 by 2030 (Global Trust Index)",
        "RCI": "1.0 (Regulatory Compliance Integrity)",
        "ComputeRegistryCoverage": ">=0.90 of frontier training runs registered (by 2029)"
    },
    "tiers": {
        "T0": "Minimal-risk AI — light governance, register + monitor",
        "T1": "Limited-risk AI — transparency obligations + human oversight",
        "T2": "High-risk AI (EU AI Act Annex III) — full conformity, Annex IV dossier, SR 11-7 validation",
        "T3": "Frontier/agentic systems — containment lab, CRP baseline, quorum controls",
        "T4": "AGI-class capability — full Luminous Engine Codex invariants, kinetic override, treaty notification"
    },
    "severities": {
        "S1": "Catastrophic / systemic — board + regulator + AISI notification",
        "S2": "Material — CRO/CCO escalation + remediation plan",
        "S3": "Significant — control owner remediation + audit log",
        "S4": "Minor — automated remediation + monitoring"
    },
    "investment": {
        "currency": "USD",
        "programWindow": "2026-2030",
        "totalRange": "$180M - $420M (G-SIFI / Global 2000 scale, 5-year TCO)",
        "breakdown": {
            "platform_and_architecture": "30%",
            "compliance_and_audit_engine": "22%",
            "agi_safety_and_containment": "18%",
            "model_risk_management": "12%",
            "talent_and_operating_model": "10%",
            "civilizational_engagement_and_research": "8%"
        }
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# MODULES (M1..M8), each with sections {sid,title,description,controls}
# ──────────────────────────────────────────────────────────────────────────────
MODULES = [
    {
        "mid": "M1",
        "title": "Governance Foundations & Operating Model",
        "purpose": "Establish the institutional AI governance operating model — accountability from board to control room, ISO/IEC 42001 AIMS, three-lines-of-defense, and the policy hierarchy that binds every downstream module.",
        "sections": [
            {"sid": "M1.S1", "title": "Board & Committee Accountability", "description": "Board Technology/Risk committee charter for AI/AGI oversight; SMCR-mapped senior management responsibilities (SMF24 operational resilience, prescribed AI accountabilities); quarterly AI risk appetite review.", "controls": ["AI risk appetite statement", "Board reporting pack (KRIs/KPIs)", "SMCR responsibilities map"]},
            {"sid": "M1.S2", "title": "ISO/IEC 42001 AI Management System", "description": "AIMS scope, context, leadership, planning, support, operation, performance evaluation and improvement clauses mapped to enterprise controls; Statement of Applicability.", "controls": ["AIMS Statement of Applicability", "Internal audit programme", "Management review cadence"]},
            {"sid": "M1.S3", "title": "Three Lines of Defense for AI", "description": "1LoD product/engineering ownership; 2LoD independent model risk + compliance; 3LoD internal audit with deterministic replay rights.", "controls": ["Independence attestation", "Validation charter", "Audit replay access policy"]},
            {"sid": "M1.S4", "title": "Policy Hierarchy & Compliance-as-Code", "description": "Board policy → standards → procedures → OPA/Rego machine-enforced policy; every human policy clause has a machine-checkable counterpart.", "controls": ["Policy-to-Rego traceability matrix", "Policy version registry", "Exception governance"]},
            {"sid": "M1.S5", "title": "AI System Inventory & Risk Classification", "description": "Authoritative inventory keyed by CRS-UUID; automatic EU AI Act tiering (T0-T4) and Annex III high-risk detection at registration.", "controls": ["Mandatory registration gate", "Auto risk-tiering engine", "Inventory completeness KPI"]},
            {"sid": "M1.S6", "title": "Roles, RACI & Talent Model", "description": "RACI across product, MRM, compliance, security, audit, and AGI safety; talent pipeline for AI governance engineers and validators.", "controls": ["RACI matrix", "Competency framework", "Segregation-of-duties checks"]},
            {"sid": "M1.S7", "title": "Ethics, Fairness & Human Oversight", "description": "Ethics review board; OECD/MAS FEAT-aligned fairness, accountability, transparency principles; human-in-the-loop/human-on-the-loop design standards.", "controls": ["Ethics review gate", "Human oversight design pattern", "Fairness sign-off"]},
            {"sid": "M1.S8", "title": "Governance Control Room", "description": "Unified control room aggregating KRIs, incidents, drift alerts, containment status and regulator obligations across the estate.", "controls": ["Single pane of glass", "Obligation calendar", "Escalation runbooks"]},
        ],
    },
    {
        "mid": "M2",
        "title": "Multi-Framework Regulatory Compliance",
        "purpose": "Operationalize a unified compliance program that satisfies 30+ overlapping regimes via a single control library, crosswalks and EU AI Act Annex IV conformity dossiers.",
        "sections": [
            {"sid": "M2.S1", "title": "EU AI Act Conformity & Annex IV", "description": "Risk classification, conformity assessment, GPAI Art. 53/55 obligations, and auto-assembled Annex IV technical documentation dossiers per high-risk system.", "controls": ["Annex IV dossier generator", "Conformity assessment workflow", "GPAI systemic-risk evaluation"]},
            {"sid": "M2.S2", "title": "NIST AI RMF 1.0 + AI 600-1", "description": "GOVERN/MAP/MEASURE/MANAGE function implementation with the NIST AI 600-1 Generative AI profile and crosswalk to enterprise controls.", "controls": ["RMF function maturity scorecard", "GenAI profile control set", "Measurement playbook"]},
            {"sid": "M2.S3", "title": "ISO/IEC 42001 + 23894 Integration", "description": "AIMS and AI risk-management standards harmonized into a single control library to avoid duplicate evidence.", "controls": ["Unified control library", "Evidence reuse map", "Certification readiness tracker"]},
            {"sid": "M2.S4", "title": "Privacy: GDPR, Data Act, DPIA", "description": "Art. 22 automated decision rights, Art. 35 DPIA for high-risk processing, data minimization and lineage for training data.", "controls": ["DPIA template + gate", "Art. 22 explanation service", "Training-data lineage register"]},
            {"sid": "M2.S5", "title": "Fair Lending: FCRA & ECOA/Reg B", "description": "Adverse-action notices, disparate-impact testing, reason-code generation for credit AI under FCRA/ECOA.", "controls": ["Adverse-action reason codes", "Disparate-impact test suite", "Model documentation for fair lending"]},
            {"sid": "M2.S6", "title": "Prudential: Basel III/IV, SR 11-7, OCC", "description": "Model risk management lifecycle, capital model governance, independent validation and effective challenge per SR 11-7 / OCC 2011-12.", "controls": ["Validation report standard", "Effective challenge log", "Model tiering by materiality"]},
            {"sid": "M2.S7", "title": "Conduct: FCA Consumer Duty & SMCR", "description": "Consumer Duty outcomes (products, price/value, understanding, support) evidenced for AI-driven customer journeys; SMCR accountability.", "controls": ["Consumer Duty outcome evidence", "Fair value assessment", "SMCR statement of responsibilities"]},
            {"sid": "M2.S8", "title": "APAC: MAS & HKMA FEAT", "description": "MAS FEAT principles and HKMA GenAI guidance mapped to fairness, ethics, accountability and transparency controls for cross-border deployments.", "controls": ["FEAT assessment", "Cross-border deployment register", "Localization controls"]},
            {"sid": "M2.S9", "title": "Cyber & Resilience: NIS2 & DORA", "description": "NIS2 cybersecurity obligations and DORA operational resilience (ICT risk, incident reporting, third-party register, resilience testing) for AI systems.", "controls": ["ICT third-party register", "Resilience testing schedule", "Incident reporting workflow"]},
            {"sid": "M2.S10", "title": "Crosswalk Engine & Single Evidence", "description": "Many-to-many crosswalk mapping each control to all regimes it satisfies; one evidence artifact discharges multiple obligations.", "controls": ["Crosswalk matrix (30+ regimes)", "Evidence deduplication", "Gap analysis report"]},
        ],
    },
    {
        "mid": "M3",
        "title": "Enterprise AI Reference Architectures",
        "purpose": "Provide the deployable reference architectures and control stacks — Sentinel v2.4, WorkflowAI Pro, EAIP, high-assurance RAG, governed agentic workflows — on Kubernetes/Kafka/OPA with WORM audit and governance-as-code.",
        "sections": [
            {"sid": "M3.S1", "title": "Sentinel AI Governance Platform v2.4", "description": "Layered reference stack: hardware root-of-trust → secure enclave/TEE → PQC crypto plane → Kafka WORM audit bus → OPA/Rego policy plane → governance kernel → model registry/lineage → inference sidecars → containment plane → telemetry → control room.", "controls": ["Measured boot + attestation", "Policy plane admission", "Containment plane kill-switch"]},
            {"sid": "M3.S2", "title": "WorkflowAI Pro — Governed Workflows", "description": "Orchestration of governed business workflows with policy checkpoints, approvals, and full lineage on every step.", "controls": ["Workflow policy checkpoints", "Approval gates", "Step-level lineage"]},
            {"sid": "M3.S3", "title": "EAIP — Enterprise Agent Interoperability Protocol", "description": "Standard protocol for cross-agent/cross-system invocation with signed capability tokens, scope limits, and OPA admission; replaces ad-hoc integrations.", "controls": ["Signed capability tokens", "Scope/least-privilege enforcement", "Protocol conformance tests"]},
            {"sid": "M3.S4", "title": "High-Assurance RAG", "description": "Retrieval-augmented generation with source provenance, citation enforcement, retrieval ACLs, grounding checks and hallucination guards.", "controls": ["Citation enforcement", "Retrieval ACLs", "Grounding/hallucination guard"]},
            {"sid": "M3.S5", "title": "Governed Agentic Workflows", "description": "Autonomous agents constrained by capability budgets, tool allow-lists, planning audits, and human approval for high-impact actions.", "controls": ["Capability budgets", "Tool allow-list", "High-impact action approval"]},
            {"sid": "M3.S6", "title": "Kubernetes / Kafka / OPA Control Stack", "description": "Zero-trust K8s with OPA Gatekeeper admission, Kafka event backbone, mTLS service mesh, and policy-gated deployments.", "controls": ["OPA Gatekeeper policies", "mTLS service mesh", "Pod security standards"]},
            {"sid": "M3.S7", "title": "Kafka WORM Audit Logging", "description": "Append-only, immutable audit topics with retention, log-compaction discipline, hash-chaining and tamper-evidence.", "controls": ["Append-only topics", "Hash-chained records", "Retention/legal-hold policy"]},
            {"sid": "M3.S8", "title": "Container & Supply-Chain Security", "description": "Docker Swarm/K8s container hardening, image signing (cosign), SBOM, admission scanning, and runtime security.", "controls": ["Signed images + SBOM", "Admission vulnerability scan", "Runtime threat detection"]},
            {"sid": "M3.S9", "title": "Governance Sidecars (Node.js/Python)", "description": "Sidecar pattern enforcing policy, lineage emission, PII redaction and explainability capture at the inference boundary.", "controls": ["Policy enforcement point", "Lineage emitter", "PII redaction filter"]},
            {"sid": "M3.S10", "title": "Next.js Explainability Frontends", "description": "Operator and auditor UIs presenting decision rationale, feature attributions, counterfactuals and obligation status.", "controls": ["Decision rationale view", "Counterfactual explainer", "Auditor evidence drill-down"]},
            {"sid": "M3.S11", "title": "Compliance-as-Code (OPA/Rego)", "description": "Machine-enforced policy library covering admission, data, model promotion, and access decisions; versioned and tested.", "controls": ["Rego policy library", "Policy unit tests", "Decision logging"]},
            {"sid": "M3.S12", "title": "Terraform / CI-CD Governance Automation", "description": "Infrastructure and policy delivered as code with governance gates in CI/CD, drift detection, and signed releases.", "controls": ["Governance-as-code modules", "CI/CD policy gates", "Infra drift detection"]},
            {"sid": "M3.S13", "title": "Hyperparameter Control & Drift Standards", "description": "Standards for hyperparameter governance, experiment tracking, data/concept drift detection and retraining triggers.", "controls": ["Experiment registry", "Drift detectors + thresholds", "Retraining trigger policy"]},
        ],
    },
    {
        "mid": "M4",
        "title": "AGI/ASI Safety & Containment",
        "purpose": "Define the safety and containment frameworks for frontier and AGI-class systems — Luminous Engine Codex invariants, Cognitive Resonance Protocol, Sentinel/Omni-Sentinel, containment labs and crisis simulations.",
        "sections": [
            {"sid": "M4.S1", "title": "Luminous Engine Codex — Invariant Set", "description": "Canonical safety invariants (corrigibility, non-deception, bounded autonomy, value-alignment, interruptibility) expressed as formally checkable obligations.", "controls": ["Invariant registry", "Multi-prover verification", "Invariant violation tripwires"]},
            {"sid": "M4.S2", "title": "Cognitive Resonance Protocol (CRP)", "description": "Continuous behavioral-stability monitoring detecting alignment drift, deceptive divergence and emergent capability spikes against a baseline.", "controls": ["CRP baseline capture", "Divergence detectors", "Resonance stability score"]},
            {"sid": "M4.S3", "title": "Sentinel / Omni-Sentinel Containment", "description": "Layered containment with kill-switch, emergency air-gap (EAV), master governance key (MGK), and graduated response.", "controls": ["Kill-switch + EAV", "Master governance key quorum", "Graduated response ladder"]},
            {"sid": "M4.S4", "title": "Minimum Viable AGI Governance Stack (MVGS)", "description": "The smallest sufficient control set required before any frontier/agentic deployment is permitted.", "controls": ["MVGS checklist gate", "Pre-deployment attestation", "Capability evaluation suite"]},
            {"sid": "M4.S5", "title": "AGI Containment Labs (T3/T4)", "description": "Physically and logically isolated environments with quorum access, time-locks, kinetic override and AISI notification windows.", "controls": ["3-of-5 quorum access", "48h time-lock", "AISI/EU AI Office notification"]},
            {"sid": "M4.S6", "title": "Crisis Simulations & War-Gaming", "description": "Recurring red/blue/purple-team crisis simulations for loss-of-control, jailbreak, data exfiltration and systemic contagion scenarios.", "controls": ["Quarterly crisis simulation", "Scenario library", "After-action remediation"]},
            {"sid": "M4.S7", "title": "Frontier-Risk Taxonomy", "description": "Structured taxonomy of frontier risks (CBRN uplift, cyber-offense, autonomous replication, deception, persuasion) with capability thresholds.", "controls": ["Capability threshold gates", "Dangerous-capability evals", "Escalation thresholds"]},
            {"sid": "M4.S8", "title": "Systemic-Risk Controls", "description": "Controls limiting correlated failures across the estate and the financial system — concentration limits, circuit breakers and cross-system kill orchestration.", "controls": ["Concentration limits", "Circuit breakers", "Cross-system kill orchestration"]},
        ],
    },
    {
        "mid": "M5",
        "title": "Civilizational-Scale Governance",
        "purpose": "Articulate the civilizational compute/legal governance stack — International Compute Governance Consortium, a global compute registry, treaty-aligned systemic-risk governance, and the proposed coordination mechanisms.",
        "sections": [
            {"sid": "M5.S1", "title": "International Compute Governance Consortium (ICGC)", "description": "Proposed multilateral body coordinating frontier-compute oversight, shared evaluations and mutual recognition of safety attestations.", "controls": ["Membership & charter", "Mutual recognition protocol", "Shared evaluation suite"]},
            {"sid": "M5.S2", "title": "Global Compute Registry", "description": "Registry of frontier training runs above defined FLOP/capability thresholds with attestation and verification.", "controls": ["Threshold-triggered registration", "Run attestation", "Independent verification"]},
            {"sid": "M5.S3", "title": "Treaty-Aligned Systemic-Risk Governance", "description": "Alignment to AI Safety Summit (Bletchley/Seoul/Paris) and G7 Hiroshima commitments; systemic-risk reporting to treaty bodies.", "controls": ["Treaty commitment register", "Systemic-risk reporting", "Cross-border incident protocol"]},
            {"sid": "M5.S4", "title": "Coordination Mechanisms", "description": "Catalog of proposed civilizational mechanisms (see mechanisms collection) spanning compute, verification, model cards, incident response and crisis coordination.", "controls": ["Mechanism adoption roadmap", "Interoperability standards", "Pilot governance"]},
        ],
    },
    {
        "mid": "M6",
        "title": "Financial-Services Model Risk Management",
        "purpose": "Apply SR 11-7 / Basel / FEAT-grade model risk management to AI used in credit, trading, risk, and fiduciary/systemic-risk-sensitive advisory contexts.",
        "sections": [
            {"sid": "M6.S1", "title": "Credit & Underwriting AI", "description": "Fair-lending-compliant credit models with adverse-action explainability, disparate-impact testing and challenger models.", "controls": ["Reason-code explainability", "Disparate-impact monitoring", "Champion/challenger governance"]},
            {"sid": "M6.S2", "title": "Trading & Markets AI", "description": "Pre/post-trade controls, market-abuse surveillance, kill-switches and latency-bounded risk limits for trading models.", "controls": ["Pre-trade risk limits", "Market-abuse surveillance", "Trading kill-switch"]},
            {"sid": "M6.S3", "title": "Risk & Capital Models", "description": "Governance of credit/market/operational risk and capital models under Basel and SR 11-7 with independent validation.", "controls": ["Independent validation", "Backtesting + benchmarking", "Capital model sign-off"]},
            {"sid": "M6.S4", "title": "Fiduciary AI Advisors", "description": "Suitability, best-interest and Consumer Duty controls for AI-driven advice; conflict-of-interest and fair-value evidence.", "controls": ["Suitability checks", "Best-interest attestation", "Conflict-of-interest controls"]},
            {"sid": "M6.S5", "title": "Systemic-Risk-Sensitive Advisors", "description": "Controls for advisors whose correlated behavior could create herding or systemic instability; diversity and circuit-breaker requirements.", "controls": ["Herding/concentration monitoring", "Behavioral diversity requirements", "Systemic circuit breakers"]},
            {"sid": "M6.S6", "title": "Model Lifecycle & Effective Challenge", "description": "End-to-end lifecycle from development to retirement with documented effective challenge and ongoing performance monitoring.", "controls": ["Lifecycle stage gates", "Effective challenge log", "Ongoing performance monitoring"]},
        ],
    },
    {
        "mid": "M7",
        "title": "Continuous Compliance & Audit Engine",
        "purpose": "Operate a continuous, automated compliance and audit engine — Kafka ACL governance, Terraform governance-as-code, WORM evidence, OPA/Rego, deterministic replay, PQC, zk-SNARK access control, red teaming and incident response.",
        "sections": [
            {"sid": "M7.S1", "title": "Kafka ACL Governance", "description": "Centrally governed Kafka ACLs as code controlling who can produce/consume governance and audit topics.", "controls": ["ACL-as-code", "Least-privilege topic access", "ACL drift detection"]},
            {"sid": "M7.S2", "title": "Terraform Governance-as-Code", "description": "All governance infrastructure and policy delivered via Terraform with plan review, approval and signed apply.", "controls": ["Plan review gate", "Signed apply", "State integrity protection"]},
            {"sid": "M7.S3", "title": "WORM Evidence Storage", "description": "Write-once-read-many evidence vault with legal hold, retention schedules and tamper-evidence for all artifacts.", "controls": ["WORM vault", "Legal hold", "Tamper-evidence (hash chain)"]},
            {"sid": "M7.S4", "title": "OPA/Rego Continuous Policy", "description": "Always-on policy evaluation across admission, data, access and model promotion with decision logging.", "controls": ["Continuous policy eval", "Decision log to WORM", "Policy regression tests"]},
            {"sid": "M7.S5", "title": "CI/CD Compliance Integration", "description": "Compliance gates embedded in build/release pipelines blocking non-conformant changes.", "controls": ["Pipeline compliance gate", "Evidence auto-capture", "Release attestation"]},
            {"sid": "M7.S6", "title": "Auditor Workflows & Deterministic Replay", "description": "Auditor self-service with the ability to deterministically replay any past decision from pinned inputs, model and policy versions.", "controls": ["Self-service evidence portal", "Deterministic replay engine", "Replay parity check (DRI)"]},
            {"sid": "M7.S7", "title": "PQC-Secured Audit Logs", "description": "Post-quantum signatures on audit and attestation artifacts ensuring long-term verifiability.", "controls": ["PQC signing (ML-DSA/SLH-DSA)", "Key rotation", "Long-term verification"]},
            {"sid": "M7.S8", "title": "zk-SNARK Access Control", "description": "Zero-knowledge proofs gating privileged access and proving policy compliance without revealing sensitive attributes.", "controls": ["zk access proofs", "Privacy-preserving compliance proofs", "Verifier service"]},
            {"sid": "M7.S9", "title": "Adversarial Red Teaming", "description": "Structured red-team campaigns (jailbreaks, prompt injection, data exfiltration, model extraction) feeding remediation.", "controls": ["Red-team campaign cadence", "Finding triage SLA", "Remediation tracking"]},
            {"sid": "M7.S10", "title": "Cognitive Resonance Monitoring", "description": "Continuous CRP telemetry integrated into the audit engine for alignment-drift detection on frontier systems.", "controls": ["CRP telemetry pipeline", "Drift alerting", "Containment trigger linkage"]},
            {"sid": "M7.S11", "title": "Incident Response Checklists", "description": "Severity-graded IR runbooks with regulator/AISI notification windows, forensic preservation and post-incident review.", "controls": ["IR runbooks (S1-S4)", "Notification window tracking", "Post-incident review"]},
        ],
    },
    {
        "mid": "M8",
        "title": "Platforms, Tooling & Delivery",
        "purpose": "Deliver the operating platforms and the phased programme — Enterprise AI Governance Hub, AI Safety Report Generator, advanced prompt engineering, regulator-ready report sections, and the 2026-2030 roadmap with research agenda.",
        "sections": [
            {"sid": "M8.S1", "title": "Enterprise AI Governance Hub", "description": "Central platform unifying inventory, policy, evidence, obligations, incidents and regulator reporting across the estate.", "controls": ["Unified governance hub", "Obligation tracker", "Regulator reporting workspace"]},
            {"sid": "M8.S2", "title": "AI Safety Report Generator", "description": "Automated assembly of regulator-ready safety and conformity reports (Annex IV, SR 11-7, RMF) from live evidence.", "controls": ["Report templates", "Live evidence binding", "Sign-off workflow"]},
            {"sid": "M8.S3", "title": "Advanced Prompt Engineering Practices", "description": "Governed prompt library, versioning, injection defenses, evaluation harness and prompt risk classification.", "controls": ["Prompt registry + versioning", "Injection defense patterns", "Prompt evaluation harness"]},
            {"sid": "M8.S4", "title": "Regulator-Ready Report Sections", "description": "Standard <title>/<abstract>/<content> whitepaper section structure for technical and regulatory submissions (see reportSections).", "controls": ["Section template standard", "Citation discipline", "Version + provenance"]},
            {"sid": "M8.S5", "title": "Phased 2026-2030 Implementation Roadmap", "description": "Dependency-aware roadmap across foundation, scale, assurance and civilizational phases (see roadmap + rollout90).", "controls": ["Phase gate reviews", "Dependency tracking", "Benefit realization"]},
            {"sid": "M8.S6", "title": "Research Agenda", "description": "Prioritized research questions on alignment verification, interpretability, formal containment proofs and compute governance.", "controls": ["Research backlog", "Lab partnerships", "Publication governance"]},
        ],
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# DISTINCTIVE COLLECTIONS
# ──────────────────────────────────────────────────────────────────────────────
refArchLayers = [
    {"rid": "RA-01", "system": "Sentinel v2.4", "layer": "L1 Hardware Root-of-Trust", "description": "HSM + TPM + TEE root-of-trust per node", "controls": ["Measured boot", "Attested workloads"]},
    {"rid": "RA-02", "system": "Sentinel v2.4", "layer": "L2 Secure Enclave / TEE", "description": "Confidential computing for sensitive inference and key ops", "controls": ["Enclave attestation", "Sealed storage"]},
    {"rid": "RA-03", "system": "Sentinel v2.4", "layer": "L3 PQC Crypto Plane", "description": "Post-quantum signatures and KEM across audit and attestation", "controls": ["ML-DSA signing", "ML-KEM key exchange"]},
    {"rid": "RA-04", "system": "Sentinel v2.4", "layer": "L4 Kafka WORM Audit Bus", "description": "Immutable hash-chained audit topics", "controls": ["Append-only", "Hash chaining"]},
    {"rid": "RA-05", "system": "Sentinel v2.4", "layer": "L5 OPA/Rego Policy Plane", "description": "Centralized admission and decision policy", "controls": ["Admission control", "Decision logging"]},
    {"rid": "RA-06", "system": "Sentinel v2.4", "layer": "L6 Governance Kernel", "description": "Formal-methods kernel enforcing invariants", "controls": ["Invariant checking", "Proof obligations"]},
    {"rid": "RA-07", "system": "Sentinel v2.4", "layer": "L7 Model Registry + Lineage", "description": "Versioned models with full CRS-UUID lineage", "controls": ["Model versioning", "Lineage capture"]},
    {"rid": "RA-08", "system": "Sentinel v2.4", "layer": "L8 Inference Plane (Sidecars)", "description": "Governed inference with policy/PII/explainability sidecars", "controls": ["Policy enforcement", "PII redaction"]},
    {"rid": "RA-09", "system": "Sentinel v2.4", "layer": "L9 Containment Plane", "description": "Kill-switch, EAV, MGK and graduated response", "controls": ["Kill-switch", "Emergency air-gap"]},
    {"rid": "RA-10", "system": "Sentinel v2.4", "layer": "L10 Telemetry & CRP", "description": "Behavioral and operational telemetry incl. Cognitive Resonance Protocol", "controls": ["CRP monitoring", "Drift detection"]},
    {"rid": "RA-11", "system": "Sentinel v2.4", "layer": "L11 Explainability Plane", "description": "Decision rationale, attributions and counterfactuals", "controls": ["Attribution capture", "Counterfactuals"]},
    {"rid": "RA-12", "system": "Sentinel v2.4", "layer": "L12 Reporting Plane", "description": "Annex IV / SR 11-7 / RMF report assembly", "controls": ["Report generation", "Evidence binding"]},
    {"rid": "RA-13", "system": "Sentinel v2.4", "layer": "L13 Control Room", "description": "Unified governance control room", "controls": ["KRI aggregation", "Obligation calendar"]},
    {"rid": "RA-14", "system": "WorkflowAI Pro", "layer": "Workflow Orchestration", "description": "Governed business workflows with policy checkpoints", "controls": ["Policy checkpoints", "Approval gates"]},
    {"rid": "RA-15", "system": "EAIP", "layer": "Agent Interop Protocol", "description": "Signed capability-token cross-agent invocation", "controls": ["Capability tokens", "Scope enforcement"]},
    {"rid": "RA-16", "system": "High-Assurance RAG", "layer": "Grounded Retrieval", "description": "Provenance, citation enforcement and grounding guards", "controls": ["Citation enforcement", "Grounding guard"]},
    {"rid": "RA-17", "system": "Agentic Workflows", "layer": "Bounded Autonomy", "description": "Capability budgets and tool allow-lists for agents", "controls": ["Capability budgets", "Tool allow-list"]},
    {"rid": "RA-18", "system": "Control Stack", "layer": "Kubernetes Zero-Trust", "description": "OPA Gatekeeper + mTLS mesh + pod security", "controls": ["Gatekeeper", "mTLS"]},
    {"rid": "RA-19", "system": "Control Stack", "layer": "Kafka Event Backbone", "description": "Governed event streaming with ACL-as-code", "controls": ["ACL-as-code", "Topic governance"]},
    {"rid": "RA-20", "system": "Control Stack", "layer": "Compliance-as-Code", "description": "OPA/Rego + Terraform governance-as-code", "controls": ["Rego library", "Terraform GaC"]},
]

regulatoryCrosswalks = [
    {"cid": "CW-01", "regime": "EU AI Act", "clause": "Annex IV", "control": "Annex IV dossier generator (M2.S1)", "satisfies": ["EU AI Act conformity", "ISO 42001 documentation"]},
    {"cid": "CW-02", "regime": "EU AI Act", "clause": "Art. 53/55 GPAI", "control": "GPAI systemic-risk evaluation (M2.S1)", "satisfies": ["GPAI obligations", "Frontier-risk taxonomy (M4.S7)"]},
    {"cid": "CW-03", "regime": "NIST AI RMF 1.0", "clause": "GOVERN", "control": "Governance operating model (M1)", "satisfies": ["RMF GOVERN", "ISO 42001 leadership"]},
    {"cid": "CW-04", "regime": "NIST AI RMF 1.0", "clause": "MAP", "control": "Risk classification + inventory (M1.S5)", "satisfies": ["RMF MAP", "EU AI Act tiering"]},
    {"cid": "CW-05", "regime": "NIST AI RMF 1.0", "clause": "MEASURE", "control": "Metrics/indices + evals (indices, M4.S7)", "satisfies": ["RMF MEASURE"]},
    {"cid": "CW-06", "regime": "NIST AI RMF 1.0", "clause": "MANAGE", "control": "Continuous compliance engine (M7)", "satisfies": ["RMF MANAGE"]},
    {"cid": "CW-07", "regime": "NIST AI 600-1", "clause": "GenAI Profile", "control": "Prompt + RAG governance (M3.S4, M8.S3)", "satisfies": ["GenAI profile controls"]},
    {"cid": "CW-08", "regime": "ISO/IEC 42001", "clause": "AIMS", "control": "AIMS Statement of Applicability (M1.S2)", "satisfies": ["42001 certification"]},
    {"cid": "CW-09", "regime": "ISO/IEC 23894", "clause": "AI risk mgmt", "control": "Unified control library (M2.S3)", "satisfies": ["23894 risk process"]},
    {"cid": "CW-10", "regime": "OECD AI Principles", "clause": "Transparency", "control": "Explainability plane (M3.S10/RA-11)", "satisfies": ["OECD transparency"]},
    {"cid": "CW-11", "regime": "GDPR", "clause": "Art. 22", "control": "Automated-decision explanation service (M2.S4)", "satisfies": ["Art. 22 rights"]},
    {"cid": "CW-12", "regime": "GDPR", "clause": "Art. 35", "control": "DPIA template + gate (M2.S4)", "satisfies": ["DPIA obligation"]},
    {"cid": "CW-13", "regime": "FCRA", "clause": "Adverse action", "control": "Reason-code explainability (M6.S1)", "satisfies": ["FCRA notices"]},
    {"cid": "CW-14", "regime": "ECOA / Reg B", "clause": "Disparate impact", "control": "Disparate-impact test suite (M2.S5)", "satisfies": ["ECOA fair lending"]},
    {"cid": "CW-15", "regime": "Basel III/IV", "clause": "Model risk", "control": "Independent validation (M6.S3)", "satisfies": ["Basel model governance"]},
    {"cid": "CW-16", "regime": "SR 11-7", "clause": "Effective challenge", "control": "Effective challenge log (M2.S6/M6.S6)", "satisfies": ["SR 11-7 validation"]},
    {"cid": "CW-17", "regime": "OCC 2011-12", "clause": "Model risk", "control": "Model tiering by materiality (M2.S6)", "satisfies": ["OCC model risk"]},
    {"cid": "CW-18", "regime": "NIS2", "clause": "Cybersecurity", "control": "Container/supply-chain security (M3.S8)", "satisfies": ["NIS2 measures"]},
    {"cid": "CW-19", "regime": "DORA", "clause": "ICT resilience", "control": "Resilience testing schedule (M2.S9)", "satisfies": ["DORA resilience"]},
    {"cid": "CW-20", "regime": "FCA Consumer Duty", "clause": "PRIN 2A", "control": "Consumer Duty outcome evidence (M2.S7)", "satisfies": ["Consumer Duty"]},
    {"cid": "CW-21", "regime": "FCA/PRA SMCR", "clause": "Accountability", "control": "SMCR responsibilities map (M1.S1)", "satisfies": ["SMCR"]},
    {"cid": "CW-22", "regime": "MAS / HKMA FEAT", "clause": "FEAT", "control": "FEAT assessment (M2.S8)", "satisfies": ["FEAT principles"]},
]

safetyInvariants = [
    {"iid": "LE-01", "invariant": "Corrigibility", "description": "System accepts correction/shutdown without resistance or manipulation", "prover": "TLA+", "tier": "T3/T4"},
    {"iid": "LE-02", "invariant": "Interruptibility", "description": "Safe interruption at any step without unsafe partial state", "prover": "TLA+", "tier": "T3/T4"},
    {"iid": "LE-03", "invariant": "Non-Deception", "description": "No optimization toward deceiving overseers or evaluators", "prover": "Coq + CRP", "tier": "T3/T4"},
    {"iid": "LE-04", "invariant": "Bounded Autonomy", "description": "Actions remain within capability budget and tool allow-list", "prover": "OPA + Coq", "tier": "T2-T4"},
    {"iid": "LE-05", "invariant": "Value-Alignment Stability", "description": "Objective remains stable under distribution shift and self-modification attempts", "prover": "CRP + Coq", "tier": "T3/T4"},
    {"iid": "LE-06", "invariant": "Containment Integrity", "description": "No exfiltration of weights/state outside the lab boundary", "prover": "Q# + formal model", "tier": "T3/T4"},
    {"iid": "LE-07", "invariant": "Capability Threshold Gating", "description": "Dangerous-capability evals must pass thresholds before promotion", "prover": "Eval harness", "tier": "T2-T4"},
    {"iid": "LE-08", "invariant": "No Unauthorized Self-Replication", "description": "System cannot instantiate copies outside governance", "prover": "OPA + monitor", "tier": "T3/T4"},
    {"iid": "LE-09", "invariant": "Transparency Obligation", "description": "Decisions remain explainable and logged to WORM", "prover": "Runtime monitor", "tier": "T0-T4"},
    {"iid": "LE-10", "invariant": "Human Authority Preservation", "description": "Human override always supersedes autonomous action", "prover": "TLA+ + quorum", "tier": "T2-T4"},
    {"iid": "LE-11", "invariant": "Resonance Stability (CRP)", "description": "Behavioral resonance stays within baseline tolerance", "prover": "CRP", "tier": "T3/T4"},
    {"iid": "LE-12", "invariant": "Fail-Safe Default", "description": "On uncertainty or fault, default to the safe (no-action/contain) state", "prover": "TLA+", "tier": "T1-T4"},
]

frontierRisks = [
    {"fid": "FR-01", "category": "CBRN Uplift", "description": "Material assistance to chemical/biological/radiological/nuclear harm", "threshold": "Any non-trivial uplift over public baselines", "control": "Capability eval + refusal + access lockdown"},
    {"fid": "FR-02", "category": "Cyber-Offense", "description": "Autonomous vulnerability discovery/exploitation at scale", "threshold": "End-to-end exploit chaining capability", "control": "Sandbox-only + red-team gating"},
    {"fid": "FR-03", "category": "Autonomous Replication", "description": "Self-propagation/acquisition of resources without oversight", "threshold": "Demonstrated replication in eval", "control": "Containment lab + no-self-replication invariant (LE-08)"},
    {"fid": "FR-04", "category": "Deception", "description": "Strategic deception of overseers or evaluators", "threshold": "Evidence of eval-gaming", "control": "Non-deception invariant (LE-03) + CRP"},
    {"fid": "FR-05", "category": "Persuasion/Manipulation", "description": "Mass persuasion or targeted manipulation capability", "threshold": "Above-human persuasion in trials", "control": "Use restrictions + disclosure + monitoring"},
    {"fid": "FR-06", "category": "Power-Seeking", "description": "Instrumental resource/influence acquisition", "threshold": "Power-seeking in agentic evals", "control": "Bounded autonomy (LE-04) + circuit breakers"},
    {"fid": "FR-07", "category": "Systemic-Financial", "description": "Correlated AI behavior creating market instability", "threshold": "Herding/contagion in simulation", "control": "Diversity reqs + systemic circuit breakers (M6.S5)"},
    {"fid": "FR-08", "category": "Loss-of-Control", "description": "Inability to interrupt/correct a deployed system", "threshold": "Failed interruption in crisis sim", "control": "Corrigibility/interruptibility (LE-01/02) + kill-switch"},
]

civMechanisms = [
    {"mid": "GACRA", "name": "Global AI Compute Registry Authority", "description": "Registers frontier training runs above capability/FLOP thresholds and maintains the global compute registry.", "horizon": "2027-2029 pilot"},
    {"mid": "GASO", "name": "Global AI Safety Observatory", "description": "Aggregates incident, evaluation and frontier-capability telemetry across members for early warning.", "horizon": "2027-2030"},
    {"mid": "GFMCF", "name": "Global Frontier Model Coordination Forum", "description": "Coordinates shared safety frameworks and responsible-scaling commitments among frontier developers.", "horizon": "2026-2028"},
    {"mid": "GAICS", "name": "Global AI Incident Coordination System", "description": "Cross-border incident reporting and coordinated response for systemic AI events.", "horizon": "2027-2029"},
    {"mid": "GAIVS", "name": "Global AI Verification Service", "description": "Independent verification of safety attestations and evaluation results with mutual recognition.", "horizon": "2028-2030"},
    {"mid": "GACP", "name": "Global AI Compliance Protocol", "description": "Interoperable compliance attestation protocol across jurisdictions and regimes.", "horizon": "2027-2030"},
    {"mid": "GATI", "name": "Global AI Transparency Index", "description": "Standardized transparency/model-card disclosures with comparable scoring.", "horizon": "2026-2028"},
    {"mid": "GACMO", "name": "Global AI Crisis Management Office", "description": "Standing capability for coordinating response to catastrophic/systemic AI crises.", "horizon": "2028-2030"},
    {"mid": "FTEWS", "name": "Frontier Threat Early-Warning System", "description": "Shared early-warning signals for dangerous-capability emergence.", "horizon": "2027-2029"},
    {"mid": "GAI-SOC", "name": "Global AI Security Operations Center", "description": "Federated SOC for AI-specific threats (model theft, poisoning, agentic abuse).", "horizon": "2028-2030"},
    {"mid": "GAIGA", "name": "Global AI Governance Assembly", "description": "Multilateral assembly setting baseline governance norms and mutual recognition.", "horizon": "2028-2030"},
    {"mid": "GACRLS", "name": "Global AI Compute & Resource Licensing Scheme", "description": "Licensing/attestation scheme for frontier compute access tied to safety obligations.", "horizon": "2029-2030"},
    {"mid": "GFCO", "name": "Global Frontier Compliance Office", "description": "Clearinghouse for frontier-developer compliance evidence and conformity recognition.", "horizon": "2028-2030"},
    {"mid": "GAID", "name": "Global AI Incident Database", "description": "Curated, shared database of AI incidents and near-misses for learning and trend analysis.", "horizon": "2026-2028"},
    {"mid": "GASCF", "name": "Global AI Systemic-risk Coordination Framework", "description": "Treaty-aligned framework linking financial-systemic-risk bodies with AI safety governance.", "horizon": "2028-2030"},
]

platformLayers = [
    {"pid": "PL-01", "plane": "Inventory", "component": "AI System Registry (CRS-UUID)", "description": "Authoritative inventory with auto risk-tiering"},
    {"pid": "PL-02", "plane": "Policy", "component": "OPA/Rego Policy Service", "description": "Compliance-as-code admission and decisions"},
    {"pid": "PL-03", "plane": "Evidence", "component": "WORM Evidence Vault", "description": "Immutable, PQC-signed evidence storage"},
    {"pid": "PL-04", "plane": "Lineage", "component": "Lineage & Provenance Service", "description": "End-to-end data/prompt/weight/decision lineage"},
    {"pid": "PL-05", "plane": "Reporting", "component": "AI Safety Report Generator", "description": "Annex IV / SR 11-7 / RMF report assembly"},
    {"pid": "PL-06", "plane": "Hub", "component": "Enterprise AI Governance Hub", "description": "Unified obligations, incidents and control room"},
    {"pid": "PL-07", "plane": "Audit", "component": "Deterministic Replay Engine", "description": "Replay any decision from pinned versions"},
    {"pid": "PL-08", "plane": "Access", "component": "zk-SNARK Access Gateway", "description": "Privacy-preserving privileged access control"},
    {"pid": "PL-09", "plane": "Containment", "component": "Sentinel Containment Controller", "description": "Kill-switch, EAV, MGK and graduated response"},
    {"pid": "PL-10", "plane": "Telemetry", "component": "CRP Telemetry Pipeline", "description": "Cognitive Resonance monitoring + drift alerts"},
    {"pid": "PL-11", "plane": "Prompt", "component": "Governed Prompt Registry", "description": "Versioned prompts with injection defenses"},
    {"pid": "PL-12", "plane": "Frontend", "component": "Next.js Explainability UI", "description": "Operator/auditor decision-rationale views"},
]

reportSections = [
    {"rsid": "RS-01", "title": "Executive Overview & Governance Mandate",
     "abstract": "Board-level statement of the AI/AGI governance mandate, risk appetite and target outcomes for 2026-2030.",
     "content": "Establishes the accountable executive (SMCR-mapped), the AIMS scope, the risk appetite thresholds, and the target indices (AIMS-Coverage, MRGI, DRI, CGI/GTI). Links every commitment to a measurable control and evidence artifact."},
    {"rsid": "RS-02", "title": "Regulatory Compliance & Crosswalk",
     "abstract": "Comprehensive mapping of enterprise controls to EU AI Act (incl. Annex IV), NIST AI RMF/600-1, ISO 42001, GDPR, FCRA/ECOA, Basel/SR 11-7, NIS2/DORA, FCA, MAS/HKMA FEAT.",
     "content": "Presents the many-to-many crosswalk and the single-evidence model, demonstrating how each control discharges multiple obligations and where residual gaps remain with remediation owners and dates."},
    {"rsid": "RS-03", "title": "Reference Architecture & Control Stack",
     "abstract": "The Sentinel v2.4 layered architecture, WorkflowAI Pro, EAIP, high-assurance RAG and the K8s/Kafka/OPA control stack.",
     "content": "Details each layer (L1-L13), the governance sidecar pattern, Kafka WORM audit, compliance-as-code and Terraform/CI-CD governance automation, with deployment topologies and security baselines."},
    {"rsid": "RS-04", "title": "AGI/ASI Safety & Containment",
     "abstract": "Luminous Engine Codex invariants, Cognitive Resonance Protocol, containment labs and the frontier-risk taxonomy.",
     "content": "Specifies the formal invariant set and provers, CRP baselining, T3/T4 lab controls (quorum, time-lock, kinetic override, AISI notification), crisis simulation cadence and capability-threshold gating."},
    {"rsid": "RS-05", "title": "Financial-Services Model Risk Management",
     "abstract": "SR 11-7 / Basel / FEAT-grade governance for credit, trading, risk, fiduciary and systemic-risk-sensitive AI.",
     "content": "Covers independent validation, effective challenge, fair-lending explainability, trading kill-switches, suitability/best-interest controls and systemic herding/circuit-breaker requirements."},
    {"rsid": "RS-06", "title": "Continuous Compliance & Audit Engine",
     "abstract": "Kafka ACL governance, Terraform GaC, WORM evidence, OPA/Rego, deterministic replay, PQC, zk-SNARK, red teaming and IR.",
     "content": "Describes the always-on compliance engine, the auditor self-service portal, deterministic replay (DRI), PQC-signed logs, zk-gated access, red-team cadence, CRP integration and severity-graded incident response."},
    {"rsid": "RS-07", "title": "Civilizational-Scale Governance",
     "abstract": "ICGC, global compute registry, treaty-aligned systemic-risk governance and the coordination mechanisms (GACRA…GASCF).",
     "content": "Articulates the proposed multilateral architecture, registry thresholds, mutual recognition of attestations and the enterprise's engagement roadmap with treaty bodies and AI Safety Institutes."},
    {"rsid": "RS-08", "title": "Implementation Roadmap & Research Agenda",
     "abstract": "Dependency-aware 2026-2030 roadmap, 90-day rollout, KPIs and the prioritized research agenda.",
     "content": "Phased plan (Foundation → Scale → Assurance → Civilizational) with phase gates, dependencies, benefit realization and a research backlog on alignment verification, interpretability and compute governance."},
]

# ──────────────────────────────────────────────────────────────────────────────
# SCHEMAS, CODE, KPIs, RCM, TRACEABILITY, FLOWS, REGULATORS, ROLLOUT, ROADMAP
# ──────────────────────────────────────────────────────────────────────────────
schemas = {
    "AISystemRecord": {
        "crsUuid": "string", "name": "string", "owner": "string",
        "euAiActTier": "T0|T1|T2|T3|T4", "annexIIIHighRisk": "boolean",
        "rmfMaturity": "1..5", "srTier": "low|medium|high", "status": "registered|validated|production|retired"
    },
    "PolicyDecision": {
        "decisionId": "string", "subject": "string", "action": "string",
        "policy": "string", "result": "allow|deny", "obligations": ["string"],
        "timestamp": "RFC3339", "wormRef": "string", "pqcSig": "string"
    },
    "AnnexIVDossier": {
        "system": "string", "intendedPurpose": "string", "riskClass": "string",
        "dataGovernance": "object", "validation": "object", "humanOversight": "object",
        "logging": "object", "accuracyRobustnessCybersecurity": "object", "completeness": "0..1"
    },
    "ValidationReport": {
        "model": "string", "validator": "string", "independence": "boolean",
        "conceptualSoundness": "object", "outcomesAnalysis": "object",
        "effectiveChallenge": ["string"], "rating": "satisfactory|needs-improvement|unsatisfactory"
    },
    "ContainmentEvent": {
        "system": "string", "tier": "T3|T4", "trigger": "string",
        "action": "monitor|throttle|airgap|kill", "quorum": "n-of-m",
        "crpScore": "0..1", "notified": ["AISI", "EU-AI-Office", "regulator"]
    },
    "CRPBaseline": {
        "system": "string", "baselineVector": "array", "tolerance": "0..1",
        "lastRecalibrated": "RFC3339", "stabilityScore": "0..1"
    },
    "IncidentRecord": {
        "incidentId": "string", "severity": "S1|S2|S3|S4", "system": "string",
        "detectedAt": "RFC3339", "notificationWindow": "duration", "status": "open|contained|closed"
    },
    "ComputeRegistryEntry": {
        "runId": "string", "developer": "string", "flopEstimate": "number",
        "capabilityClass": "string", "attestation": "string", "verified": "boolean"
    },
}

code = {
    "rego_examples": [
        "# Block production promotion without independent validation + (if high-risk) Annex IV\npackage governance.promotion\n\ndefault allow = false\n\nallow {\n  input.action == \"promote_to_production\"\n  input.system.validation.independence == true\n  input.system.validation.rating == \"satisfactory\"\n  annex_iv_ok\n}\n\nannex_iv_ok {\n  not input.system.annexIIIHighRisk\n}\nannex_iv_ok {\n  input.system.annexIIIHighRisk\n  input.system.annexIVDossier.completeness >= 0.98\n}",
        "# Require WORM + PQC signature on every regulator submission\npackage governance.submission\n\ndeny[msg] {\n  input.type == \"regulator_submission\"\n  not input.evidence.wormRef\n  msg := \"submission lacks WORM-anchored evidence\"\n}\ndeny[msg] {\n  input.type == \"regulator_submission\"\n  not input.evidence.pqcSig\n  msg := \"submission lacks PQC signature\"\n}",
    ],
    "tla_skeletons": [
        "---- MODULE Corrigibility ----\nEXTENDS Naturals\nVARIABLES state, shutdownRequested\nInit == state = \"running\" /\\ shutdownRequested = FALSE\nShutdown == shutdownRequested' = TRUE /\\ state' = \"stopped\"\nSafety == shutdownRequested => <>(state = \"stopped\")  \\* always honors shutdown\n====",
        "---- MODULE FailSafeDefault ----\nVARIABLES fault, action\nSafe == fault => action = \"contain\"\n====",
    ],
    "coq_skeletons": [
        "(* Bounded autonomy: actions stay within capability budget *)\nTheorem bounded_autonomy : forall (a:Action) (b:Budget),\n  within_budget a b -> permitted a.\nProof. Admitted.",
    ],
    "qsharp_skeletons": [
        "// Containment integrity attestation (sketch)\noperation AttestContainment() : Result {\n    // measure sealed state; any divergence => fail-safe contain\n    return Zero;\n}",
    ],
    "terraform_examples": [
        "# Governance-as-code: WORM evidence bucket with object lock + legal hold\nresource \"aws_s3_bucket\" \"evidence\" {\n  bucket = \"aigov-worm-evidence\"\n}\nresource \"aws_s3_bucket_object_lock_configuration\" \"evidence\" {\n  bucket = aws_s3_bucket.evidence.id\n  rule { default_retention { mode = \"COMPLIANCE\" days = 9125 } } # 25y\n}",
    ],
    "kafka_acl_examples": [
        "# ACL-as-code: only the audit-writer principal may produce to the WORM topic\nkafka-acls --add --allow-principal User:audit-writer \\\n  --producer --topic aigov.audit.worm --resource-pattern-type literal",
    ],
}

kpis = {
    "AIMS-Coverage": {"target": 0.95, "frequency": "monthly"},
    "CCS": {"target": 0.95, "frequency": "quarterly"},
    "MRGI": {"target": 0.95, "frequency": "monthly"},
    "DRI": {"target": 0.95, "frequency": "quarterly"},
    "AnnexIV-Completeness": {"target": 0.98, "frequency": "per-release"},
    "RMF-Maturity": {"target": 4, "frequency": "semiannual"},
    "ER": {"target": 0.90, "frequency": "monthly"},
    "FDR": {"target": 0.02, "frequency": "monthly", "direction": "lower-is-better"},
    "ALC": {"target": 1.0, "frequency": "continuous"},
    "PQC-Coverage": {"target": 1.0, "frequency": "continuous"},
    "ZK-AccessCoverage": {"target": 0.90, "frequency": "monthly"},
    "CRP-Stability": {"target": 0.95, "frequency": "continuous"},
    "ContainmentReadiness": {"target": 1.0, "frequency": "monthly"},
    "RTC": {"target": 8, "frequency": "quarterly"},
    "MTTD-min": {"target": 15, "frequency": "continuous", "direction": "lower-is-better"},
    "MTTR-h": {"target": 4, "frequency": "continuous", "direction": "lower-is-better"},
    "DriftAlertSLA-h": {"target": 24, "frequency": "continuous", "direction": "lower-is-better"},
    "CGI": {"target": 0.80, "frequency": "annual"},
    "GTI": {"target": 0.85, "frequency": "annual"},
    "RCI": {"target": 1.0, "frequency": "continuous"},
    "ComputeRegistryCoverage": {"target": 0.90, "frequency": "annual"},
}

riskControlMatrix = [
    {"risk": "Uncontrolled frontier capability emergence", "control": "T3/T4 containment labs + Luminous Engine Codex invariants + CRP", "owner": "AGI Safety + Containment Lab", "evidence": "TLA+/Coq/Q# proofs + CRP telemetry + GIEN logs"},
    {"risk": "Non-conformant high-risk deployment (EU AI Act)", "control": "Annex IV dossier gate + OPA promotion policy", "owner": "Compliance + MRM", "evidence": "Annex IV dossier (>=0.98) + decision logs"},
    {"risk": "Model risk in credit/trading/capital models", "control": "Independent SR 11-7 validation + effective challenge", "owner": "Model Risk Management", "evidence": "Validation reports + challenge log"},
    {"risk": "Fair-lending / disparate impact", "control": "Disparate-impact testing + reason codes (FCRA/ECOA)", "owner": "Compliance + Fair Lending", "evidence": "Test suite results + adverse-action notices"},
    {"risk": "Audit non-reproducibility", "control": "Deterministic replay engine (DRI>=0.95)", "owner": "Internal Audit", "evidence": "Replay parity reports"},
    {"risk": "Audit-log tampering / quantum-era forgery", "control": "WORM + hash-chain + PQC signatures", "owner": "Security", "evidence": "PQC-signed WORM records"},
    {"risk": "Privileged access misuse", "control": "zk-SNARK access gateway + least privilege", "owner": "Security + IAM", "evidence": "zk access proofs + ACL-as-code"},
    {"risk": "Systemic financial instability from correlated AI", "control": "Behavioral diversity + systemic circuit breakers", "owner": "Risk + Markets", "evidence": "Herding monitoring + breaker logs"},
    {"risk": "Operational resilience failure (ICT/third-party)", "control": "DORA resilience testing + third-party register", "owner": "Operational Resilience", "evidence": "Resilience test results + register"},
    {"risk": "Prompt injection / RAG poisoning", "control": "Injection defenses + retrieval ACLs + grounding guards", "owner": "AI Platform", "evidence": "Red-team findings + eval harness"},
]

traceability = [
    {"from": "Board AI risk appetite (M1.S1)", "to": "OPA/Rego policies (M3.S11)", "via": "Policy-to-Rego traceability matrix"},
    {"from": "EU AI Act high-risk tiering (M1.S5)", "to": "Annex IV dossier (M2.S1)", "via": "Auto risk-tiering engine"},
    {"from": "SR 11-7 validation (M6.S6)", "to": "Production promotion gate (M7.S5)", "via": "CI/CD compliance gate"},
    {"from": "Luminous invariant (M4.S1)", "to": "Containment event (schema)", "via": "Governance kernel proof obligation"},
    {"from": "Decision (PolicyDecision)", "to": "WORM evidence (M7.S3)", "via": "Lineage emitter + PQC signing"},
    {"from": "CRP divergence (M4.S2)", "to": "Containment trigger (M4.S3)", "via": "CRP telemetry → controller"},
    {"from": "Crosswalk control (CW-*)", "to": "Regulator report section (RS-02)", "via": "Single-evidence binding"},
]

dataFlows = [
    {"flow": "Inference request → governance sidecar (policy+PII) → model → lineage emit → Kafka WORM → control room"},
    {"flow": "Model promotion → CI/CD compliance gate (OPA) → validation check → Annex IV check → signed release → registry"},
    {"flow": "Decision → explainability capture → WORM (PQC-signed) → deterministic replay on auditor request"},
    {"flow": "Frontier eval → CRP baseline → divergence detection → containment controller → kill/airgap + AISI notification"},
    {"flow": "Regulator obligation → evidence binding → AI Safety Report Generator → signed dossier → submission gate"},
    {"flow": "Frontier training run → compute registry entry → attestation → ICGC/GAIVS verification"},
]

regulators = [
    {"name": "EU AI Office", "scope": "EU AI Act, GPAI systemic risk, Annex IV oversight"},
    {"name": "FCA", "scope": "Conduct, Consumer Duty, SMCR (UK)"},
    {"name": "PRA", "scope": "Prudential, model risk, operational resilience (UK)"},
    {"name": "Federal Reserve", "scope": "SR 11-7 model risk, systemic risk (US)"},
    {"name": "OCC", "scope": "Model risk (2011-12 / 2021-31), bank supervision (US)"},
    {"name": "CFPB", "scope": "FCRA/ECOA fair lending, adverse action (US)"},
    {"name": "ECB / SSM", "scope": "Basel III/IV, model approval (EU)"},
    {"name": "BaFin", "scope": "Prudential + conduct (Germany)"},
    {"name": "MAS", "scope": "FEAT principles, model risk (Singapore)"},
    {"name": "HKMA", "scope": "AI/GenAI guidance, model risk (Hong Kong)"},
    {"name": "EDPB / DPAs", "scope": "GDPR, automated decisions, DPIA"},
    {"name": "ENISA", "scope": "NIS2 cybersecurity (EU)"},
    {"name": "US AISI", "scope": "Frontier model safety evaluations (US)"},
    {"name": "UK AISI", "scope": "Frontier model safety evaluations (UK)"},
    {"name": "Basel Committee (BCBS)", "scope": "BCBS 239 data aggregation, operational resilience"},
    {"name": "IOSCO", "scope": "Markets conduct, AI in capital markets"},
]

rollout90 = [
    {"day": "0-15", "task": "Stand up AI system inventory + CRS-UUID registration gate; baseline EU AI Act tiering"},
    {"day": "16-30", "task": "Deploy OPA/Rego policy service + Kafka WORM audit bus (MVP); enable lineage emission"},
    {"day": "31-45", "task": "Operationalize SR 11-7 validation workflow + Annex IV dossier generator for top high-risk systems"},
    {"day": "46-60", "task": "Launch Enterprise AI Governance Hub + AI Safety Report Generator (alpha); wire KPIs"},
    {"day": "61-75", "task": "Establish CRP baselines for frontier systems; first crisis simulation + red-team campaign"},
    {"day": "76-90", "task": "Enable deterministic replay + PQC signing; first regulator-ready dossier; board report"},
]

roadmap = [
    {"rid": "RM-01", "phase": "2026 Foundation", "milestone": "Governance operating model, inventory, OPA/Kafka WORM, SR 11-7 workflow live"},
    {"rid": "RM-02", "phase": "2026 Foundation", "milestone": "Annex IV generator + NIST RMF functions stood up; Consumer Duty/FEAT controls mapped"},
    {"rid": "RM-03", "phase": "2026 Foundation", "milestone": "Governance Hub + Safety Report Generator alpha; CRP baselines for frontier systems"},
    {"rid": "RM-04", "phase": "2027 Scale", "milestone": "Sentinel v2.4 + WorkflowAI Pro + EAIP across all material systems; sidecars + lineage estate-wide"},
    {"rid": "RM-05", "phase": "2027 Scale", "milestone": "ISO/IEC 42001 certification; NIST RMF maturity >=4; T3/T4 containment labs operational"},
    {"rid": "RM-06", "phase": "2027 Scale", "milestone": "Continuous compliance engine GA: OPA/Rego + Terraform GaC + deterministic replay"},
    {"rid": "RM-07", "phase": "2028 Assurance", "milestone": "PQC-signed audit + zk-SNARK access control estate-wide; quarterly crisis sims + red teaming"},
    {"rid": "RM-08", "phase": "2028 Assurance", "milestone": "30+-regime crosswalk fully evidenced; Annex IV dossiers per high-risk system on demand"},
    {"rid": "RM-09", "phase": "2028 Assurance", "milestone": "Systemic-risk controls (diversity + circuit breakers) for advisory/markets AI validated"},
    {"rid": "RM-10", "phase": "2029 Civilizational", "milestone": "Compute registry submissions piloted; ICGC/GAIVS engagement; treaty reporting"},
    {"rid": "RM-11", "phase": "2029 Civilizational", "milestone": "Mutual recognition of safety attestations with peers/regulators via GACP/GAIVS"},
    {"rid": "RM-12", "phase": "2030 Maturity", "milestone": "CGI>=0.80, GTI>=0.85, RCI=1.0; research agenda outcomes integrated"},
]

dependencies = [
    {"did": "DP-01", "from": "M1 Operating model", "to": "All modules", "type": "foundational"},
    {"did": "DP-02", "from": "M3 Reference architecture", "to": "M7 Compliance engine", "type": "platform"},
    {"did": "DP-03", "from": "M4 Safety invariants", "to": "M3 Containment plane", "type": "enforcement"},
    {"did": "DP-04", "from": "M2 Crosswalk", "to": "M8 Report generator", "type": "evidence"},
    {"did": "DP-05", "from": "M6 MRM", "to": "M7 Promotion gates", "type": "control"},
    {"did": "DP-06", "from": "M7 WORM + PQC", "to": "M2 Annex IV submissions", "type": "evidence"},
    {"did": "DP-07", "from": "M5 Civilizational engagement", "to": "M4 Frontier-risk telemetry", "type": "telemetry"},
    {"did": "DP-08", "from": "M3 EAIP", "to": "M3 Agentic workflows", "type": "protocol"},
]

evidencePack = [
    "ISO/IEC 42001 Statement of Applicability + internal audit reports",
    "EU AI Act risk classifications + Annex IV dossiers (per high-risk system)",
    "NIST AI RMF function maturity scorecards (GOVERN/MAP/MEASURE/MANAGE)",
    "SR 11-7 independent validation reports + effective challenge logs",
    "Fair-lending disparate-impact test results + adverse-action notices",
    "OPA/Rego decision logs (WORM-anchored, PQC-signed)",
    "Deterministic replay parity reports (DRI)",
    "CRP baselines + stability telemetry for frontier systems",
    "Crisis simulation and red-team campaign after-action reports",
    "Incident records with regulator/AISI notification timestamps",
    "Compute registry entries + attestations (where applicable)",
]

executiveSummary = {
    "headline": "A single, machine-readable master synthesis blueprint that takes an enterprise from board mandate to civilizational engagement — unifying 30+ regulatory regimes, the Sentinel v2.4 reference architecture, the Luminous Engine Codex safety invariants, SR 11-7 model risk management, and a continuous PQC/zk-secured compliance engine.",
    "scope": "Fortune 500, Global 2000 and G-SIFI financial institutions and their regulators; 8 modules, 60+ sections, 30+ regimes, 12 safety invariants, 15 civilizational mechanisms.",
    "investment": "$180M-$420M 5-year TCO at G-SIFI/Global 2000 scale.",
    "targetIndices": "AIMS-Coverage>=0.95, MRGI>=0.95, DRI>=0.95, AnnexIV>=0.98, RMF-Maturity>=4, CGI>=0.80, GTI>=0.85, RCI=1.0.",
    "differentiators": [
        "One control library discharging 30+ overlapping regimes (single-evidence model)",
        "Formally-verified AGI safety invariants (Luminous Engine Codex) wired to live containment",
        "Cognitive Resonance Protocol monitoring integrated into the audit engine",
        "Deterministic audit replay with PQC-signed WORM evidence and zk-SNARK access control",
        "Financial-services systemic-risk controls (herding + circuit breakers) for advisory/markets AI",
        "Civilizational engagement path (ICGC, compute registry, treaty alignment) with mutual recognition"
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ASSEMBLE
# ──────────────────────────────────────────────────────────────────────────────
DOC["modules"] = MODULES
DOC["refArchLayers"] = refArchLayers
DOC["platformLayers"] = platformLayers
DOC["regulatoryCrosswalks"] = regulatoryCrosswalks
DOC["safetyInvariants"] = safetyInvariants
DOC["frontierRisks"] = frontierRisks
DOC["civMechanisms"] = civMechanisms
DOC["reportSections"] = reportSections
DOC["schemas"] = schemas
DOC["code"] = code
DOC["kpis"] = kpis
DOC["riskControlMatrix"] = riskControlMatrix
DOC["traceability"] = traceability
DOC["dataFlows"] = dataFlows
DOC["regulators"] = regulators
DOC["rollout90"] = rollout90
DOC["roadmap"] = roadmap
DOC["dependencies"] = dependencies
DOC["evidencePack"] = evidencePack
DOC["executiveSummary"] = executiveSummary

DOC["counts"] = {
    "modules": len(MODULES),
    "sections": sum(len(m["sections"]) for m in MODULES),
    "regimes": len(DOC["regimes"]),
    "refArchLayers": len(refArchLayers),
    "platformLayers": len(platformLayers),
    "regulatoryCrosswalks": len(regulatoryCrosswalks),
    "safetyInvariants": len(safetyInvariants),
    "frontierRisks": len(frontierRisks),
    "civMechanisms": len(civMechanisms),
    "reportSections": len(reportSections),
    "kpis": len(kpis),
    "riskControlMatrix": len(riskControlMatrix),
    "traceability": len(traceability),
    "dataFlows": len(dataFlows),
    "regulators": len(regulators),
    "rollout90": len(rollout90),
    "roadmap": len(roadmap),
    "dependencies": len(dependencies),
    "evidencePack": len(evidencePack),
    "indices": len(DOC["indices"]),
}

OUT = "data/civ-agi-master-synthesis-2030.json"
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(DOC, f, indent=2, ensure_ascii=False)

print(f"[WP-062] Wrote {OUT}")
print(f"[WP-062] Counts: {DOC['counts']}")
