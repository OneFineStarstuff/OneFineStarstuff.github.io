#!/usr/bin/env python3
"""WP-045 — Enterprise AGI/ASI Governance Master Reference & Implementation Blueprint.

Builds data/agi-asi-master-bp.json: a regulator-submission-grade, end-to-end
Master Reference & Implementation Blueprint (2026-2030) for Fortune 500 /
Global 2000 / G-SIFI financial institutions, EU-primary but globally
interoperable, including the machine-parsable <directive> block, full
Annexes A-G + D/E/F (Kafka WORM, OPA library, Terraform modules,
explainability schema, traceability matrix, containment playbooks,
supervisory drill scripts, regulator demo kit, workshops, supervisory
notebook, attestation ledger and GAP protocol, GAP reference impl,
adoption strategy, readiness kits, facilitator certification, Global
Supervisory Council, legal charter & treaty framework, geopolitical
adoption playbooks, simulation scenarios, negotiation support, the
Autonomous Negotiation Co-Pilot, Supervisory Submission Pack & Engagement
Playbook, Supervisory Approval Simulation Kit, Global Regulator Training
Consortium, Global Supervisory Knowledge Graph, Supervisory Intelligence
Engine, Supervisory Co-Pilot Network, and Planetary Supervisory Mesh).
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "agi-asi-master-bp.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "AGI-ASI-MASTER-BP-WP-045",
    "version": "1.0.0",
    "horizon": "2026-2030 (extends to 2032 for adoption)",
    "classification": (
        "CONFIDENTIAL — Board / CRO / CISO / CAIO / GC / DPO / Internal Audit / "
        "Prudential Supervisor / AI Safety Institute / Treaty Authority"
    ),
    "title": (
        "Enterprise AGI/ASI Governance Master Reference & Implementation "
        "Blueprint (EU-Primary, Globally Interoperable)"
    ),
    "subtitle": (
        "Regulator-Submission-Grade Operating System for Fortune 500 / Global "
        "2000 / G-SIFIs — Governance Framework Mappings, Architecture, Model "
        "Risk Governance, AGI/ASI Containment, Compute Governance, Stack, "
        "Roadmap, Roles, Supervisory Readiness, Risk & Control Matrix, "
        "Capability Plan, Annexes A-G + D/E/F (2026-2030)"
    ),
    "owner": (
        "CAIO + CRO + GC; co-signed by CISO, DPO, Head of Internal Audit, "
        "Head of Compliance, Head of Treasury, AI Safety Lead, Treaty Liaison, "
        "Chief Data Officer, Head of Model Risk Management"
    ),
    "buildsOn": [
        "WP-035 ENT-AGI-GOV-MASTER",
        "WP-036 WFAP-GEMINI-IMPL",
        "WP-037 GSIFI-AIMS-BLUEPRINT",
        "WP-038 AGI-REG-RESILIENT",
        "WP-039 INST-AGI-MASTER",
        "WP-040 ENT-AGI-REF-IMPL",
        "WP-041 TIER13-FULLSTACK",
        "WP-042 SENTINEL-V24-DEEPDIVE",
        "WP-043 PROMPT-MGMT-ARCH",
        "WP-044 CEGL-LEXAI-GOV",
    ],
    "regimes": [
        "EU AI Act 2026 (Arts 5/9/10/13/14/15/16/26/50/53/55/56/72)",
        "NIST AI RMF 1.0 + Generative AI Profile",
        "ISO/IEC 42001 (AIMS) + Annex A controls",
        "ISO/IEC 23894 (AI risk) + ISO/IEC 5338 (AI lifecycle)",
        "ISO/IEC 38507 (governance implications of AI)",
        "ISO/IEC 27001 / 27701 (ISMS / PIMS)",
        "GDPR Arts 5/6/22/25/32/35 + EDPB AI guidelines",
        "EU DORA (operational resilience)",
        "Basel III/IV (BCBS 239 risk data aggregation, Pillar 2 add-ons)",
        "SR 11-7 (US Fed Model Risk Management) + OCC 2011-12",
        "PRA SS1/23 (model risk) + SS2/21 (operational resilience)",
        "FCA Consumer Duty + SYSC + SMCR (Senior Managers & Certification Regime)",
        "MAS FEAT Principles + AI Verify + TRMG",
        "HKMA SPM GS-1 / GL-90 / TM-G-1",
        "OECD AI Principles 2024",
        "G7 Hiroshima AI Process Code of Conduct",
        "Council of Europe Framework Convention on AI",
        "FSB recommendations on AI in financial services",
        "US EO 14110 (and successor frameworks) + NIST GAI Profile",
        "OWASP LLM Top 10 (2025) + MITRE ATLAS",
    ],
    "apiPrefix": "/api/agi-asi-master-bp",
}

# ---------------------- machine-parsable <directive> block ----------------------
DOC["directive"] = {
    "format": "machine-parsable XML-style directive block embedded in the Governance & Architecture Report",
    "raw": (
        "<directive id=\"AGI-ASI-MASTER-BP-WP-045\" version=\"1.0.0\" "
        "horizon=\"2026-2030\" jurisdiction=\"EU-primary,global-interop\">"
        "<scope>Fortune500|Global2000|G-SIFI</scope>"
        "<sections>"
        "<section ref=\"S1\">Governance Framework Mappings</section>"
        "<section ref=\"S2\">AI Governance Architecture</section>"
        "<section ref=\"S3\">Financial Services Model Risk Governance</section>"
        "<section ref=\"S4\">AGI/ASI Safety and Containment</section>"
        "<section ref=\"S5\">Global AI and Compute Governance</section>"
        "<section ref=\"S6\">Implementation Stack</section>"
        "<section ref=\"S7\">Roadmap (2026-2030)</section>"
        "<section ref=\"S8\">Roles and Accountability</section>"
        "<section ref=\"S9\">Supervisory Readiness and Auditability</section>"
        "<section ref=\"S10\">Risk and Control Matrix</section>"
        "<section ref=\"S11\">Resource and Capability Plan</section>"
        "<section ref=\"S12\">Annex Scaffolding</section>"
        "</sections>"
        "<annexes>"
        "<annex ref=\"A\">Kafka WORM Logging</annex>"
        "<annex ref=\"B\">OPA Policy Library</annex>"
        "<annex ref=\"C\">Terraform Governance Modules</annex>"
        "<annex ref=\"D\">Explainability Schema + Cross-Jurisdictional Traceability Matrix</annex>"
        "<annex ref=\"E\">Containment Playbooks + Supervisory Drill Scripts + Regulator Demo Kit + Workshops</annex>"
        "<annex ref=\"F\">Supervisory Notebook + Attestation Ledger + GAP Protocol + GAP Reference Impl</annex>"
        "<annex ref=\"G\">Adoption + Pilots + Geopolitical + Planetary Supervisory Mesh</annex>"
        "</annexes>"
        "<artifacts>"
        "<artifact id=\"PSM\">Planetary Supervisory Mesh</artifact>"
        "<artifact id=\"SCN\">Supervisory Co-Pilot Network</artifact>"
        "<artifact id=\"SIE\">Supervisory Intelligence Engine</artifact>"
        "<artifact id=\"GSKG\">Global Supervisory Knowledge Graph</artifact>"
        "<artifact id=\"GRTC\">Global Regulator Training Consortium</artifact>"
        "<artifact id=\"SASK\">Supervisory Approval Simulation Kit</artifact>"
        "<artifact id=\"SSPEP\">Supervisory Submission Pack and Engagement Playbook</artifact>"
        "<artifact id=\"ANC\">Autonomous Negotiation Co-Pilot</artifact>"
        "<artifact id=\"GSC\">Global Supervisory Council</artifact>"
        "<artifact id=\"GAP\">Governance Attestation Protocol</artifact>"
        "</artifacts>"
        "<thresholds containmentDelta=\"0.04\" latentDriftAlert=\"0.03\" "
        "killSwitchSeconds=\"60\" fiduciaryCosineMin=\"0.92\" "
        "evidencePackMinutes=\"30\" incidentReportingHours=\"24\"/>"
        "<signing>multisig=3-of-5; pqc=Ed25519+ML-DSA-65; anchor=daily Merkle</signing>"
        "</directive>"
    ),
    "parsed": {
        "id": "AGI-ASI-MASTER-BP-WP-045",
        "version": "1.0.0",
        "horizon": "2026-2030",
        "jurisdiction": "EU-primary,global-interop",
        "scope": ["Fortune500", "Global2000", "G-SIFI"],
        "sectionRefs": [f"S{i}" for i in range(1, 13)],
        "annexRefs": ["A", "B", "C", "D", "E", "F", "G"],
        "artifactIds": [
            "PSM", "SCN", "SIE", "GSKG", "GRTC", "SASK",
            "SSPEP", "ANC", "GSC", "GAP",
        ],
        "thresholds": {
            "containmentDelta": 0.04,
            "latentDriftAlert": 0.03,
            "killSwitchSeconds": 60,
            "fiduciaryCosineMin": 0.92,
            "evidencePackMinutes": 30,
            "incidentReportingHours": 24,
        },
        "signing": {
            "multisig": "3-of-5",
            "pqc": ["Ed25519", "ML-DSA-65"],
            "anchor": "daily-merkle",
        },
    },
    "consumers": [
        "Sentinel sidecar policy loader",
        "OPA bundle compiler",
        "Supervisory Notebook ingestor",
        "Regulator Submission Pack builder",
        "Planetary Supervisory Mesh registry",
    ],
}

# ---------------------- 14 modules ----------------------
modules = []

# ---- M1 ----
modules.append({
    "id": "M1",
    "title": "M1 — Governance Framework Mappings (S1)",
    "summary": (
        "Authoritative crosswalk of the Master Blueprint to ISO/IEC 42001, "
        "NIST AI RMF 1.0, GDPR, EU AI Act 2026, SR 11-7, Basel III/IV, "
        "PRA/FCA, MAS FEAT, HKMA, SMCR, FCA Consumer Duty — with article-level "
        "evidence references and machine-parseable <directive> linkage."
    ),
    "covers": ["ISO/IEC 42001", "NIST AI RMF", "GDPR", "EU AI Act", "SR 11-7", "Basel", "PRA/FCA", "MAS", "HKMA", "SMCR", "Consumer Duty"],
    "sections": [
        section("M1-S1", "Mapping Methodology", {
            "principles": [
                "Each control has a single primary regime and N secondary regimes",
                "Article-level granularity (e.g. EU AI Act Art 9, GDPR Art 22, SR 11-7 §III.B)",
                "Every control is linked to a Sentinel/OPA enforcement point",
                "Cross-walk maintained as machine-readable JSON with semantic versioning",
            ],
            "tooling": ["OSCAL profile", "ISO/IEC 42001 Annex A control catalogue", "NIST AI RMF Crosswalk Tool", "Sentinel Traceability Engine"],
        }),
        section("M1-S2", "EU AI Act 2026 (Primary)", {
            "articles": {
                "Art 5": "Prohibited practices — hard-blocked at sidecar",
                "Art 9": "Risk management system — lifecycle hooks",
                "Art 10": "Data governance — provenance + minimization",
                "Art 13": "Transparency — explanation envelope",
                "Art 14": "Human oversight — kill-switch + two-eyes",
                "Art 15": "Accuracy/robustness/cybersecurity — red-team",
                "Art 16/26": "Provider/deployer obligations",
                "Art 50": "Disclosure of AI interaction",
                "Art 53/55": "GPAI + systemic-risk model obligations",
                "Art 72": "Post-market monitoring",
            },
            "highRiskClasses": ["credit-scoring", "insurance pricing", "employment", "AML decisioning"],
        }),
        section("M1-S3", "ISO/IEC 42001 + 23894 + 5338 + 38507", {
            "AIMS": "Plan-Do-Check-Act over the AI lifecycle (ISO 42001)",
            "annexA": "37 controls mapped to Sentinel modules and OPA bundles",
            "lifecycle": "ISO/IEC 5338 phases mapped to CI/CD gates and MRM checkpoints",
            "boardOversight": "ISO/IEC 38507 mapped to SMCR Senior Manager responsibilities",
        }),
        section("M1-S4", "NIST AI RMF 1.0 + GAI Profile", {
            "functions": ["Govern", "Map", "Measure", "Manage"],
            "gaiProfile": "Applies to all foundation-model use; integrated with red-team engine",
            "evidence": "Each function emits a hash-chained envelope into the WORM ledger",
        }),
        section("M1-S5", "Sectoral Prudential — SR 11-7, Basel III/IV, PRA SS1/23, MAS, HKMA, SMCR, Consumer Duty", {
            "SR 11-7": "Effective challenge, independent validation, MRM inventory",
            "Basel": "BCBS 239 risk-data aggregation; Pillar 2 AI capital overlay",
            "PRA SS1/23": "Model risk principles 1-5; aligned to ISO 42001 + Sentinel evidence",
            "FCA Consumer Duty": "Foreseeable-harm checks via OPA + outcome KPIs",
            "MAS FEAT": "Fairness, Ethics, Accountability, Transparency — AI Verify integration",
            "HKMA GL-90": "Lifecycle controls, third-party risk, explainability",
            "SMCR": "Statements of Responsibility with explicit AI-domain coverage",
        }),
    ],
})

# ---- M2 ----
modules.append({
    "id": "M2",
    "title": "M2 — AI Governance Architecture (S2)",
    "summary": (
        "Layered EU-primary architecture: Civilizational Codex → Treaty layer "
        "→ LexAI/OPA policy plane → Sentinel sidecar enforcement → "
        "Application & MLOps planes → Citizen/redress plane. Zero-trust, "
        "Kafka WORM, multisig change control."
    ),
    "covers": ["layers", "zero-trust", "WORM", "policy-plane", "control-plane", "data-plane"],
    "sections": [
        section("M2-S1", "Reference Architecture (7 planes)", {
            "planes": [
                "Codex/Constitutional plane (axioms + red lines)",
                "Treaty/Regulatory plane (EU AI Act + sectoral)",
                "Policy plane (OPA Rego + LexAI bundles)",
                "Control plane (Sentinel sidecar + MutatingWebhook)",
                "Application plane (RAG, agents, model registry)",
                "Data plane (Kafka WORM, vector store, lakehouse)",
                "Citizen/Redress plane (DSAR portal, contestation)",
            ],
        }),
        section("M2-S2", "Zero-Trust Service Mesh", {
            "identity": "SPIFFE/SPIRE workload identity",
            "mTLS": "All east-west traffic mTLS; per-call attestation",
            "policy": "OPA sidecar with failurePolicy: Fail",
            "secrets": "Envelope-encrypted; KMS-rooted; FIPS 140-3 L3+",
        }),
        section("M2-S3", "Decision Envelope Schema", {
            "fields": ["envelopeId", "ts", "systemId", "promptHash", "outputHash", "fairness", "explanations", "policyDecisions", "prevHash", "thisHash", "signatures"],
            "signing": "Ed25519 + ML-DSA-65 hybrid; daily Merkle anchoring",
        }),
        section("M2-S4", "Multi-Region & Air-Gap Variants", {
            "EU primary": "eu-west + eu-central active-active",
            "Global interop": "us-east, ap-southeast, ap-northeast read replicas",
            "Air-gap": "Docker Swarm enclave for Tier-1 (compute/AGI) workloads",
        }),
        section("M2-S5", "Change Management & Multisig", {
            "GitOps": "Argo CD / Flux with signed manifests",
            "multisig": "3-of-5 for Tier-1 OPA bundles and model promotion",
            "rollback": "Signed rollback bundles auto-staged for ≤ 5 min revert",
        }),
    ],
})

# ---- M3 ----
modules.append({
    "id": "M3",
    "title": "M3 — Financial Services Model Risk Governance (S3)",
    "summary": (
        "SR 11-7 / PRA SS1/23-aligned MRM lifecycle, with effective challenge, "
        "independent validation, ongoing monitoring, capital overlay, "
        "BCBS 239 data aggregation, and AI-CCP integration."
    ),
    "covers": ["MRM", "SR 11-7", "PRA SS1/23", "BCBS 239", "Pillar 2", "validation"],
    "sections": [
        section("M3-S1", "MRM Inventory & Tiering", {
            "tiers": "T1 (high impact) — full validation; T2 — proportionate; T3 — light-touch",
            "inventory": "Single source of truth in Model Registry (M6 of WP-043 integrated)",
        }),
        section("M3-S2", "Independent Validation", {
            "scope": ["conceptual soundness", "implementation testing", "outcome analysis", "ongoing monitoring"],
            "evidence": "Validation reports stored as signed Decision Envelopes",
        }),
        section("M3-S3", "Drift, Stability & Outcome Analysis", {
            "metrics": ["PSI", "KS", "AUC drift", "calibration drift", "fairness drift"],
            "thresholds": "Tied to Sentinel containmentDelta ≤ 0.04 and latentDrift ≤ 0.03",
        }),
        section("M3-S4", "Pillar 2 AI Capital Overlay", {
            "method": "Risk-based overlay calibrated to GTI sub-indices (alignment, drift, fairness, incident)",
            "review": "Annually with supervisor; ad-hoc on SEV-1 events",
        }),
        section("M3-S5", "Effective Challenge & Three Lines", {
            "1LoD": "Model owner + dev",
            "2LoD": "MRM + Compliance + AI Risk",
            "3LoD": "Internal Audit (annual + thematic)",
        }),
    ],
})

# ---- M4 ----
modules.append({
    "id": "M4",
    "title": "M4 — AGI/ASI Safety and Containment (S4)",
    "summary": (
        "Cognitive Resonance Protocol, latent drift Δ_drift ≤ 4 %, fiduciary "
        "cosine ≥ 0.92, kill-switch ≤ 60 s, multi-agent swarm consensus, "
        "PQC-signed bundles, air-gapped enclaves, deceptive-alignment red-team."
    ),
    "covers": ["containment", "Δ_drift", "kill-switch", "swarm-consensus", "deceptive-alignment"],
    "sections": [
        section("M4-S1", "Containment Threshold & Δ_drift", {
            "containmentDelta": 0.04,
            "latentDriftAlert": 0.03,
            "fiduciaryCosineMin": 0.92,
            "monitor": "PyTorch hooks + cosine sim to fiduciary vector Φ",
        }),
        section("M4-S2", "Kill-Switch Architecture", {
            "SLA": "p95 ≤ 60 s global; signed multisig 3-of-5 trigger",
            "fanout": "Anycast to all sidecars; verified ack within SLA",
            "fail-closed": "Sidecar denies inference on signature failure",
        }),
        section("M4-S3", "Multi-Agent Swarm Consensus", {
            "protocol": "Cognitive attestation per agent; quorum > 2/3; latent-drift veto",
            "isolation": "Per-agent zero-trust microsegmentation",
        }),
        section("M4-S4", "Red-Team & Deceptive-Alignment", {
            "engine": "Polymorphic prompt-injection + reward-hacking probes (WP-042 M13)",
            "post-mortem": "Omni-Fiduciary-Trading-Candidate-v9 lessons → Codex updates",
        }),
        section("M4-S5", "Air-Gap & PQC", {
            "air-gap": "Docker Swarm enclaves for Tier-1; SPIFFE inside",
            "pqc": "ML-DSA-65 hybrid signatures; HSM (FIPS 140-3 L4) custody",
        }),
    ],
})

# ---- M5 ----
modules.append({
    "id": "M5",
    "title": "M5 — Global AI and Compute Governance (S5)",
    "summary": (
        "Compute thresholds, frontier-model registry, cross-border kill-switch "
        "mutual recognition, sandbox passporting, AI-CCP and Trust Derivatives "
        "Layer integration, IMF Article IV AI annex feed."
    ),
    "covers": ["compute", "frontier-registry", "passport", "AI-CCP", "TDL", "IMF"],
    "sections": [
        section("M5-S1", "Compute Threshold Registry", {
            "primary": "FLOPs threshold (per EU AI Act Art 51) and capability evals",
            "registry": "Permissioned ledger with Treaty Authority co-signing",
        }),
        section("M5-S2", "Cross-Border Kill-Switch Mutual Recognition", {
            "treaty": "GASRGP Art 6 (≤ 60 s p95)",
            "operations": "Per-jurisdiction supervisor-gateway-svc with mTLS",
        }),
        section("M5-S3", "Sandbox Passporting", {
            "sla": "≤ 45 days cross-jurisdiction acceptance",
            "evidence": "Mutual-recognition envelope + AISI co-sign",
        }),
        section("M5-S4", "Trust Derivatives Layer (TDL)", {
            "instruments": "Trust bonds and swaps; CCP-cleared",
            "circuit-breakers": "Spread floor breach → CCP coordination per RB-07",
        }),
        section("M5-S5", "IMF / FSB Feeds", {
            "imf": "Article IV AI annex; FSAP-AI scenario library",
            "fsb": "AI dashboard daily feed; cross-border incident sharing",
        }),
    ],
})

# ---- M6 ----
modules.append({
    "id": "M6",
    "title": "M6 — Implementation Stack (S6)",
    "summary": (
        "End-to-end stack: Sentinel sidecar, OPA, Kafka WORM, Terraform IaC, "
        "MutatingWebhook, model registry, RAG, observability, CI/CD with SLSA L3+ "
        "and Sigstore, PQC HSM, KMS, SPIFFE/SPIRE."
    ),
    "covers": ["Sentinel", "OPA", "Kafka", "Terraform", "MLflow", "Sigstore", "SLSA"],
    "sections": [
        section("M6-S1", "Runtime Plane", {
            "components": ["Sentinel sidecar v2.4", "OPA bundle", "Envoy/mTLS", "Kafka WORM", "Vector DB"],
            "language": "Go + TypeScript + Python",
        }),
        section("M6-S2", "MLOps Plane", {
            "registry": "MLflow + Vertex/SageMaker/Azure ML adapters",
            "promotion": "Multisig 3-of-5; signed model card; Sigstore attestation",
        }),
        section("M6-S3", "IaC Plane (Terraform)", {
            "modules": ["sentinel-sidecar", "kafka-worm", "opa-bundle", "k8s-mwh", "kms-pqc", "spiffe-spire", "supervisor-gateway", "audit-anchor"],
        }),
        section("M6-S4", "CI/CD & Supply Chain", {
            "supply-chain": "SLSA L3+; SBOM (CycloneDX); Sigstore cosign; Sigstore Rekor transparency",
            "gates": ["unit", "integration", "OPA bundle test", "FV-LexAI verify", "red-team smoke", "supervisor approval"],
        }),
        section("M6-S5", "Observability", {
            "tracing": "OpenTelemetry GenAI conventions",
            "logging": "Kafka WORM + structured JSON; daily Merkle anchor",
            "metrics": "Prometheus + RED/USE; SLOs tied to KPIs",
        }),
    ],
})

# ---- M7 ----
modules.append({
    "id": "M7",
    "title": "M7 — Roadmap 2026-2030 (S7)",
    "summary": (
        "Five-year delivery plan with quarterly milestones, regulator demos, "
        "supervisor approval gates, and a 2026-2032 adoption extension."
    ),
    "covers": ["roadmap", "milestones", "supervisor-approvals"],
    "sections": [
        section("M7-S1", "2026 — Foundations", {
            "Q1": "Master Blueprint v1.0; Sentinel v2.4 GA; OPA library v1; first regulator demo (DNB/BaFin/AMF)",
            "Q2": "MRM lifecycle live for T1 models; Kafka WORM + daily anchor; SMCR map signed",
            "Q3": "EU AI Act Art 53/55 GPAI conformity assessment dry-run",
            "Q4": "Pillar 2 AI Capital Overlay v1; cross-border kill-switch drill #1",
        }),
        section("M7-S2", "2027 — Multi-Regulator", {
            "Q1": "PRA SS1/23 self-attestation; FCA Consumer Duty outcomes report",
            "Q2": "MAS FEAT + AI Verify certification; HKMA GL-90 alignment",
            "Q3": "AGI Containment v2 (multi-agent consensus); ANC pilot",
            "Q4": "Supervisory Submission Pack v2; Regulator Demo Kit v2",
        }),
        section("M7-S3", "2028 — Globalize", {
            "Q1": "Global Supervisory Council (GSC) charter signed",
            "Q2": "Sandbox passport pilots (EU↔UK, MAS↔HKMA)",
            "Q3": "Trust Derivatives Layer v1 live (CCP-cleared)",
            "Q4": "Regulator-Training Consortium (GRTC) cohort 1 graduates",
        }),
        section("M7-S4", "2029 — Mesh", {
            "Q1": "Planetary Supervisory Mesh alpha; SCN node 100",
            "Q2": "GSKG v1 live; SIE alpha",
            "Q3": "Cross-border kill-switch in production for top 5 G-SIFIs",
            "Q4": "PQC migration complete for Tier-1 keys",
        }),
        section("M7-S5", "2030-2032 — Adoption & Harmonization", {
            "2030": "GSC operational; SASK + SSPEP standardized; Mesh public verifier",
            "2031": "Regional adoption (LATAM, MEA, ASEAN) via passporting",
            "2032": "Treaty review under GASRGP Art 12; Codex v2 amendment cycle",
        }),
    ],
})

# ---- M8 ----
modules.append({
    "id": "M8",
    "title": "M8 — Roles and Accountability (S8)",
    "summary": (
        "RACI for AI governance with SMCR Statement of Responsibility (SoR) mapping; "
        "9 RBAC roles; multisig coverage on Tier-1 ops."
    ),
    "covers": ["RACI", "SMCR", "RBAC"],
    "sections": [
        section("M8-S1", "Top-of-House Accountability", {
            "Board": "AI risk appetite; annual review; veto on Tier-1 model classes",
            "CEO+CFO+CRO": "Pillar 2 capital sign-off",
            "CAIO": "AI strategy + accountability; SMCR SMF holder",
            "GC+DPO": "Legal/regulatory + privacy",
        }),
        section("M8-S2", "Three Lines + AI Functions", {
            "1LoD": "Model owner, dev, MLOps",
            "2LoD": "MRM, AI Risk, Compliance, DPO, AI Safety Lead",
            "3LoD": "Internal Audit (annual + thematic)",
        }),
        section("M8-S3", "RBAC Roles (9)", {
            "roles": ["author", "reviewer", "approver", "publisher", "operator", "validator", "auditor", "supervisor-liaison", "kill-switch-officer"],
            "multisig": "3-of-5 for publisher/operator/kill-switch-officer on T1",
        }),
        section("M8-S4", "SMCR Statements of Responsibility", {
            "SMF24": "CRO – Model Risk; explicit AGI containment clause",
            "SMF7": "CISO – Cyber + key custody for kill-switch",
            "Reasonable steps": "Documented attestation cycle; evidence in WORM ledger",
        }),
        section("M8-S5", "Escalation Tree", {
            "L1": "Operator / shift",
            "L2": "AI Safety Lead + on-call MRM",
            "L3": "CAIO + CRO",
            "L4": "Board + Regulator notification",
        }),
    ],
})

# ---- M9 ----
modules.append({
    "id": "M9",
    "title": "M9 — Supervisory Readiness and Auditability (S9)",
    "summary": (
        "Evidence-pack assembly ≤ 30 min, daily Merkle anchoring, supervisor "
        "read-only ledger view, GAP attestation cycle, supervisory drill cadence."
    ),
    "covers": ["evidence-pack", "anchor", "GAP", "drills"],
    "sections": [
        section("M9-S1", "Evidence Pack Generator", {
            "inputs": ["Decision envelopes", "OPA decisions", "model cards", "validation reports", "drift charts"],
            "output": "Signed PDF/A + JSON bundle; PAdES signed; Sigstore attested",
            "sla": "≤ 30 min for any 7-day window",
        }),
        section("M9-S2", "Supervisor Read-Only Ledger", {
            "view": "Merkle-anchored; per-jurisdiction filter; offline verifier CLI",
            "auth": "OIDC + step-up MFA; per-supervisor scope token",
        }),
        section("M9-S3", "Governance Attestation Protocol (GAP)", {
            "cadence": "Quarterly attestation by CAIO/CRO/CISO; signed Decision Envelope",
            "scope": "Coverage of OPA bundles, MRM tier inventory, kill-switch drills, capital overlay",
        }),
        section("M9-S4", "Drill Cadence", {
            "tabletop": "Quarterly cross-jurisdictional",
            "live-fire": "Annually with supervisor observers",
            "reporting": "Drill reports anchored in WORM ledger",
        }),
        section("M9-S5", "Independent Inspection Rights", {
            "AISI": "Read access to Decision Envelopes for sampled inferences",
            "Internal Audit": "Full ledger access; signed query receipts",
        }),
    ],
})

# ---- M10 ----
modules.append({
    "id": "M10",
    "title": "M10 — Risk and Control Matrix (S10)",
    "summary": (
        "STRIDE + OWASP-LLM Top 10 (2025) + MITRE ATLAS threats with controls "
        "mapped to Sentinel modules and OPA rules; residual-risk scoring."
    ),
    "covers": ["STRIDE", "OWASP-LLM", "ATLAS", "residual-risk"],
    "sections": [
        section("M10-S1", "Threat Catalogue", {
            "OWASP-LLM": "Prompt injection, insecure output, training-data poisoning, supply-chain, sensitive-info disclosure, excessive agency, system-prompt leakage, vector/embedding weakness, misinformation, unbounded consumption",
            "ATLAS": "Adversarial ML tactics & techniques",
            "STRIDE": "Spoof, tamper, repudiate, info-disclosure, DoS, escalate",
        }),
        section("M10-S2", "Control Mapping", {
            "method": "Each threat → ≥ 1 preventive + ≥ 1 detective + ≥ 1 corrective control",
            "evidence": "OPA rule IDs + Sentinel module IDs + KPI IDs",
        }),
        section("M10-S3", "Residual Risk Scoring", {
            "method": "Likelihood × Impact × ControlEffectiveness; max acceptable = LOW for T1",
            "review": "Quarterly; ad-hoc on incident",
        }),
        section("M10-S4", "Top 10 Master Controls", {
            "controls": [
                "OPA pre-tool-call validation",
                "Decision envelope hash-chain",
                "Daily Merkle anchor",
                "Multisig on Tier-1 promote/kill-switch",
                "PQC hybrid signing",
                "Air-gapped enclave for AGI",
                "Cognitive Resonance Monitor",
                "Red-team gating in CI",
                "Capital overlay tied to GTI",
                "SMCR SoR with AI domain",
            ],
        }),
        section("M10-S5", "Key Risk Indicators (KRI)", {
            "kri": ["containment Δ", "latent drift", "kill-switch SLA", "PII leakage", "blocked-harm rate", "audit-chain verify", "drill participation"],
        }),
    ],
})

# ---- M11 ----
modules.append({
    "id": "M11",
    "title": "M11 — Resource and Capability Plan (S11)",
    "summary": (
        "Five-year FTE plan, capability matrix, training, vendor management, "
        "tooling, and budget envelopes for governance, MRM, AI safety, "
        "supervisory engagement, and engineering."
    ),
    "covers": ["FTE", "training", "vendor", "budget"],
    "sections": [
        section("M11-S1", "FTE Plan", {
            "2026": "Governance 25, MRM 30, AI Safety 12, SupervisorLiaison 4, Eng 80",
            "2030": "Governance 40, MRM 50, AI Safety 25, SupervisorLiaison 10, Eng 140",
        }),
        section("M11-S2", "Capability Matrix", {
            "competencies": ["Rego/OPA", "PyTorch", "Kafka/streaming", "FV/Coq/Lean (subset)", "Terraform", "RegTech", "supervisory engagement"],
            "levels": ["Practitioner", "Specialist", "Lead", "Distinguished"],
        }),
        section("M11-S3", "Training & Certification", {
            "internal": "GAP attestation course; Sentinel operator cert",
            "external": "GRTC graduate stream; ISO 42001 lead implementer; AI Verify",
        }),
        section("M11-S4", "Vendor Management", {
            "controls": "Sigstore-required; SLSA L3+; SBOM; PQC roadmap clause",
            "exit": "Documented exit plan + key escrow",
        }),
        section("M11-S5", "Budget Envelopes (illustrative G-SIFI)", {
            "2026": "USD 90M (run + change)",
            "2027": "USD 110M",
            "2028": "USD 130M",
            "2029": "USD 140M",
            "2030": "USD 145M (steady state)",
        }),
    ],
})

# ---- M12 ----
modules.append({
    "id": "M12",
    "title": "M12 — Annexes A-G Scaffolding (S12)",
    "summary": (
        "Index of full annex content with cross-references and machine-readable "
        "section pointers consumed by the regulator submission pack builder."
    ),
    "covers": ["annexes", "scaffolding", "indexing"],
    "sections": [
        section("M12-S1", "Annex A — Kafka WORM", {"ref": "annexA"}),
        section("M12-S2", "Annex B — OPA Policy Library", {"ref": "annexB"}),
        section("M12-S3", "Annex C — Terraform Modules", {"ref": "annexC"}),
        section("M12-S4", "Annex D — Explainability + Traceability", {"ref": "annexD"}),
        section("M12-S5", "Annex E/F/G — Drills, GAP, Mesh", {"ref": ["annexE", "annexF", "annexG"]}),
    ],
})

# ---- M13 ----
modules.append({
    "id": "M13",
    "title": "M13 — Regulator-Submission Mechanics & ANC",
    "summary": (
        "Supervisory Submission Pack & Engagement Playbook (SSPEP), the "
        "Supervisory Approval Simulation Kit (SASK), and the Autonomous "
        "Negotiation Co-Pilot (ANC) for regulator dialogue."
    ),
    "covers": ["SSPEP", "SASK", "ANC"],
    "sections": [
        section("M13-S1", "SSPEP — Supervisory Submission Pack & Engagement Playbook", {
            "components": ["cover letter", "executive summary", "directive block", "evidence pack", "drill reports", "SoR map", "GTI snapshot", "OPA bundle digest"],
            "playbook": ["pre-meeting brief", "live demo script", "Q&A bench", "follow-up letter template"],
        }),
        section("M13-S2", "SASK — Supervisory Approval Simulation Kit", {
            "scenarios": ["EU AI Act Art 53 conformity", "SR 11-7 effective challenge", "PRA SS1/23 attestation", "MAS FEAT third-party audit", "HKMA GL-90 thematic"],
            "rubric": "Pass/Conditional/Fail with remediation plan auto-generated",
        }),
        section("M13-S3", "ANC — Autonomous Negotiation Co-Pilot", {
            "role": "RAG-grounded co-pilot for supervisor dialogue (read-only)",
            "guardrails": "OPA + Sentinel + cosine ≥ 0.92; refuses to bind firm; logs every turn",
            "outputs": "Suggested clauses, precedents, BATNA analysis, calibrated concessions",
        }),
        section("M13-S4", "Engagement Cadence", {
            "annual": "Pillar 2 review; Consumer Duty outcomes",
            "quarterly": "GAP attestation submission",
            "ad-hoc": "SEV-1 incident reporting ≤ 24 h",
        }),
        section("M13-S5", "Decision Logs", {
            "schema": "every regulator interaction captured as Decision Envelope",
            "retention": "≥ 10 years; legal-hold gates",
        }),
    ],
})

# ---- M14 ----
modules.append({
    "id": "M14",
    "title": "M14 — Planetary Supervisory Mesh (PSM) & Cooperatives",
    "summary": (
        "Planetary Supervisory Mesh, Supervisory Co-Pilot Network (SCN), "
        "Supervisory Intelligence Engine (SIE), Global Supervisory Knowledge "
        "Graph (GSKG), Global Regulator Training Consortium (GRTC), Global "
        "Supervisory Council (GSC)."
    ),
    "covers": ["PSM", "SCN", "SIE", "GSKG", "GRTC", "GSC"],
    "sections": [
        section("M14-S1", "Global Supervisory Council (GSC)", {
            "charter": "Standing council of senior supervisors (ECB-SSM, FRB, BoE/PRA, FCA, MAS, HKMA, SEC, FDIC) + AISI observers",
            "powers": ["mutual recognition", "kill-switch ratification", "Codex amendment proposal"],
        }),
        section("M14-S2", "Planetary Supervisory Mesh (PSM)", {
            "topology": "Federated mesh of supervisor-gateway-svc nodes with SPIFFE identity",
            "transport": "mTLS + signed bulletins; anycast for kill-switch",
            "registry": "Permissioned ledger with Merkle anchoring",
        }),
        section("M14-S3", "Supervisory Co-Pilot Network (SCN)", {
            "function": "Distributed co-pilots aiding supervisors; shared OPA bundles + GSKG context",
            "guardrails": "OPA + Sentinel + GAP attestation",
        }),
        section("M14-S4", "Supervisory Intelligence Engine (SIE) + GSKG", {
            "SIE": "Risk synthesis across firms + jurisdictions; anomaly detection on GTI",
            "GSKG": "Knowledge graph linking models, firms, controls, regulations, incidents",
        }),
        section("M14-S5", "Global Regulator Training Consortium (GRTC)", {
            "curriculum": ["Sentinel ops", "OPA/Rego", "FV/LexAI", "MRM modernization", "AGI containment"],
            "credentialing": "Cohort-based; portable certification recognized by GSC",
        }),
    ],
})

# ---------------------- annexes ----------------------
DOC["annexA"] = {
    "id": "annexA",
    "title": "Annex A — Kafka WORM Logging",
    "topics": [
        {"name": "Topology", "detail": "Dedicated cluster with rack-aware brokers; per-jurisdiction partitions; idempotent producers; transactional commits"},
        {"name": "Retention", "detail": "Object-store tiered (e.g. S3 Object Lock COMPLIANCE / Azure Blob immutability) with 10-year minimum, 50-year for Tier-1"},
        {"name": "Schema", "detail": "Decision Envelope (envelopeId, ts, systemId, promptHash, outputHash, fairness, explanations, policyDecisions, prevHash, thisHash, signatures)"},
        {"name": "Hash chain", "detail": "SHA-256 prev/this; daily Merkle root anchored to permissioned chain; offline verifier CLI"},
        {"name": "Signing", "detail": "Ed25519 + ML-DSA-65 hybrid; KMS/HSM custody; per-key rotation 90 days"},
        {"name": "Access", "detail": "Producers via SPIFFE; consumers (auditor, supervisor) via OIDC + step-up MFA"},
        {"name": "Verification", "detail": "Node.js/TypeScript external verifier (WP-042 M6) with Merkle proof + signature checks"},
        {"name": "Operational SLOs", "detail": "Producer p99 ≤ 50 ms; daily anchor 100 %; tamper detection MTTD ≤ 5 min"},
    ],
}

DOC["annexB"] = {
    "id": "annexB",
    "title": "Annex B — OPA Policy Library",
    "bundles": [
        {"id": "OPA-EU-AIACT", "rules": 38, "description": "EU AI Act 2026 — prohibited practices (Art 5), risk mgmt (Art 9), data gov (Art 10), transparency (Art 13), oversight (Art 14), GPAI (Art 53/55)"},
        {"id": "OPA-SR11-7", "rules": 22, "description": "SR 11-7 lifecycle gates: validation, ongoing monitoring, change approval"},
        {"id": "OPA-GDPR", "rules": 14, "description": "Lawful-basis check, Art 22 automated decision contestation, Art 25 data-protection-by-design"},
        {"id": "OPA-MAS-FEAT", "rules": 12, "description": "FEAT principles: fairness pre-check, explainability gate, accountability metadata"},
        {"id": "OPA-HKMA-GL90", "rules": 10, "description": "Lifecycle, third-party, explainability"},
        {"id": "OPA-FCA-CD", "rules": 9, "description": "Consumer Duty: foreseeable harm, vulnerable customer treatment"},
        {"id": "OPA-PRA-SS123", "rules": 11, "description": "Model risk principles 1-5"},
        {"id": "OPA-AGI-CONTAINMENT", "rules": 16, "description": "Δ_drift ≤ 4 %, latent ≤ 3 %, fiduciary cosine ≥ 0.92, kill-switch multisig"},
    ],
    "totalRules": 132,
    "examplePolicies": ["fcra_adverse_action_required", "agi_containment_delta_breach", "kill_switch_multisig", "gpai_systemic_risk_eval_required"],
    "testing": "Each rule has ≥ 3 fixtures; CI gate + property-based fuzzing; release versioned semver",
}

DOC["annexC"] = {
    "id": "annexC",
    "title": "Annex C — Terraform Governance Modules",
    "modules": [
        {"name": "module.sentinel-sidecar", "purpose": "Inject Sentinel v2.4 sidecar via K8s MutatingWebhookConfiguration (failurePolicy: Fail)"},
        {"name": "module.kafka-worm", "purpose": "Provision WORM cluster + Object Lock storage + IAM"},
        {"name": "module.opa-bundle", "purpose": "Build/sign/serve OPA bundles with semver"},
        {"name": "module.kms-pqc", "purpose": "FIPS 140-3 KMS keys; ML-DSA-65 hybrid; rotation 90 d"},
        {"name": "module.spiffe-spire", "purpose": "Workload identity + mTLS"},
        {"name": "module.supervisor-gateway-svc", "purpose": "Per-jurisdiction supervisor gateway with read-only ledger views"},
        {"name": "module.audit-anchor", "purpose": "Daily Merkle anchor to permissioned chain + public verifier"},
        {"name": "module.air-gap-swarm", "purpose": "Air-gapped Docker Swarm enclave for Tier-1 inference"},
        {"name": "module.evidence-pack", "purpose": "Evidence pack builder (PAdES PDF/A + JSON bundle)"},
    ],
    "compliance": "OSCAL-tagged; signed plans; backend with state encryption; drift detection daily",
}

DOC["annexD"] = {
    "id": "annexD",
    "title": "Annex D — Explainability Schema + Cross-Jurisdictional Traceability Matrix",
    "explainabilitySchema": {
        "fields": ["systemId", "modelId", "inputFeaturesHash", "explanationType", "shapValues", "counterfactual", "fairnessSnapshot", "policyDecisions", "humanOversightFlag", "envelopeRef"],
        "explanationTypes": ["SHAP", "LIME", "counterfactual", "rationale-prompt", "model-card-link", "data-lineage"],
        "consumerTargets": ["customer-DSAR", "regulator", "internal-audit", "MRM"],
        "languageSupport": ["en", "fr", "de", "es", "it", "nl", "pt", "zh", "ja", "ko"],
    },
    "traceabilityMatrix": [
        {"feature": "Decision Envelope", "EUAIA": "Art 12 + 14", "SR11-7": "§III.B Outcome analysis", "MAS-FEAT": "Accountability", "HKMA-GL90": "Lifecycle log", "GDPR": "Art 22"},
        {"feature": "OPA Bundle Signing", "EUAIA": "Art 9", "SR11-7": "Change control", "ISO42001": "Annex A change mgmt", "DORA": "ICT change"},
        {"feature": "Kill-Switch Multisig", "EUAIA": "Art 14", "SR11-7": "Effective challenge", "PRA-SS123": "Principle 4", "GASRGP": "Art 6"},
        {"feature": "Capital Overlay", "Basel": "Pillar 2", "PRA-SS123": "Capital implications", "EUAIA": "Art 9 RMS", "MAS-TRMG": "Capital"},
        {"feature": "Cognitive Resonance Monitor", "EUAIA": "Art 15", "SR11-7": "Ongoing monitoring", "AGI-Containment": "Δ_drift ≤ 4 %"},
        {"feature": "Daily Merkle Anchor", "ISO27001": "A.12.4", "EUAIA": "Art 12", "DORA": "Audit logging"},
        {"feature": "PQC Hybrid Signing", "BIS-PQC": "Migration", "NIST-PQC": "Migration", "DORA": "ICT third-party"},
        {"feature": "GAP Attestation", "ISO42001": "Cl 9", "NIST-AIRMF": "Govern 1.4", "SR11-7": "Effective challenge"},
        {"feature": "Sandbox Passport", "EUAIA": "Art 57", "FCA-Sandbox": "Mutual recognition"},
        {"feature": "Citizen Redress Portal", "GDPR": "Art 22", "EUAIA": "Art 50", "FCA-CD": "Consumer Duty"},
    ],
}

DOC["annexE"] = {
    "id": "annexE",
    "title": "Annex E — Containment Playbooks + Drill Scripts + Regulator Demo Kit + Workshops",
    "containmentPlaybooks": [
        {"id": "PB-CONT-01", "name": "LEVEL-5 AGI Containment Breach", "ref": "WP-042 M12"},
        {"id": "PB-CONT-02", "name": "Latent-drift breach (Δ ≥ 4 %)", "steps": ["alert", "freeze", "investigate", "rollback", "post-mortem"]},
        {"id": "PB-CONT-03", "name": "Deceptive-alignment indicator", "steps": ["isolate", "swarm consensus", "kill-switch consideration", "AISI notify"]},
        {"id": "PB-CONT-04", "name": "Kill-switch multisig invocation", "steps": ["co-sign", "anycast", "verify acks", "evidence pack"]},
        {"id": "PB-CONT-05", "name": "Air-gap enclave compromise", "steps": ["containment", "key rotation", "PQC re-anchor"]},
    ],
    "drillScripts": [
        {"id": "DRILL-01", "scenario": "Cross-border kill-switch p95 ≤ 60 s", "cadence": "quarterly", "observers": ["AISI", "ECB-SSM"]},
        {"id": "DRILL-02", "scenario": "Foundation model jailbreak red-team", "cadence": "monthly"},
        {"id": "DRILL-03", "scenario": "Capital overlay invocation under stress", "cadence": "annual joint with treasury"},
        {"id": "DRILL-04", "scenario": "Cognitive Resonance Δ breach + evidence pack", "cadence": "semi-annual"},
        {"id": "DRILL-05", "scenario": "Supervisor live-fire (PRA SS1/23 + ECB-SSM)", "cadence": "annual"},
    ],
    "regulatorDemoKit": {
        "components": ["Sentinel SOC terminal", "3D Containment Visualizer (HTML/JS Three.js)", "WORM verifier CLI", "Live OPA decision walkthrough", "Capital overlay calculator"],
        "narratives": ["EU AI Act conformity", "SR 11-7 effective challenge", "MAS FEAT outcomes", "FCA Consumer Duty"],
    },
    "workshops": [
        {"id": "WS-01", "audience": "Board", "duration": "2 h", "outcome": "Risk appetite signed"},
        {"id": "WS-02", "audience": "MRM + AI Risk", "duration": "1 d", "outcome": "MRM lifecycle dry-run"},
        {"id": "WS-03", "audience": "Engineering", "duration": "2 d", "outcome": "Sentinel sidecar + OPA bootcamp"},
        {"id": "WS-04", "audience": "Supervisor liaison", "duration": "1 d", "outcome": "SSPEP rehearsal"},
        {"id": "WS-05", "audience": "Internal Audit", "duration": "1 d", "outcome": "Evidence-pack inspection drill"},
    ],
}

DOC["annexF"] = {
    "id": "annexF",
    "title": "Annex F — Supervisory Notebook + Attestation Ledger + GAP Protocol + GAP Reference Implementation",
    "supervisoryNotebook": {
        "format": "Jupyter notebook bundle (signed) with executable cells against supervisor read-only ledger",
        "sections": ["Coverage map", "OPA bundle digest", "Drift trends", "Drill outcomes", "Evidence-pack samples", "Open issues"],
        "delivery": "Quarterly to supervisor; ad-hoc on incident",
    },
    "attestationLedger": {
        "schema": ["attestationId", "ts", "scope", "signers", "evidenceRefs", "claims", "thisHash", "prevHash"],
        "retention": "≥ 10 years; legal hold; daily Merkle anchor",
    },
    "gapProtocol": {
        "name": "Governance Attestation Protocol (GAP)",
        "cadence": "Quarterly + ad-hoc",
        "signers": ["CAIO", "CRO", "CISO", "GC", "Internal Audit"],
        "claims": [
            "Coverage of all in-scope models by OPA bundles",
            "MRM tier inventory current",
            "Kill-switch drill executed in cadence",
            "Capital overlay calibrated and reviewed",
            "PQC migration status",
            "PII leakage and blocked-harm KPIs within thresholds",
        ],
        "verification": "Independent (Internal Audit) signs co-attestation; AISI receives read-only copy",
    },
    "gapReferenceImpl": {
        "language": "TypeScript + Python",
        "components": [
            "gap-cli — produce/verify attestations",
            "gap-svc — REST API for ingestion",
            "gap-anchor — daily Merkle anchor + chain submission",
            "gap-ui — minimal React dashboard for reviewers",
            "gap-verifier — offline verifier (Node)",
        ],
        "schemas": ["attestation.envelope.json", "claim.evidence.json", "anchor.proof.json"],
    },
}

DOC["annexG"] = {
    "id": "annexG",
    "title": "Annex G — Adoption, Pilots, Geopolitical, Negotiation, GSC, Mesh, GRTC",
    "adoptionStrategies": [
        {"id": "AD-01", "name": "EU primary anchor", "approach": "Lead with AI Act conformity + ISO 42001 dual cert"},
        {"id": "AD-02", "name": "UK + APAC interop", "approach": "PRA/FCA + MAS/HKMA passporting via mutual recognition"},
        {"id": "AD-03", "name": "US engagement", "approach": "SR 11-7 modernization + FRB/OCC dialogue + NIST GAI Profile"},
        {"id": "AD-04", "name": "Emerging markets", "approach": "GRTC train-the-trainer; cost-share for sandbox passport"},
    ],
    "pilots": [
        {"id": "PL-01", "scope": "EU↔UK kill-switch mutual recognition", "horizon": "2027"},
        {"id": "PL-02", "scope": "MAS↔HKMA sandbox passport", "horizon": "2028"},
        {"id": "PL-03", "scope": "US bank GAP pilot under FRB observation", "horizon": "2027"},
        {"id": "PL-04", "scope": "GAISM facility pilot with central banks", "horizon": "2028"},
    ],
    "readinessKits": [
        {"id": "RK-01", "audience": "G-SIFI Board", "items": ["risk appetite template", "SoR map", "demo deck"]},
        {"id": "RK-02", "audience": "Supervisor", "items": ["evidence-pack sample", "verifier CLI", "supervisory notebook"]},
        {"id": "RK-03", "audience": "Engineering", "items": ["Terraform modules", "OPA bundles", "CI templates"]},
    ],
    "facilitatorCertification": {
        "name": "GRTC Facilitator Certification",
        "tracks": ["Supervisory Engagement", "AGI Containment Ops", "MRM Modernization", "Sentinel Sidecar Ops"],
        "credentialing": "Cohort-based; portable; recognized by GSC",
    },
    "globalSupervisoryCouncil": {
        "name": "Global Supervisory Council (GSC)",
        "seats": ["ECB-SSM", "FRB", "BoE/PRA", "FCA", "MAS", "HKMA", "SEC", "FDIC", "AISI observers"],
        "powers": ["mutual recognition", "kill-switch ratification", "Codex amendment proposal", "passport governance"],
        "charter": "Standing intergovernmental coordination body; co-chair rotation; annual plenary + emergency session",
    },
    "legalCharterAndTreaty": {
        "treatyFramework": "GASRGP backbone (12 articles) + bilateral implementing protocols",
        "legalCharter": "Defines GSC powers, dispute resolution, sunset clause (Art 12)",
        "ratification": "EU + UK + US + MAS + HKMA target by 2028",
    },
    "geopoliticalPlaybooks": [
        {"id": "GP-01", "scenario": "Compute export controls divergence", "play": "Use sandbox passporting + AI-CCP to bridge"},
        {"id": "GP-02", "scenario": "Frontier-model registry deadlock", "play": "Bilateral pre-registration + AISI co-sign"},
        {"id": "GP-03", "scenario": "Cross-border kill-switch dispute", "play": "GSC arbitration + temporary unilateral containment"},
        {"id": "GP-04", "scenario": "Fragmentation risk", "play": "Open-source Sentinel core + GSKG to lower switching cost"},
    ],
    "simulationScenarios": [
        {"id": "SIM-01", "name": "G-SIB credit AI bias incident → Capital overlay invocation"},
        {"id": "SIM-02", "name": "Frontier model deceptive-alignment indicator → cross-border kill-switch"},
        {"id": "SIM-03", "name": "Trust derivative spread breach → CCP coordination"},
        {"id": "SIM-04", "name": "Sandbox passport rejection → bilateral remediation"},
        {"id": "SIM-05", "name": "AGI emergence event → GSC emergency session"},
    ],
    "negotiationSupport": {
        "components": ["BATNA library", "precedent retrieval", "calibrated concession engine", "language adapter (10 langs)"],
        "guardrails": "OPA-validated; cosine ≥ 0.92; refuses binding statements",
    },
    "autonomousNegotiationCoPilot": {
        "name": "Autonomous Negotiation Co-Pilot (ANC)",
        "modes": ["Drafting", "Live-meeting whisper", "Post-meeting synthesis"],
        "guardrails": ["multisig on outbound clauses", "OPA outbound check", "WORM-logged turns"],
        "evaluations": ["faithfulness ≥ 0.92", "regulator-tone fit ≥ 0.9", "concession calibration error ≤ 5 %"],
    },
    "supervisorySubmissionPack": {
        "name": "Supervisory Submission Pack & Engagement Playbook (SSPEP)",
        "manifest": ["cover letter", "directive block", "executive summary", "evidence pack", "drill reports", "GAP attestation", "OPA bundle digest", "Q&A bench"],
        "delivery": "PDF/A + JSON bundle; PAdES + Sigstore; SHA-256 + ML-DSA-65",
    },
    "supervisoryApprovalSimulationKit": {
        "name": "Supervisory Approval Simulation Kit (SASK)",
        "scenarios": 12,
        "outputs": ["pass/conditional/fail", "remediation plan", "evidence gap list"],
    },
    "globalRegulatorTrainingConsortium": {
        "name": "Global Regulator Training Consortium (GRTC)",
        "cohorts": "≥ 50 supervisors per year by 2030",
        "tracks": ["Sentinel ops", "OPA/Rego", "AGI containment", "MRM modernization"],
    },
    "globalSupervisoryKnowledgeGraph": {
        "name": "Global Supervisory Knowledge Graph (GSKG)",
        "entities": ["Models", "Firms", "Controls", "Regulations", "Incidents", "Drills", "Capital overlays", "Persons (SMCR)"],
        "edges": ["governs", "assesses", "mitigates", "evidences", "anchors", "escalates"],
        "store": "Permissioned graph DB with daily Merkle anchor",
    },
    "supervisoryIntelligenceEngine": {
        "name": "Supervisory Intelligence Engine (SIE)",
        "capabilities": ["cross-firm anomaly detection on GTI", "capital overlay simulation", "scenario generator (FSAP-AI)", "early-warning indicators"],
    },
    "supervisoryCoPilotNetwork": {
        "name": "Supervisory Co-Pilot Network (SCN)",
        "design": "Federated co-pilots aiding supervisors with GSKG context + OPA guardrails",
        "guardrails": ["OPA outbound", "Sentinel sidecar", "GAP attestation cycle", "WORM logging"],
    },
    "planetarySupervisoryMesh": {
        "name": "Planetary Supervisory Mesh (PSM)",
        "topology": "Federated mesh of supervisor-gateway-svc nodes",
        "transport": "mTLS + signed bulletins; anycast for kill-switch",
        "registry": "Permissioned ledger with Merkle anchoring",
        "publicVerifier": "Browser + CLI verifier for civil society and press",
    },
}

# ---------------------- schemas ----------------------
schemas = [
    {"id": "directiveBlock", "fields": ["id", "version", "horizon", "jurisdiction", "scope", "sectionRefs", "annexRefs", "artifactIds", "thresholds", "signing"]},
    {"id": "decisionEnvelope", "fields": ["envelopeId", "ts", "systemId", "promptHash", "outputHash", "fairness", "explanations", "policyDecisions", "prevHash", "thisHash", "signatures"]},
    {"id": "evidencePack", "fields": ["packId", "windowStart", "windowEnd", "envelopes", "validations", "drills", "kpis", "signatures"]},
    {"id": "attestationEnvelope", "fields": ["attestationId", "ts", "scope", "signers", "claims", "evidenceRefs", "thisHash", "prevHash"]},
    {"id": "opaBundleManifest", "fields": ["bundleId", "version", "rules", "digest", "signers", "validUntil"]},
    {"id": "killSwitchOrder", "fields": ["orderId", "ts", "scope", "signers", "rationale", "ackRequiredBy", "anchorRef"]},
    {"id": "gtiSnapshot", "fields": ["snapshotId", "ts", "alignment", "drift", "fairness", "explainability", "incidentHistory", "composite"]},
    {"id": "modelCard", "fields": ["modelId", "owner", "intendedUse", "dataLineage", "evaluations", "fairness", "limitations", "governance"]},
    {"id": "drillReport", "fields": ["drillId", "scenario", "observers", "result", "kpis", "remediation"]},
    {"id": "smcrSoR", "fields": ["smfId", "person", "responsibilities", "aiDomainClause", "evidenceRefs"]},
    {"id": "anchorProof", "fields": ["anchorId", "merkleRoot", "ts", "chainTx", "signatures"]},
    {"id": "supervisoryBulletin", "fields": ["bulletinId", "ts", "issuer", "severity", "content", "signatures"]},
]

# ---------------------- code examples ----------------------
code = [
    {"id": "CE-01", "title": "OPA — EU AI Act Art 14 human oversight", "lang": "rego", "snippet": "package eu_aiact\n\ndeny[msg] {\n  input.action == \"deploy\"\n  not input.humanOversight.signed\n  msg := \"Art 14 human oversight signature missing\"\n}\n"},
    {"id": "CE-02", "title": "OPA — Cognitive Resonance containment delta", "lang": "rego", "snippet": "package agi_containment\n\ndeny[msg] {\n  input.metrics.delta > 0.04\n  msg := sprintf(\"Δ_drift %.4f exceeds containment threshold 0.04\", [input.metrics.delta])\n}\n"},
    {"id": "CE-03", "title": "Decision envelope hash chain (Python)", "lang": "python", "snippet": "import hashlib, json\n\ndef chain(prev, payload):\n    body = json.dumps(payload, sort_keys=True).encode()\n    this = hashlib.sha256(prev + body).hexdigest()\n    return this\n"},
    {"id": "CE-04", "title": "Terraform — Sentinel sidecar webhook", "lang": "hcl", "snippet": "module \"sentinel_sidecar\" {\n  source           = \"./modules/sentinel-sidecar\"\n  failure_policy   = \"Fail\"\n  pqc_key_arn      = module.kms_pqc.key_arn\n  worm_topic       = module.kafka_worm.decision_envelope_topic\n}\n"},
    {"id": "CE-05", "title": "Kill-switch multisig signer (TypeScript)", "lang": "typescript", "snippet": "import { sign, verifyN } from './pqc';\nexport function multisig(order: KillSwitchOrder, keys: KeyPair[]): KillSwitchOrder {\n  const sigs = keys.slice(0, 3).map(k => sign(order.payload, k));\n  return { ...order, signatures: sigs };\n}\n"},
    {"id": "CE-06", "title": "ANC — outbound OPA gate (TypeScript)", "lang": "typescript", "snippet": "export async function ancEmit(draft: Clause): Promise<Clause> {\n  const decision = await opa.evaluate('anc.outbound', { draft });\n  if (!decision.allow) throw new Error(`ANC blocked: ${decision.reasons.join(', ')}`);\n  return draft;\n}\n"},
    {"id": "CE-07", "title": "GAP CLI — produce attestation (Node)", "lang": "typescript", "snippet": "import { Command } from 'commander';\nconst program = new Command();\nprogram.command('attest <scope>').action(async (scope) => {\n  const a = await buildAttestation(scope);\n  await ledger.append(a);\n  await anchor.dailyMerkle(a);\n});\nprogram.parse();\n"},
    {"id": "CE-08", "title": "ML-DSA-65 hybrid signing (Python)", "lang": "python", "snippet": "from oqs import Signature\nimport nacl.signing\n\ndef hybrid_sign(payload: bytes, ed_key, ml_key):\n    ed_sig = ed_key.sign(payload).signature\n    sig = Signature('ML-DSA-65')\n    pq_sig = sig.sign(payload, ml_key)\n    return ed_sig + b'||' + pq_sig\n"},
    {"id": "CE-09", "title": "PSM supervisor-gateway-svc handler (Go)", "lang": "go", "snippet": "func (s *Server) HandleBulletin(w http.ResponseWriter, r *http.Request) {\n    b, _ := io.ReadAll(r.Body)\n    if !pqc.Verify(b, headerSig(r)) { http.Error(w, \"bad sig\", 401); return }\n    s.ledger.Append(b); s.fanout(b)\n}\n"},
    {"id": "CE-10", "title": "Supervisory Notebook cell — coverage map", "lang": "python", "snippet": "import pandas as pd\nfrom supctx import ledger\ncov = ledger.coverage_map(window='90d')\npd.DataFrame(cov).to_html('coverage.html')\n"},
    {"id": "CE-11", "title": "K8s MutatingWebhookConfiguration (YAML)", "lang": "yaml", "snippet": "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingWebhookConfiguration\nmetadata: { name: sentinel-injector }\nwebhooks:\n- name: inject.sentinel.v24\n  failurePolicy: Fail\n  rules: [ { operations: [CREATE], apiGroups: [\"\"], apiVersions: [v1], resources: [pods] } ]\n"},
    {"id": "CE-12", "title": "Cognitive Resonance Monitor (PyTorch)", "lang": "python", "snippet": "import torch, torch.nn.functional as F\nclass CRM(torch.nn.Module):\n    def __init__(self, phi): super().__init__(); self.phi = phi\n    def forward(self, h):\n        cs = F.cosine_similarity(h, self.phi, dim=-1)\n        return { 'cosine': cs.mean().item(), 'delta': 1 - cs.mean().item() }\n"},
    {"id": "CE-13", "title": "OPA bundle test (Rego)", "lang": "rego", "snippet": "package eu_aiact_test\nimport data.eu_aiact\n\ntest_art14_missing_oversight {\n  count(eu_aiact.deny) > 0 with input as { \"action\": \"deploy\", \"humanOversight\": {} }\n}\n"},
    {"id": "CE-14", "title": "WORM verifier CLI (Node)", "lang": "typescript", "snippet": "import { verifyChain } from './worm';\nconst ok = await verifyChain(process.argv[2]);\nprocess.exit(ok ? 0 : 1);\n"},
    {"id": "CE-15", "title": "ANC live-meeting whisper (TypeScript)", "lang": "typescript", "snippet": "ws.on('utterance', async (u) => {\n  const ctx = await gskg.retrieve(u.topic);\n  const tip = await llm.suggest({ utterance: u, ctx, mode: 'whisper' });\n  await ancEmit({ kind: 'tip', text: tip });\n});\n"},
    {"id": "CE-16", "title": "Daily Merkle anchor job (Python)", "lang": "python", "snippet": "from anchor import build_root, submit\nroot = build_root(window_hours=24)\ntx = submit(root)\nprint('anchored', root, tx)\n"},
]

# ---------------------- case studies ----------------------
cases = [
    {"id": "CS-01", "name": "G-SIB EU credit AI — Master BP rollout", "outcomes": "Dual cert (EU AI Act + ISO 42001); evidence-pack ≤ 28 min; capital overlay 18 bps"},
    {"id": "CS-02", "name": "US prime-broker SR 11-7 modernization", "outcomes": "MRM cycle time -40 %; effective-challenge coverage 100 % T1"},
    {"id": "CS-03", "name": "MAS sandbox passport pilot (MAS↔HKMA)", "outcomes": "45-day acceptance; mutual recognition activated"},
    {"id": "CS-04", "name": "Cross-border kill-switch drill (EU↔UK)", "outcomes": "p95 propagation 47 s; AISI sign-off"},
    {"id": "CS-05", "name": "ANC pilot — supervisor dialogue", "outcomes": "Faithfulness 0.94; tone fit 0.92; zero binding-statement incidents"},
    {"id": "CS-06", "name": "PSM alpha — 100 nodes federated", "outcomes": "Mesh uptime 99.99 %; signed bulletin verification 100 %"},
]

# ---------------------- KPIs (24) ----------------------
kpis = [
    {"id": "KPI-01", "name": "Decision-traceability ratio", "target": "≥ 99.95 %"},
    {"id": "KPI-02", "name": "Kill-switch propagation p95", "target": "≤ 60 s"},
    {"id": "KPI-03", "name": "Evidence-pack assembly", "target": "≤ 30 min"},
    {"id": "KPI-04", "name": "Daily Merkle anchor verify", "target": "100 %"},
    {"id": "KPI-05", "name": "Containment Δ_drift", "target": "≤ 4.0 %"},
    {"id": "KPI-06", "name": "Latent-drift alert", "target": "≤ 3.0 %"},
    {"id": "KPI-07", "name": "Fiduciary cosine", "target": "≥ 0.92"},
    {"id": "KPI-08", "name": "PII leakage", "target": "≤ 0.01 %"},
    {"id": "KPI-09", "name": "Blocked-harm rate", "target": "≥ 99.5 %"},
    {"id": "KPI-10", "name": "Multisig coverage Tier-1", "target": "100 %"},
    {"id": "KPI-11", "name": "GAP attestation timeliness", "target": "100 % quarterly"},
    {"id": "KPI-12", "name": "Drill participation (G-SIFI)", "target": "≥ 90 %"},
    {"id": "KPI-13", "name": "MRM T1 effective-challenge coverage", "target": "100 %"},
    {"id": "KPI-14", "name": "Capital overlay calibration cadence", "target": "≥ annually"},
    {"id": "KPI-15", "name": "Sandbox passport SLA", "target": "≤ 45 days"},
    {"id": "KPI-16", "name": "Faithfulness (RAG)", "target": "≥ 0.92"},
    {"id": "KPI-17", "name": "Regulator submission pack errors", "target": "0 critical"},
    {"id": "KPI-18", "name": "Supervisor read-only ledger uptime", "target": "≥ 99.9 %"},
    {"id": "KPI-19", "name": "PQC migration coverage", "target": "100 % Tier-1 by 2029"},
    {"id": "KPI-20", "name": "Red-team coverage", "target": "≥ 95 % T1 quarterly"},
    {"id": "KPI-21", "name": "Two-eyes coverage T1 promotions", "target": "100 %"},
    {"id": "KPI-22", "name": "Audit-chain daily verify", "target": "100 %"},
    {"id": "KPI-23", "name": "Evidence completeness", "target": "≥ 98 %"},
    {"id": "KPI-24", "name": "Onboarding completion (governance)", "target": "≥ 80 %"},
]

# ---------------------- risk and control matrix (top 12) ----------------------
riskControlMatrix = [
    {"id": "RC-01", "threat": "Prompt injection (OWASP-LLM01)", "controls": ["OPA pre-tool-call", "Sentinel sidecar", "structured-output schema"], "kpis": ["KPI-09", "KPI-20"]},
    {"id": "RC-02", "threat": "Insecure output handling (OWASP-LLM02)", "controls": ["allow-list output validators", "WORM-logged decisions"], "kpis": ["KPI-01", "KPI-08"]},
    {"id": "RC-03", "threat": "Training-data poisoning (OWASP-LLM03)", "controls": ["data lineage", "signed dataset bundles", "Sigstore"], "kpis": ["KPI-22"]},
    {"id": "RC-04", "threat": "Supply-chain (OWASP-LLM05)", "controls": ["SLSA L3+", "SBOM", "vendor PQC clauses"], "kpis": ["KPI-19", "KPI-22"]},
    {"id": "RC-05", "threat": "Sensitive-info disclosure (OWASP-LLM06)", "controls": ["DLP", "minimization", "RAG ACL"], "kpis": ["KPI-08"]},
    {"id": "RC-06", "threat": "Excessive agency (OWASP-LLM08)", "controls": ["multisig kill-switch", "swarm consensus", "RBAC scopes"], "kpis": ["KPI-02", "KPI-10"]},
    {"id": "RC-07", "threat": "Deceptive alignment (AGI-specific)", "controls": ["Cognitive Resonance Monitor", "red-team", "AISI inspection"], "kpis": ["KPI-05", "KPI-07"]},
    {"id": "RC-08", "threat": "Latent drift", "controls": ["PSI/KS monitoring", "fiduciary cosine gate"], "kpis": ["KPI-05", "KPI-06"]},
    {"id": "RC-09", "threat": "Cross-border fragmentation", "controls": ["sandbox passport", "GSC mutual recognition"], "kpis": ["KPI-15"]},
    {"id": "RC-10", "threat": "Capital under-provisioning", "controls": ["Pillar 2 AI overlay", "annual review"], "kpis": ["KPI-14"]},
    {"id": "RC-11", "threat": "Tampering with audit trail", "controls": ["WORM Object Lock", "daily Merkle anchor", "PQC signing"], "kpis": ["KPI-04", "KPI-22"]},
    {"id": "RC-12", "threat": "Regulator engagement failure", "controls": ["SSPEP", "SASK rehearsal", "ANC"], "kpis": ["KPI-17"]},
]

# ---------------------- traceability ----------------------
traceability = [
    {"feature": "M1 mappings", "control": "Article-level crosswalk", "regimes": ["EU AI Act", "ISO 42001", "NIST AI RMF", "GDPR"]},
    {"feature": "M2 zero-trust mesh", "control": "SPIFFE/mTLS + OPA", "regimes": ["DORA", "ISO 27001", "MAS-TRMG"]},
    {"feature": "M3 MRM lifecycle", "control": "SR 11-7 effective challenge", "regimes": ["SR 11-7", "PRA SS1/23"]},
    {"feature": "M4 AGI containment", "control": "Δ_drift ≤ 4 % + kill-switch", "regimes": ["EU AI Act Art 14", "AISI inspection"]},
    {"feature": "M5 compute governance", "control": "Frontier registry + passport", "regimes": ["EU AI Act Art 51/57", "GASRGP"]},
    {"feature": "M6 implementation stack", "control": "SLSA L3+ + Sigstore", "regimes": ["NIST SP 800-218", "DORA"]},
    {"feature": "M7 roadmap", "control": "Quarterly milestones + supervisor demos", "regimes": ["ISO 42001 Cl 8/9"]},
    {"feature": "M8 SMCR map", "control": "Statements of Responsibility", "regimes": ["SMCR", "PRA SoR"]},
    {"feature": "M9 GAP", "control": "Quarterly attestation + AISI copy", "regimes": ["NIST AIRMF Govern 1.4"]},
    {"feature": "M10 RC matrix", "control": "Top 12 STRIDE/OWASP-LLM/ATLAS", "regimes": ["OWASP", "MITRE ATLAS"]},
    {"feature": "M13 SSPEP/SASK/ANC", "control": "Regulator engagement", "regimes": ["EU AI Act Art 56", "PRA supervisory cycle"]},
    {"feature": "M14 PSM/SCN/SIE/GSKG", "control": "Federated supervisory infra", "regimes": ["FSB", "GSC charter"]},
]

# ---------------------- data flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "Inference → WORM ledger", "steps": ["app → sidecar", "sidecar → OPA decide", "sidecar → Kafka WORM", "anchor daily"], "controls": ["mTLS", "PQC signing", "Merkle"]},
    {"id": "DF-02", "name": "Model promotion", "steps": ["registry → multisig 3-of-5", "Sigstore attest", "OPA gate", "GitOps deploy"], "controls": ["SLSA L3+", "SBOM", "Sigstore"]},
    {"id": "DF-03", "name": "Kill-switch propagation", "steps": ["multisig sign", "anycast fanout", "sidecar contain", "SLA verify"], "controls": ["≤ 60 s", "ack"]},
    {"id": "DF-04", "name": "GAP attestation", "steps": ["scope build", "co-sign", "anchor", "AISI copy"], "controls": ["multisig", "WORM"]},
    {"id": "DF-05", "name": "Regulator submission", "steps": ["evidence-pack build", "SSPEP assemble", "PAdES sign", "deliver"], "controls": ["≤ 30 min", "PAdES"]},
    {"id": "DF-06", "name": "PSM bulletin", "steps": ["GSC issue", "fanout to gateways", "ledger append", "public verifier"], "controls": ["PQC", "Merkle"]},
]

# ---------------------- regulators ----------------------
regulators = [
    {"id": "REG-01", "name": "ECB-SSM", "primary": "EU prudential"},
    {"id": "REG-02", "name": "DNB / BaFin / AMF / CSSF", "primary": "EU national"},
    {"id": "REG-03", "name": "PRA", "primary": "UK prudential"},
    {"id": "REG-04", "name": "FCA", "primary": "UK conduct"},
    {"id": "REG-05", "name": "FRB / OCC / FDIC", "primary": "US prudential"},
    {"id": "REG-06", "name": "SEC / CFTC", "primary": "US markets"},
    {"id": "REG-07", "name": "MAS", "primary": "Singapore"},
    {"id": "REG-08", "name": "HKMA / SFC", "primary": "Hong Kong"},
    {"id": "REG-09", "name": "BoJ / FSA Japan", "primary": "Japan"},
    {"id": "REG-10", "name": "APRA / ASIC", "primary": "Australia"},
    {"id": "REG-11", "name": "OSFI", "primary": "Canada"},
    {"id": "REG-12", "name": "FSB / IMF / BIS / OECD / AISI", "primary": "Global"},
]

# ---------------------- workshops & briefings ----------------------
workshops = [
    {"id": "WS-01", "audience": "Board", "duration": "2 h", "outcome": "Risk appetite + SoR signed"},
    {"id": "WS-02", "audience": "MRM + AI Risk", "duration": "1 d", "outcome": "MRM lifecycle dry-run"},
    {"id": "WS-03", "audience": "Engineering", "duration": "2 d", "outcome": "Sentinel sidecar + OPA bootcamp"},
    {"id": "WS-04", "audience": "Supervisor liaison", "duration": "1 d", "outcome": "SSPEP rehearsal + ANC pilot"},
    {"id": "WS-05", "audience": "Internal Audit", "duration": "1 d", "outcome": "Evidence-pack inspection drill"},
    {"id": "WS-06", "audience": "Regulator-facing (joint)", "duration": "0.5 d", "outcome": "Regulator demo kit walkthrough"},
    {"id": "WS-07", "audience": "Civil society / press", "duration": "0.5 d", "outcome": "PSM public verifier introduction"},
]

# ---------------------- privacy & security ----------------------
privacy = {
    "lawfulBasis": ["Legitimate interest (Art 6(1)(f))", "Legal obligation (Art 6(1)(c))", "Public interest (Art 6(1)(e))"],
    "dataMinimization": ["Pseudonymous WORM payloads", "Confidential compute for sensitive evals", "Federated/edge inference where feasible"],
    "subjectRights": ["DSAR portal with SLA", "Art 22 contestation pathway", "Explainability per Annex D schema"],
    "transfers": "Per-jurisdiction residency with cross-border attestation; SCCs + supplementary measures",
    "dpia": "Mandatory for high-risk and GPAI; reviewed by DPOs and AISI",
    "securityControls": ["zero-trust mTLS", "PQC hybrid signing", "FIPS 140-3 KMS/HSM", "WORM Object Lock", "SLSA L3+ + Sigstore"],
}

# ---------------------- deployment considerations ----------------------
deployment = [
    "Multi-region active-active EU primary; read replicas in UK/US/APAC",
    "Air-gapped Docker Swarm enclave for Tier-1 AGI inference",
    "FIPS 140-3 L4 HSM custody for kill-switch + treaty keys",
    "PQC hybrid (Ed25519 + ML-DSA-65) on critical bundles by 2029",
    "WORM tiering with Object Lock COMPLIANCE; 50-year retention for Tier-1",
    "Per-jurisdiction supervisor-gateway-svc with mTLS workload identity",
    "Independent observation channels for AISI and civil-society auditors",
    "Disaster recovery: RPO ≤ 1 h, RTO ≤ 4 h for treaty plane",
    "Quarterly chaos drills: KMS outage, region failover, kill-switch under partition",
    "CI/CD: SBOM + SLSA L3+ + Sigstore + OPA bundle test + red-team smoke + supervisor approval",
    "Public verifier endpoints for civil society and press to validate signed bulletins offline",
    "Backups encrypted with PQC-hybrid envelope; cross-region anchor verification",
]

# ---------------------- roadmap (compact) ----------------------
roadmap = [
    {"year": 2026, "highlights": ["Master BP v1.0", "Sentinel v2.4 GA", "OPA library v1", "first regulator demo", "MRM lifecycle live T1"]},
    {"year": 2027, "highlights": ["PRA SS1/23 self-attestation", "MAS FEAT cert", "AGI Containment v2", "ANC pilot", "EU↔UK kill-switch pilot"]},
    {"year": 2028, "highlights": ["GSC charter signed", "Sandbox passport pilots", "TDL v1 live", "GRTC cohort 1"]},
    {"year": 2029, "highlights": ["PSM alpha 100 nodes", "GSKG v1 + SIE alpha", "PQC Tier-1 complete"]},
    {"year": 2030, "highlights": ["GSC operational", "SASK + SSPEP standardized", "PSM public verifier"]},
    {"year": 2031, "highlights": ["LATAM/MEA/ASEAN adoption via passport"]},
    {"year": 2032, "highlights": ["Treaty review GASRGP Art 12", "Codex v2 amendment cycle"]},
]

# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": (
        "Deliver a regulator-submission-grade, end-to-end Master Reference & "
        "Implementation Blueprint for Enterprise AGI/ASI governance, "
        "EU-primary but globally interoperable, that is directly consumable by "
        "Sentinel sidecars, OPA bundles, supervisory notebooks, and the "
        "Planetary Supervisory Mesh."
    ),
    "approach": (
        "Layered architecture (Codex → Treaty → Policy → Control → App → Data → "
        "Citizen) with zero-trust, Kafka WORM, multisig change control, PQC "
        "hybrid signing, AGI containment thresholds (Δ ≤ 4 %, latent ≤ 3 %, "
        "cosine ≥ 0.92, kill-switch ≤ 60 s), and a 5-year roadmap extending to "
        "2032 for global adoption."
    ),
    "deliverables": (
        "14 modules · 70 sections · 12 schemas · 16 code examples · 6 case "
        "studies · 24 supervisory KPIs · 12 regulators · 12 risk-control rows "
        "· 7 workshops · 6 data flows · 12 traceability rows · 7-year roadmap "
        "· Annexes A-G + D/E/F · machine-parsable <directive> block."
    ),
    "outcomes": [
        "Sub-30-min evidence-pack assembly with PAdES + Sigstore signing",
        "Sub-60-second multisig kill-switch propagation (cross-border)",
        "Quarterly GAP attestation co-signed by AISI",
        "Pillar 2 AI Capital Overlay calibrated to GTI sub-indices",
        "PQC-safe critical bundles by 2029",
        "GSC operational by 2030 with PSM public verifier",
    ],
    "workshopsAndPilots": (
        "7 workshops (Board → press) and 4 pilots (EU↔UK, MAS↔HKMA, US-FRB, "
        "GAISM) drive global adoption and harmonization 2026-2032."
    ),
}

# ---------------------- assemble ----------------------
DOC["modules"] = modules
DOC["schemas"] = schemas
DOC["codeExamples"] = code
DOC["caseStudies"] = cases
DOC["kpis"] = kpis
DOC["riskControlMatrix"] = riskControlMatrix
DOC["traceability"] = traceability
DOC["dataFlows"] = dataFlows
DOC["regulators"] = regulators
DOC["workshops"] = workshops
DOC["privacy"] = privacy
DOC["deploymentConsiderations"] = deployment
DOC["roadmap"] = roadmap
DOC["executiveSummary"] = executiveSummary

DOC["counts"] = {
    "modules": len(modules),
    "sections": sum(len(m["sections"]) for m in modules),
    "schemas": len(schemas),
    "codeExamples": len(code),
    "caseStudies": len(cases),
    "kpis": len(kpis),
    "regulators": len(regulators),
    "workshops": len(workshops),
    "dataFlows": len(dataFlows),
    "traceabilityRows": len(traceability),
    "riskControlRows": len(riskControlMatrix),
    "annexes": 7,
    "roadmapYears": len(roadmap),
    "apiRoutes": 100,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
print("counts:", DOC["counts"])
