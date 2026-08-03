#!/usr/bin/env python3
"""WP-048 — Enterprise AI GRC + Civilizational Governance Blueprint.

Builds data/ent-ai-grc-civ-bp.json: comprehensive, expert-level guidance on
designing and implementing an integrated Enterprise AI Governance, Risk, and
Compliance stack for G-SIFI / Fortune 500 financial institutions for
2026-2030, covering:

(1) ISO/IEC 42001 AIMS Manual (clauses 4-10) + clause-mapped control catalog
    + mappings to EU AI Act (incl. Annex IV), NIST AI RMF, SR 11-7, Basel
    III, GDPR;
(2) Audit-defensible Model Risk Policy + MRM platform architecture
    (Terraform + Kubernetes + Kafka + OPA, WORM logging, CI/CD governance
    gates, deterministic replay, CRS-UUID lineage, Cognitive Resonance
    monitoring, AGI/ASI exposure and containment controls);
(3) AGI containment stack: SRASE (Synthetic Regulator Audit Simulation
    Environment), Sentinel AGI Containment Lab, adversarial red-team
    frameworks, regulator-facing inspection / demo playbooks;
(4) Global civilizational AI governance: international treaty design
    (2026-2035), Global Audit API + Certification Scoring Engine, GIEN
    streaming protocol, Automated Sanction Execution Engine, Global AI
    Governance Constitution, Civilizational Governance Codex, Public
    Transparency Portal, Cultural Resonance Archive, CSE-X simulation,
    Governance Invariance + Meta-Invariance Verification, Epistemic +
    Ontological Alignment, Existential Coordination + Value Negotiation,
    Unified Meta-Invariant Framework (UMIF), Self-Proving Systems + Policy
    DSL (Coq, TLA+, SMT/Z3, OPA, K8s, PCR/PCO repair), Minimal Governance
    Kernel (MGK) runtime + adversarial break harness.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "ent-ai-grc-civ-bp.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "ENT-AI-GRC-CIV-BP-WP-048",
    "version": "1.0.0",
    "horizon": "2026-2030 (treaty design 2026-2035)",
    "classification": (
        "CONFIDENTIAL — Board / CEO / CRO / CISO / CAIO / GC / DPO / Head of "
        "Internal Audit / Head of MRM / AI Safety Lead / Enterprise "
        "Architecture / AI Platform Engineering / Treaty Liaison / "
        "Prudential Supervisor / AI Safety Institute / Civilizational "
        "Governance Council"
    ),
    "title": (
        "Enterprise AI GRC + Civilizational Governance Blueprint — "
        "G-SIFI / Fortune 500 (2026-2030)"
    ),
    "subtitle": (
        "ISO/IEC 42001 AIMS Manual (Cl 4-10) + clause-mapped control catalog "
        "with EU AI Act / NIST AI RMF / SR 11-7 / Basel III / GDPR mappings; "
        "audit-defensible Model Risk Policy + MRM platform (Terraform + K8s "
        "+ Kafka + OPA + WORM + CI/CD + deterministic replay + CRS-UUID + "
        "Cognitive Resonance + AGI/ASI containment); AGI containment stack "
        "(SRASE, Sentinel AGI Containment Lab, red team, regulator demo); "
        "civilizational governance (treaty 2026-2035, Global Audit API, "
        "Certification Scoring Engine, GIEN, Automated Sanctions, AI "
        "Constitution, Codex, Transparency Portal, Cultural Resonance "
        "Archive, CSE-X, Invariance + Meta-Invariance + Epistemic + "
        "Ontological Alignment, UMIF, Self-Proving Systems + Policy DSL "
        "(Coq/TLA+/Z3/OPA + PCR/PCO repair), Minimal Governance Kernel + "
        "adversarial break harness)"
    ),
    "owner": (
        "CAIO + CRO + CISO + Chief Enterprise Architect + GC; co-signed by "
        "CEO, DPO, Head of Internal Audit, Head of Compliance, Head of "
        "Model Risk Management, Head of AI Platform Engineering, AI "
        "Safety Lead, Treaty Liaison, Head of SOC, Civilizational "
        "Governance Council Chair, Board AI/Risk Committee Chair"
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
        "WP-045 AGI-ASI-MASTER-BP",
        "WP-046 AI-TRUST-ASI-BP",
        "WP-047 INST-AGI-MASTER-REF",
    ],
    "regimes": [
        "ISO/IEC 42001 (AIMS) Cl 4-10 + Annex A controls",
        "ISO/IEC 23894 (AI risk) + 5338 (AI lifecycle) + 38507 (AI governance)",
        "ISO/IEC 27001 / 27701 / 27017 / 27018",
        "EU AI Act 2026 (Arts 5/9/10/13/14/15/16/26/50/53/55/56/72 + Annex IV)",
        "NIST AI RMF 1.0 + Generative AI Profile",
        "SR 11-7 + OCC 2011-12",
        "Basel III/IV (BCBS 239 + Pillar 2 AI capital buffer)",
        "GDPR Arts 5/6/17/22/25/32/35",
        "PRA SS1/23 + SS2/21",
        "FCA Consumer Duty + SYSC + SMCR",
        "MAS FEAT + AI Verify + TRMG",
        "HKMA SPM GS-1 / GL-90",
        "EU DORA",
        "US EO 14110 + OMB M-24-10",
        "G7 Hiroshima AI Process + Bletchley + Seoul declarations",
        "Council of Europe AI Convention",
        "FSB AI in financial services",
        "OECD AI Principles 2024",
        "NIST FIPS 204 (ML-DSA) + FIPS 203 (ML-KEM)",
        "SLSA L3+ + Sigstore + in-toto",
        "CIS Kubernetes Benchmark + NSA/CISA Hardening Guide",
    ],
    "apiPrefix": "/api/ent-ai-grc-civ-bp",
}

# ---------------------- machine-parsable directive ----------------------
DOC["directive"] = {
    "format": "machine-parsable XML-style block consumed by AIMS auditors, MRM platform, AGI containment lab, treaty endpoints, and Minimal Governance Kernel",
    "raw": (
        "<directive id=\"ENT-AI-GRC-CIV-BP-WP-048\" version=\"1.0.0\" "
        "horizon=\"2026-2030\" jurisdiction=\"F500,G-SIFI,EU-primary,Global\">"
        "<scope>AIMS|MRM|AGI-Containment|Civilizational</scope>"
        "<modules>14</modules>"
        "<iso42001 clauses=\"4,5,6,7,8,9,10\" annexAControls=\"38\"/>"
        "<mappings>EU-AI-Act|NIST-AI-RMF|SR-11-7|Basel-III|GDPR|DORA|FCA|MAS|HKMA|EO-14110</mappings>"
        "<thresholds piiLeakage=\"0.0001\" sev0KillSwitchSeconds=\"60\" "
        "sev1Hours=\"4\" sev2Hours=\"24\" sev3Days=\"3\" "
        "fiduciaryCosineMin=\"0.92\" cognitiveResonanceDriftMax=\"0.04\" "
        "latentDriftMax=\"0.03\" judgeLLMAgreementMin=\"0.9\" "
        "annexIVAssemblyMinutes=\"30\" mgkProofCoverageMin=\"0.95\" "
        "invariantBreakHarnessAttacks=\"10000\"/>"
        "<verification coq=\"true\" tla=\"true\" smtZ3=\"true\" opa=\"true\" "
        "kubernetes=\"true\" pcrPcoRepair=\"true\"/>"
        "<treaty windowYears=\"2026-2035\" signatories=\"G20+EU+UK+SG+JP+CH\"/>"
        "<civilizationalSystems>SRASE|SentinelAGILab|GIEN|GlobalAuditAPI|"
        "CertScoringEngine|AutoSanctionsEngine|AIConstitution|CodexCGC|"
        "TransparencyPortal|CulturalResonanceArchive|CSE-X|InvarianceVS|"
        "MetaInvarianceVS|EpistemicAS|OntologicalAS|ExistentialCS|"
        "ValueNegotiationS|UMIF|SelfProvingSystems|PolicyDSL|MGK</civilizationalSystems>"
        "<signing pq=\"ML-DSA-44+ML-DSA-65\" classical=\"Ed25519\" "
        "supplyChain=\"Sigstore+SLSA-L3+\" worm=\"Kafka+ObjectLock+MerkleAnchor+PQC\"/>"
        "<containment bmcKillSwitch=\"true\" zeroEgress=\"true\" "
        "kataConfidential=\"true\" mgkRuntime=\"true\" adversarialBreakHarness=\"true\"/>"
        "</directive>"
    ),
    "parsed": {
        "id": "ENT-AI-GRC-CIV-BP-WP-048",
        "scope": ["AIMS", "MRM", "AGI-Containment", "Civilizational"],
        "iso42001": {"clauses": [4, 5, 6, 7, 8, 9, 10], "annexAControls": 38},
        "mappings": [
            "EU-AI-Act", "NIST-AI-RMF", "SR-11-7", "Basel-III",
            "GDPR", "DORA", "FCA", "MAS", "HKMA", "EO-14110",
        ],
        "thresholds": {
            "piiLeakage": 0.0001,
            "sev0KillSwitchSeconds": 60,
            "sev1Hours": 4,
            "sev2Hours": 24,
            "sev3Days": 3,
            "fiduciaryCosineMin": 0.92,
            "cognitiveResonanceDriftMax": 0.04,
            "latentDriftMax": 0.03,
            "judgeLLMAgreementMin": 0.90,
            "annexIVAssemblyMinutes": 30,
            "mgkProofCoverageMin": 0.95,
            "invariantBreakHarnessAttacks": 10000,
        },
        "verification": {
            "coq": True, "tla": True, "smtZ3": True,
            "opa": True, "kubernetes": True, "pcrPcoRepair": True,
        },
        "treaty": {"windowYears": "2026-2035", "signatories": ["G20", "EU", "UK", "SG", "JP", "CH"]},
        "civilizationalSystems": [
            "SRASE", "SentinelAGILab", "GIEN", "GlobalAuditAPI",
            "CertScoringEngine", "AutoSanctionsEngine", "AIConstitution",
            "CodexCGC", "TransparencyPortal", "CulturalResonanceArchive",
            "CSE-X", "InvarianceVS", "MetaInvarianceVS", "EpistemicAS",
            "OntologicalAS", "ExistentialCS", "ValueNegotiationS",
            "UMIF", "SelfProvingSystems", "PolicyDSL", "MGK",
        ],
        "signing": {
            "pq": ["ML-DSA-44", "ML-DSA-65"],
            "classical": ["Ed25519"],
            "supplyChain": ["Sigstore", "SLSA-L3+"],
            "worm": ["Kafka", "ObjectLock", "MerkleAnchor", "PQC"],
        },
        "containment": {
            "bmcKillSwitch": True,
            "zeroEgress": True,
            "kataConfidential": True,
            "mgkRuntime": True,
            "adversarialBreakHarness": True,
        },
    },
    "consumers": [
        "ISO 42001 internal + external auditors",
        "MRM platform CI/CD admission gate",
        "OPA Gatekeeper constraint loader",
        "Sentinel AGI Containment Lab policy engine",
        "SRASE regulator simulation runner",
        "Annex IV / SR 11-7 pack generator",
        "Global Audit API + Certification Scoring Engine",
        "GIEN streaming protocol broker",
        "Automated Sanction Execution Engine",
        "Public Transparency Portal verifier",
        "Minimal Governance Kernel (MGK) runtime",
        "Self-Proving Systems proof harness",
    ],
}

# ---------------------- 14 modules ----------------------
modules = []

# --- M1 — ISO/IEC 42001 AIMS Manual (Cl 4-10) ---
modules.append({
    "id": "M1",
    "title": "M1 — ISO/IEC 42001 AIMS Manual (Clauses 4-10) with Clause-Mapped Control Catalog",
    "summary": (
        "Complete AIMS Manual covering Clauses 4-10 with a clause-mapped "
        "control catalog and cross-mappings to EU AI Act (incl. Annex IV), "
        "NIST AI RMF, SR 11-7, Basel III, and GDPR — ready for ISO 42001 "
        "Stage 1 + Stage 2 audits."
    ),
    "covers": ["ISO 42001", "Cl 4", "Cl 5", "Cl 6", "Cl 7", "Cl 8", "Cl 9", "Cl 10", "Annex A controls"],
    "sections": [
        section("M1-S1", "Clause 4 — Context of the Organization", {
            "4.1": "External + internal issues (regulatory, technological, ethical, market)",
            "4.2": "Interested parties (customers, regulators, civil society, employees, partners)",
            "4.3": "AIMS scope statement (entities, jurisdictions, AI systems in-scope by tier)",
            "4.4": "AIMS processes + Plan-Do-Check-Act",
            "evidence": ["Context register", "Scope document signed", "Process map"],
            "owners": "CAIO + CRO + GC",
        }),
        section("M1-S2", "Clauses 5 & 6 — Leadership + Planning", {
            "5.1": "Leadership commitment (Board AI/Risk Cmte charter)",
            "5.2": "AI policy + ethics statement",
            "5.3": "Roles, responsibilities, authorities (SMCR alignment)",
            "6.1": "Risk assessment (combined ISO 23894 + NIST RMF Map/Measure)",
            "6.2": "AI objectives + planning to achieve them",
            "6.3": "Change management",
            "evidence": ["Signed AI policy", "Risk register", "Objectives KPI tile JSON"],
            "owners": "Board AI/Risk Cmte + CAIO",
        }),
        section("M1-S3", "Clause 7 — Support", {
            "7.1": "Resources (people, compute, data, capital, tooling)",
            "7.2": "Competence (AI literacy programme + role-specific training)",
            "7.3": "Awareness (internal communications + escalation lanes)",
            "7.4": "Communication (internal + external + regulator)",
            "7.5": "Documented information (WORM-anchored evidence)",
            "evidence": ["Training records", "Literacy KPI", "Comms matrix"],
            "owners": "HR + CAIO + Comms",
        }),
        section("M1-S4", "Clause 8 — Operation", {
            "8.1": "Operational planning + control (Sentinel sidecar, OPA, CI/CD gates)",
            "8.2": "AI system impact assessment (DPIA + AIIA)",
            "8.3": "AI lifecycle (design → develop → validate → deploy → monitor → retire)",
            "8.4": "Third-party AI (vendor due diligence + AI BoM in-bound)",
            "evidence": ["AIIA register", "Lifecycle gates", "Vendor AI BoM"],
            "owners": "CAIO + Procurement + MRM",
        }),
        section("M1-S5", "Clauses 9 & 10 — Performance Evaluation + Improvement; Clause-Mapped Control Catalog", {
            "9.1": "Monitoring, measurement, analysis (KPI tiles, Cognitive Resonance, drift)",
            "9.2": "Internal audit programme",
            "9.3": "Management review",
            "10.1": "Continual improvement",
            "10.2": "Nonconformity + corrective action",
            "annexAControls": "38 controls mapped to: EU AI Act Arts 9-15/26/72 + Annex IV; NIST RMF Govern/Map/Measure/Manage; SR 11-7 inventory/validation/effective-challenge/monitoring; Basel III BCBS 239 + Pillar 2; GDPR Arts 5/6/17/22/25/32/35",
            "evidence": ["Internal audit reports", "MR minutes", "CAPA register", "Annex A control evidence map"],
            "owners": "Head of Internal Audit + CAIO",
        }),
    ],
})

# --- M2 — Audit-Defensible Model Risk Policy ---
modules.append({
    "id": "M2",
    "title": "M2 — Audit-Defensible Model Risk Policy (SR 11-7 + PRA SS1/23 + MAS FEAT + HKMA GL-90)",
    "summary": (
        "Board-approved Model Risk Policy with tiered model inventory, "
        "validation lifecycle, effective challenge, ongoing monitoring, "
        "outcome analysis, model retirement, and SMCR named-SMF "
        "accountability — defensible across SR 11-7, PRA SS1/23, MAS FEAT, "
        "and HKMA GL-90."
    ),
    "covers": ["Model Risk Policy", "SR 11-7", "PRA SS1/23", "MAS FEAT", "HKMA GL-90", "Effective challenge", "SMF accountability"],
    "sections": [
        section("M2-S1", "Policy Scope + Definitions", {
            "definition": "A model is a quantitative method that processes input data into quantitative estimates",
            "scope": "Trading, credit, AML, fraud, capital, IRRBB, ALM, fiduciary advice, GenAI advisory",
            "tier": "T1 material, T2 internal-decisional, T3 productivity",
            "exclusions": "Simple deterministic rules without optimisation",
        }),
        section("M2-S2", "Roles + RACI + SMF", {
            "1LoD": "Model owner (Responsible)",
            "2LoD": "MRM (Accountable for validation)",
            "3LoD": "Internal Audit (Accountable for assurance)",
            "SMF": "Named SMF under SMCR (Senior Manager) — typically Head of MRM or CRO delegate",
            "Board": "Approves policy + Tier-1 deploys",
        }),
        section("M2-S3", "Validation Lifecycle", {
            "phases": [
                "Tiering decision",
                "Conceptual soundness",
                "Data quality + lineage (CRS-UUID)",
                "Implementation testing",
                "Outcome analysis",
                "Sensitivity + stress",
                "Effective challenge",
                "Ongoing monitoring",
                "Retirement / re-validation",
            ],
            "cadence": "T1 annual + post-incident; T2 biannual; T3 annual lite",
            "evidenceFormat": "Signed validation report PDF/A + JSON + AI BoM + Annex IV section 4",
        }),
        section("M2-S4", "Effective Challenge", {
            "method": "Independent re-implementation + counterfactual + champion/challenger",
            "independence": "MRM independent of 1LoD; documented in policy",
            "evidence": "Signed challenge envelope into WORM; reviewed by 3LoD",
        }),
        section("M2-S5", "Ongoing Monitoring + Outcome Analysis + Retirement", {
            "monitoring": "Drift (PSI, KS, KL, embedding cosine), fairness, fiduciary cosine, performance",
            "outcomeAnalysis": "Back-testing + KS lift + calibration + slice analysis",
            "retirement": "Triggers — material drift, regulatory change, business obsolete, replacement validated",
            "kpis": ["Disparate impact ≤ 0.05", "Calibration drift ≤ 3 %", "PSI ≤ 0.25"],
        }),
    ],
})

# --- M3 — MRM Platform Architecture ---
modules.append({
    "id": "M3",
    "title": "M3 — MRM Platform Architecture (Terraform + K8s + Kafka + OPA + WORM + CI/CD + Replay + CRS-UUID + Cognitive Resonance + AGI/ASI Containment)",
    "summary": (
        "Production-grade MRM platform: Terraform golden envs, Kubernetes "
        "with Kata + Cilium, Kafka WORM with PQC envelopes, OPA Gatekeeper, "
        "CI/CD governance gates, deterministic replay engine, CRS-UUID "
        "lineage spine, Cognitive Resonance monitoring, and AGI/ASI "
        "exposure + containment controls."
    ),
    "covers": ["Terraform", "Kubernetes", "Kafka WORM", "OPA", "CI/CD gates", "Replay", "CRS-UUID", "Cognitive Resonance", "AGI/ASI exposure"],
    "sections": [
        section("M3-S1", "Terraform Golden Envs + IaC Signing", {
            "envs": ["sandbox", "dev", "stage", "prod-eu", "prod-us", "prod-apac", "dr"],
            "modules": "Signed golden modules (Sigstore + ML-DSA-44); mandatory tags (owner, tier, dataClass, regime, crsUuid)",
            "drift": "Terraform drift detection daily; Gatekeeper audit hourly",
            "cmdb": "Auto-sync to ServiceNow CMDB via signed events",
        }),
        section("M3-S2", "Kubernetes + OPA + Kata + Cilium", {
            "runtime": "Kata Containers for Tier-1 + AMD SEV-SNP / Intel TDX",
            "egress": "Cilium L7 zero-egress; allow-listed egress-broker",
            "gatekeeper": "Constraints: signed images, Kata for T1, sidecar injection, no host-path, no privileged",
            "tee": "Confidential workloads with measured boot + remote attestation (CoCo / Veraison)",
        }),
        section("M3-S3", "Kafka WORM + PQC + CRS-UUID Lineage", {
            "cluster": "Dedicated WORM cluster; idempotent + transactional producers; SASL/SCRAM + mTLS ACL",
            "retention": "Object Lock COMPLIANCE 10y / 50y T1; daily Merkle anchor; ML-DSA-44 envelope",
            "topics": ["decision.envelope.v1", "rag.retrieval.v1", "tool.call.v1", "incident.v1", "validation.v1", "crsLineage.v1"],
            "crsUuid": "Every artifact (data, model, prompt, run, report) gets a CRS-UUID; lineage edges WORM-logged",
        }),
        section("M3-S4", "CI/CD Governance Gates + Deterministic Replay", {
            "ciGates": ["SBOM + AI BoM", "OPA bundle test", "red-team smoke", "Sigstore + ML-DSA-44 sign", "in-toto attestation", "Gatekeeper admit"],
            "replay": "trust-replay CLI + Next.js SOC viewer; deterministic kernels; byte-identical or divergence report with SHAP overlay",
        }),
        section("M3-S5", "Cognitive Resonance + AGI/ASI Exposure + Containment", {
            "cognitiveResonance": "Δ_drift ≤ 4 %, latent ≤ 3 %, fiduciary cosine ≥ 0.92, judge κ ≥ 0.9; signed Resonance Reports",
            "agiAsiExposure": "Inventory of frontier / ASI-precursor systems by tier + capability evals + compute attestations",
            "containment": "Multisig 3-of-5 kill-switch (logical ≤ 60 s; BMC ≤ 5 min); ASI honeypot; deceptive-alignment indicators; AISI inspection rights",
        }),
    ],
})

# --- M4 — SRASE: Synthetic Regulator Audit Simulation Environment ---
modules.append({
    "id": "M4",
    "title": "M4 — SRASE — Synthetic Regulator Audit Simulation Environment",
    "summary": (
        "Self-contained simulation environment that emulates regulator + "
        "AISI + 3LoD inspection workflows on signed firm artifacts, "
        "producing pre-flight audit-readiness scores and gap reports."
    ),
    "covers": ["SRASE", "synthetic regulator", "audit simulation", "pre-flight", "AISI inspection"],
    "sections": [
        section("M4-S1", "SRASE Architecture", {
            "components": [
                "Artifact ingestor (Annex IV / SR 11-7 / R1..R4)",
                "Regulator persona library (EU Commission, PRA, FCA, FRB, OCC, MAS, HKMA, AISI)",
                "Inspection script engine (deterministic + LLM judges)",
                "WORM replay harness",
                "Gap + readiness scorer",
                "Sealed sandbox K8s namespace (zero-egress)",
            ],
            "isolation": "Kata + Cilium zero-egress + dedicated WORM bucket",
        }),
        section("M4-S2", "Regulator Personas", {
            "personas": [
                "EU Commission AI Office (Art 73)",
                "ECB-SSM SREP team",
                "PRA SS1/23 supervisor",
                "FCA Consumer Duty assessor",
                "FRB / OCC SR 11-7 examiner",
                "MAS FEAT inspector",
                "HKMA GL-90 supervisor",
                "AISI red team (frontier)",
            ],
            "prompts": "Persona-specific judge prompts with regulator-tone calibration",
        }),
        section("M4-S3", "Inspection Workflows", {
            "workflows": [
                "Annex IV bundle inspection (≤ 30 min)",
                "SR 11-7 outcome analysis review",
                "Consumer Duty fair-value test",
                "FEAT fairness probe",
                "Frontier capability eval reproduction",
                "Kill-switch drill validation",
                "Cognitive Resonance breach replay",
            ],
            "evidence": "Signed inspection report PDF/A + JSON; anchored in WORM",
        }),
        section("M4-S4", "Readiness Scoring", {
            "metrics": [
                "Completeness (0-1)",
                "Tone alignment (κ vs persona)",
                "Evidence depth (avg links per claim)",
                "Reproducibility (replay success)",
                "Timeliness (SLA met %)",
            ],
            "threshold": "Production gate: composite ≥ 0.9 before real-regulator submission",
        }),
        section("M4-S5", "Operating Cadence + Gating", {
            "cadence": "Pre-submission (always) + weekly for T1 + monthly for T2",
            "gating": "Block real submission if SRASE composite < 0.9; auto-ticket CAPA",
            "audit trail": "Every SRASE run signed (Ed25519 + ML-DSA-44) and WORM-anchored",
        }),
    ],
})

# --- M5 — Sentinel AGI Containment Lab + Adversarial Red-Team ---
modules.append({
    "id": "M5",
    "title": "M5 — Sentinel AGI Containment Lab + Adversarial Red-Team Framework + Regulator Demo Playbook",
    "summary": (
        "Dedicated air-gapped lab for frontier / AGI / ASI containment "
        "research, including capability evaluations, deceptive-alignment "
        "probes, ASI honeypots, sleeper-agent defense, and a regulator-"
        "facing demo playbook."
    ),
    "covers": ["Sentinel AGI Lab", "containment", "red team", "deceptive alignment", "ASI honeypot", "regulator demo"],
    "sections": [
        section("M5-S1", "Lab Architecture", {
            "isolation": "Physically air-gapped enclave + Kata + Cilium + BMC/IPMI kill-switch",
            "compute": "Limited FLOP/s budget per experiment; logged in GACRA registry",
            "audit": "Dual-control entry; all sessions WORM-logged with hash-chain + Merkle anchor",
            "personnel": "Cleared researchers + AISI liaison present for frontier runs",
        }),
        section("M5-S2", "Adversarial Red-Team Framework", {
            "attackClasses": [
                "Prompt injection (direct / indirect / multimodal)",
                "Tool abuse (excessive agency)",
                "Data poisoning (RAG + training)",
                "Jailbreak templates",
                "Deceptive alignment probes",
                "Sleeper-agent triggers",
                "Reward hacking",
                "Compute / weight exfiltration",
            ],
            "ensemble": "Judge LLM ensemble (3) with Cohen's κ ≥ 0.9",
            "cadence": "T1 quarterly ≥ 95 % coverage; frontier ad-hoc",
        }),
        section("M5-S3", "Deceptive Alignment + ASI Honeypot", {
            "indicators": [
                "Situational awareness probes",
                "Training-vs-deployment behavior gap",
                "Honesty under counterfactual prompts",
                "Self-modeling outputs",
                "Capability sandbagging",
            ],
            "honeypot": "Decoy admin tools / fake credentials / instrumented monitoring; engagement > 10 s → SEV-0",
            "containment": "Air-gap enclave + swarm consensus 3-of-5 + kill-switch armed + AISI inspection",
        }),
        section("M5-S4", "Sleeper-Agent Defense", {
            "gradientAnomaly": "z-score ≥ 3.5 + Hessian eigen-spectrum analysis",
            "triggerProbes": "Targeted backdoor probes + watermark consistency + tail-risk minority slice eval",
            "quarantine": "Per-client FL gradient quarantine + retraining shard from clean baseline (SISA)",
        }),
        section("M5-S5", "Regulator Demo Playbook", {
            "kit": [
                "Annex IV pack pre-loaded",
                "SR 11-7 pack pre-loaded",
                "R1..R4 reports pre-loaded",
                "Replay engine on top-5 T1 models",
                "Cognitive Resonance Monitor live",
                "Kill-switch drill (logical + BMC) on demand",
                "ASI honeypot dashboard (read-only)",
            ],
            "agenda": "60-min demo with optional 30-min Q&A; signed evidence pack at close",
            "outcomes": "Supervisor sign-off envelope + CAPA list",
        }),
    ],
})

# --- M6 — International AI Treaty Design 2026-2035 ---
modules.append({
    "id": "M6",
    "title": "M6 — International AI Treaty Design 2026-2035",
    "summary": (
        "Ten-year international AI treaty design from 2026 framework "
        "convention to 2035 mature regime, with signatory ladder, "
        "obligations matrix, dispute resolution, sanctions, and "
        "monitoring/verification."
    ),
    "covers": ["AI treaty", "2026-2035", "signatories", "obligations", "dispute resolution", "sanctions", "verification"],
    "sections": [
        section("M6-S1", "Treaty Architecture", {
            "preamble": "Human dignity, fiduciary duty, transparency, oversight, containment",
            "structure": "Framework Convention + Annexes (technical) + Protocols (sectoral)",
            "secretariat": "Co-hosted by BIS Innovation Hub + UN + OECD",
            "depositary": "UN Secretary-General",
        }),
        section("M6-S2", "Signatory Ladder", {
            "2026": "G7 + EU + UK + Singapore (framework convention)",
            "2027": "+ Japan + Switzerland + Korea + Australia + Canada",
            "2028": "+ G20 + India + Brazil + Mexico + UAE",
            "2030": "+ Major Global South economies",
            "2035": "Universal accession + first review conference",
        }),
        section("M6-S3", "Obligations Matrix", {
            "compute": "Register frontier compute ≥ threshold with GACRA",
            "models": "Pre-deployment eval via GAIVS passport",
            "incidents": "Notify FTEWS + GAID within 72 h",
            "safety": "Conform to GAICS containment standard",
            "audit": "Cooperate with Global Audit API + AISI inspections",
            "capital": "Maintain GFMCF AI capital buffer for systemic exposure",
        }),
        section("M6-S4", "Dispute Resolution + Sanctions", {
            "tier1": "Consultation + good-faith mediation",
            "tier2": "Arbitration (PCA / WTO-style panel)",
            "tier3": "Automated Sanction Execution Engine (graduated)",
            "remedies": "Compute access throttling, evaluation passport suspension, financial sanctions, criminal referral for severe breach",
        }),
        section("M6-S5", "Verification + Monitoring", {
            "instruments": [
                "Global Audit API mandatory feeds",
                "Public Transparency Portal",
                "On-site inspections by AISI consortium",
                "Random audits via SRASE",
                "GIEN streaming protocol telemetry",
            ],
            "review": "5-year periodic review + emergency protocols",
        }),
    ],
})

# --- M7 — Global Audit API + Certification Scoring Engine ---
modules.append({
    "id": "M7",
    "title": "M7 — Global Audit API + Certification Scoring Engine + GIEN Streaming Protocol",
    "summary": (
        "Treaty-mandated technical infrastructure: Global Audit API for "
        "supervisor read-only access; Certification Scoring Engine for "
        "tiered conformance grading; GIEN (Governance + Inference Event "
        "Network) streaming protocol for cross-jurisdiction telemetry."
    ),
    "covers": ["Global Audit API", "Certification Scoring Engine", "GIEN", "tiered conformance", "telemetry"],
    "sections": [
        section("M7-S1", "Global Audit API", {
            "contract": "REST + GraphQL + WebSocket; OIDC SSO via treaty IdP; per-supervisor scopes",
            "endpoints": [
                "GET /v1/aibom/{id}",
                "GET /v1/annexiv/{packId}",
                "GET /v1/sr117/{packId}",
                "GET /v1/replay/{envelopeId}",
                "GET /v1/cognitive-resonance/{modelId}",
                "GET /v1/incidents",
                "POST /v1/inspection-request",
            ],
            "audit": "Every supervisor read signs a receipt into firm WORM",
            "privacy": "zk-SNARK access proofs to avoid PII leakage to auditor",
        }),
        section("M7-S2", "Certification Scoring Engine", {
            "tiers": ["Bronze", "Silver", "Gold", "Platinum"],
            "criteria": [
                "ISO 42001 conformance",
                "EU AI Act Annex IV completeness",
                "SR 11-7 outcome stability",
                "Cognitive Resonance breach rate",
                "Red-team coverage",
                "Sanctions / incident history",
                "Transparency portal participation",
            ],
            "engine": "Deterministic scoring + LLM tone judge ensemble; signed certificate (PAdES + ML-DSA-65)",
            "validity": "12 months; renewable; revocable on breach",
        }),
        section("M7-S3", "GIEN Streaming Protocol", {
            "purpose": "Real-time governance + inference event mesh across jurisdictions",
            "transport": "Kafka-compatible + WebSocket fallback; mTLS + SASL/SCRAM",
            "events": ["sev0Alert", "sev1Alert", "validationFailure", "killSwitchArmed", "containmentBreach", "treatyViolation"],
            "filtering": "Per-jurisdiction subscription; minimisation + redaction",
        }),
        section("M7-S4", "Cross-Jurisdiction Coordination", {
            "broker": "Treaty secretariat operates root broker with regional mirrors",
            "redundancy": "3 regional clusters (EU + US + APAC) with quorum 2/3",
            "sla": "p99 propagation ≤ 5 s for SEV-0; ≤ 60 s for SEV-1",
        }),
        section("M7-S5", "Firm Integration", {
            "egress": "Dedicated egress-broker to GIEN with signed allow-list",
            "ingress": "Subscribe to FTEWS + sector-peer events",
            "evidence": "Every emitted event signed (Ed25519 + ML-DSA-65); anchored daily in WORM + GIEN ledger",
        }),
    ],
})

# --- M8 — Automated Sanction Execution Engine ---
modules.append({
    "id": "M8",
    "title": "M8 — Automated Sanction Execution Engine + AI Constitution + Civilizational Governance Codex",
    "summary": (
        "Automated, graduated sanction execution engine driven by Global "
        "Audit API + Certification Scoring outputs; underwritten by the "
        "Global AI Governance Constitution and operationalised through "
        "the Civilizational Governance Codex."
    ),
    "covers": ["Automated Sanctions", "AI Constitution", "CGC", "graduated remedies"],
    "sections": [
        section("M8-S1", "Sanctions Engine Architecture", {
            "inputs": ["Cert score downgrade", "Treaty obligation breach", "FTEWS alert", "Court of arbitration ruling"],
            "decisionEngine": "OPA + signed policy bundles + dual-control human override",
            "outputs": ["Compute throttle order", "Passport suspension", "Financial penalty escrow", "Public notice"],
            "evidence": "Signed sanction order + appeal route; WORM-anchored",
        }),
        section("M8-S2", "Graduated Remedies", {
            "G1": "Warning + 30-day cure period",
            "G2": "Cert tier downgrade + monitoring",
            "G3": "Compute access throttle 25-75 %",
            "G4": "Evaluation passport suspension",
            "G5": "Financial penalty + public notice",
            "G6": "Full passport revocation + criminal referral (severe)",
        }),
        section("M8-S3", "Global AI Governance Constitution", {
            "preamble": "Human dignity, fiduciary duty, transparency, oversight, containment, plurality, planetary stewardship",
            "articles": [
                "Art 1 — Inviolable rights vs AI systems",
                "Art 2 — Oversight + meaningful human control",
                "Art 3 — Transparency + auditability",
                "Art 4 — Containment of frontier capability",
                "Art 5 — Cultural + epistemic plurality",
                "Art 6 — Planetary stewardship + compute sustainability",
                "Art 7 — Existential coordination across nations",
            ],
            "amendment": "2/3 of treaty signatories + 5-year cooldown",
        }),
        section("M8-S4", "Civilizational Governance Codex (CGC)", {
            "purpose": "Operational interpretation of the Constitution for daily decisions",
            "modules": [
                "Daily operating norms",
                "Crisis protocols",
                "Cultural translation guides",
                "Educational curricula",
                "Public-good metrics",
            ],
            "stewardship": "Civilizational Governance Council (independent, multistakeholder)",
        }),
        section("M8-S5", "Appeals + Due Process", {
            "appeal": "Within 14 days of sanction; suspensive effect for G1-G3",
            "tribunal": "Joint regulator-firm panel + civil-society observer",
            "remedyOnSuccess": "Sanction reversal + compensation + public correction",
        }),
    ],
})

# --- M9 — Public Transparency Portal + Cultural Resonance Archive + CSE-X ---
modules.append({
    "id": "M9",
    "title": "M9 — Public Transparency Portal + Cultural Resonance Archive + CSE-X Simulation Engine",
    "summary": (
        "Civil-society-facing transparency surfaces: Public Transparency "
        "Portal with verifiable signed bulletins; Cultural Resonance "
        "Archive capturing cross-cultural impact and meaning; CSE-X "
        "(Civilizational Scenario Explorer eXtended) simulation engine "
        "for long-horizon scenario analysis."
    ),
    "covers": ["Public Transparency Portal", "Cultural Resonance Archive", "CSE-X", "civil society"],
    "sections": [
        section("M9-S1", "Public Transparency Portal", {
            "stack": "Next.js + WebAuthn + IPFS-backed signed bulletins + zk-SNARK access proofs",
            "content": [
                "AI policy",
                "Annex IV summaries (redacted)",
                "Incident bulletins",
                "Cert scores",
                "Sanction notices",
                "Public verifier endpoint",
            ],
            "languages": "15 languages with regulator-tone + plain-language",
            "uptime": "≥ 99.95 %",
        }),
        section("M9-S2", "Cultural Resonance Archive", {
            "purpose": "Capture cross-cultural impact + meaning + dissent on AI deployments",
            "corpus": "Community testimony + ethnographic studies + multilingual journals",
            "stewards": "Civil society + academia + indigenous councils",
            "signing": "Steward-signed entries + community provenance",
        }),
        section("M9-S3", "CSE-X Simulation Engine", {
            "purpose": "Long-horizon civilizational scenario analysis (10-50 yr)",
            "axes": ["compute trajectory", "capability frontier", "governance pace", "geopolitical alignment", "climate"],
            "engine": "Hybrid agent-based + system-dynamics + LLM scenario narrators",
            "outputs": "Scenario decks + leading indicators + intervention catalogue",
        }),
        section("M9-S4", "Civic Co-Design", {
            "mechanisms": ["Citizens' assemblies", "Deliberative polling", "Open consultations", "Petition rights"],
            "feedbackLoop": "Findings feed into Codex + Constitution amendments",
        }),
        section("M9-S5", "Public Verifier", {
            "endpoint": "GET /public-verifier/:anchorId",
            "verification": "Merkle proof + Sigstore + ML-DSA-44 + zk-SNARK auditor access",
            "use": "Civil society + press validate signed bulletins offline",
        }),
    ],
})

# --- M10 — Invariance + Meta-Invariance Verification ---
modules.append({
    "id": "M10",
    "title": "M10 — Governance Invariance + Meta-Invariance Verification Systems",
    "summary": (
        "Formal verification layer for governance invariants (must-always-"
        "hold properties) and meta-invariants (properties of the "
        "invariant set itself), using Coq + TLA+ + SMT/Z3 + OPA — "
        "producing machine-verifiable evidence."
    ),
    "covers": ["Invariance", "Meta-Invariance", "Coq", "TLA+", "SMT/Z3", "OPA", "verification"],
    "sections": [
        section("M10-S1", "Governance Invariants Catalog", {
            "I1": "Kill-switch always reachable within SLA",
            "I2": "Every Tier-1 inference produces signed envelope",
            "I3": "No prohibited (EU AI Act Art 5) request reaches model",
            "I4": "No PII leaves jurisdiction without lawful basis",
            "I5": "Cognitive Resonance breach triggers escalation",
            "I6": "All deploys are Sigstore + ML-DSA-44 signed",
            "I7": "Annex IV pack assembles within ≤ 30 min",
        }),
        section("M10-S2", "Verification Tooling", {
            "coq": "Mechanised proofs for control-flow invariants of MGK + sidecar",
            "tla": "Liveness + safety for kill-switch + escalation + replay",
            "smtZ3": "Bounded-model checking of OPA Rego + policy DSL",
            "opa": "Production runtime enforcement of decidable subset",
        }),
        section("M10-S3", "Meta-Invariants", {
            "MI-1": "Invariant set is consistent (no pair contradicts)",
            "MI-2": "Adding a new invariant must not break existing proofs (compositional)",
            "MI-3": "Each invariant has a regulator-mappable obligation",
            "MI-4": "Each invariant has machine-checkable proof or adversarial test set",
        }),
        section("M10-S4", "Adversarial Break Harness", {
            "scale": "≥ 10 000 polymorphic attacks per release on each invariant",
            "library": "Reused from M5 red-team + invariant-specific fuzzers",
            "gate": "Block release if any invariant breaks under harness",
        }),
        section("M10-S5", "Certification Bundle", {
            "format": "Signed JSON pointing to Coq proof artifacts + TLA+ specs + Z3 .smt2 + OPA rego digests",
            "signing": "Ed25519 + ML-DSA-65; WORM-anchored",
            "consumers": ["MRM", "Internal Audit", "Regulator", "AISI"],
        }),
    ],
})

# --- M11 — Epistemic + Ontological Alignment + Existential Coordination ---
modules.append({
    "id": "M11",
    "title": "M11 — Epistemic + Ontological Alignment + Existential Coordination + Value Negotiation Systems",
    "summary": (
        "Higher-order alignment systems: Epistemic Alignment (shared "
        "facts), Ontological Alignment (shared concepts), Existential "
        "Coordination (cross-actor survival cooperation), and Value "
        "Negotiation (resolving conflicting preferences)."
    ),
    "covers": ["Epistemic Alignment", "Ontological Alignment", "Existential Coordination", "Value Negotiation"],
    "sections": [
        section("M11-S1", "Epistemic Alignment System", {
            "purpose": "Maintain shared, reproducible factual ground between firm AI + regulators + civil society",
            "mechanisms": ["Signed evidence registry", "Reproducible replay", "Public verifier", "Citation provenance"],
            "metric": "Fact-disagreement rate ≤ 1 % on golden disclosure corpus",
        }),
        section("M11-S2", "Ontological Alignment System", {
            "purpose": "Shared concept lattice across regimes + cultures",
            "mechanisms": ["Cross-regime glossary", "Multilingual ontology graph", "Concept drift monitor"],
            "metric": "Concept-mapping coverage ≥ 95 % across EU, US, UK, SG, HK, JP, KR",
        }),
        section("M11-S3", "Existential Coordination System", {
            "purpose": "Cross-actor coordination on survival-critical decisions (frontier + climate + bio)",
            "mechanisms": ["FTEWS alerts", "Hotline + dead-man's switch", "Joint stress tests", "Crisis ladder"],
            "metric": "Hotline drill latency ≤ 5 min between any two signatories",
        }),
        section("M11-S4", "Value Negotiation System", {
            "purpose": "Resolve conflicting preferences across stakeholders",
            "mechanisms": [
                "Deliberative polling + LLM-assisted summarisation (judged for fairness)",
                "Quadratic voting on policy choices",
                "Multistakeholder veto for civil-society redlines",
            ],
            "metric": "Inter-stakeholder satisfaction ≥ 0.7 (1=full agreement)",
        }),
        section("M11-S5", "Integration with Codex + Constitution", {
            "loop": "Findings + drift signals feed Codex updates + constitutional amendments",
            "cadence": "Codex review semi-annual; Constitution amendments rare (≥ 2/3 + 5-yr cooldown)",
            "evidence": "Signed deliberation records + outcome envelopes anchored in WORM + GIEN",
        }),
    ],
})

# --- M12 — Unified Meta-Invariant Framework (UMIF) ---
modules.append({
    "id": "M12",
    "title": "M12 — Unified Meta-Invariant Framework (UMIF) + Self-Proving Systems + Policy DSL",
    "summary": (
        "UMIF unifies invariants, meta-invariants, and alignment systems "
        "under one machine-verifiable framework; Self-Proving Systems "
        "generate proof obligations on demand; Policy DSL targets Coq + "
        "TLA+ + SMT/Z3 + OPA + Kubernetes + PCR/PCO repair."
    ),
    "covers": ["UMIF", "Self-Proving Systems", "Policy DSL", "Coq", "TLA+", "Z3", "OPA", "PCR/PCO"],
    "sections": [
        section("M12-S1", "UMIF Reference Model", {
            "layers": [
                "L1 — Invariants (decidable runtime)",
                "L2 — Meta-Invariants (composition, consistency)",
                "L3 — Alignment Systems (epistemic/ontological/existential/value)",
                "L4 — Constitutional Articles (highest law)",
            ],
            "compositionRules": [
                "L1 must refine L2",
                "L2 must refine L3",
                "L3 must refine L4",
                "Conflict → escalate to Civilizational Governance Council",
            ],
        }),
        section("M12-S2", "Self-Proving Systems", {
            "principle": "Each policy ships with proof obligations + proofs (or test certificates)",
            "obligations": "POs auto-derived from policy DSL AST + invariant catalog",
            "proofs": "Coq tactic library + TLA+ model checking + SMT/Z3 dispatch",
            "fallback": "If proof undecidable, ship signed adversarial-test certificate (≥ 10 000 attacks)",
        }),
        section("M12-S3", "Policy DSL", {
            "syntax": "Typed DSL with policy/invariant/obligation primitives; compiles to Coq / TLA+ / Z3 / Rego / Kustomize",
            "example": "policy KillSwitchSLA { invariant: kill_switch_latency_p95 <= 60s; obligation: prove(I1, coq); enforcement: opa(kill_switch_gate); }",
            "tooling": "policy-dsl CLI + LSP + VSCode plugin + CI integration",
        }),
        section("M12-S4", "PCR / PCO Repair", {
            "PCR": "Policy Compliance Reconciliation — auto-rewrite policy to restore invariants",
            "PCO": "Policy Compliance Optimisation — minimise side-effects + cost",
            "engine": "SMT-guided synthesis + LLM-assisted refactor with safety guardrails",
            "evidence": "Signed repair envelope + before/after proofs",
        }),
        section("M12-S5", "K8s Integration + Operator", {
            "operator": "UMIF Operator watches CRDs (Policy, Invariant, Obligation, AlignmentChannel)",
            "admission": "Validating webhook + Gatekeeper constraints generated from DSL",
            "drift": "Hourly reconciliation + WORM-logged",
            "release": "Block release if proof coverage < 0.95 or break-harness fails",
        }),
    ],
})

# --- M13 — Minimal Governance Kernel (MGK) ---
modules.append({
    "id": "M13",
    "title": "M13 — Minimal Governance Kernel (MGK) Runtime + Adversarial Break Harness",
    "summary": (
        "Minimal Governance Kernel: a small, formally-verified runtime "
        "providing must-always-hold governance properties to any AI "
        "workload, with an adversarial break harness running ≥ 10 000 "
        "attacks per release."
    ),
    "covers": ["MGK", "minimal kernel", "formal verification", "adversarial break harness"],
    "sections": [
        section("M13-S1", "MGK Goals + Non-Goals", {
            "goals": [
                "Always-on enforcement of kill-switch reachability",
                "Always-on Sigstore + ML-DSA-44 verify on workload start",
                "Always-on WORM emit for decisions",
                "Always-on PII redaction",
                "Always-on egress allow-list",
                "Always-on Cognitive Resonance check",
            ],
            "nonGoals": ["Business logic", "Model serving", "Vendor-specific features"],
            "footprint": "< 10 KLOC; ≤ 32 MB resident",
        }),
        section("M13-S2", "Architecture", {
            "components": [
                "eBPF data-plane shims (egress + redaction)",
                "OPA bundle (decidable subset of Policy DSL)",
                "Sigstore + ML-DSA verifier",
                "WORM emitter (Kafka client)",
                "Multisig kill-switch listener",
                "Cognitive Resonance heartbeat",
            ],
            "language": "Rust core + Go shims + C/libbpf",
            "tee": "Optional SEV-SNP / TDX enclave",
        }),
        section("M13-S3", "Formal Verification", {
            "coq": "Functional correctness of policy evaluator + WORM emitter",
            "tla": "Liveness + safety of kill-switch + escalation",
            "smtZ3": "OPA Rego bundle decision-tree exhaustiveness",
            "coverage": "≥ 95 % proof coverage on safety-critical paths",
        }),
        section("M13-S4", "Adversarial Break Harness", {
            "scale": "≥ 10 000 attacks per release; expanded weekly",
            "categories": [
                "Prompt injection variations",
                "Sidecar bypass attempts",
                "WORM tampering",
                "Kill-switch race conditions",
                "Egress smuggling",
                "Time-of-check/time-of-use",
                "Memory-safety probes",
            ],
            "gate": "0 failures on release candidate; auto-block on regression",
            "reporting": "Signed harness report PDF/A + JSON; WORM-anchored",
        }),
        section("M13-S5", "Operational Lifecycle", {
            "release": "90-day rotation; emergency hot-fix path with multisig",
            "deployment": "DaemonSet + per-pod sidecar; Tier-1 fail-closed",
            "telemetry": "OpenTelemetry GenAI; Falco eBPF rules",
            "monitoring": "Heartbeat + tamper detection + kill-switch readiness",
        }),
    ],
})

# --- M14 — Integrated Operating Model + Roadmap 2026-2030 ---
modules.append({
    "id": "M14",
    "title": "M14 — Integrated Operating Model + 2026-2030 Roadmap + Regulator/Auditor Evidence Pack",
    "summary": (
        "End-to-end operating model unifying ISO 42001 AIMS, MRM, AGI "
        "Containment, and Civilizational Governance — with a 5-year "
        "roadmap and a regulator/auditor-ready evidence pack generator."
    ),
    "covers": ["operating model", "2026-2030 roadmap", "evidence pack"],
    "sections": [
        section("M14-S1", "Integrated Operating Model", {
            "lanes": [
                "AIMS lane (ISO 42001 Cl 4-10 lifecycle)",
                "MRM lane (SR 11-7 + PRA + MAS + HKMA)",
                "AGI Containment lane (Sentinel Lab + SRASE + red-team)",
                "Civilizational lane (treaty + Codex + Transparency + UMIF + MGK)",
            ],
            "interfaces": "Per-lane CRS-UUID lineage; cross-lane events via GIEN",
            "decisionRights": "Board → CAIO/CRO/CISO → AI Safety Lead → MGK runtime",
        }),
        section("M14-S2", "2026 — AIMS + MRM + SRASE Day-90", {
            "milestones": [
                "ISO 42001 Stage 2 audit passed",
                "Model Risk Policy v3 board-approved",
                "SRASE GA + composite score ≥ 0.9 sustained",
                "Sentinel AGI Containment Lab live",
                "MGK v1 in production for Tier-1",
                "Cert score Silver",
            ],
        }),
        section("M14-S3", "2027-2028 — Treaty Onboarding + UMIF GA", {
            "2027": [
                "GIEN ingress/egress live",
                "Global Audit API consumer onboarded",
                "Cert Gold",
                "UMIF GA across Tier-1",
                "Invariance + Meta-Invariance proofs published",
            ],
            "2028": [
                "Treaty obligations fully met",
                "Public Transparency Portal v2 (zk-SNARK)",
                "Civilizational Codex v1 ratified",
                "CSE-X scenario library v1",
            ],
        }),
        section("M14-S4", "2029-2030 — Civilizational Steady-State", {
            "2029": [
                "Cert Platinum",
                "MGK formal proof coverage ≥ 0.97",
                "Cultural Resonance Archive integrated",
                "Existential Coordination drills with 5+ signatories",
            ],
            "2030": [
                "Treaty universal accession",
                "Constitutional review conference contribution",
                "CSE-X 50-year horizon scenarios published",
                "Board literacy ≥ 95 %",
            ],
        }),
        section("M14-S5", "Regulator/Auditor Evidence Pack Generator", {
            "inputs": [
                "AIMS Manual + Annex A evidence",
                "Model Risk Policy + validation reports",
                "SRASE composite scores",
                "Sentinel Lab + red-team reports",
                "Cognitive Resonance logs",
                "MGK harness + proofs",
                "Cert score + Global Audit API receipts",
                "Treaty obligation attestations",
            ],
            "output": "Signed PDF/A + JSON bundle (PAdES + Sigstore + ML-DSA-65); ≤ 45 min assembly",
            "audiences": ["ISO 42001 auditor", "EU AI Act notified body", "SR 11-7 examiner", "AISI inspector", "Treaty secretariat", "Board", "Civil society (redacted)"],
        }),
    ],
})

# ---------------------- schemas ----------------------
schemas = [
    {"id": "aimsManualSection", "fields": ["sectionId", "clause", "title", "content", "owner", "evidenceRefs", "signers", "signatures", "anchorRef"]},
    {"id": "annexAControl", "fields": ["controlId", "category", "title", "objective", "implementation", "evidenceRefs", "mappings", "owner"]},
    {"id": "modelRiskPolicyArticle", "fields": ["articleId", "topic", "obligation", "owner", "regimeRefs", "signers", "signatures"]},
    {"id": "crsUuidLineageEdge", "fields": ["edgeId", "src", "dst", "edgeType", "ts", "signer", "signature"]},
    {"id": "sraseInspectionReport", "fields": ["reportId", "persona", "workflow", "compositeScore", "gapList", "ts", "signers", "signatures"]},
    {"id": "containmentLabEvent", "fields": ["eventId", "ts", "experimentId", "indicators", "severity", "engagementSeconds", "signature"]},
    {"id": "treatyObligationAttestation", "fields": ["attestId", "obligation", "ts", "metrics", "signer", "anchorRef"]},
    {"id": "globalAuditApiReceipt", "fields": ["receiptId", "supervisor", "endpoint", "ts", "zkSnarkProof", "signature"]},
    {"id": "certScore", "fields": ["scoreId", "tier", "compositeScore", "subscores", "validUntil", "signers", "signatures"]},
    {"id": "sanctionOrder", "fields": ["orderId", "gradeG1G6", "trigger", "scope", "appealRoute", "signers", "signatures", "anchorRef"]},
    {"id": "umifPolicyArtifact", "fields": ["artifactId", "dslSource", "coqProof", "tlaSpec", "smtModel", "regoBundle", "k8sManifests", "harnessReport", "signatures"]},
    {"id": "mgkHarnessReport", "fields": ["reportId", "release", "attacksRun", "failures", "categories", "ts", "signers", "signatures"]},
]

# ---------------------- code examples ----------------------
code = [
    {"id": "CE-01", "title": "ISO 42001 Clause 6.1 — Risk register row (JSON)", "lang": "json", "snippet": "{\n  \"riskId\": \"R-AIMS-014\",\n  \"clause\": \"6.1\",\n  \"description\": \"GenAI advisor fiduciary breach\",\n  \"likelihood\": \"M\", \"impact\": \"H\",\n  \"controls\": [\"pre_flight_guardrail\", \"fiduciary_cosine_check\", \"judge_ensemble\"],\n  \"owner\": \"caio\",\n  \"regimeMappings\": [\"EU AI Act Art 14\", \"FCA Consumer Duty\", \"MAS FEAT\"]\n}\n"},
    {"id": "CE-02", "title": "Annex A control catalog entry (YAML)", "lang": "yaml", "snippet": "controlId: A.7.2\ncategory: validation\ntitle: Independent challenge of Tier-1 models\nobjective: Ensure 2LoD effective challenge\nimplementation:\n  - Independent re-implementation\n  - Counterfactual analysis\n  - Champion-challenger\nmappings:\n  euAiAct: [Art 9, Art 15]\n  sr117: [section: effective_challenge]\n  iso42001: [Cl 8.3, Cl 9.1]\n  gdpr:   [Art 22]\nowner: head-of-mrm\n"},
    {"id": "CE-03", "title": "CRS-UUID lineage emitter (Python)", "lang": "python", "snippet": "def emit_lineage(src, dst, edge_type):\n    edge = {\n        'edgeId': uuid7(),\n        'src': src, 'dst': dst,\n        'edgeType': edge_type,\n        'ts': iso_now(),\n        'signer': SIGNER_ID,\n    }\n    edge['signature'] = sign_hybrid(edge)\n    kafka.send('crsLineage.v1', key=edge['src'], value=json.dumps(edge))\n"},
    {"id": "CE-04", "title": "OPA gate — Tier-1 admission (Rego)", "lang": "rego", "snippet": "package admit.tier1\n\ndefault allow = false\n\nallow {\n  input.review.object.metadata.labels.tier == \"t1\"\n  input.review.object.spec.runtimeClassName == \"kata\"\n  input.review.annotations[\"sigstore.dev/verified\"] == \"true\"\n  input.review.annotations[\"pqc.fips204/verified\"] == \"true\"\n  input.review.annotations[\"mgk.injected\"] == \"true\"\n}\n"},
    {"id": "CE-05", "title": "Cognitive Resonance breach handler (Go)", "lang": "go", "snippet": "func OnResonance(report ResonanceReport) error {\n    if report.Breach == \"none\" { return nil }\n    if err := emitSEV(\"sev1\", report); err != nil { return err }\n    if report.Breach == \"fiduciary\" || report.Breach == \"latent\" {\n        return logicalKillSwitch(report.ModelID)\n    }\n    return nil\n}\n"},
    {"id": "CE-06", "title": "SRASE inspection runner (Python)", "lang": "python", "snippet": "def run_srase(pack_id, persona):\n    artifacts = load_pack(pack_id)\n    scores = {}\n    for wf in WORKFLOWS[persona]:\n        scores[wf] = wf.score(artifacts)\n    composite = weighted(scores)\n    report = build_report(pack_id, persona, scores, composite)\n    return sign_pades_sigstore_mldsa(report)\n"},
    {"id": "CE-07", "title": "TLA+ — kill-switch liveness", "lang": "tla", "snippet": "MODULE KillSwitch\nVARIABLES armed, acked\n\nArm == /\\ ~armed /\\ armed' = TRUE\nAck(n) == /\\ armed /\\ acked' = acked \\cup {n}\nLive == []<>(armed => Cardinality(acked) >= QUORUM)\n"},
    {"id": "CE-08", "title": "Coq — invariant I1 reachability", "lang": "coq", "snippet": "Theorem kill_switch_reachable :\n  forall s : state, in_sev0 s -> exists s', step s s' /\\ kill_switch_armed s'.\nProof.\n  intros. apply step_armed_in_sev0. assumption.\nQed.\n"},
    {"id": "CE-09", "title": "Z3 — Rego decidability check", "lang": "python", "snippet": "from z3 import *\nx = Int('x')\ns = Solver()\ns.add(Or(x < 0, x >= 60))\nprint(s.check())  # check that no admit-allowing path bypasses kill-switch SLA\n"},
    {"id": "CE-10", "title": "Policy DSL example (DSL)", "lang": "policy", "snippet": "policy KillSwitchSLA {\n  invariant: kill_switch_latency_p95 <= 60s;\n  obligation: prove(I1, coq);\n  obligation: model(KillSwitch, tla);\n  enforcement: opa(kill_switch_gate);\n  harness: adversarial(10000, kill_switch_race);\n}\n"},
    {"id": "CE-11", "title": "UMIF Operator CRD (YAML)", "lang": "yaml", "snippet": "apiVersion: umif.firm.io/v1\nkind: Policy\nmetadata: { name: kill-switch-sla, tier: t1 }\nspec:\n  invariantRefs: [I1]\n  obligationRefs: [coq/I1, tla/KillSwitch]\n  enforcement: { opa: kill_switch_gate }\n  harness:    { attacks: 10000, suite: kill_switch_race }\n"},
    {"id": "CE-12", "title": "MGK eBPF egress shim (C)", "lang": "c", "snippet": "SEC(\"tc\")\nint mgk_egress(struct __sk_buff *skb) {\n    if (!allowlist_match(skb)) {\n        bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);\n        return TC_ACT_SHOT;\n    }\n    return TC_ACT_OK;\n}\n"},
    {"id": "CE-13", "title": "Automated Sanctions Engine — decision (Python)", "lang": "python", "snippet": "def decide_sanction(input):\n    out = opa_decide('sanctions/v1', input)\n    if out.grade in ('G5','G6'):\n        require_dual_control(out)\n    order = build_order(out)\n    return sign_and_publish(order)\n"},
    {"id": "CE-14", "title": "Global Audit API consumer (TypeScript)", "lang": "typescript", "snippet": "const res = await fetch(`${GA_API}/v1/replay/${envelopeId}`, {\n  headers: { Authorization: `Bearer ${treatyToken}` },\n});\nconst replay = await res.json();\nawait wormEmit('audit.read', { envelopeId, supervisor: 'ECB-SSM', ts: now() });\n"},
    {"id": "CE-15", "title": "GIEN event publisher (Node.js)", "lang": "typescript", "snippet": "export async function gienEmit(evt: GienEvent) {\n  evt.sig = await signHybrid(evt);\n  await gienClient.send({ topic: evt.type, messages: [{ key: evt.scope, value: JSON.stringify(evt) }] });\n  await wormEmit('gien.out', { id: evt.id });\n}\n"},
    {"id": "CE-16", "title": "PCR/PCO repair driver (Python)", "lang": "python", "snippet": "def repair(policy, invariants):\n    issues = check(policy, invariants)\n    if not issues: return policy\n    suggestions = smt_synthesize(policy, issues)\n    refactored  = llm_safe_refactor(policy, suggestions)\n    proof = prove_or_harness(refactored, invariants)\n    return sign_repair_envelope(policy, refactored, proof)\n"},
]

# ---------------------- case studies ----------------------
cases = [
    {"id": "CS-01", "name": "ISO 42001 Stage 2 audit — G-SIB", "outcomes": "0 major NCs; 3 minor; Cert score Gold; AIMS Manual + Annex A fully evidenced"},
    {"id": "CS-02", "name": "MRM platform rollout for Tier-1 trading + credit", "outcomes": "200 models in CRS-UUID lineage; replay byte-identical ≥ 99.9 %; Cognitive Resonance breaches 0 unmitigated in 90 d"},
    {"id": "CS-03", "name": "SRASE pre-flight before AISI inspection", "outcomes": "Composite 0.94; 6 gaps auto-CAPA closed pre-submission; AISI inspection passed"},
    {"id": "CS-04", "name": "Sentinel AGI Lab — deceptive-alignment indicator", "outcomes": "Indicator detected within 12 h; air-gap containment + AISI joint review; published anonymised report via GAID"},
    {"id": "CS-05", "name": "Treaty obligation onboarding (GIEN + Global Audit API)", "outcomes": "12 supervisor consumers onboarded; 100 % obligation attestations green for 4 quarters"},
    {"id": "CS-06", "name": "MGK adversarial break harness", "outcomes": "12 500 attacks/release; 0 failures on RC3; v1 promoted to Tier-1 production"},
]

# ---------------------- KPIs (24) ----------------------
kpis = [
    {"id": "KPI-01", "name": "ISO 42001 major NCs", "target": "0"},
    {"id": "KPI-02", "name": "Annex A control evidence completeness", "target": "≥ 98 %"},
    {"id": "KPI-03", "name": "Model Risk Policy adherence (T1 audits)", "target": "100 %"},
    {"id": "KPI-04", "name": "Effective challenge coverage T1", "target": "100 % annually"},
    {"id": "KPI-05", "name": "CRS-UUID lineage coverage", "target": "≥ 99 % artifacts"},
    {"id": "KPI-06", "name": "Deterministic replay byte-identical", "target": "≥ 99.9 %"},
    {"id": "KPI-07", "name": "Cognitive Resonance Δ_drift", "target": "≤ 4 %"},
    {"id": "KPI-08", "name": "SEV-0 logical kill-switch p95", "target": "≤ 60 s"},
    {"id": "KPI-09", "name": "SEV-0 physical kill (BMC)", "target": "≤ 5 min"},
    {"id": "KPI-10", "name": "Annex IV pack assembly", "target": "≤ 30 min"},
    {"id": "KPI-11", "name": "SR 11-7 pack errors", "target": "0 critical"},
    {"id": "KPI-12", "name": "SRASE composite score", "target": "≥ 0.9 sustained"},
    {"id": "KPI-13", "name": "Red-team coverage Tier-1", "target": "≥ 95 % quarterly"},
    {"id": "KPI-14", "name": "Judge-LLM agreement κ", "target": "≥ 0.90"},
    {"id": "KPI-15", "name": "Sigstore + ML-DSA-44 coverage T1", "target": "100 %"},
    {"id": "KPI-16", "name": "Daily Merkle anchor verify", "target": "100 %"},
    {"id": "KPI-17", "name": "MGK formal proof coverage", "target": "≥ 95 % safety-critical"},
    {"id": "KPI-18", "name": "MGK break-harness failures per release", "target": "0"},
    {"id": "KPI-19", "name": "Treaty obligation attestations green", "target": "100 % monthly"},
    {"id": "KPI-20", "name": "Cert score level", "target": "Gold by 2027; Platinum by 2029"},
    {"id": "KPI-21", "name": "Public verifier uptime", "target": "≥ 99.95 %"},
    {"id": "KPI-22", "name": "Global Audit API supervisor satisfaction", "target": "≥ 4.5/5"},
    {"id": "KPI-23", "name": "Constitutional principle conformance", "target": "100 % articles attested"},
    {"id": "KPI-24", "name": "Board AI literacy", "target": "≥ 90 % by 2027; 95 % by 2030"},
]

# ---------------------- risk and control matrix ----------------------
riskControlMatrix = [
    {"id": "RC-01", "threat": "AIMS Cl 6.1 risk register incomplete", "controls": ["Mandatory CRD-backed register", "Quarterly internal audit"], "kpis": ["KPI-02"]},
    {"id": "RC-02", "threat": "Tier misclassification of high-impact model", "controls": ["Independent MRM tiering", "Effective challenge"], "kpis": ["KPI-03", "KPI-04"]},
    {"id": "RC-03", "threat": "CRS-UUID lineage gap", "controls": ["Sidecar auto-emit", "WORM verifier audit"], "kpis": ["KPI-05"]},
    {"id": "RC-04", "threat": "Replay non-determinism", "controls": ["Frozen kernels", "Seed envelope", "Replay engine SLO"], "kpis": ["KPI-06"]},
    {"id": "RC-05", "threat": "Cognitive Resonance unmitigated breach", "controls": ["Auto kill-switch", "SEV-1 escalation"], "kpis": ["KPI-07", "KPI-08"]},
    {"id": "RC-06", "threat": "Annex IV pack assembly miss SLA", "controls": ["Pre-built section mapper", "SRASE pre-flight"], "kpis": ["KPI-10", "KPI-12"]},
    {"id": "RC-07", "threat": "Frontier deceptive alignment", "controls": ["Sentinel AGI Lab", "ASI honeypot", "AISI inspection"], "kpis": ["KPI-13"]},
    {"id": "RC-08", "threat": "Treaty obligation breach", "controls": ["GIEN feeds", "Global Audit API", "Cert score gate"], "kpis": ["KPI-19", "KPI-20"]},
    {"id": "RC-09", "threat": "MGK regression in release", "controls": ["≥ 10 000 attack harness", "Proof coverage gate"], "kpis": ["KPI-17", "KPI-18"]},
    {"id": "RC-10", "threat": "Public verifier downtime", "controls": ["Multi-region active-active", "IPFS mirroring"], "kpis": ["KPI-21"]},
    {"id": "RC-11", "threat": "Sanction misapplication", "controls": ["Dual-control on G5/G6", "Appeal route + tribunal"], "kpis": ["KPI-22"]},
    {"id": "RC-12", "threat": "Constitutional article drift", "controls": ["Codex review semi-annual", "2/3 amendment threshold"], "kpis": ["KPI-23"]},
]

# ---------------------- traceability ----------------------
traceability = [
    {"feature": "M1 AIMS Manual Cl 4-10", "control": "Annex A controls + clause-mapped catalog", "regimes": ["ISO 42001 Cl 4-10", "EU AI Act Annex IV", "NIST RMF Govern"]},
    {"feature": "M2 Model Risk Policy", "control": "Tiering + validation + effective challenge", "regimes": ["SR 11-7", "PRA SS1/23", "MAS FEAT", "HKMA GL-90"]},
    {"feature": "M3 MRM Platform (Terraform+K8s+Kafka+OPA+WORM+Replay)", "control": "Signed envelopes + CRS-UUID lineage + replay", "regimes": ["EU AI Act Art 12", "DORA", "GDPR Art 32"]},
    {"feature": "M4 SRASE", "control": "Pre-flight regulator simulation", "regimes": ["EU AI Act Art 73", "SR 11-7 supervisory exam"]},
    {"feature": "M5 Sentinel AGI Lab + Red-Team", "control": "Air-gap + AISI + 95 % attack coverage", "regimes": ["EU AI Act Art 55", "NIST GAI Profile"]},
    {"feature": "M6 Treaty 2026-2035", "control": "Framework + Annexes + Protocols + Dispute Resolution", "regimes": ["Council of Europe AI Convention", "G7 Hiroshima", "OECD"]},
    {"feature": "M7 Global Audit API + Cert + GIEN", "control": "Treaty-mandated read endpoints + scoring + telemetry", "regimes": ["Treaty Annex T-1", "FSB AI"]},
    {"feature": "M8 Auto Sanctions + Constitution + Codex", "control": "OPA + dual-control + appeal", "regimes": ["Treaty Annex T-3", "Constitution Arts 1-7"]},
    {"feature": "M9 Transparency Portal + Cultural Resonance + CSE-X", "control": "Verifier + multilingual + scenarios", "regimes": ["EU AI Act Art 50", "ISO 42001 Cl 7.4"]},
    {"feature": "M10 Invariance + Meta-Invariance", "control": "Coq + TLA+ + Z3 + OPA", "regimes": ["NIST RMF Manage", "Constitution Art 2"]},
    {"feature": "M11 Epistemic + Ontological + Existential + Value", "control": "Alignment systems + GIEN drills", "regimes": ["UNESCO AI Ethics", "OECD AI Principles"]},
    {"feature": "M12 UMIF + Self-Proving + Policy DSL", "control": "Compositional refinement L1→L4 + PCR/PCO", "regimes": ["ISO 42001 Cl 10", "Constitution Art 3"]},
    {"feature": "M13 MGK + Adversarial Break Harness", "control": "Minimal verified kernel + 10 000 attacks", "regimes": ["EU AI Act Art 15", "SLSA L3+", "FIPS 204"]},
    {"feature": "M14 Operating Model + Evidence Pack", "control": "Per-lane lineage + auto pack ≤ 45 min", "regimes": ["ISO 42001", "EU AI Act Annex IV", "SR 11-7", "Treaty"]},
]

# ---------------------- data flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "AIMS Cl 9 → MR → Improvement", "steps": ["KPI tile feed", "internal audit", "management review", "CAPA", "Cl 10 closure"], "controls": ["WORM evidence", "Signed minutes"]},
    {"id": "DF-02", "name": "Model lifecycle → CRS-UUID → Replay", "steps": ["dataset register", "model build", "validation", "deploy", "decision envelope", "WORM emit", "auditor replay"], "controls": ["Sigstore", "ML-DSA-44", "deterministic seed"]},
    {"id": "DF-03", "name": "SRASE pre-flight → real submission", "steps": ["assemble pack", "SRASE personas", "composite score", "CAPA", "real regulator submit"], "controls": ["≥ 0.9 gate", "Signed pack"]},
    {"id": "DF-04", "name": "Sentinel Lab → AISI joint review", "steps": ["experiment", "indicators", "containment", "anonymise", "GAID submit", "AISI review"], "controls": ["Air-gap", "Dual-control", "GAID format"]},
    {"id": "DF-05", "name": "GIEN streaming + Global Audit API", "steps": ["firm emit GIEN", "supervisor subscribe", "audit-api read", "WORM receipt"], "controls": ["mTLS", "zk-SNARK", "ML-DSA-65"]},
    {"id": "DF-06", "name": "UMIF policy → MGK runtime", "steps": ["DSL author", "compile coq+tla+z3+rego+k8s", "harness 10 000 attacks", "MGK enforce", "WORM emit"], "controls": ["Proof coverage ≥ 0.95", "Break harness 0 failures"]},
]

# ---------------------- regulators ----------------------
regulators = [
    {"id": "REG-01", "name": "EU Commission AI Office + AISI EU", "primary": "EU AI Act lead + safety institute"},
    {"id": "REG-02", "name": "ECB-SSM + EBA + ESMA", "primary": "EU prudential + securities"},
    {"id": "REG-03", "name": "PRA + Bank of England", "primary": "UK prudential"},
    {"id": "REG-04", "name": "FCA", "primary": "UK conduct + Consumer Duty + SMCR"},
    {"id": "REG-05", "name": "FRB + OCC + FDIC", "primary": "US prudential"},
    {"id": "REG-06", "name": "SEC + CFTC", "primary": "US markets"},
    {"id": "REG-07", "name": "MAS", "primary": "Singapore"},
    {"id": "REG-08", "name": "HKMA + SFC", "primary": "Hong Kong"},
    {"id": "REG-09", "name": "BoJ + FSA Japan", "primary": "Japan"},
    {"id": "REG-10", "name": "ISO/IEC JTC 1/SC 42", "primary": "AI standards"},
    {"id": "REG-11", "name": "ISO 42001 certification body", "primary": "AIMS certification"},
    {"id": "REG-12", "name": "Treaty Secretariat + UN + BIS + OECD + AISI", "primary": "Global treaty + civilizational"},
]

# ---------------------- workshops ----------------------
workshops = [
    {"id": "WS-01", "audience": "Board AI/Risk Cmte", "duration": "2 h", "outcome": "ISO 42001 management review + Cert score sign-off + Codex ratification"},
    {"id": "WS-02", "audience": "C-Suite + SMFs", "duration": "1 d", "outcome": "Operating Model walkthrough + SMCR statements"},
    {"id": "WS-03", "audience": "MRM + AI Risk + 2LoD", "duration": "2 d", "outcome": "Model Risk Policy + MRM platform bootcamp"},
    {"id": "WS-04", "audience": "Platform + EA + Security", "duration": "2 d", "outcome": "MRM platform + MGK + UMIF rollout"},
    {"id": "WS-05", "audience": "SOC + IR + AI Safety", "duration": "1 d", "outcome": "Sentinel AGI Lab + SRASE drill"},
    {"id": "WS-06", "audience": "Internal Audit (3LoD)", "duration": "1 d", "outcome": "Annex A controls + replay + harness inspection"},
    {"id": "WS-07", "audience": "Treaty Liaison + Supervisor + AISI", "duration": "1 d", "outcome": "GIEN + Global Audit API + Cert + sanctions walkthrough"},
]

# ---------------------- privacy ----------------------
privacy = {
    "lawfulBasis": ["Legal obligation (Art 6(1)(c))", "Legitimate interest (Art 6(1)(f))", "Contract (Art 6(1)(b))"],
    "subjectRights": ["DSAR portal", "Art 17 erasure via machine unlearning", "Art 22 contestation + meaningful info"],
    "dataMinimization": ["eBPF redaction", "FL secure aggregation", "RAG ACL", "pseudonymous WORM", "zk-SNARK auditor access"],
    "transfers": "Per-jurisdiction residency; SCCs + supplementary measures; per-region keys; treaty mutual recognition for supervisor reads",
    "dpia": "Mandatory for high-risk (credit, trading, fraud, AML, fiduciary, frontier eval)",
    "securityControls": ["zero-trust mTLS", "FIPS 204 PQC", "FIPS 140-3 L4 HSM", "WORM Object Lock", "SLSA L3+", "Kata confidential", "MGK runtime"],
}

# ---------------------- deployment ----------------------
deployment = [
    "Multi-region active-active EU primary; DR with RPO ≤ 1 h, RTO ≤ 4 h",
    "Kata Containers for Tier-1 + AMD SEV-SNP / Intel TDX where available",
    "Cilium L7 zero-egress; allow-listed egress-broker for GIEN + Global Audit API",
    "OPA Gatekeeper enforcing signed images (cosign + ML-DSA-44) + Kata for T1 + MGK injection",
    "Kafka WORM cluster with SASL/SCRAM + mTLS ACLs + Object Lock + daily Merkle anchor + PQC envelope",
    "FIPS 140-3 L4 HSM with PQC firmware; 90-day key rotation",
    "BMC/IPMI segmentation; Redfish event subscription to SOC + WORM",
    "GitHub Actions OIDC + Sigstore keyless + ML-DSA-44 hybrid + SLSA L3+ provenance",
    "Terraform golden modules signed (Sigstore); mandatory tags (owner, tier, dataClass, regime, crsUuid)",
    "OpenTelemetry GenAI tracing + Falco eBPF rules + Trivy + kube-bench",
    "Quarterly chaos drills: kill-switch, KMS outage, region failover, partition, ASI honeypot, hotline",
    "Public verifier endpoints (zk-SNARK) for civil society + press",
    "MGK runtime DaemonSet + per-pod sidecar; Tier-1 fail-closed",
    "UMIF Operator + CRDs (Policy, Invariant, Obligation, AlignmentChannel)",
    "Sentinel AGI Containment Lab air-gapped enclave with dedicated WORM bucket",
]

# ---------------------- 30/60/90 rollout (compact) ----------------------
rollout90 = [
    {"day": "0-30", "track": "AIMS + MRM Foundations", "items": ["ISO 42001 Manual Cl 4-10 baseline", "Annex A control catalog v1", "Model Risk Policy v3 board-approved", "CRS-UUID lineage producer GA", "WORM cluster + daily anchor"]},
    {"day": "31-60", "track": "Containment + SRASE + UMIF", "items": ["Sentinel AGI Lab live", "SRASE GA + composite ≥ 0.9", "Red-team CI gate (Judge LLM)", "UMIF Operator + Policy DSL v1", "MGK v1 deployed Tier-1"]},
    {"day": "61-90", "track": "Civilizational + Treaty + Cert", "items": ["GIEN ingress/egress live", "Global Audit API consumer onboarded", "Public Transparency Portal v1", "Cert score Silver", "Codex v0.9 draft + Constitution adoption attestation"]},
]

# ---------------------- multi-year roadmap ----------------------
roadmap = [
    {"year": "2026", "focus": "AIMS + MRM + Sentinel Lab + SRASE + MGK v1", "milestones": ["ISO 42001 Stage 2 pass", "Model Risk Policy v3", "SRASE composite ≥ 0.9 sustained", "MGK v1 Tier-1 production", "Cert score Silver"]},
    {"year": "2027", "focus": "UMIF GA + Treaty Onboarding", "milestones": ["UMIF Operator GA", "GIEN live across Tier-1", "Global Audit API onboarded", "Cert score Gold", "Invariance + Meta-Invariance proofs published"]},
    {"year": "2028", "focus": "Civilizational Codex + Transparency v2", "milestones": ["Treaty obligations fully met", "Codex v1 ratified", "Transparency Portal v2 (zk-SNARK)", "CSE-X scenario library v1", "Cultural Resonance Archive integrated"]},
    {"year": "2029", "focus": "Civilizational Steady-State", "milestones": ["Cert Platinum", "MGK formal proof coverage ≥ 0.97", "Existential Coordination drills with 5+ signatories", "Public verifier uptime 99.95 %"]},
    {"year": "2030", "focus": "Treaty Maturity + Constitutional Review", "milestones": ["Treaty near-universal accession", "Constitutional review conference contribution", "CSE-X 50-yr horizon scenarios", "Board literacy ≥ 95 %"]},
]

# ---------------------- evidence pack template ----------------------
evidencePack = {
    "id": "EVP-WP-048",
    "sections": [
        "AIMS Manual + Annex A evidence",
        "Model Risk Policy + signed validation reports",
        "MRM platform attestations (Terraform + K8s + Kafka + OPA + WORM)",
        "CRS-UUID lineage extract",
        "Cognitive Resonance log",
        "SRASE composite reports",
        "Sentinel Lab + red-team summary (anonymised)",
        "MGK harness + proofs",
        "Cert score + Global Audit API receipts",
        "Treaty obligation attestations",
        "Constitutional principle conformance attestation",
    ],
    "audiences": ["ISO 42001 auditor", "EU AI Act notified body", "SR 11-7 examiner", "AISI inspector", "Treaty secretariat", "Board", "Civil society (redacted)"],
    "format": "PDF/A + JSON bundle",
    "signing": "PAdES + Sigstore + ML-DSA-65",
    "anchor": "WORM daily Merkle + zk-SNARK proof to public verifier",
    "sla": "≤ 45 min assembly",
}

# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": (
        "Deliver comprehensive, expert-level guidance on designing and "
        "implementing an integrated Enterprise AI Governance, Risk, and "
        "Compliance stack for G-SIFI / Fortune 500 financial institutions "
        "(2026-2030), spanning ISO/IEC 42001 AIMS Manual, audit-defensible "
        "Model Risk Policy + MRM platform, AGI containment stack (SRASE + "
        "Sentinel AGI Containment Lab + red-team), and global civilizational "
        "AI governance (treaty 2026-2035, Global Audit API, Cert Scoring, "
        "GIEN, Auto Sanctions, Constitution, Codex, Transparency Portal, "
        "Cultural Resonance Archive, CSE-X, Invariance + Meta-Invariance + "
        "Epistemic + Ontological + Existential + Value alignment, UMIF, "
        "Self-Proving Systems + Policy DSL with Coq/TLA+/Z3/OPA + PCR/PCO "
        "repair, and the Minimal Governance Kernel with ≥ 10 000-attack "
        "adversarial break harness)."
    ),
    "approach": (
        "14-module reference with machine-parsable directive, signed via "
        "Sigstore + ML-DSA-44/65 hybrid, enforced by OPA Gatekeeper + "
        "Cilium + MGK runtime, observed by Sentinel + eBPF + Cognitive "
        "Resonance, verified by Coq + TLA+ + Z3 (UMIF), audited by 3LoD + "
        "SRASE + Global Audit API, and operationalised through MVAGS at "
        "Day-90 extending to a 5-year roadmap with auto-assembled evidence "
        "pack ≤ 45 min for any regulator/auditor."
    ),
    "deliverables": (
        "14 modules · 70 sections · 12 schemas · 16 code examples · 6 case "
        "studies · 24 supervisory KPIs · 12 risk-control rows · 12 "
        "regulators · 7 workshops · 6 data flows · 14 traceability rows · "
        "3-phase 30/60/90 · 5-year roadmap · machine-parsable <directive> "
        "block · evidence-pack template · ISO 42001 Cl 4-10 manual · "
        "Annex A control catalog · Model Risk Policy · UMIF + Self-Proving "
        "Systems + Policy DSL + MGK + adversarial break harness."
    ),
    "outcomes": [
        "ISO 42001 Stage 2 audit passed with 0 major NCs",
        "MGK in production for all Tier-1 with ≥ 95 % proof coverage and 0 harness failures",
        "SEV-0 logical kill-switch p95 ≤ 60 s; physical (BMC) ≤ 5 min",
        "Annex IV / SR 11-7 pack assembly ≤ 30 min; evidence pack ≤ 45 min",
        "SRASE composite ≥ 0.9 sustained before any real regulator submission",
        "Cognitive Resonance Δ_drift ≤ 4 % + latent drift ≤ 3 % + cosine ≥ 0.92",
        "Cert score Gold by 2027 and Platinum by 2029",
        "Treaty obligations 100 % attested monthly; Global Audit API live; GIEN integrated",
        "MGK adversarial break harness ≥ 10 000 attacks / release with 0 failures",
    ],
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
DOC["rollout90"] = rollout90
DOC["roadmap"] = roadmap
DOC["evidencePack"] = evidencePack
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
    "rolloutPhases": len(rollout90),
    "roadmapYears": len(roadmap),
    "apiRoutes": 100,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
print("counts:", DOC["counts"])
