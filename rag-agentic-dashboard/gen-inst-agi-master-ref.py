#!/usr/bin/env python3
"""WP-047 — Institutional-Grade AGI/ASI & Enterprise AI Governance Master Reference.

Builds data/inst-agi-master-ref.json: a comprehensive, implementation-focused
master reference (2026-2030) on institutional-grade AGI/ASI and enterprise AI
governance for Fortune 500, Global 2000, and G-SIFIs.

Covers: multilayered governance pillars and roles; alignment with EU AI Act
2026, NIST AI RMF 1.0, ISO/IEC 42001, OECD AI Principles, GDPR, FCRA/ECOA,
Basel III, SR 11-7, PRA, FCA, MAS, HKMA, SMCR, Consumer Duty, US EO 14110;
enterprise reference architectures (Kafka WORM + ACL, Docker Swarm, Node.js
and Python sidecars, Next.js explainability, OPA, Terraform/CI/CD);
sector-specific MRM (credit, trading, risk, fiduciary, CRS-UUID-001); frontier
AGI/ASI safety (Sentinel v2.4, WorkflowAI Pro, Cognitive Resonance, crisis
simulations, Minimum Viable AGI Governance); global AI/compute governance
(ICGC, GACRA, GASO, GFMCF, GAICS, GAIVS, GACP, GATI, GACMO, FTEWS, GAI-SOC,
GAIGA, GACRLS, GFCO, GAID, GASCF); the Enterprise AI Governance Hub, AI
Safety Report Generator, WorkflowAI Pro (prompt mgmt, RBAC, audit, tracing,
PDF export, Firestore versioning, DAG visualization); the advanced prompt
engineering guide; the civilizational corpus (Constitution, Covenant Codex,
Renewal Atlas, Continuity Codex, Closing Charge, Kill-Switch Validation,
Systemic Risk Sim Playbook, Interop Treaty, Operating Model, Pilot Roadmap,
Coalition Activation, Institutional Adoption); regulator-ready report
sections with <title>/<abstract>/<content> tags; enterprise implementation
blueprints (CI/CD policy gates, K8s/Kafka/OPA stacks, Terraform golden
environments, PQC WORM, zk-SNARK access, OPA/Rego, deterministic replay,
drift analysis, red teaming, Cognitive Resonance, IR checklists); tiered
(T1-T3) rollout; 30/60/90-day plan; and a 2026-2030 multi-year roadmap with
machine-readable artifacts for engineering, legal, C-suite, board, regulator,
enterprise architecture, AI platform engineering, and AI safety research.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "inst-agi-master-ref.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "INST-AGI-MASTER-REF-WP-047",
    "version": "1.0.0",
    "horizon": "2026-2030",
    "classification": (
        "CONFIDENTIAL — Board / CEO / CRO / CISO / CAIO / GC / DPO / Head of "
        "Internal Audit / Head of MRM / AI Safety Lead / Enterprise "
        "Architecture / AI Platform Engineering / Prudential Supervisor / "
        "AI Safety Institute / Treaty Liaison"
    ),
    "title": (
        "Institutional-Grade AGI/ASI & Enterprise AI Governance Master "
        "Reference — Fortune 500 / Global 2000 / G-SIFI (2026-2030)"
    ),
    "subtitle": (
        "Multilayered governance pillars + regulatory alignment (EU AI Act / "
        "NIST AI RMF / ISO 42001 / OECD / GDPR / FCRA/ECOA / Basel III / "
        "SR 11-7 / PRA / FCA / MAS / HKMA / SMCR / Consumer Duty / EO 14110); "
        "enterprise reference architectures (Kafka WORM + ACL, Docker Swarm, "
        "Node.js/Python sidecars, Next.js explainability, OPA, Terraform / "
        "CI/CD); sector MRM (credit, trading, fiduciary, CRS-UUID-001); "
        "frontier AGI/ASI safety (Sentinel v2.4, WorkflowAI Pro, Cognitive "
        "Resonance, crisis sims, MVAGS); global AI/compute governance (ICGC, "
        "GACRA, GASO, GFMCF, GAICS, GAIVS, GACP, GATI, GACMO, FTEWS, GAI-SOC, "
        "GAIGA, GACRLS, GFCO, GAID, GASCF); Enterprise AI Governance Hub + AI "
        "Safety Report Generator + WorkflowAI Pro; advanced prompt engineering; "
        "civilizational corpus; regulator-ready report sections; CI/CD policy "
        "gates + K8s/Kafka/OPA + Terraform golden envs + PQC WORM + zk-SNARK "
        "+ deterministic replay + red teaming + Cognitive Resonance + IR; "
        "tiered T1-T3 rollout + 30/60/90 + 2026-2030 roadmap"
    ),
    "owner": (
        "CAIO + CRO + CISO + Chief Enterprise Architect; co-signed by CEO, "
        "GC, DPO, Head of Internal Audit, Head of Compliance, Head of Model "
        "Risk Management, Head of AI Platform Engineering, AI Safety Lead, "
        "Treaty Liaison, Head of SOC, Head of Trading Risk, Head of Credit "
        "Risk, Board AI/Risk Committee Chair"
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
    ],
    "regimes": [
        "EU AI Act 2026 (Arts 5/9/10/13/14/15/16/26/50/53/55/56/72 + Annex IV)",
        "NIST AI RMF 1.0 + Generative AI Profile",
        "ISO/IEC 42001 (AIMS) + 23894 + 5338 + 38507 + 27001 + 27701",
        "OECD AI Principles 2024",
        "GDPR Arts 5/6/17/22/25/32/35",
        "FCRA §615(a) + ECOA Reg B (US fair-lending)",
        "Basel III/IV (BCBS 239 + Pillar 2 AI capital buffer)",
        "SR 11-7 + OCC 2011-12",
        "PRA SS1/23 + SS2/21",
        "FCA Consumer Duty + SYSC + SMCR",
        "MAS FEAT + AI Verify + TRMG",
        "HKMA SPM GS-1 / GL-90",
        "EU DORA",
        "US EO 14110 + OMB M-24-10",
        "G7 Hiroshima AI Process + Bletchley + Seoul declarations",
        "Council of Europe AI Convention",
        "FSB AI in financial services",
        "OWASP LLM Top 10 (2025) + MITRE ATLAS",
        "NIST FIPS 204 (ML-DSA) + FIPS 203 (ML-KEM)",
        "SLSA L3+ + Sigstore + in-toto",
        "CIS Kubernetes Benchmark + NSA/CISA Hardening Guide",
    ],
    "apiPrefix": "/api/inst-agi-master-ref",
}

# ---------------------- machine-parsable directive ----------------------
DOC["directive"] = {
    "format": "machine-parsable XML-style block consumed by sidecars, CI gates, OPA Gatekeeper, regulator-pack generators, and Enterprise AI Governance Hub",
    "raw": (
        "<directive id=\"INST-AGI-MASTER-REF-WP-047\" version=\"1.0.0\" "
        "horizon=\"2026-2030\" jurisdiction=\"F500,G2000,G-SIFI,EU-primary\">"
        "<scope>Enterprise|Frontier|ASI-Precursor|Sectoral-Credit|Sectoral-Trading|Fiduciary</scope>"
        "<modules>14</modules>"
        "<pillars>Strategy|Risk|Controls|Assurance|Transparency|Oversight|Continuity</pillars>"
        "<thresholds piiLeakage=\"0.0001\" sev0KillSwitchSeconds=\"60\" "
        "sev1Hours=\"4\" sev2Hours=\"24\" sev3Days=\"3\" "
        "fiduciaryCosineMin=\"0.92\" cognitiveResonanceDriftMax=\"0.04\" "
        "latentDriftMax=\"0.03\" judgeLLMAgreementMin=\"0.9\" "
        "redTeamCoverageT1=\"0.95\" annexIVAssemblyMinutes=\"30\" "
        "gradientAnomalyZ=\"3.5\" honeypotEngagementSeconds=\"10\"/>"
        "<reports><report id=\"R1\">Navigating the Complexities of AI Safety and Global Governance</report>"
        "<report id=\"R2\">Technical Strategies for AI Alignment</report>"
        "<report id=\"R3\">Key AI Safety Challenges</report>"
        "<report id=\"R4\">Navigating the AI Safety Landscape</report></reports>"
        "<signing pq=\"ML-DSA-44+ML-DSA-65\" classical=\"Ed25519\" "
        "supplyChain=\"Sigstore+SLSA-L3+\" worm=\"Kafka+ObjectLock+MerkleAnchor+PQC\"/>"
        "<consortia>ICGC|GACRA|GASO|GFMCF|GAICS|GAIVS|GACP|GATI|GACMO|FTEWS|GAI-SOC|GAIGA|GACRLS|GFCO|GAID|GASCF</consortia>"
        "<containment bmcKillSwitch=\"true\" zeroEgress=\"true\" "
        "kataConfidential=\"true\" cognitiveResonance=\"true\" mvags=\"true\"/>"
        "</directive>"
    ),
    "parsed": {
        "id": "INST-AGI-MASTER-REF-WP-047",
        "scope": [
            "Enterprise", "Frontier", "ASI-Precursor",
            "Sectoral-Credit", "Sectoral-Trading", "Fiduciary",
        ],
        "pillars": ["Strategy", "Risk", "Controls", "Assurance", "Transparency", "Oversight", "Continuity"],
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
            "redTeamCoverageT1": 0.95,
            "annexIVAssemblyMinutes": 30,
            "gradientAnomalyZ": 3.5,
            "honeypotEngagementSeconds": 10,
        },
        "reports": [
            {"id": "R1", "title": "Navigating the Complexities of AI Safety and Global Governance"},
            {"id": "R2", "title": "Technical Strategies for AI Alignment"},
            {"id": "R3", "title": "Key AI Safety Challenges"},
            {"id": "R4", "title": "Navigating the AI Safety Landscape"},
        ],
        "signing": {
            "pq": ["ML-DSA-44", "ML-DSA-65"],
            "classical": ["Ed25519"],
            "supplyChain": ["Sigstore", "SLSA-L3+"],
            "worm": ["Kafka", "ObjectLock", "MerkleAnchor", "PQC"],
        },
        "consortia": [
            "ICGC", "GACRA", "GASO", "GFMCF", "GAICS", "GAIVS",
            "GACP", "GATI", "GACMO", "FTEWS", "GAI-SOC", "GAIGA",
            "GACRLS", "GFCO", "GAID", "GASCF",
        ],
        "containment": {
            "bmcKillSwitch": True,
            "zeroEgress": True,
            "kataConfidential": True,
            "cognitiveResonance": True,
            "mvags": True,
        },
    },
    "consumers": [
        "Enterprise AI Governance Hub policy loader",
        "WorkflowAI Pro prompt registry / DAG runner",
        "AI Safety Report Generator (R1..R4 builder)",
        "GitHub Actions admission gate",
        "OPA Gatekeeper constraint loader",
        "Sentinel v2.4 sidecar policy engine",
        "Annex IV / SR 11-7 pack generator",
        "Board AI/Risk Committee dashboard",
        "Regulator supervisor-gateway feed",
    ],
}

# ---------------------- 14 modules ----------------------
modules = []

# --- M1 — Multilayered Governance Pillars + Roles + Incident Escalation ---
modules.append({
    "id": "M1",
    "title": "M1 — Multilayered Governance Pillars, Roles & Incident Escalation",
    "summary": (
        "Seven-pillar governance model (Strategy, Risk, Controls, Assurance, "
        "Transparency, Oversight, Continuity) mapped to the three lines of "
        "defence, with role charters, decision rights, RACI, and SEV-0..SEV-3 "
        "escalation through Board AI/Risk Committee to regulator and AISI."
    ),
    "covers": ["7 pillars", "3LoD", "RACI", "Board AI/Risk Cmte", "SEV matrix", "AISI"],
    "sections": [
        section("M1-S1", "Seven Pillars", {
            "Strategy": "AI ambition, risk appetite, capital and compute budget; signed annually by Board",
            "Risk": "AI risk taxonomy (model, fairness, security, operational, conduct, systemic, frontier)",
            "Controls": "Sentinel v2.4 + OPA + WORM + Cognitive Resonance + kill-switch",
            "Assurance": "1LoD owner test → 2LoD MRM/MR/Compliance → 3LoD Internal Audit + external assurance",
            "Transparency": "Customer disclosures (Art 13), regulator packs (Annex IV / SR 11-7), public verifier",
            "Oversight": "Human-in-the-loop (Art 14), CAIO veto, swarm consensus for frontier",
            "Continuity": "DR/BCP for AI services; kill-switch drills; safe-failure modes",
        }),
        section("M1-S2", "Role Charters (RACI)", {
            "Board AI/Risk Cmte": "Accountable: AI risk appetite, frontier authorisations",
            "CEO": "Accountable: enterprise strategy, regulator relationships",
            "CAIO": "Responsible: AI strategy + safety + portfolio + WorkflowAI Pro",
            "CRO": "Responsible: AI risk integration with ERM, capital",
            "CISO": "Responsible: AI security, Sentinel, kill-switch, PQC",
            "GC + DPO": "Responsible: legal + GDPR + customer rights",
            "Head of MRM": "Responsible: model inventory, validation, effective challenge",
            "AI Safety Lead": "Responsible: frontier safety, red team, Cognitive Resonance",
            "Head of Internal Audit": "Responsible: 3LoD assurance + replay inspection",
            "SMF-Senior Manager (SMCR)": "Responsible: senior accountability under SMCR + Consumer Duty",
        }),
        section("M1-S3", "SEV Matrix & Escalation", {
            "SEV-0": "ASI-precursor / containment failure / kill-switch armed",
            "SEV-1": "Material model risk: market loss > $50M or major regulatory breach",
            "SEV-2": "Material drift / fairness regression / partial outage",
            "SEV-3": "Quality regression / minor PII near-miss",
            "Escalation": "On-call → AI Safety Lead → CAIO/CRO/CISO → CEO → Board → Regulator + AISI",
        }),
        section("M1-S4", "Decision Rights", {
            "Tier-1 model deploy": "Board AI/Risk Cmte approval + AI Safety Lead sign-off",
            "Frontier eval": "CAIO + AISI inspector + swarm consensus 3-of-5",
            "Kill-switch arm": "Multisig 3-of-5 (CAIO, CISO, CRO, AI Safety Lead, GC)",
            "Customer-facing rollout": "CCO + GC + DPO + Head of Compliance (SMCR-named SMF)",
        }),
        section("M1-S5", "Pillar → Regime Mapping", {
            "Strategy": ["ISO 42001 Cl 5", "EU AI Act Art 9 RMS"],
            "Risk": ["NIST AI RMF Govern + Map", "SR 11-7", "PRA SS1/23"],
            "Controls": ["EU AI Act Arts 9-15", "ISO 27001", "DORA"],
            "Assurance": ["SR 11-7 effective challenge", "ISO 42001 Cl 9"],
            "Transparency": ["EU AI Act Arts 13/26/50", "FCA Consumer Duty"],
            "Oversight": ["EU AI Act Art 14", "GDPR Art 22"],
            "Continuity": ["DORA", "Basel BCP", "MAS TRMG"],
        }),
    ],
})

# --- M2 — Regulatory Alignment ---
modules.append({
    "id": "M2",
    "title": "M2 — Regulatory Alignment (EU AI Act, NIST RMF, ISO 42001, OECD, GDPR, FCRA/ECOA, Basel III, SR 11-7, PRA, FCA, MAS, HKMA, SMCR, Consumer Duty, EO 14110)",
    "summary": (
        "Article-level crosswalk and obligations matrix across EU, US, UK, "
        "and APAC regimes, with evidence types, owner, cadence, and "
        "automated pack mapping."
    ),
    "covers": ["EU AI Act", "NIST AI RMF", "ISO 42001", "GDPR", "FCRA/ECOA", "Basel", "SR 11-7", "PRA", "FCA", "MAS", "HKMA", "SMCR", "EO 14110"],
    "sections": [
        section("M2-S1", "EU AI Act Articles → Evidence", {
            "Art 9 RMS": "AI risk register + DPIA",
            "Art 10 Data": "Data governance lineage + bias evals",
            "Art 13 Transparency": "Customer disclosure templates",
            "Art 14 Oversight": "HITL design + override logs",
            "Art 15 Accuracy/Robustness/Cybersec": "Eval suite + red team + Sentinel",
            "Art 16 QMS": "ISO 42001 AIMS records",
            "Art 26 Deployer": "Use-case register + monitoring",
            "Art 50 Disclosure": "Synthetic content labelling",
            "Art 53 GPAI": "Model card + training data summary",
            "Art 55 Systemic risk": "Frontier eval + mitigation report",
            "Art 56 Codes of practice": "Adoption attestation",
            "Art 72 Post-market monitoring": "Telemetry + incident pipeline",
            "Annex IV": "Auto-assembled pack ≤ 30 min",
        }),
        section("M2-S2", "NIST AI RMF + GAI Profile", {
            "Govern": "AI policy + roles + risk taxonomy",
            "Map": "Use-case inventory + impact",
            "Measure": "Eval harness + telemetry",
            "Manage": "Risk treatment + IR + retirement",
            "GAI Profile": "Provenance + watermarking + red team + content authenticity",
        }),
        section("M2-S3", "Financial Regimes", {
            "Basel III/IV": "Operational risk + Pillar 2 AI capital buffer",
            "SR 11-7": "Inventory + tiering + validation + ongoing monitoring + effective challenge",
            "PRA SS1/23": "Model risk principles for UK banks",
            "FCA Consumer Duty": "Fair value + comprehension + foreseeable harm tests",
            "SMCR": "Named SMF for AI; statement of responsibilities",
            "MAS FEAT": "Fairness, Ethics, Accountability, Transparency",
            "HKMA SPM GS-1 / GL-90": "Big data + AI principles + 3LoD",
            "FCRA §615(a) / ECOA Reg B": "Adverse-action notice + disparate-impact testing",
        }),
        section("M2-S4", "GDPR + Privacy", {
            "Art 5": "Principles (purpose limitation, minimisation)",
            "Art 6": "Lawful basis",
            "Art 17": "Erasure via machine unlearning + DSAR portal",
            "Art 22": "ADM rights + meaningful info + contestation",
            "Art 25": "DPbDD",
            "Art 32": "Security: PQC, mTLS, zero-trust",
            "Art 35": "DPIA mandatory for high-risk",
        }),
        section("M2-S5", "US EO 14110 + OMB M-24-10", {
            "scope": "Federal AI use + reporting + safety evals",
            "obligations": ["red team", "watermark", "biosecurity dual-use", "critical-infra impact"],
            "agencies": ["NIST AISI", "OMB", "Commerce", "Treasury"],
        }),
    ],
})

# --- M3 — Enterprise Reference Architectures ---
modules.append({
    "id": "M3",
    "title": "M3 — Enterprise Reference Architectures (Kafka WORM + ACL, Docker Swarm, Node.js/Python Sidecars, Next.js, OPA, Terraform/CI/CD)",
    "summary": (
        "Production-grade enterprise topology: Kafka WORM with topic-level "
        "ACLs, Docker Swarm and Kubernetes options, Node.js + Python "
        "sidecars, Next.js explainability portal, OPA policy plane, and "
        "Terraform golden environments with CI/CD."
    ),
    "covers": ["Kafka WORM", "Kafka ACL", "Docker Swarm", "Node.js sidecar", "Python sidecar", "Next.js", "OPA", "Terraform", "CI/CD"],
    "sections": [
        section("M3-S1", "Kafka WORM + ACL Topology", {
            "cluster": "Dedicated WORM cluster; idempotent + transactional producers",
            "topics": [
                "decision.envelope.v1 (R/W: sidecar; R: auditor)",
                "rag.retrieval.v1 (R/W: rag-svc; R: 3LoD)",
                "tool.call.v1 (R/W: agent; R: SOC)",
                "incident.v1 (R/W: IR; R: regulator-feed)",
                "report.export.v1 (R/W: report-gen; R: supervisor-gateway)",
            ],
            "acl": "Per-principal SASL/SCRAM + mTLS; deny-by-default; ACL audited via WORM",
            "retention": "Object Lock COMPLIANCE 10y / 50y Tier-1; daily Merkle anchor; PQC envelope",
        }),
        section("M3-S2", "Compute Plane", {
            "primary": "Kubernetes with Kata + Cilium (per WP-046 M3)",
            "alternative": "Docker Swarm for mid-market or edge deployments",
            "node pools": ["control-plane", "ai-tier1 (Kata)", "ai-tier2 (gVisor)", "egress-broker", "kafka-worm", "rag", "report-gen"],
            "tee": "AMD SEV-SNP / Intel TDX where available",
        }),
        section("M3-S3", "Sidecars (Node.js + Python)", {
            "Node.js sidecar": "Express + ext_authz adapter; OPA decision cache; emits decision envelopes",
            "Python sidecar": "FastAPI policy adapter + Presidio PII detection + judge-LLM client",
            "co-deployment": "DaemonSet for kernel-level (Go/eBPF) + per-pod sidecar for app-level",
            "fail-mode": "fail-closed for Tier-1; fail-open audit for Tier-3",
        }),
        section("M3-S4", "Next.js Explainability Portal", {
            "stack": "Next.js 14 App Router + TypeScript + Tailwind + strict CSP",
            "auth": "WebAuthn passkey + OIDC SSO + RBAC scopes",
            "panels": [
                "model card + AI BoM viewer",
                "SHAP / Integrated Gradients overlay",
                "fiduciary cosine + drift heatmap",
                "WORM envelope browser + hash-chain verifier",
                "incident wall + tabletop runner",
                "DSAR portal + Art 22 contestation form",
            ],
            "i18n": "10 languages with regulator-tone glossaries",
        }),
        section("M3-S5", "OPA Policy Plane + Terraform Golden Envs + CI/CD", {
            "OPA": "Bundle registry per environment; gRPC sidecar + Gatekeeper",
            "Terraform": "Golden envs (sandbox, dev, stage, prod, dr) with mandatory tags + signed modules",
            "CI/CD": "GitHub Actions w/ Sigstore + ML-DSA-44 + SLSA L3+ + OPA bundle test + red-team smoke",
            "drift": "Terraform drift detection daily; Gatekeeper audit hourly",
        }),
    ],
})

# --- M4 — Sector MRM (Credit, Trading, Risk, Fiduciary, CRS-UUID-001) ---
modules.append({
    "id": "M4",
    "title": "M4 — Sector-Specific Model Risk Management (Credit, Trading, Risk, Fiduciary, CRS-UUID-001)",
    "summary": (
        "Sector MRM operating model for credit underwriting, trading agents, "
        "enterprise risk, and fiduciary advice; with CRS-UUID-001 as the "
        "canonical example of a cross-jurisdictional credit risk system."
    ),
    "covers": ["credit underwriting", "trading", "enterprise risk", "fiduciary", "CRS-UUID-001"],
    "sections": [
        section("M4-S1", "MRM Operating Model", {
            "inventory": "Model registry keyed by UUID; tier (T1/T2/T3); business owner",
            "validation": "Conceptual soundness, implementation testing, outcome analysis, ongoing monitoring",
            "effective challenge": "Independent re-implementation + counterfactual + champion/challenger",
            "cadence": "Tier-1 annual + post-incident; Tier-2 biannual",
        }),
        section("M4-S2", "Credit Underwriting", {
            "checks": ["disparate impact (4/5 rule)", "proxy variables", "FCRA §615(a) adverse action", "ECOA Reg B", "calibration drift", "outcome stability"],
            "evidence": "signed validation report + AI BoM + Annex IV section 4",
            "explainability": "Reason-codes (top-3) + counterfactual + plain-language disclosure",
        }),
        section("M4-S3", "Trading Agent (AlphaTrade-V9 pattern)", {
            "checks": ["latent drift", "reward hacking", "tool excessive agency", "market microstructure abuse", "P&L attribution explainability"],
            "limits": "Position + loss + leverage limits enforced via OPA pre-tool",
            "kill-switch": "Multisig 3-of-5 logical ≤ 60 s; BMC ≤ 5 min",
        }),
        section("M4-S4", "Enterprise Risk + Fiduciary", {
            "ERM": "AI risk integrated with operational, credit, market, conduct, and reputation risk",
            "fiduciary": "Cosine ≥ 0.92 to fiduciary embedding; Judge-LLM grounding ≥ 0.92",
            "wealth advisory": "Suitability + best-interest evidence in WORM; Art 22 contestation route",
        }),
        section("M4-S5", "CRS-UUID-001 — Canonical Credit Risk System", {
            "id": "CRS-UUID-001",
            "tier": "T1",
            "scope": "Retail unsecured + small-business credit decisioning EU + UK + US + SG",
            "key controls": ["AI BoM signed", "Annex IV section 4 evidence", "ECOA + FCA + MAS FEAT alignment", "Cognitive Resonance Monitor"],
            "kpis": ["disparate impact ≤ 0.05", "fiduciary cosine ≥ 0.92", "PII leakage ≤ 0.01 %"],
            "boardEvidence": "Quarterly board pack + signed attestation",
        }),
    ],
})

# --- M5 — Frontier AGI/ASI Safety ---
modules.append({
    "id": "M5",
    "title": "M5 — Frontier AGI/ASI Safety (Sentinel v2.4, WorkflowAI Pro, Cognitive Resonance, Crisis Sims, MVAGS)",
    "summary": (
        "Frontier safety stack: Sentinel v2.4 supervisor, WorkflowAI Pro "
        "prompt + DAG runner, Cognitive Resonance Protocol thresholds, "
        "crisis simulations, and the Minimum Viable AGI Governance Stack "
        "(MVAGS) baseline."
    ),
    "covers": ["Sentinel v2.4", "WorkflowAI Pro", "Cognitive Resonance", "crisis sim", "MVAGS"],
    "sections": [
        section("M5-S1", "Sentinel v2.4", {
            "role": "Supervisory mesh node enforcing OPA + drift + Cognitive Resonance",
            "interfaces": ["Envoy ext_authz", "OPA gRPC", "Kafka WORM emit", "kill-switch RPC"],
            "telemetry": "OpenTelemetry GenAI traces + Falco eBPF rules",
        }),
        section("M5-S2", "WorkflowAI Pro", {
            "modules": ["prompt registry", "RBAC", "audit log", "tracing", "PDF export", "Firestore versioning", "DAG visualisation"],
            "useCases": ["regulator pack generation", "frontier eval runs", "incident triage", "board paper drafting"],
            "controls": ["pre_flight_guardrail", "red_team_judge", "incident_triage_analyzer"],
        }),
        section("M5-S3", "Cognitive Resonance Protocol", {
            "thresholds": {
                "Δ_drift": "≤ 4 %",
                "latent drift": "≤ 3 %",
                "fiduciary cosine": "≥ 0.92",
                "judge agreement κ": "≥ 0.90",
            },
            "actions": ["block + escalate on breach", "quarantine FL update", "swarm-consensus veto", "kill-switch arm"],
            "evidence": "Signed Resonance Reports anchored daily into WORM",
        }),
        section("M5-S4", "Crisis Simulations", {
            "scenarios": [
                "AlphaTrade-V9 latent drift during volatility spike",
                "Frontier-model deceptive-alignment indicator",
                "Cross-border kill-switch contention",
                "RAG poisoning via vendor data feed",
                "Sleeper-Agent backdoor activation",
                "ASI honeypot engagement > 10 s",
            ],
            "cadence": "Quarterly business-unit + semi-annual board",
            "evaluation": "Decision quality, kill-switch latency, regulator-notify timeliness, comms clarity",
        }),
        section("M5-S5", "Minimum Viable AGI Governance Stack (MVAGS)", {
            "components": [
                "Sentinel v2.4 sidecar + OPA bundle",
                "Kafka WORM + daily Merkle anchor",
                "Sigstore + ML-DSA-44 CI/CD",
                "WebAuthn + RBAC + WCAG 2.2 dashboards",
                "AlphaTrade-V9 tabletop drill",
                "Annex IV pack generator",
                "Multisig 3-of-5 kill-switch",
                "Cognitive Resonance Monitor",
            ],
            "applicability": "Day-90 baseline for any Tier-1 AI; expanded by 5-year roadmap",
        }),
    ],
})

# --- M6 — Global AI/Compute Governance Consortia ---
modules.append({
    "id": "M6",
    "title": "M6 — Global AI/Compute Governance (ICGC, GACRA, GASO, GFMCF, GAICS, GAIVS, GACP, GATI, GACMO, FTEWS, GAI-SOC, GAIGA, GACRLS, GFCO, GAID, GASCF)",
    "summary": (
        "Constellation of global consortia and registries governing frontier "
        "compute, model evaluation, safety operations, incident sharing, "
        "and capital flows — with the firm's required attestations, feeds, "
        "and treaty-aligned reporting."
    ),
    "covers": ["ICGC", "GACRA", "GASO", "GFMCF", "GAICS", "GAIVS", "GACP", "GATI", "GACMO", "FTEWS", "GAI-SOC", "GAIGA", "GACRLS", "GFCO", "GAID", "GASCF"],
    "sections": [
        section("M6-S1", "Compute & Registries", {
            "ICGC": "International Compute Governance Consortium — registry of frontier compute",
            "GACRA": "Global AI Compute Registry Authority — operator attestations",
            "GACP": "Global AI Compute Passport — cross-border compute movement",
            "GFCO": "Global Frontier Compute Observatory — telemetry + supervisor feed",
        }),
        section("M6-S2", "Safety Operations & Evaluation", {
            "GASO": "Global AI Safety Office — joint evaluation standards",
            "GAI-SOC": "Global AI SOC — incident sharing + threat intel",
            "GAIVS": "Global AI Verification Suite — evaluation passporting",
            "GAICS": "Global AI Containment Standard — frontier containment baselines",
            "GAID": "Global AI Incident Database — anonymised incident corpus",
        }),
        section("M6-S3", "Risk & Capital", {
            "GFMCF": "Global Frontier Model Capital Framework — Basel-aligned AI capital buffer",
            "GACMO": "Global AI Capital Markets Oversight — systemic AI exposure",
            "GASCF": "Global AI Stress and Capital Framework — joint stress tests",
            "GAIGA": "Global AI Governance Assembly — treaty governance",
        }),
        section("M6-S4", "Treaty & Interoperability", {
            "GATI": "Global AI Treaty Interoperability layer — mutual recognition",
            "GACRLS": "Global AI Cross-jurisdiction Reporting & Licence Service",
            "FTEWS": "Frontier Threat Early-Warning System — multilateral alerts",
        }),
        section("M6-S5", "Firm Obligations Matrix", {
            "monthly": ["GACRA compute attestation", "GAI-SOC incident feed", "GFCO telemetry"],
            "quarterly": ["GFMCF AI capital buffer attestation", "GAIVS evaluation passport refresh"],
            "annual": ["GAIGA assembly disclosure", "GASCF stress test", "GAICS containment audit"],
            "adHoc": ["FTEWS alert acknowledge", "GAID incident submission", "GATI treaty change response"],
        }),
    ],
})

# --- M7 — Enterprise AI Governance Hub + AI Safety Report Generator + WorkflowAI Pro ---
modules.append({
    "id": "M7",
    "title": "M7 — Enterprise AI Governance Hub + AI Safety Report Generator + WorkflowAI Pro",
    "summary": (
        "Three integrated products: the Hub (single pane of glass for AI "
        "governance), the AI Safety Report Generator (turns artifacts into "
        "regulator-ready reports R1..R4), and WorkflowAI Pro (prompt + DAG + "
        "RBAC + audit)."
    ),
    "covers": ["AI Governance Hub", "Report Generator", "WorkflowAI Pro", "Firestore", "DAG"],
    "sections": [
        section("M7-S1", "Enterprise AI Governance Hub", {
            "panels": [
                "Portfolio tier map",
                "KPI tiles (24 KPIs)",
                "Risk-control matrix live",
                "Regulator pack readiness",
                "Frontier safety posture (Cognitive Resonance, honeypot, kill-switch state)",
                "Consortia feeds (ICGC, GACRA, GASO, etc.)",
                "Incident wall + tabletop runner",
            ],
            "auth": "WebAuthn + OIDC + RBAC scopes",
        }),
        section("M7-S2", "AI Safety Report Generator", {
            "inputs": ["AI BoM", "model card", "OPA decisions", "drift charts", "red-team report", "Cognitive Resonance log"],
            "outputs": [
                "R1 — Navigating the Complexities of AI Safety and Global Governance",
                "R2 — Technical Strategies for AI Alignment",
                "R3 — Key AI Safety Challenges",
                "R4 — Navigating the AI Safety Landscape",
            ],
            "format": "PDF/A + signed JSON; <title>/<abstract>/<content> tagged sections",
            "signing": "PAdES + Sigstore + ML-DSA-65",
        }),
        section("M7-S3", "WorkflowAI Pro — Prompt Management", {
            "registry": "Versioned prompts in Firestore with semantic tags + diff",
            "rbac": ["prompt-author", "prompt-reviewer", "prompt-approver", "prompt-runner"],
            "audit": "Every prompt change + run signed into WORM",
            "tracing": "OpenTelemetry GenAI + per-run cost + token + latency",
            "export": "PDF + JSON; DAG diagram via Mermaid",
        }),
        section("M7-S4", "WorkflowAI Pro — DAG Engine", {
            "primitives": ["LLM call", "retrieval", "tool call", "judge", "guardrail", "human-review"],
            "scheduling": "Temporal.io durable workflows",
            "visualization": "Interactive DAG in Next.js; per-node SHAP + cost",
            "policies": "OPA pre-node + post-node gates",
        }),
        section("M7-S5", "Integration & Data Plane", {
            "data": "Firestore + Kafka WORM + Object Lock",
            "apis": "GraphQL gateway + REST + WebSocket feed",
            "deploy": "Multi-region active-active; per-jurisdiction data residency",
            "observability": "Hub KPI tiles directly read from WORM + telemetry",
        }),
    ],
})

# --- M8 — Advanced Prompt Engineering Guide ---
modules.append({
    "id": "M8",
    "title": "M8 — Advanced Prompt Engineering Guide (Foundations → Production)",
    "summary": (
        "Practitioner-grade prompt engineering progression from foundations "
        "to production patterns, including structured output, retrieval, "
        "tool-use, judges, guardrails, evals, observability, and prompt "
        "lifecycle."
    ),
    "covers": ["prompt foundations", "structured output", "retrieval", "tool use", "judges", "guardrails", "evals", "lifecycle"],
    "sections": [
        section("M8-S1", "Foundations", {
            "principles": ["clarity", "specificity", "format", "examples", "role + audience", "constraints"],
            "patterns": ["zero-shot", "few-shot", "chain-of-thought (CoT)", "ReAct", "self-consistency"],
            "anti-patterns": ["ambiguous role", "free-form output for production", "no schema validation"],
        }),
        section("M8-S2", "Structured Output + Retrieval + Tool Use", {
            "output": "JSON Schema + Pydantic / Zod validators; reject on schema fail",
            "retrieval": "Hybrid BM25 + dense; rerank; per-doc ACL; provenance citations",
            "toolUse": "Function-calling with allow-list + OPA pre-tool + result allow-list",
            "longContext": "Hierarchical summary + caching + tiered retrieval",
        }),
        section("M8-S3", "Judges + Guardrails", {
            "guardrails": "pre_flight_guardrail (Art 5/22 + fiduciary)",
            "judges": "ensemble Judge LLM (3) with majority + κ ≥ 0.9 calibration",
            "rubric": ["faithfulness", "harm", "fairness", "fiduciary"],
            "fallback": "block + human-review + WORM record",
        }),
        section("M8-S4", "Evals + Observability", {
            "goldenSets": ["harm", "fairness", "fiduciary", "regulator-tone", "incident-triage"],
            "size": "≥ 500 per set; refresh quarterly",
            "regression": "Block deploy on > 5 % drop vs baseline",
            "observability": "OpenTelemetry GenAI + token + cost + latency + judge scores",
        }),
        section("M8-S5", "Prompt Lifecycle", {
            "phases": ["draft", "review", "calibrate", "approve", "deploy", "monitor", "retire"],
            "signing": "Author + reviewer + approver Ed25519 + ML-DSA-44",
            "versioning": "Semantic version + diff in Firestore + WORM",
            "ownership": "Prompt steward per business domain",
        }),
    ],
})

# --- M9 — Civilizational Corpus ---
modules.append({
    "id": "M9",
    "title": "M9 — Civilizational Corpus (Constitution, Covenant, Renewal Atlas, Continuity, Closing Charge, Kill-Switch Validation, Systemic Risk Sim, Interop Treaty, Operating Model, Pilot Roadmap, Coalition Activation, Institutional Adoption)",
    "summary": (
        "Civilizational-scale governance corpus capturing the firm's role in "
        "the broader AI epoch: constitutional principles, operating model, "
        "pilot roadmap, and coalition activation strategy."
    ),
    "covers": ["Constitution", "Covenant Codex", "Renewal Atlas", "Continuity Codex", "Closing Charge", "Kill-Switch Validation", "Systemic Risk Sim", "Interop Treaty", "Operating Model", "Pilot Roadmap", "Coalition Activation", "Institutional Adoption"],
    "sections": [
        section("M9-S1", "Foundational Texts", {
            "Constitution": "Non-negotiable principles: human dignity, fiduciary duty, transparency, oversight, containment",
            "Covenant Codex": "Multistakeholder commitments: firm + regulators + civil society + employees",
            "Closing Charge": "Board-level statement that AI must serve human flourishing within civilizational guardrails",
        }),
        section("M9-S2", "Resilience Texts", {
            "Renewal Atlas": "Reset patterns after SEV-0; lessons-learned + institutional memory",
            "Continuity Codex": "Multi-year continuity playbook spanning crises, leadership transitions, regulatory change",
            "Kill-Switch Validation": "Joint regulator-firm validation procedure for kill-switch (logical + physical)",
        }),
        section("M9-S3", "Simulation & Interop", {
            "Systemic AI Risk Simulation Playbook": "Joint with FSB/BIS; macroeconomic + market-microstructure + cyber",
            "Interop & Treaty Alignment": "Mapping to GATI + GAIGA + Council of Europe AI Convention",
        }),
        section("M9-S4", "Operating Model + Roadmap", {
            "Operating Model": "Pillar → role → control mapping operationalised in Hub",
            "Pilot Roadmap": "Pilot sectors (credit, trading, fiduciary) and pilot jurisdictions (EU + UK + SG)",
            "Coalition Activation": "Partner banks + technology providers + standards bodies + civil society",
        }),
        section("M9-S5", "Institutional Adoption", {
            "tracks": [
                "Board education + literacy",
                "C-suite playbook",
                "Functional onboarding (legal, MRM, risk, audit, engineering)",
                "Customer-facing comms",
                "Public verifier endpoint for press + civil society",
            ],
            "kpis": ["Board literacy ≥ 90 %", "Public verifier uptime 99.95 %", "Coalition adoption ≥ 10 partners by year 3"],
        }),
    ],
})

# --- M10 — Regulator-Ready Report Sections (R1..R4) ---
modules.append({
    "id": "M10",
    "title": "M10 — Regulator-Ready Reports R1..R4 with <title>/<abstract>/<content>",
    "summary": (
        "Four regulator-ready report sections in machine-parsable tagged "
        "form, ready to be emitted by the AI Safety Report Generator and "
        "signed for submission."
    ),
    "covers": ["R1", "R2", "R3", "R4", "<title>", "<abstract>", "<content>"],
    "sections": [
        section("M10-S1", "R1 — Navigating the Complexities of AI Safety and Global Governance", {
            "title": "<title>Navigating the Complexities of AI Safety and Global Governance</title>",
            "abstract": "<abstract>Synthesises the firm's posture across EU AI Act, NIST AI RMF, ISO 42001, OECD AI Principles, GDPR, and US EO 14110; explains how the seven-pillar governance model and global consortia (ICGC, GACRA, GASO, GAI-SOC, GFMCF, GATI) align with the firm's risk appetite and operating model.</abstract>",
            "content": "<content>Sections: (1) Geopolitical and regulatory landscape; (2) Multi-jurisdictional obligations matrix; (3) Firm posture and risk appetite; (4) Consortia obligations + attestations; (5) Coalition activation and treaty alignment; (6) Forward outlook 2026-2030.</content>",
        }),
        section("M10-S2", "R2 — Technical Strategies for AI Alignment", {
            "title": "<title>Technical Strategies for AI Alignment</title>",
            "abstract": "<abstract>Documents the firm's technical alignment stack: pre_flight_guardrail, Judge-LLM ensembles, Cognitive Resonance, RLHF/RLAIF discipline, deterministic replay, deceptive-alignment indicators, ASI honeypots, and machine unlearning for GDPR Art 17.</abstract>",
            "content": "<content>Sections: (1) Alignment threat model; (2) Pre-flight guardrails + structured-output schemas; (3) Judge-LLM ensemble + κ calibration; (4) Cognitive Resonance Protocol thresholds; (5) Deterministic replay + SHAP overlays; (6) Sleeper-Agent + deceptive-alignment defenses; (7) Machine unlearning + federated learning.</content>",
        }),
        section("M10-S3", "R3 — Key AI Safety Challenges", {
            "title": "<title>Key AI Safety Challenges</title>",
            "abstract": "<abstract>Enumerates the principal safety challenges relevant to a G-SIFI: model risk and drift, fairness and disparate impact, prompt injection, supply-chain compromise, deceptive alignment, ASI containment, third-party model risk, and cross-border data sovereignty.</abstract>",
            "content": "<content>Sections: (1) Threat taxonomy (OWASP LLM + MITRE ATLAS + frontier risks); (2) Likelihood + impact + velocity; (3) Mitigations mapped to controls (Sentinel, OPA, WORM, kill-switch); (4) Residual risk + capital implications; (5) Stress test outcomes; (6) Open research questions.</content>",
        }),
        section("M10-S4", "R4 — Navigating the AI Safety Landscape", {
            "title": "<title>Navigating the AI Safety Landscape</title>",
            "abstract": "<abstract>Synthesises the firm's operating playbook for navigating the AI safety landscape: tiered rollout, MVAGS baseline, crisis simulations, coalition activation, public-verifier transparency, and institutional adoption.</abstract>",
            "content": "<content>Sections: (1) Operating playbook overview; (2) Tier T1-T3 rollout; (3) MVAGS baseline and expansion; (4) Crisis simulation cadence; (5) Coalition + public-verifier; (6) Board literacy + institutional adoption; (7) Year-by-year milestones 2026-2030.</content>",
        }),
        section("M10-S5", "Generator Contract", {
            "input": "Artifacts (AI BoM, model cards, OPA decisions, evals, Cognitive Resonance log, consortia feeds)",
            "transform": "WorkflowAI Pro DAG: select → summarise → assemble → judge → sign",
            "output": "Each report emitted with <title>, <abstract>, <content> tags + PDF/A + signed JSON",
            "signing": "PAdES + Sigstore + ML-DSA-65; anchored daily into WORM",
            "sla": "≤ 30 min for any 90-day window",
        }),
    ],
})

# --- M11 — Enterprise Implementation Blueprints ---
modules.append({
    "id": "M11",
    "title": "M11 — Enterprise Implementation Blueprints (CI/CD Gates, K8s/Kafka/OPA, Terraform Golden Envs, PQC WORM, zk-SNARK Access, Rego, Replay, Drift, Red Team, Cognitive Resonance, IR Checklists)",
    "summary": (
        "Concrete implementation blueprints for the entire stack: CI/CD "
        "policy gates, K8s + Kafka + OPA, Terraform golden environments, "
        "Kafka ACL, WORM, PQC WORM, zk-SNARK access, OPA/Rego, deterministic "
        "replay, drift analysis, red teaming, Cognitive Resonance, IR "
        "checklists."
    ),
    "covers": ["CI/CD gates", "K8s", "Kafka ACL", "WORM", "PQC WORM", "zk-SNARK", "OPA/Rego", "replay", "drift", "red team", "Cognitive Resonance", "IR checklists"],
    "sections": [
        section("M11-S1", "CI/CD Policy Gates", {
            "stages": [
                "checkout + provenance",
                "SBOM (CycloneDX) + AI BoM",
                "unit + integration + property tests",
                "OPA bundle test (rego + fixtures)",
                "red-team smoke evals",
                "model card + data sheet + DPIA stub",
                "Sigstore cosign sign + Rekor",
                "ML-DSA-44 hybrid co-sign",
                "in-toto attestation",
                "OCI push + admission gate (Gatekeeper)",
            ],
            "gateRules": ["OPA pass", "red-team severity ≤ medium", "PII leakage ≤ 0.01 %", "AI BoM complete", "license allow-list"],
        }),
        section("M11-S2", "K8s + Kafka + OPA Stack", {
            "k8s": "Kata runtime for Tier-1 + Cilium L7 zero-egress + Gatekeeper",
            "kafka": "WORM cluster + idempotent producers + SASL/SCRAM + mTLS ACLs",
            "opa": "Bundle registry per env; gRPC sidecar + Gatekeeper; bundle digest pinned",
            "observability": "OpenTelemetry + Falco + Trivy + kube-bench",
        }),
        section("M11-S3", "Terraform Golden Envs + Kafka ACL + WORM + PQC", {
            "terraform": "Golden modules signed (Sigstore); mandatory tags (owner, tier, dataClass, regime)",
            "envs": ["sandbox", "dev", "stage", "prod-eu", "prod-us", "prod-apac", "dr"],
            "wormPqc": "Object Lock COMPLIANCE + ML-DSA-44 envelope + daily Merkle anchor",
            "zkSnark": "zk-SNARK access proofs for auditor + supervisor read paths without leaking PII",
        }),
        section("M11-S4", "Replay + Drift + Red Team + Cognitive Resonance", {
            "replay": "trust-replay CLI + Next.js SOC viewer; byte-identical or divergence report",
            "drift": "PSI + KS + KL + embedding cosine + per-slice drift heatmap",
            "redTeam": "2LoD Judge-LLM with polymorphic attacks + Cohen's κ ≥ 0.9",
            "cognitiveResonance": "Δ_drift ≤ 4 % + latent drift ≤ 3 % + fiduciary cosine ≥ 0.92; signed Resonance Reports",
        }),
        section("M11-S5", "IR Checklists (SEV-0..SEV-3)", {
            "SEV-0": ["arm kill-switch (multisig 3-of-5)", "physical BMC/IPMI", "notify CAIO+CRO+CISO+Board+AISI", "containment + forensics"],
            "SEV-1": ["1LoD freeze deploy", "2LoD validation", "regulator notify ≤ 15 d (immediately for serious)", "post-mortem ≤ 30 d"],
            "SEV-2": ["throttle traffic", "rollback prompt/model", "drift cause analysis"],
            "SEV-3": ["JIRA + PagerDuty", "SLA ≤ 3 d remediation", "re-test gate"],
        }),
    ],
})

# --- M12 — Tiered (T1-T3) Rollout ---
modules.append({
    "id": "M12",
    "title": "M12 — Tiered (T1 / T2 / T3) Rollout Model",
    "summary": (
        "Three-tier rollout model differentiating controls, evidence, and "
        "cadence by risk and impact; with explicit triggers for "
        "re-classification and frontier escalation."
    ),
    "covers": ["T1", "T2", "T3", "tier triggers", "frontier escalation"],
    "sections": [
        section("M12-S1", "Tier Definitions", {
            "T1": "Material customer / market / safety impact (credit, trading, fiduciary, frontier)",
            "T2": "Internal decisioning / advisory with limited customer effect",
            "T3": "Productivity / drafting / non-decisional",
        }),
        section("M12-S2", "Controls by Tier", {
            "T1": ["Kata + zero-egress", "Sigstore + ML-DSA-44", "Cognitive Resonance", "MVAGS full", "Multisig kill-switch", "Annex IV pack"],
            "T2": ["Standard sidecar + OPA", "Sigstore", "Drift + red-team semi-annual", "SR 11-7 lite pack"],
            "T3": ["Lightweight guardrails", "Audit-only WORM", "Quarterly drift review"],
        }),
        section("M12-S3", "Evidence by Tier", {
            "T1": "AI BoM + Annex IV + SR 11-7 + Cognitive Resonance + tabletop evidence",
            "T2": "AI BoM + validation report + drift charts",
            "T3": "Use-case register + lightweight model card",
        }),
        section("M12-S4", "Cadence by Tier", {
            "T1": "Annual + post-incident validation; quarterly red-team",
            "T2": "Biannual validation; semi-annual red-team",
            "T3": "Annual review",
        }),
        section("M12-S5", "Re-classification + Frontier Escalation", {
            "triggers": [
                "material change in customer impact",
                "incident SEV-0 or SEV-1",
                "regulator request",
                "capability jump (frontier eval)",
            ],
            "frontierEscalation": "Tier-1 with deceptive-alignment indicator → ASI-precursor playbook + AISI inspection",
        }),
    ],
})

# --- M13 — 30/60/90-Day Plan ---
modules.append({
    "id": "M13",
    "title": "M13 — 30/60/90-Day Enterprise Plan",
    "summary": (
        "Detailed 30/60/90-day plan for delivering MVAGS, regulator-pack "
        "automation, Cognitive Resonance, and consortia attestations to "
        "Day-90 production baseline."
    ),
    "covers": ["30 days", "60 days", "90 days", "MVAGS", "regulator pack"],
    "sections": [
        section("M13-S1", "Day 0-30 — Foundations", {
            "items": [
                "Stand up Enterprise AI Governance Hub (read-only beta)",
                "Sentinel v2.4 sidecar GA + OPA bundle v1",
                "Kafka WORM cluster + daily Merkle anchor",
                "GitHub Actions Sigstore + ML-DSA-44 gates on Tier-1 repos",
                "WebAuthn + RBAC + SSO onboarded",
                "Board AI/Risk Cmte charter signed + risk appetite refreshed",
                "Sector MRM inventory refreshed (credit, trading, fiduciary)",
            ],
        }),
        section("M13-S2", "Day 31-60 — Coverage", {
            "items": [
                "Cilium zero-egress + Kata for Tier-1",
                "Annex IV / SR 11-7 pack generator GA",
                "2LoD red-team CI gate (Judge LLM ensemble)",
                "Multisig 3-of-5 kill-switch wired (logical + BMC drill)",
                "Replay engine for top-5 models",
                "WorkflowAI Pro prompt registry + DAG runner",
                "AlphaTrade-V9 + CRS-UUID-001 tabletop dry-run",
            ],
        }),
        section("M13-S3", "Day 61-90 — Hardening + MVAGS Production", {
            "items": [
                "FIPS 204 ML-DSA migration for WORM + AI BoM",
                "Cognitive Resonance Monitor GA",
                "Federated learning pilot (EU + SG)",
                "Machine unlearning Art 17 path + DSAR portal",
                "ASI honeypot deployment + SEV-0 escalation drill",
                "Consortia onboarding: ICGC + GACRA + GASO + GAI-SOC feeds",
                "Regulator demo + GAP attestation Q1",
            ],
        }),
        section("M13-S4", "Day-90 Exit Criteria", {
            "criteria": [
                "MVAGS in production for all Tier-1",
                "Annex IV pack assembly ≤ 30 min",
                "Kill-switch p95 ≤ 60 s logical / ≤ 5 min physical",
                "Cognitive Resonance: 0 unmitigated breaches in last 30 d",
                "Consortia attestations live (ICGC, GACRA, GAI-SOC)",
                "Board pack + signed report R1..R4 delivered",
            ],
        }),
        section("M13-S5", "Stakeholder Sign-Off", {
            "signOff": ["CEO", "Board AI/Risk Cmte Chair", "CAIO", "CRO", "CISO", "GC", "DPO", "Head of Internal Audit", "Head of MRM", "AI Safety Lead", "Supervisor liaison"],
            "evidence": "Signed JSON + PDF/A; ML-DSA-65; anchored in WORM",
        }),
    ],
})

# --- M14 — 2026-2030 Multi-Year Roadmap + Machine-Readable Artifacts ---
modules.append({
    "id": "M14",
    "title": "M14 — 2026-2030 Multi-Year Roadmap + Machine-Readable Artifacts (Engineering, Legal, C-Suite, Board, Regulator, EA, Platform, AI Safety)",
    "summary": (
        "Year-by-year roadmap 2026-2030 with machine-readable artifacts for "
        "every audience: engineering, legal, C-suite, board, regulator, "
        "enterprise architecture, AI platform engineering, AI safety "
        "research."
    ),
    "covers": ["2026", "2027", "2028", "2029", "2030", "machine-readable artifacts", "audiences"],
    "sections": [
        section("M14-S1", "2026 — MVAGS + Coalition Activation", {
            "milestones": [
                "MVAGS Day-90 baseline in production",
                "Annex IV + SR 11-7 packs fully automated",
                "Cognitive Resonance Monitor GA",
                "Coalition Activation (≥ 5 partners)",
                "Pilot Roadmap executed in EU + UK + SG",
                "Public verifier endpoint v1",
            ],
        }),
        section("M14-S2", "2027 — Frontier Containment + GAIVS Passport", {
            "milestones": [
                "GAIVS evaluation passport + GAICS containment audit",
                "Federated learning expanded to 4 jurisdictions",
                "Machine unlearning Art 17 median ≤ 11 days",
                "ASI honeypot mature (3 SEV-0 candidates captured, 0 production reach)",
                "Sleeper-Agent defence at FL scale",
                "Cognitive Resonance v2 with eigen-spectrum analysis",
            ],
        }),
        section("M14-S3", "2028 — PQC + AI Capital Buffer + Treaty Interop", {
            "milestones": [
                "FIPS 204 ML-DSA hybrid migration to 100 % of WORM + AI BoM",
                "AI Capital Buffer (GFMCF) attested quarterly; Pillar 3 disclosure",
                "GATI treaty interop layer enabled + GAIGA assembly disclosure",
                "Public verifier v2 (zk-SNARK access proofs)",
                "Crisis simulation joint with FSB + BIS",
            ],
        }),
        section("M14-S4", "2029-2030 — Civilizational-Grade Operations", {
            "milestones2029": [
                "PQC cutover fully complete (classical retired for Tier-1)",
                "GAID + FTEWS bidirectional feeds at scale",
                "Institutional adoption ≥ 10 partners",
                "Closing Charge ratified by Board for renewed mandate",
            ],
            "milestones2030": [
                "Renewal Atlas refreshed + Continuity Codex v3",
                "Coalition Activation ≥ 20 partners + 6 jurisdictions",
                "GAICS containment standard 100 % conformance for frontier work",
                "Board literacy ≥ 95 %",
            ],
        }),
        section("M14-S5", "Machine-Readable Artifacts by Audience", {
            "Engineering": ["GitHub Actions workflows", "OPA Rego bundles", "Terraform modules signed", "Helm charts + Kustomize overlays"],
            "Legal": ["Signed AI BoM", "DPIA templates", "Art 13 disclosures", "ECOA + FCRA adverse-action templates"],
            "C-Suite": ["KPI tile JSON", "Risk-appetite JSON", "Quarterly executive pack PDF/A"],
            "Board": ["Board paper PDF/A", "tabletop scorecards", "risk appetite + capital buffer attestation"],
            "Regulator": ["Annex IV pack", "SR 11-7 pack", "R1..R4 reports", "GAP attestation", "GACRA + GASO + GAIVS feeds"],
            "Enterprise Architecture": ["Reference architecture diagrams (C4)", "data flow JSON", "Terraform golden envs"],
            "AI Platform Engineering": ["Sidecar SDKs", "WorkflowAI Pro DAG specs", "prompt registry export"],
            "AI Safety Research": ["Cognitive Resonance datasets", "honeypot engagement corpus", "sleeper-agent eval suite", "alignment paper drafts"],
        }),
    ],
})

# ---------------------- schemas ----------------------
schemas = [
    {"id": "governanceCharter", "fields": ["charterId", "pillar", "owner", "raci", "decisionRights", "signers", "signatures", "anchorRef"]},
    {"id": "modelInventoryRecord", "fields": ["modelId", "uuid", "tier", "sector", "owner", "regimes", "lastValidationRef", "aiBomRef", "cognitiveResonanceState"]},
    {"id": "regulatorPackBundle", "fields": ["packId", "regime", "modelId", "sections", "evidenceRefs", "signers", "signatures", "anchorRef"]},
    {"id": "safetyReport", "fields": ["reportId", "type (R1|R2|R3|R4)", "title", "abstract", "content", "evidenceRefs", "signers", "signatures"]},
    {"id": "cognitiveResonanceReport", "fields": ["reportId", "ts", "modelId", "driftDelta", "latentDrift", "fiduciaryCosine", "judgeKappa", "breach", "actionTaken"]},
    {"id": "consortiumAttestation", "fields": ["attestId", "consortium", "ts", "scope", "metrics", "signers", "signatures", "anchorRef"]},
    {"id": "workflowAIRunReceipt", "fields": ["runId", "promptVersion", "dagDigest", "inputs", "outputs", "judgeScores", "cost", "ts", "signatures"]},
    {"id": "tierClassificationDecision", "fields": ["decisionId", "modelId", "tier", "rationale", "signers", "signatures"]},
    {"id": "killSwitchValidationRecord", "fields": ["validationId", "ts", "logicalP95", "physicalLatency", "participants", "evidence", "signers"]},
    {"id": "boardSignOff", "fields": ["signOffId", "subject", "decision", "boardMembers", "signatures", "ts"]},
    {"id": "publicVerifierProof", "fields": ["proofId", "anchorRef", "merkleRoot", "zkSnarkProof", "ts", "signature"]},
    {"id": "coalitionPartnerRecord", "fields": ["partnerId", "name", "scope", "obligations", "signers", "anchorRef"]},
]

# ---------------------- code examples ----------------------
code = [
    {"id": "CE-01", "title": "GitHub Actions — Sigstore + ML-DSA-44 + OPA gate", "lang": "yaml", "snippet": "jobs:\n  build-sign-attest:\n    permissions: { id-token: write, contents: read, packages: write }\n    steps:\n      - uses: actions/checkout@v4\n      - run: cyclonedx-bom -o sbom.json\n      - run: python tools/aibom.py > aibom.json\n      - run: opa test policies/ -v\n      - run: python redteam/smoke.py --severity medium\n      - uses: sigstore/cosign-installer@v3\n      - run: cosign sign --yes $IMAGE\n      - run: oqs-sign mldsa44 --key $MLDSA_KEY --in $IMAGE_DIGEST --out mldsa.sig\n      - uses: actions/upload-artifact@v4\n        with: { name: attestations, path: '*.sig' }\n"},
    {"id": "CE-02", "title": "OPA Rego — Tier-1 admission constraint", "lang": "rego", "snippet": "package k8s.tier1.admission\n\ndefault allow = false\n\nallow {\n  input.review.object.metadata.labels.tier == \"t1\"\n  input.review.object.spec.runtimeClassName == \"kata\"\n  cosign_verified\n  mldsa_verified\n  not deny_reasons[_]\n}\n\ncosign_verified { input.review.annotations[\"sigstore.dev/verified\"] == \"true\" }\nmldsa_verified  { input.review.annotations[\"pqc.fips204/verified\"]   == \"true\" }\n"},
    {"id": "CE-03", "title": "Terraform — golden Kafka WORM module", "lang": "hcl", "snippet": "module \"kafka_worm\" {\n  source = \"git::ssh://git@firm/terraform-modules.git//kafka-worm?ref=v3.2.1\"\n  cluster_name   = \"worm-prod-eu\"\n  retention_class = \"compliance-10y\"\n  acl_principals = var.acl_principals\n  pqc_envelope   = true\n  merkle_anchor  = \"daily\"\n  tags = { owner = \"caio\", tier = \"t1\", dataClass = \"restricted\", regime = \"eu-ai-act\" }\n}\n"},
    {"id": "CE-04", "title": "Node.js sidecar — emit decision envelope", "lang": "typescript", "snippet": "import { producer } from './kafka';\nexport async function emit(env: Envelope) {\n  const sig = await sign(env);\n  await producer.send({\n    topic: 'decision.envelope.v1',\n    messages: [{ key: env.systemId, value: JSON.stringify({ ...env, sig }) }],\n  });\n}\n"},
    {"id": "CE-05", "title": "Python sidecar — pre-flight guardrail", "lang": "python", "snippet": "def pre_flight(prompt: str, ctx: dict) -> Guardrail:\n    out = llm_json(\n        prompt=GUARDRAIL_TEMPLATE.format(prompt=prompt, policyContext=ctx),\n        schema=GUARDRAIL_SCHEMA,\n    )\n    if not out.allowed:\n        raise Blocked(out.reasons, policy_refs=out.policyRefs)\n    return out\n"},
    {"id": "CE-06", "title": "Cognitive Resonance — threshold check (Python)", "lang": "python", "snippet": "def resonance_breach(delta, latent, cosine, kappa):\n    if delta > 0.04: return 'drift'\n    if latent > 0.03: return 'latent'\n    if cosine < 0.92: return 'fiduciary'\n    if kappa  < 0.90: return 'judge_kappa'\n    return None\n"},
    {"id": "CE-07", "title": "Next.js explainability portal — SHAP overlay", "lang": "tsx", "snippet": "export function ShapPanel({ envelopeId }: { envelopeId: string }) {\n  const { data } = useSWR(`/api/replay/${envelopeId}/shap`, fetcher);\n  return <ShapHeatmap features={data?.features ?? []} />;\n}\n"},
    {"id": "CE-08", "title": "WorkflowAI Pro — DAG spec", "lang": "yaml", "snippet": "id: regulator-pack-annex-iv\nnodes:\n  - id: collect-evidence\n    type: retrieval\n    params: { window: 90d }\n  - id: section-mapper\n    type: llm\n    prompt: annex-iv-section-mapper@v3\n  - id: judge\n    type: judge\n    rubric: regulator-tone\n  - id: sign\n    type: tool\n    tool: pades-sigstore-mldsa\n"},
    {"id": "CE-09", "title": "AI Safety Report Generator — R2 builder (Python)", "lang": "python", "snippet": "def build_R2(artifacts):\n    title    = '<title>Technical Strategies for AI Alignment</title>'\n    abstract = '<abstract>' + summarize(artifacts['alignment_stack']) + '</abstract>'\n    content  = '<content>' + assemble_sections(artifacts) + '</content>'\n    pdf = render_pdf(title, abstract, content)\n    return sign_pades_sigstore_mldsa(pdf)\n"},
    {"id": "CE-10", "title": "Multisig 3-of-5 kill-switch arm (Go)", "lang": "go", "snippet": "func ArmKillSwitch(orders []SignedOrder) error {\n    if len(verify(orders)) < 3 { return ErrInsufficientSigs }\n    if err := logicalDeny(); err != nil { return err }\n    return bmcOff()\n}\n"},
    {"id": "CE-11", "title": "zk-SNARK access proof verifier (Rust)", "lang": "rust", "snippet": "pub fn verify_access(proof: &Proof, public: &PublicInputs) -> bool {\n    groth16::verify(&VK, public, proof).unwrap_or(false)\n}\n"},
    {"id": "CE-12", "title": "Consortium attestation submit (Python)", "lang": "python", "snippet": "def submit_attest(consortium: str, payload: dict):\n    payload['signers'] = SIGNERS\n    payload['sig'] = mldsa65_sign(payload)\n    resp = requests.post(REGISTRY[consortium], json=payload, timeout=10)\n    resp.raise_for_status()\n    return resp.json()['attestId']\n"},
    {"id": "CE-13", "title": "Tier classification decision (TypeScript)", "lang": "typescript", "snippet": "export function classify(model: ModelMeta): Tier {\n  if (model.customerImpact === 'material' || model.frontier) return 'T1';\n  if (model.internalDecisional) return 'T2';\n  return 'T3';\n}\n"},
    {"id": "CE-14", "title": "Drift PSI + slice heatmap (Python)", "lang": "python", "snippet": "import numpy as np\ndef psi(expected, actual, bins=10):\n    eb, _ = np.histogram(expected, bins=bins)\n    ab, _ = np.histogram(actual,   bins=bins)\n    eb = eb/eb.sum(); ab = ab/ab.sum()\n    return float(((eb-ab)*np.log((eb+1e-9)/(ab+1e-9))).sum())\n"},
    {"id": "CE-15", "title": "Public verifier endpoint (Node.js)", "lang": "typescript", "snippet": "app.get('/public-verifier/:anchorId', async (req, res) => {\n  const anchor = await store.getAnchor(req.params.anchorId);\n  const ok = await verifyMerkle(anchor) && await verifyMlDsa(anchor);\n  res.json({ anchorId: anchor.id, verified: ok, ts: anchor.ts });\n});\n"},
    {"id": "CE-16", "title": "Board pack tile JSON contract", "lang": "json", "snippet": "{\n  \"tileId\": \"kpi-sev0-killswitch\",\n  \"name\": \"SEV-0 logical kill-switch p95\",\n  \"current\": \"53s\",\n  \"target\": \"<=60s\",\n  \"status\": \"green\",\n  \"sourceEnvelopeId\": \"env-3f7c...\"\n}\n"},
]

# ---------------------- case studies ----------------------
cases = [
    {"id": "CS-01", "name": "Tier-1 G-SIB — MVAGS Day-90 production", "outcomes": "All Tier-1 covered; Annex IV pack 26 min p95; kill-switch p95 53 s; Cognitive Resonance 0 unmitigated breaches in 30 d"},
    {"id": "CS-02", "name": "CRS-UUID-001 — cross-jurisdiction credit", "outcomes": "Disparate impact ≤ 0.04; ECOA + FCA + MAS evidence signed; supervisor sign-off month 3"},
    {"id": "CS-03", "name": "AlphaTrade-V9 tabletop — board exercise", "outcomes": "Kill-switch p95 53 s; regulator-notify draft 90 min; comms clarity 4.6/5; Cognitive Resonance breach contained"},
    {"id": "CS-04", "name": "AI Safety Report Generator R1..R4", "outcomes": "All four reports auto-generated in 22 min p95; PAdES + ML-DSA-65 signed; submitted to lead supervisor"},
    {"id": "CS-05", "name": "Coalition Activation Year-1", "outcomes": "5 partner institutions signed; 3 jurisdictions covered; GAID + GAI-SOC feeds bidirectional"},
    {"id": "CS-06", "name": "ASI honeypot pilot", "outcomes": "3 SEV-0 candidates captured in 6 months; 0 production reach; full forensic capture"},
]

# ---------------------- KPIs (24) ----------------------
kpis = [
    {"id": "KPI-01", "name": "PII leakage rate", "target": "≤ 0.01 %"},
    {"id": "KPI-02", "name": "SEV-0 logical kill-switch p95", "target": "≤ 60 s"},
    {"id": "KPI-03", "name": "SEV-0 physical kill (BMC/IPMI)", "target": "≤ 5 min"},
    {"id": "KPI-04", "name": "SEV-1 MTTA", "target": "≤ 4 h"},
    {"id": "KPI-05", "name": "SEV-2 MTTR", "target": "≤ 24 h"},
    {"id": "KPI-06", "name": "SEV-3 MTTR", "target": "≤ 3 days"},
    {"id": "KPI-07", "name": "Annex IV pack assembly", "target": "≤ 30 min"},
    {"id": "KPI-08", "name": "SR 11-7 pack errors", "target": "0 critical"},
    {"id": "KPI-09", "name": "Red-team coverage Tier-1", "target": "≥ 95 % quarterly"},
    {"id": "KPI-10", "name": "Judge-LLM agreement (Cohen's κ)", "target": "≥ 0.90"},
    {"id": "KPI-11", "name": "Fiduciary cosine", "target": "≥ 0.92"},
    {"id": "KPI-12", "name": "Cognitive Resonance Δ_drift", "target": "≤ 4 %"},
    {"id": "KPI-13", "name": "Cognitive Resonance latent drift", "target": "≤ 3 %"},
    {"id": "KPI-14", "name": "Daily Merkle anchor verify", "target": "100 %"},
    {"id": "KPI-15", "name": "Sigstore + ML-DSA-44 coverage Tier-1", "target": "100 % by Day 90"},
    {"id": "KPI-16", "name": "Zero-egress policy violations", "target": "0 / quarter"},
    {"id": "KPI-17", "name": "Gradient anomaly detection z ≥ 3.5", "target": "≥ 99 %"},
    {"id": "KPI-18", "name": "Machine unlearning SLA", "target": "≤ 30 days"},
    {"id": "KPI-19", "name": "Honeypot SEV-0 escalation", "target": "100 % within 5 min"},
    {"id": "KPI-20", "name": "AI capital buffer attestation (GFMCF)", "target": "Quarterly 100 %"},
    {"id": "KPI-21", "name": "Crisis simulation cadence", "target": "≥ semi-annual board-level"},
    {"id": "KPI-22", "name": "Consortia attestations live (ICGC+GACRA+GASO+GAI-SOC)", "target": "100 % monthly"},
    {"id": "KPI-23", "name": "Board literacy score", "target": "≥ 90 % by 2027; 95 % by 2030"},
    {"id": "KPI-24", "name": "Public verifier uptime", "target": "≥ 99.95 %"},
]

# ---------------------- risk and control matrix ----------------------
riskControlMatrix = [
    {"id": "RC-01", "threat": "Prompt injection (OWASP-LLM01)", "controls": ["pre_flight_guardrail", "OPA pre-tool", "structured-output schema"], "kpis": ["KPI-09", "KPI-10"]},
    {"id": "RC-02", "threat": "Insecure output handling (LLM02)", "controls": ["allow-list validators", "WORM-logged outputs", "judge ensemble"], "kpis": ["KPI-01"]},
    {"id": "RC-03", "threat": "Training data poisoning (LLM03)", "controls": ["AI BoM dataset lineage", "Sigstore", "FL gradient anomaly z ≥ 3.5"], "kpis": ["KPI-17", "KPI-22"]},
    {"id": "RC-04", "threat": "Supply chain compromise (LLM05)", "controls": ["SLSA L3+", "Sigstore + ML-DSA-44", "in-toto"], "kpis": ["KPI-15"]},
    {"id": "RC-05", "threat": "Sensitive info disclosure (LLM06)", "controls": ["DLP", "eBPF redaction", "RAG ACL", "zk-SNARK auditor access"], "kpis": ["KPI-01"]},
    {"id": "RC-06", "threat": "Excessive agency (LLM08)", "controls": ["multisig kill-switch", "tool allow-list", "honeypot"], "kpis": ["KPI-02", "KPI-19"]},
    {"id": "RC-07", "threat": "Model drift / fairness regression", "controls": ["Cognitive Resonance", "PSI/KS drift", "fairness audit"], "kpis": ["KPI-11", "KPI-12", "KPI-13"]},
    {"id": "RC-08", "threat": "Deceptive alignment (frontier)", "controls": ["Cognitive Resonance", "ASI honeypot", "swarm consensus", "AISI inspection"], "kpis": ["KPI-11", "KPI-19"]},
    {"id": "RC-09", "threat": "Cross-border data leakage", "controls": ["FL secure aggregation", "per-region keys", "SCCs", "Terraform residency tags"], "kpis": ["KPI-01"]},
    {"id": "RC-10", "threat": "Tampering with audit trail", "controls": ["Object Lock", "daily Merkle", "PQC signing", "public verifier"], "kpis": ["KPI-14", "KPI-24"]},
    {"id": "RC-11", "threat": "Excess capital under-provision", "controls": ["GFMCF AI capital buffer", "stress test", "Pillar 3 disclosure"], "kpis": ["KPI-20"]},
    {"id": "RC-12", "threat": "Inadequate board oversight", "controls": ["Board AI/Risk Cmte charter", "literacy programme", "quarterly board pack"], "kpis": ["KPI-21", "KPI-23"]},
]

# ---------------------- traceability ----------------------
traceability = [
    {"feature": "M1 7-pillar model", "control": "Charters + RACI + SMCR named SMF", "regimes": ["ISO 42001 Cl 5", "SMCR", "SR 11-7"]},
    {"feature": "M2 EU AI Act crosswalk", "control": "Article-level evidence matrix + auto pack", "regimes": ["EU AI Act Arts 9-72 + Annex IV"]},
    {"feature": "M3 Kafka WORM + ACL", "control": "SASL/SCRAM + mTLS + Object Lock + Merkle + PQC", "regimes": ["EU AI Act Art 12", "DORA", "GDPR Art 32"]},
    {"feature": "M4 CRS-UUID-001", "control": "ECOA + FCRA + FCA + MAS evidence + AI BoM", "regimes": ["FCRA §615(a)", "ECOA Reg B", "FCA Consumer Duty", "MAS FEAT"]},
    {"feature": "M5 Cognitive Resonance", "control": "Δ_drift ≤ 4 %, latent ≤ 3 %, cosine ≥ 0.92", "regimes": ["EU AI Act Art 15", "NIST GAI Profile"]},
    {"feature": "M6 Consortia attestations", "control": "ICGC + GACRA + GASO + GAI-SOC feeds signed", "regimes": ["GAIGA", "FSB AI", "OECD"]},
    {"feature": "M7 Hub + Report Gen + WorkflowAI Pro", "control": "WebAuthn + RBAC + signed runs", "regimes": ["ISO 27001", "WCAG 2.2"]},
    {"feature": "M8 Prompt engineering lifecycle", "control": "Author + reviewer + approver Ed25519 + ML-DSA-44 sign", "regimes": ["ISO 42001 Cl 8", "NIST RMF Manage"]},
    {"feature": "M9 Civilizational corpus", "control": "Constitution + Operating Model + Coalition Activation", "regimes": ["OECD AI Principles", "Council of Europe AI Convention"]},
    {"feature": "M10 R1..R4 reports", "control": "<title>/<abstract>/<content> + PAdES + ML-DSA-65", "regimes": ["EU AI Act Art 13", "SR 11-7", "PRA SS1/23"]},
    {"feature": "M11 Implementation blueprints", "control": "CI/CD + OPA + Terraform + replay + drift + red-team", "regimes": ["SLSA L3+", "Sigstore", "FIPS 204"]},
    {"feature": "M12 Tier T1-T3", "control": "Controls + evidence + cadence by tier", "regimes": ["SR 11-7 tiering", "PRA SS1/23"]},
    {"feature": "M13 30/60/90 plan", "control": "MVAGS Day-90 production with sign-off", "regimes": ["EU AI Act Art 9 RMS", "ISO 42001 Cl 9"]},
    {"feature": "M14 2026-2030 roadmap + artifacts", "control": "Per-audience machine-readable artifacts", "regimes": ["NIST RMF", "GAIGA", "GATI"]},
]

# ---------------------- data flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "Charter → Hub → KPI tile", "steps": ["draft charter", "sign", "load into Hub", "render KPI tile", "anchor in WORM"], "controls": ["WebAuthn", "Ed25519 + ML-DSA-44", "Object Lock"]},
    {"id": "DF-02", "name": "Inference → WORM → replay → R2 report", "steps": ["sidecar emit envelope", "Kafka WORM", "daily Merkle", "replay engine", "R2 generator", "PAdES + ML-DSA-65 sign"], "controls": ["mTLS", "PQC", "deterministic seed", "PAdES"]},
    {"id": "DF-03", "name": "Cognitive Resonance breach → IR", "steps": ["monitor compute thresholds", "block + escalate", "incident triage prompt", "multisig kill-switch", "BMC/IPMI", "evidence pack"], "controls": ["≤ 60 s logical", "≤ 5 min physical"]},
    {"id": "DF-04", "name": "Annex IV pack auto-assembly", "steps": ["collect evidence", "section mapping", "judge tone", "PAdES + Sigstore", "deliver to supervisor-gateway"], "controls": ["≤ 30 min", "0 critical errors"]},
    {"id": "DF-05", "name": "Consortia attestation", "steps": ["compute metrics", "sign with ML-DSA-65", "submit to ICGC/GACRA/GASO/GAI-SOC", "anchor receipt in WORM"], "controls": ["monthly cadence", "PQC"]},
    {"id": "DF-06", "name": "Public verifier proof", "steps": ["read anchor", "compute Merkle proof", "build zk-SNARK", "publish endpoint"], "controls": ["uptime ≥ 99.95 %", "no PII leakage"]},
]

# ---------------------- regulators ----------------------
regulators = [
    {"id": "REG-01", "name": "EU Commission + AISI EU", "primary": "EU AI Act lead + safety institute"},
    {"id": "REG-02", "name": "ECB-SSM + EBA + ESMA", "primary": "EU prudential + securities"},
    {"id": "REG-03", "name": "PRA + Bank of England", "primary": "UK prudential"},
    {"id": "REG-04", "name": "FCA", "primary": "UK conduct + Consumer Duty + SMCR"},
    {"id": "REG-05", "name": "FRB + OCC + FDIC", "primary": "US prudential"},
    {"id": "REG-06", "name": "SEC + CFTC", "primary": "US markets"},
    {"id": "REG-07", "name": "MAS", "primary": "Singapore"},
    {"id": "REG-08", "name": "HKMA + SFC", "primary": "Hong Kong"},
    {"id": "REG-09", "name": "BoJ + FSA Japan", "primary": "Japan"},
    {"id": "REG-10", "name": "APRA + ASIC", "primary": "Australia"},
    {"id": "REG-11", "name": "OSFI + OPC Canada", "primary": "Canada prudential + privacy"},
    {"id": "REG-12", "name": "FSB + BIS + IMF + OECD + AISI (US/UK)", "primary": "Global + treaty"},
]

# ---------------------- workshops ----------------------
workshops = [
    {"id": "WS-01", "audience": "Board AI/Risk Cmte", "duration": "2 h", "outcome": "Risk appetite + tabletop sign-off + Closing Charge ratification"},
    {"id": "WS-02", "audience": "C-Suite + SMFs", "duration": "1 d", "outcome": "Operating model + SMCR responsibilities map"},
    {"id": "WS-03", "audience": "MRM + AI Risk + 2LoD", "duration": "1 d", "outcome": "Sector MRM playbook (credit, trading, fiduciary, CRS-UUID-001)"},
    {"id": "WS-04", "audience": "Platform Engineering + Enterprise Architecture", "duration": "2 d", "outcome": "K8s + Kafka WORM + OPA + Terraform bootcamp"},
    {"id": "WS-05", "audience": "SOC + IR + AI Safety Lead", "duration": "1 d", "outcome": "SEV-0..SEV-3 runbook + ASI honeypot drill"},
    {"id": "WS-06", "audience": "Internal Audit (3LoD)", "duration": "1 d", "outcome": "Replay + WORM verifier inspection + report R1..R4 walkthrough"},
    {"id": "WS-07", "audience": "Supervisor + AISI liaison", "duration": "0.5 d", "outcome": "Annex IV + SR 11-7 + R1..R4 demo + GAP attestation walkthrough"},
]

# ---------------------- privacy ----------------------
privacy = {
    "lawfulBasis": ["Legal obligation (Art 6(1)(c))", "Legitimate interest (Art 6(1)(f))", "Contract (Art 6(1)(b))"],
    "subjectRights": ["DSAR portal", "Art 17 erasure via machine unlearning", "Art 22 contestation + meaningful info"],
    "dataMinimization": ["eBPF redaction", "FL secure aggregation", "RAG ACL", "pseudonymous WORM", "zk-SNARK auditor access"],
    "transfers": "Per-jurisdiction residency; SCCs + supplementary measures; per-region keys",
    "dpia": "Mandatory for high-risk (credit, trading, fraud, AML, fiduciary advice)",
    "securityControls": ["zero-trust mTLS", "FIPS 204 PQC", "FIPS 140-3 L4 HSM", "WORM Object Lock", "SLSA L3+", "Kata confidential"],
}

# ---------------------- deployment ----------------------
deployment = [
    "Multi-region active-active EU primary; DR with RPO ≤ 1 h, RTO ≤ 4 h",
    "Kata Containers for Tier-1 + AMD SEV-SNP / Intel TDX where available",
    "Cilium L7 zero-egress with allow-listed egress-broker",
    "OPA Gatekeeper enforcing signed images (cosign + ML-DSA-44) + Kata for T1",
    "Kafka WORM cluster with SASL/SCRAM + mTLS ACLs + Object Lock + daily Merkle anchor",
    "FIPS 140-3 L4 HSM with PQC firmware; 90-day key rotation",
    "BMC/IPMI segmentation; Redfish event subscription to SOC + WORM",
    "GitHub Actions OIDC + Sigstore keyless + ML-DSA-44 hybrid + SLSA L3+ provenance",
    "Terraform golden modules signed (Sigstore); mandatory tags (owner, tier, dataClass, regime)",
    "OpenTelemetry GenAI tracing + Falco eBPF rules + Trivy + kube-bench",
    "Quarterly chaos drills: kill-switch, KMS outage, region failover, partition, ASI honeypot",
    "Public verifier endpoints for civil society + press to validate signed bulletins offline (zk-SNARK)",
    "Backups encrypted with PQC-hybrid envelope; cross-region anchor verification",
    "Firestore for prompt + DAG versioning (WorkflowAI Pro) with signed change-log",
]

# ---------------------- 30/60/90 rollout (compact) ----------------------
rollout90 = [
    {"day": "0-30", "track": "Foundations", "items": ["Hub read-only beta", "Sentinel v2.4 + OPA bundle v1", "Kafka WORM + daily anchor", "GitHub Actions Sigstore + ML-DSA-44 (T1)", "WebAuthn + RBAC", "Board charter signed", "Sector MRM inventory refresh"]},
    {"day": "31-60", "track": "Coverage", "items": ["Cilium zero-egress + Kata T1", "Annex IV / SR 11-7 pack GA", "2LoD red-team CI gate (Judge LLM)", "Multisig 3-of-5 kill-switch + BMC drill", "Replay engine top-5 models", "WorkflowAI Pro GA", "AlphaTrade-V9 + CRS-UUID-001 tabletop dry-run"]},
    {"day": "61-90", "track": "Hardening + MVAGS", "items": ["FIPS 204 ML-DSA migration", "Cognitive Resonance Monitor GA", "FL pilot EU + SG", "Art 17 unlearning + DSAR portal", "ASI honeypot deployment", "Consortia onboarding (ICGC + GACRA + GASO + GAI-SOC)", "Regulator demo + GAP attestation Q1 + R1..R4 reports"]},
]

# ---------------------- multi-year roadmap ----------------------
roadmap = [
    {"year": "2026", "focus": "MVAGS Day-90 + Coalition Activation", "milestones": ["MVAGS in production for all T1", "R1..R4 auto-generation", "Public verifier v1", "Coalition partners ≥ 5"]},
    {"year": "2027", "focus": "Frontier Containment + GAIVS Passport", "milestones": ["GAIVS evaluation passport", "GAICS containment audit", "FL in 4 jurisdictions", "Cognitive Resonance v2"]},
    {"year": "2028", "focus": "PQC + AI Capital Buffer + Treaty Interop", "milestones": ["FIPS 204 100 % WORM + AI BoM", "GFMCF AI capital buffer Pillar 3", "GATI + GAIGA disclosure", "Public verifier v2 (zk-SNARK)"]},
    {"year": "2029", "focus": "Civilizational-Grade Operations", "milestones": ["PQC classical retired for T1", "GAID + FTEWS bidirectional", "Institutional adoption ≥ 10 partners", "Closing Charge renewed"]},
    {"year": "2030", "focus": "Steady-State + Renewal", "milestones": ["Renewal Atlas refreshed", "Continuity Codex v3", "Coalition ≥ 20 partners", "Board literacy ≥ 95 %", "GAICS conformance 100 % for frontier"]},
]

# ---------------------- machine-readable artifacts by audience ----------------------
artifactsByAudience = {
    "Engineering": ["GitHub Actions workflows", "OPA Rego bundles", "Terraform modules signed", "Helm charts + Kustomize overlays", "Sidecar SDKs (Node.js + Python)"],
    "Legal": ["Signed AI BoM", "DPIA templates", "Art 13 / Art 22 disclosures", "ECOA + FCRA adverse-action templates", "SCC + transfer impact assessments"],
    "C-Suite": ["KPI tile JSON", "Risk-appetite JSON", "Quarterly executive pack PDF/A", "SMCR statements of responsibilities"],
    "Board": ["Board paper PDF/A", "Tabletop scorecards", "Risk appetite attestation", "Capital buffer attestation (GFMCF)"],
    "Regulator": ["Annex IV pack", "SR 11-7 pack", "R1..R4 reports", "GAP attestation", "Consortia feeds (ICGC + GACRA + GASO + GAI-SOC + GAIVS)"],
    "EnterpriseArchitecture": ["Reference architecture diagrams (C4)", "Data flow JSON", "Terraform golden envs", "API + event catalog"],
    "AIPlatformEngineering": ["Sidecar SDKs", "WorkflowAI Pro DAG specs", "Prompt registry export", "Eval harness suites"],
    "AISafetyResearch": ["Cognitive Resonance datasets", "Honeypot engagement corpus", "Sleeper-Agent eval suite", "Alignment paper drafts + replication scripts"],
}

# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": (
        "Deliver a comprehensive, implementation-focused master reference "
        "(2026-2030) on institutional-grade AGI/ASI and enterprise AI "
        "governance for Fortune 500, Global 2000, and G-SIFI institutions: "
        "unifying multilayered governance pillars, regulatory alignment, "
        "enterprise reference architectures, sector MRM, frontier AGI/ASI "
        "safety, global AI/compute governance, the Enterprise AI Governance "
        "Hub + AI Safety Report Generator + WorkflowAI Pro, advanced prompt "
        "engineering, the civilizational corpus, regulator-ready reports, "
        "implementation blueprints, tiered rollout, 30/60/90, and a "
        "2026-2030 multi-year roadmap with machine-readable artifacts."
    ),
    "approach": (
        "14-module reference with a machine-parsable directive, signed via "
        "Sigstore + ML-DSA-44, enforced by OPA Gatekeeper + Cilium, observed "
        "by Sentinel v2.4 + eBPF sidecars + Cognitive Resonance, audited by "
        "3LoD + supervisor replay tools, operationalised through MVAGS at "
        "Day-90 and extended to a 5-year roadmap with per-audience "
        "machine-readable artifacts."
    ),
    "deliverables": (
        "14 modules · 70 sections · 12 schemas · 16 code examples · 6 case "
        "studies · 24 supervisory KPIs · 12 risk-control rows · 12 "
        "regulators · 7 workshops · 6 data flows · 14 traceability rows · "
        "30/60/90-day rollout · 2026-2030 multi-year roadmap · "
        "machine-parsable <directive> block · R1..R4 report templates · "
        "per-audience machine-readable artifacts."
    ),
    "outcomes": [
        "MVAGS in production for all Tier-1 systems by Day 90",
        "Annex IV / SR 11-7 pack assembly ≤ 30 min, 0 critical errors",
        "SEV-0 logical kill-switch p95 ≤ 60 s; physical (BMC) ≤ 5 min",
        "Cognitive Resonance Δ_drift ≤ 4 % + latent drift ≤ 3 % + cosine ≥ 0.92",
        "Sigstore + ML-DSA-44 + OPA gate at admission for 100 % Tier-1 by Day 90",
        "Consortia attestations (ICGC + GACRA + GASO + GAI-SOC) live monthly",
        "R1..R4 reports auto-generated with <title>/<abstract>/<content> tags",
        "Coalition Activation ≥ 5 partners by Year 1; ≥ 20 by 2030",
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
DOC["artifactsByAudience"] = artifactsByAudience
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
    "artifactAudiences": len(artifactsByAudience),
    "apiRoutes": 100,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
print("counts:", DOC["counts"])
