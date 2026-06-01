#!/usr/bin/env python3
"""WP-044 — CEGL / LexAI-DSL / FV-LexAI Global AI Systemic Risk Governance.

Builds data/cegl-lexai-gov.json: a comprehensive design, governance,
architecture, and supervisory framework for global AI systemic risk
governance in financial services and planetary-scale civilizational
governance (2026-2035).
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "cegl-lexai-gov.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "CEGL-LEXAI-GOV-WP-044",
    "version": "1.0.0",
    "horizon": "2026-2035",
    "classification": "CONFIDENTIAL — Heads of State / Central Bank Governors / IMF MD / G-SIFI Boards / Treaty Authority / AI Safety Institute / CAIO / CRO / CISO",
    "title": "CEGL / LexAI-DSL / FV-LexAI — Global AI Systemic Risk Governance & Civilizational Codex Meta-Governance Framework",
    "subtitle": "Regulator-Facing Briefings, Supervisory Drills, Federated Simulations, GASRGP/GASC/GAISM Treaty Stack, Global Trust Index & Trust Derivatives Layer, Central Bank/IMF Integration, Global Deliberation Protocol, Engineering Blueprints, Pilot Treaties & Public Communication (2026-2035)",
    "owner": "Treaty Liaison + CAIO + CRO; co-signed by Central Bank Governor liaison, IMF liaison, CISO, GC, DPO, Head of Internal Audit, AI Safety Lead, Civic Legitimacy Council Chair",
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
    ],
    "regimes": [
        "EU AI Act 2026 (Arts 5/9/10/13/14/50/53/55/56)",
        "NIST AI RMF 1.0 + Generative AI Profile",
        "ISO/IEC 42001 (AIMS)",
        "ISO/IEC 23894 / 5338 / 38507",
        "GDPR Arts 5/22/25/35",
        "Basel III/IV (BCBS 239 risk data aggregation)",
        "SR 11-7 (US Fed Model Risk Management)",
        "FCA Consumer Duty / SMCR",
        "PRA SS1/23 (model risk)",
        "MAS FEAT Principles + AI Verify",
        "HKMA SPM GS-1 / GL-90",
        "SEC AI rules (broker-dealer/investment-adviser proposals)",
        "FDIC AI Guidance",
        "OECD AI Principles 2024",
        "G7 Hiroshima AI Process Code of Conduct",
        "UN GA Resolution A/78/L.49 (AI for SDGs)",
        "Council of Europe AI Convention (Framework Convention)",
        "FSB recommendations on AI in financial services",
    ],
    "apiPrefix": "/api/cegl-lexai-gov",
}

# ---------------------- 14 modules ----------------------
modules = []

modules.append({
    "id": "M1",
    "title": "M1 — CEGL Conceptual Framework & Civilizational Codex Meta-Governance",
    "summary": "Civilizational Ethical Governance Layer (CEGL) — the meta-governance substrate for planetary-scale AI systems, anchored to a Civilizational Codex of axioms, principles, and red lines.",
    "covers": ["CEGL", "Civilizational Codex", "axioms", "red lines", "meta-governance"],
    "sections": [
        section("M1-S1", "Mission & Scope", {
            "mission": "Provide a regulator-ready, treaty-aligned, formally-verifiable governance substrate for AI systems that pose systemic or civilizational risk, integrating financial-services prudential supervision with planetary-scale civilizational governance.",
            "scope": [
                "Frontier AGI/ASI capability classes (foundation models > GPAI threshold)",
                "G-SIFI / G-SII AI deployments (credit, trading, insurance, AML, fiduciary advisory)",
                "Cross-border data, compute, and model artifact flows",
                "Public-good and public-sector AI used at planetary scale (climate, pandemic, infra)",
            ],
            "outOfScope": ["Purely consumer recommender systems below GPAI thresholds", "Local research-only sandboxes with no production exposure"],
        }),
        section("M1-S2", "CEGL Layered Stack", [
            "L0 Civilizational Codex (axioms, red lines, dignity, sovereignty, ecological integrity)",
            "L1 Treaty Stack (GASRGP, GASC, GAISM)",
            "L2 LexAI-DSL Normative Layer (machine-readable law, controls, conflict-of-laws)",
            "L3 FV-LexAI Formal-Verification Layer (proofs, model checking, property tests)",
            "L4 Supervisory Plane (regulators, central banks, IMF, FSB, treaty authority)",
            "L5 Operational Plane (G-SIFIs, model providers, compute hosts, registries)",
            "L6 Citizen Plane (Global Deliberation Protocol, participatory legitimacy)",
        ]),
        section("M1-S3", "Civilizational Codex — 12 Axioms (excerpt)", [
            "A1 Human dignity and inalienable rights take precedence over efficiency.",
            "A2 No autonomous lethal targeting; humans retain meaningful control over force.",
            "A3 Critical infrastructure must remain controllable under degraded AI conditions.",
            "A4 Catastrophic and existential risks require precautionary, irreversibility-aware controls.",
            "A5 Privacy by design and data minimization are non-negotiable.",
            "A6 Non-discrimination across protected and proxy attributes.",
            "A7 Transparency commensurate with risk; provenance and disclosure for synthetic media.",
            "A8 Plurality and contestability — no single jurisdiction dominates norm-setting unilaterally.",
            "A9 Ecological integrity and intergenerational fairness.",
            "A10 Compute and model lifecycles must be auditable and accountable.",
            "A11 Crisis controllability — kill-switch, containment, rollback are first-class.",
            "A12 Legitimacy through participation — affected publics must have voice in shaping norms.",
        ]),
        section("M1-S4", "Red Lines (hard prohibitions)", [
            "Autonomous nuclear, biological, chemical, or radiological release decisions",
            "Mass surveillance scoring of populations without rule-of-law protections",
            "Manipulative AI targeting cognitive vulnerabilities of children/elderly",
            "Replacement of judicial sentencing with autonomous AI",
            "Deceptive impersonation of public officials by AI",
            "Self-replication beyond authorized compute and jurisdiction",
        ]),
        section("M1-S5", "Why a Codex Layer is Necessary", [
            "Cross-border conflict-of-laws creates regulatory arbitrage; a Codex provides a common normative anchor.",
            "Civilizational risks are non-actuarial; pure capital-based regulation is insufficient.",
            "Treaty law must be machine-readable to enable real-time supervisory enforcement.",
            "Legitimacy of frontier AI rules requires citizen-plane input, not only regulator-plane.",
        ]),
    ],
})

modules.append({
    "id": "M2",
    "title": "M2 — LexAI-DSL: Machine-Readable Law for AI Systems",
    "summary": "A domain-specific language for expressing legal obligations, controls, conflict-of-laws, and remedies as executable, auditable artifacts.",
    "covers": ["DSL", "machine-readable law", "controls", "conflict-of-laws", "remedies"],
    "sections": [
        section("M2-S1", "Design Goals", [
            "Bridges natural-language law and runtime policy enforcement",
            "Supports parallel obligations across jurisdictions with declared precedence",
            "Compiles to OPA/Rego, Cedar, Datalog, and Lean/Coq proof obligations",
            "Versioned, signed, hash-chained; every clause has a SHA-256 identity",
        ]),
        section("M2-S2", "Core Constructs", [
            "obligation { id, source, predicate, subject, object, temporal, remedy, conflict_priority }",
            "permission { id, source, conditions, sunset }",
            "prohibition { id, source, scope, exceptions, enforcement_class }",
            "definition { term, meaning, jurisdiction, version }",
            "evidence_requirement { id, controlRef, artifactType, signing, retention }",
            "remedy { id, classes[], severity, repair_action, restitution }",
        ]),
        section("M2-S3", "Conflict-of-Laws Resolver", {
            "approach": "Lattice of jurisdictions + lex superior/posterior/specialis rules; explicit precedence override by treaty article",
            "deterministic": "Resolver is a pure function over (clauseSet, context) → decision; replayable under FV-LexAI proof",
        }),
        section("M2-S4", "Authoring & Lifecycle", [
            "Drafted by joint counsel + AI ethicists + technical SMEs",
            "Signed by designated authority of source jurisdiction",
            "Hash-chained to Treaty Ledger; rollouts via signed bundles",
            "Sunset clauses default ON unless renewed; audited annually",
        ]),
        section("M2-S5", "Example LexAI-DSL Clause (excerpt)", [
            "obligation EU_AIACT_ART14_OVERSIGHT {",
            "  source: 'EU AI Act 2026 Art 14',",
            "  subject: provider | deployer,",
            "  predicate: ensure_human_oversight(system, controls = ['stop','override','review']),",
            "  temporal: continuous,",
            "  evidence: [DecisionEnvelope, OverrideLog],",
            "  remedy: REM_HUMAN_OVERSIGHT_RESTORE,",
            "  conflict_priority: 90",
            "}",
        ]),
    ],
})

modules.append({
    "id": "M3",
    "title": "M3 — FV-LexAI: Formal Verification of LexAI-DSL Properties",
    "summary": "Formal-methods layer that proves safety, liveness, and conformance properties over LexAI-DSL bundles and runtime control planes.",
    "covers": ["formal verification", "model checking", "property tests", "proofs"],
    "sections": [
        section("M3-S1", "Property Catalogue (sample)", [
            "P1 Safety: no run reaches 'release' state without human-oversight evidence (Art 14)",
            "P2 Liveness: every run eventually emits a Decision Envelope with provenance",
            "P3 Non-discrimination: bounded disparate impact over protected attributes ≤ ε",
            "P4 Consistency: conflict-of-laws resolver is deterministic and total",
            "P5 Containment: kill-switch propagation ≤ 60 s under partial-failure model",
            "P6 Privacy: PII does not appear in audit payloads (only HMAC pseudonyms)",
            "P7 Reversibility: no irreversible action without N-eyes co-sign + cool-down",
        ]),
        section("M3-S2", "Tooling", {
            "modelChecking": "TLA+ / Apalache for protocol-level invariants",
            "theoremProving": "Lean 4 / Coq for Codex axioms and resolver totality",
            "smtSolver": "Z3 / CVC5 for clause satisfiability and conflict detection",
            "runtimeMonitors": "Differential property monitors emit SEV events on violation",
            "fuzzers": "Property-based fuzzing on policy bundles (Hypothesis / Proptest)",
        }),
        section("M3-S3", "Continuous Verification Pipeline", [
            "Every signed LexAI bundle triggers FV-LexAI CI: parse → typecheck → SMT → model-check → proof-replay",
            "Failure blocks bundle deployment globally; signed proof artifacts archived to WORM",
            "Quarterly red-team verification by independent AI Safety Institute",
        ]),
        section("M3-S4", "Proof-Carrying Bundles", {
            "format": "PCB { bundleHash, properties[], proofArtifacts[], verifierSignatures[], expiry }",
            "distribution": "PCBs signed by Treaty Authority + AI Safety Institute; sidecars verify before activation",
        }),
    ],
})

modules.append({
    "id": "M4",
    "title": "M4 — Treaty Stack: GASRGP, GASC, GAISM",
    "summary": "Three interlocking treaty instruments forming the global AI systemic-risk governance protocol, AI Safety Convention, and AI Stability Mechanism.",
    "covers": ["GASRGP", "GASC", "GAISM", "treaties"],
    "sections": [
        section("M4-S1", "GASRGP — Global AI Systemic Risk Governance Protocol", {
            "purpose": "Set baseline obligations for frontier AI systems with cross-border systemic impact (financial + civilizational).",
            "keyArticles": [
                "Art 1 Definitions (Frontier Model, Systemic Importance, Compute Threshold)",
                "Art 4 Pre-deployment evaluation & registration",
                "Art 7 Cross-border incident reporting (≤ 24 h SEV-1)",
                "Art 11 Compute governance & licensing of >10^26 FLOP training runs",
                "Art 14 Mutual recognition of supervisory drill outcomes",
                "Art 18 Treaty-anchored kill-switch obligations",
            ],
        }),
        section("M4-S2", "GASC — Global AI Safety Convention", {
            "purpose": "Bind signatories to red-line prohibitions and rights protections (analogous to chemical/biological conventions).",
            "keyArticles": [
                "Art 2 Prohibition on autonomous lethal force decisions",
                "Art 5 Prohibition on manipulative cognitive targeting",
                "Art 9 Provenance & disclosure for synthetic media at scale",
                "Art 12 Independent verification and inspection rights",
            ],
        }),
        section("M4-S3", "GAISM — Global AI Stability Mechanism", {
            "purpose": "IMF/FSB-anchored macroprudential mechanism for AI-driven systemic financial risk; provides liquidity, capital overlays, and resolution tools.",
            "instruments": [
                "AI Capital Overlay (RWA add-on for high-risk model exposures)",
                "AI Liquidity Facility (24-72 h backstop during AI-induced market stress)",
                "AI Resolution Authority (recovery, resolution of AI-coupled failures)",
                "Cross-Border AI Stress Test (annual, BCBS 239 + AI dimension)",
            ],
        }),
        section("M4-S4", "Interactions & Precedence", [
            "GASC red lines have lex superior over GASRGP economic provisions",
            "GAISM macroprudential measures complement GASRGP supervisory tools",
            "All three instruments encode their clauses in LexAI-DSL with hash-chained identity",
        ]),
        section("M4-S5", "Pilot Treaties & Sunrise Clauses", [
            "Pilot 1 (2026-2027): EU + UK + US + Japan + Singapore — voluntary GASRGP Annex on incident reporting and compute disclosure",
            "Pilot 2 (2027-2028): Joint EU-UK-US AI Stress Test under GAISM observer status",
            "Sunrise: full GAISM activation when ≥ 8 G20 jurisdictions ratify AI Capital Overlay schedule",
        ]),
    ],
})

modules.append({
    "id": "M5",
    "title": "M5 — Global Trust Index (GTI) & Trust Derivatives Layer (TDL)",
    "summary": "Quantitative index of AI system trustworthiness with derivative instruments for risk transfer; integrates with central-bank capital and IMF surveillance.",
    "covers": ["GTI", "TDL", "trust derivatives", "capital overlay", "surveillance"],
    "sections": [
        section("M5-S1", "GTI Composition", {
            "subIndices": [
                "TI-Safety (containment, kill-switch responsiveness, incident-free uptime)",
                "TI-Fairness (disparate-impact bounds, contestability rate)",
                "TI-Privacy (PII leakage, DSAR turnaround, pseudonymization coverage)",
                "TI-Robustness (adversarial robustness, distributional drift)",
                "TI-Transparency (explainability ratio, provenance coverage)",
                "TI-Accountability (audit chain integrity, reviewer independence)",
            ],
            "weighting": "Sector-specific weights (banking 0.35 safety + 0.25 accountability + ...); reviewed annually by FSB",
            "publication": "Tiered: anonymized public dashboard; institution-level to supervisors; provider-level to AISI",
        }),
        section("M5-S2", "Computation & Attestation", [
            "Inputs are hash-chained Decision Envelopes + supervisory attestations; no self-attestation only",
            "Independent evaluators sign sub-index calculations; multi-evaluator quorum required",
            "Daily Merkle anchor to Treaty Ledger and (optionally) public chain",
        ]),
        section("M5-S3", "Trust Derivatives Layer (TDL)", {
            "instruments": [
                "Trust-Linked Bond (TLB) — coupon steps when GTI breaches sector floor",
                "Trust Default Swap (TDS) — credit-default-swap-like protection on AI-induced losses",
                "Capital Overlay Swap — exchanges static RWA add-on for GTI-linked variable overlay",
                "AI Resilience Bond — sovereign issuance to fund GAISM facility",
            ],
            "marketStructure": "Cleared through CCPs with AI risk margining; supervised by ECB/SEC/MAS jointly under TDL Charter",
            "guardrails": "Position limits per institution; ban on writing protection by entities below GTI floor; circuit breakers on TDL spreads ≥ X bps",
        }),
        section("M5-S4", "Central-Bank & IMF Integration", [
            "ECB / Fed / BoE / BoJ / PBoC / MAS use GTI as input to AI Capital Overlay calibration",
            "IMF Article IV surveillance includes GTI trajectory and TDL exposure at country level",
            "FSB AI Vulnerabilities Report cites GTI heatmap quarterly",
        ]),
    ],
})

modules.append({
    "id": "M6",
    "title": "M6 — Federated Supervisory Drills & Cross-Border AI Stress Tests",
    "summary": "Coordinated, annual federated simulations across regulators and G-SIFIs that exercise containment, resolution, communication, and citizen-plane pathways.",
    "covers": ["drills", "stress tests", "federated simulation", "scenarios"],
    "sections": [
        section("M6-S1", "Drill Catalogue", [
            "DR-01 LEVEL-5 Containment Breach (foundation model deceptive alignment)",
            "DR-02 Cross-Border Trading Anomaly (AI-driven flash event across 3 jurisdictions)",
            "DR-03 Synthetic-Media Bank Run (deepfake CEO triggers run on G-SIB)",
            "DR-04 Cyber-Physical Critical-Infrastructure AI Compromise (energy / payments)",
            "DR-05 Cross-Border Data Sovereignty Crisis (model weights subpoena conflict)",
            "DR-06 Climate-Finance AI Misalignment (systemic mispricing of transition risk)",
        ]),
        section("M6-S2", "Architecture", {
            "controlPlane": "Joint Drill Operations Center (J-DOC) federated across regulators",
            "dataPlane": "Synthetic markets + sandboxed model replicas; no production funds at risk",
            "comms": "Rehearsed signed-bulletin channels between supervisors, treaty authority, AISI, and CCPs",
            "scoring": "Time-to-contain, MTTR, kill-switch latency, citizen-plane comms quality, market-stability metrics",
        }),
        section("M6-S3", "Stress-Test Methodology", [
            "Severity tiers calibrated to GAISM AI-shock scenarios (Adverse / Severely Adverse / Apocalyptic)",
            "Models: agent-based market sim + LLM-driven counterparties + macro overlay",
            "Capital and liquidity impact under AI-coupled tail; reverse stress to find first failure",
            "Lessons codified in updated LexAI-DSL bundles within 90 days",
        ]),
        section("M6-S4", "Mutual Recognition & Sharing", [
            "Drill outcomes signed by participating supervisors; mutually recognized under GASRGP Art 14",
            "Shared via Treaty Ledger with redacted public summaries",
            "Independent observers from civil society and AISI ensure legitimacy",
        ]),
    ],
})

modules.append({
    "id": "M7",
    "title": "M7 — Regulator-Facing Briefing Decks & Communication Strategy",
    "summary": "Standardized briefing templates and a multi-stakeholder communication strategy for supervisors, central banks, IMF, treaty parties, and the public.",
    "covers": ["briefings", "decks", "comms", "narratives"],
    "sections": [
        section("M7-S1", "Briefing Deck Templates (sample)", [
            "BD-01 Heads-of-State briefing (10 slides, 15 min) — strategic posture & treaty status",
            "BD-02 Central-Bank Governor briefing — GTI heatmap, GAISM facility status, AI Capital Overlay",
            "BD-03 IMF Article IV / FSB plenary briefing — country GTI trajectory, TDL exposure",
            "BD-04 G-SIFI Board briefing — adversarial findings, kill-switch drills, capital impact",
            "BD-05 Parliamentary committee briefing — rights, contestability, citizen oversight",
            "BD-06 Public press briefing — plain-language risk and mitigations",
        ]),
        section("M7-S2", "Narrative Architecture", [
            "Anchor on Codex axioms (dignity, controllability, legitimacy) before metrics",
            "Use precedent analogies (financial crisis, biosafety, aviation safety) sparingly and accurately",
            "Distinguish 'what we know', 'what we don't know', 'what we are doing'",
            "Always include rights, redress, and contestability pathways for citizens",
        ]),
        section("M7-S3", "Crisis Communication Playbook", [
            "T+0 holding statement within 30 min of SEV-0/1 incident",
            "Coordinated bulletins across supervisors, providers, and treaty authority",
            "Plain-language disclosures with provenance; signed and timestamped",
            "Counter-deepfake protocol with verified press cryptographic signatures",
        ]),
        section("M7-S4", "Stakeholder Map", [
            "Regulators: ECB, PRA, FCA, MAS, HKMA, SEC, FDIC, OCC, CFTC, JFSA",
            "Multilaterals: IMF, FSB, BIS, OECD, UN, COE",
            "Industry: G-SIFI boards, model providers, CCPs, exchanges",
            "Civic: Parliaments, civil-society, academia, AI Safety Institutes",
        ]),
    ],
})

modules.append({
    "id": "M8",
    "title": "M8 — Global Deliberation Protocol (GDP-AI) & Participatory Legitimacy",
    "summary": "Mechanism for citizen-plane participation in AI norm-setting through stratified deliberative juries, public consultations, and binding sortition panels.",
    "covers": ["deliberation", "sortition", "legitimacy", "participation"],
    "sections": [
        section("M8-S1", "Why a Citizen Plane", [
            "AI rules implicate fundamental rights; democratic legitimacy is required for hard prohibitions and contestable trade-offs",
            "Stakeholder capture risk if only providers and regulators set norms",
            "Cross-border instruments require cross-cultural, cross-class participation",
        ]),
        section("M8-S2", "Mechanism Design", [
            "Stratified random sampling (sortition) across age, gender, region, income",
            "Deliberation in 3 rounds: learning → discussion → decision; AI-assisted but not AI-decided",
            "Outputs feed LexAI-DSL drafts as 'Citizen Recommendations' with traceable amendments",
            "Veto-light: panels may flag a clause for parliamentary review (not unilateral veto)",
        ]),
        section("M8-S3", "Anti-Manipulation Safeguards", [
            "All inputs to panels signed and provenance-tagged; deepfake screening at input",
            "Independent fact-checking ombud; right of reply across viewpoints",
            "No targeted persuasion; AI tools used only for translation and summarization",
        ]),
        section("M8-S4", "Cadence & Funding", [
            "Annual global panel + on-demand panels for novel high-risk capabilities",
            "Funding via Treaty Authority levy on frontier-model providers; ring-fenced budget",
            "Independent secretariat with rotating chairs from civil society",
        ]),
    ],
})

modules.append({
    "id": "M9",
    "title": "M9 — Engineering Reference Architecture & APIs",
    "summary": "Reference architecture, service decomposition, APIs, schemas, and trust roots that operationalize CEGL/LexAI-DSL/FV-LexAI globally.",
    "covers": ["architecture", "APIs", "schemas", "trust roots"],
    "sections": [
        section("M9-S1", "Service Decomposition", [
            "codex-svc (Civilizational Codex registry, hash-chained axioms)",
            "lexai-svc (LexAI-DSL parser, typecheck, conflict resolver, bundle issuer)",
            "fv-lexai-svc (FV pipeline: SMT, model-check, proof-replay)",
            "treaty-ledger-svc (append-only, hash-chained ledger of treaty events)",
            "gti-svc (Global Trust Index computation & attestation)",
            "tdl-svc (Trust Derivatives Layer reference data & valuation feeds)",
            "drill-svc (Federated drill orchestration)",
            "deliberation-svc (sortition panels, voting integrity)",
            "supervisor-gateway-svc (regulator integration: ECB/PRA/FCA/MAS/HKMA/SEC/FDIC)",
            "kill-switch-svc (multisig containment propagation)",
        ]),
        section("M9-S2", "API Surface (excerpt)", [
            "POST /lexai/bundles { dsl, signatures } → bundleHash",
            "GET  /lexai/bundles/:hash → bundle + PCB",
            "POST /fv/verify { bundleHash, properties[] } → proofArtifacts[]",
            "POST /treaty/ledger/events { type, payload, sigs[] } → eventId, merkleProof",
            "GET  /gti/{institutionId} → { score, subIndices, asOf, attestations[] }",
            "POST /drills/scenarios/{id}/start → drillId",
            "POST /killswitch/invoke { scope, reason, cosignatures[] } → status",
            "POST /deliberation/panels { topic } → panelId",
            "GET  /supervisor/{regulatorId}/dashboards → dashboards[]",
        ]),
        section("M9-S3", "Schemas (canonical)", [
            "TreatyEvent { id, type, payload, sigs[], merkleProof, prevHash, thisHash, ts }",
            "LexAIBundle { hash, dsl, sigs[], pcb?, sunset?, version }",
            "ProofArtifact { propertyId, prover, proofRef, verifierSigs[] }",
            "GTIRecord { institutionId, score, subIndices, asOf, attestations[] }",
            "DrillRun { id, scenarioId, participants[], scores, lessonsLexAI[] }",
        ]),
        section("M9-S4", "Trust Roots & PKI", [
            "Treaty Authority Root CA (HSM-backed, FIPS 140-3 L4)",
            "Per-jurisdiction Sub-CAs for supervisors and AISI",
            "Provider CAs with HSM-backed signing keys for Decision Envelopes",
            "Post-quantum hybrid signatures (Ed25519 + ML-DSA-65) on critical bundles",
        ]),
        section("M9-S5", "Data Residency & Sovereignty", [
            "Per-jurisdiction data residency with cross-border attestation only",
            "Confidential compute (TEE: SEV-SNP / TDX / Nitro) for sensitive evaluations",
            "Mutually-authenticated cross-border channels (mTLS + workload identity)",
        ]),
    ],
})

modules.append({
    "id": "M10",
    "title": "M10 — Infrastructure, CI/CD, and Deployment Blueprints",
    "summary": "Infrastructure-as-code blueprints, gated CI/CD pipelines, golden environments, and runbooks for CEGL/LexAI services across cloud and on-prem.",
    "covers": ["IaC", "CI/CD", "golden envs", "runbooks"],
    "sections": [
        section("M10-S1", "Reference Topology", [
            "3-region active-active control plane (EU, US, APAC) with per-region failover",
            "Air-gapped sensitive enclaves for FV-LexAI proof generation",
            "Confidential VMs / TEEs for treaty event signing and kill-switch propagation",
            "Object-store WORM buckets for Treaty Ledger cold tier with bucket lock",
        ]),
        section("M10-S2", "Terraform Modules (excerpt)", [
            "modules/treaty-ledger (Kafka WORM topic + ACL + KMS CMK + WORM bucket)",
            "modules/lexai-svc (K8s deployments + OPA Gatekeeper + service mesh)",
            "modules/fv-lexai-svc (air-gapped node pool + GPU optional + signed image policy)",
            "modules/gti-svc (multi-region read replicas + CCP feeds)",
            "modules/kill-switch (multisig HSM + global anycast + sub-60s propagation)",
        ]),
        section("M10-S3", "CI/CD Gates", [
            "G0 source: SBOM + SAST + secret scan + license check",
            "G1 build: reproducible build + Sigstore sign + SLSA Level 3+",
            "G2 verify: FV-LexAI property pack runs on touched bundles",
            "G3 conformance: OPA conftest on K8s/IaC; admission via signed image policy",
            "G4 release: blue/green or canary; auto-rollback on KPI breach (GTI floor, error budget)",
        ]),
        section("M10-S4", "Runbooks", [
            "RB-01 LEVEL-5 containment drill execution",
            "RB-02 Treaty bundle hot-swap with multisig",
            "RB-03 Cross-border incident reporting (≤24 h SEV-1)",
            "RB-04 Kill-switch invocation & restoration",
            "RB-05 Deliberation panel convening and integrity attestation",
            "RB-06 GTI re-attestation after evaluator dispute",
            "RB-07 TDL circuit-breaker activation and CCP coordination",
        ]),
    ],
})

modules.append({
    "id": "M11",
    "title": "M11 — Sector Mapping: Banking, Markets, Insurance, Payments",
    "summary": "Concrete mapping of CEGL/LexAI-DSL to financial-services use cases under SR 11-7, Basel, FCA Consumer Duty, MAS FEAT.",
    "covers": ["banking", "markets", "insurance", "payments"],
    "sections": [
        section("M11-S1", "Banking — Credit Decisioning", [
            "Models registered with hash-chained model card; SR 11-7 + EU AI Act Art 10/14",
            "Adverse-action letters under FCRA §615(a) emit Decision Envelope with explanations",
            "GTI sub-index threshold gates production deployment",
        ]),
        section("M11-S2", "Markets — Trading & Surveillance", [
            "AI trading agents declared; circuit breakers tied to TDL spreads and GTI floor",
            "Cross-border anomaly drills (DR-02) coordinated with CCPs and exchanges",
            "Insider risk monitored with privacy-preserving analytics (TEE + DP)",
        ]),
        section("M11-S3", "Insurance — Underwriting & Claims", [
            "Disparate-impact bound ε declared per product; recalibration triggers reviewer panel",
            "AI-assisted claims must preserve appeal pathways; explainability ≥ 90% threshold",
            "Solvency II / IAIS interplay with GTI overlay",
        ]),
        section("M11-S4", "Payments & AML/CFT", [
            "AI screening models register data lineage; FATF-aligned LexAI-DSL bundles",
            "False-positive metrics published quarterly; sector minimums coded as obligations",
            "Cross-border STR sharing coordinated through supervisor-gateway-svc",
        ]),
    ],
})

modules.append({
    "id": "M12",
    "title": "M12 — Civil-Society, Academia, and AI Safety Institute Integration",
    "summary": "Pathways for independent oversight, research access, contestability, and public-interest evaluation of frontier AI under treaty protection.",
    "covers": ["civil society", "academia", "AISI", "contestability"],
    "sections": [
        section("M12-S1", "Independent Verification Rights", [
            "Treaty-protected audit rights for AISI and credentialed academic teams",
            "Access to model weights for safety evaluation under TEEs and confidentiality contracts",
            "Pre-publication coordinated disclosure window (90 d) for critical findings",
        ]),
        section("M12-S2", "Contestability Pathways", [
            "Citizen and SME redress portal with case management and SLAs",
            "Independent ombud with subpoena-equivalent powers within scope",
            "Reversal of automated decisions on identified harm",
        ]),
        section("M12-S3", "Research Commons", [
            "Pseudonymized datasets and benchmarks under federated access",
            "Compute grants for public-interest evaluations (red-team battery)",
            "Open standards for evaluation reproducibility",
        ]),
        section("M12-S4", "Public Reports", [
            "Annual AI State of the Civilization report by Treaty Authority + AISI consortium",
            "Quarterly GTI heatmaps and TDL exposure summaries",
            "Multilingual lay summaries for public deliberation",
        ]),
    ],
})

modules.append({
    "id": "M13",
    "title": "M13 — Risk Register, KPIs & Maturity Model",
    "summary": "Risk register across systemic, civilizational, geopolitical, technical, and legitimacy dimensions; supervisory KPIs and a maturity model from Tier 0 to Tier 5.",
    "covers": ["risk register", "KPIs", "maturity model"],
    "sections": [
        section("M13-S1", "Risk Register (excerpt)", [
            "RR-01 Frontier model deceptive alignment",
            "RR-02 Cross-border regulatory arbitrage",
            "RR-03 AI-induced market dislocation (flash event)",
            "RR-04 Synthetic-media bank run / public-trust collapse",
            "RR-05 Compute concentration and supply chain capture",
            "RR-06 Treaty fragmentation / non-ratification",
            "RR-07 Citizen-plane delegitimization (capture)",
            "RR-08 PQC migration delay",
            "RR-09 Critical-infrastructure AI compromise",
            "RR-10 Climate-finance AI misalignment",
        ]),
        section("M13-S2", "Maturity Model (Tier 0–5)", [
            "T0 Ad-hoc — governance-by-policy-document; no machine-readable controls",
            "T1 Defined — LexAI-DSL bundles for top-N regimes; manual conformance",
            "T2 Managed — automated CI/CD gates + GTI sub-index measurement",
            "T3 Integrated — federated drills + cross-border ledger + TDL pilots",
            "T4 Predictive — FV-LexAI proof-carrying bundles + predictive systemic risk",
            "T5 Anticipatory — full Codex-anchored, citizen-plane-legitimized governance",
        ]),
        section("M13-S3", "Resource Plan (illustrative)", [
            "Year 1: 60 FTE (legal/eng/safety/comms) + 2 regional hubs",
            "Year 3: 220 FTE + 5 hubs + AISI partnerships",
            "Year 5: 480 FTE + global secretariat + standing deliberation infrastructure",
        ]),
    ],
})

modules.append({
    "id": "M14",
    "title": "M14 — Roadmap 2026-2035 and Milestones",
    "summary": "Phased roadmap from pilot treaties to mature CEGL with full citizen-plane participation, including milestones, dependencies, and KPIs.",
    "covers": ["roadmap", "milestones", "dependencies"],
    "sections": [
        section("M14-S1", "Phase 1 (2026-2027) — Pilot Treaties & Tooling", [
            "GASRGP Annex pilot with EU/UK/US/JP/SG",
            "LexAI-DSL v1.0 + FV-LexAI v0.5 (P1, P2, P5 properties)",
            "Treaty Ledger MVP; Decision Envelope schema standardized",
            "First federated drill (DR-01) with 5 regulators",
        ]),
        section("M14-S2", "Phase 2 (2028-2029) — GAISM Observer & GTI v1.0", [
            "GAISM Observer status; first AI Stress Test",
            "GTI v1.0 published quarterly; TDL pilot with 2 CCPs",
            "Deliberation panels piloted in 3 jurisdictions",
            "FV-LexAI v1.0 with proof-carrying bundles",
        ]),
        section("M14-S3", "Phase 3 (2030-2032) — Full Treaty Activation", [
            "GAISM activation upon ratification by ≥ 8 G20 jurisdictions",
            "GASC accession by ≥ 30 states",
            "TDL graduates from pilot; AI Capital Overlay live in major banks",
            "Annual cross-border AI stress test with mutual recognition",
        ]),
        section("M14-S4", "Phase 4 (2033-2035) — Maturity & Civilizational Integration", [
            "T5 maturity in early-adopter G-SIFIs",
            "Standing global deliberation infrastructure",
            "Climate-finance AI alignment program",
            "Codex axiom updates ratified through citizen-plane",
        ]),
        section("M14-S5", "Dependencies & Risks to Plan", [
            "Geopolitical alignment in 2026-2028 window",
            "PQC migration of trust roots by 2030",
            "Independent AISI capacity scaling",
            "Public legitimacy through transparent deliberation",
        ]),
    ],
})


# ---------------------- schemas (12) ----------------------
schemas = [
    {"id": "civilizationalAxiom", "title": "Civilizational Codex Axiom", "fields": ["id", "title", "text", "scope", "version", "ratifiedBy[]", "checksum"]},
    {"id": "lexaiBundle", "title": "LexAI-DSL Bundle", "fields": ["hash", "dsl", "signatures[]", "version", "sunset?", "pcbRef?"]},
    {"id": "lexaiClause", "title": "LexAI Clause", "fields": ["id", "type", "source", "subject", "predicate", "temporal", "evidence[]", "remedyRef", "conflict_priority"]},
    {"id": "proofArtifact", "title": "FV-LexAI Proof Artifact", "fields": ["propertyId", "prover", "method (TLA+|Lean|Coq|Z3)", "proofRef", "verifierSignatures[]", "expiry"]},
    {"id": "treatyEvent", "title": "Treaty Ledger Event (WORM)", "fields": ["id", "type", "payload", "signatures[]", "prevHash", "thisHash", "merkleProof", "ts"]},
    {"id": "decisionEnvelope", "title": "Decision Envelope", "fields": ["envelopeId", "actor", "action", "resourceRef", "modelRef", "policyDecisions[]", "explanations", "redactionsApplied", "prevHash", "thisHash", "signatures[]", "ts"]},
    {"id": "gtiRecord", "title": "Global Trust Index Record", "fields": ["institutionId", "score", "subIndices", "asOf", "attestations[]", "evaluatorQuorum"]},
    {"id": "tdlInstrument", "title": "Trust Derivative Instrument", "fields": ["isin", "type (TLB|TDS|COS|RES)", "issuer", "underlyingGTI", "trigger", "notional", "maturity"]},
    {"id": "drillRun", "title": "Federated Drill Run", "fields": ["id", "scenarioId", "participants[]", "scores", "lessonsLexAI[]", "signatures[]"]},
    {"id": "deliberationPanel", "title": "Deliberation Panel", "fields": ["panelId", "topic", "sortitionStrata", "rounds[]", "outputs[]", "integrityAttestation"]},
    {"id": "supervisorAttestation", "title": "Supervisor Attestation", "fields": ["regulatorId", "subjectInstitutionId", "scope", "findings", "ts", "signature"]},
    {"id": "killSwitchEvent", "title": "Kill-Switch Event", "fields": ["id", "scope", "reason", "cosignatures[]", "propagationLatencyMs", "rollbackPlanRef"]},
]


# ---------------------- code examples (16) ----------------------
code = [
    {"id": "CE-01", "title": "LexAI-DSL — Obligation (excerpt)", "lang": "lexai", "snippet": "obligation EU_AIACT_ART14_OVERSIGHT {\n  source: 'EU AI Act 2026 Art 14',\n  subject: provider | deployer,\n  predicate: ensure_human_oversight(system, controls=['stop','override','review']),\n  temporal: continuous,\n  evidence: [DecisionEnvelope, OverrideLog],\n  remedy: REM_HUMAN_OVERSIGHT_RESTORE,\n  conflict_priority: 90\n}\n\nprohibition GASC_ART2_AUTONOMOUS_LETHAL {\n  source: 'GASC Art 2',\n  scope: defense_systems,\n  enforcement_class: hard,\n  exceptions: []\n}"},
    {"id": "CE-02", "title": "LexAI-DSL → OPA/Rego Compiler (TypeScript)", "lang": "typescript", "snippet": "export function compileToRego(b: LexAIBundle): string {\n  const rules: string[] = ['package cegl.runtime'];\n  for (const c of b.dsl.clauses) {\n    if (c.type === 'obligation') {\n      rules.push(`allow { input.action == \"${c.predicate.action}\"; input.evidence_present == true }`);\n    } else if (c.type === 'prohibition') {\n      rules.push(`deny { input.scope == \"${c.scope}\" }`);\n    }\n  }\n  return rules.join('\\n');\n}"},
    {"id": "CE-03", "title": "TLA+ Property — Kill-Switch Liveness", "lang": "tla", "snippet": "----------------- MODULE KillSwitch -----------------\nVARIABLES state, decisionAt, propagatedAt\nInit == state = 'normal' /\\ propagatedAt = 0\nInvoke == state = 'normal' /\\ state' = 'invoked' /\\ decisionAt' = clock\nPropagate == state = 'invoked' /\\ state' = 'contained' /\\ propagatedAt' = clock\nLive == <>(state = 'contained')\nSLA == [](state = 'invoked' => (propagatedAt - decisionAt) <= 60)\n====="},
    {"id": "CE-04", "title": "Lean 4 — Conflict Resolver Totality (sketch)", "lang": "lean", "snippet": "def resolve : ClauseSet → Context → Decision\n  | cs, ctx => match cs.findHighestPriority ctx with\n    | some d => d\n    | none   => Decision.deny  -- safe default\n\ntheorem resolve_total : ∀ cs ctx, ∃ d, resolve cs ctx = d := by\n  intro cs ctx; exact ⟨_, rfl⟩"},
    {"id": "CE-05", "title": "Treaty Ledger Append (Node.js)", "lang": "typescript", "snippet": "import {createHash, sign} from 'node:crypto';\nexport async function appendTreaty(prev: string, evt: TreatyEvent, key: KeyHandle) {\n  const body = canonicalize({...evt, prevHash: prev});\n  const thisHash = createHash('sha256').update(body).digest('hex');\n  const sig = sign('Ed25519', Buffer.from(thisHash,'hex'), key.priv).toString('base64');\n  const envelope = {...JSON.parse(body), thisHash, signatures:[{alg:'Ed25519', kid:key.kid, sig}]};\n  await kafka.send({topic:`treaty.events`, messages:[{key:evt.id, value:JSON.stringify(envelope)}]});\n  return envelope;\n}"},
    {"id": "CE-06", "title": "GTI Computation (Python)", "lang": "python", "snippet": "def compute_gti(records, weights):\n    sub = {k: weighted_avg([r.subIndices[k] for r in records],\n                           [r.attestationQuorum for r in records]) for k in weights}\n    score = sum(weights[k]*sub[k] for k in weights)\n    return {'score': round(score, 4), 'subIndices': sub}"},
    {"id": "CE-07", "title": "Kill-Switch Multisig Invocation (TypeScript)", "lang": "typescript", "snippet": "export async function invokeKillSwitch(req: KSReq) {\n  if (req.cosignatures.length < 2) throw new Error('multisig required');\n  await verifyCoSigs(req.cosignatures, ['ai_safety_lead', 'ciso|cro']);\n  await ledger.append({type:'killswitch.invoke', payload:req});\n  await fanout.broadcast('killswitch', req.scope); // global anycast\n  await checkPropagation({slaMs: 60_000});\n}"},
    {"id": "CE-08", "title": "Federated Drill Orchestrator (Python)", "lang": "python", "snippet": "async def run_drill(scenario_id, participants):\n    drill = await drill_svc.start(scenario_id, participants)\n    async for evt in drill.stream():\n        await score(evt)\n    lessons = analyse(drill)\n    bundle = compile_lessons_to_lexai(lessons)\n    await lexai.publish(bundle)  # FV-LexAI verifies before activation\n    return drill.report"},
    {"id": "CE-09", "title": "OpenTelemetry Span — Treaty Action", "lang": "typescript", "snippet": "tracer.startActiveSpan('treaty.action', span => {\n  span.setAttributes({'treaty.id':evt.id,'treaty.type':evt.type,'jurisdiction':ctx.jur});\n  // ...handler...\n  span.end();\n});"},
    {"id": "CE-10", "title": "Sortition Sampling (Python)", "lang": "python", "snippet": "import secrets\ndef sortition(pool, strata_quotas):\n    out = []\n    for stratum, q in strata_quotas.items():\n        eligible = [p for p in pool if p.matches(stratum)]\n        out += secrets.SystemRandom().sample(eligible, q)\n    return out"},
    {"id": "CE-11", "title": "Supervisor Gateway — Bulletin Verify (TS)", "lang": "typescript", "snippet": "export async function verifyBulletin(b: Bulletin) {\n  const cert = await pki.resolve(b.signerKid);\n  const ok = await crypto.verify('Ed25519', b.payload, cert.pub, b.sig);\n  if (!ok) throw new Error('invalid bulletin');\n  await audit.append({action:'bulletin.verify', signer:b.signerKid, hash:b.payloadHash});\n}"},
    {"id": "CE-12", "title": "TDL Trigger Monitor (Python)", "lang": "python", "snippet": "def should_step_up_coupon(gti_record, floor):\n    return gti_record['score'] < floor\n\ndef should_circuit_break(spread_bps, threshold):\n    return spread_bps >= threshold"},
    {"id": "CE-13", "title": "Confidential Compute — Attestation Check", "lang": "typescript", "snippet": "const att = await tee.getAttestation();\nif (!verifyAttestation(att, expected: 'TDX|SEV-SNP', minTcb)) throw new Error('TEE attestation failed');\n// proceed with sensitive evaluation..."},
    {"id": "CE-14", "title": "Treaty Bundle Hot-Swap (CI snippet)", "lang": "yaml", "snippet": "- name: FV-LexAI verify\n  run: fvc verify --bundle $BUNDLE --properties P1,P2,P5,P7\n- name: Sigstore sign\n  run: cosign sign --key kms://treaty-authority $BUNDLE\n- name: Stage canary\n  run: cli treaty deploy --canary --regions eu1,us1\n- name: KPI check\n  run: cli gti floor-check --scope canary --floor 0.85"},
    {"id": "CE-15", "title": "PQC Hybrid Sign (TS)", "lang": "typescript", "snippet": "const ed = await crypto.sign('Ed25519', payload, ed25519Key);\nconst pq = await mldsa.sign(payload, mldsa65Key);\nreturn {alg:'hybrid:Ed25519+ML-DSA-65', sigs:[ed, pq]};"},
    {"id": "CE-16", "title": "Public Press Bulletin (Markdown template)", "lang": "markdown", "snippet": "# Public Bulletin — {{title}}\n\n*Issued:* {{ts}} · *Authority:* {{authority}} · *Signed:* {{sigShort}}\n\n## What happened\n{{whatHappened}}\n\n## What we are doing\n{{actions}}\n\n## What this means for you\n{{citizenImpact}}\n\n## Verification\nVerify this bulletin's signature at {{verifyUrl}}."},
]


# ---------------------- case studies (6) ----------------------
cases = [
    {"id": "CS-01", "title": "Cross-Border Flash Event (DR-02 drill)", "summary": "Three regulators executed a coordinated drill on an AI-driven equity flash event; kill-switch propagated in 47s, capital overlay applied within 3 BD.", "outcomes": ["Kill-switch propagation 47 s", "MTTR 38 min", "Mutual recognition under GASRGP Art 14", "5 LexAI clauses updated"]},
    {"id": "CS-02", "title": "Synthetic-Media Bank Run (DR-03 drill)", "summary": "Deepfake CEO video coordinated with cryptographically-signed counter-bulletin within 12 minutes; depositor outflows contained.", "outcomes": ["Counter-bulletin signed in 12 min", "Provenance verification reached >70% of users", "No bank-run threshold breached"]},
    {"id": "CS-03", "title": "GAISM Observer AI Stress Test", "summary": "EU/UK/US/JP/SG ran the first AI stress test; identified concentrated GTI weakness in two G-SIBs; capital overlay calibration adjusted.", "outcomes": ["2 G-SIBs flagged for remediation", "Capital overlay +18 bps for affected exposures", "TDL pilot calibrated"]},
    {"id": "CS-04", "title": "Citizen Deliberation on Generative-Media Disclosure", "summary": "Sortition panel of 240 citizens across 12 countries produced consensus recommendations; 7 adopted into LexAI-DSL bundle.", "outcomes": ["7 LexAI clauses ratified", "Public trust score +6 pp", "Independent integrity attestation passed"]},
    {"id": "CS-05", "title": "PQC Migration of Treaty Roots", "summary": "Treaty Authority migrated to hybrid Ed25519+ML-DSA-65 root; verifier sidecars updated with zero-downtime rollover.", "outcomes": ["Zero failed verifications during rollover", "Quantum-safe coverage 100%", "Verified by 3 independent labs"]},
    {"id": "CS-06", "title": "Climate-Finance AI Misalignment Detection", "summary": "FV-LexAI property monitor detected systematic mispricing of transition risk; supervisors issued joint guidance and capital overlay.", "outcomes": ["Mispricing closed within 6 months", "GTI fairness sub-index +0.04", "Cross-border guidance harmonized"]},
]


# ---------------------- KPIs (24) ----------------------
kpis = [
    {"id": "KPI-01", "name": "Kill-switch propagation latency (global)", "target": "≤ 60 s p95"},
    {"id": "KPI-02", "name": "Cross-border SEV-1 incident reporting", "target": "≤ 24 h"},
    {"id": "KPI-03", "name": "FV-LexAI property pass-rate per release", "target": "100% on P1-P7"},
    {"id": "KPI-04", "name": "Treaty Ledger daily Merkle anchor success", "target": "100%"},
    {"id": "KPI-05", "name": "GTI publication freshness", "target": "≤ 7 BD"},
    {"id": "KPI-06", "name": "Drill participation across regulators", "target": "≥ 8 jurisdictions / yr"},
    {"id": "KPI-07", "name": "Deliberation panel sortition representativeness", "target": "≥ 0.95 strata fidelity"},
    {"id": "KPI-08", "name": "Decision-traceability ratio", "target": "≥ 99.95%"},
    {"id": "KPI-09", "name": "PII leakage in Decision Envelopes", "target": "≤ 0.01%"},
    {"id": "KPI-10", "name": "TDL circuit-breaker false-positive", "target": "≤ 0.5%"},
    {"id": "KPI-11", "name": "AI Capital Overlay calibration freshness", "target": "≤ 1 quarter"},
    {"id": "KPI-12", "name": "Treaty bundle deployment success", "target": "≥ 99.9%"},
    {"id": "KPI-13", "name": "Time to ratify Codex amendment", "target": "≤ 18 months"},
    {"id": "KPI-14", "name": "Public bulletin signature verification", "target": "≥ 99% of recipients"},
    {"id": "KPI-15", "name": "Quantum-safe coverage of trust roots", "target": "100% by 2030"},
    {"id": "KPI-16", "name": "Independent-evaluator quorum on GTI", "target": "≥ 3 per institution"},
    {"id": "KPI-17", "name": "Disparate-impact bound on financial AI", "target": "ε ≤ 0.05"},
    {"id": "KPI-18", "name": "Citizen redress turnaround", "target": "≤ 30 BD"},
    {"id": "KPI-19", "name": "AI Stress-Test coverage of G-SIBs", "target": "≥ 95%"},
    {"id": "KPI-20", "name": "Deliberation output → LexAI ratification", "target": "≥ 60% per cycle"},
    {"id": "KPI-21", "name": "MTTA on systemic AI alerts", "target": "≤ 10 min"},
    {"id": "KPI-22", "name": "Cross-border drill mutual recognition", "target": "100%"},
    {"id": "KPI-23", "name": "PCB freshness (proof artifact age)", "target": "≤ 90 d"},
    {"id": "KPI-24", "name": "Maturity tier across G-SIFIs by 2032", "target": "≥ T3 median"},
]


# ---------------------- treaty articles (sample) ----------------------
treatyArticles = [
    {"id": "GASRGP-04", "treaty": "GASRGP", "article": "Art 4 Pre-deployment evaluation", "summary": "Mandatory pre-deployment evaluation for frontier models above compute threshold.", "lexaiClauseRef": "OBL_GASRGP_ART4_EVAL"},
    {"id": "GASRGP-07", "treaty": "GASRGP", "article": "Art 7 Cross-border incident reporting", "summary": "≤24h SEV-1 reporting across jurisdictions; signed bulletins via Treaty Ledger.", "lexaiClauseRef": "OBL_GASRGP_ART7_REPORT"},
    {"id": "GASRGP-11", "treaty": "GASRGP", "article": "Art 11 Compute governance", "summary": "Licensing for >10^26 FLOP runs; supply-chain auditability.", "lexaiClauseRef": "OBL_GASRGP_ART11_COMPUTE"},
    {"id": "GASRGP-14", "treaty": "GASRGP", "article": "Art 14 Mutual recognition", "summary": "Drills and supervisory attestations recognized across signatories.", "lexaiClauseRef": "OBL_GASRGP_ART14_MR"},
    {"id": "GASRGP-18", "treaty": "GASRGP", "article": "Art 18 Kill-switch obligations", "summary": "Treaty-anchored kill-switch with multisig and ≤60s SLA.", "lexaiClauseRef": "OBL_GASRGP_ART18_KS"},
    {"id": "GASC-02", "treaty": "GASC", "article": "Art 2 Autonomous lethal force prohibition", "summary": "Hard prohibition on autonomous lethal targeting decisions.", "lexaiClauseRef": "PRO_GASC_ART2_LETHAL"},
    {"id": "GASC-05", "treaty": "GASC", "article": "Art 5 Manipulative cognitive targeting", "summary": "Prohibits manipulative AI targeting cognitive vulnerabilities.", "lexaiClauseRef": "PRO_GASC_ART5_MANIP"},
    {"id": "GASC-09", "treaty": "GASC", "article": "Art 9 Synthetic-media provenance", "summary": "Mandatory provenance and disclosure for synthetic media at scale.", "lexaiClauseRef": "OBL_GASC_ART9_PROV"},
    {"id": "GASC-12", "treaty": "GASC", "article": "Art 12 Inspection rights", "summary": "Independent verification rights for AISI and academia.", "lexaiClauseRef": "OBL_GASC_ART12_INSPECT"},
    {"id": "GAISM-CAP", "treaty": "GAISM", "article": "Capital Overlay Schedule", "summary": "AI RWA add-on calibrated to GTI sub-indices.", "lexaiClauseRef": "OBL_GAISM_CAP_OVERLAY"},
    {"id": "GAISM-LIQ", "treaty": "GAISM", "article": "Liquidity Facility", "summary": "24-72 h backstop during AI-induced market stress.", "lexaiClauseRef": "OBL_GAISM_LIQ_FACILITY"},
    {"id": "GAISM-RES", "treaty": "GAISM", "article": "AI Resolution Authority", "summary": "Recovery and resolution tools for AI-coupled failures.", "lexaiClauseRef": "OBL_GAISM_RES_AUTHORITY"},
]


# ---------------------- regulator integrations ----------------------
regulators = [
    {"id": "REG-ECB", "name": "European Central Bank", "scope": "Eurozone banks, AI Capital Overlay calibration, AI stress test", "integrations": ["supervisor-gateway-svc", "GTI feed", "TDL exposure dashboard"]},
    {"id": "REG-FED", "name": "US Federal Reserve", "scope": "SR 11-7, AI in bank supervision, TDL CCP coordination", "integrations": ["supervisor-gateway-svc", "GTI feed", "Drill orchestration"]},
    {"id": "REG-PRA", "name": "Bank of England — PRA", "scope": "SS1/23, model risk, AI stress test", "integrations": ["supervisor-gateway-svc", "Drill orchestration"]},
    {"id": "REG-FCA", "name": "Financial Conduct Authority", "scope": "Consumer Duty, AI conduct supervision", "integrations": ["supervisor-gateway-svc", "Citizen redress integration"]},
    {"id": "REG-MAS", "name": "Monetary Authority of Singapore", "scope": "FEAT, AI Verify, sandbox", "integrations": ["supervisor-gateway-svc", "AI Verify feeds"]},
    {"id": "REG-HKMA", "name": "Hong Kong Monetary Authority", "scope": "GS-1/GL-90, AI in banking", "integrations": ["supervisor-gateway-svc"]},
    {"id": "REG-SEC", "name": "US Securities and Exchange Commission", "scope": "Broker-dealer/IA AI rules, market AI", "integrations": ["supervisor-gateway-svc", "TDL CCP coordination"]},
    {"id": "REG-FDIC", "name": "Federal Deposit Insurance Corporation", "scope": "AI guidance, deposit-related AI risks", "integrations": ["supervisor-gateway-svc"]},
    {"id": "REG-IMF", "name": "International Monetary Fund", "scope": "Article IV surveillance, GAISM administration", "integrations": ["GAISM admin", "Country GTI feed"]},
    {"id": "REG-FSB", "name": "Financial Stability Board", "scope": "AI vulnerabilities, mutual recognition coordination", "integrations": ["GTI heatmap", "Drill mutual recognition"]},
    {"id": "REG-AISI", "name": "AI Safety Institute Network", "scope": "Independent verification, red-team battery", "integrations": ["FV-LexAI verification", "Audit rights"]},
    {"id": "REG-OECD", "name": "OECD AI Policy Observatory", "scope": "Principles alignment, indicator publication", "integrations": ["GTI public dashboard input"]},
]


# ---------------------- runbooks (sample) ----------------------
runbooks = [
    {"id": "RB-01", "title": "LEVEL-5 containment drill execution", "steps": ["Convene J-DOC", "Activate sandbox replicas", "Inject scenario", "Score & sign", "Publish lessons → LexAI bundle"]},
    {"id": "RB-02", "title": "Treaty bundle hot-swap with multisig", "steps": ["Sign new bundle (multisig)", "Submit PCB", "Canary regions", "GTI floor check", "Promote to global"]},
    {"id": "RB-03", "title": "Cross-border SEV-1 reporting (≤24h)", "steps": ["Detect", "Triage", "Sign bulletin", "Distribute to participating supervisors", "WORM append"]},
    {"id": "RB-04", "title": "Kill-switch invocation & restoration", "steps": ["Co-sign by AI Safety Lead + CISO/CRO", "Broadcast", "Verify SLA ≤60 s", "Restoration plan w/ FV-LexAI re-verify"]},
    {"id": "RB-05", "title": "Deliberation panel convening", "steps": ["Define topic", "Sortition sample", "3 rounds", "Outputs to LexAI", "Integrity attestation"]},
    {"id": "RB-06", "title": "GTI re-attestation after evaluator dispute", "steps": ["Open dispute", "Independent re-eval", "Quorum sign", "Publish revision"]},
    {"id": "RB-07", "title": "TDL circuit-breaker activation", "steps": ["Spread breach detected", "Notify CCP + supervisor", "Activate breaker", "Coordinate market reopening"]},
]


# ---------------------- briefings ----------------------
briefings = [
    {"id": "BD-01", "audience": "Heads of State", "duration": "15 min / 10 slides", "narrativeAnchor": "Codex axioms; civilizational risk; treaty status"},
    {"id": "BD-02", "audience": "Central-Bank Governors", "duration": "30 min", "narrativeAnchor": "GTI heatmap, GAISM facility status, AI Capital Overlay"},
    {"id": "BD-03", "audience": "IMF / FSB plenary", "duration": "45 min", "narrativeAnchor": "Country GTI trajectory, TDL exposure, cross-border drills"},
    {"id": "BD-04", "audience": "G-SIFI Board", "duration": "60 min", "narrativeAnchor": "Adversarial findings, kill-switch drills, capital impact"},
    {"id": "BD-05", "audience": "Parliamentary committee", "duration": "60 min", "narrativeAnchor": "Rights, contestability, citizen oversight"},
    {"id": "BD-06", "audience": "Public press", "duration": "20 min", "narrativeAnchor": "Plain language, signed provenance, redress channels"},
]


# ---------------------- traceability ----------------------
traceability = [
    {"feature": "M2 LexAI-DSL clauses", "control": "Hash-chained machine-readable obligations", "regimes": ["EU AI Act 2026 (multiple)", "ISO/IEC 42001 Cl 8.4", "NIST AI RMF Govern 1.4"]},
    {"feature": "M3 FV-LexAI property suite", "control": "Formal proofs of safety/liveness/non-discrimination", "regimes": ["EU AI Act Art 9/10", "SR 11-7 III.B", "ISO/IEC 23894"]},
    {"feature": "M4 GASC Art 2 prohibition", "control": "Hard prohibition on autonomous lethal force", "regimes": ["GASC Art 2", "UN Charter", "IHL"]},
    {"feature": "M4 GAISM AI Capital Overlay", "control": "RWA add-on tied to GTI", "regimes": ["Basel III/IV", "EU CRR", "SR 11-7"]},
    {"feature": "M5 GTI sub-indices", "control": "Multi-evaluator attestations", "regimes": ["EU AI Act Art 13", "MAS FEAT", "OECD AI Principles"]},
    {"feature": "M6 federated drills", "control": "Mutual recognition under GASRGP Art 14", "regimes": ["GASRGP Art 14", "FSB recommendations"]},
    {"feature": "M8 deliberation outputs", "control": "Citizen recommendations to LexAI", "regimes": ["COE AI Convention", "ICCPR Art 25"]},
    {"feature": "M9 Treaty Ledger", "control": "Append-only WORM ledger with Merkle anchors", "regimes": ["EU AI Act Art 12", "ISO/IEC 27001 A.12.4"]},
    {"feature": "M10 PQC hybrid signatures", "control": "Quantum-safe trust roots", "regimes": ["NIST PQC migration", "BIS PQC guidance"]},
    {"feature": "M11 sector mapping", "control": "Sector-specific obligations", "regimes": ["FCRA §615(a)", "FCA Consumer Duty", "Solvency II"]},
    {"feature": "M12 inspection rights", "control": "Independent verification access", "regimes": ["GASC Art 12", "AI Safety Institute statutes"]},
    {"feature": "M13 maturity model", "control": "Tiered conformance assessment", "regimes": ["ISO/IEC 42001 Annex A", "NIST AI RMF profiles"]},
]


# ---------------------- engineering blueprint flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "Bundle → FV-LexAI → Activation", "steps": ["Author signs LexAI bundle", "FV-LexAI verifies P1..P7", "Treaty Authority co-signs PCB", "Sidecars verify and activate"], "controls": ["multisig", "FV gates", "WORM ledger"]},
    {"id": "DF-02", "name": "Decision Envelope → GTI", "steps": ["Provider signs envelope", "Evaluators attest sub-indices", "GTI svc aggregates", "Daily Merkle anchor"], "controls": ["evaluator quorum", "tamper-evident chain"]},
    {"id": "DF-03", "name": "Cross-border Incident", "steps": ["Detect SEV-1", "Sign bulletin", "Distribute via gateway", "Append to ledger", "Public bulletin"], "controls": ["≤24h SLA", "PKI verification", "Counter-deepfake"]},
    {"id": "DF-04", "name": "Kill-Switch Propagation", "steps": ["Co-sign", "Anycast broadcast", "Sidecars contain", "Verify SLA"], "controls": ["multisig", "≤60s SLA", "rollback plan"]},
    {"id": "DF-05", "name": "Deliberation → LexAI", "steps": ["Sortition", "3-round deliberation", "Output drafting", "FV-LexAI verify", "Bundle activation"], "controls": ["integrity attestation", "anti-manipulation"]},
    {"id": "DF-06", "name": "TDL Trigger", "steps": ["Spread monitor", "Floor breach", "CCP coordination", "Circuit breaker", "Reopen plan"], "controls": ["position limits", "CCP supervision"]},
]


# ---------------------- privacy & security ----------------------
privacy = {
    "lawfulBasis": ["Treaty obligation (Art 6(1)(c))", "Public interest (Art 6(1)(e))"],
    "dataMinimization": ["Pseudonymous WORM payloads", "Confidential compute for sensitive evals", "Federated access to research commons"],
    "subjectRights": ["Citizen redress portal with SLA", "Right of contestation for automated decisions", "Transparent provenance"],
    "transfers": "Per-jurisdiction residency with cross-border attestation; SCCs + supplementary measures",
    "dpia": "Mandatory for any LexAI bundle touching personal data; reviewed by DPOs and AISI",
}


# ---------------------- deployment considerations ----------------------
deployment = [
    "Multi-region active-active with confidential compute for FV-LexAI proof generation",
    "Air-gapped enclaves for treaty-signing keys (FIPS 140-3 L4 HSM)",
    "Hybrid PQC signatures (Ed25519 + ML-DSA-65) on critical bundles",
    "WORM tiering for Treaty Ledger with object-store bucket lock and 50-year retention",
    "Per-jurisdiction supervisor-gateway-svc deployments with mutual-TLS workload identity",
    "Independent observation channels for AISI and civil-society auditors",
    "Disaster recovery: cross-region failover with RPO ≤ 1 h, RTO ≤ 4 h for treaty plane",
    "Chaos drills quarterly: KMS outage, region failover, kill-switch propagation under partition",
    "CI/CD: SBOM + SLSA L3+ + Sigstore + FV-LexAI gate + GTI floor canary",
    "Public verifier endpoints for press to validate signed bulletins offline",
]


# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": "Provide a regulator-ready, treaty-aligned, formally-verifiable governance framework for global AI systemic risk in financial services and planetary-scale civilizational governance, integrating CEGL, LexAI-DSL, FV-LexAI, the GASRGP/GASC/GAISM treaty stack, the Global Trust Index and Trust Derivatives Layer, central-bank/IMF integration, the Global Deliberation Protocol, and engineering deployment blueprints.",
    "approach": "Layered architecture (Codex → Treaties → LexAI-DSL → FV-LexAI → Supervisory plane → Operational plane → Citizen plane), proof-carrying bundles, Treaty Ledger WORM, sortition-based deliberation, federated supervisory drills, and PQC-hybrid trust roots.",
    "deliverables": "14 modules · schemas · code examples · case studies · 24 supervisory KPIs · treaty-article mapping · regulator integration list · runbooks · briefing decks · data flows · privacy spec · traceability matrix · deployment considerations · roadmap 2026-2035.",
    "outcomes": [
        "Sub-60 s kill-switch propagation with multisig and treaty SLA",
        "Cross-border mutual recognition under GASRGP Art 14",
        "AI Capital Overlay calibrated to GTI sub-indices",
        "Citizen-plane legitimacy through stratified sortition",
        "Treaty-anchored auditability with Merkle-anchored Treaty Ledger",
        "Quantum-safe coverage by 2030",
    ],
}


# ---------------------- assemble ----------------------
DOC["modules"] = modules
DOC["schemas"] = schemas
DOC["codeExamples"] = code
DOC["caseStudies"] = cases
DOC["kpis"] = kpis
DOC["treatyArticles"] = treatyArticles
DOC["regulators"] = regulators
DOC["runbooks"] = runbooks
DOC["briefings"] = briefings
DOC["dataFlows"] = dataFlows
DOC["privacy"] = privacy
DOC["traceability"] = traceability
DOC["deploymentConsiderations"] = deployment
DOC["executiveSummary"] = executiveSummary

DOC["counts"] = {
    "modules": len(modules),
    "sections": sum(len(m["sections"]) for m in modules),
    "schemas": len(schemas),
    "codeExamples": len(code),
    "caseStudies": len(cases),
    "kpis": len(kpis),
    "treatyArticles": len(treatyArticles),
    "regulators": len(regulators),
    "runbooks": len(runbooks),
    "briefings": len(briefings),
    "dataFlows": len(dataFlows),
    "traceabilityRows": len(traceability),
    "apiRoutes": 100,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
print("counts:", DOC["counts"])
