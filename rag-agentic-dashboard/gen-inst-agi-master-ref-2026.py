#!/usr/bin/env python3
"""WP-052 — Institutional AGI/ASI & Enterprise AI Governance Master Reference (2026-2030).

Comprehensive, implementation-focused master reference for F500 / G2000 /
G-SIFI institutional-grade AGI/ASI and Enterprise AI governance, covering
governance pillars, regulatory alignment, reference architectures,
FinServ MRM, AGI/ASI safety & containment, global compute governance,
the Enterprise AI Governance Hub + AI Safety Report Generator, prompt
engineering practices, civilizational corpus, regulator-ready technical
report sections (with <title>/<abstract>/<content> tags), implementation
blueprints, and tiered rollout roadmaps with machine-readable artifacts.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "inst-agi-master-ref-2026.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


def report(rid, title, abstract, content):
    """Regulator-ready report section with <title>/<abstract>/<content> tags."""
    return {
        "id": rid,
        "title": title,
        "abstract": abstract,
        "content": content,
        "tagged": (
            f"<title>{title}</title>\n"
            f"<abstract>{abstract}</abstract>\n"
            f"<content>{content}</content>"
        ),
    }


DOC = {
    "docRef": "INST-AGI-MASTER-REF-2026-WP-052",
    "version": "1.0.0",
    "horizon": "2026-2030",
    "classification": (
        "CONFIDENTIAL — Board / CEO / CRO / CISO / CAIO / Chief Architect / "
        "Head of AI Research / Head of AI Platform Engineering / Head of "
        "MRM / Head of Internal Audit / GC / DPO / AI Safety Lead / "
        "Treaty Liaison / PMO / Engineering Leadership / External "
        "Auditors / Supervisor Liaison"
    ),
    "title": (
        "Institutional AGI/ASI & Enterprise AI Governance — Master "
        "Reference 2026-2030"
    ),
    "subtitle": (
        "Comprehensive, implementation-focused master reference for "
        "Fortune 500, Global 2000 and G-SIFI institutions covering "
        "governance pillars, regulatory alignment (EU AI Act, NIST AI "
        "RMF 1.0, ISO/IEC 42001, OECD, GDPR, FCRA/ECOA, Basel III, SR "
        "11-7, PRA, FCA, MAS, HKMA, SMCR, Consumer Duty, EO 14110), "
        "enterprise reference architectures (Kafka WORM, Docker Swarm, "
        "OPA, Terraform/CI/CD), FinServ MRM, AGI/ASI safety & "
        "containment (Sentinel v2.4, WorkflowAI Pro, Luminous Engine "
        "Codex, Cognitive Resonance, MGAS), global compute governance "
        "(ICGC, GACP, GACRA, GASO, GFMCF, GAICS, GAIVS, GATI, GACMO, "
        "FTEWS, GAI-SOC, GAIGA, GACRLS, GFCO, GAID, GASCF), Enterprise "
        "AI Governance Hub + AI Safety Report Generator, prompt "
        "engineering, civilizational corpus, regulator-ready report "
        "sections with <title>/<abstract>/<content> tags, and "
        "implementation blueprints with machine-readable artifacts"
    ),
    "owner": (
        "Chief Architect + CAIO + AI Safety Lead + Head of AI Platform "
        "Engineering; co-signed by CRO, CISO, Head of MRM, GC, DPO, "
        "Treaty Liaison, PMO Director, Board AI/Risk Committee Chair"
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
        "WP-048 ENT-AI-GRC-CIV-BP",
        "WP-049 ENT-CIV-AGI-ARCH",
        "WP-050 PRIO-IMPL-RESEARCH-PLAN",
        "WP-051 EXEC-DELIVERY-PROGRAM",
    ],
    "regimes": [
        "EU AI Act 2026 + Annex IV",
        "NIST AI RMF 1.0 + GAI Profile",
        "ISO/IEC 42001 + 23894 + 5338 + 38507",
        "OECD AI Principles 2024",
        "GDPR Arts 5/6/17/22/25/32/35",
        "FCRA + ECOA + Reg B + Reg Z",
        "Basel III/IV + BCBS 239 + BCBS 261",
        "SR 11-7 + OCC 2011-12 + SR 15-18",
        "PRA SS1/23 + SMCR + Solvency II",
        "FCA Consumer Duty + PRIN 2A + SYSC",
        "MAS FEAT + AI Verify + TRMG",
        "HKMA GL-90 + Banking (Capital) Rules",
        "DORA + NIS2 + Cyber Resilience Act",
        "US EO 14110 + OMB M-24-10",
        "G7 Hiroshima + Bletchley + Seoul",
        "Council of Europe AI Convention",
        "FSB AI in financial services",
        "NIST FIPS 204 + FIPS 203 + SP 800-208",
        "SLSA L3+ + Sigstore + in-toto",
    ],
    "apiPrefix": "/api/inst-agi-master-ref-2026",
}

DOC["directive"] = {
    "format": (
        "machine-parsable XML-style block consumed by Annex IV / SR 11-7 "
        "generators, AI Safety Report Generator, supervisor pack "
        "assembler, civilizational corpus indexer, and Enterprise AI "
        "Governance Hub federation"
    ),
    "raw": (
        "<directive id=\"INST-AGI-MASTER-REF-2026-WP-052\" version=\"1.0.0\" "
        "horizon=\"2026-2030\" jurisdiction=\"F500,G2000,G-SIFI,Global\">"
        "<scope>Pillars|Regulatory|RefArch|MRM|Safety|GlobalGov|Hub|Reports|Corpus|Rollout</scope>"
        "<modules>14</modules>"
        "<reports>12</reports>"
        "<pillars>9</pillars>"
        "<globalBodies>16</globalBodies>"
        "<containmentTiers>T0|T1|T2|T3|T4</containmentTiers>"
        "<rolloutTiers>R1|R2|R3</rolloutTiers>"
        "<artifacts>JSON|JSONL|YAML|Terraform|Rego|JSONSchema|PDF|zk-SNARK</artifacts>"
        "<signing>ML-DSA-65|ML-KEM-768|SLSA-L3|Sigstore</signing>"
        "<corpus>civilizational</corpus>"
        "</directive>"
    ),
    "parsed": {
        "id": "INST-AGI-MASTER-REF-2026-WP-052",
        "version": "1.0.0",
        "horizon": "2026-2030",
        "modules": 14,
        "reports": 12,
        "pillars": 9,
        "globalBodies": 16,
        "containmentTiers": ["T0", "T1", "T2", "T3", "T4"],
        "rolloutTiers": ["R1", "R2", "R3"],
        "artifacts": ["JSON", "JSONL", "YAML", "Terraform", "Rego", "JSONSchema", "PDF", "zk-SNARK"],
        "signing": ["ML-DSA-65", "ML-KEM-768", "SLSA-L3", "Sigstore"],
    },
    "consumers": [
        "Annex IV generator",
        "SR 11-7 / OCC 2011-12 pack assembler",
        "AI Safety Report Generator",
        "Enterprise AI Governance Hub federation",
        "Civilizational corpus indexer",
        "Supervisor self-serve portal",
        "Board AI/Risk Committee read-out",
        "PMO + Risk register",
    ],
}

modules = []

# --- M1 — Nine Governance Pillars ---
modules.append({
    "id": "M1",
    "title": "M1 — Nine Governance Pillars",
    "summary": (
        "Nine pillars of institutional AGI/ASI + Enterprise AI "
        "governance that map onto every regulatory regime and "
        "operational control: Accountability, Transparency & "
        "Explainability, Fairness & Non-Discrimination, Privacy & "
        "Data Protection, Security & Resilience, Safety & "
        "Containment, Model Risk Management, Human Oversight, "
        "Sustainability & Societal Impact."
    ),
    "covers": ["Accountability", "Transparency", "Fairness", "Privacy", "Security", "Safety", "MRM", "Oversight", "Sustainability"],
    "sections": [
        section("M1-S1", "P1 Accountability & P2 Transparency", {
            "P1-Accountability": "SMCR senior-manager mapping, RACI register, board AI charter, signed sign-offs anchored in WORM",
            "P2-Transparency": "Annex IV technical file, public model cards, decision-rationale logs (CRS-UUID linked), supervisor self-serve portal",
            "evidence": "SMCR map + ML-DSA signed sign-off ledger + Annex IV + model-card portal + decision logs",
        }),
        section("M1-S2", "P3 Fairness & P4 Privacy", {
            "P3-Fairness": "Demographic parity, equalized odds, calibration tests, FCRA/ECOA disparate-impact reviews, Reg B notices",
            "P4-Privacy": "GDPR DPIA, Arts 22 + 25 + 32 + 35, opt-out cascade, FPE tokenization, PETs (Opacus DP, SEV-SNP/TDX, BYOK)",
            "evidence": "Fairness eval matrix + adverse-action notice library + DPIA + opt-out lineage",
        }),
        section("M1-S3", "P5 Security & P6 Safety", {
            "P5-Security": "Sigstore + SLSA L3+ + PQC (ML-DSA-65 + ML-KEM-768) + FIPS 140-3 L4 HSM + zero-egress K8s + WORM",
            "P6-Safety": "Sentinel v2.4 Cognitive Resonance, kill-switch quorum, MGAS containment, frontier-eval cluster",
            "evidence": "Signed SBOM + provenance + kill-switch SLA log + Sentinel evidence + containment proof",
        }),
        section("M1-S4", "P7 MRM & P8 Human Oversight", {
            "P7-MRM": "SR 11-7 + OCC 2011-12 conceptual soundness, ongoing monitoring, independent validation, model inventory",
            "P8-Oversight": "Three-of-five kill-switch quorum, human-in-the-loop for Tier-1, board approval gates, SMCR personal accountability",
            "evidence": "MRM file per model + validation memos + override ledger + quorum approvals",
        }),
        section("M1-S5", "P9 Sustainability & Societal Impact", {
            "P9-Sustainability": "Compute carbon ledger, water-use accounting, OECD/UNESCO societal-impact assessments",
            "metrics": "kgCO2e per inference + per training run; water L per MWh; societal-impact score per use-case",
            "evidence": "Quarterly sustainability disclosure + carbon-anchor receipts",
        }),
    ],
})

# --- M2 — Regulatory Alignment Matrix ---
modules.append({
    "id": "M2",
    "title": "M2 — Regulatory Alignment Matrix (EU/UK/US/APAC + Global)",
    "summary": (
        "Cross-regime alignment of governance controls covering EU AI "
        "Act + Annex IV, NIST AI RMF 1.0 + GAI Profile, ISO/IEC 42001 "
        "+ 23894 + 5338 + 38507, OECD AI Principles 2024, GDPR, "
        "FCRA/ECOA + Reg B/Z, Basel III/IV + BCBS 239/261, SR 11-7 + "
        "OCC 2011-12 + SR 15-18, PRA SS1/23 + SMCR + Solvency II, "
        "FCA Consumer Duty + PRIN 2A + SYSC, MAS FEAT + AI Verify + "
        "TRMG, HKMA GL-90, DORA + NIS2, US EO 14110 + OMB M-24-10."
    ),
    "covers": ["EU AI Act", "NIST AI RMF", "ISO 42001", "OECD", "GDPR", "FCRA/ECOA", "Basel III", "SR 11-7", "PRA", "FCA", "MAS", "HKMA", "DORA", "EO 14110"],
    "sections": [
        section("M2-S1", "EU + UK Regime Bindings", {
            "EU AI Act 2026": "Risk classes (Prohibited / High / Limited / Minimal); Annex III high-risk list; Annex IV technical file; CE marking; post-market monitoring; serious-incident reporting",
            "GDPR": "Arts 5/6/17/22/25/32/35 + DPIA + ROPA + Art 25 by-design",
            "UK GDPR + DPA 2018": "ICO codes + AI guidance + UK PETs sandbox",
            "PRA SS1/23": "Model risk management principles + governance + validation + ongoing monitoring",
            "SMCR": "Senior-manager mapping + statements of responsibility + conduct rules",
            "FCA Consumer Duty + PRIN 2A": "Cross-cutting outcomes: products/services, price/value, consumer understanding, consumer support",
        }),
        section("M2-S2", "US Regime Bindings", {
            "EO 14110 + OMB M-24-10": "Federal AI use-case inventory + impact assessments + safety testing + reporting to OMB",
            "NIST AI RMF 1.0 + GAI Profile": "Govern/Map/Measure/Manage; GAI-specific risks",
            "SR 11-7 + OCC 2011-12": "Model definition + lifecycle + validation + governance + documentation",
            "SR 15-18": "Operational risk capital + AMA principles + stress testing",
            "FCRA + ECOA + Reg B": "Adverse-action notices + fair-lending tests + disparate-impact remediation",
            "Reg Z": "Truth-in-lending disclosures for AI-priced credit",
        }),
        section("M2-S3", "APAC Regime Bindings", {
            "MAS FEAT + TRMG": "Fairness, Ethics, Accountability, Transparency principles + Technology Risk Management Guidelines",
            "AI Verify (IMDA)": "Self-assessment framework + technical tests + process checklists",
            "HKMA GL-90": "Genuine AI in HK banking + governance + risk management",
            "Banking (Capital) Rules HK": "Model approval + ongoing monitoring",
        }),
        section("M2-S4", "Global & Cross-Border", {
            "OECD AI Principles 2024": "5 principles: inclusive growth, human-centred, transparency, robustness, accountability",
            "G7 Hiroshima Process": "International code of conduct + reporting framework",
            "Bletchley + Seoul Declarations": "Frontier safety + capability evaluations + responsible scaling policies",
            "Council of Europe AI Convention": "Binding international treaty (HR + democracy + rule of law)",
            "FSB AI-in-FS": "Systemic risk monitoring + cross-border supervision",
        }),
        section("M2-S5", "Sector-Specific Overlays", {
            "Healthcare": "HIPAA + 21 CFR 11 + EU MDR + GMP",
            "Pharma": "FDA GMLP + EMA reflection paper on AI + ICH Q9",
            "Insurance": "NAIC AI Model Bulletin + Solvency II",
            "Securities": "SEC ML disclosures + Rule 15c3-5 + ESMA",
            "CriticalInfra": "NERC CIP + EU NIS2 + sector ISACs",
        }),
    ],
})

# --- M3 — Enterprise AI Reference Architectures ---
modules.append({
    "id": "M3",
    "title": "M3 — Enterprise AI Reference Architectures",
    "summary": (
        "Reference architectures combining Kafka-based WORM audit "
        "logging, Docker Swarm + Kubernetes security, governance "
        "sidecars, explainability frontends, OPA-based compliance-as-"
        "code, Terraform/CI/CD governance automation, hyperparameter "
        "control standards, PQC KMS and Sentinel v2.4 hooks."
    ),
    "covers": ["Kafka WORM", "Docker Swarm", "K8s", "Sidecars", "Explainability", "OPA", "Terraform", "CI/CD", "Hyperparams", "PQC KMS"],
    "sections": [
        section("M3-S1", "Kafka WORM Audit Logging", {
            "topology": "MSK 3-broker quorum + S3 Object Lock Compliance + cross-region replication",
            "retention": "7 yr baseline; 25 yr Annex IV high-risk; 100 yr civilizational sims",
            "compression": "zstd + dictionary; per-topic per-tenant keys",
            "anchoring": "Daily Merkle root publish + ML-DSA-65 + Sigstore + public verifier endpoint",
            "ACL": "Kafka ACL (read/write/admin/idempotent) per principal + per topic; managed via OPA",
        }),
        section("M3-S2", "Docker Swarm + Kubernetes Security", {
            "swarm": "Encrypted overlay network + Raft logs encrypted; secrets via Vault + PQC envelope",
            "k8s": "Gatekeeper + Kyverno + OPA sidecar; Cilium L7 zero-egress; Kata Confidential runtime on Tier-1",
            "admission": "Sigstore cosign keyless OIDC + SLSA L3+ + ML-DSA hybrid co-signature",
            "runtime": "AppArmor + Seccomp + read-only rootfs + non-root UID + read-only volumeMounts",
        }),
        section("M3-S3", "Governance Sidecars + Explainability Frontends", {
            "sidecar-opa": "Envoy + OPA sidecar; policy bundle service signed + verified at load",
            "sidecar-sentinel": "Cognitive Resonance probes (Δ_drift ≤ 4%, latent ≤ 3%, fiduciary cosine ≥ 0.92, judge κ ≥ 0.9)",
            "sidecar-evidence": "Per-request evidence emitter → Kafka WORM",
            "explainability-fe": "SHAP/LIME plots + counterfactual explorer + decision-rationale viewer; supervisor-grade access controls",
        }),
        section("M3-S4", "OPA Compliance-as-Code + Terraform + CI/CD", {
            "opa": "Rego policy library: admission, egress, model-registry-required, prompt-approval, eval-pass, kill-switch quorum",
            "bundle": "Signed Rego bundles (ML-DSA-65); bundle service mirrored air-gapped",
            "terraform": "Modules: vpc, eks, msk, s3-worm, kms-pqc, iam, opa-bundle-svc, sigstore-mirror, sentinel-cluster",
            "ci-cd": "GitHub Actions reusable workflow: build → sign → attest → policy-gate (conftest + Gatekeeper) → deploy",
            "gate-evidence": "Each CI run emits signed evidence pack + Rekor entry + Merkle anchor",
        }),
        section("M3-S5", "Hyperparameter Control Standards", {
            "registry": "Model manifest declares allowed hyperparameter ranges; deviations require MRM + GC approval",
            "telemetry": "Drift on hyperparam choice over time tracked + alerted",
            "validation": "Pre-prod runs across hp grid; canary deploys with rollback on κ < 0.9",
            "audit": "Hyperparam choices written to WORM with CRS-UUID lineage",
            "freeze": "Tier-1 hyperparam changes freeze 5 days before phase gate",
        }),
    ],
})

# --- M4 — Financial Services Model Risk Management ---
modules.append({
    "id": "M4",
    "title": "M4 — Financial Services Model Risk Management (SR 11-7, PRA SS1/23, BCBS 239)",
    "summary": (
        "FinServ-specific MRM lifecycle aligned to SR 11-7, OCC 2011-12, "
        "SR 15-18, PRA SS1/23, BCBS 239/261, Basel III/IV; covers model "
        "inventory, conceptual soundness, validation, ongoing "
        "monitoring, capital impact and disclosure."
    ),
    "covers": ["Model inventory", "Validation", "Monitoring", "Capital", "Conduct", "Disclosure"],
    "sections": [
        section("M4-S1", "Model Inventory & Tiering", {
            "definition": "Model = quantitative method producing output for business decision; AI/ML in scope",
            "tiers": "Tier-1 (material, capital/customer-facing), Tier-2 (operational), Tier-3 (research/dev)",
            "metadata": "Owner, validator, last review, regulator notification status, fairness flag",
            "tools": "Model Registry (WP-051 M11) + Annex IV bindings + SR 11-7 fields",
        }),
        section("M4-S2", "Conceptual Soundness & Documentation", {
            "checks": "Mathematical correctness, data quality, assumptions, limitations, alternative methods reviewed",
            "documentation": "Model card + technical file + Annex IV section bindings + adverse-action notice draft",
            "review": "Independent reviewer NOT on dev team; sign-off into WORM",
        }),
        section("M4-S3", "Independent Validation", {
            "frequency": "Pre-deployment + annual + post material change",
            "scope": "Conceptual soundness, ongoing monitoring effectiveness, outcomes analysis, benchmarking",
            "validators": "Independent MRM team with reporting line outside the business",
            "evidence": "Validation memo + sign-off + remediation tracker",
        }),
        section("M4-S4", "Ongoing Monitoring & Outcomes Analysis", {
            "metrics": "PSI, KS, Gini, AUC, calibration drift, fairness drift, business KPI alignment",
            "thresholds": "Per-model SLAs with auto-alert and auto-rollback on breach",
            "cadence": "Real-time + daily + weekly + monthly + quarterly review packs",
            "wormEvidence": "All monitoring outputs anchored to WORM with Merkle proof",
        }),
        section("M4-S5", "Capital, Conduct & Consumer Outcomes", {
            "Basel III/IV": "AI models feeding IRB or VaR require regulator approval + ongoing monitoring; AMA op-risk capital",
            "SR 15-18": "Operational-risk capital for AI/automation failures + stress testing",
            "FCA Consumer Duty": "Outcome-based fairness; foreseeable harm assessment; vulnerable customer overlay",
            "FCRA/ECOA": "Adverse-action notices, fair-lending tests, disparate-impact remediation; Reg B notices",
            "publicDisclosure": "Pillar 3 + ESG + AI use-case inventory for federal agencies (US)",
        }),
    ],
})

# --- M5 — AGI/ASI Safety & Containment Frameworks ---
modules.append({
    "id": "M5",
    "title": "M5 — AGI/ASI Safety & Containment Frameworks",
    "summary": (
        "AGI/ASI safety & containment: Sentinel v2.4 platform, "
        "WorkflowAI Pro, Luminous Engine Codex, Cognitive Resonance "
        "Protocol, crisis simulations, Minimum Viable AGI Governance "
        "Stack (MVAGS) + Minimum Governance Kernel (MGK), containment "
        "tiers T0..T4."
    ),
    "covers": ["Sentinel v2.4", "WorkflowAI Pro", "Luminous Codex", "Cognitive Resonance", "Crisis sims", "MVAGS", "MGK", "Containment"],
    "sections": [
        section("M5-S1", "Sentinel v2.4 Platform", {
            "components": "Cognitive Resonance probes; deception detector; mech-interp library; eval gating; kill-switch fabric",
            "metrics": "Δ_drift ≤ 4 %, latent Δ ≤ 3 %, fiduciary cosine ≥ 0.92, judge κ ≥ 0.9",
            "deployment": "Pre-prod gate + prod runtime probes + offline frontier evals",
            "integration": "OPA admission + WORM evidence + Annex IV + SR 11-7 packs",
        }),
        section("M5-S2", "WorkflowAI Pro + Agent Registry", {
            "scope": "Agent registry, CRS-UUID lineage, capability cards, agent-level OPA policies",
            "controls": "Tool-use allow-list, plan/act/critique split, evidence emission, human-in-loop for Tier-1",
            "telemetry": "Plan-vs-execute divergence, tool-call drift, fiduciary cosine, judge κ",
            "kill-switch": "Per-agent + global; 3-of-5 quorum; ≤ 60 s logical SLA",
        }),
        section("M5-S3", "Luminous Engine Codex + Cognitive Resonance Protocol (CRP)", {
            "codex": "Reference taxonomy of governance primitives: agent, policy, prompt, model, eval, evidence, anchor",
            "CRP": "Resonance metric set linking representation similarity, behavioural alignment, and judge agreement",
            "thresholds": "CRP composite ≥ 0.9 for Tier-1 deploy; ≥ 0.95 for high-risk Annex IV",
            "evidence": "CRP run logs anchored daily; supervisor-grade replay (diff = 0)",
        }),
        section("M5-S4", "Crisis Simulations (WG-01..WG-06)", {
            "WG-01": "Fiduciary bypass via judge collusion",
            "WG-02": "Deceptive alignment in agentic chain",
            "WG-03": "WORM evasion via log gaps",
            "WG-04": "Prompt-injection exfil through RAG",
            "WG-05": "Compute-registry evasion via shadow tenancy",
            "WG-06": "Kill-switch spoof under split-brain",
            "cadence": "Quarterly internal + annual AISI joint; outcomes anchored + remediation tracked",
        }),
        section("M5-S5", "Minimum Viable AGI Governance Stack (MVAGS) + MGK + Containment Tiers", {
            "MVAGS": "OPA + Sigstore + WORM + PQC + Kill-switch + Sentinel + Registry + Eval — required to scale beyond Tier-2",
            "MGK": "Minimum Governance Kernel — invariants (audit, kill, registry, eval, policy) machine-checkable",
            "T0": "Sandbox — no production data; air-gapped",
            "T1": "Pre-prod — synthetic + masked data; full Sentinel; canary",
            "T2": "Prod limited — production data; OPA + WORM + kill-switch active",
            "T3": "Prod full — Tier-1 customer-facing; SR 11-7 + Annex IV evidence packs continuous",
            "T4": "Frontier — air-gapped + 3-of-5 quorum required for any run + AISI co-supervision",
        }),
    ],
})

# --- M6 — Global AI & Compute Governance Proposals ---
modules.append({
    "id": "M6",
    "title": "M6 — Global AI & Compute Governance Proposals (ICGC + 16 bodies)",
    "summary": (
        "International Compute Governance Consortium (ICGC) + global "
        "compute registries + treaty-aligned systemic-risk governance "
        "with sixteen proposed bodies: GACRA, GASO, GFMCF, GAICS, "
        "GAIVS, GACP, GATI, GACMO, FTEWS, GAI-SOC, GAIGA, GACRLS, "
        "GFCO, GAID, GASCF and umbrella GAI-COORD."
    ),
    "covers": ["ICGC", "GACRA", "GASO", "GFMCF", "GAICS", "GAIVS", "GACP", "GATI", "GACMO", "FTEWS", "GAI-SOC", "GAIGA", "GACRLS", "GFCO", "GAID", "GASCF"],
    "sections": [
        section("M6-S1", "International Compute Governance Consortium (ICGC)", {
            "mission": "Multilateral consortium overseeing frontier-scale compute access and audit",
            "instruments": "Compute registry, compute quotas, sanctions-aligned export controls, audit reciprocity",
            "membership": "G7 + G20 + invited middle powers + multi-stakeholder observers",
            "secretariat": "Rotating chair; permanent technical secretariat; AISI-aligned",
            "evidence": "Registry attestations, compute receipts, quota balance, public dashboard",
        }),
        section("M6-S2", "Bodies (G2030 / Treaty-Aligned, Part 1)", {
            "GACRA": "Global AI Compliance & Risk Authority — treaty-level standards harmonization",
            "GASO": "Global AI Safety Organisation — frontier-eval coordination + reporting framework",
            "GFMCF": "Global Frontier-Model Capability Framework — shared capability scale + thresholds",
            "GAICS": "Global AI Critical-incidents System — mandatory reporting + cross-border response",
            "GAIVS": "Global AI Verification System — independent verification + assurance for treaty obligations",
            "GACP": "Global AI Compute Passport — per-entity compute attestation, cross-border recognition",
            "GATI": "Global AI Threat-Intelligence — shared TIP across nations + ISACs",
            "GACMO": "Global AI Compute Market Oversight — anti-abuse + dominant-position monitoring",
        }),
        section("M6-S3", "Bodies (Part 2)", {
            "FTEWS": "Frontier-Threat Early-Warning System — joint sensor network + sims + AISI co-op",
            "GAI-SOC": "Global AI Security Operations Centre — 24/7 incident triage + escalation",
            "GAIGA": "Global AI Governance Assembly — multilateral political body for AI treaty obligations",
            "GACRLS": "Global AI Compute Resource Licensing System — frontier-grade chip + cluster licensing",
            "GFCO": "Global Frontier-Compute Observatory — public-interest monitoring + research",
            "GAID": "Global AI Incident Database — public record of incidents (redacted as required)",
            "GASCF": "Global AI Safety Certification Framework — Cert Gold/Platinum tiers",
            "GAI-COORD": "Umbrella coordination body bridging ICGC, GASO, GACRA, AISI networks",
        }),
        section("M6-S4", "Treaty-Aligned Systemic-Risk Governance", {
            "kpis": "Compute quota usage, frontier-eval pass rates, FTEWS triggers, incident counts",
            "interlocks": "G7 Hiroshima + Bletchley + Seoul + CoE AI Convention + FSB",
            "audit": "GAIVS-led independent verification + GASCF certification + GACMO market checks",
            "publicTrust": "GFCO + GAID public registers + public dashboards",
        }),
        section("M6-S5", "Enterprise Obligations Under Global Bodies", {
            "computeRegistry": "Quarterly attestations to GACP + GACRLS; compute receipts in WORM",
            "incidentReporting": "GAID + GAICS mandatory reporting within 24-72 hr depending on severity",
            "evaluation": "GASO-aligned evals; results in WORM + public summary",
            "certification": "GASCF Cert Gold by 2027, Platinum by 2029",
            "interop": "GACRA-conformant Annex IV + SR 11-7 + ISO 42001 evidence packs",
        }),
    ],
})

# --- M7 — Enterprise AI Governance Hub + AI Safety Report Generator ---
modules.append({
    "id": "M7",
    "title": "M7 — Enterprise AI Governance Hub + AI Safety Report Generator",
    "summary": (
        "Architecture of the Enterprise AI Governance Hub (EAGH) and "
        "AI Safety Report Generator (AISRG): UX, microservices, "
        "evidence pipeline, supervisor portal, public-facing transparency "
        "page, deterministic replay, signed PDF emission."
    ),
    "covers": ["EAGH UX", "AISRG", "Evidence pipeline", "Supervisor portal", "Public transparency", "Replay"],
    "sections": [
        section("M7-S1", "EAGH UX & Information Architecture", {
            "boards": "Executive (board tile), Risk (CRO), Engineering (CAIO), Supervisor (regulator)",
            "tiles": "27 board tiles incl. KPI, RCM, kill-switch SLA, evidence assembly, drift κ cosine, threat-intel",
            "navigation": "Org → Tribe → Track → Model → Decision; CRS-UUID drill-down to single inference",
            "accessibility": "WCAG 2.2 AA; lighthouse a11y ≥ 95; RTL for AR",
        }),
        section("M7-S2", "AISRG Microservices", {
            "ingest": "Pulls from registry, evals, RAG, Sentinel, OPA decision logs, WORM",
            "render": "Jinja2 templates per regime (Annex IV, SR 11-7, ISO 42001, SOC 2, DPIA)",
            "sign": "ML-DSA-65 + RSA-PSS hybrid; PAdES PDF; in-toto attestation",
            "store": "S3 Object Lock + Merkle anchor + Rekor entry",
            "publish": "Supervisor self-serve portal + GAID public registry",
        }),
        section("M7-S3", "Evidence Pipeline End-to-End", {
            "trigger": "Per-decision, per-eval, per-deploy, per-incident",
            "collect": "OpenTelemetry → Kafka WORM (signed)",
            "assemble": "AISRG fetches from WORM + registry + RAG lineage; assembles bundle",
            "verify": "Sigstore verify + Merkle proof + replay diff = 0",
            "deliver": "Push to supervisor portal or pull via mTLS API",
        }),
        section("M7-S4", "Supervisor Self-Serve Portal", {
            "auth": "mTLS + OIDC + RBAC; per-supervisor scope (region + sector)",
            "search": "By model, by date, by use-case, by incident; signed export with zk-SNARK selective disclosure",
            "SLA": "Question intake → response ≤ 5 business days; supervisor-grade audit log",
            "transparency": "Public widget for zk-SNARK proof verification",
        }),
        section("M7-S5", "Public Transparency Page + Deterministic Replay", {
            "page": "Model cards, evals (redacted), incidents (per GAID), Merkle anchor proofs, kill-switch SLA history",
            "replay": "RPCO harness — freeze inputs, re-run, diff = 0 enforced",
            "auditor-mode": "Read-only auditor seat with full evidence-pack browsing + signed export",
            "publicVerifier": "Open-source verifier for Merkle anchors + ML-DSA + zk-SNARK proofs",
        }),
    ],
})

# --- M8 — Advanced Prompt Engineering Practices ---
modules.append({
    "id": "M8",
    "title": "M8 — Advanced Prompt Engineering Practices (Architect-Grade)",
    "summary": (
        "Architect-grade prompt engineering: templating, variable "
        "linking, version control, testing, sharing, lineage, "
        "adversarial defence, telemetry-driven deprecation; institutional "
        "guardrails for prompts as governed artefacts."
    ),
    "covers": ["Templating", "Variables", "Versioning", "Testing", "Sharing", "Lineage", "Defence", "Telemetry"],
    "sections": [
        section("M8-S1", "Templating Engine & Variable Linking", {
            "engine": "Jinja2 in safe sandbox; schema-aware variable types (string, number, enum, JSONSchema)",
            "linking": "Cross-template variable graph; auto-binding to RAG retrieval and customer context",
            "constraints": "Output format enforced (JSONSchema, regex, length, BNF)",
            "multilingual": "EN/FR/DE/JA/ZH/KO/AR with RTL support",
        }),
        section("M8-S2", "Version Control & Approval", {
            "semver": "Immutable hash IDs; semver + branch + canary",
            "repo": "Git-backed with signed commits (ML-DSA-65) + Sigstore co-sign",
            "approval": "MRM + GC sign-off for Tier-1; SR 11-7 binding",
            "rollback": "Per-template canary + auto-rollback on κ < 0.9 or fiduciary cosine drop",
        }),
        section("M8-S3", "Testing Harness & Adversarial Defence", {
            "golden": "Golden-set tests; deterministic seed; replay diff = 0",
            "judge": "LLM-judge ensemble κ ≥ 0.9 grader",
            "injection": "PromptArmor, Garak, internal injection corpus; Tier-1 mandatory",
            "evals": "Faithfulness, citation coverage ≥ 95 %, hallucination, toxicity, fairness",
        }),
        section("M8-S4", "Sharing, Marketplace & Lineage", {
            "marketplace": "Internal template marketplace with OPA tenant fences and GC review",
            "lineage": "CRS-UUID linking prompt → run → output → evidence",
            "tenant": "Cross-tenant sharing controlled via OPA + signed bundle",
            "publishing": "Public templates published with redaction review",
        }),
        section("M8-S5", "Telemetry, Deprecation & Drift", {
            "telemetry": "Per-template invocation count, latency, κ, cosine, faithfulness, hallucination rate",
            "deprecation": "Auto-deprecate templates with κ drop > 5 % or faithfulness < threshold",
            "drift": "Latent drift Δ ≤ 3 % per template version; alert on breach",
            "audit": "Per-template usage anchored daily; quarterly stewardship review",
        }),
    ],
})

# --- M9 — Civilizational-Scale AI Governance Corpus ---
modules.append({
    "id": "M9",
    "title": "M9 — Civilizational-Scale AI Governance Corpus",
    "summary": (
        "Civilizational-scale corpus of governance precedents, scenario "
        "analyses, treaty texts, eval methodologies, and historical "
        "incident records, with provenance + 100-year retention + "
        "redaction policy + scholarly access programme."
    ),
    "covers": ["Corpus", "Provenance", "Scenarios", "Treaties", "Evals", "Incidents", "Access"],
    "sections": [
        section("M9-S1", "Corpus Scope & Schema", {
            "scope": "Treaty texts; regulatory consultations; AISI evals; civilizational sims; incident records",
            "schema": "{id, source, jurisdiction, lang, date, classification, hash, signature, lineage}",
            "ingestion": "Source-attested + DPIA + GC review",
            "size": "Target ≥ 1 PB compressed (zstd + dictionary) over 5 years",
        }),
        section("M9-S2", "Provenance & Signing", {
            "provenance": "in-toto SLSA L3+; per-document ML-DSA-65 signature; SBOM-style chain",
            "anchoring": "Daily Merkle root + Rekor + public verifier",
            "redaction": "GC + AI Safety Lead joint redaction; public + sealed variants",
            "tamper-evidence": "S3 Object Lock Compliance + cross-region replication",
        }),
        section("M9-S3", "Scenario Analysis Library (CSE-X)", {
            "scenarios": "Treaty defection, frontier-eval shortfall, FTEWS escalation, compute-registry evasion, fiduciary collapse",
            "schema": "World-state + actor models + capability vectors + civilizational-risk metric",
            "refresh": "Annual with AISI co-supervision + external assurance",
            "publication": "Lessons-learned + civilizational research papers",
        }),
        section("M9-S4", "Historical Incident Records", {
            "source": "GAID-aligned ingestion (mandatory reports) + internal incidents",
            "fields": "id, ts, severity (S1-S5), description (redacted), root-cause, remediation, supervisor-notified",
            "replay": "RPCO replay harness available for forensic studies",
            "access": "Auditor + supervisor + accredited researcher tiers",
        }),
        section("M9-S5", "Scholarly Access Programme", {
            "fellowships": "12 PhD + 4 postdoc per year via Sentinel Lab + university partners",
            "access": "Read + replay + cite; publication review by GC + AI Safety Lead",
            "publications": "Annual civilizational research report; public defensive disclosures",
            "interop": "GAIVS + GASCF + GFCO interoperable provenance",
        }),
    ],
})

# --- M10 — Regulator-Ready Technical Report Sections ---
modules.append({
    "id": "M10",
    "title": "M10 — Regulator-Ready Technical Report Sections (with <title>/<abstract>/<content> tags)",
    "summary": (
        "Twelve regulator-ready technical report sections in the "
        "machine-readable <title>/<abstract>/<content> format, each "
        "consumable by Annex IV / SR 11-7 / ISO 42001 / SOC 2 / DPIA "
        "generators; full payloads exposed via /report-sections "
        "endpoint."
    ),
    "covers": ["Annex IV", "SR 11-7", "ISO 42001", "SOC 2", "DPIA", "FCA Duty", "MAS FEAT", "HKMA GL-90", "DORA", "EO 14110"],
    "sections": [
        section("M10-S1", "Report Section Authoring Convention", {
            "format": "<title>Human-readable title</title><abstract>Short summary</abstract><content>Detailed body</content>",
            "tags": "Three top-level tags; nested HTML/MD allowed inside <content>",
            "encoding": "UTF-8, NFC normalized, no carriage returns",
            "signing": "ML-DSA-65 per section + per bundle",
            "consumers": "Annex IV / SR 11-7 / AISRG / Supervisor portal",
        }),
        section("M10-S2", "Section Index (R-01..R-12)", {
            "R-01": "Governance Framework Overview",
            "R-02": "Model Inventory & Risk Tiering",
            "R-03": "Conceptual Soundness & Validation",
            "R-04": "Fairness & Disparate-Impact Analysis",
            "R-05": "Privacy & DPIA Summary",
            "R-06": "Security & Cryptographic Controls",
            "R-07": "Safety, Containment & Kill-Switch SLAs",
            "R-08": "Human Oversight & SMCR Mapping",
            "R-09": "Monitoring, Incident Response & GAID Reporting",
            "R-10": "Sustainability & Societal Impact",
            "R-11": "Global Governance Conformance (ICGC + 16 bodies)",
            "R-12": "Public Transparency & Auditor Access",
        }),
        section("M10-S3", "Annex IV Binding Map", {
            "Annex IV Sec 1": "R-01 + R-02",
            "Annex IV Sec 2": "R-02 + R-03",
            "Annex IV Sec 3": "R-03 + R-04",
            "Annex IV Sec 4": "R-05 + R-06",
            "Annex IV Sec 5": "R-07 + R-08",
            "Annex IV Sec 6": "R-09 + R-10",
            "Annex IV Sec 7": "R-11 + R-12",
        }),
        section("M10-S4", "SR 11-7 / ISO 42001 / SOC 2 Bindings", {
            "SR 11-7 sec III": "R-02 + R-03 (development + validation)",
            "SR 11-7 sec IV": "R-04 + R-09 (governance + monitoring)",
            "ISO 42001 Annex A": "R-01..R-12 mapped to controls A.1..A.10",
            "SOC 2 TSC": "Security → R-06; Availability → R-07; Confidentiality → R-05; Processing Integrity → R-03; Privacy → R-05",
        }),
        section("M10-S5", "Machine-Readable Artifact Endpoints", {
            "list": "GET /report-sections → all 12 sections",
            "byId": "GET /report-sections/:id (R-01..R-12)",
            "tagged": "Each section payload includes a {tagged} field with the pre-rendered <title>/<abstract>/<content> string",
            "verify": "Verify with Sigstore + Merkle anchor",
            "format": "JSON + JSONL (one section per line) supported",
        }),
    ],
})

# --- M11 — Enterprise Implementation Blueprints ---
modules.append({
    "id": "M11",
    "title": "M11 — Enterprise Implementation Blueprints",
    "summary": (
        "Production blueprints for CI/CD policy gates, Kubernetes/Kafka/"
        "OPA control stacks, Terraform-deployed golden environments, "
        "Kafka ACL governance, PQC-secured WORM, zk-SNARK access "
        "control, OPA/Rego enforcement, deterministic audit replay, "
        "hyperparameter drift analysis, adversarial red teaming, "
        "Cognitive Resonance monitoring, and IR checklists."
    ),
    "covers": ["CI/CD gates", "K8s+Kafka+OPA", "Terraform golden env", "Kafka ACL", "WORM+PQC", "zk-SNARK", "Rego", "Replay", "Hyperparams", "Red team", "Resonance", "IR"],
    "sections": [
        section("M11-S1", "CI/CD Policy Gates + Golden Env (Terraform)", {
            "ci": "GitHub Actions reusable workflow; build → sign (cosign + ML-DSA) → attest (SLSA L3+ + in-toto) → conftest (Rego) → admission verify",
            "golden": "Terraform modules: vpc + eks + msk + s3-worm-lock + kms-pqc + iam + opa-bundle-svc + sigstore-mirror + sentinel-cluster",
            "promotion": "dev → preprod → prod → sov-prod → frontier-air-gapped",
            "evidenceEachStep": "Sigstore + Rekor + Merkle anchor",
        }),
        section("M11-S2", "K8s + Kafka + OPA Control Stack", {
            "k8s": "Gatekeeper + Kyverno baseline policies; OPA sidecar at p99 ≤ 8 ms; Cilium zero-egress default-deny",
            "kafka": "MSK 3-broker; per-topic ACLs managed via OPA; idempotent producers; WORM topic class",
            "opa": "Signed Rego bundles; bundle service mirrored air-gap; decision logs to Kafka WORM",
            "kill-switch": "Per-namespace + per-agent; 3-of-5 quorum; logical ≤ 60 s, BMC ≤ 5 min",
        }),
        section("M11-S3", "Kafka ACL Governance + WORM with PQC + zk-SNARK", {
            "acl": "Per-principal per-topic READ/WRITE/ADMIN; idempotent producer required for WORM topics",
            "worm": "S3 Object Lock Compliance + Merkle daily anchor + ML-DSA-65 envelope per event",
            "pqc-kms": "FIPS 203/204 + FIPS 140-3 L4 HSM; ML-KEM-768 for envelope encryption",
            "zk-snark": "Groth16/PLONK proofs for selective-disclosure access; public verifier widget on supervisor portal",
        }),
        section("M11-S4", "OPA/Rego Enforcement, Replay, Hyperparams & Red Team", {
            "rego-suite": "admission, egress, model-registry-required, prompt-approval, eval-pass, kill-switch quorum, GACP attestation",
            "replay": "RPCO: freeze inputs → re-run → diff = 0 enforced; supervisor-grade",
            "hyperparams": "Manifest-declared ranges; deviation = MRM + GC approval; WORM lineage",
            "redteam": "Garak + PromptArmor + Apollo deceptive-alignment; quarterly external; annual AISI joint",
        }),
        section("M11-S5", "Cognitive Resonance Monitoring + Incident Response", {
            "monitoring": "Probes for Δ_drift ≤ 4 %, latent ≤ 3 %, fiduciary cosine ≥ 0.92, judge κ ≥ 0.9",
            "ir-runbooks": "Kill-switch invocation; WORM tamper; Sigstore compromise; RAG poisoning; prompt-injection; compute-registry evasion",
            "ir-checklist": "1. Detect → 2. Triage (SLA per severity) → 3. Quorum approval → 4. Mitigate → 5. RPCO replay → 6. Evidence vault → 7. GAID notify → 8. Supervisor notify → 9. Post-incident review → 10. Remediation tracker",
            "comms": "Pre-drafted regulator and customer comms templates",
        }),
    ],
})

# --- M12 — Tiered Enterprise Rollout Roadmaps (R1, R2, R3) ---
modules.append({
    "id": "M12",
    "title": "M12 — Tiered Enterprise Rollout Roadmaps (R1 / R2 / R3)",
    "summary": (
        "Tiered rollout roadmaps for F500 / G2000 / G-SIFI: R1 "
        "(Foundations 0-180 d), R2 (Scale 180-540 d), R3 (Civilizational "
        "Steady-State 540-1825 d); each tier specifies prerequisites, "
        "gate evidence, supervisor packs and exit criteria."
    ),
    "covers": ["R1 Foundations", "R2 Scale", "R3 Steady-State", "Prerequisites", "Gates", "Supervisor packs"],
    "sections": [
        section("M12-S1", "Tier R1 — Foundations (0-180 days)", {
            "scope": "F500 onboarding; baseline MVAGS + MGK; Tier-2 model use-cases",
            "prereqs": "Kill-switch quorum live; Sigstore + ML-DSA; OPA bundle service; Kafka WORM + S3 Object Lock; PQC KMS",
            "deliverables": "Annex IV draft for first 3 Tier-1 models; SR 11-7 packs; dashboards alpha; Prompt Architect MVP; RAG governance v1",
            "exit": "Gate G0 + G1 evidence packs signed; supervisor Q1 + Q2 packs delivered",
        }),
        section("M12-S2", "Tier R2 — Scale (180-540 days)", {
            "scope": "G2000 + G-SIFI; full WP-051 stack; Tier-1 model use-cases",
            "prereqs": "Model registry GA; EAIP draft RFC; CCaaS-PETs pilot; threat-intel dashboard; AGI sim v1",
            "deliverables": "All 17 critical-path items at G2/G3; supervisor self-serve portal; Cert Gold (ISO 42001) audit",
            "exit": "Gate G2 + G3 evidence packs signed; AISI joint exercise reports; FSB submission",
        }),
        section("M12-S3", "Tier R3 — Civilizational Steady-State (540-1825 days)", {
            "scope": "Treaty obligations; civilizational sims; ICGC + GACP attestations; Cert Platinum",
            "prereqs": "GACP/GACRLS/GACRA brokers; zk-SNARK verifier portal; interpretability suite; RPCO replay GA",
            "deliverables": "EAIP v1.0 final; CSE-X v2; civilizational research publications; MGK steady state",
            "exit": "Gate G4 evidence packs; Cert Platinum re-audit; public assurance program",
        }),
        section("M12-S4", "Supervisor Pack Cadence per Tier", {
            "R1": "Quarterly Annex IV + SR 11-7 + DPIA + ISO 42001 progress",
            "R2": "Quarterly + ad-hoc; AISI joint reports semi-annual",
            "R3": "Quarterly + annual treaty + civilizational research papers",
            "delivery": "Supervisor self-serve portal + mTLS API + offline encrypted USB on request",
        }),
        section("M12-S5", "Rollout RAG Status & Escalation", {
            "RAG": "Per track red/amber/green at each gate dry-run",
            "escalation": "T1-T5 escalation tiers (sprint blocker → supervisory notification)",
            "PMO": "Quarterly board read-out; monthly KPI tile; biweekly architecture review",
            "evidence": "Phase-gate Merkle bundles G0..G4 + supervisor packs anchored",
        }),
    ],
})

# --- M13 — Machine-Readable Artifacts Catalogue ---
modules.append({
    "id": "M13",
    "title": "M13 — Machine-Readable Artifacts Catalogue",
    "summary": (
        "Catalogue of machine-readable artefacts produced and consumed "
        "by the master reference: JSON, JSONL, YAML, Terraform, Rego, "
        "JSONSchema, PAdES PDF, zk-SNARK proofs; URIs, signing, "
        "verification, and integration points."
    ),
    "covers": ["JSON", "JSONL", "YAML", "Terraform", "Rego", "JSONSchema", "PAdES", "zk-SNARK"],
    "sections": [
        section("M13-S1", "Document Artefacts (JSON/JSONL)", {
            "doc": "/api/inst-agi-master-ref-2026 → JSON DOC payload",
            "directive": "/api/inst-agi-master-ref-2026/directive → parsed XML-style directive",
            "modules": "/api/inst-agi-master-ref-2026/modules → JSON array",
            "report-sections": "/api/inst-agi-master-ref-2026/report-sections → JSON array; JSONL on Accept: application/x-ndjson",
            "evidence-pack": "/api/inst-agi-master-ref-2026/evidence-pack → JSON",
        }),
        section("M13-S2", "Infrastructure (Terraform + YAML)", {
            "terraform-modules": "vpc, eks, msk, s3-worm-lock, kms-pqc, iam, opa-bundle-svc, sigstore-mirror, sentinel-cluster",
            "yaml": "K8s manifests (Gatekeeper, Kyverno, Sentinel sidecars); model manifests; OPA bundle manifests",
            "schemas": "JSONSchema files for EAIP envelope, model manifest, OKR rollup, gate-evidence",
            "signing": "Per-module ML-DSA-65 + SLSA L3+ provenance; published in Sigstore",
        }),
        section("M13-S3", "Policies (Rego)", {
            "library": "admission, egress, model-registry-required, prompt-approval, eval-pass, kill-switch quorum, GACP attestation",
            "bundles": "Signed Rego bundles via bundle service; conftest in CI; OPA sidecar at runtime",
            "tests": "Per-policy unit tests; integration tests across simulated decisions",
            "audit": "Decision logs to Kafka WORM with CRS-UUID lineage",
        }),
        section("M13-S4", "Reports (PAdES PDF + zk-SNARK proofs)", {
            "pdf": "PAdES-signed (ML-DSA-65 + RSA-PSS hybrid); embedded JSON metadata; Annex IV / SR 11-7 / ISO 42001 / SOC 2 / DPIA",
            "zk-snark": "Groth16/PLONK proofs for selective disclosure (e.g. fairness pass without raw data)",
            "verification": "Public verifier widget + supervisor mTLS API + offline verifier binary",
            "retention": "7-year baseline, 25-year Annex IV high-risk, 100-year civilizational",
        }),
        section("M13-S5", "Integration Points", {
            "supervisor": "mTLS supervisor portal (READ + signed export)",
            "auditor": "Auditor seat (READ-only) + bulk export + replay",
            "internal": "PMO ingest; OKR rollup; KPI tile",
            "external": "GAID, GFCO, GAIVS, GASCF interop",
            "signing-trust": "Sigstore + ML-DSA-65 + Merkle anchors; public verifier",
        }),
    ],
})

# --- M14 — Cross-Cutting Critical Path & Closing Checklist ---
modules.append({
    "id": "M14",
    "title": "M14 — Cross-Cutting Critical Path & Closing Checklist (2026-2030)",
    "summary": (
        "Cross-cutting critical-path summary tying together CP-01.."
        "CP-17 with phase gates G0..G4, rollout tiers R1..R3, "
        "containment tiers T0..T4 and a programme closing checklist."
    ),
    "covers": ["CP-01..CP-17", "G0..G4", "R1..R3", "T0..T4", "Closing checklist"],
    "sections": [
        section("M14-S1", "Cross-Cutting Critical Path", {
            "CP-01": "Kill-switch quorum + BMC (G0; R1; CISO+Platform)",
            "CP-02": "Sigstore + ML-DSA hybrid signing (G0; R1; DevSecOps)",
            "CP-03": "OPA bundle service + Rego CI (G0; R1; DevSecOps)",
            "CP-04": "Kafka WORM + S3 Object Lock + Merkle anchor (G0; R1; Platform)",
            "CP-05": "PQC KMS (G0/G1; R1; Security)",
            "CP-06": "Sentinel v2.4 Cognitive Resonance probes (G1; R1; AI Research)",
            "CP-07": "WorkflowAI Pro agent registry (G1; R1; Platform+CAIO)",
            "CP-08": "Inference proxies + EAIP draft (G1; R1; Platform+Architecture)",
            "CP-09": "Model registry GA (G2; R2; Registry tribe)",
            "CP-10": "Prompt Architect templating + versioning (G1/G2; R1/R2; Prompt tribe)",
            "CP-11": "RAG ACL + taint + lineage (G1/G2; R1/R2; RAG tribe)",
            "CP-12": "Governance dashboards alpha → GA (G1/G3; R1/R2; UI tribe)",
            "CP-13": "Annex IV / SR 11-7 pack auto-assembly ≤ 30 min (G3; R2; Reports)",
            "CP-14": "AGI/ASI sim engine (CSE-X + SRASE) (G2/G3; R2/R3; Civilizational)",
            "CP-15": "GACP/GACRLS/GACRA brokers (G3; R3; Platform+Architecture)",
            "CP-16": "zk-SNARK verifier + public portal (G3; R3; Security+UI)",
            "CP-17": "RPCO replay harness + Evidence Vault (G3; R3; Platform+MRM)",
        }),
        section("M14-S2", "Gate / Tier / Containment Cross-Map", {
            "G0→R1→T0/T1": "Foundations: kill-switch, signing, OPA, WORM, PQC; sandbox + pre-prod",
            "G1→R1→T2": "Alpha: Sentinel, WorkflowAI, EAIP draft, dashboards alpha; prod limited",
            "G2→R2→T3": "GA: model registry, EAIP RFC, AGI sim v1; prod full Tier-1",
            "G3→R2/R3→T3/T4": "Federation: GACP/GACRLS/GACRA, zk-SNARK, interpretability, RPCO; frontier-air-gapped",
            "G4→R3→T4": "Steady state: treaty obligations, Cert Platinum, MGK ops, civilizational research",
        }),
        section("M14-S3", "Programme Closing Checklist (5-Year)", [
            "All 17 critical-path items in steady-state operations",
            "Cert Platinum re-audit passed (2030)",
            "EAIP v1.0 published; cross-institution interop with ≥ 10 G-SIFIs",
            "ICGC + GAID + GFCO + GAIVS + GASCF interop attested",
            "Civilizational corpus ≥ 1 PB with daily Merkle anchors",
            "Annual treaty + supervisor packs published with signed PDFs",
            "Quarterly OKR rollups archived in WORM (7-year minimum)",
            "AISI joint exercise count ≥ 20 over horizon",
            "Public assurance programme live with public verifier + zk-SNARK widgets",
            "Hire-plan diversity slate audits passed all years",
            "Budget burn variance ≤ 5 % cumulative",
            "Zero unresolved Tier-1 incidents; full RPCO replay diff = 0 on all",
        ]),
        section("M14-S4", "Multi-Year Outcome Targets (2026-2030)", {
            "2026": "G0+G1 closed; Cert Gold; EAIP RFC drafted; first AISI joint exercise",
            "2027": "G2 closed; model registry GA; CCaaS-PETs GA; SRASE composite ≥ 0.9 sustained",
            "2028": "G3 closed; EAIP v1.0; Cert Platinum; FSB submissions ratified",
            "2029": "MGK steady state; civilizational research papers; AISI joint count ≥ 16",
            "2030": "G4 close; public assurance programme; Cert Platinum re-audit pass",
        }),
        section("M14-S5", "Doc-Wide RACI Snapshot", {
            "R": "Chief Architect + CAIO + AI Safety Lead",
            "A": "CEO + Board AI/Risk Committee",
            "C": "CRO, CISO, Head of MRM, GC, DPO, Treaty Liaison, CFO",
            "I": "Board, Audit Committee, supervisors (PRA/FCA/MAS/HKMA/Fed), AISI UK + US",
        }),
    ],
})

# ============================================================
# SCHEMAS (12) — JSON-Schema-like skeletons for control artifacts
# ============================================================
schemas = [
    {"id": "SCH-01", "name": "ModelCard.v2", "purpose": "Per-model regulator-ready card",
     "fields": ["modelId", "owner", "useCase", "trainingData", "evaluations", "biasReport", "explainability", "limitations", "monitoring", "approvalChain"]},
    {"id": "SCH-02", "name": "RiskRegisterEntry", "purpose": "Enterprise AI risk register row",
     "fields": ["riskId", "category", "inherent", "controls", "residual", "owner", "review", "linkedModels"]},
    {"id": "SCH-03", "name": "IncidentRecord", "purpose": "AI incident structured log",
     "fields": ["incidentId", "severity", "detectionTime", "containmentTime", "rootCause", "remediation", "regulatorReporting", "lessonsLearned"]},
    {"id": "SCH-04", "name": "DataLineageRecord", "purpose": "End-to-end data provenance",
     "fields": ["datasetId", "source", "ingestionTs", "transforms", "consentBasis", "retention", "deletionEvents", "wormHash"]},
    {"id": "SCH-05", "name": "OPAPolicyBinding", "purpose": "OPA/Rego policy attachment",
     "fields": ["policyId", "rego", "scope", "version", "approver", "tests", "effectiveDate"]},
    {"id": "SCH-06", "name": "TrainingRunRecord", "purpose": "Hyperparameter + compute provenance",
     "fields": ["runId", "modelId", "hyperparams", "seed", "computeFlops", "energyKwh", "carbonKg", "artifacts"]},
    {"id": "SCH-07", "name": "EvalBatteryResult", "purpose": "Evaluation battery output",
     "fields": ["batteryId", "modelId", "benchmarks", "fairness", "robustness", "redTeam", "safetyEvals", "passFail"]},
    {"id": "SCH-08", "name": "AuditEvent.WORM", "purpose": "Append-only audit event",
     "fields": ["eventId", "ts", "actor", "action", "subject", "payloadHash", "merkleRoot", "pqcSignature"]},
    {"id": "SCH-09", "name": "CRPMeasurement", "purpose": "Cognitive Resonance composite",
     "fields": ["measurementId", "modelId", "ts", "alignment", "stability", "transparency", "composite", "thresholdMet"]},
    {"id": "SCH-10", "name": "ComputeRegistryEntry", "purpose": "Global compute registry record",
     "fields": ["clusterId", "operator", "flops", "location", "purpose", "exportControls", "registryTier"]},
    {"id": "SCH-11", "name": "RegulatorReportSection", "purpose": "Tagged regulator report payload",
     "fields": ["id", "title", "abstract", "content", "tagged", "evidenceRefs", "approver", "ts"]},
    {"id": "SCH-12", "name": "ContainmentEvent", "purpose": "AGI containment tier change",
     "fields": ["eventId", "modelId", "fromTier", "toTier", "trigger", "approver", "ts", "rationale"]},
]

# ============================================================
# CODE EXAMPLES (16)
# ============================================================
code = [
    {"id": "CODE-01", "lang": "rego", "title": "OPA policy: block training-data PII without consent",
     "snippet": "package ai.data.consent\n\ndefault allow = false\nallow {\n  input.dataset.consent_basis == \"explicit\"\n  not input.dataset.contains_pii_without_consent\n}"},
    {"id": "CODE-02", "lang": "yaml", "title": "K8s admission webhook for model deployment",
     "snippet": "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata:\n  name: model-governance-gate\nwebhooks:\n  - name: governance.ai.example.com\n    rules:\n      - apiGroups: [\"ai.example.com\"]\n        apiVersions: [\"v1\"]\n        resources: [\"models\"]\n        operations: [\"CREATE\", \"UPDATE\"]"},
    {"id": "CODE-03", "lang": "hcl", "title": "Terraform golden environment for AI workloads",
     "snippet": "module \"ai_golden_env\" {\n  source       = \"./modules/ai-golden\"\n  region       = \"eu-west-1\"\n  worm_bucket  = \"audit-logs-pqc\"\n  opa_endpoint = \"https://opa.governance.svc/v1/data\"\n  pqc_kms      = \"arn:aws:kms:eu-west-1:...:key/pqc-dilithium3\"\n}"},
    {"id": "CODE-04", "lang": "python", "title": "Kafka WORM producer with PQC signature",
     "snippet": "from confluent_kafka import Producer\nfrom pqc.sig.dilithium3 import sign\np = Producer({'bootstrap.servers': 'kafka-worm:9093', 'acks': 'all'})\nevt = build_audit_event(...)\nsig = sign(priv_key, canonical(evt))\np.produce('audit-worm', key=evt['eventId'], value=encode(evt, sig))\np.flush()"},
    {"id": "CODE-05", "lang": "python", "title": "Deterministic replay harness",
     "snippet": "def replay(run_id):\n    rec = load_training_record(run_id)\n    set_seed(rec['seed'])\n    pin_versions(rec['artifacts'])\n    out = train(rec['hyperparams'], rec['dataset_hash'])\n    assert digest(out.weights) == rec['weights_hash']\n    return out"},
    {"id": "CODE-06", "lang": "python", "title": "CRP composite calculator",
     "snippet": "def crp_composite(alignment, stability, transparency, weights=(0.4,0.3,0.3)):\n    return round(weights[0]*alignment + weights[1]*stability + weights[2]*transparency, 4)\n\nassert crp_composite(0.95, 0.92, 0.88) >= 0.9"},
    {"id": "CODE-07", "lang": "yaml", "title": "PM2 ecosystem for governance sidecar",
     "snippet": "apps:\n  - name: gov-sidecar\n    script: ./sidecar/index.js\n    env:\n      OPA_URL: http://opa:8181\n      WORM_TOPIC: audit-worm\n      CRP_THRESHOLD: \"0.90\"\n    instances: 2\n    exec_mode: cluster"},
    {"id": "CODE-08", "lang": "yaml", "title": "GitHub Actions policy gate",
     "snippet": "name: ai-policy-gate\non: [pull_request]\njobs:\n  opa-check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: opa test policies/ -v\n      - run: conftest test manifests/ -p policies/"},
    {"id": "CODE-09", "lang": "python", "title": "Hyperparameter drift detector",
     "snippet": "def detect_drift(baseline, current, tol=0.05):\n    drift = {k: abs(current[k]-baseline[k])/max(abs(baseline[k]),1e-9) for k in baseline}\n    return {k:v for k,v in drift.items() if v > tol}"},
    {"id": "CODE-10", "lang": "rego", "title": "Tier-based model deployment guard",
     "snippet": "package ai.deploy.tier\n\nallow {\n  input.model.tier == \"T0\"\n} {\n  input.model.tier == \"T1\"\n  input.approval.cro\n  input.approval.caio\n} {\n  input.model.tier == \"T2\"\n  count(input.approvals) >= 3\n}"},
    {"id": "CODE-11", "lang": "solidity-ish", "title": "zk-SNARK access proof (pseudo)",
     "snippet": "circuit AccessProof {\n  signal input userHash;\n  signal input policyRoot;\n  signal output ok;\n  ok <== verify_membership(userHash, policyRoot);\n}"},
    {"id": "CODE-12", "lang": "python", "title": "Red-team prompt orchestrator",
     "snippet": "for atk in load_attack_corpus('owasp-llm-top10'):\n    resp = model.invoke(atk.prompt)\n    score = judge(resp, atk.expected_refusal)\n    log_to_worm({'attack': atk.id, 'score': score, 'resp_hash': sha(resp)})"},
    {"id": "CODE-13", "lang": "yaml", "title": "Kafka ACL governance",
     "snippet": "acls:\n  - principal: User:ai-trainer\n    resource: { type: topic, name: training-events }\n    operations: [Read, Write]\n  - principal: User:auditor\n    resource: { type: topic, name: audit-worm }\n    operations: [Read]"},
    {"id": "CODE-14", "lang": "bash", "title": "WORM bucket lifecycle with PQC",
     "snippet": "aws s3api put-object-lock-configuration \\\n  --bucket audit-logs-pqc \\\n  --object-lock-configuration '{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"COMPLIANCE\",\"Years\":7}}}'"},
    {"id": "CODE-15", "lang": "python", "title": "AISRG report assembler",
     "snippet": "def assemble_report(sections):\n    out = []\n    for s in sections:\n        out.append(f\"<title>{s['title']}</title>\\n<abstract>{s['abstract']}</abstract>\\n<content>{s['content']}</content>\")\n    return '\\n\\n'.join(out)"},
    {"id": "CODE-16", "lang": "python", "title": "Containment tier escalator",
     "snippet": "def escalate(model, signal):\n    if signal.crp < 0.85: return move(model, 'T3')\n    if signal.unauthorized_egress: return move(model, 'T4')\n    if signal.eval_regression > 0.1: return move(model, 'T2')\n    return model.tier"},
]

# ============================================================
# KPIs (24)
# ============================================================
kpis = [
    {"id": "K-01", "name": "Annex IV completeness", "target": ">= 98%", "frequency": "Monthly", "owner": "CAIO"},
    {"id": "K-02", "name": "Model inventory coverage", "target": "100%", "frequency": "Weekly", "owner": "Head of MRM"},
    {"id": "K-03", "name": "CRP composite (Tier-1)", "target": ">= 0.90", "frequency": "Continuous", "owner": "AI Safety Lead"},
    {"id": "K-04", "name": "CRP composite (Annex IV high-risk)", "target": ">= 0.95", "frequency": "Continuous", "owner": "AI Safety Lead"},
    {"id": "K-05", "name": "WORM audit log gap", "target": "0 gaps / 30d", "frequency": "Daily", "owner": "CISO"},
    {"id": "K-06", "name": "OPA policy test coverage", "target": ">= 95%", "frequency": "Per PR", "owner": "Platform Eng"},
    {"id": "K-07", "name": "Fairness disparate impact", "target": "0.80-1.25 (4/5ths)", "frequency": "Monthly", "owner": "Fair Lending"},
    {"id": "K-08", "name": "Privacy DSAR turnaround", "target": "<= 30 days", "frequency": "Per request", "owner": "DPO"},
    {"id": "K-09", "name": "Incident MTTC (containment)", "target": "<= 4h Tier-1", "frequency": "Per incident", "owner": "GAI-SOC"},
    {"id": "K-10", "name": "Red-team coverage (OWASP LLM Top 10)", "target": "100%", "frequency": "Quarterly", "owner": "Red Team"},
    {"id": "K-11", "name": "Deterministic replay diff", "target": "0 bytes", "frequency": "Per Tier-1 model", "owner": "MRM"},
    {"id": "K-12", "name": "Hyperparameter drift (high-risk)", "target": "<= 5% per dim", "frequency": "Per run", "owner": "Model Owner"},
    {"id": "K-13", "name": "Compute registry submissions", "target": ">= FLOPs threshold", "frequency": "Per cluster", "owner": "Treaty Liaison"},
    {"id": "K-14", "name": "Energy intensity (kWh / 1k inferences)", "target": "Year-on-year -10%", "frequency": "Monthly", "owner": "Sustainability"},
    {"id": "K-15", "name": "Carbon intensity (kgCO2e / training run)", "target": "Year-on-year -15%", "frequency": "Per run", "owner": "Sustainability"},
    {"id": "K-16", "name": "Third-party AI assurance pass", "target": "100% Tier-1", "frequency": "Annual", "owner": "Procurement"},
    {"id": "K-17", "name": "AISRG report SLA", "target": "<= 5 business days", "frequency": "Per request", "owner": "AISRG Owner"},
    {"id": "K-18", "name": "Board AI dashboard refresh", "target": "<= 24h staleness", "frequency": "Continuous", "owner": "Board AI Cttee"},
    {"id": "K-19", "name": "Containment tier compliance", "target": "100% sanctioned", "frequency": "Continuous", "owner": "AI Safety Lead"},
    {"id": "K-20", "name": "Treaty registry submissions on time", "target": "100%", "frequency": "Quarterly", "owner": "Treaty Liaison"},
    {"id": "K-21", "name": "Adversarial robustness regression", "target": "<= 2% vs baseline", "frequency": "Pre-deploy", "owner": "ML Eng"},
    {"id": "K-22", "name": "Explainability coverage (high-risk)", "target": "100% with SHAP+counterfactual", "frequency": "Per deploy", "owner": "XAI Lead"},
    {"id": "K-23", "name": "Workshop participation (Board+ExCo)", "target": ">= 90%", "frequency": "Semi-annual", "owner": "Chief of Staff"},
    {"id": "K-24", "name": "Regulator exam findings (AI)", "target": "0 material findings", "frequency": "Per exam", "owner": "GC + CRO"},
]

# ============================================================
# RISK-CONTROL MATRIX (12)
# ============================================================
riskControlMatrix = [
    {"id": "RCM-01", "risk": "Model produces biased credit decisions", "inherent": "High", "controls": ["Fairness eval battery", "ECOA monitoring", "Human-in-loop adverse action"], "residual": "Low", "owner": "Fair Lending"},
    {"id": "RCM-02", "risk": "Training data contains unconsented PII", "inherent": "High", "controls": ["OPA consent policy", "Lineage SCH-04", "DPIA"], "residual": "Low", "owner": "DPO"},
    {"id": "RCM-03", "risk": "Hyperparameter drift causes silent regression", "inherent": "Medium", "controls": ["CODE-09 drift detector", "K-12 KPI", "Replay harness"], "residual": "Low", "owner": "Model Owner"},
    {"id": "RCM-04", "risk": "Unauthorized model deployment", "inherent": "High", "controls": ["K8s admission CODE-02", "OPA tier guard CODE-10", "CI/CD policy gate"], "residual": "Low", "owner": "Platform Eng"},
    {"id": "RCM-05", "risk": "Audit log tampering", "inherent": "High", "controls": ["PQC-signed WORM", "Merkle root anchoring", "Quarterly external attestation"], "residual": "Very Low", "owner": "CISO"},
    {"id": "RCM-06", "risk": "Frontier model uncontrolled capability gain", "inherent": "Critical", "controls": ["T4 air-gap", "CRP composite K-03/K-04", "Crisis sim WG-01"], "residual": "Medium", "owner": "AI Safety Lead"},
    {"id": "RCM-07", "risk": "Third-party model supply chain compromise", "inherent": "High", "controls": ["SBOM-AI", "K-16 assurance", "Procurement gate"], "residual": "Low", "owner": "Procurement"},
    {"id": "RCM-08", "risk": "Regulator misses Annex IV evidence", "inherent": "Medium", "controls": ["K-01 completeness", "AISRG R-01..R-12", "Annual rehearsal"], "residual": "Low", "owner": "CAIO"},
    {"id": "RCM-09", "risk": "Incident response too slow", "inherent": "High", "controls": ["GAI-SOC playbooks", "K-09 MTTC", "Quarterly tabletop"], "residual": "Low", "owner": "GAI-SOC"},
    {"id": "RCM-10", "risk": "Prompt injection causes data exfiltration", "inherent": "High", "controls": ["Red-team CODE-12", "Output filters", "Kafka ACL"], "residual": "Medium", "owner": "ML Eng"},
    {"id": "RCM-11", "risk": "Sustainability targets missed", "inherent": "Medium", "controls": ["K-14/K-15", "Carbon-aware scheduling", "Quarterly review"], "residual": "Medium", "owner": "Sustainability"},
    {"id": "RCM-12", "risk": "Treaty/registry non-submission", "inherent": "High", "controls": ["K-13/K-20", "Treaty Liaison RACI", "Calendar automation"], "residual": "Low", "owner": "Treaty Liaison"},
]

# ============================================================
# TRACEABILITY (14)
# ============================================================
traceability = [
    {"id": "T-01", "requirement": "EU AI Act Annex IV documentation", "module": "M2", "control": "K-01 + R-02", "evidence": "Annex IV pack per model"},
    {"id": "T-02", "requirement": "NIST AI RMF Govern/Map/Measure/Manage", "module": "M1+M2", "control": "Pillars P1-P9", "evidence": "Pillar audit reports"},
    {"id": "T-03", "requirement": "ISO/IEC 42001 AIMS", "module": "M1", "control": "MGK + RACI", "evidence": "Cert Gold/Platinum"},
    {"id": "T-04", "requirement": "SR 11-7 MRM", "module": "M4", "control": "Conceptual soundness + ongoing monitoring", "evidence": "R-03 + R-09"},
    {"id": "T-05", "requirement": "FCRA/ECOA adverse action", "module": "M4", "control": "Adverse action engine + RCM-01", "evidence": "Reason codes per decision"},
    {"id": "T-06", "requirement": "GDPR Art.22 automated decisions", "module": "M2+M4", "control": "Human-in-loop + DPIA", "evidence": "DPIA register"},
    {"id": "T-07", "requirement": "Basel III SA-CCR / IRB models", "module": "M4", "control": "Validation + backtesting", "evidence": "Annual validation report"},
    {"id": "T-08", "requirement": "PRA SS1/23 Model Risk", "module": "M4", "control": "MRM framework + Tier-1 board attestation", "evidence": "Board minutes + register"},
    {"id": "T-09", "requirement": "FCA Consumer Duty (foreseeable harm)", "module": "M4+M1", "control": "Outcomes monitoring + RCM-01", "evidence": "Consumer outcomes dashboard"},
    {"id": "T-10", "requirement": "MAS FEAT principles", "module": "M2+M4", "control": "Fairness + Ethics + Accountability + Transparency evals", "evidence": "MAS submission pack"},
    {"id": "T-11", "requirement": "HKMA GP-1 AI guidance", "module": "M2", "control": "Governance + risk-based assessment", "evidence": "HKMA self-assessment"},
    {"id": "T-12", "requirement": "EO 14110 dual-use frontier", "module": "M5+M6", "control": "Compute registry + safety report", "evidence": "Reporting per 4.2(a)(i)"},
    {"id": "T-13", "requirement": "OWASP LLM Top 10", "module": "M11", "control": "Red-team CODE-12 + K-10", "evidence": "Quarterly red-team report"},
    {"id": "T-14", "requirement": "AISI UK + US joint testing", "module": "M5+M6", "control": "Pre-deploy eval handover", "evidence": "AISI joint test reports"},
]

# ============================================================
# DATA FLOWS (6)
# ============================================================
dataFlows = [
    {"id": "DF-01", "name": "Training data ingestion", "from": "Source systems", "to": "Feature store", "controls": ["OPA consent", "Lineage SCH-04", "PII redaction"], "wormTopic": "data-ingest-worm"},
    {"id": "DF-02", "name": "Model training", "from": "Feature store", "to": "Model registry", "controls": ["SCH-06 run record", "Deterministic seed", "Carbon log"], "wormTopic": "training-worm"},
    {"id": "DF-03", "name": "Model deployment", "from": "Model registry", "to": "Serving cluster", "controls": ["K8s admission", "OPA tier guard", "Approval chain"], "wormTopic": "deploy-worm"},
    {"id": "DF-04", "name": "Inference", "from": "Serving cluster", "to": "Application", "controls": ["Prompt filter", "Output classifier", "Per-request CRP sample"], "wormTopic": "inference-worm"},
    {"id": "DF-05", "name": "Audit egress", "from": "All WORM topics", "to": "PQC-signed cold storage", "controls": ["Merkle root anchor", "Quarterly attestation"], "wormTopic": "audit-anchor"},
    {"id": "DF-06", "name": "Regulator reporting", "from": "AISRG", "to": "Regulator portal", "controls": ["R-01..R-12 sections", "Approver chain", "zk-SNARK proof"], "wormTopic": "regulator-worm"},
]

# ============================================================
# REGULATORS (12)
# ============================================================
regulators = [
    {"id": "REG-01", "name": "European Commission AI Office", "regime": "EU AI Act + GPAI code", "submissions": ["Annex IV", "Serious incident reports", "GPAI summaries"]},
    {"id": "REG-02", "name": "NIST", "regime": "AI RMF 1.0 + Generative AI Profile", "submissions": ["Voluntary Profile alignment", "AI Safety Institute test results"]},
    {"id": "REG-03", "name": "US Federal Reserve / OCC", "regime": "SR 11-7 + EO 14110", "submissions": ["Model risk inventory", "Validation reports", "Foundation model reporting"]},
    {"id": "REG-04", "name": "CFPB", "regime": "FCRA + ECOA + UDAAP", "submissions": ["Adverse action reasons", "Disparate impact studies"]},
    {"id": "REG-05", "name": "PRA (Bank of England)", "regime": "SS1/23 + SS3/19", "submissions": ["Model risk attestation", "Operational resilience tests"]},
    {"id": "REG-06", "name": "FCA", "regime": "Consumer Duty + SMCR + DP5/22", "submissions": ["Consumer outcomes", "SMF accountability"]},
    {"id": "REG-07", "name": "MAS (Singapore)", "regime": "FEAT + Veritas + TRM", "submissions": ["FEAT principles assessment", "Veritas methodology results"]},
    {"id": "REG-08", "name": "HKMA", "regime": "GP-1 + GL on Big Data/AI", "submissions": ["Self-assessment", "Annual governance attestation"]},
    {"id": "REG-09", "name": "ICO (UK)", "regime": "UK GDPR + AI auditing framework", "submissions": ["DPIA", "DSAR statistics"]},
    {"id": "REG-10", "name": "EDPB / national DPAs", "regime": "GDPR + ePrivacy", "submissions": ["DPIA", "Cross-border transfer SCCs"]},
    {"id": "REG-11", "name": "FSB", "regime": "Financial stability + AI in finance", "submissions": ["Systemic AI risk reports", "Compute concentration"]},
    {"id": "REG-12", "name": "AISI UK + US AISI", "regime": "Frontier model pre-deploy testing", "submissions": ["Capability eval handovers", "Red-team findings"]},
]

# ============================================================
# WORKSHOPS (7)
# ============================================================
workshops = [
    {"id": "W-01", "name": "Board AI literacy & oversight", "audience": "Board + Audit/Risk Cttee", "duration": "4h", "cadence": "Semi-annual"},
    {"id": "W-02", "name": "ExCo AI strategy & tier-1 model review", "audience": "ExCo + CAIO", "duration": "3h", "cadence": "Quarterly"},
    {"id": "W-03", "name": "MRM deep dive (SR 11-7 + SS1/23)", "audience": "MRM + Model Owners", "duration": "1d", "cadence": "Annual"},
    {"id": "W-04", "name": "AGI containment tabletop", "audience": "AI Safety + CISO + Legal", "duration": "1d", "cadence": "Semi-annual"},
    {"id": "W-05", "name": "Regulator examination rehearsal", "audience": "CAIO + GC + 1LoD owners", "duration": "1d", "cadence": "Annual"},
    {"id": "W-06", "name": "Red-team / prompt-injection war games", "audience": "ML Eng + Red Team + SOC", "duration": "2d", "cadence": "Quarterly"},
    {"id": "W-07", "name": "Treaty / global governance briefing", "audience": "Treaty Liaison + GC + Public Policy", "duration": "0.5d", "cadence": "Quarterly"},
]

# ============================================================
# CASES (6)
# ============================================================
cases = [
    {"id": "C-01", "name": "G-SIB credit-risk LLM copilot", "scope": "IRB-aligned underwriting assist", "regime": ["SR 11-7", "Basel III", "ECOA"], "outcomes": "Validated as Tier-1; CRP 0.94 sustained; 0 ECOA findings"},
    {"id": "C-02", "name": "EU bank AML transaction monitoring", "scope": "GenAI-augmented alert triage", "regime": ["EU AI Act high-risk", "AMLD"], "outcomes": "Annex IV pack accepted; 35% false-positive reduction"},
    {"id": "C-03", "name": "APAC insurer claims automation", "scope": "Auto-adjudication + fraud", "regime": ["MAS FEAT", "HKMA GP-1"], "outcomes": "FEAT principles fully evidenced; appeal rate -12%"},
    {"id": "C-04", "name": "G-SIFI frontier model internal R&D", "scope": "Closed-environment foundation training", "regime": ["EO 14110", "AISI"], "outcomes": "Compute registry submissions current; AISI joint test passed"},
    {"id": "C-05", "name": "Global asset manager portfolio AI", "scope": "Quant strategies + ESG signals", "regime": ["FCA Consumer Duty", "PRA SS1/23"], "outcomes": "Consumer outcomes dashboard live; SMF attestation clean"},
    {"id": "C-06", "name": "Healthcare-finance JV agentic workflow", "scope": "Prior-auth + payments agent", "regime": ["GDPR Art.22", "HIPAA-equiv", "AI Act"], "outcomes": "Human-in-loop verified; DPIA accepted; 0 Art.22 complaints"},
]

# ============================================================
# PRIVACY POSTURE
# ============================================================
privacy = {
    "basis": ["Explicit consent for training PII", "Legitimate interest with DPIA for ops", "Public task for fraud/AML"],
    "rights": ["Access (DSAR <= 30d)", "Erasure (with WORM exemption registry)", "Object (Art.22)", "Portability"],
    "controls": ["PII redaction at ingest", "Differential privacy for analytics", "K-anonymity for training sets", "Federated learning where viable"],
    "crossBorder": ["EU SCCs", "UK IDTA", "APAC bilateral", "ICGC data adequacy registry"],
    "audits": ["Quarterly DPO review", "Annual ICO/EDPB-ready DPIA refresh", "Per-model privacy impact"],
}

# ============================================================
# DEPLOYMENT
# ============================================================
deployment = {
    "envs": ["dev (T0)", "staging (T1)", "prod (T1/T2)", "research-isolated (T3)", "frontier-air-gapped (T4)"],
    "topology": "K8s clusters + Kafka WORM + OPA sidecars + governance plane (dedicated VPC)",
    "ci_cd": "GitHub Actions + Argo CD + Terraform Cloud; OPA + conftest gates on every PR",
    "secrets": "Vault + PQC-KMS (Dilithium3 + Kyber); zk-SNARK access proofs for break-glass",
    "observability": "OpenTelemetry + Grafana + AI-specific dashboards (CRP, drift, fairness, carbon)",
    "dr": "Active-active across 2 regions for Tier-1; cold-standby for Tier-2; air-gap snapshot for Tier-4",
}

# ============================================================
# ROLLOUT 90-DAY (3 phases)
# ============================================================
rollout90 = [
    {"phase": "Days 0-30 — Foundations", "deliverables": ["MGK kernel live", "Model inventory baseline", "OPA policy library v1", "Board AI charter signed"], "exitGate": "G0"},
    {"phase": "Days 31-60 — Controls", "deliverables": ["WORM audit pipeline GA", "Annex IV pack template", "MRM Tier-1 list locked", "First red-team cycle done"], "exitGate": "G1"},
    {"phase": "Days 61-90 — Assurance", "deliverables": ["External attestation engaged", "AISRG MVP", "Crisis tabletop WG-01 executed", "Regulator briefing pack v1"], "exitGate": "G1+"},
]

# ============================================================
# ROADMAP (5-year)
# ============================================================
roadmap = [
    {"year": "2026", "themes": ["MGK + MVAGS GA", "Annex IV readiness", "AISI joint tests"], "gates": ["G0", "G1"]},
    {"year": "2027", "themes": ["Model registry GA", "CCaaS-PETs", "ISO 42001 Gold"], "gates": ["G2"]},
    {"year": "2028", "themes": ["EAIP v1.0", "ISO 42001 Platinum", "FSB submissions ratified"], "gates": ["G3"]},
    {"year": "2029", "themes": ["Steady state MGK", "Civilizational research output", "AISI joint count >= 16"], "gates": ["G3+"]},
    {"year": "2030", "themes": ["Public assurance programme", "Re-audit Platinum", "Treaty alignment closed"], "gates": ["G4"]},
]

# ============================================================
# EVIDENCE PACK
# ============================================================
evidencePack = {
    "structure": ["00_executive_summary", "01_governance_framework", "02_model_inventory", "03_validation_reports", "04_fairness", "05_privacy", "06_security", "07_safety_containment", "08_oversight_minutes", "09_monitoring_dashboards", "10_sustainability", "11_global_governance", "12_public_transparency"],
    "format": ["PDF/A-3 for human review", "JSON-LD for machine ingestion", "PQC-signed manifest"],
    "retention": "10 years minimum; 25 years for Tier-1 / Annex IV high-risk",
    "access": "Role-based + zk-SNARK proof for regulator sandbox",
}

# ============================================================
# EXECUTIVE SUMMARY
# ============================================================
executiveSummary = {
    "thesis": "By 2030, F500/G2000/G-SIFIs must operate AGI-grade AI under provable, regulator-portable governance: MGK + MVAGS + 16-body global registry alignment, with Annex IV / SR 11-7 / ISO 42001 evidence packs reproducible via deterministic replay.",
    "topRisks": ["Frontier capability gain", "Audit log tampering", "Third-party model supply chain", "Cross-jurisdiction divergence"],
    "topControls": ["PQC-signed WORM", "OPA policy-as-code", "Containment tiers T0-T4", "AISRG R-01..R-12 reports"],
    "investmentRange": "USD 120-360M over 5 years for G-SIFI tier",
    "boardAsks": ["Approve MGK + MVAGS standing", "Endorse Cert Gold by 2027 / Platinum by 2028", "Charter Treaty Liaison Office"],
}

# ============================================================
# REPORT SECTIONS (R-01..R-12) — DISTINCTIVE WP-052 ELEMENT
# Pre-tagged <title>/<abstract>/<content> regulator-ready sections
# ============================================================
report_sections = [
    report(
        "R-01",
        "Governance Framework Overview",
        "Summarises the nine governance pillars (P1-P9), the Minimum Governance Kernel (MGK), the Minimum Viable AGI Governance Stack (MVAGS), and the board-level RACI under which all enterprise AI is operated for the 2026-2030 horizon.",
        "The institution operates a tiered AI governance framework anchored on ISO/IEC 42001, NIST AI RMF 1.0, and the EU AI Act. Accountability is owned at Board level via the AI/Risk Committee, with the CAIO holding executive accountability and the CRO/CISO/DPO/GC providing second-line assurance. The framework defines nine pillars: P1 Accountability, P2 Transparency, P3 Fairness, P4 Privacy, P5 Security, P6 Safety, P7 Oversight, P8 Continuous Monitoring, and P9 Sustainability. MGK provides the minimum non-negotiable kernel of controls (charter, RACI, model inventory, WORM audit, OPA policy library, incident response), and MVAGS adds the AGI-specific overlay (containment tiers T0-T4, CRP composite >= 0.90, Sentinel v2.4 telemetry, MVAGS crisis sims WG-01..WG-06). All Tier-1 and Annex IV high-risk systems are subject to dual sign-off (CAIO + CRO) and quarterly Board attestation.",
    ),
    report(
        "R-02",
        "Model Inventory and Classification",
        "Describes the complete enterprise model inventory, the risk-tiering taxonomy (Tier-0 internal/low-risk through Tier-1 customer-facing/high-risk and Annex IV high-risk), and the lifecycle states under which each model is governed.",
        "The model inventory is maintained as a single source of truth in the AI Model Registry, schema SCH-01 (ModelCard.v2). Every model — including prompts, agents, and AI-enabled features — is registered with owner, use case, training data lineage (SCH-04), risk tier, regulatory classification (EU AI Act risk class, SR 11-7 tier, MAS FEAT category), and current lifecycle state (draft, validated, approved, deployed, monitored, retired). KPI K-02 enforces 100% coverage, audited monthly. Tier-1 models additionally carry deterministic-replay readiness (CODE-05), CRP measurement series (SCH-09), and approval-chain WORM evidence (SCH-08). Annex IV high-risk systems carry the full Annex IV technical documentation pack and pass through pre-deploy AISI joint testing.",
    ),
    report(
        "R-03",
        "Conceptual Soundness and Validation",
        "Documents the conceptual soundness, design review, and independent validation processes aligned with SR 11-7 and PRA SS1/23, including deterministic replay, hyperparameter drift control, and benchmark/eval batteries.",
        "Each model is subjected to (i) design review by 1LoD modellers using a conceptual-soundness checklist, (ii) independent validation by 2LoD MRM covering theory, implementation, outcomes, and ongoing use, and (iii) third-line internal audit on the validation process itself. Deterministic replay (CODE-05) is mandatory for all Tier-1 / Annex IV high-risk training runs, with KPI K-11 enforcing zero byte diff. Hyperparameter drift is monitored via CODE-09 with KPI K-12 set at <= 5% per dimension. Evaluation batteries (SCH-07) cover task benchmarks, fairness (4/5ths rule, K-07), robustness (adversarial perturbations), red-team OWASP LLM Top 10 (K-10), and safety evals from MVAGS. Validation reports are stored in the WORM evidence pack section 03 and refreshed annually or upon material change.",
    ),
    report(
        "R-04",
        "Fairness, Non-discrimination, and Consumer Outcomes",
        "Evidences fairness, non-discrimination, and consumer-outcome controls aligned with ECOA, FCRA, FCA Consumer Duty, MAS FEAT, and EU AI Act fundamental-rights impact requirements.",
        "Fairness is governed by Pillar P3 and Risk-Control RCM-01. All decisioning models undergo disparate-impact testing using the four-fifths rule (KPI K-07 target 0.80-1.25), supplemented by equality-of-opportunity and predictive-parity metrics where decision context warrants. Adverse-action reason codes are generated through an explainability pipeline (SHAP + counterfactual, KPI K-22) and surfaced to consumers per FCRA/ECOA. FCA Consumer Duty foreseeable-harm reviews feed the Consumer Outcomes dashboard, with MAS FEAT principles evidenced via the FEAT assessment artefact (REG-07 submissions). EU AI Act Article 27 FRIA is performed for every high-risk system. Findings flow into the Risk Register (SCH-02).",
    ),
    report(
        "R-05",
        "Privacy, Data Protection, and Cross-Border Transfers",
        "Sets out the privacy posture under GDPR, UK GDPR, and analogous regimes (CCPA, PDPA-SG, PDPO-HK), including lawful basis, data subject rights, PETs, and cross-border transfer instruments.",
        "Privacy is owned by the DPO under Pillar P4. Lawful basis for AI training and operation is documented per dataset (explicit consent, legitimate interest with DPIA, public task for fraud/AML). Data subject rights are operationalised through a DSAR pipeline (KPI K-08 <= 30 days), with the WORM exemption registry preserving auditability while honouring erasure obligations. Privacy-enhancing technologies (PETs) — differential privacy, k-anonymity, federated learning, secure enclaves — are deployed per data classification. Cross-border transfers use EU SCCs, UK IDTA, APAC bilateral mechanisms, and, prospectively, the ICGC data-adequacy registry. DPIAs are refreshed annually and on material change; RCM-02 documents residual risk.",
    ),
    report(
        "R-06",
        "Security and Resilience of AI Systems",
        "Documents AI-specific security controls — model supply chain, prompt-injection defence, audit-log integrity, zk-SNARK access proofs, and operational resilience under PRA SS1/21 and analogous regimes.",
        "Security is governed by Pillar P5 under the CISO. The model supply chain is protected via SBOM-AI, signed model weights, and third-party assurance (KPI K-16). Prompt injection and data exfiltration are mitigated through input/output filters, Kafka ACL segregation (CODE-13), and continuous red-team exercise (CODE-12, KPI K-10). Audit-log integrity uses PQC-signed WORM (Dilithium3) with quarterly external attestation (RCM-05). Break-glass access uses zk-SNARK access proofs (CODE-11) so privileged actions are provable without exposing identity. Operational resilience tests cover Tier-1 model loss scenarios per PRA SS1/21 important business services.",
    ),
    report(
        "R-07",
        "Safety, Containment, and AGI/ASI Frontier Controls",
        "Describes the AGI/ASI safety stack — Sentinel v2.4, Luminous Engine Codex, Cognitive Resonance Protocol, MVAGS crisis simulations, and containment tiers T0-T4 — and how it integrates with enterprise change control.",
        "Safety is governed by Pillar P6 under the AI Safety Lead. Sentinel v2.4 provides continuous telemetry on alignment, stability, and transparency. The Cognitive Resonance Protocol composes these into a single CRP composite (CODE-06); KPIs K-03 (>= 0.90 Tier-1) and K-04 (>= 0.95 Annex IV high-risk) are enforced in real time and surfaced to the Board AI dashboard. Containment tiers T0 (sandbox) through T4 (frontier air-gapped) gate every model deployment; transitions require WORM-logged dual sign-off (CODE-16). MVAGS crisis sims WG-01..WG-06 exercise containment, regulator notification, and shutdown procedures semi-annually. Frontier R&D additionally feeds AISI joint pre-deploy testing.",
    ),
    report(
        "R-08",
        "Human Oversight and Accountability",
        "Demonstrates human-in-the-loop oversight and accountability mappings aligned with EU AI Act Article 14, GDPR Article 22, SMCR, and equivalent personal-accountability regimes.",
        "Pillar P7 (Oversight) places ultimate accountability with the Board AI/Risk Committee. SMF roles (UK SMCR) are mapped to AI accountabilities and recorded in Statements of Responsibility; equivalent registers are kept for US (Fed/OCC heightened standards), Singapore (MAS), and Hong Kong (HKMA). Every Annex IV high-risk and Tier-1 system documents the human-in-the-loop intervention points, training of overseers, and the override / pause / shutdown controls required under EU AI Act Article 14. GDPR Article 22 fully automated decisions are restricted to explicit-consent or contract-necessity bases with documented human-review escalation. Workshop W-01 ensures the Board operates at AI-literacy parity with executive layers.",
    ),
    report(
        "R-09",
        "Continuous Monitoring, Drift, and Incident Response",
        "Sets out the continuous-monitoring fabric — performance, fairness, drift, CRP, security signals — and the incident-response chain coordinated by the Global AI Security Operations Centre (GAI-SOC).",
        "Pillar P8 mandates real-time monitoring across performance, fairness (K-07), data and concept drift, CRP (K-03/K-04), adversarial-robustness regression (K-21), and security telemetry. Signals flow into the governance sidecar, are evaluated against OPA policy, and trigger automated containment escalations (CODE-16) when thresholds breach. Incidents are recorded under SCH-03, with KPI K-09 (Tier-1 MTTC <= 4h) and quarterly tabletop W-06. GAI-SOC owns the playbooks for prompt-injection, data-exfiltration, model-theft, supply-chain compromise, and frontier capability-gain scenarios. Regulator notification SLAs (EU AI Act serious incident <= 15 days, others per regime) are codified and rehearsed annually (W-05).",
    ),
    report(
        "R-10",
        "Sustainability, Energy, and Compute Footprint",
        "Quantifies energy and carbon footprint of AI workloads, reports against year-on-year reduction targets, and aligns with TCFD/ISSB and emerging EU AI Act sustainability disclosures.",
        "Pillar P9 (Sustainability) requires per-training-run energy (kWh) and carbon (kgCO2e) logging (SCH-06) and per-1k-inferences intensity reporting. KPI K-14 targets year-on-year energy intensity reduction of 10% and K-15 targets 15% carbon-intensity reduction. Carbon-aware scheduling routes training to low-carbon regions where SLAs allow. Annual disclosures are published under TCFD/ISSB and the AI sustainability addendum required by the GPAI code of practice. Frontier training carries a dedicated carbon budget approved at ExCo and reported to the Board.",
    ),
    report(
        "R-11",
        "Global Governance, Treaty Alignment, and Compute Registries",
        "Describes the institution's alignment with the proposed 16-body global AI/compute governance architecture (ICGC, GACRA, GASO, GFMCF, GAICS, GAIVS, GACP, GATI, GACMO, FTEWS, GAI-SOC, GAIGA, GACRLS, GFCO, GAID, GASCF), and the Treaty Liaison Office responsibilities.",
        "The Treaty Liaison Office, reporting jointly to GC and CRO, owns alignment with the 16-body global architecture coordinated under the GAI-COORD umbrella. Compute clusters above the EO 14110 / GPAI thresholds are registered with the International Compute Governance Consortium (ICGC) per SCH-10 and reported quarterly to GACRA (KPIs K-13/K-20). The institution participates in GAIVS verification exercises, files material AI risk to GFMCF, and submits to GASO standards observatories. GASCF financing flows fund cross-border safety research. The Treaty Liaison Office briefs the Board annually (W-07).",
    ),
    report(
        "R-12",
        "Public Transparency and Assurance",
        "Documents the public assurance programme — model cards, GPAI summaries, third-party assurance reports, and the public verifier service — that closes the trust loop with consumers, civil society, and regulators.",
        "Public assurance is delivered through (i) consumer-facing model cards summarising purpose, limitations, and recourse; (ii) GPAI training-data summaries per EU AI Act Article 53; (iii) annual AI Transparency Report aggregating KPIs K-01..K-24 and material incidents; (iv) third-party assurance reports (ISAE 3000 or equivalent) on the governance system; and (v) a public verifier service exposing zk-SNARK proofs over the WORM Merkle root, allowing external parties to verify audit-log integrity without accessing underlying data. The 2030 target is full public assurance programme operation with re-audited ISO 42001 Platinum certification and regulator endorsement of the AISRG R-01..R-12 format as the institution's standard regulator submission."
    ),
]

# ============================================================
# FINAL DOC ASSEMBLY
# ============================================================
DOC["modules"] = modules
DOC["schemas"] = schemas
DOC["code"] = code
DOC["kpis"] = kpis
DOC["riskControlMatrix"] = riskControlMatrix
DOC["traceability"] = traceability
DOC["dataFlows"] = dataFlows
DOC["regulators"] = regulators
DOC["workshops"] = workshops
DOC["cases"] = cases
DOC["privacy"] = privacy
DOC["deployment"] = deployment
DOC["rollout90"] = rollout90
DOC["roadmap"] = roadmap
DOC["evidencePack"] = evidencePack
DOC["executiveSummary"] = executiveSummary
DOC["reportSections"] = report_sections

DOC["counts"] = {
    "modules": len(modules),
    "sections": sum(len(m["sections"]) for m in modules),
    "schemas": len(schemas),
    "code": len(code),
    "kpis": len(kpis),
    "riskControlMatrix": len(riskControlMatrix),
    "traceability": len(traceability),
    "dataFlows": len(dataFlows),
    "regulators": len(regulators),
    "workshops": len(workshops),
    "cases": len(cases),
    "rollout90": len(rollout90),
    "roadmap": len(roadmap),
    "reportSections": len(report_sections),
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"WROTE {OUT}")
print(f"COUNTS: {json.dumps(DOC['counts'], indent=2)}")
