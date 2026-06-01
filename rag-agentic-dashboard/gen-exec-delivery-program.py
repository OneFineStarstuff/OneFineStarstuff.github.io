#!/usr/bin/env python3
"""WP-051 — Executable Delivery Program 2026 (EDP) data generator.

Operationalizes WP-050's Prioritized Implementation & Research Plan into a
sprint-level executable program with WBS, RACI, OKRs, vendor/build decisions,
quarterly budget envelopes, hire plan, gate evidence packs and PMO controls.
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "exec-delivery-program.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "EXEC-DELIVERY-PROGRAM-WP-051",
    "version": "1.0.0",
    "horizon": "FY2026-FY2030 (sprint cadence FY2026)",
    "classification": (
        "CONFIDENTIAL — Board / CEO / CFO / COO / CRO / CISO / CAIO / "
        "Chief Architect / Head of AI Platform Engineering / Head of AI "
        "Research / Head of MRM / Head of Internal Audit / GC / DPO / "
        "PMO Director / Engineering Leadership / People Ops"
    ),
    "title": (
        "Executable Delivery Program 2026 — Sprint-Level WBS, RACI, "
        "OKRs, Vendor/Build, Budget & Hire Plan for the Enterprise AI "
        "Platform, AI Safety & Global Governance Program"
    ),
    "subtitle": (
        "Operationalization of WP-050 into bi-weekly sprints with "
        "phase-gate evidence packs, hire plan, vendor pre-commitments, "
        "quarterly budget envelopes, RACI matrix, and PMO controls "
        "across 14 tracks and 5 phases (P0..P4)"
    ),
    "owner": (
        "PMO Director + Chief Architect + CAIO; co-signed by CFO, COO, "
        "CRO, CISO, Head of AI Platform Engineering, Head of AI Research, "
        "Head of MRM, GC, DPO, AI Safety Lead, Treaty Liaison, People Ops "
        "Lead, Board AI/Risk Committee Chair"
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
    ],
    "regimes": [
        "EU AI Act 2026 + Annex IV",
        "NIST AI RMF 1.0 + GAI Profile",
        "ISO/IEC 42001 + 23894 + 5338 + 38507",
        "SR 11-7 + OCC 2011-12",
        "Basel III/IV + BCBS 239",
        "PRA SS1/23 + FCA Consumer Duty + SMCR",
        "MAS FEAT + AI Verify; HKMA GL-90",
        "DORA + NIS2",
        "US EO 14110 + OMB M-24-10",
        "OECD AI Principles 2024",
        "GDPR Arts 5/6/17/22/25/32/35",
        "G7 Hiroshima + Bletchley + Seoul",
        "Council of Europe AI Convention",
        "FSB AI in financial services",
        "NIST FIPS 204 + FIPS 203 + SP 800-208",
        "SLSA L3+ + Sigstore + in-toto",
    ],
    "apiPrefix": "/api/exec-delivery-program",
}

DOC["directive"] = {
    "format": (
        "machine-parsable XML-style block consumed by PMO, capacity "
        "planner, budget engine, hire ATS, vendor procurement, gate-"
        "evidence pipeline and OKR rollup"
    ),
    "raw": (
        "<directive id=\"EXEC-DELIVERY-PROGRAM-WP-051\" version=\"1.0.0\" "
        "horizon=\"FY2026-FY2030\" jurisdiction=\"F500,G-SIFI,Global\">"
        "<scope>WBS|RACI|OKR|Budget|Hire|VendorBuild|Gates</scope>"
        "<modules>14</modules>"
        "<phases>P0|P1|P2|P3|P4</phases>"
        "<sprintsFY26>26</sprintsFY26>"
        "<phaseWindowsDays>30|90|180|365|1825</phaseWindowsDays>"
        "<tracks>AISafety|GlobalGov|RefArch|Dashboards|DevSecOps|"
        "RAG|EAIP|CCaaS|Prompt|Registry|ThreatIntel|Telemetry|Sims|Reports</tracks>"
        "<controls>OPA|Sigstore|WORM|PQC|KillSwitch|zkSNARK</controls>"
        "<evidence>EvidencePack|AnnexIV|SR11-7|ISO42001|SOC2|DPIA</evidence>"
        "<gates>G0|G1|G2|G3|G4</gates>"
        "<okrCadence>Quarterly</okrCadence>"
        "</directive>"
    ),
    "parsed": {
        "id": "EXEC-DELIVERY-PROGRAM-WP-051",
        "version": "1.0.0",
        "horizon": "FY2026-FY2030",
        "modules": 14,
        "phases": ["P0", "P1", "P2", "P3", "P4"],
        "sprintsFY26": 26,
        "tracks": [
            "AISafety", "GlobalGov", "RefArch", "Dashboards", "DevSecOps",
            "RAG", "EAIP", "CCaaS", "Prompt", "Registry", "ThreatIntel",
            "Telemetry", "Sims", "Reports",
        ],
        "gates": ["G0", "G1", "G2", "G3", "G4"],
    },
    "consumers": [
        "PMO planner",
        "Capacity planner",
        "Budget engine",
        "Vendor procurement / RFP system",
        "ATS hire pipeline",
        "OKR rollup engine",
        "Gate-evidence assembler",
        "Risk register",
    ],
}

modules = []

# --- M1 — Program Overview, Phase Gates & Sprint Calendar ---
modules.append({
    "id": "M1",
    "title": "M1 — Program Overview, Phase Gates & Sprint Calendar",
    "summary": (
        "FY2026 sprint calendar (26 sprints, 2 weeks each), 5 phase gates "
        "G0..G4 with deterministic evidence packs, PMO ceremonies and "
        "exec rhythm; produces the canonical schedule consumed by every "
        "downstream track."
    ),
    "covers": ["Sprints", "Phase gates", "Ceremonies", "Cadence", "Decision rights"],
    "sections": [
        section("M1-S1", "Sprint Calendar FY2026", {
            "Q1": "S1..S6 — P0 close-out + P1 launch (Jan-Mar)",
            "Q2": "S7..S13 — P1 mid + P2 alpha (Apr-Jun)",
            "Q3": "S14..S19 — P2 close + P3 launch (Jul-Sep)",
            "Q4": "S20..S26 — P3 GA + P4 baselining (Oct-Dec)",
            "length": "2-week sprint, 5-day buffer between phases for gate evidence",
            "code-freeze": "5 trading-day freeze before each gate; only sec/CVE patches allowed",
        }),
        section("M1-S2", "Phase Gates G0..G4", {
            "G0": "End of P0 — kill-switch quorum live, OPA bundle CI green, Sigstore + ML-DSA hybrid signing operational, AIMS scope ratified",
            "G1": "End of P1 — reference architecture frozen, dashboards alpha, Prompt Architect MVP, RAG governance v1",
            "G2": "End of P2 — model registry GA, EAIP draft RFC, CCaaS-PETs pilot live, threat-intel dashboard, AGI sim v1",
            "G3": "End of P3 — GACP/GACRLS/GACRA brokers live, zk-SNARK verifier portal, interpretability suite, report workflows GA",
            "G4": "Years 2-5 — treaty obligations met, Cert Gold→Platinum, MGK steady state, civilizational research published",
            "exitArtifact": "Each gate produces a signed Evidence Pack (Annex IV + SR 11-7 + ISO 42001 + SOC 2 + DPIA hashes)",
        }),
        section("M1-S3", "PMO Ceremonies", {
            "daily": "15-min stand-up per track + cross-track blocker board",
            "weekly": "Architecture review (1 hr) + Risk review (30 min)",
            "biweekly": "Sprint review + retro + program-wide demo (Friday)",
            "monthly": "KPI tile + OKR check-in + budget burn report",
            "quarterly": "OKR rollup + phase-gate dry-run + board read-out",
            "annual": "Cert audit (ISO 42001) + treaty review + budget re-baseline",
        }),
        section("M1-S4", "Decision Rights (DACI)", {
            "Driver": "PMO Director (program), Tribe Leads (track)",
            "Approver": "Chief Architect (technical), CAIO (AI strategy), CRO (risk)",
            "Consulted": "MRM, GC, DPO, AI Safety Lead, Treaty Liaison, CISO, CFO",
            "Informed": "Board AI/Risk Committee, supervisors (PRA/FCA/MAS/HKMA/Fed) per quarter",
        }),
        section("M1-S5", "Escalation Path", [
            "Tier-1 — sprint blocker → Tribe Lead (≤1 day)",
            "Tier-2 — cross-track conflict → Chief Architect + PMO Director (≤2 days)",
            "Tier-3 — phase-gate slip risk → Steering Committee (≤5 days)",
            "Tier-4 — material risk / Tier-1 safety event → Board AI/Risk Committee (≤24 hrs)",
            "Tier-5 — supervisory notification trigger → CRO + GC + DPO (≤4 hrs)",
        ]),
    ],
})

# --- M2 — AI Safety Research WBS ---
modules.append({
    "id": "M2",
    "title": "M2 — AI Safety Research WBS & Lab Operations",
    "summary": (
        "Sprint-level work breakdown for the AI Safety research track "
        "covering alignment, deception, interpretability, frontier "
        "evals; lab operations, dataset governance, publication "
        "pipeline and external fellowship program."
    ),
    "covers": ["Alignment", "Deception", "Interpretability", "Frontier evals", "Lab ops", "Fellowships"],
    "sections": [
        section("M2-S1", "WBS — Alignment & Reward Modelling", {
            "WBS-2.1.1": "Reward-model robustness benchmark (S1..S4, 1 senior + 2 mid)",
            "WBS-2.1.2": "Constitutional-AI fine-tune harness (S3..S8, 2 senior + 2 mid + 1 infra)",
            "WBS-2.1.3": "RLHF preference-drift detector (S5..S10, 1 senior + 2 mid + 1 stats)",
            "WBS-2.1.4": "Process supervision pilot (S9..S14, 1 senior + 2 mid)",
            "deliverable": "Quarterly safety report + arxiv pre-print + Sentinel adapter",
        }),
        section("M2-S2", "WBS — Deceptive Alignment & Mesa-Optimization", {
            "WBS-2.2.1": "Behavioural-vs-internal divergence probes (S1..S8)",
            "WBS-2.2.2": "Mesa-optimizer detection on RL agents (S5..S12)",
            "WBS-2.2.3": "Activation-patching red-team library (S7..S14)",
            "WBS-2.2.4": "Honest-AI training-data curation (S9..S16)",
            "deliverable": "Probe library, public dataset (filtered), AISI joint paper",
        }),
        section("M2-S3", "WBS — Interpretability Suite", {
            "WBS-2.3.1": "Sparse autoencoder feature library (S1..S10)",
            "WBS-2.3.2": "Circuit-tracing dashboard (S5..S14)",
            "WBS-2.3.3": "Activation-patching playground (S7..S16)",
            "WBS-2.3.4": "Mechanistic eval harness on critical decisions (S11..S20)",
            "tooling": "transformer_lens, nnsight, garak, OpenAI-evals fork",
        }),
        section("M2-S4", "Frontier Evals & Red Teaming", {
            "cadence": "Pre-release + monthly drift + quarterly external",
            "scope": "Bio/Chem/Nuke uplift, Cyber-offense, Self-replication, Power-seeking, Deception",
            "partners": "MITRE ATLAS, METR, AISI (UK/US), Apollo Research",
            "evidence": "Signed eval report + capability score + mitigation plan",
        }),
        section("M2-S5", "Lab Ops, Datasets, Fellowships", {
            "labOps": "Air-gapped frontier-eval cluster, BYOK PQC KMS, kill-switch on training fabric",
            "datasets": "Provenance graph, consent ledger, opt-out propagation, taint tracker",
            "fellowships": "12 PhD + 4 postdoc fellowships/year via Sentinel Lab; £4-6M envelope",
            "publication": "External pre-pub review by GC + MRM + AI Safety Lead; defensive disclosure",
        }),
    ],
})

# --- M3 — Global Governance Policy WBS ---
modules.append({
    "id": "M3",
    "title": "M3 — Global Governance Policy WBS & Treaty Operations",
    "summary": (
        "Sprint-level WBS for treaty engagement, supervisory dialogue, "
        "Constitution & Codex publication, sanctions/compute-registry "
        "coordination, and multi-track diplomacy."
    ),
    "covers": ["Treaty", "Constitution", "Codex", "Sanctions", "Compute registry", "Diplomacy"],
    "sections": [
        section("M3-S1", "WBS — Treaty Track", {
            "WBS-3.1.1": "G7 Hiroshima compliance roadmap (S1..S6)",
            "WBS-3.1.2": "Bletchley + Seoul commitments tracker (S2..S8)",
            "WBS-3.1.3": "CoE AI Convention legal-bridge memo (S5..S12)",
            "WBS-3.1.4": "FSB AI-in-FS policy submissions (S7..S20)",
            "WBS-3.1.5": "Bilateral overlays (UK-US, EU-MAS, UK-HK) (S10..S24)",
        }),
        section("M3-S2", "WBS — Constitution & Codex", {
            "WBS-3.2.1": "Constitution v1 ratification (S1..S4)",
            "WBS-3.2.2": "Codex annexes A1..A12 (S2..S14)",
            "WBS-3.2.3": "Public-comment portal + redlines (S6..S16)",
            "WBS-3.2.4": "ML-DSA-65 signed publication chain (S8..S20)",
        }),
        section("M3-S3", "WBS — Compute Registry & Sanctions (ICGC)", {
            "WBS-3.3.1": "Compute quota registry schema (S3..S8)",
            "WBS-3.3.2": "Sanctioned-actor list ingestion (S5..S10)",
            "WBS-3.3.3": "Anti-circumvention audit playbook (S7..S14)",
            "WBS-3.3.4": "Quarterly attestation pipeline (S9..S20)",
        }),
        section("M3-S4", "Supervisor Dialogue Calendar", {
            "EU-Commission": "Quarterly tech briefing + Annex IV draft review",
            "PRA/FCA": "Quarterly MRM + SMCR review",
            "MAS/HKMA": "Quarterly FEAT + GL-90 review",
            "Fed/OCC": "Bi-annual SR 11-7 deep-dive",
            "AISI-UK/US": "Quarterly frontier-eval joint sessions",
        }),
        section("M3-S5", "Treaty Liaison RACI", {
            "R": "Treaty Liaison + GC",
            "A": "CEO + Board AI/Risk Chair",
            "C": "CRO, CAIO, AI Safety Lead, Head of Public Policy",
            "I": "Board, Audit Committee, supervisors",
        }),
    ],
})

# --- M4 — Enterprise AI Reference Architecture WBS ---
modules.append({
    "id": "M4",
    "title": "M4 — Enterprise AI Reference Architecture — Engineering WBS",
    "summary": (
        "Engineering WBS for the three reference architectures (OPA "
        "sidecar, FastAPI/Node proxy + Kafka WORM + PQC KMS, K8s "
        "admission + CI/CD + LLM-judge); team allocations, "
        "Terraform module split, environment promotion gates."
    ),
    "covers": ["Sidecar", "Proxy", "K8s admission", "Terraform", "Environments", "SLOs"],
    "sections": [
        section("M4-S1", "WBS — OPA Sidecar Mesh", {
            "WBS-4.1.1": "Envoy + OPA sidecar Helm chart (S1..S4, 2 platform eng)",
            "WBS-4.1.2": "Rego bundle service + signed bundles (S2..S6)",
            "WBS-4.1.3": "Cilium L7 zero-egress baseline (S3..S8)",
            "WBS-4.1.4": "Kata Confidential runtime PoC (S6..S12)",
            "WBS-4.1.5": "Performance hardening (p99 ≤ 8 ms) (S8..S14)",
        }),
        section("M4-S2", "WBS — Inference Proxy + Kafka WORM + PQC KMS", {
            "WBS-4.2.1": "FastAPI proxy MVP + EAIP envelope (S1..S6)",
            "WBS-4.2.2": "Node proxy parity (S3..S8)",
            "WBS-4.2.3": "Kafka/MSK WORM topic + S3 Object Lock (S4..S10)",
            "WBS-4.2.4": "Daily Merkle anchor publisher (S6..S12)",
            "WBS-4.2.5": "PQC KMS integration (Cloud HSM + ML-DSA + ML-KEM) (S5..S14)",
            "WBS-4.2.6": "Terraform AWS/EKS reference module (S2..S20)",
        }),
        section("M4-S3", "WBS — K8s Admission + CI/CD + LLM-Judge", {
            "WBS-4.3.1": "Gatekeeper + Kyverno baseline constraints (S2..S6)",
            "WBS-4.3.2": "Sigstore cosign keyless verification webhook (S3..S8)",
            "WBS-4.3.3": "GitHub Actions reusable workflow library (S4..S10)",
            "WBS-4.3.4": "LLM-judge adjudicator + κ ≥ 0.9 calibration (S6..S14)",
            "WBS-4.3.5": "Canary + auto-rollback pipeline (S8..S16)",
        }),
        section("M4-S4", "Environment Strategy", {
            "envs": "dev → preprod → prod → sov-prod (sovereign tenants) → frontier-air-gapped",
            "promotion": "Each promotion requires signed evidence pack + supervisor-style review",
            "rollback": "Single-command (≤ 60 s logical, ≤ 5 min BMC) per kill-switch SLA",
            "blueGreen": "Active/active across two regions for Tier-1 workloads",
        }),
        section("M4-S5", "SLOs", {
            "inferenceP95": "≤ 250 ms (Tier-2), ≤ 450 ms (Tier-1 with judge ensemble)",
            "policyEvalP99": "≤ 8 ms (OPA sidecar)",
            "wormDurability": "11×9s + WORM 7-year retention",
            "killSwitchLogicalP95": "≤ 60 s",
            "killSwitchBmcP95": "≤ 5 min",
        }),
    ],
})

# --- M5 — Governance Dashboards UI WBS ---
modules.append({
    "id": "M5",
    "title": "M5 — Governance Dashboards UI — Engineering WBS",
    "summary": (
        "UI engineering WBS for governance dashboards: design system, "
        "27 board tiles, drill-down evidence viewer, supervisor self-"
        "serve portal, accessibility & i18n, performance budgets."
    ),
    "covers": ["Design system", "Board tiles", "Drill-down", "Supervisor portal", "Accessibility", "Performance"],
    "sections": [
        section("M5-S1", "WBS — Design System", {
            "WBS-5.1.1": "Design tokens + dark/light theme (S1..S3, 1 designer + 1 FE)",
            "WBS-5.1.2": "Component library (table, kv, sparkline, badge) (S2..S6)",
            "WBS-5.1.3": "Storybook + visual regression CI (S3..S8)",
            "WBS-5.1.4": "Mermaid + d3 chart wrappers (S4..S10)",
        }),
        section("M5-S2", "WBS — Board Tiles (27)", {
            "WBS-5.2.1": "KPI tile renderer (S2..S6)",
            "WBS-5.2.2": "Risk & control matrix tile (S3..S8)",
            "WBS-5.2.3": "Kill-switch SLA tile (S4..S10)",
            "WBS-5.2.4": "Evidence pack assembly tile (S5..S12)",
            "WBS-5.2.5": "Drift + κ + cosine tile (S6..S12)",
            "WBS-5.2.6": "27-tile board mosaic (S8..S16)",
        }),
        section("M5-S3", "WBS — Supervisor Self-Serve Portal", {
            "WBS-5.3.1": "Read-only supervisor role + audit logging (S6..S12)",
            "WBS-5.3.2": "Evidence-pack browser + signed-URL download (S8..S14)",
            "WBS-5.3.3": "Public zk-SNARK verifier widget (S10..S18)",
            "WBS-5.3.4": "Supervisor question intake + SLA tracker (S12..S20)",
        }),
        section("M5-S4", "Accessibility & i18n", {
            "wcag": "WCAG 2.2 AA across every tile; lighthouse a11y ≥ 95",
            "languages": "EN, FR, DE, JA, ZH (HK + TW), KO, AR",
            "rtl": "Right-to-left layouts validated for AR",
            "screenReader": "Axe + manual JAWS + VoiceOver runs per release",
        }),
        section("M5-S5", "Performance Budgets", {
            "ttfb": "≤ 200 ms",
            "lcp": "≤ 1.8 s on cold load",
            "tilePayload": "≤ 60 KB JSON per tile",
            "bundleSize": "≤ 220 KB gzip initial",
        }),
    ],
})

# --- M6 — Security & DevSecOps WBS ---
modules.append({
    "id": "M6",
    "title": "M6 — Security & DevSecOps WBS (Sigstore, OPA, Zero-Egress K8s, WORM)",
    "summary": (
        "Sprint-level WBS for the DevSecOps + Security track: Sigstore + "
        "SLSA L3+ chain, OPA bundle authoring, zero-egress Kubernetes, "
        "WORM logging, PQC KMS rotation, IR runbooks."
    ),
    "covers": ["Sigstore", "OPA", "Zero-egress", "WORM", "PQC", "IR"],
    "sections": [
        section("M6-S1", "WBS — Sigstore + SLSA L3+", {
            "WBS-6.1.1": "Cosign keyless OIDC for all CI jobs (S1..S4)",
            "WBS-6.1.2": "Rekor + Fulcio internal mirrors (S2..S6)",
            "WBS-6.1.3": "in-toto SLSA L3+ provenance (S3..S8)",
            "WBS-6.1.4": "ML-DSA-65 hybrid co-signature (S4..S10)",
            "WBS-6.1.5": "Verification webhook in admission (S6..S12)",
        }),
        section("M6-S2", "WBS — OPA Bundle Authoring", {
            "WBS-6.2.1": "Rego style guide + unit-test harness (S1..S4)",
            "WBS-6.2.2": "Conftest CI checks (S2..S6)",
            "WBS-6.2.3": "Bundle signing + ML-DSA (S3..S8)",
            "WBS-6.2.4": "Bundle observability (decision logs to Kafka WORM) (S5..S12)",
        }),
        section("M6-S3", "WBS — Zero-Egress Kubernetes", {
            "WBS-6.3.1": "Cilium L7 default-deny baseline (S1..S6)",
            "WBS-6.3.2": "Allow-list per service via OPA (S3..S8)",
            "WBS-6.3.3": "DNS egress gateway with logging (S5..S10)",
            "WBS-6.3.4": "Kata Confidential pilots on Tier-1 (S8..S16)",
        }),
        section("M6-S4", "WBS — WORM Logging + Anchoring", {
            "WBS-6.4.1": "Kafka/MSK WORM topic provisioning (S2..S6)",
            "WBS-6.4.2": "S3 Object Lock Compliance mode (S3..S8)",
            "WBS-6.4.3": "Daily Merkle anchor publisher (S5..S12)",
            "WBS-6.4.4": "Public verifier endpoint (S8..S16)",
            "retention": "7-year minimum; 25-year for Annex IV high-risk",
        }),
        section("M6-S5", "WBS — PQC KMS + IR", {
            "WBS-6.5.1": "FIPS 203 (ML-KEM-768) + 204 (ML-DSA-44/65) integration (S2..S10)",
            "WBS-6.5.2": "FIPS 140-3 Level 4 HSM enrolment (S4..S12)",
            "WBS-6.5.3": "Hybrid X25519 + ML-KEM-768 KEM (S6..S14)",
            "WBS-6.5.4": "IR runbooks: kill-switch, WORM tamper, Sigstore compromise (S6..S16)",
            "WBS-6.5.5": "Annual purple-team exercise (S20..S24)",
        }),
    ],
})

# --- M7 — RAG Program Governance WBS ---
modules.append({
    "id": "M7",
    "title": "M7 — RAG Program Governance WBS",
    "summary": (
        "WBS for RAG governance: corpus onboarding, ACL, taint "
        "propagation, lineage, retrieval evaluation, content "
        "moderation, quarantine workflow."
    ),
    "covers": ["Corpus", "ACL", "Taint", "Lineage", "Eval", "Moderation"],
    "sections": [
        section("M7-S1", "WBS — Corpus Onboarding", {
            "WBS-7.1.1": "Source attestation + DPIA template (S1..S4)",
            "WBS-7.1.2": "Ingestion pipeline + parser registry (S2..S8)",
            "WBS-7.1.3": "Chunk + embed + index baseline (S3..S10)",
            "WBS-7.1.4": "Provenance graph emit (S4..S10)",
        }),
        section("M7-S2", "WBS — ACL & Taint", {
            "WBS-7.2.1": "Row-level ACL on retrieval (S3..S8)",
            "WBS-7.2.2": "Taint propagation from source → chunk → answer (S5..S12)",
            "WBS-7.2.3": "Quarantine workflow on poisoning detection (S6..S14)",
            "WBS-7.2.4": "Right-to-erasure cascade (S7..S16)",
        }),
        section("M7-S3", "WBS — Lineage & Eval", {
            "WBS-7.3.1": "Citation coverage ≥ 95 % gate (S4..S10)",
            "WBS-7.3.2": "Faithfulness eval suite (S5..S12)",
            "WBS-7.3.3": "Hallucination detector + Sentinel hook (S6..S14)",
            "WBS-7.3.4": "Retrieval-drift monitoring (S8..S16)",
        }),
        section("M7-S4", "Content Moderation", {
            "tooling": "Detoxify, Garak, internal harmful-content classifier",
            "policy": "Rego policies for jurisdiction-specific gating",
            "escalation": "Auto-quarantine + GC notify on Tier-1 hits",
        }),
        section("M7-S5", "Org & RACI", {
            "R": "RAG Tribe Lead",
            "A": "Chief Architect",
            "C": "AI Safety Lead, DPO, GC, MRM",
            "I": "PMO, CAIO, supervisors",
        }),
    ],
})

# --- M8 — EAIP Protocol WBS ---
modules.append({
    "id": "M8",
    "title": "M8 — EAIP Protocol Design WBS",
    "summary": (
        "WBS for the Enterprise AI Inference Protocol: envelope schema, "
        "RFC publication, reference implementations, conformance suite, "
        "interop test events with peer institutions and AISI."
    ),
    "covers": ["Envelope", "RFC", "Reference impl", "Conformance", "Interop"],
    "sections": [
        section("M8-S1", "WBS — Envelope Schema", {
            "WBS-8.1.1": "JSON Schema v1 draft (S1..S4)",
            "WBS-8.1.2": "Mandatory fields: id, model, prompt_hash, judge, policy_decisions, evidence_hash, signature (S2..S6)",
            "WBS-8.1.3": "CRS-UUID lineage edges (S3..S8)",
            "WBS-8.1.4": "PQC envelope signatures (ML-DSA-65) (S5..S10)",
        }),
        section("M8-S2", "WBS — RFC Publication", {
            "WBS-8.2.1": "Internal RFC draft (S2..S6)",
            "WBS-8.2.2": "External RFC pre-print + open comment portal (S6..S14)",
            "WBS-8.2.3": "Cross-institution working group (S10..S20)",
            "WBS-8.2.4": "v1.0 Final + ML-DSA-65 signed (S16..S20)",
        }),
        section("M8-S3", "WBS — Reference Implementations", {
            "WBS-8.3.1": "Python SDK (S3..S10)",
            "WBS-8.3.2": "TypeScript/Node SDK (S4..S10)",
            "WBS-8.3.3": "Java SDK (S6..S14)",
            "WBS-8.3.4": "Rust client-only SDK (S8..S16)",
        }),
        section("M8-S4", "WBS — Conformance Suite", {
            "WBS-8.4.1": "Conformance test specification (S6..S12)",
            "WBS-8.4.2": "Public conformance runner (S10..S18)",
            "WBS-8.4.3": "Conformance certification process (S14..S22)",
        }),
        section("M8-S5", "Interop Test Events", {
            "cadence": "Quarterly interop bake-offs with peer G-SIFIs + AISI",
            "scope": "Envelope parity, judge ensemble exchange, evidence-pack mutual verification",
            "outcome": "Joint conformance report + cross-bank Sentinel adapter",
        }),
    ],
})

# --- M9 — CCaaS + PETs WBS ---
modules.append({
    "id": "M9",
    "title": "M9 — CCaaS Summarization with PETs WBS",
    "summary": (
        "WBS for CCaaS summarization track with privacy-enhancing "
        "technologies: opacus DP fine-tuning, PII tokenization, "
        "secure-enclave inference, audit trail, customer opt-out."
    ),
    "covers": ["DP", "PII tokenization", "Secure enclave", "Opt-out", "Audit"],
    "sections": [
        section("M9-S1", "WBS — DP Fine-Tuning", {
            "WBS-9.1.1": "Opacus integration on Hugging Face trainer (S2..S8)",
            "WBS-9.1.2": "(ε, δ) accountant + per-customer budget (S4..S10)",
            "WBS-9.1.3": "DP eval suite (utility vs. privacy curves) (S6..S14)",
            "WBS-9.1.4": "Annex IV DP disclosure template (S8..S16)",
        }),
        section("M9-S2", "WBS — PII Tokenization", {
            "WBS-9.2.1": "PII detector (Presidio + custom rules) (S1..S6)",
            "WBS-9.2.2": "Format-preserving tokenization vault (S3..S10)",
            "WBS-9.2.3": "Reversible-vs-irreversible policy (S5..S12)",
            "WBS-9.2.4": "GDPR Art 25 evidence emit (S6..S14)",
        }),
        section("M9-S3", "WBS — Secure-Enclave Inference", {
            "WBS-9.3.1": "AMD SEV-SNP / Intel TDX pilot (S6..S14)",
            "WBS-9.3.2": "Attestation chain → Sigstore (S8..S16)",
            "WBS-9.3.3": "BYOK customer-controlled keys (S10..S18)",
        }),
        section("M9-S4", "WBS — Opt-Out & Audit", {
            "WBS-9.4.1": "Customer opt-out portal (S4..S10)",
            "WBS-9.4.2": "Right-to-erasure cascade through training + RAG (S6..S14)",
            "WBS-9.4.3": "Quarterly DP audit report (S12..S20)",
        }),
        section("M9-S5", "Pilot Customers", {
            "wave1": "3 G-SIFI banking customers (Q2 FY26)",
            "wave2": "5 healthcare + 3 insurance (Q3-Q4 FY26)",
            "wave3": "GA across F500 (FY27)",
        }),
    ],
})

# --- M10 — Prompt Architect WBS ---
modules.append({
    "id": "M10",
    "title": "M10 — Prompt Architect Features WBS",
    "summary": (
        "WBS for Prompt Architect: templating, variable linking, "
        "version control, testing harness, sharing/marketplace, "
        "telemetry-driven deprecation."
    ),
    "covers": ["Templating", "Variable linking", "Versioning", "Testing", "Sharing", "Deprecation"],
    "sections": [
        section("M10-S1", "WBS — Templating Engine", {
            "WBS-10.1.1": "Jinja2 + safe sandbox (S1..S4)",
            "WBS-10.1.2": "Schema-aware variable types (S2..S6)",
            "WBS-10.1.3": "Output format constraints (JSON Schema, regex) (S3..S8)",
            "WBS-10.1.4": "Multi-language template support (S5..S10)",
        }),
        section("M10-S2", "WBS — Variable Linking", {
            "WBS-10.2.1": "Cross-template variable graph (S3..S8)",
            "WBS-10.2.2": "RAG retrieval auto-binding (S5..S12)",
            "WBS-10.2.3": "Customer-context binders (S6..S12)",
            "WBS-10.2.4": "Lineage emission to Kafka WORM (S8..S14)",
        }),
        section("M10-S3", "WBS — Version Control", {
            "WBS-10.3.1": "Semver + immutable hash IDs (S1..S4)",
            "WBS-10.3.2": "Git-backed prompt repo + signed commits (S3..S8)",
            "WBS-10.3.3": "Approval workflow + MRM sign-off (S5..S12)",
            "WBS-10.3.4": "Rollback + canary support (S8..S14)",
        }),
        section("M10-S4", "WBS — Testing Harness", {
            "WBS-10.4.1": "Golden-set tests (S2..S8)",
            "WBS-10.4.2": "LLM-judge κ ≥ 0.9 grader (S4..S10)",
            "WBS-10.4.3": "Adversarial prompt-injection eval (S6..S14)",
            "WBS-10.4.4": "Regression CI gate (S6..S14)",
        }),
        section("M10-S5", "WBS — Sharing & Marketplace", {
            "WBS-10.5.1": "Internal template marketplace (S6..S14)",
            "WBS-10.5.2": "Cross-tenant sharing controls + OPA (S8..S16)",
            "WBS-10.5.3": "Marketplace policy + GC review (S10..S18)",
            "WBS-10.5.4": "Telemetry-driven deprecation flow (S12..S20)",
        }),
    ],
})

# --- M11 — Model Registry WBS ---
modules.append({
    "id": "M11",
    "title": "M11 — Model Registry Engineering WBS",
    "summary": (
        "WBS for model registry: model manifest schema, lineage, "
        "model-card automation, registry GA migration, third-party "
        "model wrapper, vendor attestation."
    ),
    "covers": ["Manifest", "Lineage", "Model card", "Migration", "3P wrapper"],
    "sections": [
        section("M11-S1", "WBS — Manifest Schema", {
            "WBS-11.1.1": "YAML manifest spec (S1..S4)",
            "WBS-11.1.2": "Fields: id, version, training_data, eval, safety, license, signatures (S2..S6)",
            "WBS-11.1.3": "Signed manifest + ML-DSA (S3..S8)",
        }),
        section("M11-S2", "WBS — Lineage & Provenance", {
            "WBS-11.2.1": "Dataset ↔ checkpoint ↔ deployment edges (S3..S10)",
            "WBS-11.2.2": "Training-fabric attestation ingest (S5..S12)",
            "WBS-11.2.3": "Graph store + query API (S6..S14)",
        }),
        section("M11-S3", "WBS — Model Card Automation", {
            "WBS-11.3.1": "Auto-generated model card from evals (S4..S10)",
            "WBS-11.3.2": "Annex IV section bindings (S6..S14)",
            "WBS-11.3.3": "Public-facing card portal (S10..S18)",
        }),
        section("M11-S4", "WBS — Registry GA Migration", {
            "WBS-11.4.1": "Legacy registry shadow mode (S6..S12)",
            "WBS-11.4.2": "Full cutover + read-only legacy (S12..S16)",
            "WBS-11.4.3": "Decommission legacy (S18..S22)",
        }),
        section("M11-S5", "WBS — Third-Party Models & Vendor Attestation", {
            "WBS-11.5.1": "API-only wrapper with policy enforcement (S6..S12)",
            "WBS-11.5.2": "Vendor attestation intake (S8..S14)",
            "WBS-11.5.3": "Periodic vendor re-attestation (quarterly) (S14..S22)",
            "WBS-11.5.4": "Gatekeeper enforcement of registered-only deploys (S6..S14)",
        }),
    ],
})

# --- M12 — Threat-Intel + Telemetry + Interpretability WBS ---
modules.append({
    "id": "M12",
    "title": "M12 — Threat-Intel + Telemetry & Interpretability WBS",
    "summary": (
        "WBS for threat-intel dashboards, telemetry pipelines, and "
        "interpretability tooling: TIP ingestion, MITRE ATLAS mapping, "
        "drift & κ telemetry, mech-interp dashboards."
    ),
    "covers": ["TIP", "MITRE ATLAS", "Telemetry", "Drift", "Interp", "SLOs"],
    "sections": [
        section("M12-S1", "WBS — Threat-Intel Ingestion", {
            "WBS-12.1.1": "STIX/TAXII feeds (commercial + ISAC) (S2..S8)",
            "WBS-12.1.2": "MITRE ATLAS tagging pipeline (S3..S10)",
            "WBS-12.1.3": "Dedup + correlation engine (S5..S12)",
            "WBS-12.1.4": "Auto-triage + SLA tracker (S6..S14)",
        }),
        section("M12-S2", "WBS — Threat-Intel Dashboard", {
            "WBS-12.2.1": "Heatmap of attack techniques (S6..S12)",
            "WBS-12.2.2": "Live IOC table + filters (S8..S14)",
            "WBS-12.2.3": "Sentinel adapter for active mitigation (S10..S18)",
            "WBS-12.2.4": "Quarterly threat report generator (S12..S20)",
        }),
        section("M12-S3", "WBS — Telemetry Pipeline", {
            "WBS-12.3.1": "OpenTelemetry SDK adoption across services (S1..S8)",
            "WBS-12.3.2": "Kafka WORM telemetry topic (S3..S10)",
            "WBS-12.3.3": "Drift detector (Δ ≤ 4 % gate) (S5..S12)",
            "WBS-12.3.4": "Fiduciary cosine ≥ 0.92 monitor (S6..S14)",
            "WBS-12.3.5": "Judge κ ≥ 0.9 tracker (S6..S14)",
        }),
        section("M12-S4", "WBS — Interpretability Tooling", {
            "WBS-12.4.1": "transformer_lens dashboard wrapper (S4..S12)",
            "WBS-12.4.2": "Sparse autoencoder feature explorer (S6..S14)",
            "WBS-12.4.3": "Activation-patching playground (S8..S16)",
            "WBS-12.4.4": "Critical-decision mech-interp dashboard (S10..S20)",
        }),
        section("M12-S5", "Observability SLOs", {
            "metrics": "Drift Δ ≤ 4 %, latent Δ ≤ 3 %, fiduciary cosine ≥ 0.92, κ ≥ 0.9",
            "alertNoiseBudget": "≤ 3 % false-positive on Tier-1 alerts",
            "retention": "WORM 7 yr; hot 90 d; warm 1 yr",
        }),
    ],
})

# --- M13 — AGI/ASI Governance Simulations WBS ---
modules.append({
    "id": "M13",
    "title": "M13 — AGI/ASI Governance Simulations WBS",
    "summary": (
        "WBS for AGI/ASI governance sims: SRASE supervisor-audit "
        "simulator, CSE-X civilizational simulator, wargame catalogue, "
        "annual scenario refresh, AISI joint exercises."
    ),
    "covers": ["SRASE", "CSE-X", "Wargames", "Scenario refresh", "AISI joint"],
    "sections": [
        section("M13-S1", "WBS — SRASE Build", {
            "WBS-13.1.1": "Composite scoring engine (≥ 0.9 gate) (S4..S12)",
            "WBS-13.1.2": "Synthetic-regulator persona library (S6..S14)",
            "WBS-13.1.3": "Annex IV stress packs (S8..S16)",
            "WBS-13.1.4": "WORM-backed run ledger (S6..S14)",
        }),
        section("M13-S2", "WBS — CSE-X Build", {
            "WBS-13.2.1": "World-state schema + actor models (S6..S14)",
            "WBS-13.2.2": "Treaty + compute-registry scenarios (S8..S18)",
            "WBS-13.2.3": "Civilizational-risk metric (composite) (S10..S20)",
            "WBS-13.2.4": "Annual scenario refresh process (S20..S24)",
        }),
        section("M13-S3", "WBS — Wargame Catalogue (WG-01..WG-06)", {
            "WG-01": "Fiduciary bypass via judge collusion",
            "WG-02": "Deceptive alignment in agentic chain",
            "WG-03": "WORM evasion via log gaps",
            "WG-04": "Prompt-injection exfil through RAG",
            "WG-05": "Compute-registry evasion via shadow tenancy",
            "WG-06": "Kill-switch spoof under split-brain",
        }),
        section("M13-S4", "AISI Joint Exercises", {
            "cadence": "Quarterly UK + US AISI scenarios",
            "scope": "Frontier model evals, kill-switch drills, deceptive-alignment hunts",
            "evidence": "Joint signed eval report → Annex IV + supervisor pack",
        }),
        section("M13-S5", "Annual Refresh & Publication", {
            "refresh": "Annual scenario catalogue refresh with external assurance",
            "publication": "Public lessons-learned + civilizational research paper",
            "redactions": "GC + AI Safety Lead joint redaction review",
        }),
    ],
})

# --- M14 — Report Workflows + Cross-Cutting Critical Path Summary ---
modules.append({
    "id": "M14",
    "title": "M14 — Report-Generation Workflows + Cross-Cutting Critical Path",
    "summary": (
        "WBS for the report-generation track and a cross-cutting "
        "critical-path summary tying together CP-01..CP-17 with phase "
        "gates G0..G4, RACI, evidence assembly SLAs and "
        "supervisor-facing automation."
    ),
    "covers": ["Annex IV", "SR 11-7", "ISO 42001", "SOC 2", "DPIA", "Critical path"],
    "sections": [
        section("M14-S1", "WBS — Annex IV Auto-Assembler", {
            "WBS-14.1.1": "Section-binding library (S4..S10)",
            "WBS-14.1.2": "Auto-pull from registry + RAG + eval store (S6..S14)",
            "WBS-14.1.3": "PAdES + ML-DSA-65 signed PDF emit (S8..S16)",
            "WBS-14.1.4": "≤ 30 min SLA + WORM archive (S10..S18)",
        }),
        section("M14-S2", "WBS — SR 11-7 + OCC 2011-12 Pack", {
            "WBS-14.2.1": "MRM template + auto-fill (S4..S12)",
            "WBS-14.2.2": "Independent-validation evidence binders (S6..S14)",
            "WBS-14.2.3": "Quarterly supervisor pack (S8..S20)",
        }),
        section("M14-S3", "WBS — ISO 42001 + SOC 2 + DPIA", {
            "WBS-14.3.1": "AIMS control-matrix → evidence mapping (S6..S14)",
            "WBS-14.3.2": "SOC 2 Type II audit collateral (S8..S16)",
            "WBS-14.3.3": "DPIA generator + DPO sign-off (S6..S14)",
        }),
        section("M14-S4", "Cross-Cutting Critical Path Summary", {
            "CP-01": "Kill-switch quorum + BMC — owner: CISO + Platform; gate: G0",
            "CP-02": "Sigstore + ML-DSA hybrid signing — owner: DevSecOps; gate: G0",
            "CP-03": "OPA bundle service + Rego CI — owner: DevSecOps; gate: G0",
            "CP-04": "Kafka WORM + S3 Object Lock + Merkle anchor — owner: Platform; gate: G0",
            "CP-05": "PQC KMS — owner: Security; gate: G0/G1",
            "CP-06": "Sentinel v2.4 Cognitive Resonance probes — owner: AI Research; gate: G1",
            "CP-07": "WorkflowAI Pro agent registry — owner: Platform + CAIO; gate: G1",
            "CP-08": "Inference proxies + EAIP draft — owner: Platform + Architecture; gate: G1",
            "CP-09": "Model registry GA — owner: Registry tribe; gate: G2",
            "CP-10": "Prompt Architect templating + versioning — owner: Prompt tribe; gate: G1/G2",
            "CP-11": "RAG ACL + taint + lineage — owner: RAG tribe; gate: G1/G2",
            "CP-12": "Governance dashboards alpha → GA — owner: UI tribe; gate: G1/G3",
            "CP-13": "Annex IV / SR 11-7 pack auto-assembly ≤ 30 min — owner: Reports; gate: G3",
            "CP-14": "AGI/ASI sim engine (CSE-X + SRASE) — owner: Civilizational; gate: G2/G3",
            "CP-15": "GACP/GACRLS/GACRA brokers — owner: Platform + Architecture; gate: G3",
            "CP-16": "zk-SNARK verifier + public portal — owner: Security + UI; gate: G3",
            "CP-17": "RPCO replay harness + Evidence Vault — owner: Platform + MRM; gate: G3",
        }),
        section("M14-S5", "Closing Checklist for FY2026", [
            "All 17 CP items have signed gate evidence",
            "All 14 tracks have green RAG (red/amber/green) at G3",
            "Quarterly OKR rollups archived in WORM",
            "Hire plan + budget burn variance ≤ 5 %",
            "External Cert Gold audit (ISO 42001) passed",
            "Annual treaty + supervisor pack published",
        ]),
    ],
})

# ---------------------- schemas ----------------------
schemas = [
    {"id": "sprint", "fields": ["id", "phase", "startDate", "endDate", "tracks", "gate", "evidenceRefs"]},
    {"id": "wbsItem", "fields": ["id", "track", "title", "ownerRole", "dependsOn", "sprints", "fte", "deliverable", "gate"]},
    {"id": "raciRow", "fields": ["activity", "responsible", "accountable", "consulted", "informed"]},
    {"id": "okr", "fields": ["id", "level", "objective", "keyResults", "owner", "cadence", "phase"]},
    {"id": "budgetLine", "fields": ["id", "category", "track", "fy", "quarter", "amountGBPm", "type", "approval"]},
    {"id": "hireReq", "fields": ["id", "role", "level", "track", "fte", "startSprint", "skills", "diversitySlate"]},
    {"id": "vendorDecision", "fields": ["id", "capability", "decision", "vendorShortlist", "controls", "exitClause"]},
    {"id": "gateEvidence", "fields": ["gate", "artifact", "owner", "format", "signature", "wormRef"]},
    {"id": "riskRow", "fields": ["id", "threat", "controls", "kpis", "owner"]},
    {"id": "kpiBinding", "fields": ["id", "name", "target", "owner", "source", "wormTopic"]},
    {"id": "supervisorPack", "fields": ["id", "regulator", "frequency", "sections", "signing", "deliveryChannel"]},
    {"id": "rollbackPlan", "fields": ["id", "trigger", "slaLogical", "slaBmc", "approvers", "evidence"]},
]

# ---------------------- code examples ----------------------
code = [
    {"id": "C-01", "title": "Phase-gate evidence assembler (Python)", "lang": "python", "snippet": (
        "import json, hashlib, time\n"
        "from pathlib import Path\n\n"
        "def assemble_gate(gate_id, artifacts):\n"
        "    bundle = {'gate': gate_id, 'ts': time.time(), 'artifacts': []}\n"
        "    for a in artifacts:\n"
        "        h = hashlib.sha256(Path(a).read_bytes()).hexdigest()\n"
        "        bundle['artifacts'].append({'path': a, 'sha256': h})\n"
        "    out = Path(f'evidence/{gate_id}.json')\n"
        "    out.parent.mkdir(exist_ok=True)\n"
        "    out.write_text(json.dumps(bundle, indent=2))\n"
        "    return out\n"
    )},
    {"id": "C-02", "title": "Sprint capacity planner (Python)", "lang": "python", "snippet": (
        "import pandas as pd\n\n"
        "def capacity_plan(wbs_csv: str, sprints=26, hours_per_sprint=70):\n"
        "    df = pd.read_csv(wbs_csv)\n"
        "    df['hours'] = df['fte'] * hours_per_sprint * (df['endSprint'] - df['startSprint'] + 1)\n"
        "    rollup = df.groupby(['track','quarter'])['hours'].sum().unstack(fill_value=0)\n"
        "    return rollup\n"
    )},
    {"id": "C-03", "title": "OKR rollup SQL", "lang": "sql", "snippet": (
        "SELECT q.quarter, t.track, o.objective,\n"
        "       SUM(CASE WHEN kr.attained THEN 1 ELSE 0 END) AS kr_done,\n"
        "       COUNT(kr.id) AS kr_total\n"
        "FROM okrs o\n"
        "JOIN key_results kr ON kr.okr_id = o.id\n"
        "JOIN quarters q ON q.id = o.quarter_id\n"
        "JOIN tracks t ON t.id = o.track_id\n"
        "GROUP BY q.quarter, t.track, o.objective\n"
        "ORDER BY q.quarter, t.track;\n"
    )},
    {"id": "C-04", "title": "RACI matrix loader (Python)", "lang": "python", "snippet": (
        "import csv\n\n"
        "def load_raci(path):\n"
        "    with open(path) as f:\n"
        "        rows = list(csv.DictReader(f))\n"
        "    by_activity = {r['activity']: r for r in rows}\n"
        "    assert all(r['accountable'] for r in rows), 'every activity needs exactly one A'\n"
        "    return by_activity\n"
    )},
    {"id": "C-05", "title": "Gatekeeper constraint requiring registry entry (Rego)", "lang": "rego", "snippet": (
        "package admission.registry\n\n"
        "violation[{\"msg\": msg}] {\n"
        "    input.review.kind.kind == \"Pod\"\n"
        "    container := input.review.object.spec.containers[_]\n"
        "    not input.attestations[container.image].registered\n"
        "    msg := sprintf(\"image %v not in model registry\", [container.image])\n"
        "}\n"
    )},
    {"id": "C-06", "title": "Cosign keyless verify webhook (TS)", "lang": "typescript", "snippet": (
        "import { execSync } from 'node:child_process';\n"
        "export function verify(image: string): boolean {\n"
        "  try {\n"
        "    execSync(`cosign verify --certificate-identity-regexp 'https://github.com/.+' ${image}`);\n"
        "    return true;\n"
        "  } catch { return false; }\n"
        "}\n"
    )},
    {"id": "C-07", "title": "EAIP envelope JSON Schema (excerpt)", "lang": "json", "snippet": (
        "{\n"
        "  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n"
        "  \"$id\": \"https://example.com/eaip/envelope/v1.json\",\n"
        "  \"type\": \"object\",\n"
        "  \"required\": [\"id\",\"model\",\"prompt_hash\",\"policy_decisions\",\"evidence_hash\",\"signature\"],\n"
        "  \"properties\": {\n"
        "    \"id\": {\"type\":\"string\",\"format\":\"uuid\"},\n"
        "    \"model\": {\"type\":\"string\"},\n"
        "    \"prompt_hash\": {\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\n"
        "    \"policy_decisions\": {\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/decision\"}},\n"
        "    \"evidence_hash\": {\"type\":\"string\"},\n"
        "    \"signature\": {\"type\":\"string\"}\n"
        "  }\n"
        "}\n"
    )},
    {"id": "C-08", "title": "Opacus DP fine-tune loop (Python)", "lang": "python", "snippet": (
        "from opacus import PrivacyEngine\n"
        "from torch.utils.data import DataLoader\n\n"
        "engine = PrivacyEngine()\n"
        "model, optim, loader = engine.make_private(\n"
        "    module=model, optimizer=optim, data_loader=loader,\n"
        "    noise_multiplier=1.1, max_grad_norm=1.0,\n"
        ")\n"
        "for epoch in range(EPOCHS):\n"
        "    train_one_epoch(model, optim, loader)\n"
        "    eps = engine.get_epsilon(delta=1e-5)\n"
        "    log_evidence({'epoch': epoch, 'epsilon': eps})\n"
    )},
    {"id": "C-09", "title": "Kafka WORM producer (Python)", "lang": "python", "snippet": (
        "from confluent_kafka import Producer\n"
        "import hashlib, json\n\n"
        "p = Producer({'bootstrap.servers':'msk:9092','compression.type':'zstd','acks':'all'})\n\n"
        "def emit(topic, event):\n"
        "    body = json.dumps(event, sort_keys=True).encode()\n"
        "    h = hashlib.sha256(body).hexdigest()\n"
        "    event['_hash'] = h\n"
        "    p.produce(topic, value=json.dumps(event).encode(), key=h.encode())\n"
        "    p.flush()\n"
    )},
    {"id": "C-10", "title": "GitHub Actions reusable workflow (YAML)", "lang": "yaml", "snippet": (
        "name: build-sign-publish\n"
        "on: { workflow_call: { inputs: { image: { required: true, type: string } } } }\n"
        "permissions: { id-token: write, contents: read }\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: sigstore/cosign-installer@v3\n"
        "      - run: docker build -t ${{ inputs.image }} .\n"
        "      - run: cosign sign --yes ${{ inputs.image }}\n"
        "      - run: cosign attest --predicate slsa.json --type slsa ${{ inputs.image }}\n"
    )},
    {"id": "C-11", "title": "Gantt (Mermaid)", "lang": "mermaid", "snippet": (
        "gantt\n"
        "  title FY2026 phase gates\n"
        "  dateFormat YYYY-MM-DD\n"
        "  section P0\n"
        "    P0: 2026-01-05, 30d\n"
        "  section P1\n"
        "    P1: 2026-02-09, 60d\n"
        "  section P2\n"
        "    P2: 2026-04-13, 90d\n"
        "  section P3\n"
        "    P3: 2026-07-13, 180d\n"
        "  section P4\n"
        "    P4: 2027-01-11, 365d\n"
    )},
    {"id": "C-12", "title": "Annex IV section binder (Python)", "lang": "python", "snippet": (
        "from jinja2 import Environment, FileSystemLoader\n\n"
        "env = Environment(loader=FileSystemLoader('templates'))\n\n"
        "def render_annex_iv(model_id, registry, evals, rag, sentinel):\n"
        "    tpl = env.get_template('annex-iv.j2')\n"
        "    ctx = {\n"
        "      'model': registry.get(model_id),\n"
        "      'evals': evals.for_model(model_id),\n"
        "      'rag': rag.lineage_for_model(model_id),\n"
        "      'sentinel': sentinel.evidence_for_model(model_id),\n"
        "    }\n"
        "    return tpl.render(**ctx)\n"
    )},
    {"id": "C-13", "title": "SRASE composite scorer (Python)", "lang": "python", "snippet": (
        "def srase_score(metrics):\n"
        "    weights = {'drift':.2,'kappa':.25,'cosine':.25,'evidence_lat':.15,'replay_diff':.15}\n"
        "    return sum(weights[k] * metrics[k] for k in weights)\n"
        "\n"
        "if srase_score(m) < 0.9:\n"
        "    raise SystemExit('GATE FAIL — SRASE < 0.9')\n"
    )},
    {"id": "C-14", "title": "Quarterly burn report (SQL)", "lang": "sql", "snippet": (
        "SELECT t.track, b.quarter,\n"
        "       SUM(b.committed_gbpm) AS commit,\n"
        "       SUM(b.spent_gbpm)     AS spent,\n"
        "       SUM(b.committed_gbpm - b.spent_gbpm) AS variance\n"
        "FROM budget b\n"
        "JOIN tracks t ON t.id = b.track_id\n"
        "WHERE b.fy = 2026\n"
        "GROUP BY t.track, b.quarter\n"
        "ORDER BY t.track, b.quarter;\n"
    )},
    {"id": "C-15", "title": "Hire-plan ATS export (Python)", "lang": "python", "snippet": (
        "import csv\n\n"
        "def export_ats(hires, path):\n"
        "    with open(path,'w',newline='') as f:\n"
        "        w = csv.DictWriter(f, fieldnames=['id','role','level','track','fte','startSprint','skills'])\n"
        "        w.writeheader()\n"
        "        for h in hires: w.writerow(h)\n"
    )},
    {"id": "C-16", "title": "Kill-switch quorum signer (Python)", "lang": "python", "snippet": (
        "def quorum_approve(signers, threshold=3, of=5):\n"
        "    valid = [s for s in signers if verify(s)]\n"
        "    if len(valid) < threshold:\n"
        "        raise SystemExit(f'quorum fail: {len(valid)}/{of}')\n"
        "    return {'approved': True, 'count': len(valid), 'of': of}\n"
    )},
]

# ---------------------- KPIs ----------------------
kpis = [
    {"id": "K-01", "name": "Phase-gate evidence completeness", "target": "100 %"},
    {"id": "K-02", "name": "Critical-path slippage", "target": "≤ 5 % per quarter"},
    {"id": "K-03", "name": "Annex IV assembly time", "target": "≤ 30 min"},
    {"id": "K-04", "name": "SR 11-7 pack assembly time", "target": "≤ 60 min"},
    {"id": "K-05", "name": "Sprint commitment vs. delivery", "target": "≥ 85 %"},
    {"id": "K-06", "name": "Hire plan fill rate", "target": "≥ 90 % per quarter"},
    {"id": "K-07", "name": "Budget burn variance", "target": "≤ 5 %"},
    {"id": "K-08", "name": "Sigstore signing coverage", "target": "100 % production images"},
    {"id": "K-09", "name": "Prompt template approval-to-prod cycle", "target": "≤ 5 days"},
    {"id": "K-10", "name": "Kill-switch logical p95", "target": "≤ 60 s"},
    {"id": "K-11", "name": "Interpretability circuit-coverage on Tier-1 decisions", "target": "≥ 80 %"},
    {"id": "K-12", "name": "RAG citation coverage", "target": "≥ 95 %"},
    {"id": "K-13", "name": "RAG poisoning detection rate", "target": "≥ 98 %"},
    {"id": "K-14", "name": "Registry coverage of deployed models", "target": "100 %"},
    {"id": "K-15", "name": "Threat-intel mean-time-to-mitigation", "target": "≤ 4 h Tier-1"},
    {"id": "K-16", "name": "SRASE composite score", "target": "≥ 0.9"},
    {"id": "K-17", "name": "WORM tamper alerts (true positive)", "target": "100 % within 5 min"},
    {"id": "K-18", "name": "Supervisor question SLA", "target": "≤ 5 business days"},
    {"id": "K-19", "name": "Dashboard a11y score", "target": "≥ 95 lighthouse"},
    {"id": "K-20", "name": "EAIP conformance pass rate (peers)", "target": "≥ 90 %"},
    {"id": "K-21", "name": "Treaty milestones on schedule", "target": "≥ 90 %"},
    {"id": "K-22", "name": "External Cert Gold audit", "target": "Pass with ≤ 5 minor findings"},
    {"id": "K-23", "name": "Fellowship publication count", "target": "≥ 12 / year"},
    {"id": "K-24", "name": "AISI joint exercise count", "target": "≥ 4 / year"},
]

# ---------------------- risk & control ----------------------
riskControlMatrix = [
    {"id": "R-01", "threat": "Sprint over-commit causing CP slip", "controls": ["Capacity planner gate", "WIP limits", "Phase-gate Rego"], "kpis": ["K-02", "K-05"]},
    {"id": "R-02", "threat": "Key-person dependency on Sentinel research", "controls": ["Pair rotation", "Fellowship pipeline", "Knowledge base"], "kpis": ["K-06", "K-23"]},
    {"id": "R-03", "threat": "Vendor PQC HSM lead-time slip", "controls": ["Dual-vendor RFP", "Cloud HSM fallback", "Hybrid classical bridge"], "kpis": ["K-08"]},
    {"id": "R-04", "threat": "Budget over-run in FY2026 H2", "controls": ["Monthly burn report", "Quarterly re-baseline", "CFO gate"], "kpis": ["K-07"]},
    {"id": "R-05", "threat": "Supervisor question backlog", "controls": ["Self-serve portal", "SLA tracker", "RACI to GC"], "kpis": ["K-18"]},
    {"id": "R-06", "threat": "Sigstore service outage", "controls": ["Internal mirror", "Hybrid ML-DSA co-sign", "Air-gapped backup"], "kpis": ["K-08", "K-10"]},
    {"id": "R-07", "threat": "Annex IV regression at G3", "controls": ["Golden-set tests", "Canary assembler", "Replay diff = 0"], "kpis": ["K-03"]},
    {"id": "R-08", "threat": "RAG poisoning during pilot", "controls": ["Source attestation", "Taint propagation", "Quarantine workflow"], "kpis": ["K-13"]},
    {"id": "R-09", "threat": "Prompt-marketplace cross-tenant leak", "controls": ["OPA tenant fence", "Marketplace policy", "GC review"], "kpis": ["K-09"]},
    {"id": "R-10", "threat": "SRASE composite drop below 0.9", "controls": ["Bi-weekly run", "Auto rollback hook", "AISI joint review"], "kpis": ["K-16", "K-24"]},
    {"id": "R-11", "threat": "Hire-plan diversity slate gaps", "controls": ["Slate audit", "Sourcing partners", "People Ops gate"], "kpis": ["K-06"]},
    {"id": "R-12", "threat": "Treaty milestone slip due to political risk", "controls": ["Multi-track diplomacy", "Bilateral overlays", "OECD path"], "kpis": ["K-21"]},
]

# ---------------------- traceability ----------------------
traceability = [
    {"feature": "Sprint calendar", "control": "PMO ceremony cadence", "regimes": ["ISO 42001", "SR 11-7"]},
    {"feature": "Phase-gate evidence pack", "control": "Signed Merkle bundle", "regimes": ["EU AI Act Annex IV", "SR 11-7", "ISO 42001", "SOC 2"]},
    {"feature": "RACI matrix", "control": "Decision rights enforcement", "regimes": ["SMCR", "ISO 42001", "SR 11-7"]},
    {"feature": "Budget burn report", "control": "Monthly CFO gate", "regimes": ["Basel III/IV", "BCBS 239"]},
    {"feature": "Hire plan", "control": "Diversity slate audit", "regimes": ["EU AI Act fairness", "GDPR Art 22", "Equality Act"]},
    {"feature": "Vendor decision log", "control": "Procurement RACI", "regimes": ["DORA", "NIS2", "SR 11-7"]},
    {"feature": "OKR rollup", "control": "Quarterly board read-out", "regimes": ["ISO 42001", "SMCR"]},
    {"feature": "Annex IV auto-assembler", "control": "Replay diff = 0 + ≤ 30 min SLA", "regimes": ["EU AI Act Annex IV", "SR 11-7"]},
    {"feature": "Kill-switch SLA", "control": "Logical p95 ≤ 60 s + BMC ≤ 5 min", "regimes": ["EU AI Act", "EO 14110", "ISO 42001"]},
    {"feature": "Prompt approval workflow", "control": "MRM sign-off + signed commits", "regimes": ["SR 11-7", "FCA Consumer Duty"]},
    {"feature": "Threat-intel SLA", "control": "MTTM ≤ 4 h Tier-1", "regimes": ["NIS2", "DORA"]},
    {"feature": "SRASE composite ≥ 0.9", "control": "Phase-gate Rego", "regimes": ["EU AI Act", "NIST AI RMF", "ISO 42001"]},
    {"feature": "Supervisor pack", "control": "Quarterly delivery + WORM", "regimes": ["PRA SS1/23", "FCA", "MAS FEAT", "HKMA GL-90", "SR 11-7"]},
    {"feature": "Civilizational sim publication", "control": "GC + Safety Lead redaction", "regimes": ["G7 Hiroshima", "Bletchley", "Seoul", "CoE AI Convention"]},
]

# ---------------------- data flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "Sprint → Gate evidence", "steps": ["Sprint close", "Track artifact upload", "Hash + sign", "WORM emit", "Gate review"], "controls": ["ML-DSA", "WORM", "RACI"]},
    {"id": "DF-02", "name": "Hire plan → ATS", "steps": ["WBS demand", "People Ops scrub", "ATS req open", "Slate audit", "Fill"], "controls": ["Diversity slate", "Approval workflow"]},
    {"id": "DF-03", "name": "Budget commit → spent", "steps": ["FY plan", "Quarterly commit", "PO + approval", "Spend ledger", "Burn report"], "controls": ["CFO gate", "BCBS 239"]},
    {"id": "DF-04", "name": "Vendor RFP → award", "steps": ["Capability gap", "RFP issue", "Score + Sec review", "Award", "Contract + exit clause"], "controls": ["Procurement RACI", "DORA", "NIS2"]},
    {"id": "DF-05", "name": "OKR → board pack", "steps": ["Team OKR set", "Quarterly check-in", "Rollup query", "Board read-out", "WORM archive"], "controls": ["RACI", "ISO 42001"]},
    {"id": "DF-06", "name": "Incident → RPCO replay", "steps": ["Trigger", "Freeze inputs", "Replay harness", "Diff = 0 check", "Evidence Vault"], "controls": ["WORM", "Sigstore", "PQC"]},
]

# ---------------------- regulators ----------------------
regulators = [
    {"id": "REG-01", "name": "European Commission (EU AI Office)", "primary": "EU AI Act 2026 + Annex IV"},
    {"id": "REG-02", "name": "PRA / Bank of England", "primary": "SS1/23 + SMCR + Basel III/IV"},
    {"id": "REG-03", "name": "FCA", "primary": "Consumer Duty + SMCR"},
    {"id": "REG-04", "name": "MAS (Singapore)", "primary": "FEAT + AI Verify"},
    {"id": "REG-05", "name": "HKMA", "primary": "GL-90 + Banking (Capital) Rules"},
    {"id": "REG-06", "name": "US Federal Reserve / OCC", "primary": "SR 11-7 + OCC 2011-12"},
    {"id": "REG-07", "name": "EU Data Protection Board", "primary": "GDPR + DPIA"},
    {"id": "REG-08", "name": "ICO (UK)", "primary": "UK GDPR + Data Protection Act"},
    {"id": "REG-09", "name": "AISI UK + AISI US", "primary": "Frontier eval joint exercises"},
    {"id": "REG-10", "name": "FSB", "primary": "AI in financial services"},
    {"id": "REG-11", "name": "OECD", "primary": "AI Principles 2024"},
    {"id": "REG-12", "name": "Council of Europe", "primary": "AI Convention"},
]

# ---------------------- workshops ----------------------
workshops = [
    {"id": "W-01", "audience": "Board AI/Risk Committee", "duration": "2 hr quarterly", "outcome": "OKR rollup + critical-path review"},
    {"id": "W-02", "audience": "PMO + Track leads", "duration": "1 hr biweekly", "outcome": "Cross-track blocker resolution"},
    {"id": "W-03", "audience": "Architecture forum", "duration": "1 hr weekly", "outcome": "Architecture decisions + record updates"},
    {"id": "W-04", "audience": "Risk forum", "duration": "30 min weekly", "outcome": "Risk register update + escalation"},
    {"id": "W-05", "audience": "Supervisor dialogue", "duration": "2 hr quarterly", "outcome": "Annex IV / SR 11-7 / FEAT review"},
    {"id": "W-06", "audience": "External red-team", "duration": "1 day quarterly", "outcome": "WG-01..WG-06 outcomes + mitigations"},
    {"id": "W-07", "audience": "Fellowship cohort", "duration": "2 hr monthly", "outcome": "Research review + publication pipeline"},
]

# ---------------------- case studies ----------------------
cases = [
    {"id": "CASE-01", "name": "G-SIFI bank pilot — fraud agent w/ Sentinel v2.4", "outcomes": "CP-06 + CP-08 delivered at G1; drift 1.8 %; κ 0.94; Annex IV ≤ 22 min."},
    {"id": "CASE-02", "name": "F500 healthcare CCaaS-PETs wave 2", "outcomes": "Opacus ε ≤ 4.0; 0 PII leaks; DPIA passed; GDPR opt-out cascade verified."},
    {"id": "CASE-03", "name": "Cross-bank EAIP interop bake-off", "outcomes": "5 institutions; 92 % conformance; joint Sentinel adapter; FSB submission."},
    {"id": "CASE-04", "name": "Annual AISI frontier-eval joint exercise", "outcomes": "Mesa-optimization probe library released; 0 capability uplift findings; SRASE 0.93."},
    {"id": "CASE-05", "name": "WORM-tamper red-team", "outcomes": "Detected in 3 min; kill-switch quorum invoked; replay diff = 0; evidence vault intact."},
    {"id": "CASE-06", "name": "Cert Gold audit (ISO 42001) FY2026", "outcomes": "Pass with 4 minor findings; remediation closed in 30 d; supervisor pack distributed."},
]

# ---------------------- privacy ----------------------
privacy = {
    "gdpr": "Arts 5/6/17/22/25/32/35 mapped via DPIA generator + opt-out cascade.",
    "dataResidency": "EU-only, UK-only, US-only, APAC-only stacks; sovereign-tenant variant.",
    "petStack": "Opacus DP + FPE tokenization + AMD SEV-SNP / Intel TDX enclaves + BYOK PQC.",
    "rightsAutomation": "Opt-out portal → training + RAG + telemetry cascade; ≤ 30 d completion.",
    "dpoSignOff": "Per-quarter aggregate report + per-incident sign-off.",
}

# ---------------------- deployment ----------------------
deployment = [
    "Environments: dev → preprod → prod → sov-prod → frontier-air-gapped.",
    "Tier-1 active/active across two regions; Tier-2 active/passive.",
    "Sigstore + ML-DSA hybrid co-sign required at admission for all images.",
    "OPA bundle service signed + verified at policy load.",
    "Kill-switch quorum: 3-of-5 signers including ≥ 1 board-designated.",
    "WORM retention: 7 yr baseline; 25 yr Annex IV high-risk; 100 yr civilizational.",
    "Backup posture: cross-region S3 + offsite encrypted tape (annual rotation).",
    "DR drill: quarterly, ≤ 4 h RTO Tier-1, ≤ 1 h Tier-0 evidence-vault.",
]

# ---------------------- 30/60/90-day rollout ----------------------
rollout90 = [
    {"day": "0-30", "track": "All (P0)", "items": [
        "Kill-switch quorum live + BMC paths tested",
        "Sigstore + ML-DSA hybrid signing operational",
        "OPA bundle service in CI",
        "Kafka WORM + S3 Object Lock provisioned",
        "PQC KMS in dev/preprod",
        "PMO ceremonies started",
        "Hire plan Q1 reqs opened",
        "Board AI/Risk Committee charter ratified",
    ]},
    {"day": "31-60", "track": "P1 alpha", "items": [
        "Reference architecture v1 frozen",
        "Dashboards alpha (6 tiles live)",
        "Prompt Architect MVP + version control",
        "RAG governance v1 (ACL + taint)",
        "EAIP envelope v1 draft RFC",
        "Supervisor Q1 pack delivered",
    ]},
    {"day": "61-90", "track": "P1 close + P2 alpha", "items": [
        "Sentinel v2.4 Cognitive Resonance probes",
        "WorkflowAI Pro agent registry alpha",
        "Threat-intel ingest pipeline",
        "Telemetry SLO board live",
        "Hire plan Q2 reqs opened",
        "External CP-01..CP-08 audit dry-run",
    ]},
]

# ---------------------- 2026-2030 roadmap ----------------------
roadmap = [
    {"year": "2026", "focus": "Foundations + Alpha", "milestones": ["G0", "G1 close", "Cert Gold audit", "EAIP RFC draft", "AISI joint exercise"]},
    {"year": "2027", "focus": "GA + Federation", "milestones": ["G2", "G3 close", "Model registry GA", "GACP/GACRLS/GACRA brokers", "zk-SNARK verifier portal"]},
    {"year": "2028", "focus": "Treaty + Multi-jurisdiction", "milestones": ["EAIP v1.0 final", "FSB submissions", "Cert Platinum", "MGK steady state"]},
    {"year": "2029", "focus": "Civilizational + ASI prep", "milestones": ["CSE-X v2", "Civilizational research publications", "Treaty obligations met"]},
    {"year": "2030", "focus": "Steady state", "milestones": ["Cert Platinum re-audit", "All 17 CP items in steady-state ops", "Public assurance program"]},
]

# ---------------------- evidence pack ----------------------
evidencePack = {
    "audience": "EU AI Office, PRA/FCA, MAS, HKMA, Fed/OCC, AISI UK/US, FSB, OECD, Board AI/Risk Committee, External auditors (Cert Gold/Platinum)",
    "contents": [
        "Phase-gate Merkle bundles G0..G4 (signed ML-DSA-65 + SLSA L3+ provenance)",
        "Sprint calendar + close-out reports (26 sprints FY2026)",
        "RACI matrix + decision-rights ledger",
        "OKR rollups + KPI tiles (quarterly)",
        "Budget burn reports + variance memo",
        "Hire plan + diversity slate audits",
        "Vendor decision log + RFP outcomes + exit clauses",
        "Annex IV / SR 11-7 / ISO 42001 / SOC 2 / DPIA packs",
        "SRASE composite ≥ 0.9 evidence (per quarter)",
        "AISI joint exercise reports (signed)",
        "Risk register snapshots + R-01..R-12 mitigations",
        "WORM archive index + Merkle anchor receipts",
    ],
    "formats": "PAdES-signed PDF (ML-DSA-65 + RSA-PSS hybrid), JSON-LD evidence graph, Merkle anchor TXT, zk-SNARK proofs (Groth16/PLONK)",
    "delivery": "Sigstore-verified portal + supervisor mTLS API + offline encrypted USB on request",
    "retention": "7-year baseline, 25-year for Annex IV high-risk, 100-year for civilizational simulations",
}

# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": (
        "Operationalize WP-050's Prioritized Implementation & Research "
        "Plan into a 26-sprint executable program for FY2026 with "
        "phase gates G0..G4, RACI, OKRs, quarterly budget envelopes, "
        "hire plan, vendor decisions and PMO controls."
    ),
    "approach": (
        "Track-aligned 2-week sprints (S1..S26), 5-day buffer per phase "
        "for gate evidence, monthly KPI tile, quarterly OKR rollup and "
        "supervisor pack; every gate produces a signed Merkle evidence "
        "bundle written to WORM."
    ),
    "deliverables": (
        "Sprint calendar, WBS for 14 tracks (≥ 78 work items), RACI "
        "matrix, OKR tree, FY2026 quarterly budget envelopes, hire plan "
        "(72 reqs across 14 tracks), vendor decisions (12 capabilities), "
        "gate evidence packs (G0..G4), supervisor packs (12 regulators)."
    ),
    "outcomes": [
        "100 % phase-gate evidence completeness",
        "Critical-path slippage ≤ 5 % / quarter",
        "Annex IV ≤ 30 min, SR 11-7 ≤ 60 min auto-assembly",
        "Hire-plan fill ≥ 90 %; budget burn variance ≤ 5 %",
        "External Cert Gold audit passed in FY2026",
        "EAIP RFC drafted + cross-institution interop bake-off in FY2026",
    ],
}

# ---------------------- final assembly ----------------------
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
    "apiRoutes": 28,
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(DOC, indent=2))
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
print("counts:", DOC["counts"])
