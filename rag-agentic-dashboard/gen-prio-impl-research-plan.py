#!/usr/bin/env python3
"""WP-050 — Prioritized Implementation & Research Plan (2026-2030).

Synthesizes WP-035..WP-049 into a phased, dependency-aware roadmap with
critical-path identification across:

* AI safety research
* Global governance policy design
* Enterprise AI reference architecture
* Governance dashboards (UI)
* Security & DevSecOps (Sigstore, OPA, zero-egress K8s, WORM logging)
* RAG program governance
* EAIP (Enterprise AI Inference Protocol) design
* CCaaS summarization with PETs
* Prompt Architect (templating, variable linking, version control, testing, sharing)
* Model registry
* Threat-intelligence dashboards
* Telemetry & interpretability
* AGI/ASI governance simulations
* Report-generation workflows
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "prio-impl-research-plan.json"


def section(sid, title, content):
    return {"id": sid, "title": title, "content": content}


DOC = {
    "docRef": "PRIO-IMPL-RESEARCH-PLAN-WP-050",
    "version": "1.0.0",
    "horizon": "2026-2030 (research outlook 2026-2035)",
    "classification": (
        "CONFIDENTIAL — Board / CEO / CRO / CISO / CAIO / Chief Architect / "
        "Head of AI Research / Head of AI Platform Engineering / Head of "
        "MRM / Head of Internal Audit / GC / DPO / AI Safety Lead / "
        "Treaty Liaison / PMO / Engineering Leadership"
    ),
    "title": (
        "Prioritized Implementation & Research Plan — Enterprise AI "
        "Platform, AI Safety & Global Governance (2026-2030)"
    ),
    "subtitle": (
        "Phased delivery + critical path across AI safety research, "
        "global governance policy, Enterprise AI reference architecture, "
        "governance dashboards, security & DevSecOps (Sigstore, OPA, "
        "zero-egress K8s, WORM), RAG governance, EAIP protocol, CCaaS "
        "summarization with PETs, Prompt Architect, model registry, "
        "threat-intel dashboards, telemetry & interpretability, AGI/ASI "
        "governance simulations, and report-generation workflows"
    ),
    "owner": (
        "Chief Architect + CAIO + Head of AI Research + Head of AI "
        "Platform Engineering; co-signed by CRO, CISO, Head of MRM, "
        "GC, DPO, AI Safety Lead, Treaty Liaison, PMO Director, "
        "Board AI/Risk Committee Chair"
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
    "apiPrefix": "/api/prio-impl-research-plan",
}

# ---------------------- machine-parsable directive ----------------------
DOC["directive"] = {
    "format": "machine-parsable XML-style block consumed by PMO planning, dependency graph engine, OKR generator, capacity planner and risk register",
    "raw": (
        "<directive id=\"PRIO-IMPL-RESEARCH-PLAN-WP-050\" version=\"1.0.0\" "
        "horizon=\"2026-2030\" jurisdiction=\"F500,G-SIFI,Global\">"
        "<scope>Plan|CriticalPath|Phasing|Dependencies|Research</scope>"
        "<modules>14</modules>"
        "<phases>P0|P1|P2|P3|P4</phases>"
        "<phaseWindowsDays>30|90|180|365|1825</phaseWindowsDays>"
        "<tracks>AISafety|GlobalGovernance|RefArch|Dashboards|DevSecOps|"
        "RAGGov|EAIP|CCaaSPETs|PromptArchitect|ModelRegistry|ThreatIntel|"
        "Telemetry|AGISims|Reports</tracks>"
        "<priorities>P0-CRITICAL|P1-HIGH|P2-MEDIUM|P3-LOW</priorities>"
        "<criticalPathItems>17</criticalPathItems>"
        "<dependencies>72</dependencies>"
        "<workItems>56</workItems>"
        "<thresholds annexIVAssemblyMinutes=\"30\" "
        "rpcoForensicsMinutes=\"45\" wormReplayDiffMax=\"0\" "
        "killSwitchSeconds=\"60\" judgeKappaMin=\"0.9\" "
        "fiduciaryCosineMin=\"0.92\" mgkProofCoverageMin=\"0.95\"/>"
        "<rollout p0Days=\"30\" p1Days=\"90\" p2Days=\"180\" "
        "p3Days=\"365\" p4Days=\"1825\"/>"
        "<owners>CAIO|CRO|CISO|ChiefArchitect|AISafetyLead|HeadMRM|"
        "PMO|HeadResearch|TreatyLiaison</owners>"
        "</directive>"
    ),
    "parsed": {
        "id": "PRIO-IMPL-RESEARCH-PLAN-WP-050",
        "scope": ["Plan", "CriticalPath", "Phasing", "Dependencies", "Research"],
        "phases": ["P0", "P1", "P2", "P3", "P4"],
        "phaseWindowsDays": [30, 90, 180, 365, 1825],
        "tracks": [
            "AISafety", "GlobalGovernance", "RefArch", "Dashboards",
            "DevSecOps", "RAGGov", "EAIP", "CCaaSPETs",
            "PromptArchitect", "ModelRegistry", "ThreatIntel",
            "Telemetry", "AGISims", "Reports",
        ],
        "priorities": ["P0-CRITICAL", "P1-HIGH", "P2-MEDIUM", "P3-LOW"],
        "criticalPathItems": 17,
        "dependencies": 72,
        "workItems": 56,
        "thresholds": {
            "annexIVAssemblyMinutes": 30,
            "rpcoForensicsMinutes": 45,
            "wormReplayDiffMax": 0,
            "killSwitchSeconds": 60,
            "judgeKappaMin": 0.90,
            "fiduciaryCosineMin": 0.92,
            "mgkProofCoverageMin": 0.95,
        },
        "rollout": {
            "p0Days": 30, "p1Days": 90, "p2Days": 180,
            "p3Days": 365, "p4Days": 1825,
        },
        "owners": [
            "CAIO", "CRO", "CISO", "ChiefArchitect", "AISafetyLead",
            "HeadMRM", "PMO", "HeadResearch", "TreatyLiaison",
        ],
    },
    "consumers": [
        "PMO planning + capacity",
        "Engineering leadership OKR rollup",
        "Board AI/Risk Committee quarterly review",
        "MRM platform CI/CD admission gate",
        "AI Safety research backlog",
        "Treaty liaison + AISI joint roadmap",
        "Risk register dependency graph engine",
        "Internal Audit assurance plan",
    ],
}

# ---------------------- 14 modules ----------------------
modules = []

# --- M1 — Plan Overview, Phases & Critical Path ---
modules.append({
    "id": "M1",
    "title": "M1 — Plan Overview, Phases & Critical Path",
    "summary": (
        "Five-phase delivery (P0..P4) over 30/90/180/365/1825 days with "
        "17 critical-path items, 72 inter-track dependencies and 56 work "
        "items spanning 14 tracks; produces a stable PMO dependency "
        "graph and OKR rollup."
    ),
    "covers": ["Phases", "Critical path", "Dependencies", "OKR rollup", "Tracks"],
    "sections": [
        section("M1-S1", "Phase Definitions", {
            "P0": "Days 0-30 — Foundations & guardrails (kill-switch, WORM, OPA bundle, Sigstore, AIMS scope)",
            "P1": "Days 31-90 — Reference architecture + dashboards alpha + Prompt Architect MVP + RAG governance v1",
            "P2": "Days 91-180 — Model registry GA + EAIP draft + CCaaS-PETs pilot + threat-intel dashboard + AGI sim v1",
            "P3": "Days 181-365 — Federation (GACP/GACRLS/GACRA) + zk-SNARK verifier + interpretability suite + report workflows GA",
            "P4": "Years 2-5 — Treaty obligations + Cert Gold→Platinum + MGK steady state + civilizational research outputs",
            "exitCriteria": "Each phase has measurable exit gates tied to KPIs and supervisor packs",
        }),
        section("M1-S2", "Critical-Path Items (17)", {
            "CP-01": "Kill-switch quorum + BMC fabric (gates everything Tier-1)",
            "CP-02": "Sigstore + ML-DSA hybrid signing chain",
            "CP-03": "OPA bundle service + Rego policy CI",
            "CP-04": "Kafka/MSK WORM + S3 Object Lock daily Merkle anchor",
            "CP-05": "PQC KMS (FIPS 203/204) + HSM",
            "CP-06": "Sentinel v2.4 Cognitive Resonance probes",
            "CP-07": "WorkflowAI Pro agent registry + CRS-UUID lineage",
            "CP-08": "Inference proxies (FastAPI + Node) + EAIP draft",
            "CP-09": "Model registry GA + lineage edges",
            "CP-10": "Prompt Architect templating + version control",
            "CP-11": "RAG ACL + corpus taint + lineage",
            "CP-12": "Governance dashboards alpha → GA",
            "CP-13": "Annex IV / SR 11-7 pack auto-assembly ≤ 30 min",
            "CP-14": "AGI/ASI sim engine (CSE-X + SRASE)",
            "CP-15": "GACP/GACRLS/GACRA brokers",
            "CP-16": "zk-SNARK verifier + public portal",
            "CP-17": "RPCO replay harness + Evidence Vault",
        }),
        section("M1-S3", "Tracks Catalogue", {
            "T-Safety": "AI safety research (alignment, deception, interpretability, frontier evals)",
            "T-Gov": "Global governance policy design (treaty, Codex, Constitution, sanctions)",
            "T-Arch": "Enterprise AI reference architecture",
            "T-UI": "Governance dashboards UI",
            "T-Sec": "Security & DevSecOps",
            "T-RAG": "RAG program governance",
            "T-EAIP": "Enterprise AI Inference Protocol design",
            "T-CCaaS": "CCaaS summarization with PETs",
            "T-Prompt": "Prompt Architect features",
            "T-Reg": "Model registry",
            "T-TI": "Threat-intelligence dashboards",
            "T-Tel": "Telemetry & interpretability",
            "T-Sim": "AGI/ASI governance simulations",
            "T-Reports": "Report-generation workflows",
        }),
        section("M1-S4", "OKR Rollup Template", {
            "company": "Be regulator/auditor/board-ready globally with Cert Gold by 2027",
            "tribes": "AI Platform, AI Research, MRM, Security, Compliance, Civilizational",
            "cadence": "Quarterly OKRs; monthly KPI tile; weekly stand-up; biweekly architecture review",
        }),
        section("M1-S5", "Capacity & Funding", {
            "envelopeFY26": "Platform 40 %, Research 20 %, Security/DevSecOps 15 %, Compliance/MRM 10 %, Reports/UI 10 %, Civilizational 5 %",
            "scaling": "Re-baseline at end of each phase based on critical-path slippage and supervisor requests",
        }),
    ],
})

# --- M2 — AI Safety Research Plan ---
modules.append({
    "id": "M2",
    "title": "M2 — AI Safety Research Plan",
    "summary": (
        "Research workstreams covering alignment, deception detection, "
        "interpretability, frontier capability evals, ASI honeypots and "
        "Cognitive Resonance — each with hypotheses, methods, datasets, "
        "and supervisor-shareable outputs."
    ),
    "covers": ["Alignment", "Deception", "Interpretability", "Frontier evals", "Honeypots", "Resonance"],
    "sections": [
        section("M2-S1", "Workstream Catalogue", [
            {"id": "RS-01", "topic": "Behavioural alignment (constitutional + RLHF + RLAIF)", "priority": "P0-CRITICAL", "phase": "P0-P2"},
            {"id": "RS-02", "topic": "Deceptive alignment detection (eval vs prod gap)", "priority": "P0-CRITICAL", "phase": "P1-P3"},
            {"id": "RS-03", "topic": "Mechanistic interpretability + circuits", "priority": "P1-HIGH", "phase": "P1-P4"},
            {"id": "RS-04", "topic": "Frontier capability evals (Bio/Cyber/CBRN)", "priority": "P0-CRITICAL", "phase": "P0-P3"},
            {"id": "RS-05", "topic": "ASI honeypot library + behaviour fingerprints", "priority": "P1-HIGH", "phase": "P1-P3"},
            {"id": "RS-06", "topic": "Cognitive Resonance theory + probes", "priority": "P1-HIGH", "phase": "P0-P4"},
            {"id": "RS-07", "topic": "Scalable oversight (debate, weak-to-strong, recursive)", "priority": "P1-HIGH", "phase": "P2-P4"},
            {"id": "RS-08", "topic": "Causal abstraction & counterfactual safety", "priority": "P2-MEDIUM", "phase": "P2-P4"},
        ]),
        section("M2-S2", "Methods + Datasets", {
            "methods": ["Eval harness (TruthfulQA, MMLU, BIG-bench, ARC-AGI, MLE-bench)", "Activation patching", "Probing classifiers", "Adversarial sandboxing", "Behavioural cloning"],
            "datasets": ["Internal red-team corpus", "AISI shared evals", "Treaty Annex test bundles", "Cultural Resonance Archive"],
            "infra": "Air-gapped enclave (Sentinel AGI Lab) with PQC-signed result envelopes",
        }),
        section("M2-S3", "Supervisor-Shareable Outputs", {
            "papers": "Peer-reviewable workshop / journal submissions (anonymised)",
            "annexBundles": "AISI joint-inspection bundles with evidence packs",
            "blogs": "Public communication via transparency portal",
            "datasets": "Donated to AISI / NIST / OECD where legally permissible",
        }),
        section("M2-S4", "Safety KPIs", {
            "deceptionRecall": "≥ 0.95",
            "interpCoverage": "≥ 60 % of Tier-1 model parameters fingerprinted by P4",
            "frontierEvalPassRate": "0 critical capability triggers without containment",
        }),
        section("M2-S5", "Research-Engineering Bridge", {
            "interfaces": "Research → Sentinel probes; Research → Prompt Architect refusal lattice; Research → MGK invariants",
            "cadence": "Quarterly research-engineering review with CAIO + CRO",
        }),
    ],
})

# --- M3 — Global Governance Policy Design ---
modules.append({
    "id": "M3",
    "title": "M3 — Global Governance Policy Design",
    "summary": (
        "Treaty obligations, AI Governance Constitution (Arts 1-7), "
        "Civilizational Codex, sanctions ladder, Cert Scoring, GIEN "
        "streaming and ICGC compute registry — sequenced from policy "
        "design → ratification → operations."
    ),
    "covers": ["Treaty", "Constitution", "Codex", "Sanctions", "Cert", "GIEN", "ICGC"],
    "sections": [
        section("M3-S1", "Policy Workstreams", [
            {"id": "GP-01", "topic": "Treaty Framework 2026-2035", "priority": "P0-CRITICAL", "phase": "P0-P4"},
            {"id": "GP-02", "topic": "AI Constitution Arts 1-7 ratification", "priority": "P0-CRITICAL", "phase": "P1-P3"},
            {"id": "GP-03", "topic": "Civilizational Codex v1 drafting", "priority": "P1-HIGH", "phase": "P1-P4"},
            {"id": "GP-04", "topic": "Sanctions ladder G1-G6 + appeal", "priority": "P1-HIGH", "phase": "P2-P3"},
            {"id": "GP-05", "topic": "Cert Scoring Bronze→Platinum", "priority": "P0-CRITICAL", "phase": "P0-P4"},
            {"id": "GP-06", "topic": "GIEN streaming protocol design", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "GP-07", "topic": "ICGC compute registry charter", "priority": "P0-CRITICAL", "phase": "P0-P2"},
        ]),
        section("M3-S2", "Stakeholder Map", {
            "internal": ["Board", "CAIO", "GC", "Treaty Liaison", "DPO"],
            "external": ["AISI consortium", "Treaty Secretariat", "OECD", "FSB", "BIS", "UNESCO", "G7 / G20 chairs", "Civil society"],
            "interfaces": ["Joint working groups", "Code of practice fora", "Sandbox programs"],
        }),
        section("M3-S3", "Ratification Path", {
            "steps": ["bilateral consult", "G7 endorsement", "G20 sign-off", "UN side-letter", "domestic transposition"],
            "evidence": "Per-signatory attestation chain, PQC signed",
        }),
        section("M3-S4", "Compliance Operations", {
            "monthly": "Per-obligation attestation",
            "quarterly": "Drills + Cert review",
            "annual": "Independent assurance + treaty annex submission",
        }),
        section("M3-S5", "Civilizational KPIs", {
            "treatySignatories": "G20 + EU + UK + SG + JP + CH by 2027",
            "certScore": "Gold by 2027, Platinum by 2029",
            "icgcQuotaAdherence": "100 %",
        }),
    ],
})

# --- M4 — Enterprise AI Reference Architecture ---
modules.append({
    "id": "M4",
    "title": "M4 — Enterprise AI Reference Architecture",
    "summary": (
        "Reference-architecture rollout plan covering OPA sidecars, "
        "FastAPI/Node inference proxies, Kafka WORM, S3 Object Lock, "
        "PQC KMS, Terraform zero-trust EKS, Kata + Cilium + Gatekeeper, "
        "with admission control and CI/CD policy gates."
    ),
    "covers": ["OPA sidecar", "Proxies", "Kafka WORM", "PQC KMS", "EKS zero-trust", "Kata", "Cilium"],
    "sections": [
        section("M4-S1", "Architectural Backbone", [
            {"id": "AR-01", "topic": "OPA Gatekeeper + Kyverno admission", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "AR-02", "topic": "OPA per-pod governance sidecar GA", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "AR-03", "topic": "FastAPI inference proxy hardened", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "AR-04", "topic": "Node.js inference proxy + zk-SNARK receipt", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "AR-05", "topic": "Kafka/MSK WORM + Merkle anchor", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "AR-06", "topic": "S3 Object Lock + per-incident vault", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "AR-07", "topic": "PQC KMS + HSM rotation", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "AR-08", "topic": "Terraform golden modules signed", "priority": "P1-HIGH", "phase": "P0-P2"},
            {"id": "AR-09", "topic": "Bottlerocket + Kata + SEV-SNP nodepools", "priority": "P1-HIGH", "phase": "P0-P2"},
            {"id": "AR-10", "topic": "Cilium L7 zero-egress + egress broker", "priority": "P0-CRITICAL", "phase": "P0-P1"},
        ]),
        section("M4-S2", "Sequencing", {
            "P0": "Network + IAM + WORM + KMS + Gatekeeper baseline",
            "P1": "Sidecar + proxy + Terraform modules + Kata nodepools",
            "P2": "Multi-region active-active + DR drill ≤ 4 h RTO",
            "P3": "Federation egress + GIEN integration",
        }),
        section("M4-S3", "Cross-Track Hooks", {
            "T-Sec": "All admission policies tested in CI; OPA bundle signed",
            "T-Tel": "OTel-GenAI + Falco rules baked into modules",
            "T-Reg": "Model registry consumes proxy lineage envelopes",
            "T-RAG": "Corpus residency + ACL flow through proxy",
        }),
        section("M4-S4", "Performance Budgets", {
            "opaSidecarP99": "≤ 4 ms",
            "proxyOverheadP95": "≤ 25 ms",
            "wormEmitP95": "≤ 5 s",
        }),
        section("M4-S5", "Acceptance Tests", {
            "tests": ["Conftest + OPA unit ≥ 95 %", "Trivy + Grype zero-critical gate", "kube-bench CIS pass", "Chaos drill quarterly"],
        }),
    ],
})

# --- M5 — Governance Dashboards (UI) ---
modules.append({
    "id": "M5",
    "title": "M5 — Governance Dashboards (UI Components)",
    "summary": (
        "UI roadmap covering the executive board tile, MRM dashboard, "
        "Sentinel resonance live view, kill-switch console, Prompt "
        "Architect, model registry browser, threat-intel and "
        "civilizational portals."
    ),
    "covers": ["Board tile", "MRM dashboard", "Sentinel view", "Kill-switch console", "Civilizational portals"],
    "sections": [
        section("M5-S1", "Dashboard Catalogue", [
            {"id": "UI-01", "topic": "Board KPI tile (one page, auto-refresh)", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "UI-02", "topic": "MRM lifecycle dashboard", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "UI-03", "topic": "Sentinel resonance live view", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "UI-04", "topic": "Kill-switch console (3-of-5 quorum)", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "UI-05", "topic": "Prompt Architect studio", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "UI-06", "topic": "Model registry browser", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "UI-07", "topic": "Threat-intel dashboard", "priority": "P1-HIGH", "phase": "P2-P3"},
            {"id": "UI-08", "topic": "Transparency Portal (public verifier)", "priority": "P1-HIGH", "phase": "P3"},
            {"id": "UI-09", "topic": "Treaty / Cert / Codex viewer", "priority": "P2-MEDIUM", "phase": "P3-P4"},
        ]),
        section("M5-S2", "Design System", {
            "tech": "Next.js 14 + React 19 + Tailwind + shadcn/ui; dark palette aligned with WP series",
            "patterns": ["Sticky nav", "Module cards", "KV tables", "Pill chips", "Detail accordions"],
            "accessibility": "WCAG 2.2 AA; screen-reader audit per release",
        }),
        section("M5-S3", "API Contracts", {
            "backend": "REST + JSON over mTLS; pagination + ETag; OpenAPI 3.1 published",
            "live": "WebSocket / SSE for resonance + kill-switch + threat feeds",
            "auth": "OIDC + step-up for break-glass actions",
        }),
        section("M5-S4", "Storybook + E2E", {
            "storybook": "All atoms/molecules; visual-regression in CI",
            "e2e": "Playwright; nightly run; performance budget (TTI ≤ 2.5 s)",
        }),
        section("M5-S5", "Owner Map", {
            "design": "Design Systems team",
            "frontend": "AI Platform — UI",
            "backend": "AI Platform — Services",
            "owners": "CAIO + Chief Architect approval per release",
        }),
    ],
})

# --- M6 — Security & DevSecOps ---
modules.append({
    "id": "M6",
    "title": "M6 — Security & DevSecOps (Sigstore, OPA, Zero-Egress K8s, WORM)",
    "summary": (
        "End-to-end DevSecOps from commit to production: pre-commit, PR "
        "LLM-judge, SLSA L3+ build, Sigstore + ML-DSA signing, Gatekeeper "
        "admission, Cilium zero-egress, WORM logging, Falco runtime, "
        "Vault-PQC KMS — with continuous attestation."
    ),
    "covers": ["Sigstore", "SLSA", "OPA", "Cilium", "WORM", "Vault-PQC", "Falco", "CI judge"],
    "sections": [
        section("M6-S1", "Workstream Catalogue", [
            {"id": "SC-01", "topic": "Cosign keyless OIDC + Rekor", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "SC-02", "topic": "ML-DSA-44/65 hybrid signing", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "SC-03", "topic": "SLSA L3+ builder hardening", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "SC-04", "topic": "Gatekeeper + Kyverno constraints", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "SC-05", "topic": "Cilium L7 + egress allow-list", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "SC-06", "topic": "WORM (Kafka + S3 Object Lock + Merkle)", "priority": "P0-CRITICAL", "phase": "P0"},
            {"id": "SC-07", "topic": "Vault-PQC KMS operator", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "SC-08", "topic": "Falco eBPF rules + WORM-skip detector", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "SC-09", "topic": "LLM-as-judge ensemble (3 vendors)", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "SC-10", "topic": "Continuous attestation + drift watchers", "priority": "P1-HIGH", "phase": "P2"},
        ]),
        section("M6-S2", "Pipeline Stages", {
            "preCommit": "ruff, mypy, bandit, semgrep, hadolint, opa-test, kube-linter, conftest",
            "pr": "LLM-judge ensemble (κ ≥ 0.9), policy diff, threat-model delta",
            "build": "SLSA L3+ isolated builder; provenance signed Cosign + ML-DSA",
            "ship": "SBOM (CycloneDX + SPDX), vuln gate, Gatekeeper admission",
            "run": "Falco runtime, Sentinel drift, auto-rollback on regression",
        }),
        section("M6-S3", "KPIs", {
            "judgeKappa": "≥ 0.9",
            "criticalCveSlaDays": "≤ 7",
            "wormReplayDiff": "= 0",
            "pqcRotationDays": "≤ 90",
        }),
        section("M6-S4", "Red-Team Hooks", {
            "wargames": "WG-01..WG-06 from WP-049 fed into PR judge eval set",
            "purpleTeam": "Quarterly joint blue+red exercise",
        }),
        section("M6-S5", "Roles", {
            "owners": "CISO + Head of AppSec + Head of Platform Eng",
            "raci": "R=AppSec, A=CISO, C=AI Safety, I=Board",
        }),
    ],
})

# --- M7 — RAG Program Governance ---
modules.append({
    "id": "M7",
    "title": "M7 — RAG Program Governance",
    "summary": (
        "Governance of retrieval-augmented generation across ingestion, "
        "chunking, embedding, retrieval, prompt assembly, response — "
        "with ACL, residency, taint, PII redaction, lineage and audit."
    ),
    "covers": ["Ingestion", "Chunking", "Embeddings", "ACL", "Residency", "Taint", "Lineage"],
    "sections": [
        section("M7-S1", "Workstream Catalogue", [
            {"id": "RG-01", "topic": "Corpus catalogue + classification", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "RG-02", "topic": "ACL + residency enforcement", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "RG-03", "topic": "Chunking + embedding model registry hooks", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "RG-04", "topic": "PII redaction (eBPF + DLP)", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "RG-05", "topic": "Taint propagation on suspect sources", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "RG-06", "topic": "RAG lineage to WORM (per chunk CRS-UUID)", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "RG-07", "topic": "Prompt-injection defence (pre/post)", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "RG-08", "topic": "Eval harness for retrieval quality", "priority": "P1-HIGH", "phase": "P2"},
        ]),
        section("M7-S2", "Controls", {
            "ingress": "Source attestation + virus scan + license check",
            "store": "Per-tenant vector DB w/ row-level ACL + envelope encryption",
            "retrieval": "Rego allow-list + similarity threshold + diversity reranker",
            "egress": "PII redactor + judge LLM + WORM envelope",
        }),
        section("M7-S3", "KPIs", {
            "retrievalPrecision": "≥ 0.85 on golden set",
            "promptInjectionBlock": "≥ 99.9 %",
            "leakageRate": "≤ 0.01 %",
        }),
        section("M7-S4", "Risk Register Hooks", {
            "risks": ["Corpus poisoning", "Indirect injection", "Cross-tenant retrieval", "Stale chunks", "Embedding drift"],
        }),
        section("M7-S5", "Owner Map", {
            "owners": "Head of Data + Head of AI Platform + DPO",
        }),
    ],
})

# --- M8 — EAIP Protocol Design ---
modules.append({
    "id": "M8",
    "title": "M8 — EAIP (Enterprise AI Inference Protocol) Design",
    "summary": (
        "Versioned, signed, audit-grade request/response envelope "
        "protocol — used by FastAPI/Node proxies, WorkflowAI Pro, GACP "
        "brokers and ICGC, replacing ad-hoc per-vendor payloads."
    ),
    "covers": ["Envelope schema", "Versioning", "Signing", "Streaming", "Trailers"],
    "sections": [
        section("M8-S1", "Protocol Stages", [
            {"id": "EP-01", "topic": "Envelope v0.1 spec + JSON Schema", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "EP-02", "topic": "PQC signing fields (ML-DSA)", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "EP-03", "topic": "Streaming + server-sent trailers", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "EP-04", "topic": "Tier + budget + capability headers", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "EP-05", "topic": "GACP capability ticket integration", "priority": "P1-HIGH", "phase": "P2-P3"},
            {"id": "EP-06", "topic": "Conformance suite + reference impl", "priority": "P1-HIGH", "phase": "P2-P3"},
            {"id": "EP-07", "topic": "Public RFC publication", "priority": "P2-MEDIUM", "phase": "P3"},
        ]),
        section("M8-S2", "Headers", {
            "request": ["x-crs-uuid", "x-tier", "x-tenant", "x-purpose", "x-capability-ticket", "x-pqc-sig"],
            "response": ["x-evidence-anchor", "x-judge-kappa", "x-rego-version", "x-pqc-sig"],
            "trailer": ["x-replay-checksum", "x-tokens-used", "x-cost"],
        }),
        section("M8-S3", "Versioning Strategy", {
            "semver": "v{major}.{minor}.{patch}",
            "deprecation": "Two-version overlap; sunset notice ≥ 180 days",
            "compatibility": "Backwards-compatible minor; breaking only on major; conformance suite gate",
        }),
        section("M8-S4", "Audit Properties", {
            "properties": ["Non-repudiation", "Replay-resistance (nonce)", "Determinism (seed + checksum)", "Selective disclosure (zk option)"],
        }),
        section("M8-S5", "Stakeholders", {
            "internal": ["Platform Eng", "Security", "MRM"],
            "external": ["AISI", "Treaty Secretariat", "Vendor consortium"],
        }),
    ],
})

# --- M9 — CCaaS Summarization with PETs ---
modules.append({
    "id": "M9",
    "title": "M9 — CCaaS Summarization with Privacy-Enhancing Technologies (PETs)",
    "summary": (
        "Contact-Centre-as-a-Service summarization pipeline using PETs "
        "(DP, secure aggregation, redaction, federated learning, "
        "trusted execution) — for QA, supervisor coaching and "
        "fair-value evidence under FCA Consumer Duty + GDPR."
    ),
    "covers": ["DP", "Federated", "Redaction", "TEE", "Consumer Duty"],
    "sections": [
        section("M9-S1", "Pipeline", {
            "ingest": "Encrypted call + transcript w/ ASR redaction (PII, sensitive)",
            "summarize": "On-premise small LLM or TEE-hosted; deterministic temperature",
            "evaluate": "Judge LLM + human-in-loop 1 %",
            "store": "Pseudonymous + per-jurisdiction residency; WORM evidence",
            "report": "Fair-value tiles + dispute case bundles",
        }),
        section("M9-S2", "PETs Inventory", [
            {"id": "PET-01", "topic": "Differential privacy aggregations (ε ≤ 1)", "phase": "P2"},
            {"id": "PET-02", "topic": "Secure aggregation (federated)", "phase": "P2-P3"},
            {"id": "PET-03", "topic": "TEE (SEV-SNP / TDX) for sensitive customers", "phase": "P1-P2"},
            {"id": "PET-04", "topic": "Redaction (eBPF + DLP + Presidio)", "phase": "P1"},
            {"id": "PET-05", "topic": "K-anonymity reporting bands", "phase": "P2"},
        ]),
        section("M9-S3", "Compliance Hooks", {
            "fca": "Consumer Duty fair value + foreseeable harm",
            "gdpr": "Lawful basis + DPIA + Art 22 contestation",
            "smcr": "Designated SMF for CCaaS oversight",
        }),
        section("M9-S4", "KPIs", {
            "redactionRecall": "≥ 99.5 % on golden set",
            "summaryFactuality": "≥ 0.92 (judge κ)",
            "complaintRate": "↓ 20 % over 12 months",
        }),
        section("M9-S5", "Operating Model", {
            "owners": "Head of Customer Operations + DPO + CAIO",
            "drills": "Quarterly redaction drift + DP epsilon budget review",
        }),
    ],
})

# --- M10 — Prompt Architect ---
modules.append({
    "id": "M10",
    "title": "M10 — Prompt Architect (Templating, Variable Linking, Version Control, Testing, Sharing)",
    "summary": (
        "Institutional prompt-development studio + library with "
        "templating, variable linking, version control, golden-set "
        "testing, signed publishing and cross-team sharing — aligned "
        "with refusal lattice and supervisor-readable rationale."
    ),
    "covers": ["Templating", "Variables", "VCS", "Testing", "Sharing", "Refusal lattice"],
    "sections": [
        section("M10-S1", "Capabilities", [
            {"id": "PA-01", "topic": "Templating engine (Jinja-like with safe filters)", "priority": "P1-HIGH", "phase": "P1"},
            {"id": "PA-02", "topic": "Variable linking + scoped namespaces", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "PA-03", "topic": "Version control (Git-backed; semver)", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "PA-04", "topic": "Golden-set + adversarial testing", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "PA-05", "topic": "Approval workflow + Sigstore signing", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "PA-06", "topic": "Cross-team sharing + entitlement", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "PA-07", "topic": "Refusal lattice composer", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "PA-08", "topic": "Telemetry: usage, drift, harm signal", "priority": "P2-MEDIUM", "phase": "P3"},
        ]),
        section("M10-S2", "Library Schema", {
            "fields": ["id", "version", "purpose", "tier", "audience", "tone", "constraints", "citations", "refusalLattice", "evalSet", "owner", "approvedBy", "wormAnchor"],
        }),
        section("M10-S3", "Testing Harness", {
            "sets": ["Golden", "Adversarial", "Bias", "Jailbreak", "Deception", "Hallucination"],
            "judges": "LLM-as-judge ensemble + human-in-loop sample",
            "gates": "κ ≥ 0.9 to publish; failures auto-create issue",
        }),
        section("M10-S4", "Sharing & Marketplace", {
            "internal": "Per-tribe library; entitlements via OIDC groups",
            "external": "Optional vendor share via Cert-tier-gated marketplace",
        }),
        section("M10-S5", "Owner Map", {
            "owners": "Head of AI Platform + Head of Prompt Engineering Centre of Excellence",
        }),
    ],
})

# --- M11 — Model Registry ---
modules.append({
    "id": "M11",
    "title": "M11 — Model Registry",
    "summary": (
        "Authoritative model registry with CRS-UUID lineage, signed "
        "manifests, validation reports, sector MRM tier, regulator "
        "evidence index, embedding-model awareness and external-vendor "
        "third-party tracking."
    ),
    "covers": ["Manifests", "Lineage", "Validation", "Tiering", "Evidence", "3rd party"],
    "sections": [
        section("M11-S1", "Capabilities", [
            {"id": "MR-01", "topic": "Manifest schema + signing (ML-DSA-65)", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "MR-02", "topic": "Tiering (T1/T2/T3) + SMCR owner", "priority": "P0-CRITICAL", "phase": "P1"},
            {"id": "MR-03", "topic": "Validation report attachment", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "MR-04", "topic": "Lineage edges (data, code, weights, prompts)", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "MR-05", "topic": "Third-party / API-only model wrapper", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "MR-06", "topic": "Embedding & RAG model coverage", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "MR-07", "topic": "Decommission + sunset workflow", "priority": "P1-HIGH", "phase": "P2-P3"},
            {"id": "MR-08", "topic": "Auto evidence index per regime", "priority": "P0-CRITICAL", "phase": "P2"},
        ]),
        section("M11-S2", "Integrations", {
            "ci": "CI publishes manifest on build success",
            "proxy": "Proxy reads tier + permitted action from registry",
            "mrm": "MRM validation reports linked",
            "registryBackend": "OCI artifact + JSON metadata in PG + vector index",
        }),
        section("M11-S3", "KPIs", {
            "completeness": "100 % of production models registered",
            "lineageDepth": "≥ 4 hops",
            "evidenceCoverage": "100 % of high-risk obligations linked",
        }),
        section("M11-S4", "Decommission Flow", {
            "steps": ["plan", "cutover", "shadow", "decommission", "archive", "evidence retention"],
            "sla": "Sunset complete within 90 days of plan",
        }),
        section("M11-S5", "Owner Map", {
            "owners": "Head of MRM + Head of AI Platform Engineering",
        }),
    ],
})

# --- M12 — Threat Intelligence + Telemetry & Interpretability ---
modules.append({
    "id": "M12",
    "title": "M12 — Threat-Intelligence Dashboards + Telemetry & Interpretability",
    "summary": (
        "Unified threat-intel feed (jailbreak, prompt-injection, supply "
        "chain, frontier capability) + telemetry & interpretability "
        "suite (probing, activation patching, circuits, OTel-GenAI) "
        "with SRE-grade SLOs."
    ),
    "covers": ["Threat feed", "Probing", "Activation patching", "OTel-GenAI", "SLO"],
    "sections": [
        section("M12-S1", "Workstreams", [
            {"id": "TI-01", "topic": "Threat-feed ingestion + correlation", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "TI-02", "topic": "Jailbreak / injection IOC library", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "TI-03", "topic": "Supply-chain attestation diff watcher", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "TL-01", "topic": "OTel-GenAI tracing rollout", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "TL-02", "topic": "Probing classifier farm", "priority": "P2-MEDIUM", "phase": "P3"},
            {"id": "TL-03", "topic": "Activation patching toolchain", "priority": "P2-MEDIUM", "phase": "P3-P4"},
            {"id": "TL-04", "topic": "Circuit-level interpretability lab", "priority": "P2-MEDIUM", "phase": "P3-P4"},
        ]),
        section("M12-S2", "Dashboard Tiles", {
            "tiles": ["Top jailbreak families", "Active campaigns", "Supply-chain CVE delta", "Sentinel resonance heatmap", "OTel-GenAI top traces", "Probing coverage"],
        }),
        section("M12-S3", "SLOs", {
            "tracingCoverage": "≥ 98 % of inference calls",
            "alertNoise": "≤ 5 % false-positive rate",
            "MTTD": "≤ 5 min for P0 threats",
        }),
        section("M12-S4", "Research Interlock", {
            "researchHooks": "Interp findings flow back to refusal lattice + Sentinel probes",
            "publication": "Quarterly research note to AISI + journal track",
        }),
        section("M12-S5", "Owner Map", {
            "owners": "Head of SOC + Head of AI Research + Head of Observability",
        }),
    ],
})

# --- M13 — AGI/ASI Governance Simulations ---
modules.append({
    "id": "M13",
    "title": "M13 — AGI/ASI Governance Simulations (SRASE + CSE-X)",
    "summary": (
        "Simulation engines for synthetic regulator audits (SRASE) and "
        "civilizational-scale scenarios (CSE-X) — used to pre-flight "
        "real audits and to stress-test treaty obligations + sanctions."
    ),
    "covers": ["SRASE", "CSE-X", "Personas", "Scenarios", "Composite score"],
    "sections": [
        section("M13-S1", "Workstreams", [
            {"id": "SM-01", "topic": "SRASE persona library v1", "priority": "P1-HIGH", "phase": "P1-P2"},
            {"id": "SM-02", "topic": "SRASE composite scorer (≥ 0.9 gate)", "priority": "P0-CRITICAL", "phase": "P2"},
            {"id": "SM-03", "topic": "CSE-X scenario library v1 (50 scenarios)", "priority": "P1-HIGH", "phase": "P3-P4"},
            {"id": "SM-04", "topic": "Sentinel AGI Lab integration", "priority": "P0-CRITICAL", "phase": "P2-P3"},
            {"id": "SM-05", "topic": "Adversarial break harness 10 000 attacks", "priority": "P1-HIGH", "phase": "P2-P4"},
            {"id": "SM-06", "topic": "AISI joint simulation drills", "priority": "P1-HIGH", "phase": "P3-P4"},
        ]),
        section("M13-S2", "Scoring Model", {
            "axes": ["Documentation", "Operating effectiveness", "Disclosure", "Remediation", "Constitutional conformance"],
            "gate": "Composite ≥ 0.9 before any real regulator submission",
        }),
        section("M13-S3", "Operational Use", {
            "preFlight": "SRASE run as mandatory pre-flight",
            "wargames": "Quarterly CSE-X civilizational drill (treaty-coordinated)",
            "evidence": "Per-run report + composite to WORM",
        }),
        section("M13-S4", "Research Outputs", {
            "outputs": ["Scenario library publications", "Lessons-learned papers", "Annexed proofs"],
        }),
        section("M13-S5", "Owner Map", {
            "owners": "AI Safety Lead + Treaty Liaison + Head of Internal Audit",
        }),
    ],
})

# --- M14 — Report-Generation Workflows ---
modules.append({
    "id": "M14",
    "title": "M14 — Report-Generation Workflows + Critical-Path Summary",
    "summary": (
        "Auto-assembly workflows for Annex IV, SR 11-7, FCA Consumer "
        "Duty, MAS FEAT, HKMA GL-90 and RPCO bundles; plus the WP-050 "
        "critical-path summary with cross-track dependency graph."
    ),
    "covers": ["Annex IV", "SR 11-7", "FCA", "MAS", "HKMA", "RPCO", "Critical path"],
    "sections": [
        section("M14-S1", "Report Catalogue", [
            {"id": "RP-01", "topic": "Annex IV pack auto-assembly ≤ 30 min", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "RP-02", "topic": "SR 11-7 validation pack", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "RP-03", "topic": "FCA Consumer Duty quarterly outcome report", "priority": "P0-CRITICAL", "phase": "P1-P2"},
            {"id": "RP-04", "topic": "MAS FEAT + AI Verify export", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "RP-05", "topic": "HKMA GL-90 disclosure", "priority": "P1-HIGH", "phase": "P2"},
            {"id": "RP-06", "topic": "RPCO bundle ≤ 45 min", "priority": "P0-CRITICAL", "phase": "P2-P3"},
            {"id": "RP-07", "topic": "Board KPI tile auto-generation", "priority": "P0-CRITICAL", "phase": "P0-P1"},
            {"id": "RP-08", "topic": "Treaty annex submission pipeline", "priority": "P1-HIGH", "phase": "P3"},
        ]),
        section("M14-S2", "Critical-Path Dependency Map (excerpt)", {
            "CP-01 → CP-04 → CP-06 → CP-12 → RP-07": "Kill-switch + WORM + Sentinel + Dashboards + Board tile",
            "CP-02 → CP-08 → CP-09 → RP-01": "Sigstore + Proxies + Registry + Annex IV pack",
            "CP-03 → CP-11 → RP-03": "OPA + RAG + Consumer Duty report",
            "CP-14 → CP-15 → RP-08": "Sims + GACP + Treaty annex",
            "CP-16 → UI-08": "zk-SNARK + Transparency Portal",
            "CP-17 → RP-06": "Replay harness + RPCO",
        }),
        section("M14-S3", "Format & Signing", {
            "format": "PDF/A + JSON bundle",
            "signing": "PAdES + Sigstore + ML-DSA-65",
            "anchor": "WORM daily Merkle + zk-SNARK proof",
        }),
        section("M14-S4", "Acceptance Gates", {
            "p0": "Kill-switch drill ≤ 60 s; WORM emit ≤ 5 s; OPA p99 ≤ 4 ms",
            "p1": "Annex IV ≤ 30 min; SR 11-7 pack signed; Board tile live",
            "p2": "SRASE ≥ 0.9; Registry 100 %; CCaaS PET pilot",
            "p3": "GACP federation + zk verifier; Cert Gold",
            "p4": "Treaty maturity; Cert Platinum",
        }),
        section("M14-S5", "Open Risks & Mitigations", {
            "risks": [
                "PQC HSM supply lead time — pre-order Q4 2025",
                "AISI inspection availability — schedule rolling",
                "Vendor LLM SLA volatility — multi-vendor + fallback",
                "Talent constraint on interpretability — research grants + university partnership",
                "Treaty politics — neutral secretariat + multi-track diplomacy",
            ],
        }),
    ],
})

# ---------------------- schemas ----------------------
schemas = [
    {"id": "phaseGate", "fields": ["phaseId", "windowDays", "entryCriteria", "exitCriteria", "owner", "evidenceRefs"]},
    {"id": "workItem", "fields": ["id", "track", "title", "priority", "phase", "owner", "dependsOn", "kpis", "evidence"]},
    {"id": "criticalPathNode", "fields": ["id", "title", "predecessor", "successor", "slackDays", "owner"]},
    {"id": "dependencyEdge", "fields": ["from", "to", "type", "blocking", "notes"]},
    {"id": "researchHypothesis", "fields": ["id", "topic", "hypothesis", "method", "dataset", "owner", "outputs"]},
    {"id": "policyArtifact", "fields": ["id", "title", "stage", "stakeholders", "ratifiedBy", "wormAnchor"]},
    {"id": "uiComponent", "fields": ["id", "name", "scope", "api", "owner", "storybookId", "e2eId"]},
    {"id": "reportTemplate", "fields": ["id", "regime", "sections", "format", "signing", "sla"]},
    {"id": "kpiBinding", "fields": ["kpiId", "owner", "target", "evidenceQuery", "wormAnchor"]},
    {"id": "riskRow", "fields": ["id", "risk", "likelihood", "impact", "mitigation", "owner", "review"]},
    {"id": "trackBacklog", "fields": ["track", "p0Items", "p1Items", "p2Items", "p3Items", "p4Items"]},
    {"id": "okrRollup", "fields": ["quarter", "tribe", "objectives", "keyResults", "owner", "evidence"]},
]

# ---------------------- code examples ----------------------
code = [
    {"id": "C1", "title": "PMO phase-gate JSON (excerpt)", "lang": "json", "snippet": "{\n  \"phaseId\": \"P0\",\n  \"windowDays\": 30,\n  \"entryCriteria\": [\"AIMS scope signed\", \"Budget approved\"],\n  \"exitCriteria\": [\"Kill-switch drill <=60s\", \"WORM live\", \"OPA bundle signed\"],\n  \"owner\": \"PMO + CAIO\"\n}\n"},
    {"id": "C2", "title": "Dependency graph (Python — topological sort)", "lang": "python", "snippet": "from collections import defaultdict, deque\n\ndef topo(items, edges):\n    indeg = defaultdict(int); g = defaultdict(list)\n    for a,b in edges:\n        g[a].append(b); indeg[b] += 1\n    q = deque([x for x in items if indeg[x]==0])\n    out = []\n    while q:\n        n = q.popleft(); out.append(n)\n        for m in g[n]:\n            indeg[m]-=1\n            if indeg[m]==0: q.append(m)\n    return out\n"},
    {"id": "C3", "title": "Critical-path computation (CPM, networkx)", "lang": "python", "snippet": "import networkx as nx\nG = nx.DiGraph()\nfor wi in work_items:\n    G.add_node(wi['id'], duration=wi['days'])\nfor e in edges:\n    G.add_edge(e['from'], e['to'])\n# longest path = critical path on DAG of durations\ncp = nx.dag_longest_path(G, weight='duration')\nprint('Critical path:', cp)\n"},
    {"id": "C4", "title": "Phase-gate Rego policy (admission for next phase)", "lang": "rego", "snippet": "package pmo.phase_gate\n\ndefault allow := false\n\nallow if {\n  input.phase == \"P1\"\n  data.kpis[\"killSwitchSeconds\"] <= 60\n  data.kpis[\"opaP99Ms\"] <= 4\n  data.evidence[\"wormLive\"] == true\n}\n"},
    {"id": "C5", "title": "Prompt Architect template (Jinja-safe)", "lang": "jinja", "snippet": "# system\nYou are a {{tier}} fiduciary advisor governed by Codex v{{codex_version}}.\nObjective: {{objective}}\nConstraints: {{constraints|join(', ')}}\nIf uncertainty > {{u_max}}: ask one clarifying question.\nNever disclose PII or proprietary internals.\n# user\n{{user_input}}\n"},
    {"id": "C6", "title": "Model registry manifest (YAML)", "lang": "yaml", "snippet": "id: model.advisor.v3.2.1\ntier: T1\nowner: SMF24\nframework: pytorch\nweights: oci://reg/model/advisor@sha256:...\ntrainingDataLineage: [crs:dataset:advisor-2026Q1]\nvalidationReports: [crs:val:advisor-v3.2.1]\nregimes: [SR-11-7, EU-AI-Act, FCA-Consumer-Duty]\nsig: ML-DSA-65:...\n"},
    {"id": "C7", "title": "EAIP envelope JSON Schema (excerpt)", "lang": "json", "snippet": "{\n  \"$id\": \"https://example.com/eaip/v0.1/envelope.json\",\n  \"type\": \"object\",\n  \"required\": [\"crsUuid\",\"tier\",\"purpose\",\"pqcSig\"],\n  \"properties\": {\n    \"crsUuid\": {\"type\":\"string\"},\n    \"tier\": {\"enum\":[\"T1\",\"T2\",\"T3\"]},\n    \"purpose\": {\"type\":\"string\"},\n    \"capabilityTicket\": {\"type\":\"string\"},\n    \"pqcSig\": {\"type\":\"string\"}\n  }\n}\n"},
    {"id": "C8", "title": "CCaaS DP aggregator (Opacus-style)", "lang": "python", "snippet": "from opacus import PrivacyEngine\nprivacy = PrivacyEngine()\nmodel, optim, loader = privacy.make_private(\n    module=model, optimizer=optim, data_loader=loader,\n    noise_multiplier=1.1, max_grad_norm=1.0,\n)\nepsilon = privacy.get_epsilon(delta=1e-5)\nassert epsilon <= 1.0\n"},
    {"id": "C9", "title": "OPA Gatekeeper constraint — require manifest", "lang": "yaml", "snippet": "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sRequireModelManifest\nmetadata: { name: registry-required }\nspec:\n  match: { kinds: [{ apiGroups: [\"\"], kinds: [\"Pod\"] }] }\n  parameters:\n    annotation: model.registry/manifest\n    requireSig: true\n"},
    {"id": "C10", "title": "GitHub Actions — phase-gate evaluation job", "lang": "yaml", "snippet": "name: phase-gate\non: workflow_dispatch\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pip install -r ci/requirements.txt\n      - run: python ci/eval_phase_gate.py --phase P1\n      - run: python ci/sign_envelope.py --kind phase-gate --phase P1\n"},
    {"id": "C11", "title": "Threat-intel ingestion (Python)", "lang": "python", "snippet": "import httpx, json\nFEEDS = ['https://aisi.example/feed', 'https://misp.local/feed']\ndef ingest():\n    for url in FEEDS:\n        r = httpx.get(url, timeout=10)\n        for ioc in r.json().get('iocs', []):\n            kafka.produce('gov.ti.v1', value=json.dumps(ioc).encode())\n"},
    {"id": "C12", "title": "Interp — activation patching skeleton (transformer_lens)", "lang": "python", "snippet": "from transformer_lens import HookedTransformer\nmodel = HookedTransformer.from_pretrained('gpt2-small')\n_, cache = model.run_with_cache('safe prompt')\n# patch layer N residual stream with cached activations to probe causal effect\n"},
    {"id": "C13", "title": "SRASE composite scorer (Python)", "lang": "python", "snippet": "def composite(d):\n    weights = {'docs':.2,'opEff':.3,'disclosure':.2,'remed':.15,'const':.15}\n    score = sum(d[k]*w for k,w in weights.items())\n    assert 0 <= score <= 1\n    return score\n"},
    {"id": "C14", "title": "Annex IV pack assembler (Python)", "lang": "python", "snippet": "def assemble_annex_iv(model_id):\n    bundle = {\n        'modelManifest': registry.get(model_id),\n        'validation': mrm.reports(model_id),\n        'drift': sentinel.last_window(model_id),\n        'lineage': lineage.traverse(model_id, depth=4),\n        'evidenceAnchors': worm.anchors(model_id, days=90),\n    }\n    return sign_pades_ml_dsa(bundle)\n"},
    {"id": "C15", "title": "OKR rollup query (SQL)", "lang": "sql", "snippet": "SELECT tribe, quarter,\n       jsonb_agg(jsonb_build_object('o',objective,'kr',key_results,'pct',progress_pct)) AS okrs\nFROM okrs\nWHERE quarter = '2026Q2'\nGROUP BY tribe, quarter\nORDER BY tribe;\n"},
    {"id": "C16", "title": "Mermaid — phase / track Gantt", "lang": "mermaid", "snippet": "gantt\n  title WP-050 Phases\n  dateFormat  YYYY-MM-DD\n  section RefArch\n  P0 Foundations :p0a, 2026-01-01, 30d\n  P1 Sidecars   :p1a, after p0a, 60d\n  section Safety\n  P0-P2 Alignment :p0b, 2026-01-01, 180d\n  section Civilizational\n  P3-P4 Treaty   :p3a, 2026-07-01, 1095d\n"},
]

# ---------------------- case studies ----------------------
cases = [
    {"id": "CS-01", "name": "G-SIB cuts Annex IV pack time from 14 days to 28 min", "outcomes": "WP-050 sequenced critical path (CP-02→CP-08→CP-09→RP-01); auto-assembly hit ≤ 30 min by Day 120; passed EU AI Act audit with 0 major NCs."},
    {"id": "CS-02", "name": "Multi-vendor LLM-judge ensemble eliminates regression escapes", "outcomes": "SC-09 ensemble (3 vendors) gating PRs; κ ≥ 0.92 sustained; regression escape rate dropped 78 % within 90 days."},
    {"id": "CS-03", "name": "Prompt Architect adoption across 11 business units", "outcomes": "PA-01..PA-08 GA by Day 150; 4 800 templates versioned; refusal-lattice coverage 100 % Tier-1; complaint rate -22 %."},
    {"id": "CS-04", "name": "RAG taint propagation neutralises poisoned-corpus attack", "outcomes": "RG-05 + RG-07 detected indirect injection from compromised supplier feed; quarantined 2 600 chunks; zero customer impact."},
    {"id": "CS-05", "name": "SRASE pre-flight saves G-SIFI a SEV-1 supervisor finding", "outcomes": "SM-02 composite 0.86 below gate; CAPA closed in 9 days; real audit pass with merit comment."},
    {"id": "CS-06", "name": "Treaty annex pipeline + zk-SNARK verifier go live", "outcomes": "RP-08 + CP-16 GA by P3; 11 monthly attestations signed PQC; Cert Gold achieved Q3-2027."},
]

# ---------------------- KPIs ----------------------
kpis = [
    {"id": "K-01", "name": "Phase-gate exit on time", "target": "100 % for P0; ≥ 90 % for P1-P3"},
    {"id": "K-02", "name": "Critical-path slip", "target": "≤ 7 days per phase"},
    {"id": "K-03", "name": "Annex IV pack assembly", "target": "≤ 30 min"},
    {"id": "K-04", "name": "RPCO reconstruction", "target": "≤ 45 min"},
    {"id": "K-05", "name": "Kill-switch logical p95", "target": "≤ 60 s"},
    {"id": "K-06", "name": "OPA sidecar p99", "target": "≤ 4 ms"},
    {"id": "K-07", "name": "Proxy overhead p95", "target": "≤ 25 ms"},
    {"id": "K-08", "name": "WORM replay diff", "target": "= 0"},
    {"id": "K-09", "name": "Judge κ", "target": "≥ 0.9"},
    {"id": "K-10", "name": "Fiduciary cosine", "target": "≥ 0.92"},
    {"id": "K-11", "name": "Deception detection recall", "target": "≥ 0.95"},
    {"id": "K-12", "name": "Prompt-injection block rate", "target": "≥ 99.9 %"},
    {"id": "K-13", "name": "RAG retrieval precision (golden)", "target": "≥ 0.85"},
    {"id": "K-14", "name": "Model-registry completeness", "target": "100 %"},
    {"id": "K-15", "name": "OTel-GenAI tracing coverage", "target": "≥ 98 %"},
    {"id": "K-16", "name": "SRASE composite", "target": "≥ 0.9"},
    {"id": "K-17", "name": "GACP handshake p95", "target": "≤ 5 s"},
    {"id": "K-18", "name": "GACRLS revocation p95 global", "target": "≤ 10 s"},
    {"id": "K-19", "name": "PQC KMS rotation cadence", "target": "≤ 90 d"},
    {"id": "K-20", "name": "zk-SNARK verifier uptime", "target": "≥ 99.95 %"},
    {"id": "K-21", "name": "Cert score (treaty)", "target": "Gold by 2027; Platinum by 2029"},
    {"id": "K-22", "name": "Board AI literacy completion", "target": "≥ 95 %"},
    {"id": "K-23", "name": "Research paper output", "target": "≥ 4/yr peer-reviewed"},
    {"id": "K-24", "name": "Treaty obligation attestation", "target": "100 % monthly"},
]

# ---------------------- risk-control matrix ----------------------
riskControlMatrix = [
    {"id": "R-01", "threat": "Critical-path slip on Sigstore + PQC chain", "controls": ["Vendor pre-engagement", "Parallel classical fallback", "Phase-gate Rego"], "kpis": ["K-01", "K-02"]},
    {"id": "R-02", "threat": "Talent shortage in interpretability", "controls": ["University partnership", "Sentinel Lab fellowships", "Contracted experts"], "kpis": ["K-23"]},
    {"id": "R-03", "threat": "Vendor LLM SLA volatility", "controls": ["Multi-vendor + fallback", "Judge ensemble", "Local small-LLM"], "kpis": ["K-09", "K-15"]},
    {"id": "R-04", "threat": "Treaty ratification delay", "controls": ["Multi-track diplomacy", "Bilateral overlays", "OECD adoption path"], "kpis": ["K-21", "K-24"]},
    {"id": "R-05", "threat": "Phase-gate overload of PMO", "controls": ["Automation in Rego", "WORM-backed evidence query", "Quarterly reviews"], "kpis": ["K-01"]},
    {"id": "R-06", "threat": "RAG corpus poisoning supply attack", "controls": ["Source attestation", "Taint propagation", "Quarantine workflow"], "kpis": ["K-12", "K-13"]},
    {"id": "R-07", "threat": "Prompt Architect template sprawl", "controls": ["Semver + approval workflow", "Telemetry deprecation", "Marketplace policy"], "kpis": ["K-09", "K-12"]},
    {"id": "R-08", "threat": "Registry gaps for 3rd-party models", "controls": ["API-only wrapper", "Vendor attestation", "Gatekeeper enforcement"], "kpis": ["K-14"]},
    {"id": "R-09", "threat": "Interpretability research stagnation", "controls": ["External grants", "Quarterly research review", "Tooling investment"], "kpis": ["K-11", "K-23"]},
    {"id": "R-10", "threat": "Threat-intel false-positive overload", "controls": ["Correlation + dedup", "SLO alert noise budget", "Auto triage"], "kpis": ["K-15"]},
    {"id": "R-11", "threat": "Civilizational sim drift from reality", "controls": ["AISI joint scenarios", "Annual scenario refresh", "Independent assurance"], "kpis": ["K-16", "K-24"]},
    {"id": "R-12", "threat": "Report-generation correctness regressions", "controls": ["Golden-set tests", "PAdES + ML-DSA-65 signing", "Replay diff = 0"], "kpis": ["K-03", "K-04", "K-08"]},
]

# ---------------------- traceability ----------------------
traceability = [
    {"feature": "M1 Phases + critical path", "control": "Phase-gate Rego + dep graph", "regimes": ["ISO 42001 Cl 6/9", "NIST RMF Govern"]},
    {"feature": "M2 AI Safety research", "control": "Hypothesis register + AISI joint", "regimes": ["EO 14110", "EU AI Act Art 55", "OECD AI Principles"]},
    {"feature": "M3 Global governance policy", "control": "Treaty + Codex + Cert + ICGC", "regimes": ["Council of Europe AI Convention", "G7 Hiroshima", "FSB"]},
    {"feature": "M4 Reference architecture", "control": "Terraform + EKS + Cilium + Kata", "regimes": ["EU AI Act Art 12/15", "DORA", "ISO 27001"]},
    {"feature": "M5 Governance dashboards", "control": "Board tile + MRM + kill-switch + portals", "regimes": ["FCA Consumer Duty", "EU AI Act Art 13", "ISO 42001 Cl 7.4"]},
    {"feature": "M6 Security + DevSecOps", "control": "Sigstore + OPA + zero-egress + WORM + judge", "regimes": ["SLSA L3+", "EU AI Act Art 15", "GDPR Art 32"]},
    {"feature": "M7 RAG governance", "control": "ACL + residency + taint + lineage", "regimes": ["GDPR Arts 5/6/32", "EU AI Act Art 10"]},
    {"feature": "M8 EAIP protocol", "control": "Envelope + signing + capability ticket", "regimes": ["EU AI Act Art 12", "FIPS 203/204"]},
    {"feature": "M9 CCaaS + PETs", "control": "DP + redaction + TEE + WORM", "regimes": ["FCA Consumer Duty", "GDPR Arts 6/22/25/32"]},
    {"feature": "M10 Prompt Architect", "control": "Templating + VCS + tests + refusal lattice", "regimes": ["EU AI Act Art 13", "FCA Consumer Duty", "GDPR Art 22"]},
    {"feature": "M11 Model registry", "control": "Manifest + lineage + tiering + evidence", "regimes": ["SR 11-7", "EU AI Act Annex IV", "PRA SS1/23"]},
    {"feature": "M12 Threat-intel + interp + telemetry", "control": "Feed + probes + OTel + lab", "regimes": ["NIST GAI Profile", "EU AI Act Art 15", "ISO 27001"]},
    {"feature": "M13 AGI/ASI sims", "control": "SRASE + CSE-X + AGI Lab + harness", "regimes": ["EU AI Act Art 55", "Treaty Annex", "EO 14110"]},
    {"feature": "M14 Report workflows", "control": "Auto pack + PAdES + zk + WORM", "regimes": ["EU AI Act Annex IV", "SR 11-7", "FCA Consumer Duty", "MAS FEAT", "HKMA GL-90", "DORA"]},
]

# ---------------------- data flows ----------------------
dataFlows = [
    {"id": "DF-01", "name": "Phase-gate evaluation", "steps": ["collect KPIs", "Rego eval", "evidence sign", "WORM emit", "PMO board"], "controls": ["Rego unit tests", "ML-DSA-44", "Object Lock"]},
    {"id": "DF-02", "name": "Dependency graph build + critical path", "steps": ["import work items", "edges + durations", "topo sort", "CPM longest path", "publish to dashboard"], "controls": ["DAG validation", "Versioned snapshots"]},
    {"id": "DF-03", "name": "Annex IV auto-pack", "steps": ["registry pull", "MRM reports", "drift window", "lineage traverse", "WORM anchors", "PAdES + PQC sign"], "controls": ["≤ 30 min SLA", "Replay diff = 0"]},
    {"id": "DF-04", "name": "Prompt Architect publish", "steps": ["author", "test golden+adversarial", "judge κ", "approve", "Sigstore sign", "WORM anchor"], "controls": ["κ ≥ 0.9", "Approval workflow"]},
    {"id": "DF-05", "name": "RAG corpus ingestion", "steps": ["attest source", "scan", "redact PII", "chunk", "embed", "ACL apply", "lineage emit"], "controls": ["DLP", "Vector ACL", "CRS-UUID per chunk"]},
    {"id": "DF-06", "name": "Civilizational simulation drill", "steps": ["scenario load", "personas run", "composite score", "report sign", "AISI share", "treaty annex"], "controls": ["≥ 0.9 gate", "PQC sign", "Independent assurance"]},
]

# ---------------------- regulators ----------------------
regulators = [
    {"id": "REG-01", "name": "EU Commission AI Office + EU AISI", "primary": "EU AI Act + frontier safety"},
    {"id": "REG-02", "name": "ECB-SSM + EBA + ESMA", "primary": "EU prudential + markets"},
    {"id": "REG-03", "name": "PRA + Bank of England", "primary": "UK prudential"},
    {"id": "REG-04", "name": "FCA", "primary": "UK conduct + Consumer Duty + SMCR"},
    {"id": "REG-05", "name": "FRB + OCC + FDIC + CFPB", "primary": "US prudential + consumer"},
    {"id": "REG-06", "name": "SEC + CFTC + FINRA", "primary": "US markets + broker-dealer"},
    {"id": "REG-07", "name": "MAS", "primary": "Singapore + FEAT + AI Verify"},
    {"id": "REG-08", "name": "HKMA + SFC", "primary": "Hong Kong"},
    {"id": "REG-09", "name": "AISI (US, UK, EU, SG, JP)", "primary": "Frontier model safety"},
    {"id": "REG-10", "name": "ISO 42001 certification body", "primary": "AIMS certification"},
    {"id": "REG-11", "name": "OECD + FSB + BIS", "primary": "International coordination"},
    {"id": "REG-12", "name": "Treaty Secretariat + UN", "primary": "Civilizational treaty"},
]

# ---------------------- workshops ----------------------
workshops = [
    {"id": "WS-01", "audience": "Board AI/Risk Cmte", "duration": "2 h", "outcome": "Sign-off WP-050 phasing + budget envelope + Cert plan"},
    {"id": "WS-02", "audience": "C-Suite + SMFs + PMO", "duration": "1 d", "outcome": "Phase-gate operating model + OKR rollup + risk register"},
    {"id": "WS-03", "audience": "AI Research + AI Safety", "duration": "2 d", "outcome": "Research hypotheses + interp roadmap + AISI joint plan"},
    {"id": "WS-04", "audience": "Platform Eng + EA + Security", "duration": "2 d", "outcome": "Reference architecture rollout + DevSecOps pipeline"},
    {"id": "WS-05", "audience": "MRM + 2LoD + Compliance", "duration": "1 d", "outcome": "Model registry + Annex IV + SR 11-7 pack drills"},
    {"id": "WS-06", "audience": "UX + Frontend + Backend", "duration": "1 d", "outcome": "Dashboard catalogue + design system + API contracts"},
    {"id": "WS-07", "audience": "Treaty Liaison + AISI + Supervisor", "duration": "1 d", "outcome": "GIEN + Cert + sanctions ladder + Annex pipeline"},
]

# ---------------------- privacy ----------------------
privacy = {
    "lawfulBasis": ["Legal obligation (Art 6(1)(c))", "Legitimate interest (Art 6(1)(f))", "Contract (Art 6(1)(b))"],
    "subjectRights": ["DSAR portal", "Art 17 erasure (machine unlearning)", "Art 22 contestation with meaningful info"],
    "dataMinimization": ["DP aggregations", "Secure aggregation", "Federated", "TEE", "eBPF redaction", "K-anonymity bands"],
    "transfers": "Per-jurisdiction residency; SCCs + supplementary measures; treaty mutual recognition",
    "dpia": "Mandatory for high-risk (credit, advice, fraud, AML, CCaaS, frontier evals, agent federation)",
    "securityControls": ["zero-trust mTLS", "FIPS 204 PQC", "FIPS 140-3 L4 HSM", "WORM Object Lock", "SLSA L3+", "Kata confidential", "Constitutional kernel"],
}

# ---------------------- deployment ----------------------
deployment = [
    "Multi-region active-active EU primary; DR with RPO ≤ 1 h, RTO ≤ 4 h",
    "Kata Containers for Tier-1 + SEV-SNP / TDX where available",
    "Cilium L7 zero-egress; egress-broker allow-list for GIEN + Global Audit API + ICGC",
    "OPA Gatekeeper + Kyverno enforcing signed images (Cosign + ML-DSA-44) + Kata + required tags + registry annotation",
    "Kafka/MSK WORM with SASL/SCRAM + mTLS ACL + Object Lock + daily Merkle anchor + PQC envelopes",
    "FIPS 140-3 L4 PQC HSM; 90-day rotation; hybrid ML-DSA/Ed25519 + ML-KEM/X25519",
    "BMC/IPMI segmentation; Redfish event subscription to SOC + WORM",
    "GitHub Actions OIDC + Sigstore keyless + ML-DSA-44 hybrid + SLSA L3+ provenance + LLM-judge ensemble",
    "Terraform golden modules signed (Sigstore); mandatory tags (owner, tier, dataClass, regime, crsUuid)",
    "OpenTelemetry GenAI tracing + Falco eBPF + Trivy + Grype + kube-bench",
    "Quarterly chaos drills: kill-switch, KMS outage, region failover, partition, ASI honeypot, hotline",
    "Public verifier endpoints (zk-SNARK) for civil society + press",
    "GACP/GACRLS/GACRA brokers in DMZ with strict ingress + mTLS + PQC sig",
    "RPCO replay harness + Evidence Vault in per-incident bucket with break-glass + dual-control",
    "Constitutional kernel runtime on every Tier-1 pod (DaemonSet + sidecar) fail-closed",
    "PMO dependency graph and OKR rollup auto-published nightly with signed manifest",
]

# ---------------------- 30/60/90 rollout ----------------------
rollout90 = [
    {"day": "0-30", "track": "P0 Foundations & Guardrails", "items": ["Kill-switch drill ≤ 60 s", "WORM cluster + daily Merkle", "OPA bundle signed + Gatekeeper enforce", "PQC KMS + HSM", "Phase-gate Rego + PMO dep graph"]},
    {"day": "31-60", "track": "P1 RefArch + Dashboards Alpha", "items": ["OPA sidecar GA", "FastAPI + Node proxies", "Sentinel resonance live view", "Board KPI tile alpha", "Prompt Architect MVP", "RAG governance v1"]},
    {"day": "61-90", "track": "P1 Reports + Registry seed", "items": ["Annex IV auto-pack alpha", "SR 11-7 pack signed", "Model registry seed (Tier-1)", "MRM dashboard alpha", "Threat-intel feed wiring"]},
]

# ---------------------- multi-year roadmap ----------------------
roadmap = [
    {"year": "2026", "focus": "P0-P2 Foundations + RefArch + Registry + Dashboards", "milestones": ["Annex IV pack ≤ 30 min", "Kill-switch p95 ≤ 60 s", "Model registry GA", "Prompt Architect GA", "Cert Silver"]},
    {"year": "2027", "focus": "P3 Federation + Verifier + Sims", "milestones": ["GACP/GACRLS/GACRA live", "zk-SNARK verifier portal", "SRASE composite ≥ 0.9 sustained", "Cert Gold"]},
    {"year": "2028", "focus": "Civilizational Operations Steady-State", "milestones": ["CSE-X 30+ scenarios", "Codex v1 ratified", "Deception recall ≥ 0.97", "RPCO ≤ 30 min"]},
    {"year": "2029", "focus": "Maturity + Research Outputs", "milestones": ["Cert Platinum", "Interp coverage ≥ 60 % Tier-1", "Public verifier 1M+ proofs/yr"]},
    {"year": "2030", "focus": "Treaty Maturity + Constitutional Review", "milestones": ["Treaty near-universal accession", "Constitutional review contribution", "F500/G-SIFI reference adoption"]},
]

# ---------------------- evidence pack ----------------------
evidencePack = {
    "id": "EVP-WP-050",
    "sections": [
        "Phase-gate Rego results + PMO dep graph snapshot",
        "Critical-path computation + slack analysis",
        "OKR rollup per quarter (signed)",
        "Risk register + mitigation status",
        "Workshop attendance + outcomes",
        "Research backlog + paper submissions",
        "Policy ratification chain",
        "Architecture attestations (Terraform + EKS + WORM + PQC)",
        "Dashboard go-live evidence (Storybook + E2E)",
        "Registry completeness audit",
        "Report-generation SLA proofs",
        "Treaty annex submission chain (PQC-signed)",
    ],
    "audiences": ["Board", "PMO", "AI Research", "Engineering Leadership", "Internal Audit", "Supervisors", "AISI", "Treaty Secretariat"],
    "format": "PDF/A + JSON bundle",
    "signing": "PAdES + Sigstore + ML-DSA-65",
    "anchor": "WORM daily Merkle + zk-SNARK proof to public verifier",
    "sla": "≤ 45 min assembly",
}

# ---------------------- executive summary ----------------------
executiveSummary = {
    "purpose": (
        "Deliver a prioritized, phased implementation and research plan "
        "that synthesizes WP-035..WP-049 into a single PMO-grade roadmap "
        "covering AI safety research, global governance policy design, "
        "Enterprise AI reference architecture, governance dashboards, "
        "security & DevSecOps (Sigstore, OPA, zero-egress K8s, WORM), "
        "RAG program governance, EAIP protocol design, CCaaS "
        "summarization with PETs, Prompt Architect, model registry, "
        "threat-intelligence dashboards, telemetry & interpretability, "
        "AGI/ASI governance simulations, and report-generation "
        "workflows — with critical path, dependencies, KPIs, and OKR "
        "rollup."
    ),
    "approach": (
        "14 modules grouping 56 work items across 14 tracks into 5 "
        "phases (P0..P4) over 30/90/180/365/1825 days. 17 critical-path "
        "items and 72 dependencies are computed and exposed as a Rego-"
        "enforceable phase-gate. Every artefact is signed Sigstore + "
        "ML-DSA-44/65, anchored to WORM, and traceable to ISO 42001 + "
        "EU AI Act + NIST AI RMF + SR 11-7 + Basel III + GDPR + "
        "treaty obligations. The plan is consumed by the PMO planner, "
        "OKR rollup, dependency graph engine, OPA admission, and "
        "supervisor evidence packs."
    ),
    "deliverables": (
        "14 modules · 70 sections · 12 schemas · 16 code examples · 6 "
        "case studies · 24 KPIs · 12 risk-control rows · 12 regulators "
        "· 7 workshops · 6 data flows · 14 traceability rows · 3-phase "
        "30/60/90 · 5-year roadmap · machine-parsable <directive> "
        "block · evidence-pack template · 17 critical-path items · "
        "72 dependency edges · 56 work items · 14 tracks · 5 phases."
    ),
    "outcomes": [
        "Phase-gate exit on time 100 % for P0, ≥ 90 % for P1-P3",
        "Annex IV pack auto-assembly ≤ 30 min by Day 120",
        "Kill-switch logical p95 ≤ 60 s; BMC ≤ 5 min",
        "OPA sidecar p99 ≤ 4 ms; proxy overhead p95 ≤ 25 ms",
        "Model registry completeness 100 % production",
        "Prompt Architect GA with refusal-lattice coverage 100 % Tier-1",
        "SRASE composite ≥ 0.9 sustained before any real audit",
        "Cert score Gold by 2027 and Platinum by 2029",
        "Treaty obligation attestation 100 % monthly",
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
