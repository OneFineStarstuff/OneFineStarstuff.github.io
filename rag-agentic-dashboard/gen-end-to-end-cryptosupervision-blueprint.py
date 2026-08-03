#!/usr/bin/env python3
"""
WP-060: End-to-End 2026-2030 Enterprise & Civilizational AI Governance
and Cryptographic Supervision Blueprint for G-SIFIs and Global Financial Institutions.

Six-pillar synthesis:
  P1 — Institutional-grade AI governance & control platform on K8s+Kafka+OPA
       (Governance sidecars, Kafka WORM audit, CI/CD governance, OPA/Rego,
        Governance Hub UI/API, GitOps, GQL+sGQL, ARRE, ARE)
  P2 — Sentinel Enterprise AI Governance & AGI Containment Stack
       (AIMS+MRM, AWS/EKS Terraform, TLA+ MGK, Global Codex,
        Cognitive Resonance & Deterministic Telemetry, OPA sanctions,
        Synthetic Regulator Audit Sim, GIEN, EpistemicAlignmentVerifier,
        Adversarial Testing, Systemic-Risk, Zero-Trust)
  P3 — 2026-2030 AI Governance Blueprint for Global FIs
       (EU AI Act+NIST+ISO 42001+Basel+SR 11-7+NIS2+FCA+MAS/HKMA,
        Sentinel monitoring, WorkflowAI orchestration, MRM, RedTeam, roadmap)
  P4 — Enterprise AI Architecture for Prompt Management & Reporting App
       (Prompt engineering governance, enterprise AI strategy, agent
        interoperability, AGI/ASI safety reports, product/UX backlog)
  P5 — Regulator-Grade Multi-Layer AI Governance & Cryptographic Supervision
       (Multi-framework crosswalks, OPA/Rego+JSON-LD libraries, K8s+Kafka+OPA,
        CAS + CAS-SPP, SR-DSL -> Rego+WASM+zk-circuits, meta-governance)
  P6 — Sentinel AI v2.4 & WorkflowAI Pro G-SIFI Deployment Architecture
       (Docker/K8s/Terraform, PQC WORM, RedTeam suites, dashboards,
        Autonomous trading agents + guardrails, zero-trust networking,
        systemic-risk telemetry, containment breach response,
        cryptographic provenance, CI/CD+DevSecOps, AutonomousAgentFleet,
        SIEM/SOAR, global systemic risk registry, QKD telemetry,
        sovereign AI failover, regulator audit gateway, production best
        practices)
"""
import json, os

OUT = os.path.join(os.path.dirname(__file__), "data", "end-to-end-cryptosupervision-blueprint.json")

DOC = {
    "docRef": "END-TO-END-CRYPTOSUPERVISION-BLUEPRINT-WP-060",
    "version": "1.0.0",
    "title": "End-to-End 2026-2030 Enterprise & Civilizational AI Governance and Cryptographic Supervision Blueprint for G-SIFIs and Global Financial Institutions",
    "horizon": "2026-2030+",
    "apiPrefix": "/api/end-to-end-cryptosupervision-blueprint",
    "buildsOn": ["WP-035", "WP-040", "WP-045", "WP-050", "WP-054", "WP-055", "WP-056", "WP-057", "WP-058", "WP-059"],
    "status": "regulator-submission-grade-six-pillar-synthesis",
    "classification": "Confidential / Restricted — Board, CRO, CCO, CISO, CDAO, Group Internal Audit, External Regulators (on request), Cryptographic Supervisory Authorities",
    "directive": {
        "scope": "Six-pillar end-to-end synthesis: (P1) Institutional AI governance/control platform on K8s+Kafka+OPA with Governance Hub, GQL/sGQL, ARRE, ARE; (P2) Sentinel Enterprise AGI Containment Stack with TLA+ MGK, Cognitive Resonance Engine, GIEN, EpistemicAlignmentVerifier; (P3) 2026-2030 multi-regime FI blueprint; (P4) Prompt management/reporting product architecture with agent interoperability; (P5) Cryptographic supervision with CAS, CAS-SPP, SR-DSL compiling to Rego/WASM/zk; (P6) Sentinel v2.4 + WorkflowAI Pro G-SIFI deployment with PQC WORM, autonomous agents, QKD, sovereign failover, regulator audit gateway",
        "outcomes": [
            "AI Governance Platform (Sidecars+Hub+GQL+sGQL+ARRE+ARE) live across all Tier-1/2 systems by 2027",
            "Sentinel Enterprise AGI Containment Stack with TLA+ MGK + Cognitive Resonance + GIEN operational by 2027",
            "28-regime regulatory compliance mapping + automated reporting (ARRE) to all 19 regulators",
            "Prompt management & reporting application productionized with agent interoperability (A2A/MCP/ACP) by 2026Q4",
            "CAS + CAS-SPP cryptographic supervisory proof protocol issuing zk-attestations to regulators by 2028",
            "SR-DSL compiler emitting Rego + WASM + zk-circuits with bidirectional traceability to regulations",
            "Sentinel AI v2.4 + WorkflowAI Pro G-SIFI deployment with PQC WORM archives at 99.999% durability",
            "AutonomousAgentFleet (trading + ops + governance) with bounded actuation + kill-switches",
            "QKD-backed telemetry between core data centers + sovereign AI failover across 3 jurisdictions",
            "Regulator Audit Gateway exposing read-only zk-verifiable views to AISI/EU AI Office/Fed/PRA/MAS/HKMA",
            "Global Systemic Risk Registry federated across G-SIFI peers + central banks + AISIs",
            "SIEM/SOAR integration with containment breach response runbooks (mean time-to-isolate <60s)"
        ],
        "doNot": [
            "Do NOT deploy any agent or AI system without sidecar attestation, OPA admission, MRM tiering, and SR-DSL policy bundle",
            "Do NOT export model weights, prompts, or audit logs outside WORM/PQC boundary without dual-control + zk attestation",
            "Do NOT bypass CAS-SPP supervisory proof emission or regulator audit gateway access logs",
            "Do NOT activate AutonomousAgentFleet trading agents without kill-switch drill, ICAAP capital add-on, and SR 11-7 validation",
            "Do NOT deploy frontier (T4) systems without TLA+ MGK proof, 3-of-5 quorum, kinetic override drill, AISI pre-notification"
        ]
    },
    "pillars": [
        "P1 — AI Governance & Control Platform (K8s+Kafka+OPA, Sidecars, Hub, GQL/sGQL, ARRE, ARE)",
        "P2 — Sentinel Enterprise AGI Containment Stack (AIMS+MRM, TLA+ MGK, Cognitive Resonance, GIEN, EAV)",
        "P3 — 2026-2030 Global FI AI Governance Blueprint (28 regimes, MRM, RedTeam, Roadmap)",
        "P4 — Prompt Management & Reporting Application (Governance, Agent Interop, Product Backlog)",
        "P5 — Regulator-Grade Cryptographic Supervision (CAS, CAS-SPP, SR-DSL -> Rego+WASM+zk)",
        "P6 — Sentinel v2.4 + WorkflowAI Pro G-SIFI Deployment (PQC WORM, Autonomous Agents, QKD, Sovereign Failover, Audit Gateway)"
    ],
    "regimes": [
        "EU AI Act 2024/1689 + GPAI Art. 53/55 + 2026 high-risk phase",
        "NIST AI RMF 1.0 + AI 600-1 Generative Profile",
        "NIST SP 800-53 Rev.5 + SP 800-218 SSDF",
        "ISO/IEC 42001:2023 AIMS",
        "ISO/IEC 23894:2023 AI Risk",
        "ISO/IEC 27001:2022 ISMS",
        "ISO/IEC 27701:2019 PIMS",
        "OECD AI Principles 2019/2024",
        "EU GDPR + Art. 22 + DPIA Art. 35",
        "EU DORA + NIS2 + CRA",
        "US FCRA 615 + ECOA Reg-B 1002",
        "US Fed SR 11-7 + OCC 2011-12",
        "Basel III/IV + ICAAP + FRTB + IFRS 9/CECL",
        "US SEC 17a-4 + 10-K/8-K + Cyber Disclosure + Reg-SCI",
        "FINRA 3110/4511",
        "UK FCA Consumer Duty + PRA/FCA SS1/23 + SMCR SMF-AI",
        "MAS FEAT + TRM 2021",
        "HKMA GP-1 + GS-2 GenAI",
        "OSFI E-23",
        "FINMA AI Guidance",
        "G7 Hiroshima AI Process",
        "Bletchley/Seoul/Paris AI Safety Declarations",
        "UN AI Advisory Body",
        "CEGL (Civilizational Ethical Governance Layer)",
        "LexAI-DSL + FV-LexAI",
        "GASRGP / GASC / GAISM treaty stacks",
        "Global Trust Index + Trust Derivatives Layer",
        "NSA CNSA 2.0 PQC transition mandate"
    ],
    "indices": {
        "AIMS-Coverage": ">=0.95 (ISO 42001 controls coverage)",
        "MRGI": ">=0.95 (Model Risk Governance Index, SR 11-7 + OCC 2011-12)",
        "DRI": ">=0.95 (Decision Reproducibility Index, n=10)",
        "CCS": ">=0.95 (Control Coverage Score across 28 regimes)",
        "ARI": ">=0.9 (Alignment Robustness Index, frontier)",
        "CSI": ">=0.95 (Containment Sufficiency Index, T3/T4)",
        "RTRI": ">=0.9 (Red-Team Resilience Index)",
        "CDC-Score": ">=0.9 (FCA Consumer Duty compliance)",
        "CSPI": ">=0.95 (Cryptographic Supervisory Proof Integrity)",
        "ARRE-Coverage": ">=0.98 (Automated Regulator Reporting Engine coverage)",
        "ARE-MTTR": "<=15min (Autonomous Remediation Engine mean-time-to-remediate)",
        "ZTC-Score": ">=0.95 (Zero-Trust Coverage)",
        "PQC-Migration": ">=0.95 by 2028 (CNSA 2.0 mandate)",
        "QKD-Uptime": ">=99.9 (QKD inter-DC link availability)",
        "SovFailover-RTO": "<=15min (Sovereign AI failover Recovery Time Objective)",
        "CGI": ">=0.75 (Civilizational Governance Index by 2030)",
        "GTI": ">=0.85 (Global Trust Index target by 2030)",
        "RCI": "=1.0 (Regulator Confidence Index)"
    },
    "tiers": {
        "T0": "Sandbox - isolated VPC, synthetic data, no network egress",
        "T1": "Staging - shadow mode, real data, no actuation",
        "T2": "Canary - <=1% production traffic, automated rollback",
        "T3": "Production - Nitro Enclaves / TDX / SEV-SNP + KMS + dual control + full audit",
        "T4": "Frontier Air-Gapped - 3-of-5 quorum (CRO+CISO+CDAO+Board AI Chair+AISI rep) + kinetic override + 48h time-lock + AISI <=24h + EU AI Office <=15d"
    },
    "severities": {
        "SEV-0": "Civilizational / systemic - AISI <=24h, EU AI Office <=15d, Board chair, public statement consideration",
        "SEV-1": "Major - SEC 8-K <=4 BD, DORA <=4h, FCA <=72h, MAS <=24h",
        "SEV-2": "Material - regulator notification <=72h",
        "SEV-3": "Operational - internal escalation <=10 BD"
    },
    "investment": {
        "envelope": "USD 250-650M / 5y (G-SIFI tier end-to-end program including cryptographic supervision + autonomous agent fleet)",
        "NPV": "USD 700-1900M (5y risk-adjusted, includes uplift from CAS-SPP + ARRE/ARE automation + sovereign failover)",
        "uplift_vs_WP059": "USD 50-100M envelope; USD 100-200M NPV from cryptographic supervisory layer (CAS-SPP), autonomous remediation (ARE), QKD telemetry, and sovereign AI failover",
        "drivers": [
            "AI Governance Platform (Sidecars + Hub + GQL/sGQL + ARRE + ARE) build",
            "Sentinel Enterprise AGI Containment Stack with TLA+ MGK + GIEN",
            "CAS + CAS-SPP cryptographic supervisory proof protocol",
            "SR-DSL compiler infrastructure (Rego + WASM + zk-circuits)",
            "PQC WORM archives (ML-DSA-87 + ML-KEM-1024 + SLH-DSA fallback)",
            "AutonomousAgentFleet trading + ops + governance with kill-switches",
            "QKD telemetry + sovereign AI failover across 3 jurisdictions",
            "Regulator Audit Gateway (read-only zk views to 19 regulators)",
            "Global Systemic Risk Registry federation",
            "SIEM/SOAR integration with containment breach response"
        ]
    },
    "counts": {}
}

# ---------- Typed helpers (16) ----------
def section(sid, title, **body):
    return {"sid": sid, "title": title, **body}

def module(mid, title, summary, sections):
    return {"mid": mid, "title": title, "summary": summary, "sections": sections}

def platform_component(pid, plane, component, **body):
    """P1 — AI Governance Platform component (sidecar, hub, GQL, ARRE, ARE, GitOps)."""
    return {"pid": pid, "plane": plane, "component": component, **body}

def sentinel_layer(slid, layer, capability, **body):
    """P2 — Sentinel Enterprise stack layer."""
    return {"slid": slid, "layer": layer, "capability": capability, **body}

def containment_control(cid, tier, control, **body):
    """P2 — AGI containment control (zero-trust + invariants)."""
    return {"cid": cid, "tier": tier, "control": control, **body}

def fi_blueprint(fid, domain, blueprint, **body):
    """P3 — Financial Institution blueprint item."""
    return {"fid": fid, "domain": domain, "blueprint": blueprint, **body}

def prompt_governance(qid, area, capability, **body):
    """P4 — Prompt management / agent interop / product backlog item."""
    return {"qid": qid, "area": area, "capability": capability, **body}

def crypto_supervision(xid, layer, mechanism, **body):
    """P5 — Cryptographic supervision component (CAS, CAS-SPP, SR-DSL, zk)."""
    return {"xid": xid, "layer": layer, "mechanism": mechanism, **body}

def deployment_artifact(did, surface, artifact, **body):
    """P6 — Sentinel v2.4 + WorkflowAI Pro deployment artifact (IaC, PQC, QKD, etc.)."""
    return {"did": did, "surface": surface, "artifact": artifact, **body}

def autonomous_agent(aid, fleet, role, **body):
    """P6 — Autonomous agent fleet member (trading/ops/governance)."""
    return {"aid": aid, "fleet": fleet, "role": role, **body}

def regulator_gateway(gid, regulator, surface, **body):
    """P6 — Regulator audit gateway endpoint."""
    return {"gid": gid, "regulator": regulator, "surface": surface, **body}

def roadmap_item(rid, phase, milestone, **body):
    return {"rid": rid, "phase": phase, "milestone": milestone, **body}

def dep(eid, fromItem, toItem, **body):
    return {"eid": eid, "from": fromItem, "to": toItem, **body}


# =========================================================================
# M1 — Pillar P1: Institutional AI Governance & Control Platform
# =========================================================================
m1 = module("M1",
    "P1 — AI Governance & Control Platform (K8s + Kafka + OPA + Hub + GQL/sGQL + ARRE + ARE)",
    "Institutional-grade AI governance and control platform for Tier-1 financial institutions on Kubernetes, Kafka, and OPA. Includes governance sidecars enforcing policy at the data plane, Kafka-based WORM audit logging with PQC sealing, CI/CD governance automation, OPA/Rego compliance-as-code, Governance Hub UI/API, GitOps repo structure, Governance Query Language (GQL) and streaming GQL (sGQL), regulator-scoped query layers, Automated Regulator Reporting Engine (ARRE), and Autonomous Remediation Engine (ARE).",
    [
        section("M1.1", "Governance Sidecar Architecture",
            sidecars=[
                "policy-sidecar: OPA Envoy ext_authz at <5ms p99",
                "audit-sidecar: Kafka producer to aigov.* topics with Avro schemas",
                "telemetry-sidecar: OTel + drift + fairness + capability evals emission",
                "redaction-sidecar: PII/PHI/PCI tokenization with format-preserving encryption",
                "lineage-sidecar: OpenLineage + W3C PROV emission"
            ],
            injection="Kubernetes admission webhook + Istio EnvoyFilter; opt-out denied at OPA",
            sla="p99 added latency <=8ms; resource overhead <=10% CPU"),
        section("M1.2", "Kafka-Based WORM Audit Logging",
            topics=["aigov.access", "aigov.policy-changes", "aigov.model-events", "aigov.red-team-findings", "aigov.incidents", "aigov.regulator-queries"],
            sealing="Producer-side Merkle inclusion + ML-DSA-87 batch signing every 60s",
            tieredStorage="Hot (Kafka 7d) -> Warm (Iceberg S3 90d) -> Cold (WORM S3 Object Lock COMPLIANCE 25y) with cross-region replication",
            retention="25y with PQC re-signing every 5y per NSA CNSA 2.0 mandate"),
        section("M1.3", "CI/CD Governance Automation",
            stages=[
                "PR: policy lint (conftest), SBOM (Syft), SAST (Semgrep+CodeQL), secrets (gitleaks)",
                "Build: container signing (cosign), SLSA-3 provenance, ML-DSA-87 attestation",
                "Test: unit + integration + governance contract tests + RedTeam smoke",
                "Stage: shadow + drift + fairness + capability evals",
                "Canary: <=1% traffic with auto-rollback on KPI violation",
                "Prod: dual-control approval + OPA admission + WORM audit"
            ],
            tools=["GitHub Actions / GitLab CI", "Argo CD GitOps", "Tekton Chains for SLSA", "in-toto attestations"]),
        section("M1.4", "Compliance-as-Code with OPA/Rego",
            bundleLayout="bundles/{regime}/{domain}/{rule}.rego with JSON-LD ontology",
            decisionLogs="Streamed to aigov.policy-decisions Kafka topic; WORM-sealed nightly",
            performance="p99 <5ms via decision caching + partial evaluation; 1.2M qps per cluster"),
        section("M1.5", "Governance Hub UI/API",
            ui=["Inventory (assets, models, datasets, agents)", "Risk register", "Policy catalog", "Evidence browser", "Regulator portal", "Incident war-room", "RedTeam findings", "MRM dashboard"],
            api="GraphQL Federation + REST + Webhook; OIDC + mTLS; per-regulator scoped tokens",
            access="Role-based (CRO/CCO/CISO/CDAO/Auditor/Regulator) with break-glass requiring dual-control"),
        section("M1.6", "GitOps Repo Structure",
            repos=[
                "governance-policies/ (Rego bundles + JSON-LD ontology)",
                "governance-pipelines/ (Argo workflows + Tekton)",
                "governance-infra/ (Terraform + Crossplane + Helm)",
                "governance-evidence/ (auto-generated evidence + signed receipts)",
                "governance-runbooks/ (incident + DR + breach response)"
            ],
            branching="trunk-based + signed commits + 2-eye review for prod bundles"),
        section("M1.7", "Governance Query Language (GQL) + Streaming GQL (sGQL)",
            gql="SQL-superset with built-in regulator scopes (gql>>WHERE regulator='FCA'); compiles to SQL+Cypher+SPARQL+Rego",
            sgql="Streaming variant over Kafka aigov.* topics with windowing + alerting; sub-second SLA",
            usage=["Self-serve compliance queries", "Regulator on-demand views", "Continuous control monitoring", "Automated evidence harvesting"]),
        section("M1.8", "Regulator-Scoped Query Layers",
            scopes={"FCA": "Consumer Duty + SS1/23", "PRA": "SS1/23 + ICAAP", "SEC": "10-K/8-K + cyber", "Fed": "SR 11-7", "EU AI Office": "AI Act high-risk + GPAI", "MAS": "FEAT + TRM", "HKMA": "GP-1 + GS-2"},
            redaction="Per-scope PII/MNPI redaction enforced at query plane via OPA",
            cadence="Continuous + on-demand + scheduled (quarterly attestations)"),
        section("M1.9", "Automated Regulator Reporting Engine (ARRE)",
            outputs=["EU AI Act Annex IV technical docs", "ISO 42001 management review", "SR 11-7 model inventory + validation reports", "FCA SS1/23 returns", "MAS FEAT self-assessment", "HKMA GP-1/GS-2 attestations", "SEC 8-K cyber disclosures", "DORA major-incident reports"],
            coverage=">=98% auto-generation; human review for narrative sections",
            sla="Quarterly: T-5BD draft; T-2BD review; T-0 file"),
        section("M1.10", "Autonomous Remediation Engine (ARE)",
            scope=["Policy drift auto-revert", "Failed control auto-remediate (e.g., re-encrypt, re-tier, rotate keys)", "MRM gate failure -> auto-rollback", "OPA decision violation -> auto-quarantine", "RedTeam finding -> auto-ticket + auto-patch where signed"],
            sla="MTTR <=15min for 80% of remediations; SEV-1+ requires dual-control",
            guardrails="All ARE actions logged to WORM; reversible by default; SR 11-7 model validation required for ARE policies"),
    ])

# =========================================================================
# M2 — Pillar P2: Sentinel Enterprise AI Governance & AGI Containment Stack
# =========================================================================
m2 = module("M2",
    "P2 — Sentinel Enterprise AI Governance & AGI Containment Stack",
    "Technical and governance stack for a G-SIFI bank's Sentinel Enterprise AI Governance & AGI Containment Stack. Includes AIMS + AI/ML model risk policies, AWS/EKS Terraform architecture, TLA+ Minimal Governance Kernel (MGK), global AI governance codex with meta-invariants, Cognitive Resonance & Deterministic Telemetry Engine, OPA-based sanction execution, Synthetic Regulator Audit Simulation Environment, GIEN protocol, EpistemicAlignmentVerifier, adversarial testing environment, systemic-risk protocols, and zero-trust containment architecture.",
    [
        section("M2.1", "AIMS + AI/ML Model Risk Policies",
            aims="ISO/IEC 42001 AIMS with Annex A controls A.2-A.10; Policy stack: AI Acceptable Use, Model Risk, Data, Privacy, Security, RedTeam, AGI Containment",
            mrm="SR 11-7 + OCC 2011-12 + ECB TRIM model lifecycle (Tier 1-4 with annual revalidation for T1+T2)",
            ownership="Three Lines of Defense: 1LoD model owners; 2LoD MRM + AI Risk + Compliance; 3LoD Internal Audit"),
        section("M2.2", "AWS/EKS Terraform Architecture",
            modules=[
                "modules/network: VPC + TGW + endpoints (S3, KMS, STS) + PrivateLink for Hub",
                "modules/eks: Bottlerocket nodes + Karpenter + Cilium + Istio + Falco",
                "modules/kafka: MSK Serverless + Schema Registry + tiered storage",
                "modules/opa: OPA bundles via S3 + decision logs to Kafka",
                "modules/worm: S3 Object Lock COMPLIANCE + Glacier Deep Archive",
                "modules/kms: per-tenant CMK + HSM-backed PQC migration path",
                "modules/observability: AMP Prometheus + AMG Grafana + OpenSearch + Jaeger",
                "modules/sentinel: dedicated EKS for Sentinel control plane + Nitro Enclaves"
            ],
            policy="OPA Gatekeeper + Conftest + tf-sec + Checkov pre-merge"),
        section("M2.3", "TLA+ Minimal Governance Kernel (MGK)",
            spec="TLA+ specification of the minimal kernel: quorum approval, time-lock, kinetic override, immutable audit, capability ceiling enforcement",
            invariants=["NoActuationWithoutQuorum", "AuditMonotonic", "CapabilityBounded", "KineticDominates", "TimeLockHonored"],
            verification="TLC model-checked for 5-action depth; Apalache for parametric verification; runtime enforcement via dedicated MGK microservice",
            sla="MGK availability 99.999%; latency added <=50ms; failures default to 'deny'"),
        section("M2.4", "Global AI Governance Codex + Meta-Invariants",
            codex="Versioned ontology of governance concepts: Principal, Action, Asset, Risk, Control, Evidence, Regulator, Right",
            metaInvariants=["No-Bypass (all actuation flows through MGK)", "Non-Repudiation (every decision Merkle-anchored)", "Reversibility (every action has a documented undo)", "Reproducibility (DRI>=0.95)", "Provenance (W3C PROV + in-toto)"],
            evolution="Codex changes require dual-control + TLA+ regression + Board AI Risk Committee approval"),
        section("M2.5", "Cognitive Resonance & Deterministic Telemetry Engine",
            cre="Per-decision capture of: prompt, context, retrieved docs, intermediate reasoning, tool calls, output, citations, calibration scores",
            deterministicMode="Temperature=0 replay for SEV-0/SEV-1 + regulator queries; fingerprint = SHA-512 of (model_id, weights_hash, seed, prompt, context)",
            storage="Kafka aigov.cre + WORM; 25y retention; query via GQL + sGQL"),
        section("M2.6", "OPA-Based Sanction Execution",
            sanctions=["Watchlist screening (OFAC/UN/EU/HMT/SECO/MAS)", "Sectoral sanctions", "50% rule", "Travel rule (FATF R.16)", "Adverse media + PEP"],
            implementation="Rego policies + entity-resolution sidecar + WORM-sealed decisions",
            sla="p99 <50ms; 100% audit coverage; quarterly sanctions list re-load with diff alerts"),
        section("M2.7", "Synthetic Regulator Audit Simulation Environment",
            personas=["EU AI Office Inspector", "FCA Supervisor", "PRA Examiner", "Fed Reserve Examiner", "MAS Inspector", "HKMA Examiner", "SEC Staff", "AISI Researcher"],
            simulations="Per-persona query batteries (~50-200 questions) run weekly; outputs scored on completeness + accuracy + timeliness",
            usage="Pre-audit dry-runs; RCI calibration; ARRE coverage validation"),
        section("M2.8", "GIEN Protocol (Governance Integrity Exchange Network)",
            purpose="Federated exchange of governance attestations between G-SIFI peers + AISIs + regulators",
            tech="JSON-LD + ML-DSA-87 signed + Merkle-anchored to public commitment chain",
            payloads=["RedTeam findings (anonymized)", "AGI capability eval results", "Incident summaries", "Control attestations"],
            governance="GIEN Council with rotating chairs; charter ratified by participating Boards"),
        section("M2.9", "EpistemicAlignmentVerifier (EAV)",
            purpose="Continuously verify that deployed models' stated values + behaviors match the institution's policies + societal commitments",
            tech="Constitutional AI probes + adversarial value-elicitation suite + interpretability checks (SAE features)",
            metric="EAV-Score >=0.9 required for T2+; <0.8 triggers SEV-1 + automatic quarantine"),
        section("M2.10", "Adversarial Testing Environment",
            harnesses=["Prompt injection + jailbreak", "Data poisoning + backdoor", "Adversarial examples + evasion", "Model extraction + inversion", "Membership inference", "Tool-use abuse", "Agent goal-misgeneralization"],
            cadence="Continuous for T2+; weekly for T1; per-release for all",
            partners=["UK AISI", "US AISI", "EU AI Office", "MITRE ATLAS", "external red-team vendors"]),
        section("M2.11", "Systemic-Risk Protocols",
            indicators=["Cross-firm model concentration", "Common-mode failure modes", "Procyclical hedging", "Liquidity feedback loops", "Inter-agent coordination drift"],
            actions="Per-indicator playbooks; SEV-0 escalation to FSB/IMF AI Risk Cell + central banks",
            reporting="Quarterly Systemic AI Risk Report to Board + FSOC equivalents"),
        section("M2.12", "Zero-Trust Containment Architecture",
            principles=["Verify explicitly", "Least privilege", "Assume breach", "Continuous verification"],
            implementation=["mTLS everywhere (SPIRE/SPIFFE)", "Microsegmentation (Cilium)", "Just-in-time access (Teleport)", "BeyondCorp for human access", "Confidential compute for T3+", "Air-gap for T4"],
            metrics="ZTC-Score >=0.95; quarterly purple-team exercises"),
    ])


# =========================================================================
# M3 — Pillar P3: 2026-2030 Global FI AI Governance Blueprint
# =========================================================================
m3 = module("M3",
    "P3 — 2026-2030 Global FI AI Governance Blueprint (28 Regimes, MRM, RedTeam, Roadmap)",
    "Comprehensive 2026-2030 AI governance blueprint for global financial institutions integrating EU AI Act, NIST AI RMF, ISO/IEC 42001, GDPR, Basel III/IV, SR 11-7, NIS2, FCA Consumer Duty, MAS/HKMA guidance, and other frameworks into an enterprise AI governance architecture with Sentinel-style monitoring, WorkflowAI-style orchestration, model risk management, AI red-teaming, technical controls, and phased implementation roadmap.",
    [
        section("M3.1", "28-Regime Integrated Compliance Matrix",
            crosswalks=["ISO 42001 <-> NIST AI RMF <-> EU AI Act <-> GPAI", "SR 11-7 <-> OCC 2011-12 <-> Basel III/IV ICAAP", "GDPR Art-22 <-> FCRA 615 <-> ECOA Reg-B", "FCA Consumer Duty <-> MAS FEAT <-> HKMA GP-1/GS-2", "DORA <-> NIS2 <-> CRA <-> NIST SSDF"],
            controlMap="One canonical control set in JSON-LD; bidirectional mapping to all 28 regimes; ARRE harvests evidence per regime"),
        section("M3.2", "Sentinel-Style Monitoring",
            telemetry=["Capability drift", "Alignment drift", "Calibration", "Fairness across protected classes", "Robustness", "Tool-use safety", "Agent goal-coherence"],
            dashboards="Capability dashboard per model + per agent fleet; SLO + SLI + error budget"),
        section("M3.3", "WorkflowAI-Style Orchestration",
            patterns=["RAG with citation enforcement", "Tool-using agents with bounded actuation", "Multi-agent debate for high-stakes", "Human-in-the-loop gates for SEV-1+", "Process supervision for complex tasks"],
            guardrails="Per-pattern guardrail library + RedTeam evals + KPI gates"),
        section("M3.4", "Model Risk Management (Integrated)",
            tiers={"Tier 1": "Capital/credit/market models + LLMs in adverse-action", "Tier 2": "Process automation + decisioning support", "Tier 3": "Productivity + non-decisioning", "Tier 4": "Sandbox + research"},
            revalidation={"Tier 1": "Annual + on material change", "Tier 2": "Annual", "Tier 3": "Biennial", "Tier 4": "Triennial"},
            independence="MRM under CRO; independent from model owners; veto authority for Tier 1+2"),
        section("M3.5", "AI Red-Teaming Program",
            scope=["Internal continuous (Tier 1+2)", "External quarterly (Tier 1)", "Crowdsourced bug bounty", "Regulator-facilitated (EU AI Office, AISIs)"],
            taxonomy="MITRE ATLAS + OWASP LLM Top 10 + AISI capability evals",
            integration="Findings -> Jira/ServiceNow + Kafka aigov.red-team-findings + ARE auto-patch where applicable"),
        section("M3.6", "Technical Controls Stack",
            controls=["Confidential compute (Nitro Enclaves / TDX / SEV-SNP)", "PQC migration (ML-DSA-87 + ML-KEM-1024)", "WORM audit (S3 Object Lock + 25y)", "OPA admission/runtime", "SIEM/SOAR (Splunk/Sentinel/SOAR)", "DLP (Microsoft Purview + custom)", "DSPM (Varonis + custom)"],
            integration="Hub federation across all controls; single pane of glass + ARRE evidence pull"),
        section("M3.7", "Phased Implementation Roadmap (2026-2030)",
            phases=[
                "2026 H1: Foundation - AIMS scoping + ISO 42001 stage-1; Sentinel + Hub MVP",
                "2026 H2: Pilot - 3-5 Tier 1 models on full stack; ARRE for FCA + MAS",
                "2027 H1: Scale - 50% Tier 1+2 covered; ISO 42001 certified",
                "2027 H2: AGI Containment - T3/T4 controls live; AISI MoUs",
                "2028 H1: CAS + CAS-SPP rollout; zk-attestation to EU AI Office",
                "2028 H2: AutonomousAgentFleet trading live with kill-switches",
                "2029: Federated GIEN + Global Systemic Risk Registry",
                "2030: Civilizational layer (CEGL/GASRGP) + GTI participation"
            ]),
        section("M3.8", "Phased Investment Plan",
            envelope="USD 250-650M / 5y; broken into Foundation (USD 60-130M), Scale (USD 80-180M), Frontier (USD 60-140M), Crypto+Sovereign (USD 50-200M)",
            governance="Board-approved annual budget; quarterly progress to Board AI Risk Committee"),
    ])

# =========================================================================
# M4 — Pillar P4: Prompt Management & Reporting Application
# =========================================================================
m4 = module("M4",
    "P4 — Prompt Management & Reporting Application (Governance, Agent Interop, Product Backlog)",
    "Enterprise AI architecture, governance, and product implementation plan for an AI prompt management and reporting application. Covers prompt engineering governance, enterprise AI strategy, agent interoperability (A2A, MCP, ACP), AGI/ASI safety and global governance reports, and detailed product/UX backlog.",
    [
        section("M4.1", "Product Vision & Strategy",
            vision="Single pane of glass for prompt lifecycle: author, version, test, evaluate, deploy, monitor, audit; with regulator-grade evidence",
            personas=["Prompt Engineer", "Model Owner", "MRM Validator", "Compliance Officer", "Auditor", "Regulator", "Executive"],
            northStar="Reduce prompt-related incidents by 90%; cut time-to-prod for new prompts by 70%; achieve RCI=1.0 for FCA/MAS/HKMA"),
        section("M4.2", "Prompt Engineering Governance",
            lifecycle=["Author (with templates + linting)", "Review (peer + automated)", "Test (golden + adversarial + RedTeam)", "Approve (dual-control for Tier 1)", "Deploy (canary + monitor)", "Retire (with archival + WORM evidence)"],
            policies=["No PII in prompts", "No MNPI in prompts", "Citation enforcement for RAG", "Refusal patterns for prohibited use cases", "Bias check + fairness evals"]),
        section("M4.3", "Prompt Registry & Versioning",
            registry="Git-backed + signed commits + ML-DSA-87 attestation per version; bidirectional links to MRM tier",
            versioning="Semver + provenance (W3C PROV) + lineage to training data + eval results",
            access="Role-based with break-glass; full audit to Kafka aigov.prompt-events"),
        section("M4.4", "Reporting Engine",
            reports=["Prompt inventory + risk classification", "Per-regulator prompt evidence packs", "Incident reports (prompt-injection + jailbreak)", "MRM validation reports for prompt-based systems", "Board AI Risk Committee monthly + Board quarterly"],
            outputs=["PDF/A-3 with embedded JSON evidence", "Signed regulator submissions via ARRE", "Live dashboards via Hub"]),
        section("M4.5", "Enterprise AI Strategy Integration",
            alignment=["Tied to Board-approved AI strategy", "MRM tier per prompt + system", "Capital + operational risk add-ons via ICAAP", "Procurement gating for vendor LLMs"],
            governance="AI Council reviews quarterly; Board AI Risk Committee approves Tier 1 prompts"),
        section("M4.6", "Agent Interoperability",
            protocols=["A2A (Agent-to-Agent) for inter-agent coordination", "MCP (Model Context Protocol) for tool integration", "ACP (Agent Communication Protocol) for federated agents"],
            controls="Per-protocol OPA policies + capability bounds + bounded actuation + kill-switch + WORM audit",
            registry="Agent registry with capabilities, MRM tier, RedTeam status, approved counterparties"),
        section("M4.7", "AGI/ASI Safety & Global Governance Reports",
            reports=["Quarterly Frontier AI Capability Report (T3/T4)", "Annual AGI Containment Drill Report", "Civilizational Risk Assessment (per AISI templates)", "GIEN exchange contributions", "GTI participation report"],
            distribution=["Board AI Risk Committee", "External AISIs", "EU AI Office", "G7 Hiroshima participants", "GIEN Council"]),
        section("M4.8", "Product / UX Backlog (Top Items)",
            backlog=[
                "EP-01: Prompt registry MVP (author/version/diff)",
                "EP-02: Linter + auto-redaction sidecar",
                "EP-03: Golden eval framework + RedTeam smoke",
                "EP-04: MRM tier integration + approval workflow",
                "EP-05: Canary deploy + auto-rollback",
                "EP-06: Per-regulator evidence packs (FCA, MAS, HKMA, EU AI Office)",
                "EP-07: Agent registry + A2A/MCP/ACP gateway",
                "EP-08: AGI safety report templates + AISI integration",
                "EP-09: Hub federation + GIEN connector",
                "EP-10: ARRE integration + scheduled submissions"
            ]),
    ])


# =========================================================================
# M5 — Pillar P5: Regulator-Grade Cryptographic Supervision (CAS, CAS-SPP, SR-DSL)
# =========================================================================
m5 = module("M5",
    "P5 — Regulator-Grade Multi-Layer AI Governance & Cryptographic Supervision",
    "Regulator-grade, multi-layer AI governance and cryptographic supervision architecture for high-risk and systemic AI systems. Includes multi-framework regulatory crosswalks, OPA/Rego and JSON-LD policy libraries, Kubernetes/Kafka/OPA runtime, Control Assurance Specification (CAS) and CAS-SPP cryptographic supervisory proof protocol, supervisory DSL (SR-DSL) compiling to Rego, WASM, and zk-circuits, and meta-governance layers.",
    [
        section("M5.1", "Multi-Framework Regulatory Crosswalks",
            ontology="JSON-LD ontology mapping 28 regimes to canonical control vocabulary (~600 controls)",
            api="SPARQL + GraphQL Federation + REST; OIDC + mTLS",
            governance="Ontology changes require dual-control + Board AI Risk Committee notification"),
        section("M5.2", "OPA/Rego & JSON-LD Policy Libraries",
            libraries=["compliance/eu-ai-act/*", "compliance/nist-ai-rmf/*", "compliance/iso-42001/*", "compliance/basel/*", "compliance/sr-11-7/*", "compliance/fca-cd/*", "compliance/mas-feat/*", "compliance/hkma-gp1/*", "compliance/gdpr/*", "compliance/dora/*"],
            versioning="Semver + signed bundles + Argo CD GitOps + RTBF (right-to-be-forgotten) revocation lists",
            performance="OPA p99 <5ms; bundle reload <30s; cache hit rate >95%"),
        section("M5.3", "Kubernetes / Kafka / OPA Runtime",
            runtime="Sidecar OPA (Envoy ext_authz) + admission OPA (Gatekeeper) + audit OPA (decision logs)",
            kafka="aigov.policy-decisions + aigov.policy-changes WORM-sealed",
            sla="Cluster-wide policy enforcement at 99.99% with <5ms p99 + 1.2M qps"),
        section("M5.4", "Control Assurance Specification (CAS)",
            cas="Machine-readable specification of every control with: id, regime mapping, evidence schema, runtime hook, validation cadence, owner, severity",
            format="JSON-LD + JSON Schema + protobuf for streaming",
            registry="CAS Registry as the single source of truth for controls; all platform components consume CAS"),
        section("M5.5", "CAS-SPP (Cryptographic Supervisory Proof Protocol)",
            purpose="Issue verifiable cryptographic proofs to regulators that controls were enforced as specified, without exposing underlying data",
            protocol=["Per-control Merkle tree of evidence", "Periodic batch root signed with ML-DSA-87", "zk-SNARK proofs for selective disclosure", "Public commitment to immutable chain (e.g., Sigstore Rekor)"],
            cadence="Continuous for high-risk; daily batches for material controls; quarterly summaries to all 19 regulators"),
        section("M5.6", "Supervisory DSL (SR-DSL)",
            purpose="High-level DSL where supervisory rules are authored in regulator-friendly syntax, compiling to Rego (admission), WASM (runtime), and zk-circuits (proofs)",
            syntax="Declarative; e.g., 'rule fca_cd_1 { ensure consumer_duty_outcome.delivered for high_risk_decision }'",
            compiler="srdslc emits: rego/*.rego, wasm/*.wasm, zk/*.r1cs+*.zkey; bidirectional traceability to regulation citations",
            governance="DSL changes require dual-control + Compliance Council approval; full WORM audit of compiler runs"),
        section("M5.7", "Meta-Governance Layers",
            layers=[
                "L0 Constitutional (Board AI Charter + AI Acceptable Use)",
                "L1 Codex (canonical ontology + meta-invariants)",
                "L2 CAS Registry (controls)",
                "L3 SR-DSL Rules (supervisory rules)",
                "L4 Rego/WASM/zk Bundles (executable)",
                "L5 Runtime (admission + sidecar + audit)",
                "L6 CAS-SPP (cryptographic proofs)",
                "L7 Hub + Regulator Audit Gateway"
            ],
            integrity="Every layer signed + Merkle-anchored; tamper detection at <60s; SEV-0 on tamper"),
        section("M5.8", "Regulator Adoption & Interop",
            partners=["EU AI Office (CAS-SPP pilot 2027)", "UK FCA (zk-attestation for Consumer Duty)", "MAS (FEAT zk-evidence)", "HKMA (GS-2 attestation)", "Fed (SR 11-7 cryptographic evidence)", "AISIs (capability eval proofs)"],
            standards="Contribute to ISO/IEC AWI 22989 update + NIST AI 600-2 draft + EU AI Office harmonized standards"),
    ])

# =========================================================================
# M6 — Pillar P6: Sentinel v2.4 + WorkflowAI Pro G-SIFI Deployment
# =========================================================================
m6 = module("M6",
    "P6 — Sentinel AI v2.4 + WorkflowAI Pro G-SIFI Deployment Architecture",
    "Sentinel AI v2.4 & WorkflowAI Pro-based G-SIFI deployment architecture with Docker/Kubernetes/Terraform infrastructure, PQC WORM archiving, AI red-team suites, governance dashboards, autonomous trading agents and guardrails, zero-trust networking, systemic risk telemetry, containment breach response, cryptographic provenance, CI/CD and DevSecOps, AutonomousAgentFleet configuration, SIEM/SOAR integration, global systemic risk registry, QKD telemetry, sovereign AI failover, regulator audit gateway, and production best practices.",
    [
        section("M6.1", "Docker / Kubernetes / Terraform Infrastructure",
            containers="Distroless base + cosign-signed + SLSA-3 provenance + ML-DSA-87 attestation; pinned digests",
            k8s="EKS/GKE/AKS + Bottlerocket + Karpenter + Cilium + Istio + Falco; multi-region active-active",
            terraform="Modular repos (network/eks/kafka/opa/worm/kms/observability/sentinel/wfap); Atlantis + Spacelift for CI/CD",
            policy="OPA Gatekeeper + Conftest + tf-sec + Checkov pre-merge"),
        section("M6.2", "PQC WORM Archiving",
            kem="ML-KEM-1024 for key encapsulation",
            sig="ML-DSA-87 primary + SLH-DSA-256s fallback",
            storage="S3 Object Lock COMPLIANCE + Glacier Deep Archive + Azure Immutable + GCS Bucket Lock",
            retention="25y + 5y re-signing rotation per CNSA 2.0; tamper-evident Merkle chain"),
        section("M6.3", "AI Red-Team Suites",
            suites=["Prompt injection battery (~500 vectors)", "Jailbreak corpus (~1,200 vectors)", "Data poisoning canaries", "Backdoor probes", "Adversarial example generators", "Agent goal-misgen scenarios", "Tool-use abuse"],
            integration="Findings -> Jira/ServiceNow + Kafka + Hub + ARE auto-patch; coverage tracked via RTRI"),
        section("M6.4", "Governance Dashboards",
            dashboards=["Executive (Board + ExCo)", "CRO/CCO (risk + compliance posture)", "CISO (security + zero-trust)", "CDAO (data + AI inventory)", "MRM (model lifecycle)", "Auditor (evidence)", "Regulator (scoped views)"],
            tech="Grafana + Superset + custom React; OIDC + per-scope RBAC; live + scheduled exports"),
        section("M6.5", "Autonomous Trading Agents + Guardrails",
            agents=["Market-making agent (FX + rates)", "Liquidity-routing agent", "Algorithmic execution agent", "Risk-hedging agent"],
            guardrails=["Position limits + VaR/ES caps", "Loss-cut kill-switch", "Circuit-breaker integration", "RFQ-only mode under stress", "Dual-control for parameter changes", "MRM Tier 1 + annual revalidation"],
            constraints="No autonomous principal-trading without ICAAP add-on + Board AI Risk Committee + FCA SS1/23 attestation"),
        section("M6.6", "Zero-Trust Networking",
            implementation=["mTLS via SPIRE/SPIFFE", "Microsegmentation via Cilium", "Just-in-time access via Teleport", "BeyondCorp for human access", "DNS-RPZ + Pi-hole-style egress filtering", "Tailscale for legacy systems"],
            metric="ZTC-Score >=0.95; quarterly purple-team validation"),
        section("M6.7", "Systemic Risk Telemetry",
            indicators=["Cross-firm model concentration via federated GIEN exchange", "Procyclicality scores per agent class", "Liquidity feedback loop detectors", "Correlated drawdown alarms", "Inter-agent coordination drift"],
            integration="Telemetry -> Global Systemic Risk Registry (M6.13) + FSB/IMF AI Risk Cell + central banks"),
        section("M6.8", "Containment Breach Response",
            playbooks=["T0 breach -> automatic snapshot + quarantine", "T1 breach -> SEV-2 + RedTeam triage", "T2 breach -> SEV-1 + CRO + dual-control rollback", "T3 breach -> SEV-0 + Board AI Chair + AISI <=24h", "T4 breach -> SEV-0 + kinetic override + EU AI Office <=15d"],
            sla="Mean time-to-isolate <60s; mean time-to-rollback <15min; runbook drills quarterly"),
        section("M6.9", "Cryptographic Provenance",
            provenance="W3C PROV + in-toto + SLSA-3 + cosign + ML-DSA-87",
            scope=["Container images", "Model weights", "Training data", "Prompts", "Audit logs", "Regulator submissions", "Policy bundles"],
            verification="Hub + ARE + Regulator Audit Gateway can verify any artifact's chain back to source"),
        section("M6.10", "CI/CD & DevSecOps",
            pipeline=["PR: lint + SAST + SBOM + secrets + governance contract", "Build: signed + provenance", "Test: unit + integration + RedTeam smoke", "Stage: shadow + drift + fairness", "Canary: <=1% + auto-rollback", "Prod: dual-control + OPA + WORM"],
            tools=["GitHub Actions / GitLab CI", "Argo CD", "Tekton Chains", "Backstage developer portal"]),
        section("M6.11", "AutonomousAgentFleet Configuration",
            fleets={"Trading": "4 agents (market-making, liquidity, execution, hedging)", "Operations": "6 agents (incident, change, capacity, FinOps, evidence-harvester, RedTeam-orchestrator)", "Governance": "5 agents (policy-author, control-tester, audit-prep, ARRE-runner, ARE-executor)"},
            shared=["MRM tier per agent", "OPA capability bounds", "WORM audit", "Kill-switch + dead-man-switch", "Per-action ML-DSA-87 attestation"],
            governance="Fleet Council weekly review; quarterly Board AI Risk Committee report"),
        section("M6.12", "SIEM / SOAR Integration",
            siem=["Splunk Enterprise Security", "Microsoft Sentinel", "QRadar", "Chronicle"],
            soar=["Splunk SOAR", "XSOAR", "Tines", "custom Argo-based"],
            integration="Kafka aigov.* + governance events -> SIEM correlation; SEV-1+ triggers SOAR playbook + Hub incident war-room"),
        section("M6.13", "Global Systemic Risk Registry",
            registry="Federated registry across G-SIFI peers + central banks + AISIs",
            schema="JSON-LD + ML-DSA-87 signed; entries: firm-anonymized model exposure, capability evals, RedTeam findings, incidents",
            governance="Registry Council with rotating chairs; participants ratified by central banks + Boards",
            cadence="Continuous streaming + weekly summaries + quarterly systemic-risk report"),
        section("M6.14", "QKD Telemetry",
            scope="Quantum-Key-Distribution links between core data centers (London + Frankfurt + Singapore + Tokyo) + Hub HQ",
            usage=["Key delivery for PQC fallback", "Telemetry integrity for SEV-0 channels", "Regulator notification confidentiality"],
            uptime=">=99.9% per link; ID Quantique + Toshiba + QuantumXC vendors; ETSI QKD standards"),
        section("M6.15", "Sovereign AI Failover",
            scope="Sovereign AI failover across 3 jurisdictions (e.g., US + EU + APAC) with full active-active for Tier 1 + Hub",
            rto="<=15min; RPO <=5min; tested monthly via Chaos Engineering",
            governance="Data residency per regime (GDPR + MAS Notice 658 + HKMA); sovereign cloud where required (AWS GovCloud + Azure Sovereign + GCP Sovereign Controls)"),
        section("M6.16", "Regulator Audit Gateway",
            gateway="Read-only zk-verifiable gateway exposing scoped views to: EU AI Office, UK FCA, PRA, US Fed, OCC, SEC, FINRA, MAS, HKMA, OSFI, FINMA, BaFin, ACPR, AMF, AISIs (UK+US+EU+SG+JP+CA)",
            tech="GraphQL Federation + REST + per-regulator OIDC + zk-attestation via CAS-SPP",
            access="All queries logged to WORM; SLA <2s p99; quarterly cadence + on-demand"),
        section("M6.17", "Production Best Practices",
            practices=["Trunk-based development + signed commits", "Pre-merge OPA + tf-sec + SBOM + SAST", "Canary + shadow + auto-rollback", "Dual-control for prod + Tier 1+2 changes", "WORM audit + 25y retention", "Quarterly DR + breach drills", "Quarterly RedTeam external", "Annual ISO 42001 surveillance", "Continuous capability evals for T2+"],
            roi="Best-in-class controls reduce SEV-1+ incidents by ~70% vs baseline; ARRE saves ~15-25 FTE/year vs manual"),
    ])

MODULES = [m1, m2, m3, m4, m5, m6]


# =========================================================================
# DISTINCTIVE ARRAY 1: platformComponents (P1) — 18 items
# =========================================================================
platformComponents = [
    platform_component("PC-01", "Sidecar", "policy-sidecar (OPA + Envoy ext_authz)", sla="p99 <5ms", regimes=["EU AI Act Art. 15", "NIST AI RMF MAP-4.1", "ISO 42001 A.6"]),
    platform_component("PC-02", "Sidecar", "audit-sidecar (Kafka producer + Avro)", sla="zero-loss; 100% audit", regimes=["SEC 17a-4", "ISO 42001 A.7", "DORA"]),
    platform_component("PC-03", "Sidecar", "telemetry-sidecar (OTel + drift + fairness)", sla="1s emit", regimes=["NIST AI RMF MEASURE-2", "EU AI Act Art. 15"]),
    platform_component("PC-04", "Sidecar", "redaction-sidecar (PII/PHI/PCI tokenization)", sla="p99 <2ms", regimes=["GDPR", "PCI-DSS", "GLBA"]),
    platform_component("PC-05", "Sidecar", "lineage-sidecar (OpenLineage + W3C PROV)", sla="streamed real-time", regimes=["EU AI Act Art. 12", "ISO 42001 A.8"]),
    platform_component("PC-06", "Audit", "Kafka aigov.* topics + Avro Schema Registry", retention="7d hot + 90d warm + 25y WORM", regimes=["SEC 17a-4", "DORA", "MiFID II"]),
    platform_component("PC-07", "Audit", "WORM S3 Object Lock COMPLIANCE", retention="25y + PQC re-sign 5y", regimes=["SEC 17a-4 f(2)", "FINRA 4511", "FCA SYSC 9"]),
    platform_component("PC-08", "CI/CD", "Argo CD GitOps + Tekton Chains SLSA-3", coverage="100% Tier 1+2", regimes=["NIST SSDF SP 800-218", "EU AI Act Art. 17"]),
    platform_component("PC-09", "CI/CD", "Cosign + ML-DSA-87 attestation + in-toto", coverage="all container images + model weights", regimes=["CNSA 2.0", "NIST SSDF"]),
    platform_component("PC-10", "Policy", "OPA Gatekeeper (admission)", sla="p99 <50ms", regimes=["EU AI Act Art. 9", "ISO 42001 A.6.2.2"]),
    platform_component("PC-11", "Policy", "OPA Sidecar (data-plane runtime)", sla="p99 <5ms; 1.2M qps", regimes=["EU AI Act Art. 14", "NIST AI RMF MANAGE-2"]),
    platform_component("PC-12", "Hub", "Governance Hub UI (React + OIDC + per-scope RBAC)", coverage="all roles + regulators", regimes=["ISO 42001 A.10", "EU AI Act Art. 26"]),
    platform_component("PC-13", "Hub", "Governance Hub API (GraphQL Federation + REST + Webhook)", sla="p99 <500ms", regimes=["ISO 42001 A.10"]),
    platform_component("PC-14", "GitOps", "governance-policies/ + governance-pipelines/ + governance-infra/", review="2-eye + signed commits", regimes=["NIST SSDF", "ISO 42001 A.6.1.4"]),
    platform_component("PC-15", "Query", "GQL (Governance Query Language) compiler", outputs=["SQL", "Cypher", "SPARQL", "Rego"], regimes=["EU AI Act Annex IV", "ISO 42001 A.7"]),
    platform_component("PC-16", "Query", "sGQL (streaming Governance Query Language) over Kafka", latency="sub-second", regimes=["DORA Art. 17", "ISO 42001 A.7"]),
    platform_component("PC-17", "Reporting", "ARRE (Automated Regulator Reporting Engine)", coverage=">=98%; quarterly to 19 regulators", regimes=["FCA SS1/23", "MAS FEAT", "HKMA GP-1", "EU AI Act Annex IV"]),
    platform_component("PC-18", "Remediation", "ARE (Autonomous Remediation Engine)", mttr="<=15min for 80%; dual-control SEV-1+", regimes=["SR 11-7", "ISO 42001 A.6.2.5"]),
]

# =========================================================================
# DISTINCTIVE ARRAY 2: sentinelLayers (P2) — 13 items
# =========================================================================
sentinelLayers = [
    sentinel_layer("SL-01", "L1 Substrate", "HW + Confidential Compute (Nitro Enclaves / TDX / SEV-SNP)", attestation="ML-DSA-87 signed measurements"),
    sentinel_layer("SL-02", "L2 Control Plane", "TLA+ MGK (Minimal Governance Kernel) microservice", sla="99.999% + deny-fail-closed"),
    sentinel_layer("SL-03", "L3 Containment", "T0-T4 tier model + capability ceiling enforcement", verification="TLA+ + Lean/Coq invariants"),
    sentinel_layer("SL-04", "L4 Alignment", "RLHF + DPO + Constitutional + Process supervision + Debate", metric="ARI >=0.9 for frontier"),
    sentinel_layer("SL-05", "L5 Interpretability", "Mech-Interp + Probes + Sparse Autoencoders", coverage="all T3+ frontier models"),
    sentinel_layer("SL-06", "L6 Evaluation", "HELM + ARC Evals + METR + Apollo + cyber-offense + WMD probes", cadence="continuous T2+; per-release all"),
    sentinel_layer("SL-07", "L7 Telemetry", "Cognitive Resonance & Deterministic Telemetry Engine", storage="WORM 25y"),
    sentinel_layer("SL-08", "L8 Coordination", "AISI MoUs (UK + US + EU + SG + JP + CA)", protocol="GIEN + bilateral"),
    sentinel_layer("SL-09", "L9 Codex", "Global AI Governance Codex + Meta-Invariants", evolution="dual-control + TLA+ regression + Board"),
    sentinel_layer("SL-10", "L10 Sanctions", "OPA-based sanction execution (OFAC/UN/EU/HMT/SECO/MAS)", sla="p99 <50ms"),
    sentinel_layer("SL-11", "L11 Audit Sim", "Synthetic Regulator Audit Simulation Environment", personas=8),
    sentinel_layer("SL-12", "L12 Verification", "EpistemicAlignmentVerifier (EAV)", metric="EAV-Score >=0.9 for T2+"),
    sentinel_layer("SL-13", "L13 Resilience", "Adversarial Testing Environment + Systemic-Risk Protocols + Zero-Trust", drills="quarterly"),
]

# =========================================================================
# DISTINCTIVE ARRAY 3: containmentControls (P2) — 18 items
# =========================================================================
containmentControls = [
    containment_control("CC-01", "T0", "Isolated VPC + no network egress + synthetic data only", verification="Cilium network policy + Falco"),
    containment_control("CC-02", "T0", "Resource cgroups: CPU/GPU/mem caps signed", verification="eBPF + cgroup v2"),
    containment_control("CC-03", "T1", "Shadow mode: production data, no actuation", verification="OPA admission denies actuation"),
    containment_control("CC-04", "T1", "Output diffing vs baseline + KPI shadow scoring", verification="aigov.shadow Kafka topic + GQL"),
    containment_control("CC-05", "T2", "Canary <=1% traffic", verification="Argo Rollouts + auto-rollback on KPI"),
    containment_control("CC-06", "T2", "Auto-rollback on RTRI/ARI/CSI/EAV violations", verification="ARE policy + dual-control SEV-1+"),
    containment_control("CC-07", "T3", "Nitro Enclaves / TDX / SEV-SNP confidential compute", verification="ML-DSA-87 attested measurements"),
    containment_control("CC-08", "T3", "Dual-control approvals for prod actuation", verification="MGK quorum + WORM audit"),
    containment_control("CC-09", "T3", "Full WORM audit + cryptographic provenance", verification="W3C PROV + in-toto + cosign"),
    containment_control("CC-10", "T4", "Air-gapped frontier enclaves + one-way diode telemetry", verification="hardware diode + signed channels"),
    containment_control("CC-11", "T4", "3-of-5 quorum (CRO+CISO+CDAO+Board AI Chair+AISI rep)", verification="MGK quorum protocol + ML-DSA-87 sigs"),
    containment_control("CC-12", "T4", "Kinetic override (physical kill-switch)", verification="quarterly drill + Board attestation"),
    containment_control("CC-13", "T4", "48h time-lock for any change to T4 invariants", verification="TLA+ TimeLockHonored invariant"),
    containment_control("CC-14", "T4", "AISI <=24h notification + EU AI Office <=15d", verification="WORM-sealed regulator dispatch logs"),
    containment_control("CC-15", "ALL", "TLA+ MGK formally-verified invariants (NoBypass, AuditMonotonic, CapabilityBounded)", verification="TLC + Apalache + runtime eBPF"),
    containment_control("CC-16", "ALL", "Mean time-to-isolate <60s on breach detection", verification="quarterly purple-team drills"),
    containment_control("CC-17", "ALL", "Mean time-to-rollback <15min for SEV-1+", verification="DR runbooks + Argo Rollouts"),
    containment_control("CC-18", "ALL", "Capability ceiling enforcement (eval threshold crossing -> SEV-0)", verification="HELM + ARC + METR + Apollo + WMD probes"),
]

# =========================================================================
# DISTINCTIVE ARRAY 4: fiBlueprints (P3) — 16 items
# =========================================================================
fiBlueprints = [
    fi_blueprint("FB-01", "Capital", "Basel III/IV + ICAAP AI add-on for SR 11-7 Tier 1 models", regimes=["Basel III/IV", "SR 11-7", "ICAAP"]),
    fi_blueprint("FB-02", "Credit", "FCRA 615 + ECOA Reg-B with EU AI Act high-risk Art. 6", regimes=["FCRA 615", "ECOA Reg-B", "EU AI Act Art. 6"]),
    fi_blueprint("FB-03", "Market", "FRTB + IMA models with SR 11-7 + AI/ML model risk policy", regimes=["FRTB", "SR 11-7"]),
    fi_blueprint("FB-04", "Operational", "DORA + NIS2 + AI Act incident reporting harmonization", regimes=["DORA", "NIS2", "EU AI Act"]),
    fi_blueprint("FB-05", "Trading", "FCA SS1/23 + MAS FEAT + HKMA GS-2 for algorithmic trading", regimes=["FCA SS1/23", "MAS FEAT", "HKMA GS-2"]),
    fi_blueprint("FB-06", "Consumer", "FCA Consumer Duty PRIN 2A + CDC-Score telemetry", regimes=["FCA Consumer Duty", "GDPR Art-22"]),
    fi_blueprint("FB-07", "AML/Sanctions", "OFAC + UN + EU + HMT + SECO + MAS + FATF R.16 via OPA", regimes=["OFAC", "FATF R.16"]),
    fi_blueprint("FB-08", "Privacy", "GDPR + GDPR Art-22 + DPIA Art-35 + UK DPA 2018", regimes=["GDPR", "UK DPA"]),
    fi_blueprint("FB-09", "Cybersecurity", "NIST SP 800-53 + ISO 27001 + DORA + SEC cyber disclosure", regimes=["NIST 800-53", "ISO 27001", "DORA", "SEC"]),
    fi_blueprint("FB-10", "Cloud", "OSFI E-23 + EBA Outsourcing + FFIEC + MAS Notice 658", regimes=["OSFI E-23", "EBA", "FFIEC", "MAS 658"]),
    fi_blueprint("FB-11", "Vendor LLM", "Procurement gating + MRM + RedTeam + ICAAP add-on", regimes=["SR 11-7", "OCC 2011-12"]),
    fi_blueprint("FB-12", "GenAI", "EU AI Act GPAI Art. 53/55 + NIST AI 600-1", regimes=["EU AI Act Art. 53/55", "NIST AI 600-1"]),
    fi_blueprint("FB-13", "Agentic", "Bounded actuation + capability bounds + kill-switch + MRM Tier 1", regimes=["SR 11-7", "ISO 42001 A.6.2.5"]),
    fi_blueprint("FB-14", "Frontier", "T3/T4 containment + AISI MoUs + EU AI Office pre-notification", regimes=["EU AI Act Art. 51/55", "G7 Hiroshima"]),
    fi_blueprint("FB-15", "Sustainability", "ESG disclosure + carbon accounting for AI workloads", regimes=["TCFD", "ISSB S2"]),
    fi_blueprint("FB-16", "Civilizational", "CEGL + LexAI-DSL + GASRGP/GASC + GTI participation", regimes=["CEGL", "LexAI-DSL", "GASRGP", "GTI"]),
]


# =========================================================================
# DISTINCTIVE ARRAY 5: promptGovernance (P4) — 15 items
# =========================================================================
promptGovernance = [
    prompt_governance("PG-01", "Authoring", "Prompt templates + linter + auto-redaction", coverage="100% Tier 1+2 prompts"),
    prompt_governance("PG-02", "Authoring", "PII/MNPI/PCI ban list enforced at lint", regimes=["GDPR", "MAR", "PCI-DSS"]),
    prompt_governance("PG-03", "Review", "2-eye peer review + automated quality checks", sla="<2 BD for non-urgent"),
    prompt_governance("PG-04", "Testing", "Golden eval suite (~100 cases per prompt)", coverage="all prompts"),
    prompt_governance("PG-05", "Testing", "RedTeam smoke (injection + jailbreak + bias)", cadence="per-release"),
    prompt_governance("PG-06", "Approval", "Dual-control for Tier 1; MRM tiering required", regimes=["SR 11-7", "ISO 42001"]),
    prompt_governance("PG-07", "Deployment", "Canary <=1% + auto-rollback on KPI breach", sla="<5min rollback"),
    prompt_governance("PG-08", "Monitoring", "Drift + fairness + calibration + citation enforcement", cadence="continuous"),
    prompt_governance("PG-09", "Retirement", "Archival to WORM + reason + replacement linkage", retention="25y"),
    prompt_governance("PG-10", "Registry", "Git-backed + signed commits + ML-DSA-87 per version", provenance="W3C PROV"),
    prompt_governance("PG-11", "Reporting", "Per-regulator prompt evidence packs", regimes=["FCA SS1/23", "MAS FEAT", "HKMA GP-1"]),
    prompt_governance("PG-12", "Agent Interop", "A2A protocol with OPA capability bounds", protocol="A2A v0.1"),
    prompt_governance("PG-13", "Agent Interop", "MCP (Model Context Protocol) for tool integration", protocol="MCP v1.0"),
    prompt_governance("PG-14", "Agent Interop", "ACP (Agent Communication Protocol) for federated agents", protocol="ACP draft"),
    prompt_governance("PG-15", "AGI/ASI Reports", "Quarterly Frontier AI Capability Report + AGI containment drill", distribution=["Board", "AISIs", "EU AI Office"]),
]

# =========================================================================
# DISTINCTIVE ARRAY 6: cryptoSupervisionLayers (P5) — 18 items
# =========================================================================
cryptoSupervisionLayers = [
    crypto_supervision("CS-01", "Ontology", "JSON-LD ontology mapping 28 regimes -> ~600 canonical controls", api="SPARQL + GraphQL + REST"),
    crypto_supervision("CS-02", "Policy Libraries", "compliance/eu-ai-act/* Rego bundle", coverage="Art. 5-72 + Annex IV"),
    crypto_supervision("CS-03", "Policy Libraries", "compliance/nist-ai-rmf/* Rego bundle", coverage="GOVERN+MAP+MEASURE+MANAGE"),
    crypto_supervision("CS-04", "Policy Libraries", "compliance/iso-42001/* Rego bundle", coverage="Clauses 4-10 + Annex A"),
    crypto_supervision("CS-05", "Policy Libraries", "compliance/basel/* + compliance/sr-11-7/* Rego bundle", coverage="ICAAP + FRTB + IFRS9"),
    crypto_supervision("CS-06", "Policy Libraries", "compliance/fca-cd/* + compliance/mas-feat/* + compliance/hkma-gp1/*", coverage="Consumer + GenAI guidance"),
    crypto_supervision("CS-07", "Runtime", "OPA Gatekeeper (admission) + OPA Sidecar (data-plane)", sla="p99 <5ms; 1.2M qps"),
    crypto_supervision("CS-08", "Runtime", "Kafka aigov.policy-decisions WORM-sealed", sla="zero-loss; 25y retention"),
    crypto_supervision("CS-09", "CAS", "Control Assurance Specification machine-readable registry", format="JSON-LD + JSON Schema + protobuf"),
    crypto_supervision("CS-10", "CAS-SPP", "Per-control Merkle tree + ML-DSA-87 batch signing", cadence="continuous high-risk; daily material"),
    crypto_supervision("CS-11", "CAS-SPP", "zk-SNARK proofs for selective disclosure to regulators", scheme="Groth16 + PLONK"),
    crypto_supervision("CS-12", "CAS-SPP", "Public commitment to Sigstore Rekor for tamper-evidence", anchor="Sigstore Rekor + private chain"),
    crypto_supervision("CS-13", "SR-DSL", "Supervisory DSL syntax + parser + AST", design="declarative + regulator-friendly"),
    crypto_supervision("CS-14", "SR-DSL", "srdslc compiler: SR-DSL -> Rego (admission)", target="OPA Gatekeeper bundles"),
    crypto_supervision("CS-15", "SR-DSL", "srdslc compiler: SR-DSL -> WASM (runtime)", target="Envoy Wasm filters"),
    crypto_supervision("CS-16", "SR-DSL", "srdslc compiler: SR-DSL -> zk-circuits (r1cs/zkey)", target="Circom + snarkjs + arkworks"),
    crypto_supervision("CS-17", "Meta-Governance", "L0-L7 layered governance with signed + Merkle-anchored layers", tamper="<60s detection -> SEV-0"),
    crypto_supervision("CS-18", "Interop", "EU AI Office + FCA + MAS + HKMA + Fed + AISIs CAS-SPP adoption", pilot="2027 EU AI Office; 2028 wider"),
]

# =========================================================================
# DISTINCTIVE ARRAY 7: deploymentArtifacts (P6) — 22 items
# =========================================================================
deploymentArtifacts = [
    deployment_artifact("DA-01", "IaC", "modules/network: VPC + TGW + endpoints + PrivateLink", tech="Terraform + Atlantis"),
    deployment_artifact("DA-02", "IaC", "modules/eks: Bottlerocket + Karpenter + Cilium + Istio + Falco", tech="Terraform + EKS"),
    deployment_artifact("DA-03", "IaC", "modules/kafka: MSK Serverless + Schema Registry + tiered storage", tech="Terraform + MSK"),
    deployment_artifact("DA-04", "IaC", "modules/opa: bundles via S3 + decision logs Kafka", tech="Terraform + OPA"),
    deployment_artifact("DA-05", "IaC", "modules/worm: S3 Object Lock COMPLIANCE + Glacier Deep Archive", tech="Terraform + S3 + Glacier"),
    deployment_artifact("DA-06", "IaC", "modules/kms: per-tenant CMK + HSM-backed PQC migration", tech="Terraform + KMS + CloudHSM"),
    deployment_artifact("DA-07", "Containers", "Distroless base + cosign-signed + SLSA-3 + ML-DSA-87", tech="Docker + cosign + slsa-github-generator"),
    deployment_artifact("DA-08", "PQC", "ML-KEM-1024 key encapsulation + ML-DSA-87 signing", tech="liboqs + AWS KMS PQC preview"),
    deployment_artifact("DA-09", "PQC", "SLH-DSA-256s fallback for stateless signing", tech="liboqs + custom HSM module"),
    deployment_artifact("DA-10", "WORM", "S3 Object Lock COMPLIANCE 25y + 5y re-sign rotation", regimes=["SEC 17a-4", "CNSA 2.0"]),
    deployment_artifact("DA-11", "RedTeam", "Prompt injection battery (~500 vectors) + jailbreak corpus (~1,200)", coverage="all Tier 1+2"),
    deployment_artifact("DA-12", "RedTeam", "Backdoor probes + adversarial example generators + tool-use abuse", partners=["MITRE ATLAS", "external vendors"]),
    deployment_artifact("DA-13", "Dashboards", "Executive + CRO + CCO + CISO + CDAO + MRM + Auditor + Regulator", tech="Grafana + Superset + custom React"),
    deployment_artifact("DA-14", "Zero-Trust", "SPIRE/SPIFFE mTLS + Cilium microsegmentation + Teleport JIT", metric="ZTC-Score >=0.95"),
    deployment_artifact("DA-15", "Telemetry", "OTel + Prometheus + Jaeger + OpenSearch", retention="365d hot + 7y warm"),
    deployment_artifact("DA-16", "Systemic", "Global Systemic Risk Registry federation client", protocol="JSON-LD + ML-DSA-87 signed"),
    deployment_artifact("DA-17", "QKD", "ID Quantique + Toshiba + QuantumXC links London+Frankfurt+Singapore+Tokyo", standards="ETSI QKD"),
    deployment_artifact("DA-18", "Failover", "Sovereign AI failover US+EU+APAC + AWS GovCloud + Azure Sovereign + GCP Sov Controls", rto="<=15min"),
    deployment_artifact("DA-19", "Gateway", "Regulator Audit Gateway zk-verifiable read-only", sla="<2s p99; 19 regulators"),
    deployment_artifact("DA-20", "CI/CD", "Argo CD + Tekton Chains + cosign + in-toto + Backstage", tech="GitHub Actions / GitLab CI"),
    deployment_artifact("DA-21", "SIEM/SOAR", "Splunk ES / MS Sentinel / QRadar / Chronicle + SOAR playbooks", coverage="all aigov.* topics"),
    deployment_artifact("DA-22", "Provenance", "W3C PROV + in-toto + SLSA-3 + cosign + ML-DSA-87 end-to-end", scope=["containers", "weights", "data", "prompts", "logs"]),
]

# =========================================================================
# DISTINCTIVE ARRAY 8: autonomousAgents (P6) — 15 items
# =========================================================================
autonomousAgents = [
    autonomous_agent("AA-01", "Trading", "Market-making agent (FX + rates)", guardrails=["Position limits", "VaR/ES caps", "Loss-cut kill-switch"], mrmTier="Tier 1"),
    autonomous_agent("AA-02", "Trading", "Liquidity-routing agent", guardrails=["Best-execution constraints", "Venue caps", "RFQ-only stress mode"], mrmTier="Tier 1"),
    autonomous_agent("AA-03", "Trading", "Algorithmic execution agent (TCA-aware)", guardrails=["TCA bands", "Anti-gaming filters", "Kill-switch"], mrmTier="Tier 1"),
    autonomous_agent("AA-04", "Trading", "Risk-hedging agent", guardrails=["Hedge ratio bounds", "Procyclicality dampers", "Dual-control"], mrmTier="Tier 1"),
    autonomous_agent("AA-05", "Operations", "Incident-response agent", guardrails=["SEV-1+ requires human", "WORM audit", "ARE policy bound"], mrmTier="Tier 2"),
    autonomous_agent("AA-06", "Operations", "Change-management agent", guardrails=["No prod without dual-control", "OPA admission"], mrmTier="Tier 2"),
    autonomous_agent("AA-07", "Operations", "Capacity-planning agent", guardrails=["FinOps budget caps", "Carbon caps"], mrmTier="Tier 3"),
    autonomous_agent("AA-08", "Operations", "FinOps-optimizer agent", guardrails=["Budget caps", "No production-impacting changes without human"], mrmTier="Tier 3"),
    autonomous_agent("AA-09", "Operations", "Evidence-harvester agent (ARRE feeder)", guardrails=["Read-only; WORM-sealed receipts"], mrmTier="Tier 2"),
    autonomous_agent("AA-10", "Operations", "RedTeam-orchestrator agent", guardrails=["Bounded harnesses; OPA capability bounds"], mrmTier="Tier 2"),
    autonomous_agent("AA-11", "Governance", "Policy-author agent (drafts only)", guardrails=["No autonomous merge; human approval"], mrmTier="Tier 3"),
    autonomous_agent("AA-12", "Governance", "Control-tester agent", guardrails=["Read-only; emits findings to Hub"], mrmTier="Tier 2"),
    autonomous_agent("AA-13", "Governance", "Audit-prep agent", guardrails=["Read-only; per-regulator scoped"], mrmTier="Tier 2"),
    autonomous_agent("AA-14", "Governance", "ARRE-runner agent (scheduled submissions)", guardrails=["Human sign-off pre-submit; WORM audit"], mrmTier="Tier 1"),
    autonomous_agent("AA-15", "Governance", "ARE-executor agent", guardrails=["Bounded remediation set; reversible; SEV-1+ dual-control"], mrmTier="Tier 1"),
]


# =========================================================================
# DISTINCTIVE ARRAY 9: regulatorGateways (P6) — 19 items
# =========================================================================
regulatorGateways = [
    regulator_gateway("RG-01", "EU AI Office", "AI Act high-risk + GPAI Art. 53/55 zk-attestation", cadence="continuous + quarterly summary"),
    regulator_gateway("RG-02", "UK FCA", "Consumer Duty + SS1/23 + SMCR SMF-AI", cadence="continuous + quarterly returns"),
    regulator_gateway("RG-03", "UK PRA", "SS1/23 + ICAAP AI add-on", cadence="quarterly + on-request"),
    regulator_gateway("RG-04", "US Fed Reserve", "SR 11-7 model inventory + validation evidence", cadence="quarterly + annual"),
    regulator_gateway("RG-05", "US OCC", "OCC 2011-12 model risk + AI/ML systems", cadence="quarterly + on-request"),
    regulator_gateway("RG-06", "US SEC", "17a-4 WORM evidence + 10-K/8-K cyber + Reg-SCI", cadence="on-event + quarterly"),
    regulator_gateway("RG-07", "FINRA", "3110/4511 supervision + recordkeeping", cadence="continuous + audit"),
    regulator_gateway("RG-08", "MAS Singapore", "FEAT principles + TRM 2021", cadence="quarterly + on-request"),
    regulator_gateway("RG-09", "HKMA Hong Kong", "GP-1 governance + GS-2 GenAI", cadence="quarterly + on-request"),
    regulator_gateway("RG-10", "OSFI Canada", "E-23 model risk + OSFI guideline", cadence="quarterly + annual"),
    regulator_gateway("RG-11", "FINMA Switzerland", "AI Guidance + circular updates", cadence="quarterly + on-request"),
    regulator_gateway("RG-12", "BaFin Germany", "AI Act implementation + MaRisk + BAIT", cadence="quarterly + on-request"),
    regulator_gateway("RG-13", "ACPR France", "AI Act + Solvency II AI add-on", cadence="quarterly + annual"),
    regulator_gateway("RG-14", "AMF France", "Algorithmic trading + MIF II AI", cadence="quarterly + on-request"),
    regulator_gateway("RG-15", "UK AISI", "Capability evals + RedTeam findings (GIEN)", cadence="continuous + quarterly summary"),
    regulator_gateway("RG-16", "US AISI (NIST)", "Capability evals + AI RMF evidence", cadence="continuous + quarterly summary"),
    regulator_gateway("RG-17", "Singapore AI Verify", "AI Verify framework + GIEN exchange", cadence="quarterly + on-request"),
    regulator_gateway("RG-18", "Japan AISI", "Capability evals + G7 Hiroshima evidence", cadence="quarterly + on-request"),
    regulator_gateway("RG-19", "Canada AISI", "Capability evals + AIDA implementation evidence", cadence="quarterly + on-request"),
]

# =========================================================================
# DISTINCTIVE ARRAY 10: roadmapItems (Phased 2026-2030) — 18 items
# =========================================================================
roadmapItems = [
    roadmap_item("RM-01", "2026Q1", "Foundation: AIMS scoping + ISO 42001 stage-1 audit + Hub MVP", deps=[]),
    roadmap_item("RM-02", "2026Q2", "Governance Sidecars + OPA bundles + Kafka aigov.* live", deps=["RM-01"]),
    roadmap_item("RM-03", "2026Q3", "WORM 25y + PQC migration kickoff + ARRE pilot (FCA + MAS)", deps=["RM-02"]),
    roadmap_item("RM-04", "2026Q4", "Sentinel Enterprise stack MVP + TLA+ MGK first proof + EAV v0.1", deps=["RM-02"]),
    roadmap_item("RM-05", "2027Q1", "Prompt Management & Reporting App productionized + Agent registry (A2A/MCP/ACP)", deps=["RM-02", "RM-04"]),
    roadmap_item("RM-06", "2027Q2", "ISO 42001 certification + ARRE coverage >=80% + Hub federation", deps=["RM-01", "RM-03"]),
    roadmap_item("RM-07", "2027Q3", "AGI Containment T3/T4 live + AISI MoUs (UK + US + EU)", deps=["RM-04"]),
    roadmap_item("RM-08", "2027Q4", "RedTeam external quarterly + RTRI >=0.9 + ARE production rollout", deps=["RM-05"]),
    roadmap_item("RM-09", "2028Q1", "CAS Registry + SR-DSL v1.0 + srdslc compiler emits Rego+WASM", deps=["RM-02", "RM-06"]),
    roadmap_item("RM-10", "2028Q2", "CAS-SPP pilot with EU AI Office + first zk-attestations", deps=["RM-09"]),
    roadmap_item("RM-11", "2028Q3", "AutonomousAgentFleet trading live (Tier 1 + ICAAP add-on)", deps=["RM-05", "RM-07"]),
    roadmap_item("RM-12", "2028Q4", "QKD telemetry between core DCs + sovereign failover drilled", deps=["RM-03"]),
    roadmap_item("RM-13", "2029Q1", "GIEN protocol live + federated exchange with peers + AISIs", deps=["RM-07"]),
    roadmap_item("RM-14", "2029Q2", "Global Systemic Risk Registry federated + first systemic report", deps=["RM-13"]),
    roadmap_item("RM-15", "2029Q3", "Regulator Audit Gateway live for 19 regulators + RCI=1.0 target", deps=["RM-10", "RM-13"]),
    roadmap_item("RM-16", "2029Q4", "CAS-SPP adoption broadened (FCA + MAS + HKMA + Fed)", deps=["RM-10", "RM-15"]),
    roadmap_item("RM-17", "2030Q2", "Civilizational layer (CEGL + LexAI-DSL + GASRGP/GASC) + GTI participation", deps=["RM-13", "RM-15"]),
    roadmap_item("RM-18", "2030Q4", "CGI >=0.75 + GTI >=0.85 + RCI =1.0 + program steady state", deps=["RM-17"]),
]

# =========================================================================
# DISTINCTIVE ARRAY 11: dependencies (DAG edges) — 17 items
# =========================================================================
dependencies = [
    dep("DEP-01", "RM-01", "RM-02", reason="AIMS + Hub required before Sidecar rollout"),
    dep("DEP-02", "RM-02", "RM-03", reason="Sidecars feed audit which feeds WORM + ARRE"),
    dep("DEP-03", "RM-02", "RM-04", reason="OPA + Kafka substrate required for Sentinel stack"),
    dep("DEP-04", "RM-04", "RM-07", reason="MGK + EAV required for T3/T4 containment"),
    dep("DEP-05", "RM-02", "RM-05", reason="Sidecars + OPA required for prompt app + agents"),
    dep("DEP-06", "RM-05", "RM-08", reason="Agent registry required for RedTeam coverage of agents"),
    dep("DEP-07", "RM-01", "RM-06", reason="ISO 42001 stage-1 -> certification path"),
    dep("DEP-08", "RM-03", "RM-06", reason="ARRE pilot evidence required for ISO 42001 cert"),
    dep("DEP-09", "RM-02", "RM-09", reason="OPA libraries required for CAS Registry + SR-DSL compiler"),
    dep("DEP-10", "RM-06", "RM-09", reason="ISO 42001 cert demonstrates control coverage required for CAS"),
    dep("DEP-11", "RM-09", "RM-10", reason="CAS + SR-DSL required for CAS-SPP zk-attestations"),
    dep("DEP-12", "RM-05", "RM-11", reason="Agent registry + interop required for trading fleet activation"),
    dep("DEP-13", "RM-07", "RM-11", reason="T3 containment required for autonomous trading Tier 1"),
    dep("DEP-14", "RM-03", "RM-12", reason="PQC migration must precede QKD telemetry rollout"),
    dep("DEP-15", "RM-07", "RM-13", reason="AISI MoUs required for GIEN federation"),
    dep("DEP-16", "RM-13", "RM-14", reason="GIEN required for Global Systemic Risk Registry federation"),
    dep("DEP-17", "RM-10", "RM-15", reason="CAS-SPP required for zk-verifiable Audit Gateway"),
]


# =========================================================================
# Standard tail collections
# =========================================================================

schemas = [
    {"name": "platformComponent.schema.json", "purpose": "P1 AI governance platform component"},
    {"name": "sentinelLayer.schema.json", "purpose": "P2 Sentinel Enterprise stack layer"},
    {"name": "containmentControl.schema.json", "purpose": "P2 AGI containment control"},
    {"name": "fiBlueprint.schema.json", "purpose": "P3 FI blueprint item"},
    {"name": "promptGovernance.schema.json", "purpose": "P4 prompt management governance item"},
    {"name": "cryptoSupervisionLayer.schema.json", "purpose": "P5 CAS/CAS-SPP/SR-DSL layer"},
    {"name": "deploymentArtifact.schema.json", "purpose": "P6 deployment artifact (IaC/PQC/QKD)"},
    {"name": "autonomousAgent.schema.json", "purpose": "P6 AutonomousAgentFleet member"},
    {"name": "regulatorGateway.schema.json", "purpose": "P6 regulator audit gateway endpoint"},
    {"name": "roadmapItem.schema.json", "purpose": "Phased roadmap milestone"},
    {"name": "dependency.schema.json", "purpose": "DAG edge between roadmap items"},
    {"name": "casRecord.schema.json", "purpose": "Control Assurance Specification record"},
    {"name": "casSppProof.schema.json", "purpose": "CAS-SPP cryptographic supervisory proof envelope"},
    {"name": "srDslRule.schema.json", "purpose": "SR-DSL supervisory rule AST"},
    {"name": "kpi.schema.json", "purpose": "KPI definition with target + cadence"},
    {"name": "evidence.schema.json", "purpose": "Evidence pack envelope"},
    {"name": "regulatorReport.schema.json", "purpose": "ARRE regulator report envelope"},
    {"name": "incidentRecord.schema.json", "purpose": "SEV-* incident record"},
    {"name": "redTeamFinding.schema.json", "purpose": "RedTeam finding with ATLAS/OWASP taxonomy"},
    {"name": "agentAttestation.schema.json", "purpose": "Per-action agent attestation (ML-DSA-87)"},
]

code = [
    {"lang": "rego", "name": "compliance/eu-ai-act/high_risk.rego", "purpose": "EU AI Act high-risk admission policy"},
    {"lang": "rego", "name": "compliance/sr-11-7/model_tier.rego", "purpose": "SR 11-7 model tier admission"},
    {"lang": "rego", "name": "compliance/fca-cd/consumer_duty.rego", "purpose": "FCA Consumer Duty outcome enforcement"},
    {"lang": "yaml", "name": "k8s/sidecars/policy-sidecar.yaml", "purpose": "OPA Envoy ext_authz sidecar deployment"},
    {"lang": "yaml", "name": "k8s/sidecars/audit-sidecar.yaml", "purpose": "Kafka audit producer sidecar"},
    {"lang": "terraform", "name": "modules/worm/main.tf", "purpose": "S3 Object Lock COMPLIANCE 25y"},
    {"lang": "terraform", "name": "modules/eks/main.tf", "purpose": "Bottlerocket + Karpenter EKS"},
    {"lang": "tla", "name": "specs/MGK.tla", "purpose": "TLA+ Minimal Governance Kernel specification"},
    {"lang": "tla", "name": "specs/MGK.cfg", "purpose": "TLC model-check config"},
    {"lang": "circom", "name": "zk/cas_spp.circom", "purpose": "CAS-SPP zk-SNARK circuit"},
    {"lang": "python", "name": "srdslc/compiler.py", "purpose": "SR-DSL -> Rego/WASM/zk compiler"},
    {"lang": "yaml", "name": "argocd/governance-app.yaml", "purpose": "Argo CD app for governance bundles"},
    {"lang": "yaml", "name": "tekton/sign-and-attest.yaml", "purpose": "Tekton Chains signing + in-toto"},
    {"lang": "json", "name": "schemas/casRecord.schema.json", "purpose": "CAS record JSON Schema"},
    {"lang": "graphql", "name": "hub/schema.graphql", "purpose": "Governance Hub GraphQL Federation"},
    {"lang": "sql", "name": "gql/examples/fca_consumer_duty.gql", "purpose": "GQL example: FCA Consumer Duty evidence"},
    {"lang": "yaml", "name": "siem/correlation-rules.yaml", "purpose": "SIEM correlation rules for aigov.* topics"},
    {"lang": "yaml", "name": "soar/playbooks/sev1-rollback.yaml", "purpose": "SOAR playbook for SEV-1+ auto-rollback"},
    {"lang": "yaml", "name": "qkd/link-monitor.yaml", "purpose": "QKD link health monitoring"},
    {"lang": "yaml", "name": "failover/sovereign-runbook.yaml", "purpose": "Sovereign AI failover runbook"},
]

kpis = [
    {"kpi": "AIMS-Coverage", "target": ">=0.95", "cadence": "quarterly"},
    {"kpi": "MRGI", "target": ">=0.95", "cadence": "quarterly"},
    {"kpi": "DRI", "target": ">=0.95 (n=10)", "cadence": "monthly"},
    {"kpi": "CCS", "target": ">=0.95", "cadence": "quarterly"},
    {"kpi": "ARI", "target": ">=0.9 (frontier)", "cadence": "per-release"},
    {"kpi": "CSI", "target": ">=0.95 (T3/T4)", "cadence": "monthly"},
    {"kpi": "RTRI", "target": ">=0.9", "cadence": "quarterly"},
    {"kpi": "CDC-Score", "target": ">=0.9", "cadence": "monthly"},
    {"kpi": "CSPI", "target": ">=0.95", "cadence": "continuous"},
    {"kpi": "ARRE-Coverage", "target": ">=0.98", "cadence": "quarterly"},
    {"kpi": "ARE-MTTR", "target": "<=15min for 80%", "cadence": "continuous"},
    {"kpi": "ZTC-Score", "target": ">=0.95", "cadence": "quarterly"},
    {"kpi": "PQC-Migration", "target": ">=0.95 by 2028", "cadence": "quarterly"},
    {"kpi": "QKD-Uptime", "target": ">=99.9% per link", "cadence": "monthly"},
    {"kpi": "SovFailover-RTO", "target": "<=15min", "cadence": "monthly drill"},
    {"kpi": "CGI", "target": ">=0.75 by 2030", "cadence": "annual"},
    {"kpi": "GTI", "target": ">=0.85 by 2030", "cadence": "annual"},
    {"kpi": "RCI", "target": "=1.0", "cadence": "quarterly"},
    {"kpi": "Sidecar-Latency-p99", "target": "<=8ms added", "cadence": "monthly"},
    {"kpi": "OPA-Decision-p99", "target": "<5ms", "cadence": "monthly"},
    {"kpi": "WORM-Durability", "target": "99.999999999% (11 9s)", "cadence": "annual"},
    {"kpi": "Audit-Loss-Rate", "target": "0", "cadence": "monthly"},
    {"kpi": "RedTeam-External-Cadence", "target": "Quarterly (Tier 1)", "cadence": "quarterly"},
    {"kpi": "ISO-42001-Surveillance", "target": "Annual + zero majors", "cadence": "annual"},
    {"kpi": "Breach-Isolate-MTTI", "target": "<60s", "cadence": "monthly drill"},
    {"kpi": "Breach-Rollback-MTTR", "target": "<15min for SEV-1+", "cadence": "monthly drill"},
    {"kpi": "Hub-Federation-Coverage", "target": ">=95% of FIN/RISK systems", "cadence": "quarterly"},
    {"kpi": "Agent-Kill-Switch-Drill", "target": "Monthly + 100% pass", "cadence": "monthly"},
    {"kpi": "ARRE-On-Time-Filing", "target": ">=99%", "cadence": "quarterly"},
    {"kpi": "CAS-Coverage", "target": ">=100% of in-scope controls", "cadence": "quarterly"},
    {"kpi": "SR-DSL-Compile-Success", "target": ">=99% on PR merge", "cadence": "monthly"},
    {"kpi": "zk-Attestation-Verify-Rate", "target": "=1.0 (regulator-side)", "cadence": "monthly"},
    {"kpi": "GIEN-Exchange-Coverage", "target": ">=80% of peer FIs by 2029", "cadence": "annual"},
    {"kpi": "Systemic-Risk-Registry-Coverage", "target": ">=70% of in-scope models by 2030", "cadence": "annual"},
]

riskControlMatrix = [
    {"risk": "Unsupervised AI actuation", "control": "OPA admission + MGK quorum", "owner": "CISO+CRO", "regimes": ["EU AI Act Art. 14", "SR 11-7"]},
    {"risk": "Audit tampering", "control": "WORM + Merkle + ML-DSA-87", "owner": "CISO", "regimes": ["SEC 17a-4", "DORA"]},
    {"risk": "Model drift", "control": "Drift telemetry + auto-rollback (ARE)", "owner": "CDAO+MRM", "regimes": ["NIST AI RMF MEASURE-3"]},
    {"risk": "PII leak in prompts", "control": "Redaction sidecar + linter ban list", "owner": "DPO", "regimes": ["GDPR"]},
    {"risk": "Prompt injection", "control": "RedTeam suite + filter + canary", "owner": "CISO", "regimes": ["OWASP LLM Top 10"]},
    {"risk": "Capability threshold crossing (frontier)", "control": "T4 + 3-of-5 quorum + AISI <=24h", "owner": "Board AI Chair", "regimes": ["EU AI Act Art. 55"]},
    {"risk": "Cryptographic compromise (classical)", "control": "PQC migration + ML-DSA-87 + ML-KEM-1024", "owner": "CISO", "regimes": ["CNSA 2.0"]},
    {"risk": "Cross-firm model concentration", "control": "GIEN exchange + Systemic Risk Registry", "owner": "CRO", "regimes": ["FSB AI guidance"]},
    {"risk": "Autonomous trading run-away", "control": "Position/VaR caps + kill-switch + MRM T1", "owner": "Head of Markets", "regimes": ["FCA SS1/23", "FRTB"]},
    {"risk": "Regulator data gap", "control": "ARRE + Audit Gateway + CAS-SPP", "owner": "CCO", "regimes": ["FCA SS1/23", "MAS FEAT"]},
    {"risk": "Air-gap breach", "control": "Hardware diode + signed channels + drills", "owner": "CISO", "regimes": ["EU AI Act Art. 55"]},
    {"risk": "MGK bypass", "control": "TLA+ NoBypass invariant + eBPF enforcement", "owner": "CISO", "regimes": ["ISO 42001 A.6"]},
    {"risk": "Vendor LLM data exfil", "control": "Procurement gating + sandbox + redaction", "owner": "CISO+CCO", "regimes": ["GDPR", "GLBA"]},
    {"risk": "Adverse-action disclosure failure", "control": "FCRA 615 + ECOA Reg-B reasons + GDPR Art-22", "owner": "CCO", "regimes": ["FCRA 615", "ECOA Reg-B", "GDPR Art-22"]},
    {"risk": "ICAAP capital under-estimation for AI", "control": "AI Pillar 2 add-on + scenario tests", "owner": "CRO", "regimes": ["Basel III/IV", "ICAAP"]},
    {"risk": "Sanctions miss", "control": "OPA-based sanction execution + quarterly list refresh", "owner": "Head of Sanctions", "regimes": ["OFAC", "FATF R.16"]},
    {"risk": "QKD link outage", "control": "Multi-vendor links + PQC fallback", "owner": "CISO", "regimes": ["CNSA 2.0", "ETSI QKD"]},
    {"risk": "Sovereign jurisdiction loss", "control": "3-jurisdiction sovereign failover + GovCloud", "owner": "CIO+CCO", "regimes": ["GDPR", "MAS Notice 658"]},
    {"risk": "AGI deception / goal misgen", "control": "EpistemicAlignmentVerifier + Apollo evals", "owner": "Head of AI Safety", "regimes": ["EU AI Act Art. 55", "G7 Hiroshima"]},
    {"risk": "Civilizational misalignment", "control": "CEGL + LexAI-DSL + GASRGP + GTI", "owner": "Board AI Chair", "regimes": ["CEGL", "GTI"]},
    {"risk": "Container/image supply chain", "control": "cosign + SLSA-3 + ML-DSA-87 + Sigstore Rekor", "owner": "CISO", "regimes": ["NIST SSDF"]},
    {"risk": "OPA policy drift", "control": "GitOps + signed bundles + ARE auto-revert", "owner": "Head of Platform", "regimes": ["NIST SSDF", "ISO 42001"]},
]

traceability = [
    {"from": "EU AI Act Art. 9", "to": "PC-10 (OPA Gatekeeper) + CC-15 (MGK invariants)"},
    {"from": "EU AI Act Art. 10", "to": "PC-04 (redaction sidecar) + PC-05 (lineage sidecar)"},
    {"from": "EU AI Act Art. 14", "to": "PC-11 (OPA Sidecar) + CC-08 (T3 dual-control)"},
    {"from": "EU AI Act Art. 15", "to": "PC-03 (telemetry sidecar) + DA-15 (OTel + Prometheus + Jaeger + OpenSearch)"},
    {"from": "EU AI Act Art. 53/55", "to": "SL-06 (L6 Evaluation) + CC-14 (AISI <=24h) + CC-15 (MGK)"},
    {"from": "NIST AI RMF GOVERN", "to": "FB-* + Hub + Codex (SL-09)"},
    {"from": "NIST AI RMF MAP", "to": "M3.1 (28-Regime Crosswalk) + CS-01 (Ontology)"},
    {"from": "NIST AI RMF MEASURE", "to": "SL-06 (Evals) + PG-08 (Monitoring)"},
    {"from": "NIST AI RMF MANAGE", "to": "PC-18 (ARE) + M6.8 (Breach Response) + M6.11 (Fleet)"},
    {"from": "ISO 42001 Clause 6", "to": "M2.1 (AIMS) + M3.4 (MRM)"},
    {"from": "ISO 42001 Annex A.6", "to": "PC-10/PC-11 (OPA) + CC-15 (MGK)"},
    {"from": "ISO 42001 Annex A.8", "to": "PC-05 (lineage) + DA-22 (provenance)"},
    {"from": "GDPR Art. 22", "to": "FB-08 + PG-02 + RG-01 (EU AI Office)"},
    {"from": "GDPR Art. 35", "to": "DPIA template + Hub workflow + M3.4"},
    {"from": "FCRA 615", "to": "FB-02 + adverse-action template + ARRE"},
    {"from": "ECOA Reg-B 1002", "to": "FB-02 + fairness telemetry + M3.4"},
    {"from": "SR 11-7", "to": "M2.1 (MRM) + M3.4 + AA-* (agent MRM tier)"},
    {"from": "OCC 2011-12", "to": "M2.1 + M3.4 + FB-11 (Vendor LLM)"},
    {"from": "Basel III/IV + ICAAP", "to": "FB-01 + M3.8 (Investment) + AA-* (trading agents)"},
    {"from": "FRTB", "to": "FB-03 + AA-01/02/03/04 (trading agents) + MRM T1"},
    {"from": "SEC 17a-4", "to": "PC-06/PC-07 (Kafka + WORM) + DA-10 (S3 Object Lock)"},
    {"from": "DORA Art. 17", "to": "PC-06 + PC-16 (sGQL) + M6.12 (SIEM/SOAR)"},
    {"from": "FCA Consumer Duty", "to": "FB-06 + PG-11 + RG-02 + M3.4"},
    {"from": "FCA SS1/23", "to": "FB-05 + AA-* (trading) + M6.5 + RG-02/RG-03"},
    {"from": "MAS FEAT", "to": "FB-* + PG-11 + RG-08 + M3.1"},
    {"from": "HKMA GP-1 + GS-2", "to": "FB-* + PG-11 + RG-09 + M3.1"},
    {"from": "G7 Hiroshima + Bletchley", "to": "SL-08 (AISI) + CC-14 + M5.7/M5.8 (CAS-SPP + interop)"},
    {"from": "CEGL + LexAI-DSL + GASRGP", "to": "FB-16 + RM-17 + civilizational outcomes (CGI/GTI)"},
    {"from": "NSA CNSA 2.0", "to": "DA-08/DA-09 (PQC) + PC-07 (WORM 5y re-sign) + RM-03"},
    {"from": "MITRE ATLAS", "to": "M2.10 (Adversarial) + DA-12 + M3.5 (RedTeam)"},
]

dataFlows = [
    {"flow": "App -> policy-sidecar (OPA ext_authz) -> allow/deny + decision log -> Kafka aigov.policy-decisions"},
    {"flow": "App -> redaction-sidecar -> tokenized payload -> downstream + tokenization-vault audit"},
    {"flow": "App -> audit-sidecar -> Kafka aigov.* -> Iceberg S3 -> WORM S3 Object Lock COMPLIANCE 25y"},
    {"flow": "App -> telemetry-sidecar -> OTel collector -> Prometheus + Jaeger + OpenSearch + drift/fairness store"},
    {"flow": "App -> lineage-sidecar -> OpenLineage -> Marquez/Hub + W3C PROV emission"},
    {"flow": "Sentinel evals -> aigov.cre + WORM + capability dashboard + AISI MoU dispatch"},
    {"flow": "Hub UI -> GraphQL Federation -> backend stitching (Hub API + ARRE + GQL + sGQL)"},
    {"flow": "ARRE -> templates engine -> per-regulator submission -> regulator portal + WORM evidence pack"},
    {"flow": "ARE -> bounded actions -> OPA admission -> dual-control SEV-1+ -> WORM audit + Hub incident view"},
    {"flow": "CAS Registry -> CAS-SPP service -> Merkle root + ML-DSA-87 sig -> zk-SNARK proof -> Sigstore Rekor commit -> Regulator Audit Gateway"},
    {"flow": "SR-DSL source -> srdslc -> Rego bundle + WASM filter + zk circuit -> Argo CD GitOps deploy"},
    {"flow": "AutonomousAgentFleet action -> per-action ML-DSA-87 attestation -> OPA capability bounds -> WORM audit -> Hub fleet view"},
    {"flow": "QKD link -> key delivery -> PQC fallback if degraded -> SEV-* on outage > thresholds"},
    {"flow": "Sovereign failover trigger -> Argo Rollouts cross-region -> DNS shift -> RTO <=15min -> WORM record"},
    {"flow": "GIEN exchange -> peer/AISI -> anonymized payload -> Hub view + Systemic Risk Registry feed"},
]

regulators = [
    {"name": "EU AI Office", "regime": "EU AI Act", "cadence": "continuous + quarterly summary"},
    {"name": "UK FCA", "regime": "Consumer Duty + SS1/23 + SMCR", "cadence": "continuous + quarterly returns"},
    {"name": "UK PRA", "regime": "SS1/23 + ICAAP", "cadence": "quarterly + on-request"},
    {"name": "US Fed Reserve", "regime": "SR 11-7", "cadence": "quarterly + annual"},
    {"name": "US OCC", "regime": "OCC 2011-12", "cadence": "quarterly + on-request"},
    {"name": "US SEC", "regime": "17a-4 + 10-K/8-K + Reg-SCI", "cadence": "on-event + quarterly"},
    {"name": "FINRA", "regime": "3110/4511", "cadence": "continuous + audit"},
    {"name": "MAS Singapore", "regime": "FEAT + TRM 2021", "cadence": "quarterly + on-request"},
    {"name": "HKMA Hong Kong", "regime": "GP-1 + GS-2", "cadence": "quarterly + on-request"},
    {"name": "OSFI Canada", "regime": "E-23", "cadence": "quarterly + annual"},
    {"name": "FINMA Switzerland", "regime": "AI Guidance", "cadence": "quarterly + on-request"},
    {"name": "BaFin Germany", "regime": "AI Act + MaRisk + BAIT", "cadence": "quarterly + on-request"},
    {"name": "ACPR France", "regime": "AI Act + Solvency II", "cadence": "quarterly + annual"},
    {"name": "AMF France", "regime": "Algo Trading + MIF II", "cadence": "quarterly + on-request"},
    {"name": "UK AISI", "regime": "Capability evals + GIEN", "cadence": "continuous"},
    {"name": "US AISI (NIST)", "regime": "Capability evals + AI RMF", "cadence": "continuous"},
    {"name": "Singapore AI Verify", "regime": "AI Verify + GIEN", "cadence": "quarterly + on-request"},
    {"name": "Japan AISI", "regime": "Capability evals + G7 Hiroshima", "cadence": "quarterly"},
    {"name": "Canada AISI", "regime": "Capability evals + AIDA", "cadence": "quarterly"},
]

rollout90 = [
    {"phase": "D0-30", "name": "Foundation", "actions": ["AIMS scoping", "OPA bundles seed", "Kafka aigov.* topics", "Hub MVP wireframes", "TLA+ MGK draft spec", "SR-DSL design doc", "QKD vendor SOW", "Sovereign failover region planning"]},
    {"phase": "D31-60", "name": "Pilot", "actions": ["Policy sidecar in staging", "Audit sidecar in staging", "WORM S3 Object Lock prov", "ARRE skeleton with FCA + MAS pilots", "Sentinel L1-L3 MVP", "Prompt registry MVP", "RedTeam smoke suite", "ARE policies drafted + paused"]},
    {"phase": "D61-90", "name": "Pre-Prod", "actions": ["Canary deploy sidecars to Tier 2", "ARRE first FCA filing draft", "TLA+ MGK first proof", "Hub federation MVP", "Agent registry MVP", "ISO 42001 stage-1 ready", "Board AI Risk Committee chartered + first meeting", "Regulator Audit Gateway pilot endpoint live"]},
]

roadmap = [
    {"phase": "Phase 1 (2026)", "items": ["RM-01 Foundation", "RM-02 Sidecars/OPA/Kafka", "RM-03 WORM/PQC/ARRE", "RM-04 Sentinel MVP"]},
    {"phase": "Phase 2 (2027 H1)", "items": ["RM-05 Prompt App + Agents", "RM-06 ISO 42001 cert"]},
    {"phase": "Phase 3 (2027 H2)", "items": ["RM-07 T3/T4 + AISI MoUs", "RM-08 RedTeam ext + ARE prod"]},
    {"phase": "Phase 4 (2028)", "items": ["RM-09 CAS + SR-DSL", "RM-10 CAS-SPP pilot", "RM-11 AutonomousAgentFleet trading", "RM-12 QKD + sovereign failover"]},
    {"phase": "Phase 5 (2029)", "items": ["RM-13 GIEN", "RM-14 Systemic Risk Registry", "RM-15 Audit Gateway 19 regs", "RM-16 CAS-SPP broadened"]},
    {"phase": "Phase 6 (2030)", "items": ["RM-17 Civilizational layer", "RM-18 Steady state CGI/GTI/RCI"]},
]

evidencePack = [
    {"item": "ISO 42001 management review + stage-1 + stage-2 audit reports"},
    {"item": "EU AI Act Annex IV technical documentation (per high-risk system)"},
    {"item": "GPAI Art. 53/55 evals + adversarial testing + cybersecurity + incident reports"},
    {"item": "NIST AI RMF GOVERN/MAP/MEASURE/MANAGE evidence per Tier 1+2 model"},
    {"item": "SR 11-7 model inventory + validation reports + MRM tier letters"},
    {"item": "OCC 2011-12 model risk + vendor LLM attestations"},
    {"item": "Basel III/IV ICAAP AI Pillar 2 add-on + scenario tests"},
    {"item": "FCA Consumer Duty PRIN 2A outcome reports + CDC-Score telemetry"},
    {"item": "FCA/PRA SS1/23 returns + SMCR SMF-AI letters"},
    {"item": "MAS FEAT self-assessment + TRM 2021 attestations"},
    {"item": "HKMA GP-1 + GS-2 attestations"},
    {"item": "SEC 17a-4 WORM evidence + 10-K/8-K cyber disclosures"},
    {"item": "DORA major-incident reports + NIS2 attestations"},
    {"item": "GDPR DPIAs + Art-22 disclosures + Art-35 evidence"},
    {"item": "FCRA 615 adverse-action templates + ECOA fairness reports"},
    {"item": "AISI bilateral MoUs + capability eval reports (UK + US + EU + SG + JP + CA)"},
    {"item": "GIEN exchange logs + peer attestations"},
    {"item": "CAS-SPP zk-attestation receipts (per regulator)"},
    {"item": "WORM audit chain-of-custody + 25y retention attestations"},
    {"item": "Board AI Risk Committee minutes + Board minutes + annual AI Risk Report"},
    {"item": "AutonomousAgentFleet kill-switch drill logs + ICAAP add-on capital memos"},
    {"item": "RedTeam external quarterly reports + bounty program statistics"},
    {"item": "QKD link uptime reports + sovereign failover drill logs"},
    {"item": "Civilizational reports (CEGL participation, GTI scores, CGI evidence)"},
]

executiveSummary = {
    "tagline": "End-to-end 2026-2030 AI governance + cryptographic supervision for G-SIFIs — production-ready across six integrated pillars",
    "investment": "USD 250-650M / 5y per G-SIFI; NPV USD 700-1900M",
    "uplift_vs_WP059": "USD 50-100M envelope; USD 100-200M NPV from CAS-SPP + ARE automation + QKD + sovereign failover",
    "topThree": [
        "Operationalize CAS-SPP cryptographic supervisory proofs to all 19 regulators by 2029",
        "Stand up AutonomousAgentFleet with TLA+ MGK + kill-switches + ICAAP add-on by 2028",
        "Anchor civilizational layer (CEGL/LexAI-DSL/GASRGP + GTI) with CGI >=0.75 by 2030"
    ],
    "ninetyDayWins": [
        "OPA sidecar in staging + Kafka aigov.* live + WORM S3 Object Lock proved",
        "ARRE pilot filing for FCA + MAS",
        "Sentinel MVP L1-L3 + TLA+ MGK draft",
        "Hub MVP federated to 3 critical systems",
        "Board AI Risk Committee chartered + first meeting"
    ],
    "boardAsks": [
        "Approve USD 250-650M / 5y program envelope",
        "Designate SMF-AI under SMCR",
        "Charter Board AI Risk Committee + GIEN representation + AGI containment T4 protocol",
        "Ratify CAS-SPP regulator pilot + AutonomousAgentFleet trading activation criteria",
        "Mandate ISO 42001 certification by 2027 and PQC migration >=0.95 by 2028"
    ],
}

# =========================================================================
# Final assembly
# =========================================================================
DOC["modules"] = MODULES
DOC["platformComponents"] = platformComponents
DOC["sentinelLayers"] = sentinelLayers
DOC["containmentControls"] = containmentControls
DOC["fiBlueprints"] = fiBlueprints
DOC["promptGovernance"] = promptGovernance
DOC["cryptoSupervisionLayers"] = cryptoSupervisionLayers
DOC["deploymentArtifacts"] = deploymentArtifacts
DOC["autonomousAgents"] = autonomousAgents
DOC["regulatorGateways"] = regulatorGateways
DOC["roadmapItems"] = roadmapItems
DOC["dependencies"] = dependencies
DOC["schemas"] = schemas
DOC["code"] = code
DOC["kpis"] = kpis
DOC["riskControlMatrix"] = riskControlMatrix
DOC["traceability"] = traceability
DOC["dataFlows"] = dataFlows
DOC["regulators"] = regulators
DOC["rollout90"] = rollout90
DOC["roadmap"] = roadmap
DOC["evidencePack"] = evidencePack
DOC["executiveSummary"] = executiveSummary

DOC["counts"] = {
    "modules": len(MODULES),
    "sections": sum(len(m["sections"]) for m in MODULES),
    "platformComponents": len(platformComponents),
    "sentinelLayers": len(sentinelLayers),
    "containmentControls": len(containmentControls),
    "fiBlueprints": len(fiBlueprints),
    "promptGovernance": len(promptGovernance),
    "cryptoSupervisionLayers": len(cryptoSupervisionLayers),
    "deploymentArtifacts": len(deploymentArtifacts),
    "autonomousAgents": len(autonomousAgents),
    "regulatorGateways": len(regulatorGateways),
    "roadmapItems": len(roadmapItems),
    "dependencies": len(dependencies),
    "schemas": len(schemas),
    "code": len(code),
    "kpis": len(kpis),
    "riskControlMatrix": len(riskControlMatrix),
    "traceability": len(traceability),
    "dataFlows": len(dataFlows),
    "regulators": len(regulators),
    "rollout90": len(rollout90),
    "roadmap": len(roadmap),
    "evidencePack": len(evidencePack),
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump(DOC, f, indent=2)

print(f"WP-060 JSON written: {OUT}")
print(f"Size: {os.path.getsize(OUT):,} bytes ({os.path.getsize(OUT)/1024:.1f} KB)")
print(f"Counts: {DOC['counts']}")
