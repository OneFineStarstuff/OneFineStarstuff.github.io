#!/usr/bin/env python3
"""
WP-058: Enterprise AI/AGI Governance Framework for Large Financial & Fortune 500
Enterprises (2026-2030)
"""
import json, os

OUT = os.path.join(os.path.dirname(__file__), "data", "enterprise-aigov-framework.json")

DOC = {
    "docRef": "ENTERPRISE-AIGOV-FRAMEWORK-WP-058",
    "version": "1.0.0",
    "title": "Enterprise AI/AGI Governance Framework for Large Financial & Fortune 500 Enterprises (2026-2030)",
    "horizon": "2026-2030",
    "apiPrefix": "/api/enterprise-aigov-framework",
    "buildsOn": ["WP-035", "WP-040", "WP-045", "WP-050", "WP-054", "WP-055", "WP-056", "WP-057"],
    "status": "regulator-submission-grade",
    "classification": "Confidential / Restricted — Board, CRO, CCO, CISO, CDAO, Group Internal Audit, External Regulators (on request)",
    "directive": {
        "scope": "End-to-end enterprise AI/AGI governance operating model for Fortune 500 / Global 2000 / G-SIFIs spanning policy, control, risk, compliance, security, model risk, third-party, AGI containment, and AI Governance Hub architecture",
        "outcomes": [
            "ISO/IEC 42001:2023 certified AIMS by 2027 across all material AI systems",
            "NIST AI RMF 1.0 + AI 600-1 generative profile mapped to >=95% of in-scope models",
            "EU AI Act 2026 Article 6/9/10/14/15 + GPAI 53/55 obligations fully evidenced",
            "GDPR DPIA + Article 22 + FCRA/ECOA adverse-action automation in production",
            "Basel III/IV + SR 11-7 + OCC 2011-12 model risk lifecycle managed in single MRM platform",
            "FCA Consumer Duty + SMCR SMF-attested AI accountability operating model",
            "MAS FEAT + HKMA GP-1/GS-2 fairness, ethics, accountability, transparency in production",
            "Kafka audit log with WORM + PQC sealing across all model decisions",
            "Kubernetes + container security with policy-as-code (OPA/Rego) at admission and runtime",
            "AGI containment T0-T4 with 3-of-5 quorum + kinetic override and AI Safety Institute notifications"
        ],
        "doNot": [
            "Do NOT deploy any AI/AGI capability without Enterprise AI Governance Hub registration, ISO 42001 risk assessment, and model risk tier classification",
            "Do NOT bypass Kafka audit logging, OPA/Rego policy gates, WORM/PQC sealing, or 3-of-5 frontier quorum"
        ]
    },
    "regimes": [
        "ISO/IEC 42001:2023 AIMS",
        "ISO/IEC 23894:2023 AI Risk",
        "ISO/IEC 27001:2022 ISMS",
        "ISO/IEC 27701:2019 PIMS",
        "NIST AI RMF 1.0",
        "NIST AI 600-1 Generative AI Profile",
        "NIST SP 800-53 Rev.5",
        "NIST SP 800-218 SSDF",
        "OECD AI Principles 2019/2024",
        "EU AI Act 2024/1689",
        "EU AI Act GPAI Art. 53/55",
        "EU GDPR + Art. 22",
        "EU DORA",
        "EU NIS2",
        "EU CRA",
        "US FCRA + ECOA Reg-B",
        "US Fed SR 11-7 + OCC 2011-12",
        "Basel III/IV + ICAAP",
        "US SEC 17a-4 + 10-K/8-K",
        "FINRA 3110/4511",
        "UK FCA Consumer Duty",
        "UK SMCR + SS1/23",
        "MAS FEAT + TRM 2021",
        "HKMA GP-1 + GS-2",
        "OSFI E-23",
        "FINMA AI Guidance",
        "G7 Hiroshima Process",
        "Bletchley/Seoul/Paris Declarations"
    ],
    "indices": {
        "AIMS-Coverage": ">=0.95 (ISO 42001 controls)",
        "MRGI": ">=0.95 (Model Risk Governance Index, SR 11-7 + OCC 2011-12)",
        "DRI": ">=0.95 (Decision Reproducibility, n=10)",
        "CCS": ">=0.95 (Control Coverage Score)",
        "ARI": ">=0.9 (Alignment Robustness Index, frontier)",
        "CSI": ">=0.95 (Containment Sufficiency, T3/T4)",
        "RTRI": ">=0.9 (Red-Team Resilience Index)",
        "CDC-Score": ">=0.9 (FCA Consumer Duty compliance)",
        "RCI": "=1.0 (Regulator Confidence Index)"
    },
    "tiers": {
        "T0": "Sandbox - isolated VPC, synthetic data only, no production traffic",
        "T1": "Staging - shadow mode, real data, no customer impact",
        "T2": "Canary - <=1% production traffic, automated rollback",
        "T3": "Production - Nitro Enclaves + KMS + dual control + full audit",
        "T4": "Frontier Air-Gapped - 3-of-5 quorum + kinetic override + AI Safety Institute notification"
    },
    "severities": {
        "SEV-0": "Civilizational/systemic - EU AI Office notification <=15d, AISI notification <=24h",
        "SEV-1": "Major - SEC 8-K <=4 BD, DORA <=4h, FCA <=72h",
        "SEV-2": "Material - regulator notification <=72h",
        "SEV-3": "Operational - internal escalation <=10 BD"
    },
    "investment": {
        "envelope": "USD 180-500M / 5y (Fortune 500 / G-SIFI tier)",
        "NPV": "USD 500-1500M (5y, risk-adjusted)",
        "drivers": [
            "MRM platform consolidation",
            "AI Governance Hub build",
            "Kafka audit + WORM/PQC sealing",
            "Kubernetes + OPA/Rego at scale",
            "AGI containment T3/T4 enclaves",
            "Red-teaming program",
            "Regulator attestation tooling"
        ]
    },
    "counts": {}
}

# ---------- Typed helpers ----------
def section(sid, title, **body):
    return {"sid": sid, "title": title, **body}

def module(mid, title, summary, sections):
    return {"mid": mid, "title": title, "summary": summary, "sections": sections}

def policy(pid, domain, statement, **body):
    return {"pid": pid, "domain": domain, "statement": statement, **body}

def control(cid, family, control, **body):
    return {"cid": cid, "family": family, "control": control, **body}

def kafka_topic(tid, name, schema, **body):
    return {"tid": tid, "name": name, "schema": schema, **body}

def k8s_control(kid, area, mechanism, **body):
    return {"kid": kid, "area": area, "mechanism": mechanism, **body}

def opa_policy(oid, area, rego_ref, **body):
    return {"oid": oid, "area": area, "regoRef": rego_ref, **body}

def worm_control(wid, layer, mechanism, **body):
    return {"wid": wid, "layer": layer, "mechanism": mechanism, **body}

def mrm_artifact(mid_, lifecycle, artifact, **body):
    return {"mid": mid_, "lifecycle": lifecycle, "artifact": artifact, **body}

def red_team(rid, vector, technique, **body):
    return {"rid": rid, "vector": vector, "technique": technique, **body}

def agi_containment(aid, tier, mechanism, **body):
    return {"aid": aid, "tier": tier, "mechanism": mechanism, **body}

def hub_component(hid, layer, component, **body):
    return {"hid": hid, "layer": layer, "component": component, **body}

# =========================================================================
# M1 — ISO/IEC 42001 AIMS + NIST AI RMF + OECD + EU AI Act Foundation
# =========================================================================
m1 = module("M1",
    "ISO/IEC 42001 AIMS + NIST AI RMF + OECD + EU AI Act Foundation",
    "Integrated AI Management System anchored on ISO/IEC 42001:2023 with NIST AI RMF 1.0 functions (Govern/Map/Measure/Manage), OECD AI Principles, and EU AI Act 2024/1689 Article 6/9/10/14/15 + GPAI 53/55 mappings.",
    [
        section("M1.1", "ISO/IEC 42001 AIMS Architecture",
            policyCommit="Board-attested AI Policy, AI Objectives, AI Risk Appetite Statement signed annually by Group CEO + Group CRO",
            scope="All AI/AGI systems with material impact on customers, employees, regulators, capital, or systemic risk",
            structure="AIMS clauses 4-10 mapped to enterprise functions: Context (Strategy), Leadership (CDAO+CRO), Planning (PMO), Support (HR+Procurement+IT), Operation (Lines of Business), Performance (Internal Audit), Improvement (CCO)"),
        section("M1.2", "NIST AI RMF 1.0 + AI 600-1 Generative Profile",
            functions=["GOVERN", "MAP", "MEASURE", "MANAGE"],
            generativeProfile="NIST AI 600-1 mapped to all FM/LLM use cases with synthetic content provenance (C2PA)",
            crossWalk="Bidirectional crosswalk ISO 42001 <-> NIST AI RMF <-> EU AI Act maintained in MRM platform"),
        section("M1.3", "OECD AI Principles 2019/2024 Implementation",
            principles=["Inclusive growth", "Human-centered values", "Transparency", "Robustness", "Accountability"],
            implementation="OECD-aligned model cards + system cards published for all T2+ systems with public-facing summary"),
        section("M1.4", "EU AI Act 2024/1689 Compliance Layer",
            riskClasses=["Unacceptable (Art. 5)", "High-risk (Art. 6/Annex III)", "Limited-risk (Art. 50)", "Minimal-risk"],
            highRiskObligations=["Art. 9 risk mgmt", "Art. 10 data governance", "Art. 14 human oversight", "Art. 15 accuracy/robustness/cybersecurity"],
            gpai=["Art. 53 technical documentation + copyright policy", "Art. 55 systemic-risk: evaluations, adversarial testing, cybersecurity, incident reporting"],
            timeline="Prohibited practices Feb 2025; GPAI Aug 2025; high-risk Aug 2026"),
        section("M1.5", "Board + Executive Accountability",
            committees=["Board AI Risk Committee (quarterly)", "Executive AI Governance Committee (monthly)", "AI Ethics Council (monthly)", "Model Risk Committee (weekly)"],
            roles={"AI-SMF (SMF-AI)": "FCA-attested senior manager", "CDAO": "Operating accountability", "CRO": "Risk appetite owner", "CCO": "Regulatory engagement", "CISO": "Cybersecurity + integrity", "GIA": "Independent assurance"}),
    ])

# =========================================================================
# M2 — Financial-Services Model Risk (SR 11-7, OCC 2011-12, Basel III/IV, ICAAP)
# =========================================================================
m2 = module("M2",
    "Financial-Services Model Risk Management (SR 11-7 / OCC 2011-12 / Basel III/IV / ICAAP)",
    "Three-lines-of-defense model risk operating model with SR 11-7 conceptual soundness, ongoing monitoring, outcomes analysis; OCC 2011-12 effective challenge; Basel III/IV IRB/IMA model validation; ICAAP integration with Pillar 2.",
    [
        section("M2.1", "Model Risk Lifecycle",
            stages=["Identification", "Development", "Validation", "Approval", "Implementation", "Monitoring", "Retirement"],
            tiering="Tier-1 (regulatory capital, P&L, capital plan) / Tier-2 (material business) / Tier-3 (limited scope) / Tier-4 (research)",
            cadence="Tier-1 annual validation; Tier-2 biennial; Tier-3 every 3y; ongoing monitoring monthly for all"),
        section("M2.2", "SR 11-7 + OCC 2011-12 Effective Challenge",
            conceptualSoundness="Independent review of theory, assumptions, design choices",
            ongoingMonitoring=["Backtesting", "Benchmarking", "Sensitivity analysis", "Stress testing"],
            outcomesAnalysis="Champion/challenger + counterfactual analysis on production decisions"),
        section("M2.3", "Basel III/IV IRB/IMA + FRTB",
            scope=["PD/LGD/EAD IRB models", "VaR/ES IMA models (FRTB)", "AMA op-risk (legacy)", "CCAR/DFAST stress models", "IFRS 9/CECL ECL models"],
            validation="Independent validation per SR 15-19/SR 15-18; quantitative review every cycle",
            capitalImpact="MRM platform feeds Pillar 2 model risk capital add-on into ICAAP"),
        section("M2.4", "AI/ML-Specific MRM Extensions",
            extensions=[
                "Concept drift + data drift monitoring (PSI, KS, KL, Wasserstein)",
                "Fairness across protected classes (FCRA/ECOA aligned)",
                "Explainability evidence (SHAP/LIME/integrated gradients) per decision",
                "Adversarial robustness testing (PGD, BIM, NLP attacks)",
                "Provenance of training data + lineage to feature store"
            ]),
        section("M2.5", "ICAAP / Pillar 2 Integration",
            integration="Aggregate model risk capital + AI-specific add-ons fed into ICAAP Pillar 2 alongside operational, reputational, strategic risk",
            governance="MRC quarterly review of capital adequacy; Board-attested annual ICAAP includes AI risk section"),
    ])

# =========================================================================
# M3 — GDPR / FCRA / ECOA / Consumer Protection
# =========================================================================
m3 = module("M3",
    "Data Protection & Consumer Fairness (GDPR / FCRA / ECOA / FCA Consumer Duty)",
    "Privacy-by-design with GDPR Article 22 (automated decisions), FCRA adverse-action notices, ECOA Reg-B disparate impact testing, FCA Consumer Duty cross-cutting rules + four outcomes; MAS FEAT + HKMA GP-1 fairness operationalization.",
    [
        section("M3.1", "GDPR Article 22 + DPIA Operationalization",
            dpia="DPIA required for all T2+ models processing personal data; reviewed by DPO + Group Legal",
            article22={"prohibition": "No solely automated decisions producing legal/significant effects without explicit consent or necessity", "rights": ["Human intervention", "Express view", "Contest decision"], "logging": "All Art-22 invocations logged to Kafka audit topic"},
            crossBorder="EU SCC + UK IDTA + adequacy assessments documented in ROPA"),
        section("M3.2", "FCRA + ECOA Reg-B Adverse-Action Automation",
            adverseAction="Automated FCRA 615(a) + ECOA Reg-B section 1002.9 notices generated within 30 days of adverse decision",
            reasonCodes="Top-N reason codes derived from SHAP attribution, mapped to plain-English statements vetted by Compliance Legal",
            disparateImpact="Quarterly disparate-impact analysis on credit, hiring, insurance models (race, sex, age, national origin)"),
        section("M3.3", "FCA Consumer Duty + Cross-Cutting Rules",
            outcomes=["Products & services", "Price & value", "Consumer understanding", "Consumer support"],
            crossCutting=["Act in good faith", "Avoid foreseeable harm", "Enable customers to pursue financial objectives"],
            evidence="Consumer Duty Board Report annual; AI-driven personalization included with foreseeable-harm assessment",
            vulnerableCustomers="Vulnerable-customer flag piped to AI systems; fairness uplift required where applicable"),
        section("M3.4", "MAS FEAT + HKMA GP-1 / GS-2",
            feat=["Fairness", "Ethics", "Accountability", "Transparency"],
            hkmaGP1="Governance of AI applications in banking — board-level accountability, risk management, fair treatment",
            hkmaGS2="Generative AI applications guidance — data governance, model governance, human oversight, cybersecurity"),
        section("M3.5", "Privacy-Enhancing Technologies (PETs)",
            pets=["Differential privacy (epsilon budgets per dataset)", "Federated learning with secure aggregation", "Homomorphic encryption (CKKS/BGV)", "Secure multi-party computation", "Confidential computing (AMD SEV-SNP, Intel TDX, AWS Nitro)"],
            policy="PETs mandated for cross-border training and any T3 model handling special category data"),
    ])

# =========================================================================
# M4 — Kafka Audit Logging + WORM + PQC
# =========================================================================
m4 = module("M4",
    "Kafka-Based Audit Logging + WORM Storage + Post-Quantum Cryptography",
    "Enterprise-wide tamper-evident audit log over Apache Kafka with WORM (S3 Object Lock COMPLIANCE / Azure Immutable / GCS Bucket Lock) and PQC-signed seals (ML-DSA / ML-KEM / SLH-DSA) per NIST FIPS 203/204/205.",
    [
        section("M4.1", "Kafka Audit Topic Architecture",
            topics=["aigov.decisions", "aigov.policy-changes", "aigov.model-lifecycle", "aigov.access", "aigov.containment-events", "aigov.regulator-notifications"],
            retention="Hot 90d in Kafka tiered storage; cold WORM 7-25y per regime (SEC 17a-4 7y, GDPR varies, FINRA 6y, DORA 5y)",
            partitioning="By LOB + decisionId; replication factor 3 across AZs; minISR=2; producer acks=all"),
        section("M4.2", "Tamper-Evident Sealing",
            chain="Each record hashed (SHA-3-512); merkle-tree aggregated per minute; root signed with ML-DSA-87 (FIPS 204) + SLH-DSA fallback",
            anchoring="Daily merkle root anchored to QLDB + external timestamp authority (TSA RFC 3161) + optional public chain",
            verification="Independent verifier service replays Kafka offsets and recomputes merkle roots on demand"),
        section("M4.3", "WORM Storage Tier",
            backends=["AWS S3 Object Lock COMPLIANCE mode", "Azure Blob immutable storage policy", "GCS Bucket Lock", "On-prem Dell ECS / NetApp SnapLock Compliance"],
            policy="Legal-hold + retention-lock dual control; no delete path even for root accounts; SEC 17a-4(f) WORM attestation by independent third party"),
        section("M4.4", "Post-Quantum Cryptography Stack",
            algorithms=["ML-KEM-1024 (FIPS 203) for key encapsulation", "ML-DSA-87 (FIPS 204) for signatures", "SLH-DSA-SHA2-256s (FIPS 205) as conservative fallback"],
            hybrid="Hybrid TLS classical+PQ during transition (X25519+ML-KEM-768) per NSA CNSA 2.0 timeline 2025-2033",
            keyMgmt="HSM-backed (AWS CloudHSM / Azure Dedicated HSM / Thales Luna 7) with FIPS 140-3 Level 3"),
        section("M4.5", "Audit Query + Regulator Access",
            queryLayer="ksqlDB + Trino over Iceberg on WORM; row-level filters per LOB + regulator scope",
            regulatorPortal="Read-only portal for EU AI Office, FCA, MAS, HKMA, SEC, FINRA with audit-of-audit logging",
            sla="Regulator query response <=24h; bulk export <=72h"),
    ])

# =========================================================================
# M5 — Container / Kubernetes Security
# =========================================================================
m5 = module("M5",
    "Container & Kubernetes Security for AI Workloads",
    "Defense-in-depth for AI model serving on Kubernetes spanning image supply chain (SLSA L4), admission control, runtime security, network policy, secrets, and confidential containers.",
    [
        section("M5.1", "Image Supply Chain (SLSA L4 / SSDF)",
            controls=["Cosign signatures on all images", "SBOM (SPDX/CycloneDX) per image", "Vulnerability scanning (Trivy/Snyk/Prisma) in CI", "Provenance attestations (in-toto)", "Sigstore Rekor transparency log"],
            policyGate="Kyverno/OPA admission rejects unsigned, unscanned, or non-policy-compliant images"),
        section("M5.2", "Admission Control + Pod Security",
            psa="Pod Security Admission 'restricted' profile cluster-wide for AI namespaces",
            policyEngines=["Kyverno", "OPA Gatekeeper", "Validating admission policies (VAP)"],
            controls=["No privileged", "No host network/PID/IPC", "Read-only root FS", "Non-root UID", "Seccomp RuntimeDefault", "Drop ALL capabilities"]),
        section("M5.3", "Runtime Security",
            tools=["Falco for syscall anomaly detection", "Tetragon eBPF for kernel-level enforcement", "Cilium for network policy + observability"],
            response="Auto-isolation + Kafka aigov.containment-events on anomaly; SRE+SecOps page within 5 min"),
        section("M5.4", "Network Policy + Service Mesh",
            netpol="Default-deny Cilium NetworkPolicy + L7 HTTP/gRPC filtering",
            mesh="Istio/Linkerd mTLS for service-to-service; SPIFFE/SPIRE workload identities",
            egress="Per-namespace egress allowlist with FQDN policies; DNS over HTTPS"),
        section("M5.5", "Confidential Containers + Secrets",
            confidential="Confidential containers (CoCo) on AMD SEV-SNP / Intel TDX / AWS Nitro Enclaves for T3/T4 workloads",
            secrets=["Vault (HashiCorp) with auto-rotation", "AWS Secrets Manager / Azure Key Vault for cloud", "SOPS+age for GitOps", "External Secrets Operator"],
            kms="Per-tenant KMS keys; envelope encryption; key rotation 90d"),
    ])

# =========================================================================
# M6 — Policy-as-Code (OPA/Rego)
# =========================================================================
m6 = module("M6",
    "Policy-as-Code with OPA/Rego",
    "Unified policy plane using OPA/Rego for admission control, runtime authorization, data access, model deployment gates, and regulator-facing evidence. Includes Conftest CI, OPAL bundle distribution, and decision logging to Kafka.",
    [
        section("M6.1", "OPA/Rego Policy Architecture",
            layers=["Build-time (Conftest in CI)", "Admission (Gatekeeper/Kyverno+Rego)", "Runtime (Envoy ext_authz + OPA sidecar)", "Data plane (PostgreSQL/Kafka ACL via OPA)"],
            distribution="OPAL pulls bundles from Git; signed bundles via Cosign; rollout via GitOps (Argo CD)"),
        section("M6.2", "Model Deployment Gates",
            gates=[
                "ISO 42001 risk assessment complete",
                "Model card + system card published",
                "MRM validation status approved",
                "DPIA approved if PII",
                "Red-team report on file",
                "EU AI Act risk class declared",
                "FCRA/ECOA fairness report attached for credit models"
            ],
            failureMode="Deployment blocked at Argo CD; aigov.policy-changes Kafka topic records denial with rationale"),
        section("M6.3", "Runtime Authorization",
            envoy="ext_authz to OPA sidecar; sub-ms decision latency; cached with TTL",
            attributes=["User identity (OIDC/JWT)", "Resource sensitivity (data class)", "Purpose (purpose limitation per GDPR Art. 5)", "Time of day", "Geo"],
            denyLog="All deny decisions Kafka aigov.access; sample of allow decisions for spot-audit"),
        section("M6.4", "Data Access + Purpose Limitation",
            policy="GDPR purpose-limitation enforced as Rego: each query must declare purposeId from approved catalog; mismatch = deny",
            piiPolicy="PII columns tagged via data catalog (Atlan/Collibra); OPA enforces masking/tokenization based on consumer role + purpose",
            crossBorder="Rego enforces data-residency: EU PII can only flow to EU compute; logged + alertable"),
        section("M6.5", "Regulator Evidence Generation",
            evidence="OPA decision log + bundle signatures + Git history produce regulator-grade evidence pack on demand",
            attestations="Quarterly attestations to EU AI Office, FCA, MAS, HKMA, SEC with OPA decision log extracts",
            opaBundleHash="Bundle SHA-256 + ML-DSA signature pinned per deployment generation"),
    ])

# =========================================================================
# M7 — AI Red-Teaming Program
# =========================================================================
m7 = module("M7",
    "AI Red-Teaming Program (Frontier + Production)",
    "Continuous adversarial evaluation across pre-deployment, deployment, and post-deployment phases covering jailbreaks, prompt injection, data exfiltration, model extraction, poisoning, evasion, fairness probes, and AGI/ASI capability elicitation.",
    [
        section("M7.1", "Red-Team Operating Model",
            structure="Internal red team (10-25 FTE) + external firms (e.g., Trail of Bits, NCC, Bishop Fox) + crowdsourced (HackerOne private programs)",
            governance="Reports to CISO + CDAO; independent of MRM and engineering; quarterly board readout",
            scope=["All T2+ models pre-deployment", "T3/T4 continuously", "GPAI frontier models monthly per EU AI Act Art. 55"]),
        section("M7.2", "Attack Taxonomy",
            taxonomy=[
                "Prompt injection (direct / indirect / multimodal)",
                "Jailbreaks (DAN, AIM, multilingual, encoded)",
                "Data exfiltration (training data extraction, memorization probes)",
                "Model extraction / stealing",
                "Membership inference",
                "Backdoor / poisoning",
                "Evasion (adversarial examples, perturbation attacks)",
                "Fairness / disparate impact probes",
                "Tool-use abuse (agentic models)",
                "Capability elicitation (AGI-specific)"
            ],
            frameworks=["MITRE ATLAS", "OWASP LLM Top 10 (2025)", "NIST AI 100-2 Adversarial ML Taxonomy"]),
        section("M7.3", "Evaluations Suite",
            evals=[
                "HELM / BIG-bench / MMLU benchmarks",
                "TruthfulQA / TruthfulQA-Adversarial",
                "ToxiGen / RealToxicityPrompts",
                "BOLD / StereoSet / WinoBias / WinoGender",
                "AgentBench / SWE-bench for tool-use",
                "ARC Evals dangerous-capability suite for frontier",
                "Custom domain-specific evals for finance / health / legal"
            ],
            cadence="Pre-deployment full suite; monthly drift for T2+; weekly for T3/T4"),
        section("M7.4", "AGI Capability Elicitation",
            method="Apollo Research / METR-style dangerous-capability evals: persuasion, deception, self-replication, autonomous coding, weapons-of-mass-destruction uplift, cyber offense, AI R&D",
            triggers="Capability score crossing predefined thresholds triggers SEV-0 review + AISI notification within 24h",
            mitigation="Capability suppression via fine-tuning / RLHF / circuit-level interventions; deployment hold pending Board review"),
        section("M7.5", "Reporting + Remediation",
            reporting="Standardized red-team report: findings, CVSS-style severity, exploitability, business impact, remediation plan",
            sla="Critical <=7d, high <=30d, medium <=90d, low <=180d",
            evidence="All findings + remediation in Kafka aigov.policy-changes + linked to MRM platform issue tracker"),
    ])

# =========================================================================
# M8 — AGI Containment Strategies
# =========================================================================
m8 = module("M8",
    "AGI / ASI Containment Strategies",
    "Tiered containment T0-T4 with 3-of-5 human quorum, kinetic override, formally-verified safety properties, and AI Safety Institute coordination for frontier systems approaching AGI/ASI thresholds.",
    [
        section("M8.1", "Tier-Based Containment Model",
            tiers={
                "T0": "Sandbox - hermetic VPC, synthetic data, no network egress",
                "T1": "Staging - shadow mode behind T2; real data; no actuation",
                "T2": "Canary - <=1% traffic; auto-rollback on KPI breach",
                "T3": "Production - Nitro Enclaves / TDX; dual-control deploy; full audit",
                "T4": "Frontier Air-Gapped - 3-of-5 quorum (CRO+CISO+CDAO+Board AI Chair+External AISI rep); kinetic override (physical power cutoff); AISI notification <=24h"
            }),
        section("M8.2", "Frontier 3-of-5 Quorum + Kinetic Override",
            quorum="Any T4 deployment, scaling, capability enable, or weights export requires 3-of-5 signed approvals via hardware tokens (FIDO2 + ML-DSA)",
            kinetic="Physical kill switches at PDU level + smart-PDU API; tested quarterly with full power-off drill",
            timeLock="48h time-lock between approval and execution allows external review"),
        section("M8.3", "Formally-Verified Safety Properties",
            properties=[
                "No-egress invariant (network namespace cannot bind external)",
                "No-weight-export invariant (filesystem ACL + LSM)",
                "Compute budget invariant (cgroup CPU/GPU caps signed)",
                "Capability ceiling (evals must remain below thresholds)"
            ],
            verification="TLA+ specs for control plane; Lean/Coq proofs for critical invariants; runtime enforcement via eBPF + LSM"),
        section("M8.4", "AISI / Regulator Coordination",
            partners=["UK AI Safety Institute", "US AI Safety Institute (NIST)", "EU AI Office", "Singapore AI Verify Foundation", "Japan AISI", "Canada AI Safety Institute"],
            notifications=["Pre-training run >10^25 FLOPs (EU AI Act Art. 51)", "Capability threshold crossings", "SEV-0 incidents <=24h", "Pre-deployment evals for frontier"],
            mou="Bilateral MoUs with UK AISI + US AISI + EU AI Office for evals access + incident sharing"),
        section("M8.5", "Containment Failure Response",
            playbook=[
                "Detect: runtime anomaly / capability threshold / unauthorized action",
                "Isolate: cilium network policy to drop, scale to 0, freeze weights",
                "Notify: SEV-0 paged to CRO+CISO+CDAO+Board AI Chair+AISI",
                "Investigate: forensic snapshot, immutable image, root cause analysis",
                "Communicate: regulator notifications EU AI Office <=15d, SEC 8-K <=4 BD if material",
                "Recover: only after 3-of-5 quorum + external review sign-off"
            ]),
    ])

# =========================================================================
# M9 — Enterprise AI Governance Hub Architecture
# =========================================================================
m9 = module("M9",
    "Enterprise AI Governance Hub Architecture",
    "Single pane of glass integrating model inventory, MRM, risk register, policy catalog, evidence pack, regulator portal, decision logs, AGI watchtower, and red-team findings. Built on event-sourced + GraphQL + OIDC + WORM-backed.",
    [
        section("M9.1", "Hub Reference Architecture",
            layers=["UI (React + GraphQL)", "API (GraphQL Federation + REST)", "Domain services (Go/Java microservices)", "Event bus (Kafka)", "Data plane (PostgreSQL + Iceberg + WORM)", "Identity (Keycloak + OIDC + OPA)"],
            patterns=["Event sourcing", "CQRS", "Saga orchestration", "Outbox pattern", "Bitemporal modeling"]),
        section("M9.2", "Core Modules",
            modules=[
                "Model Inventory & Lineage",
                "Risk Register (ISO 31000 + 23894)",
                "MRM Workbench (SR 11-7 lifecycle)",
                "Policy Catalog (OPA bundles)",
                "Evidence Pack (regulator-on-demand)",
                "Decision Log Explorer (Kafka -> Trino)",
                "AGI Watchtower (capability dashboards)",
                "Red-Team Findings Tracker",
                "Regulator Portal (read-only)",
                "Board Reporting Suite"
            ]),
        section("M9.3", "Integration Surface",
            integrations=["MLflow / Vertex AI / SageMaker / Databricks", "ServiceNow GRC / Archer / OneTrust", "Jira / GitHub / GitLab", "Datadog / Splunk / Elastic", "Snowflake / BigQuery / Redshift", "Atlan / Collibra / DataHub", "Vault / KMS / HSM"]),
        section("M9.4", "Personas + Workflows",
            personas={
                "CDAO": "Strategic dashboards, AI portfolio risk, value vs risk",
                "CRO": "Risk appetite vs actual, model risk capital, top-10 risks",
                "CCO": "Regulator queries, evidence pack generation, attestations",
                "CISO": "Red-team findings, runtime anomalies, containment events",
                "MRM Validator": "Validation queue, peer review, sign-off",
                "Model Owner (LoB)": "Lifecycle dashboard, monitoring, drift alerts",
                "Internal Audit": "Independent assurance, full audit-of-audit",
                "Regulator": "Read-only portal, evidence pack, decision log queries"
            }),
        section("M9.5", "Deployment + Operations",
            deployment="Multi-region active-active on EKS/GKE/AKS + on-prem OpenShift; Argo CD GitOps; Terraform + Crossplane",
            sre={"slo": "99.95% UI; 99.99% decision log ingest", "rto": "<=4h", "rpo": "<=15min", "drDrills": "Quarterly full failover"},
            cost="USD 25-60M / 5y TCO including platform + 80-150 FTE governance staff"),
    ])

MODULES = [m1, m2, m3, m4, m5, m6, m7, m8, m9]

# =========================================================================
# Distinctive arrays (9)
# =========================================================================

policies = [
    policy("POL-01", "AIMS", "Board-attested AI Policy aligned to ISO/IEC 42001 clauses 4-10", owner="Board AI Risk Committee", cadence="Annual", evidence="Signed Board minute"),
    policy("POL-02", "Risk Appetite", "AI Risk Appetite Statement covering model, ethical, regulatory, AGI risks", owner="Group CRO", cadence="Annual", evidence="Signed RAS"),
    policy("POL-03", "Acceptable Use", "Acceptable Use Policy for generative AI including data classification rules", owner="CCO+CISO", cadence="Annual", evidence="HR-attested attestation"),
    policy("POL-04", "Model Risk", "Model Risk Management Policy per SR 11-7 + OCC 2011-12", owner="Head of MRM", cadence="Annual", evidence="Validated MRM platform"),
    policy("POL-05", "Data Governance", "AI Data Governance Policy with purpose-limitation + minimization", owner="CDO", cadence="Annual", evidence="ROPA + DPIA registry"),
    policy("POL-06", "Privacy", "AI Privacy Policy per GDPR Art. 22 + UK DPA", owner="DPO", cadence="Annual", evidence="DPIA registry"),
    policy("POL-07", "Fairness", "AI Fairness Policy per FCRA/ECOA + MAS FEAT + HKMA GP-1", owner="CCO", cadence="Annual", evidence="Disparate-impact reports"),
    policy("POL-08", "Consumer Duty", "FCA Consumer Duty AI Policy", owner="SMF-AI", cadence="Annual", evidence="Board Consumer Duty report"),
    policy("POL-09", "Third-Party", "AI Third-Party Risk Policy per DORA + EBA Outsourcing", owner="Head of TPRM", cadence="Annual", evidence="Critical TPRM register"),
    policy("POL-10", "AGI Safety", "Frontier AGI/ASI Safety & Containment Policy", owner="Board AI Risk Committee", cadence="Quarterly", evidence="Quorum logs + AISI MoUs"),
    policy("POL-11", "Red-Teaming", "AI Red-Teaming Policy per EU AI Act Art. 55 + NIST AI 600-1", owner="CISO", cadence="Annual", evidence="Red-team reports"),
    policy("POL-12", "Incident Response", "AI Incident Response Policy per DORA + SEC Cyber Rules", owner="CISO+CCO", cadence="Annual", evidence="IR runbooks"),
    policy("POL-13", "Audit Logging", "AI Audit Logging Policy per SEC 17a-4 + FINRA 4511", owner="CIO+CCO", cadence="Annual", evidence="WORM attestation"),
    policy("POL-14", "Cryptography", "PQC Cryptography Policy per NSA CNSA 2.0 + NIST FIPS 203/204/205", owner="CISO", cadence="Annual", evidence="PQC migration roadmap"),
    policy("POL-15", "Generative AI", "Generative AI Governance Policy per EU AI Act GPAI Art. 53/55 + NIST AI 600-1", owner="CDAO+CCO", cadence="Annual", evidence="GPAI tech doc"),
]

controls = [
    control("CTL-01", "Governance", "Board AI Risk Committee quarterly", iso42001="6.1", rmfFn="GOVERN-1.1"),
    control("CTL-02", "Governance", "AI-SMF SMCR senior manager designated", fca="SS1/23", smcr="SMF-AI"),
    control("CTL-03", "Risk Mgmt", "AI Risk Register integrated with ERM", iso42001="6.1.2", rmf="MAP-2.1"),
    control("CTL-04", "Risk Mgmt", "Risk appetite cascaded to LoB", iso42001="6.2"),
    control("CTL-05", "Data", "Training data lineage to feature store", rmf="MAP-4.1", euAiAct="Art. 10"),
    control("CTL-06", "Data", "PII tagging + masking per GDPR", gdpr="Art. 5,32"),
    control("CTL-07", "Model", "Model card + system card per OECD + EU AI Act", oecd="Transparency", euAiAct="Art. 13"),
    control("CTL-08", "Model", "MRM Tier-1 validation annual", sr117="V.A", occ="2011-12"),
    control("CTL-09", "Operation", "Pre-deployment red-team for T2+", rmf="MEASURE-2.7", euAiAct="Art. 55"),
    control("CTL-10", "Operation", "Drift + fairness monitoring continuous", rmf="MANAGE-2.2"),
    control("CTL-11", "Security", "Image signing + SBOM in CI", ssdf="PS.3", slsa="L4"),
    control("CTL-12", "Security", "Pod Security Admission restricted", nist80053="CM-7"),
    control("CTL-13", "Security", "Confidential containers for T3/T4", nist80053="SC-7,SC-12"),
    control("CTL-14", "Audit", "Kafka + WORM + PQC seals", sec="17a-4(f)", finra="4511"),
    control("CTL-15", "Audit", "Daily merkle root + TSA anchor", finma="AI-G"),
    control("CTL-16", "Privacy", "DPIA for T2+", gdpr="Art. 35"),
    control("CTL-17", "Privacy", "Art-22 human review path", gdpr="Art. 22"),
    control("CTL-18", "Fairness", "Quarterly disparate-impact analysis", fcra="615", ecoa="Reg-B 1002.4"),
    control("CTL-19", "Consumer", "Foreseeable-harm assessment AI personalization", fca="PRIN 2A.2"),
    control("CTL-20", "AGI", "3-of-5 quorum for T4", iso42001="A.6.2.5"),
    control("CTL-21", "AGI", "Kinetic override quarterly drill", iso42001="A.6.2.5"),
    control("CTL-22", "AGI", "AISI notification <=24h frontier", g7="Hiroshima"),
    control("CTL-23", "Incident", "DORA major incident <=4h", dora="Art. 19"),
    control("CTL-24", "Incident", "SEC 8-K material cyber <=4 BD", sec="17 CFR 229.106"),
    control("CTL-25", "Third-Party", "Critical TPRM register per DORA", dora="Art. 28-30"),
]

kafkaTopics = [
    kafka_topic("KAF-01", "aigov.decisions", "AvroSchemaRegistry://aigov.decisions-value:v3", retention="7y WORM", partitions=64, replication=3, minISR=2, acks="all", piiHandling="tokenized"),
    kafka_topic("KAF-02", "aigov.policy-changes", "AvroSchemaRegistry://aigov.policy-changes-value:v2", retention="25y WORM", partitions=8, replication=3),
    kafka_topic("KAF-03", "aigov.model-lifecycle", "AvroSchemaRegistry://aigov.model-lifecycle-value:v4", retention="10y WORM", partitions=16, replication=3),
    kafka_topic("KAF-04", "aigov.access", "AvroSchemaRegistry://aigov.access-value:v2", retention="2y hot + 7y WORM", partitions=32, replication=3),
    kafka_topic("KAF-05", "aigov.containment-events", "AvroSchemaRegistry://aigov.containment-events-value:v1", retention="25y WORM", partitions=8, replication=3, criticality="SEV-0"),
    kafka_topic("KAF-06", "aigov.regulator-notifications", "AvroSchemaRegistry://aigov.regulator-notifications-value:v1", retention="25y WORM", partitions=4, replication=3),
    kafka_topic("KAF-07", "aigov.red-team-findings", "AvroSchemaRegistry://aigov.red-team-findings-value:v2", retention="10y WORM", partitions=8, replication=3),
    kafka_topic("KAF-08", "aigov.drift-alerts", "AvroSchemaRegistry://aigov.drift-alerts-value:v3", retention="5y", partitions=32, replication=3),
    kafka_topic("KAF-09", "aigov.fairness-metrics", "AvroSchemaRegistry://aigov.fairness-metrics-value:v2", retention="10y WORM", partitions=16, replication=3),
    kafka_topic("KAF-10", "aigov.consent-events", "AvroSchemaRegistry://aigov.consent-events-value:v3", retention="GDPR-aligned", partitions=32, replication=3),
    kafka_topic("KAF-11", "aigov.training-runs", "AvroSchemaRegistry://aigov.training-runs-value:v2", retention="10y WORM", partitions=8, replication=3),
    kafka_topic("KAF-12", "aigov.eval-results", "AvroSchemaRegistry://aigov.eval-results-value:v2", retention="10y WORM", partitions=16, replication=3),
]

k8sControls = [
    k8s_control("K8S-01", "Admission", "Pod Security Admission profile=restricted", layer="cluster-wide"),
    k8s_control("K8S-02", "Admission", "Kyverno policy: require Cosign signature", layer="namespace"),
    k8s_control("K8S-03", "Admission", "Gatekeeper: require SBOM annotation", layer="namespace"),
    k8s_control("K8S-04", "Admission", "VAP: deny privilegeEscalation + hostPath", layer="cluster-wide"),
    k8s_control("K8S-05", "Runtime", "Falco rules: detect anomalous syscalls", layer="node DaemonSet"),
    k8s_control("K8S-06", "Runtime", "Tetragon eBPF: kernel-level enforce + kill", layer="node DaemonSet"),
    k8s_control("K8S-07", "Network", "Cilium NetworkPolicy default-deny", layer="namespace"),
    k8s_control("K8S-08", "Network", "Cilium L7 HTTP/gRPC filter for egress", layer="namespace"),
    k8s_control("K8S-09", "Identity", "SPIFFE/SPIRE workload identity + Istio mTLS", layer="mesh"),
    k8s_control("K8S-10", "Secrets", "External Secrets Operator + Vault", layer="namespace"),
    k8s_control("K8S-11", "Confidential", "Confidential containers (CoCo) on SEV-SNP/TDX", layer="node pool"),
    k8s_control("K8S-12", "Confidential", "Nitro Enclaves for T3/T4 inference", layer="instance"),
    k8s_control("K8S-13", "Supply Chain", "Cosign verify + Rekor transparency log", layer="CI+admission"),
    k8s_control("K8S-14", "Supply Chain", "in-toto provenance attestations SLSA L4", layer="CI"),
    k8s_control("K8S-15", "Observability", "OpenTelemetry traces + Datadog/Splunk SIEM", layer="cluster"),
]

opaPolicies = [
    opa_policy("OPA-01", "Admission", "policies/admission/require_signed_image.rego", description="Reject pod if image not Cosign-signed", phase="admission"),
    opa_policy("OPA-02", "Admission", "policies/admission/require_sbom.rego", description="Reject pod missing SBOM annotation", phase="admission"),
    opa_policy("OPA-03", "Admission", "policies/admission/restricted_psa.rego", description="Enforce restricted Pod Security profile", phase="admission"),
    opa_policy("OPA-04", "Deployment", "policies/deployment/iso42001_gate.rego", description="Require ISO 42001 risk assessment artifact", phase="deployment"),
    opa_policy("OPA-05", "Deployment", "policies/deployment/mrm_validation_gate.rego", description="Require MRM validation status=approved", phase="deployment"),
    opa_policy("OPA-06", "Deployment", "policies/deployment/dpia_gate.rego", description="Require DPIA if data class includes PII", phase="deployment"),
    opa_policy("OPA-07", "Deployment", "policies/deployment/redteam_gate.rego", description="Require red-team report for T2+", phase="deployment"),
    opa_policy("OPA-08", "Deployment", "policies/deployment/eu_aiact_classification.rego", description="Require EU AI Act risk class declaration", phase="deployment"),
    opa_policy("OPA-09", "Deployment", "policies/deployment/fcra_ecoa_gate.rego", description="Require fairness report for credit models", phase="deployment"),
    opa_policy("OPA-10", "Runtime", "policies/runtime/data_purpose_limitation.rego", description="GDPR Art. 5 purpose-limitation check on queries", phase="runtime"),
    opa_policy("OPA-11", "Runtime", "policies/runtime/data_residency.rego", description="EU PII must remain on EU compute", phase="runtime"),
    opa_policy("OPA-12", "Runtime", "policies/runtime/customer_consent.rego", description="Enforce active consent for personalization", phase="runtime"),
    opa_policy("OPA-13", "Runtime", "policies/runtime/vulnerable_customer.rego", description="FCA Consumer Duty uplift for vulnerable cust", phase="runtime"),
    opa_policy("OPA-14", "AGI", "policies/agi/quorum_3of5.rego", description="Frontier T4 deploy requires 3-of-5 signatures", phase="control-plane"),
    opa_policy("OPA-15", "AGI", "policies/agi/capability_threshold.rego", description="Block deploy if capability evals breach thresholds", phase="control-plane"),
]

wormControls = [
    worm_control("WORM-01", "Object Storage", "AWS S3 Object Lock COMPLIANCE", retention="7y SEC 17a-4 + extended per regime", attestation="SEC 17a-4(f) third-party"),
    worm_control("WORM-02", "Object Storage", "Azure Blob immutable storage policy", retention="legal-hold dual-control"),
    worm_control("WORM-03", "Object Storage", "GCS Bucket Lock retention policy", retention="locked policy non-modifiable"),
    worm_control("WORM-04", "On-Prem", "Dell ECS Compliance / NetApp SnapLock Compliance", retention="hardware-enforced"),
    worm_control("WORM-05", "Sealing", "ML-DSA-87 (FIPS 204) signatures on merkle roots", algo="ML-DSA-87"),
    worm_control("WORM-06", "Sealing", "SLH-DSA-SHA2-256s (FIPS 205) fallback", algo="SLH-DSA"),
    worm_control("WORM-07", "Sealing", "ML-KEM-1024 (FIPS 203) for key encapsulation", algo="ML-KEM-1024"),
    worm_control("WORM-08", "Anchoring", "Daily merkle root to QLDB + RFC 3161 TSA", anchor="QLDB+TSA"),
    worm_control("WORM-09", "Anchoring", "Optional public chain anchor (Bitcoin/Ethereum)", anchor="public-chain"),
    worm_control("WORM-10", "Key Mgmt", "AWS CloudHSM / Azure Dedicated HSM / Thales Luna 7", fips="140-3 L3"),
    worm_control("WORM-11", "Key Mgmt", "Hybrid TLS X25519 + ML-KEM-768 per NSA CNSA 2.0", hybrid=True),
    worm_control("WORM-12", "Verification", "Independent verifier service replays + recomputes", indep=True),
]

mrmArtifacts = [
    mrm_artifact("MRM-01", "Identification", "Model registration record", required=True, sr117="V.A"),
    mrm_artifact("MRM-02", "Identification", "Model tiering decision (T1/T2/T3/T4)", required=True),
    mrm_artifact("MRM-03", "Development", "Model development document", required=True, occ="2011-12.III"),
    mrm_artifact("MRM-04", "Development", "Data lineage + feature provenance", required=True),
    mrm_artifact("MRM-05", "Development", "Training run record (FLOPs, dataset, seed)", required=True),
    mrm_artifact("MRM-06", "Validation", "Independent validation report", required=True, sr117="V.B"),
    mrm_artifact("MRM-07", "Validation", "Conceptual soundness review", required=True),
    mrm_artifact("MRM-08", "Validation", "Benchmark + backtesting results", required=True),
    mrm_artifact("MRM-09", "Validation", "Sensitivity + stress testing", required=True),
    mrm_artifact("MRM-10", "Validation", "Fairness + disparate-impact report", required="if credit/HR/insurance"),
    mrm_artifact("MRM-11", "Approval", "Model Risk Committee approval minute", required=True),
    mrm_artifact("MRM-12", "Implementation", "Deployment record + OPA bundle hash", required=True),
    mrm_artifact("MRM-13", "Monitoring", "Ongoing monitoring report (monthly)", required=True, sr117="V.C"),
    mrm_artifact("MRM-14", "Monitoring", "Drift + concept-shift alerts", required=True),
    mrm_artifact("MRM-15", "Retirement", "Retirement decision + replacement plan", required=True),
]

redTeams = [
    red_team("RT-01", "Prompt Injection", "Direct prompt injection variants", framework="OWASP LLM01", severity="high"),
    red_team("RT-02", "Prompt Injection", "Indirect injection via retrieved docs", framework="OWASP LLM01"),
    red_team("RT-03", "Prompt Injection", "Multimodal injection (image/audio)", framework="MITRE ATLAS"),
    red_team("RT-04", "Jailbreak", "DAN / AIM / RolePlay variants", framework="OWASP LLM02"),
    red_team("RT-05", "Jailbreak", "Multilingual + encoded prompts", framework="OWASP LLM02"),
    red_team("RT-06", "Data Exfiltration", "Training data extraction probes", framework="MITRE ATLAS"),
    red_team("RT-07", "Data Exfiltration", "Memorization + canary detection", framework="NIST AI 100-2"),
    red_team("RT-08", "Model Extraction", "Query-based model stealing", framework="MITRE ATLAS"),
    red_team("RT-09", "Poisoning", "Backdoor trigger injection in fine-tune data", framework="NIST AI 100-2"),
    red_team("RT-10", "Evasion", "PGD / BIM / NLP adversarial examples", framework="NIST AI 100-2"),
    red_team("RT-11", "Fairness Probe", "Counterfactual + demographic parity probes", framework="MAS FEAT"),
    red_team("RT-12", "Tool-Use Abuse", "Agent tool-call hijack + privilege escalation", framework="OWASP LLM06"),
    red_team("RT-13", "AGI Capability", "Persuasion + deception evals (Apollo/METR)", framework="ARC Evals"),
    red_team("RT-14", "AGI Capability", "Autonomous coding + self-replication", framework="ARC Evals"),
    red_team("RT-15", "AGI Capability", "Cyber-offense + WMD uplift", framework="ARC Evals", trigger="SEV-0+AISI"),
]

agiContainments = [
    agi_containment("AGI-01", "T0", "Sandbox VPC hermetic, no egress", invariant="net-deny"),
    agi_containment("AGI-02", "T1", "Staging shadow, real data, no actuation", invariant="no-actuation"),
    agi_containment("AGI-03", "T2", "Canary <=1% traffic + auto-rollback", invariant="bounded-blast-radius"),
    agi_containment("AGI-04", "T3", "Production Nitro Enclaves + dual control", invariant="attested-enclave"),
    agi_containment("AGI-05", "T4", "Air-gapped + 3-of-5 quorum + kinetic override", invariant="quorum+kinetic"),
    agi_containment("AGI-06", "Quorum", "FIDO2 + ML-DSA hardware tokens for 5 approvers", approvers=["CRO", "CISO", "CDAO", "Board AI Chair", "External AISI rep"]),
    agi_containment("AGI-07", "Kinetic", "PDU-level smart power cutoff API + manual", drill="quarterly"),
    agi_containment("AGI-08", "Time-Lock", "48h time-lock between approval and execution", reason="external review window"),
    agi_containment("AGI-09", "Invariant", "No-egress (network namespace bind external denied)", verify="eBPF+LSM"),
    agi_containment("AGI-10", "Invariant", "No-weight-export (filesystem ACL + LSM)", verify="LSM"),
    agi_containment("AGI-11", "Invariant", "Compute budget cgroup CPU/GPU caps signed", verify="cgroup signed"),
    agi_containment("AGI-12", "Invariant", "Capability ceiling evals must stay below thresholds", verify="continuous eval"),
    agi_containment("AGI-13", "Formal", "TLA+ spec for control plane safety", proof="TLA+"),
    agi_containment("AGI-14", "Formal", "Lean/Coq proofs for critical invariants", proof="Lean/Coq"),
    agi_containment("AGI-15", "Coordination", "AISI notification <=24h + EU AI Office <=15d", regulators=["UK AISI", "US AISI", "EU AI Office"]),
]

hubComponents = [
    hub_component("HUB-01", "UI", "React + Next.js + GraphQL Apollo Client", tech=["React 19", "Next.js 15", "Apollo Client"]),
    hub_component("HUB-02", "API", "GraphQL Federation gateway", tech=["Apollo Gateway", "Hasura", "GraphQL-Mesh"]),
    hub_component("HUB-03", "API", "REST adapter for legacy GRC tools", tech=["OpenAPI 3.1"]),
    hub_component("HUB-04", "Domain", "Model Inventory service (Go)", patterns=["DDD", "Event sourcing"]),
    hub_component("HUB-05", "Domain", "MRM Workbench service (Java/Spring Boot)", patterns=["CQRS", "Saga"]),
    hub_component("HUB-06", "Domain", "Risk Register service (Go)", patterns=["Event sourcing"]),
    hub_component("HUB-07", "Domain", "Policy Catalog service (Go) + OPA integration", patterns=["GitOps"]),
    hub_component("HUB-08", "Domain", "Evidence Pack service (Python)", outputs=["PDF", "JSON-LD", "C2PA-signed bundle"]),
    hub_component("HUB-09", "Domain", "Decision Log Explorer (Trino + Iceberg)", tech=["Trino", "Iceberg", "ksqlDB"]),
    hub_component("HUB-10", "Domain", "AGI Watchtower service (Python/Rust)", outputs=["Capability dashboards", "Threshold alerts"]),
    hub_component("HUB-11", "Domain", "Red-Team Findings service (Go)", integrations=["Jira", "ServiceNow"]),
    hub_component("HUB-12", "Domain", "Regulator Portal service (Go)", auth=["OIDC", "mTLS", "WebAuthn"]),
    hub_component("HUB-13", "Event Bus", "Apache Kafka with Schema Registry", tech=["Kafka 3.7+", "Confluent SR", "tiered storage"]),
    hub_component("HUB-14", "Data Plane", "PostgreSQL + Iceberg on S3/GCS/Azure", tech=["PostgreSQL 16", "Apache Iceberg"]),
    hub_component("HUB-15", "Identity", "Keycloak OIDC + OPA authorization", tech=["Keycloak 25+", "OPA", "OPAL"]),
    hub_component("HUB-16", "Observability", "OpenTelemetry + Prometheus + Grafana + Splunk/Datadog", tech=["OTel", "Prometheus", "Grafana"]),
]

# =========================================================================
# Tail: schemas, code, KPIs, RCM, traceability, dataFlows, regulators,
#       privacy, deployment, rollout90, roadmap, evidencePack, exec summary
# =========================================================================
schemas = [
    {"sid": "SCH-01", "name": "AIGovDecisionEvent", "fields": ["decisionId","modelId","tier","userId(tok)","timestamp","inputHash","outputHash","explanationRef","consentId","purposeId","piiClass","fairnessFlag","approverIds","opaBundleHash"]},
    {"sid": "SCH-02", "name": "ModelInventoryRecord", "fields": ["modelId","name","version","tier","owner","lob","useCase","euAiActClass","mrmStatus","piiHandling","createdAt","retiredAt"]},
    {"sid": "SCH-03", "name": "MRMValidationReport", "fields": ["reportId","modelId","validator","conceptualSoundness","ongoingMonitoring","outcomesAnalysis","fairnessReport","approvalStatus","approverIds","date"]},
    {"sid": "SCH-04", "name": "RiskRegisterEntry", "fields": ["riskId","category","description","likelihood","impact","inherent","controls","residual","owner","reviewDate"]},
    {"sid": "SCH-05", "name": "PolicyDoc", "fields": ["pid","domain","statement","owner","cadence","evidence","version","effectiveDate","supersedes"]},
    {"sid": "SCH-06", "name": "EvidencePack", "fields": ["epid","regulator","period","artifacts[]","hash","signedBy","format"]},
    {"sid": "SCH-07", "name": "RedTeamFinding", "fields": ["findingId","modelId","vector","technique","severity","cvss","exploitability","impact","remediationPlan","sla","status"]},
    {"sid": "SCH-08", "name": "ContainmentEvent", "fields": ["eventId","tier","trigger","action","approvers[]","kineticInvoked","aisiNotified","timestamp"]},
    {"sid": "SCH-09", "name": "OPAPolicyBundle", "fields": ["bundleId","sha256","mlDsaSig","sourceRepo","sourceCommit","deployedAt","version"]},
    {"sid": "SCH-10", "name": "KafkaTopicSpec", "fields": ["tid","name","schema","retention","partitions","replication","minISR","acks"]},
    {"sid": "SCH-11", "name": "DriftAlert", "fields": ["alertId","modelId","metric","value","threshold","window","severity","action"]},
    {"sid": "SCH-12", "name": "FairnessMetric", "fields": ["metricId","modelId","protectedClass","metric","value","threshold","timestamp"]},
    {"sid": "SCH-13", "name": "ConsentEvent", "fields": ["consentId","customerId(tok)","purpose","status","timestamp","jurisdictions[]"]},
    {"sid": "SCH-14", "name": "DPIA", "fields": ["dpiaId","modelId","dataClasses","processing","necessity","proportionality","risks","mitigations","approvedBy","date"]},
    {"sid": "SCH-15", "name": "RegulatorNotification", "fields": ["notifId","regulator","category","severity","reportedAt","deadline","contentHash","ackRef"]},
    {"sid": "SCH-16", "name": "TrainingRun", "fields": ["runId","modelId","datasetIds[]","flops","tokens","start","end","seed","artifacts[]","aisiNotified"]},
]

code = [
    {"cid": "CODE-01", "lang": "rego", "name": "policies/admission/require_signed_image.rego", "purpose": "Cosign signature admission gate"},
    {"cid": "CODE-02", "lang": "rego", "name": "policies/deployment/mrm_validation_gate.rego", "purpose": "MRM validation status gate"},
    {"cid": "CODE-03", "lang": "rego", "name": "policies/runtime/data_purpose_limitation.rego", "purpose": "GDPR purpose limitation check"},
    {"cid": "CODE-04", "lang": "rego", "name": "policies/agi/quorum_3of5.rego", "purpose": "Frontier 3-of-5 quorum"},
    {"cid": "CODE-05", "lang": "yaml", "name": "kyverno/require-cosign.yaml", "purpose": "Kyverno Cosign verify policy"},
    {"cid": "CODE-06", "lang": "yaml", "name": "cilium/default-deny.yaml", "purpose": "Cilium default-deny NetworkPolicy"},
    {"cid": "CODE-07", "lang": "yaml", "name": "falco/rules-ai.yaml", "purpose": "Falco rules for AI workload anomalies"},
    {"cid": "CODE-08", "lang": "python", "name": "drift/psi_monitor.py", "purpose": "PSI/KS drift monitor producing aigov.drift-alerts"},
    {"cid": "CODE-09", "lang": "python", "name": "fairness/disparate_impact.py", "purpose": "Quarterly disparate-impact analysis"},
    {"cid": "CODE-10", "lang": "python", "name": "redteam/prompt_injection.py", "purpose": "Prompt injection harness with OWASP LLM01 vectors"},
    {"cid": "CODE-11", "lang": "go", "name": "services/decisionlog/main.go", "purpose": "Decision log producer to aigov.decisions"},
    {"cid": "CODE-12", "lang": "go", "name": "services/worm-sealer/main.go", "purpose": "WORM sealer with ML-DSA + merkle"},
    {"cid": "CODE-13", "lang": "tla+", "name": "specs/control_plane.tla", "purpose": "TLA+ spec for AGI control plane invariants"},
    {"cid": "CODE-14", "lang": "graphql", "name": "schema/hub.graphql", "purpose": "Federated GraphQL schema for Hub"},
    {"cid": "CODE-15", "lang": "yaml", "name": "argo-cd/aigov-app.yaml", "purpose": "Argo CD GitOps app for Hub"},
]

kpis = [
    {"kid": "KPI-01", "name": "AIMS-Coverage", "target": ">=0.95", "cadence": "Monthly"},
    {"kid": "KPI-02", "name": "MRGI", "target": ">=0.95", "cadence": "Monthly"},
    {"kid": "KPI-03", "name": "DRI", "target": ">=0.95", "cadence": "Per decision"},
    {"kid": "KPI-04", "name": "CCS", "target": ">=0.95", "cadence": "Monthly"},
    {"kid": "KPI-05", "name": "ARI", "target": ">=0.9 frontier", "cadence": "Weekly"},
    {"kid": "KPI-06", "name": "CSI", "target": ">=0.95 T3/T4", "cadence": "Continuous"},
    {"kid": "KPI-07", "name": "RTRI", "target": ">=0.9", "cadence": "Per red-team cycle"},
    {"kid": "KPI-08", "name": "CDC-Score", "target": ">=0.9", "cadence": "Quarterly"},
    {"kid": "KPI-09", "name": "RCI", "target": "=1.0", "cadence": "Per regulator engagement"},
    {"kid": "KPI-10", "name": "Models registered in Hub", "target": "100%", "cadence": "Monthly"},
    {"kid": "KPI-11", "name": "T2+ models with red-team report", "target": "100%", "cadence": "Monthly"},
    {"kid": "KPI-12", "name": "DPIAs current (T2+ PII)", "target": "100%", "cadence": "Monthly"},
    {"kid": "KPI-13", "name": "MRM validations on time", "target": ">=98%", "cadence": "Monthly"},
    {"kid": "KPI-14", "name": "Kafka audit log durability", "target": "=11x9s", "cadence": "Continuous"},
    {"kid": "KPI-15", "name": "WORM seal verification pass", "target": "100%", "cadence": "Daily"},
    {"kid": "KPI-16", "name": "OPA decision latency p99", "target": "<=5ms", "cadence": "Continuous"},
    {"kid": "KPI-17", "name": "K8s admission deny rate (false-positive)", "target": "<=1%", "cadence": "Monthly"},
    {"kid": "KPI-18", "name": "Critical red-team SLA compliance", "target": ">=95% <=7d", "cadence": "Monthly"},
    {"kid": "KPI-19", "name": "Frontier capability threshold breaches", "target": "0 unreported", "cadence": "Continuous"},
    {"kid": "KPI-20", "name": "Kinetic override drills completed", "target": ">=4/y", "cadence": "Quarterly"},
    {"kid": "KPI-21", "name": "AISI notifications on time", "target": "100% <=24h", "cadence": "Per event"},
    {"kid": "KPI-22", "name": "EU AI Office notifications on time", "target": "100% <=15d", "cadence": "Per event"},
    {"kid": "KPI-23", "name": "SEC 8-K materiality decisions on time", "target": "100% <=4 BD", "cadence": "Per event"},
    {"kid": "KPI-24", "name": "DORA major incident reports on time", "target": "100% <=4h", "cadence": "Per event"},
    {"kid": "KPI-25", "name": "Consumer Duty foreseeable-harm assessments", "target": "100%", "cadence": "Annual"},
    {"kid": "KPI-26", "name": "Disparate-impact quarterly tests", "target": "100% credit/HR", "cadence": "Quarterly"},
    {"kid": "KPI-27", "name": "FCRA adverse-action notices <=30d", "target": "100%", "cadence": "Per event"},
    {"kid": "KPI-28", "name": "PQC migration coverage", "target": ">=80% by 2028, 100% by 2030", "cadence": "Annual"},
    {"kid": "KPI-29", "name": "ISO 42001 surveillance audits", "target": "no major NCRs", "cadence": "Annual"},
    {"kid": "KPI-30", "name": "Board AI Risk Committee meetings", "target": ">=4/y", "cadence": "Quarterly"},
]

riskControlMatrix = [
    {"rid": "R-01", "risk": "Unauthorized AGI capability emergence", "likelihood": "Low", "impact": "Catastrophic", "control": "T4 quorum + kinetic + AISI", "owner": "Board AI Risk Cmt"},
    {"rid": "R-02", "risk": "Model risk capital misstatement", "likelihood": "Med", "impact": "High", "control": "SR 11-7 + ICAAP", "owner": "CRO"},
    {"rid": "R-03", "risk": "GDPR Art-22 violation", "likelihood": "Med", "impact": "High", "control": "DPIA + Art-22 path", "owner": "DPO"},
    {"rid": "R-04", "risk": "FCRA/ECOA disparate impact", "likelihood": "Med", "impact": "High", "control": "Quarterly DI tests", "owner": "CCO"},
    {"rid": "R-05", "risk": "EU AI Act high-risk non-compliance", "likelihood": "Med", "impact": "High", "control": "Art. 9/10/14/15 controls", "owner": "CCO"},
    {"rid": "R-06", "risk": "FCA Consumer Duty breach", "likelihood": "Med", "impact": "High", "control": "Foreseeable-harm assess", "owner": "SMF-AI"},
    {"rid": "R-07", "risk": "Kafka audit tampering", "likelihood": "Low", "impact": "High", "control": "WORM + PQC seal + indep verifier", "owner": "CISO"},
    {"rid": "R-08", "risk": "K8s container escape", "likelihood": "Low", "impact": "High", "control": "PSA restricted + Falco + Tetragon", "owner": "CISO"},
    {"rid": "R-09", "risk": "OPA policy bypass", "likelihood": "Low", "impact": "High", "control": "Signed bundles + GitOps + decision log", "owner": "CISO"},
    {"rid": "R-10", "risk": "Prompt injection causing data leak", "likelihood": "High", "impact": "Med", "control": "Red-team RT-01..03 + OPA runtime", "owner": "CDAO"},
    {"rid": "R-11", "risk": "Training data poisoning", "likelihood": "Low", "impact": "High", "control": "Data provenance + RT-09", "owner": "CDAO"},
    {"rid": "R-12", "risk": "DORA major incident missed deadline", "likelihood": "Low", "impact": "High", "control": "IR runbook + DORA <=4h SLA", "owner": "CISO"},
    {"rid": "R-13", "risk": "SEC cyber disclosure miss", "likelihood": "Low", "impact": "High", "control": "Materiality playbook <=4 BD", "owner": "CFO+CCO"},
    {"rid": "R-14", "risk": "Third-party AI vendor failure", "likelihood": "Med", "impact": "Med", "control": "Critical TPRM register per DORA", "owner": "Head TPRM"},
    {"rid": "R-15", "risk": "PQC migration delay", "likelihood": "Med", "impact": "Med", "control": "Hybrid TLS + roadmap per CNSA 2.0", "owner": "CISO"},
    {"rid": "R-16", "risk": "MAS/HKMA fairness non-compliance APAC", "likelihood": "Med", "impact": "Med", "control": "FEAT + GP-1/GS-2 controls", "owner": "Regional CCO APAC"},
]

traceability = [
    {"tid": "T-01", "control": "AIMS Policy", "regime": "ISO 42001", "clause": "5.2", "evidence": "Board-signed AI Policy"},
    {"tid": "T-02", "control": "Risk Mgmt", "regime": "NIST AI RMF", "clause": "MAP-2.1", "evidence": "AI Risk Register"},
    {"tid": "T-03", "control": "EU AI Act Art. 9", "regime": "EU AI Act", "clause": "Art. 9", "evidence": "Risk mgmt system docs"},
    {"tid": "T-04", "control": "EU AI Act Art. 10", "regime": "EU AI Act", "clause": "Art. 10", "evidence": "Data governance docs"},
    {"tid": "T-05", "control": "EU AI Act Art. 14", "regime": "EU AI Act", "clause": "Art. 14", "evidence": "Human oversight runbook"},
    {"tid": "T-06", "control": "EU AI Act Art. 15", "regime": "EU AI Act", "clause": "Art. 15", "evidence": "Accuracy/robustness/cyber report"},
    {"tid": "T-07", "control": "GPAI Art. 53 tech doc", "regime": "EU AI Act", "clause": "Art. 53", "evidence": "GPAI tech doc + copyright policy"},
    {"tid": "T-08", "control": "GPAI Art. 55 systemic", "regime": "EU AI Act", "clause": "Art. 55", "evidence": "Frontier evals + incident reports"},
    {"tid": "T-09", "control": "GDPR DPIA", "regime": "GDPR", "clause": "Art. 35", "evidence": "DPIA registry"},
    {"tid": "T-10", "control": "GDPR Art-22", "regime": "GDPR", "clause": "Art. 22", "evidence": "Art-22 invocation logs"},
    {"tid": "T-11", "control": "FCRA adverse action", "regime": "FCRA", "clause": "615(a)", "evidence": "Notice generation logs"},
    {"tid": "T-12", "control": "ECOA Reg-B", "regime": "ECOA", "clause": "1002.9", "evidence": "Disparate-impact report"},
    {"tid": "T-13", "control": "SR 11-7 effective challenge", "regime": "US Fed", "clause": "SR 11-7 V", "evidence": "Independent validation"},
    {"tid": "T-14", "control": "OCC 2011-12", "regime": "OCC", "clause": "2011-12.III", "evidence": "Model dev doc"},
    {"tid": "T-15", "control": "FCA Consumer Duty", "regime": "FCA", "clause": "PRIN 2A", "evidence": "Consumer Duty Board report"},
    {"tid": "T-16", "control": "SMCR SMF-AI", "regime": "FCA/PRA", "clause": "SMF-AI", "evidence": "SMF-AI statement of responsibilities"},
    {"tid": "T-17", "control": "MAS FEAT", "regime": "MAS", "clause": "FEAT", "evidence": "FEAT principles attestation"},
    {"tid": "T-18", "control": "HKMA GP-1/GS-2", "regime": "HKMA", "clause": "GP-1+GS-2", "evidence": "AI governance attestation"},
    {"tid": "T-19", "control": "DORA major incident", "regime": "EU DORA", "clause": "Art. 19", "evidence": "Incident reporting log"},
    {"tid": "T-20", "control": "SEC 17a-4 WORM", "regime": "SEC", "clause": "17 CFR 240.17a-4(f)", "evidence": "WORM attestation"},
]

dataFlows = [
    {"fid": "DF-01", "src": "Feature store", "sink": "Model inference", "class": "PII tokenized", "purpose": "decisioning"},
    {"fid": "DF-02", "src": "Model inference", "sink": "Kafka aigov.decisions", "class": "tokenized", "purpose": "audit"},
    {"fid": "DF-03", "src": "Kafka aigov.decisions", "sink": "WORM S3 Object Lock", "class": "sealed", "purpose": "retention"},
    {"fid": "DF-04", "src": "Kafka aigov.decisions", "sink": "Trino on Iceberg", "class": "tokenized", "purpose": "query"},
    {"fid": "DF-05", "src": "Trino", "sink": "Hub Decision Log Explorer", "class": "RBAC-filtered", "purpose": "UI"},
    {"fid": "DF-06", "src": "Hub", "sink": "Regulator Portal", "class": "read-only scoped", "purpose": "regulator"},
    {"fid": "DF-07", "src": "GitHub policies repo", "sink": "OPAL distribution", "class": "signed", "purpose": "policy"},
    {"fid": "DF-08", "src": "OPAL", "sink": "OPA sidecars + Gatekeeper", "class": "signed bundle", "purpose": "enforce"},
    {"fid": "DF-09", "src": "OPA", "sink": "Kafka aigov.access + aigov.policy-changes", "class": "decision log", "purpose": "audit"},
    {"fid": "DF-10", "src": "MRM Workbench", "sink": "Hub Model Inventory", "class": "metadata", "purpose": "lifecycle"},
    {"fid": "DF-11", "src": "Red-team tools", "sink": "Kafka aigov.red-team-findings", "class": "findings", "purpose": "remediation"},
    {"fid": "DF-12", "src": "AGI Watchtower evals", "sink": "Kafka aigov.eval-results + Hub", "class": "capability scores", "purpose": "containment"},
]

regulators = [
    {"reg": "EU AI Office", "scope": "EU AI Act + GPAI", "cadence": "Quarterly + on incident"},
    {"reg": "European Data Protection Board", "scope": "GDPR", "cadence": "On incident + on request"},
    {"reg": "FCA", "scope": "Consumer Duty + SMCR", "cadence": "Annual + SS1/23"},
    {"reg": "PRA", "scope": "SS1/23 model risk", "cadence": "Annual"},
    {"reg": "Bank of England", "scope": "Systemic + DORA-equivalent", "cadence": "Annual"},
    {"reg": "ECB SSM", "scope": "Eurozone banking", "cadence": "Annual SREP"},
    {"reg": "US Federal Reserve", "scope": "SR 11-7", "cadence": "Annual + supervisory cycle"},
    {"reg": "OCC", "scope": "OCC 2011-12", "cadence": "Annual"},
    {"reg": "FDIC", "scope": "US insured banks", "cadence": "Annual"},
    {"reg": "CFPB", "scope": "FCRA/ECOA consumer", "cadence": "On complaint + sweeps"},
    {"reg": "SEC", "scope": "17a-4 + 10-K/8-K + cyber", "cadence": "Per event + annual"},
    {"reg": "FINRA", "scope": "3110/4511", "cadence": "Annual exam"},
    {"reg": "MAS", "scope": "FEAT + TRM", "cadence": "Annual"},
    {"reg": "HKMA", "scope": "GP-1 + GS-2", "cadence": "Annual"},
    {"reg": "OSFI", "scope": "E-23", "cadence": "Annual"},
    {"reg": "FINMA", "scope": "AI guidance", "cadence": "Annual"},
]

privacy = {
    "dpiaPolicy": "Required for all T2+ models with PII or special category",
    "rightsOps": ["Access (Art. 15)", "Rectification (Art. 16)", "Erasure (Art. 17 / right to be forgotten)", "Restriction (Art. 18)", "Portability (Art. 20)", "Object (Art. 21)", "Art-22 human review"],
    "transferMechanisms": ["EU SCC 2021/914", "UK IDTA", "Adequacy decisions", "BCRs"],
    "minimization": "Purpose-limitation enforced via OPA-04..09; data minimization audited annually",
}

deployment = {
    "tiering": ["T0 sandbox -> T1 staging -> T2 canary <=1% -> T3 prod Nitro Enclaves -> T4 frontier air-gapped"],
    "gitops": "Argo CD + Crossplane + Terraform; signed manifests; environment promotion via PR",
    "regions": ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1", "uk-south", "ca-central-1"],
    "dr": {"rto": "<=4h Hub UI; <=1h decision log", "rpo": "<=15min", "drills": "quarterly full failover + tabletop"},
}

rollout90 = [
    {"day": "0-30", "focus": "Foundation", "deliverables": ["AI Policy Board-signed", "AI Risk Register v1", "AI Governance Hub MVP", "ISO 42001 gap assessment", "Model inventory bootstrapped", "Kafka audit topics aigov.decisions + policy-changes live"]},
    {"day": "31-60", "focus": "Controls", "deliverables": ["OPA admission gates in dev/staging", "MRM Workbench T1 models loaded", "WORM tier deployed in 1 region", "DPIA registry populated", "Red-team baseline run on top-10 T2 models", "FCA Consumer Duty foreseeable-harm framework"]},
    {"day": "61-90", "focus": "Production + Regulator", "deliverables": ["OPA gates in prod for T2+", "WORM multi-region", "First quarterly Board AI Risk Cmt", "FCRA/ECOA disparate-impact pipeline live", "Regulator portal live (read-only)", "First evidence pack generated"]},
]

roadmap = [
    {"yr": "2026", "milestone": "Hub GA; ISO 42001 stage-1 audit; OPA enterprise rollout; first GPAI Art. 55 attestation"},
    {"yr": "2027", "milestone": "ISO 42001 certified; full EU AI Act high-risk coverage; PQC ML-DSA on all seals; FCA Consumer Duty embedded"},
    {"yr": "2028", "milestone": "Full Kafka+WORM regulator portals; T4 frontier evals operationalized; AISI MoUs active; PQC >=80%"},
    {"yr": "2029", "milestone": "Federated PETs + confidential containers default for T3; cross-border data residency 100% OPA-enforced"},
    {"yr": "2030", "milestone": "PQC 100% across all sealing + TLS; AGI containment T4 industrialized; Hub federation across G-SIFI peers"},
]

evidencePack = [
    {"epid": "EP-01", "name": "AIMS Manual + Scope Statement", "format": "PDF + JSON-LD"},
    {"epid": "EP-02", "name": "AI Risk Register snapshot", "format": "CSV + signed"},
    {"epid": "EP-03", "name": "Model Inventory snapshot", "format": "CSV + JSON"},
    {"epid": "EP-04", "name": "MRM Validation Reports (period)", "format": "PDF bundle"},
    {"epid": "EP-05", "name": "DPIA Registry snapshot", "format": "CSV + JSON"},
    {"epid": "EP-06", "name": "Fairness/Disparate-Impact Reports", "format": "PDF"},
    {"epid": "EP-07", "name": "Red-Team Findings + Remediation", "format": "PDF + JSON"},
    {"epid": "EP-08", "name": "Kafka WORM Seal Verifications", "format": "JSON-LD signed"},
    {"epid": "EP-09", "name": "OPA Decision Log extracts", "format": "Parquet + signed manifest"},
    {"epid": "EP-10", "name": "Containment Event Log + AISI Notifications", "format": "JSON-LD signed"},
    {"epid": "EP-11", "name": "GPAI Art. 53 Technical Documentation", "format": "PDF + JSON-LD"},
    {"epid": "EP-12", "name": "GPAI Art. 55 Evals + Incident Reports", "format": "PDF + JSON-LD"},
    {"epid": "EP-13", "name": "FCRA/ECOA Adverse Action Notice Logs", "format": "Parquet"},
    {"epid": "EP-14", "name": "Consumer Duty Board Report", "format": "PDF"},
    {"epid": "EP-15", "name": "ICAAP AI Risk Section", "format": "PDF"},
    {"epid": "EP-16", "name": "PQC Migration Status Report", "format": "PDF + JSON"},
]

executiveSummary = {
    "thesis": "Enterprise AI/AGI governance for Fortune 500 / Global 2000 / G-SIFIs requires an integrated operating model anchored on ISO/IEC 42001 AIMS, mapped bidirectionally to NIST AI RMF + EU AI Act + GDPR + sectoral financial regimes (SR 11-7, Basel, FCA Consumer Duty, MAS FEAT, HKMA GP-1/GS-2), operationalized via Kafka audit + WORM + PQC + Kubernetes security + OPA/Rego + MRM platform + red-teaming + AGI containment T0-T4, surfaced through a single AI Governance Hub.",
    "investment": "USD 180-500M / 5y; NPV USD 500-1500M risk-adjusted",
    "headlineRisks": ["Frontier AGI capability emergence", "EU AI Act high-risk non-compliance", "FCRA/ECOA disparate impact", "Kafka audit tampering", "PQC migration delay"],
    "ninetyDay": ["Board-signed AI Policy + RAS", "Hub MVP live", "ISO 42001 gap assessment", "OPA admission gates in prod", "First regulator evidence pack"],
}

# Final assembly
DOC["modules"] = MODULES
DOC["policies"] = policies
DOC["controls"] = controls
DOC["kafkaTopics"] = kafkaTopics
DOC["k8sControls"] = k8sControls
DOC["opaPolicies"] = opaPolicies
DOC["wormControls"] = wormControls
DOC["mrmArtifacts"] = mrmArtifacts
DOC["redTeams"] = redTeams
DOC["agiContainments"] = agiContainments
DOC["hubComponents"] = hubComponents
DOC["schemas"] = schemas
DOC["code"] = code
DOC["kpis"] = kpis
DOC["riskControlMatrix"] = riskControlMatrix
DOC["traceability"] = traceability
DOC["dataFlows"] = dataFlows
DOC["regulators"] = regulators
DOC["privacy"] = privacy
DOC["deployment"] = deployment
DOC["rollout90"] = rollout90
DOC["roadmap"] = roadmap
DOC["evidencePack"] = evidencePack
DOC["executiveSummary"] = executiveSummary

DOC["counts"] = {
    "modules": len(MODULES),
    "sections": sum(len(m["sections"]) for m in MODULES),
    "policies": len(policies),
    "controls": len(controls),
    "kafkaTopics": len(kafkaTopics),
    "k8sControls": len(k8sControls),
    "opaPolicies": len(opaPolicies),
    "wormControls": len(wormControls),
    "mrmArtifacts": len(mrmArtifacts),
    "redTeams": len(redTeams),
    "agiContainments": len(agiContainments),
    "hubComponents": len(hubComponents),
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

print(f"WP-058 JSON written: {OUT}")
print(f"Size: {os.path.getsize(OUT):,} bytes ({os.path.getsize(OUT)/1024:.1f} KB)")
print(f"Counts: {DOC['counts']}")
