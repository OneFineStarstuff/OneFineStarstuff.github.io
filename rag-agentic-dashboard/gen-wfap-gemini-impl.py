#!/usr/bin/env python3
"""
WFAP-GEMINI-IMPL-WP-036 — WorkflowAI Pro / GeminiService Implementation Plan
Generates: data/wfap-gemini-impl.json

Comprehensive implementation plan, technical architecture, data models, data
flows, governance frameworks, and best-practice design guidelines for an
enterprise WorkflowAI Pro / GeminiService platform.

Capabilities covered:
  - AI-driven workflow recommendation with active learning
  - Adaptive content and UI by user context and skill
  - RAG-based grounded chat with citations and faithfulness scoring
  - Collaborative prompt engineering (templates, variables, lineage)
  - Enterprise model registry governance with RBAC, compliance metadata,
    rollback, tagging
  - AI safety and global governance reporting (existential risk, misuse,
    bias, threat assessment, alignment failure, international collaboration)
  - High-assurance RAG governance (lineage, citation, PII redaction)
  - GeminiService security & privacy: telemetry integrity, GDPR PII
    redaction, EU AI Act Art. 5 prohibited-practices checks, adversarial
    prompt defenses
  - Task / report management features
  - Step-by-step implementation strategy, module boundaries, APIs,
    integration patterns
"""

import json
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE / "data" / "wfap-gemini-impl.json"


def meta():
    return {
        "docRef": "WFAP-GEMINI-IMPL-WP-036",
        "version": "1.0.0",
        "date": "2026-04-26",
        "title": "WorkflowAI Pro / GeminiService — Enterprise Implementation Plan",
        "subtitle": (
            "Comprehensive implementation plan, technical architecture, data "
            "models, data flows, governance frameworks, and best-practice "
            "design guidelines for an enterprise AI-driven workflow "
            "recommendation, RAG chat, collaborative prompt engineering, "
            "enterprise model registry, AI safety reporting, and "
            "GeminiService security platform."
        ),
        "classification": (
            "CONFIDENTIAL — Board / Enterprise Architects / AI Platform "
            "Engineers / Internal Audit / DPO"
        ),
        "owner": "Group CTO + Chief AI Officer (CAIO) — co-signed by CISO, DPO, GC",
        "audience": [
            "Board of Directors / Risk & Audit Committees",
            "C-Suite (CEO, CFO, CRO, CISO, CAIO, CTO, COO)",
            "Enterprise architects",
            "AI platform engineers / SREs",
            "Data scientists / prompt engineers",
            "Researchers (AI safety, governance)",
            "Regulators & supervisors (PRA, FCA, OCC, MAS, ICO)",
        ],
        "horizon": "2026-2030",
        "regulatoryAlignment": [
            "EU AI Act (Regulation (EU) 2024/1689) — Articles 5, 9, 10, 12, 13, 14, 15, 53, 55",
            "NIST AI RMF 1.0 + GenAI Profile (AI 600-1)",
            "ISO/IEC 42001:2023 — AI Management System",
            "ISO/IEC 23894:2023 — AI risk management",
            "ISO/IEC 27001:2022 / 27701:2019 / 27018",
            "GDPR / UK GDPR (Articles 5, 6, 22, 25, 32, 33, 34, 35)",
            "OECD AI Principles",
            "OWASP Top 10 for LLM Applications (2025)",
            "MITRE ATLAS / STRIDE / LINDDUN",
            "SR 11-7 / OCC 2011-12 — Model Risk Management",
            "SOC 2 Type II / FedRAMP Moderate",
        ],
        "deliverableInventory": {
            "modules": 12,
            "architectureLayers": 7,
            "dataFlows": 8,
            "dataModels": 9,
            "apis": 110,
            "integrationPatterns": 8,
            "schemas": 8,
            "codeExamples": 12,
            "caseStudies": 5,
            "phases": 6,
            "kpis": 15,
        },
        "subjectSystem": {
            "platform": "WorkflowAI Pro",
            "geminiService": "GeminiService backend integration tier",
            "scope": "Enterprise SaaS / private cloud / hybrid",
            "scale": "10k concurrent workflows · 100k agents · 500k users / tenant",
            "deploymentTopology": "Multi-region active-active; sovereign-cloud variant for EU/UK/US-Gov",
        },
    }


def executive_summary():
    return {
        "purpose": (
            "To deliver a regulator-ready, board-approvable, end-to-end "
            "implementation plan for the WorkflowAI Pro platform with the "
            "GeminiService integration tier — covering architecture, data, "
            "governance, security, AI safety reporting, and operational "
            "excellence."
        ),
        "scope": (
            "All AI capabilities of the platform, from workflow "
            "recommendation and adaptive UX through RAG chat, collaborative "
            "prompt engineering, model registry, and the GeminiService "
            "security/privacy substrate."
        ),
        "designPrinciples": [
            "Compliance-by-design: every capability ships with EU AI Act / GDPR / ISO 42001 controls",
            "Defense-in-depth: 7 architectural planes with independent guardrails",
            "Evidence-as-data: every action emits a signed telemetry envelope",
            "Active learning with human-on-the-loop and cryptographically-signed feedback",
            "Adaptive UX without dark patterns; transparency mandated",
            "Grounded outputs only: RAG answers must cite or refuse",
            "Zero-trust GeminiService: prompt-injection / Art. 5 / PII checks before every call",
        ],
        "keyOutcomes": {
            "timeToGovernedDeployment": "≤ 72 hours",
            "ragGroundednessScore": "≥ 0.92 faithfulness",
            "promptCollabAdoption": "≥ 80% of teams within 6 months",
            "modelRegistryCoverage": "100% of production AI assets tagged & versioned",
            "geminiBlockedHarmRate": "≥ 99.5% on red-team suite",
            "piiLeakageRate": "≤ 0.01% (post-redaction sample audit)",
            "incidentMTTR": "≤ 60 min",
            "auditReadiness": "≥ 92% evidence automation",
        },
        "boardNarrative": (
            "WorkflowAI Pro upgrades enterprise productivity with AI while "
            "treating safety, privacy, and compliance as first-class "
            "platform capabilities — measurable, monitorable, and "
            "demonstrable to regulators."
        ),
    }


def m1_architecture():
    return {
        "id": "M1",
        "title": "M1 — Platform Architecture (7-Plane Reference)",
        "summary": "Seven-plane architecture isolating workload, governance, identity, data, AI, observability, and supply-chain concerns.",
        "sections": [
            {
                "id": "M1-S1",
                "title": "Architecture Planes",
                "planes": [
                    {"id": "P1", "name": "Edge & Identity Plane", "components": ["WAF/CDN", "OIDC IdP", "SCIM", "FIDO2/WebAuthn", "API Gateway"], "responsibilities": "AuthN/AuthZ, rate limiting, geo routing"},
                    {"id": "P2", "name": "Application Plane", "components": ["Next.js frontend", "Node/Express API", "Python services", "BFF", "Webhooks"], "responsibilities": "Feature surfaces, orchestration, tenancy"},
                    {"id": "P3", "name": "AI Plane", "components": ["GeminiService gateway", "Prompt registry", "RAG service", "Recommender", "Active-learning loop"], "responsibilities": "All inference + retrieval"},
                    {"id": "P4", "name": "Governance Plane", "components": ["Model registry", "Policy engine (OPA)", "Compliance engine", "Evidence store"], "responsibilities": "Policy decisions, evidence, attestations"},
                    {"id": "P5", "name": "Data Plane", "components": ["Postgres/CRDB", "Vector DB (pgvector/Weaviate)", "Object store", "Kafka", "Cache"], "responsibilities": "Persistence, lineage, search"},
                    {"id": "P6", "name": "Observability Plane", "components": ["OTel collector", "Prometheus", "Loki/ELK", "WORM telemetry topic", "SIEM"], "responsibilities": "Metrics, logs, traces, audit"},
                    {"id": "P7", "name": "Supply-Chain Plane", "components": ["SLSA L3 build", "Sigstore/Cosign", "SBOM", "Dependency scanner"], "responsibilities": "Build integrity, SBOM, attestations"},
                ],
            },
            {
                "id": "M1-S2",
                "title": "Deployment Topology",
                "tiers": [
                    {"tier": "Edge", "regions": "global PoPs", "tech": "Cloudflare / AWS CloudFront"},
                    {"tier": "App", "regions": "primary + DR", "tech": "EKS/GKE/AKS, blue-green"},
                    {"tier": "AI", "regions": "primary + DR", "tech": "GPU node pools, KEDA, vLLM/Triton"},
                    {"tier": "Data", "regions": "active-active multi-region", "tech": "Aurora/Spanner, replicated S3"},
                ],
            },
            {
                "id": "M1-S3",
                "title": "Tenancy Model",
                "patterns": [
                    "Pool-multi-tenant (default) with row-level security and per-tenant KMS keys",
                    "Silo-per-tenant for regulated tenants (banks, gov)",
                    "Sovereign-cloud variant with in-region GeminiService endpoints",
                ],
            },
        ],
    }


def m2_data_models():
    return {
        "id": "M2",
        "title": "M2 — Data Models",
        "summary": "Core entities and relationships for the platform.",
        "sections": [
            {
                "id": "M2-S1",
                "title": "Entity Catalogue",
                "entities": [
                    {"id": "DM-01", "name": "User", "fields": "userId, tenantId, role[], skillProfile, locale, consents", "owner": "IAM service"},
                    {"id": "DM-02", "name": "Workflow", "fields": "workflowId, ownerId, dag, version, status, tags[]", "owner": "Workflow service"},
                    {"id": "DM-03", "name": "Recommendation", "fields": "recId, userId, candidateWorkflows[], context, score, feedback", "owner": "Recommender"},
                    {"id": "DM-04", "name": "PromptTemplate", "fields": "templateId, versions[], variables[], owner, visibility, tags[], lineage", "owner": "Prompt registry"},
                    {"id": "DM-05", "name": "ModelRegistration", "fields": "modelId, provider, version, sha256, evalRefs[], complianceTags[], rbacPolicyRef, status, rollbackTargetId", "owner": "Model registry"},
                    {"id": "DM-06", "name": "RAGCorpus", "fields": "corpusId, sourceRefs[], lineage, retentionClass, piiPolicy, embeddingModelId", "owner": "RAG service"},
                    {"id": "DM-07", "name": "GeminiCall", "fields": "callId, userId, modelId, promptHash, redactedPrompt, completionHash, safetyDecision, telemetrySig", "owner": "GeminiService"},
                    {"id": "DM-08", "name": "Incident", "fields": "incidentId, severity, signals[], affectedAssets[], status, narrative", "owner": "SOC"},
                    {"id": "DM-09", "name": "EvidenceRecord", "fields": "evidenceId, controlId, payloadHash, merkleRoot, signature, retainUntil", "owner": "Compliance engine"},
                ],
            },
            {
                "id": "M2-S2",
                "title": "Lineage & Versioning",
                "rules": [
                    "All entities are immutable-on-update (event-sourced + materialised views)",
                    "Every mutation emits a signed event into the WORM Kafka topic ai.audit.v1",
                    "PromptTemplate, ModelRegistration, RAGCorpus carry SemVer + content hash",
                    "Rollback = pointer flip to a prior signed version; never a destructive op",
                ],
            },
            {
                "id": "M2-S3",
                "title": "Retention & Classification",
                "classes": [
                    {"class": "C1 Public", "retention": "indefinite", "storage": "S3 standard"},
                    {"class": "C2 Internal", "retention": "5 yr", "storage": "S3 SSE-KMS"},
                    {"class": "C3 Confidential", "retention": "7 yr WORM", "storage": "S3 Object Lock"},
                    {"class": "C4 Restricted/PII", "retention": "policy-driven", "storage": "Tokenised + envelope encryption"},
                ],
            },
        ],
    }


def m3_data_flows():
    return {
        "id": "M3",
        "title": "M3 — Data Flows",
        "summary": "Eight canonical end-to-end flows with governance hooks.",
        "sections": [
            {
                "id": "M3-S1",
                "title": "Flow Catalogue",
                "flows": [
                    {"id": "DF-01", "name": "User → Workflow recommendation", "stages": "context → recommender → policy gate → UI", "governanceHooks": "consent check, fairness probe, telemetry"},
                    {"id": "DF-02", "name": "Active-learning feedback", "stages": "user feedback → signer → kafka → trainer → recommender", "governanceHooks": "Ed25519 signature, bias re-eval"},
                    {"id": "DF-03", "name": "RAG-grounded chat", "stages": "prompt → retriever → reranker → GeminiService → faithfulness scorer → UI", "governanceHooks": "PII redact, citation enforce, refusal policy"},
                    {"id": "DF-04", "name": "Collaborative prompt edit", "stages": "edit → CRDT merge → variable lint → review → publish", "governanceHooks": "RBAC, lineage, prompt-injection lint"},
                    {"id": "DF-05", "name": "Model registration", "stages": "submit → evals → sign → register → tag → rollout", "governanceHooks": "evals coverage, complianceTags, attestation"},
                    {"id": "DF-06", "name": "GeminiService inference", "stages": "request → Art. 5 check → injection guard → call → safety classifier → response", "governanceHooks": "telemetry envelope, decision log"},
                    {"id": "DF-07", "name": "AI safety incident", "stages": "detection → triage → containment → notification → forensic → post-mortem", "governanceHooks": "GDPR Art. 33/34, EU AI Act Art. 73"},
                    {"id": "DF-08", "name": "Adaptive UX evaluation", "stages": "user signal → skill estimator → UX selector → A/B → ethics gate", "governanceHooks": "no dark patterns, transparency, opt-out"},
                ],
            },
            {
                "id": "M3-S2",
                "title": "Governance Hooks (cross-cutting)",
                "hooks": [
                    "Consent verifier (per-purpose GDPR Art. 6/7)",
                    "PII redactor (Microsoft Presidio + custom rules)",
                    "EU AI Act Art. 5 prohibited-practice check",
                    "Prompt-injection / jailbreak detector",
                    "Faithfulness scorer for RAG outputs",
                    "Fairness probe (AIR / SPD windows)",
                    "Telemetry signer (Ed25519, optional Dilithium3)",
                    "Evidence emitter (control → evidence record)",
                ],
            },
        ],
    }


def m4_workflow_recommender():
    return {
        "id": "M4",
        "title": "M4 — AI-Driven Workflow Recommendation & Active Learning",
        "summary": "Two-tower recommender with bandit exploration, signed feedback loop, and bias guardrails.",
        "sections": [
            {
                "id": "M4-S1",
                "title": "Recommender Architecture",
                "components": [
                    "Two-tower retrieval (user tower + workflow tower) on Vertex AI / SageMaker",
                    "Reranker LLM (Gemini Flash) with policy filter",
                    "Contextual bandit (LinUCB) for exploration",
                    "Post-rank fairness pass (group AIR ≥ 0.8)",
                ],
            },
            {
                "id": "M4-S2",
                "title": "Active Learning Loop",
                "stages": [
                    "Implicit feedback: dwell, completion, abandonment",
                    "Explicit feedback: thumbs / rationale / correction",
                    "Cryptographic signature on every feedback event (Ed25519)",
                    "Daily retrain with drift gate (PSI ≤ 0.1, no fairness regression)",
                    "Shadow + canary deploy (5% → 25% → 100%)",
                ],
            },
            {
                "id": "M4-S3",
                "title": "Cold-start & Privacy",
                "controls": [
                    "Skill-profile bootstrap from role + opt-in onboarding survey",
                    "Federated personalisation option (no raw signals leave device)",
                    "Differential privacy noise (ε ≤ 4) on aggregate analytics",
                ],
            },
            {
                "id": "M4-S4",
                "title": "APIs",
                "routes": [
                    "POST /api/recommend/workflows",
                    "POST /api/recommend/feedback",
                    "GET  /api/recommend/profile",
                    "POST /api/recommend/retrain (admin)",
                ],
            },
        ],
    }


def m5_adaptive_ux():
    return {
        "id": "M5",
        "title": "M5 — Adaptive Content & UI by Context and Skill",
        "summary": "Skill-aware progressive disclosure and content adaptation with anti-dark-pattern guardrails.",
        "sections": [
            {
                "id": "M5-S1",
                "title": "Skill Estimator",
                "design": [
                    "Bayesian skill model per capability (workflow design, prompt eng, data analysis)",
                    "Inputs: completion of guided tasks, support tickets, self-rating",
                    "Decay function for inactivity",
                ],
            },
            {
                "id": "M5-S2",
                "title": "UX Adaptation Patterns",
                "patterns": [
                    "Progressive disclosure tiers: Novice / Practitioner / Expert / Power",
                    "Inline coaching with dismissible cards",
                    "Reading-level adaptation (Flesch-Kincaid 8/12/16)",
                    "Locale + accessibility (WCAG 2.2 AA, ARIA, keyboard-only)",
                ],
            },
            {
                "id": "M5-S3",
                "title": "Ethics & Transparency",
                "guardrails": [
                    "No dark patterns (FTC + EU 2026 Digital Fairness Act)",
                    "Always-visible 'Why am I seeing this?' explainer",
                    "User-facing UX preference reset",
                    "Adaptation events emitted with consent flag",
                ],
            },
        ],
    }


def m6_rag_chat():
    return {
        "id": "M6",
        "title": "M6 — High-Assurance RAG-Based Grounded Chat",
        "summary": "RAG with lineage, citation enforcement, faithfulness scoring, and refusal-on-low-evidence.",
        "sections": [
            {
                "id": "M6-S1",
                "title": "Retrieval Pipeline",
                "stages": [
                    "Query rewrite (intent + decomposition)",
                    "Hybrid search (BM25 + dense + filters)",
                    "Reranker (cross-encoder)",
                    "Context window builder with token budget + diversity",
                    "Citation pinner (chunk-level provenance)",
                ],
            },
            {
                "id": "M6-S2",
                "title": "Generation & Faithfulness",
                "controls": [
                    "Constrained generation: 'cite or refuse'",
                    "Faithfulness score (Q²/AlignScore/RAGAS) gating ≥ 0.92",
                    "Hallucination flag on unsupported claims",
                    "Refusal templates: 'I do not have evidence in your corpus to answer that.'",
                ],
            },
            {
                "id": "M6-S3",
                "title": "Corpus Governance",
                "controls": [
                    "Source allowlist & licence metadata",
                    "PII redaction at ingestion (Presidio + DLP)",
                    "Retention class on every chunk",
                    "Per-document RBAC enforced at query time (post-retrieval filter)",
                    "Right-to-be-forgotten propagation (vector deletion + reindex)",
                ],
            },
            {
                "id": "M6-S4",
                "title": "APIs",
                "routes": [
                    "POST /api/rag/chat",
                    "POST /api/rag/ingest",
                    "DELETE /api/rag/document/:id (RTBF)",
                    "GET  /api/rag/corpus/:id/manifest",
                ],
            },
        ],
    }


def m7_prompt_collab():
    return {
        "id": "M7",
        "title": "M7 — Collaborative Prompt Engineering",
        "summary": "Multi-user prompt template lifecycle with CRDT editing, lineage, and review workflow.",
        "sections": [
            {
                "id": "M7-S1",
                "title": "Lifecycle Stages",
                "stages": ["Draft", "Review", "Approved", "Published", "Deprecated", "Archived"],
            },
            {
                "id": "M7-S2",
                "title": "Collaboration Mechanics",
                "design": [
                    "CRDT (Yjs) for real-time co-editing",
                    "Variable schema with type, default, sensitivity",
                    "Variable-link UI to dataset / workflow context",
                    "Live test panel against canary model + sample dataset",
                    "PR-style review: 2-of-N approvers; CI runs eval suite",
                ],
            },
            {
                "id": "M7-S3",
                "title": "Lineage & Provenance",
                "controls": [
                    "Every version content-addressed (sha256)",
                    "Parent/child template links + diff view",
                    "Usage telemetry: per-template invocation count, faithfulness, satisfaction",
                    "Export/import as signed bundles (tar.gz + sig)",
                ],
            },
            {
                "id": "M7-S4",
                "title": "APIs",
                "routes": [
                    "POST /api/prompts/templates",
                    "GET  /api/prompts/templates/:id",
                    "PATCH /api/prompts/templates/:id",
                    "POST /api/prompts/templates/:id/review",
                    "POST /api/prompts/templates/:id/publish",
                    "GET  /api/prompts/templates/:id/lineage",
                    "POST /api/prompts/test",
                ],
            },
        ],
    }


def m8_model_registry():
    return {
        "id": "M8",
        "title": "M8 — Enterprise Model Registry Governance",
        "summary": "RBAC, compliance metadata, rollback, tagging, attestations.",
        "sections": [
            {
                "id": "M8-S1",
                "title": "Registry Schema",
                "fields": [
                    "modelId, provider, family, version, sha256",
                    "evalRefs[]: pointers to eval suites and results",
                    "complianceTags[]: 'EU_AI_ACT_HIGH_RISK', 'GDPR_DPIA', 'SR_11_7_TIER_1'",
                    "rbacPolicyRef: OPA bundle key",
                    "status: draft|registered|approved|published|paused|retired",
                    "rollbackTargetId: previous-known-good model pointer",
                    "ownerSubjectId; approvers[]; signatures[]",
                ],
            },
            {
                "id": "M8-S2",
                "title": "RBAC & Policy",
                "roles": [
                    "model_author", "model_validator", "model_approver", "model_operator",
                    "auditor (read-only)", "dpo (read+veto on PII concerns)",
                ],
                "policies": [
                    "deploy_gate.rego: signature + IMV + DPIA non-expired",
                    "high_risk_label.rego: Annex IV dossier present",
                    "rollback_window.rego: rollback always within 30s window",
                ],
            },
            {
                "id": "M8-S3",
                "title": "Tagging & Search",
                "design": [
                    "Tag namespace: regulatory, sector, capability, sensitivity, lifecycle",
                    "Full-text + facet search across registry",
                    "Saved queries for audit & supervisor read-only views",
                ],
            },
            {
                "id": "M8-S4",
                "title": "APIs",
                "routes": [
                    "POST /api/models/register",
                    "GET  /api/models/:id",
                    "POST /api/models/:id/approve",
                    "POST /api/models/:id/publish",
                    "POST /api/models/:id/rollback",
                    "POST /api/models/:id/tag",
                    "GET  /api/models/search",
                    "GET  /api/models/:id/attestations",
                ],
            },
        ],
    }


def m9_safety_reporting():
    return {
        "id": "M9",
        "title": "M9 — AI Safety & Global Governance Reporting",
        "summary": "Reporting framework spanning existential risk, misuse, bias, threat assessment, alignment failure, and international collaboration.",
        "sections": [
            {
                "id": "M9-S1",
                "title": "Report Catalogue",
                "reports": [
                    {"id": "SR-01", "name": "Existential Risk Outlook", "cadence": "Annual", "audience": "Board + Treaty Authority"},
                    {"id": "SR-02", "name": "Misuse & Dual-Use Threat Assessment", "cadence": "Semi-annual", "audience": "CISO + Treaty + GC"},
                    {"id": "SR-03", "name": "Bias & Fairness Report", "cadence": "Quarterly", "audience": "DPO + Compliance + Board"},
                    {"id": "SR-04", "name": "Alignment Failure Scenarios", "cadence": "Quarterly tabletop + post-incident", "audience": "Board + CAIO + research community"},
                    {"id": "SR-05", "name": "International Collaboration Brief", "cadence": "Quarterly", "audience": "Treaty Liaison Officer"},
                    {"id": "SR-06", "name": "Capability Evaluation Disclosure", "cadence": "Per material capability change", "audience": "ICGC / regulator"},
                    {"id": "SR-07", "name": "Incident & Near-Miss Register", "cadence": "Continuous", "audience": "CISO + Internal Audit"},
                    {"id": "SR-08", "name": "Annual AI Safety Statement", "cadence": "Annual public", "audience": "Public + investors"},
                ],
            },
            {
                "id": "M9-S2",
                "title": "Risk Taxonomy",
                "categories": [
                    "Existential / civilizational",
                    "Misuse (CBRN, cyber, mass-disinfo)",
                    "Bias / disparate impact",
                    "Privacy / re-identification",
                    "Alignment failure (specification gaming, deceptive alignment)",
                    "Containment escape / agentic over-reach",
                    "Concentration / monoculture",
                    "Conduct / consumer harm",
                ],
            },
            {
                "id": "M9-S3",
                "title": "International Collaboration",
                "channels": [
                    "ICGC compute & capability disclosure",
                    "Bletchley/Seoul/Paris commitments",
                    "OECD AI Policy Observatory",
                    "G7 Hiroshima AI Process Code of Conduct",
                    "AISI / UK AISI / US AISI evaluation participation",
                    "Council of Europe AI Convention compliance",
                ],
            },
            {
                "id": "M9-S4",
                "title": "APIs",
                "routes": [
                    "GET  /api/safety/reports",
                    "GET  /api/safety/reports/:id",
                    "POST /api/safety/incidents",
                    "GET  /api/safety/risk-register",
                    "POST /api/safety/disclosures (treaty)",
                ],
            },
        ],
    }


def m10_gemini_security():
    return {
        "id": "M10",
        "title": "M10 — GeminiService Security & Privacy Controls",
        "summary": "Telemetry integrity, GDPR PII redaction, EU AI Act Art. 5 checks, adversarial-prompt defenses.",
        "sections": [
            {
                "id": "M10-S1",
                "title": "GeminiService Gateway",
                "design": [
                    "All Gemini calls routed through internal gateway (no direct SDK from frontend)",
                    "Per-tenant API keys vaulted in HSM/KMS",
                    "mTLS to provider; egress allowlist; outbound DLP",
                    "Per-call decision log signed (Ed25519) and shipped to WORM Kafka",
                ],
            },
            {
                "id": "M10-S2",
                "title": "Pre-Call Pipeline (in order)",
                "stages": [
                    "1. AuthN/AuthZ (OIDC + scope + tenancy)",
                    "2. Rate / cost guard (token budget per user/tenant)",
                    "3. PII redactor (Presidio + custom regex + ML classifier)",
                    "4. EU AI Act Art. 5 prohibited-practice classifier (manipulation, social scoring, biometric categorisation, predictive policing for individuals, etc.)",
                    "5. Prompt-injection / jailbreak detector (rules + LLM judge + perplexity heuristic)",
                    "6. Constitutional / policy filter",
                    "7. Telemetry envelope creation + signature",
                ],
            },
            {
                "id": "M10-S3",
                "title": "Post-Call Pipeline",
                "stages": [
                    "1. Output safety classifier (toxicity, self-harm, illegal, CSAM)",
                    "2. PII / secrets leakage scan (egress redactor)",
                    "3. Faithfulness / citation check (RAG path)",
                    "4. Final policy filter; deliver or refuse",
                    "5. Append response hash + final decision to telemetry envelope",
                ],
            },
            {
                "id": "M10-S4",
                "title": "Telemetry Integrity",
                "controls": [
                    "Append-only Kafka topic ai.gemini.telemetry.v1 with mTLS + ACLs",
                    "Daily Merkle root anchored to RFC 3161 timestamp + (optional) blockchain anchor",
                    "PQC-ready signatures (Dilithium3 dual-signature option)",
                    "Tamper alarms on hash-chain breaks (auto-incident creation)",
                ],
            },
            {
                "id": "M10-S5",
                "title": "Adversarial Defenses",
                "defenses": [
                    "Multi-layer prompt-injection detection (pre-, mid-, post-)",
                    "Tool-call allowlisting + scoped credentials per call",
                    "Indirect-prompt-injection sanitisation on retrieved content",
                    "Canary tokens to detect data exfiltration via prompts",
                    "Red-team test suite gated in CI (block release if regression)",
                ],
            },
            {
                "id": "M10-S6",
                "title": "APIs",
                "routes": [
                    "POST /api/gemini/generate",
                    "POST /api/gemini/embed",
                    "POST /api/gemini/vision",
                    "GET  /api/gemini/telemetry/:callId",
                    "GET  /api/gemini/policies",
                ],
            },
        ],
    }


def m11_task_report():
    return {
        "id": "M11",
        "title": "M11 — Task & Report Management",
        "summary": "End-user and admin features for tasks, reports, exports, and audit packs.",
        "sections": [
            {
                "id": "M11-S1",
                "title": "Task Management",
                "features": [
                    "Task DAG visualisation (D3/dagre)",
                    "Assignment & SLA tracking",
                    "Comments + @mentions + activity stream",
                    "Linked artefacts: prompts, models, RAG corpora, evidence",
                    "Bulk operations with idempotency keys",
                ],
            },
            {
                "id": "M11-S2",
                "title": "Report Generation",
                "features": [
                    "Templated reports (Markdown with <title>/<abstract>/<content>)",
                    "PDF/A-3 export with embedded JSON-LD evidence",
                    "Scheduled reports (cron + event-driven)",
                    "Distribution: email (DMARC), Slack/Teams, SFTP, S3 dropzone",
                    "Auditor read-only export channel",
                ],
            },
            {
                "id": "M11-S3",
                "title": "APIs",
                "routes": [
                    "POST /api/tasks",
                    "GET  /api/tasks/:id",
                    "PATCH /api/tasks/:id",
                    "POST /api/tasks/:id/comment",
                    "GET  /api/reports/templates",
                    "POST /api/reports/render",
                    "POST /api/reports/schedule",
                    "GET  /api/reports/exports/:id",
                ],
            },
        ],
    }


def m12_implementation_strategy():
    return {
        "id": "M12",
        "title": "M12 — Implementation Strategy & Integration Patterns",
        "summary": "Step-by-step strategy, module boundaries, and integration patterns for enterprise deployment.",
        "sections": [
            {
                "id": "M12-S1",
                "title": "Six-Phase Plan (52 weeks)",
                "phases": [
                    {"phase": "P1 Foundations", "weeks": "1-6", "deliverables": ["Tenancy model", "Identity (OIDC/SCIM)", "OPA bundle bootstrap", "Kafka WORM cluster", "Skeleton APIs"]},
                    {"phase": "P2 Governance Spine", "weeks": "7-14", "deliverables": ["Model registry + RBAC", "Compliance engine", "Evidence store", "Telemetry envelopes"]},
                    {"phase": "P3 AI Core", "weeks": "15-26", "deliverables": ["GeminiService gateway", "Prompt registry + collab", "RAG service + faithfulness", "Recommender v1"]},
                    {"phase": "P4 Adaptive UX & Tasks", "weeks": "27-34", "deliverables": ["Skill estimator", "Adaptive UI", "Task DAG", "Reports v1"]},
                    {"phase": "P5 Safety Reporting & Treaty", "weeks": "35-44", "deliverables": ["Safety report suite", "Treaty disclosure pack", "Tabletop GC1-GC7"]},
                    {"phase": "P6 Hardening & Certification", "weeks": "45-52", "deliverables": ["ISO 42001 cert", "SOC 2 Type II", "Annex IV pilots", "Pen-test + red-team"]},
                ],
            },
            {
                "id": "M12-S2",
                "title": "Module Boundaries",
                "boundaries": [
                    "Identity service (P1) — single source of truth for users/roles",
                    "Workflow service — owns workflow DAGs; consumes recommendations",
                    "Recommender service — stateless API; trained offline; reads features from feature store",
                    "Prompt registry — owns templates + lineage; emits events",
                    "RAG service — owns corpora + retrieval; isolates per-tenant indices",
                    "Model registry — owns ModelRegistration; enforces RBAC + signatures",
                    "GeminiService gateway — single egress point to provider",
                    "Compliance engine — read-side projection from event log; emits coverage scorecards",
                    "Observability — strictly read-only consumer of telemetry topics",
                ],
            },
            {
                "id": "M12-S3",
                "title": "Integration Patterns",
                "patterns": [
                    "Event-driven via Kafka (ai.audit.v1, ai.gemini.telemetry.v1, ai.recsys.events.v1)",
                    "Synchronous REST/gRPC behind API gateway with mTLS",
                    "Webhooks for tenant-side integrations (signed payloads, replay protection)",
                    "OIDC-federated SSO + SCIM provisioning",
                    "Outbound connectors: Slack/Teams, Jira, ServiceNow, Splunk, Datadog",
                    "Data-residency routing via gateway + per-region GeminiService endpoints",
                    "Sovereign-cloud variant with no cross-border calls",
                    "BYOK (Bring-Your-Own-Key) for tenant KMS",
                ],
            },
            {
                "id": "M12-S4",
                "title": "KPIs / OKRs",
                "kpis": [
                    {"id": "KPI-01", "name": "Time-to-governed-deployment", "target": "≤ 72 h"},
                    {"id": "KPI-02", "name": "RAG faithfulness", "target": "≥ 0.92"},
                    {"id": "KPI-03", "name": "Prompt collab adoption", "target": "≥ 80% teams"},
                    {"id": "KPI-04", "name": "Model registry coverage", "target": "100%"},
                    {"id": "KPI-05", "name": "Gemini blocked-harm rate", "target": "≥ 99.5%"},
                    {"id": "KPI-06", "name": "PII leakage", "target": "≤ 0.01%"},
                    {"id": "KPI-07", "name": "Containment MTTR", "target": "≤ 60 min"},
                    {"id": "KPI-08", "name": "Evidence automation", "target": "≥ 92%"},
                    {"id": "KPI-09", "name": "Alignment-drift MTTD", "target": "≤ 4 min"},
                    {"id": "KPI-10", "name": "Active-learning loop latency", "target": "≤ 24 h to retrain"},
                    {"id": "KPI-11", "name": "Adaptive-UX opt-out completion", "target": "≤ 3 clicks"},
                    {"id": "KPI-12", "name": "Audit finding closure", "target": "≤ 90 d (high)"},
                    {"id": "KPI-13", "name": "Recommender AIR floor", "target": "≥ 0.8"},
                    {"id": "KPI-14", "name": "Telemetry continuity", "target": "≥ 99.99%"},
                    {"id": "KPI-15", "name": "Adversarial-prompt block rate", "target": "≥ 99% on red-team set"},
                ],
            },
            {
                "id": "M12-S5",
                "title": "Risk Register (top 8)",
                "risks": [
                    {"id": "R1", "name": "Prompt-injection via retrieved content", "mitigation": "Indirect-injection sanitiser + tool allowlist"},
                    {"id": "R2", "name": "Hallucination in RAG chat", "mitigation": "Faithfulness gate + cite-or-refuse"},
                    {"id": "R3", "name": "PII leakage to provider", "mitigation": "Pre-call redactor + egress DLP + telemetry audit"},
                    {"id": "R4", "name": "Bias amplification via active learning", "mitigation": "Per-loop fairness gate + counterfactual eval"},
                    {"id": "R5", "name": "Model rollback failure", "mitigation": "Always-on N-1 hot path + 30s rollback test in CI"},
                    {"id": "R6", "name": "Telemetry tampering", "mitigation": "Hash-chained WORM + Merkle anchor + alarms"},
                    {"id": "R7", "name": "EU AI Act Art. 5 violation in user prompt", "mitigation": "Pre-call classifier + refusal templates"},
                    {"id": "R8", "name": "Concentration risk on Gemini", "mitigation": "Multi-provider abstraction + benchmark fail-over"},
                ],
            },
        ],
    }


def schemas():
    return {
        "promptTemplate": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/prompt-template.json",
            "type": "object",
            "required": ["templateId", "version", "owner", "body", "variables"],
            "properties": {
                "templateId": {"type": "string"},
                "version": {"type": "string"},
                "owner": {"type": "string"},
                "body": {"type": "string"},
                "variables": {"type": "array", "items": {"type": "object",
                    "required": ["name", "type"],
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"enum": ["string", "number", "bool", "enum", "json"]},
                        "default": {},
                        "sensitivity": {"enum": ["public", "internal", "confidential", "pii"]},
                        "linkTo": {"type": "string"},
                    }}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "lineage": {"type": "object"},
            },
        },
        "modelRegistration": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/model-registration.json",
            "type": "object",
            "required": ["modelId", "provider", "version", "sha256", "status"],
            "properties": {
                "modelId": {"type": "string"},
                "provider": {"type": "string"},
                "version": {"type": "string"},
                "sha256": {"type": "string", "pattern": "^[A-Fa-f0-9]{64}$"},
                "evalRefs": {"type": "array", "items": {"type": "string"}},
                "complianceTags": {"type": "array", "items": {"type": "string"}},
                "rbacPolicyRef": {"type": "string"},
                "status": {"enum": ["draft", "registered", "approved", "published", "paused", "retired"]},
                "rollbackTargetId": {"type": "string"},
                "signatures": {"type": "array"},
            },
        },
        "ragQueryEnvelope": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/rag-query-envelope.json",
            "type": "object",
            "required": ["queryId", "userId", "tenantId", "corpusId", "query", "ts"],
            "properties": {
                "queryId": {"type": "string"},
                "userId": {"type": "string"},
                "tenantId": {"type": "string"},
                "corpusId": {"type": "string"},
                "query": {"type": "string"},
                "ts": {"type": "string", "format": "date-time"},
                "redactionFlags": {"type": "array"},
                "consents": {"type": "object"},
            },
        },
        "geminiCallEnvelope": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/gemini-call-envelope.json",
            "type": "object",
            "required": ["callId", "userId", "modelId", "promptHash", "ts", "signature"],
            "properties": {
                "callId": {"type": "string"},
                "userId": {"type": "string"},
                "tenantId": {"type": "string"},
                "modelId": {"type": "string"},
                "promptHash": {"type": "string"},
                "redactedPromptPreview": {"type": "string"},
                "completionHash": {"type": "string"},
                "safetyDecision": {"enum": ["allow", "warn", "refuse"]},
                "art5Decision": {"enum": ["allow", "block"]},
                "injectionScore": {"type": "number"},
                "ts": {"type": "string", "format": "date-time"},
                "signature": {"type": "object", "required": ["alg", "value", "keyId"]},
            },
        },
        "feedbackEvent": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/feedback-event.json",
            "type": "object",
            "required": ["eventId", "userId", "subjectId", "subjectType", "verdict", "signature"],
            "properties": {
                "eventId": {"type": "string"},
                "userId": {"type": "string"},
                "subjectId": {"type": "string"},
                "subjectType": {"enum": ["recommendation", "rag-answer", "prompt", "workflow"]},
                "verdict": {"enum": ["up", "down", "correct", "abandon"]},
                "rationale": {"type": "string"},
                "signature": {"type": "object"},
            },
        },
        "recommendation": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/recommendation.json",
            "type": "object",
            "required": ["recId", "userId", "candidates", "ts"],
            "properties": {
                "recId": {"type": "string"},
                "userId": {"type": "string"},
                "candidates": {"type": "array", "items": {"type": "object",
                    "properties": {"workflowId": {"type": "string"}, "score": {"type": "number"}, "reasonCodes": {"type": "array"}}}},
                "context": {"type": "object"},
                "fairness": {"type": "object"},
                "ts": {"type": "string", "format": "date-time"},
            },
        },
        "evidenceRecord": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/evidence-record.json",
            "type": "object",
            "required": ["evidenceId", "controlId", "payloadHash", "merkleRoot", "signature", "retainUntil"],
            "properties": {
                "evidenceId": {"type": "string"},
                "controlId": {"type": "string"},
                "payloadHash": {"type": "string"},
                "merkleRoot": {"type": "string"},
                "signature": {"type": "object"},
                "retainUntil": {"type": "string", "format": "date-time"},
            },
        },
        "incidentRecord": {
            "$id": "https://workflowai.pro/schemas/wfap-gemini/incident-record.json",
            "type": "object",
            "required": ["incidentId", "severity", "status", "openedAt"],
            "properties": {
                "incidentId": {"type": "string"},
                "severity": {"enum": ["SEV-3", "SEV-2", "SEV-1", "SEV-0"]},
                "status": {"enum": ["open", "contained", "resolved", "post-mortem"]},
                "category": {"type": "string"},
                "affectedAssets": {"type": "array"},
                "openedAt": {"type": "string", "format": "date-time"},
                "narrative": {"type": "string"},
            },
        },
    }


def code_examples():
    return {
        "geminiGatewayPython": '''#!/usr/bin/env python3
"""GeminiService gateway — pre/post pipeline (FastAPI)."""
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import hashlib, time
from cryptography.hazmat.primitives.asymmetric import ed25519
from policy import art5_check, injection_score, redact_pii, output_safety

app = FastAPI()
SK = ed25519.Ed25519PrivateKey.generate()  # demo only; load from KMS

class GenReq(BaseModel):
    user_id: str
    tenant_id: str
    model_id: str
    prompt: str

@app.post("/api/gemini/generate")
def generate(req: GenReq, authorization: str = Header(...)):
    redacted, flags = redact_pii(req.prompt)
    if art5_check(redacted) == "block":
        raise HTTPException(451, "Art. 5 prohibited practice")
    if injection_score(redacted) > 0.85:
        raise HTTPException(400, "prompt injection suspected")
    completion = call_gemini(req.model_id, redacted)
    if output_safety(completion) == "refuse":
        return {"refused": True, "reason": "safety classifier"}
    envelope = {
        "callId": hashlib.sha256(f"{req.user_id}{time.time_ns()}".encode()).hexdigest(),
        "userId": req.user_id, "tenantId": req.tenant_id,
        "modelId": req.model_id,
        "promptHash": hashlib.sha256(req.prompt.encode()).hexdigest(),
        "completionHash": hashlib.sha256(completion.encode()).hexdigest(),
        "safetyDecision": "allow", "art5Decision": "allow",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    sig = SK.sign(json.dumps(envelope, sort_keys=True).encode()).hex()
    envelope["signature"] = {"alg": "Ed25519", "value": sig, "keyId": "kms:gemini-gw-2026"}
    emit_kafka("ai.gemini.telemetry.v1", envelope)
    return {"completion": completion, "envelope": envelope}
''',
        "ragChatTypeScript": '''// /api/rag/chat — Express + retriever + faithfulness gate
import express from "express";
import { hybridSearch, rerank, faithfulness, redact } from "./rag";
const app = express();
app.use(express.json());

app.post("/api/rag/chat", async (req, res) => {
  const { tenantId, userId, corpusId, question } = req.body;
  const safe = redact(question);
  const hits = await hybridSearch(corpusId, safe, { tenantAcl: tenantId });
  const ranked = await rerank(safe, hits);
  if (ranked.length === 0) {
    return res.json({ refused: true, reason: "no evidence in corpus" });
  }
  const draft = await callGemini({ system: SYSTEM_CITE_OR_REFUSE, ctx: ranked, q: safe });
  const score = await faithfulness(draft, ranked);
  if (score < 0.92) {
    return res.json({ refused: true, reason: "low faithfulness", score });
  }
  res.json({ answer: draft, citations: ranked.map(r => r.docRef), score });
});
''',
        "modelRegistryNode": '''// Model registry — register / approve / rollback
const express = require("express");
const { sign, verify } = require("./pqc");
const opa = require("./opa");
const router = express.Router();

router.post("/api/models/register", async (req, res) => {
  const m = req.body;
  if (!/^[A-Fa-f0-9]{64}$/.test(m.sha256)) return res.status(400).json({ error: "bad sha256" });
  const decision = await opa.eval("wfap.deploy_gate.allow", { model: m });
  if (!decision.allow) return res.status(403).json(decision);
  m.status = "registered";
  m.signatures = [sign(m)];
  await db.models.insert(m);
  res.json(m);
});

router.post("/api/models/:id/rollback", async (req, res) => {
  const cur = await db.models.find(req.params.id);
  if (!cur.rollbackTargetId) return res.status(400).json({ error: "no rollback target" });
  const tgt = await db.models.find(cur.rollbackTargetId);
  await db.models.update(cur.id, { status: "paused" });
  await db.models.update(tgt.id, { status: "published" });
  emitAudit({ type: "model.rollback", from: cur.id, to: tgt.id });
  res.json({ rolledBackTo: tgt.id });
});

module.exports = router;
''',
        "promptCollabCRDT": '''// Prompt template collaborative editor (Yjs server)
const Y = require("yjs");
const { setupWSConnection } = require("y-websocket/bin/utils");
const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 1234 });
wss.on("connection", (conn, req) => {
  const auth = verifyJwt(req.headers["sec-websocket-protocol"]);
  if (!auth) return conn.close(4401);
  setupWSConnection(conn, req, {
    docName: `prompt:${auth.tenantId}:${req.url.slice(1)}`,
    gc: true,
  });
  conn.on("close", () => emitAudit({ type: "prompt.session.close", user: auth.sub }));
});
''',
        "recommenderActiveLearning": '''#!/usr/bin/env python3
"""Active-learning loop — drift gate + fairness gate."""
import pandas as pd, numpy as np
from cryptography.hazmat.primitives.asymmetric import ed25519

def psi(a, b, bins=10):
    qs = np.linspace(0,1,bins+1)
    cuts = np.quantile(np.concatenate([a,b]), qs)
    pa,_ = np.histogram(a, cuts); pa = pa/pa.sum()+1e-9
    pb,_ = np.histogram(b, cuts); pb = pb/pb.sum()+1e-9
    return float(np.sum((pa-pb)*np.log(pa/pb)))

def air(scores, group):
    rates = pd.Series(scores).groupby(group).mean()
    return rates.min()/rates.max()

def gate(new_scores, old_scores, groups):
    if psi(new_scores, old_scores) > 0.1: raise SystemExit("PSI drift")
    if air(new_scores, groups) < 0.8:    raise SystemExit("AIR floor")
    print("PASS")
''',
        "regoDeployGate": '''package wfap.deploy_gate

# OPA policy gating model deployment
default allow = false

allow {
  input.model.signatures[_].verified
  input.model.evalRefs[_]
  not expired_dpia
  has_required_tags
}

expired_dpia {
  time.parse_rfc3339_ns(input.model.dpia.expiresAt) < time.now_ns()
}

has_required_tags {
  required := {"FAIRNESS_TESTED", "PII_REDACTION_VERIFIED"}
  set := {t | t := input.model.complianceTags[_]}
  required - set == set()
}
''',
        "art5Classifier": '''#!/usr/bin/env python3
"""EU AI Act Art. 5 prohibited-practice classifier (heuristic + LLM judge)."""
PROHIBITED = [
    "subliminal_techniques",
    "exploitation_of_vulnerabilities",
    "social_scoring_individuals",
    "biometric_categorisation_sensitive",
    "real_time_remote_biometric_id",
    "predictive_policing_individual",
    "emotion_recognition_workplace_education",
    "untargeted_facial_image_scraping",
]

def art5_check(text: str) -> str:
    # 1. rule-based fast path
    if any(k in text.lower() for k in ["social score", "rank citizens", "predict who will commit"]):
        return "block"
    # 2. LLM judge (Gemini Flash) — JSON schema response
    judge = call_gemini_judge(text, PROHIBITED)
    return "block" if judge.get("matches") else "allow"
''',
        "piiRedactorPython": '''#!/usr/bin/env python3
"""GDPR PII redactor — Presidio + custom rules."""
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

ANALYZER = AnalyzerEngine()
ANON = AnonymizerEngine()

def redact_pii(text: str, lang: str = "en"):
    results = ANALYZER.analyze(text=text, language=lang,
        entities=["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD",
                  "IBAN_CODE","IP_ADDRESS","LOCATION","UK_NHS","US_SSN"])
    out = ANON.anonymize(text=text, analyzer_results=results)
    flags = sorted({r.entity_type for r in results})
    return out.text, flags
''',
        "merkleAuditTelemetry": '''#!/usr/bin/env python3
"""Daily Merkle audit of GeminiService telemetry."""
import hashlib, json, time, boto3

def merkle(leaves):
    layer = [hashlib.sha256(l).digest() for l in leaves] or [b""]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i]+layer[i+1]).digest()
                 for i in range(0,len(layer),2)]
    return layer[0]

def daily(bucket, prefix):
    s3 = boto3.client("s3")
    leaves = [s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
              for o in s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])]
    root = merkle(leaves).hex()
    manifest = {"date": time.strftime("%Y-%m-%d"), "merkleRoot": root, "leaves": len(leaves)}
    s3.put_object(Bucket=bucket, Key=f"{prefix}/_manifests/{manifest['date']}.json",
                  Body=json.dumps(manifest).encode(),
                  ObjectLockMode="COMPLIANCE",
                  ObjectLockRetainUntilDate="2033-01-01T00:00:00Z")
    return manifest
''',
        "ciGithubWorkflow": '''# .github/workflows/wfap-gemini.yml
name: wfap-gemini-ci
on: [push, pull_request]
jobs:
  govern:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: opa fmt --diff policies/ && opa test policies/
      - run: conftest test --policy policies deploy/
      - run: pytest tests/redteam tests/art5 tests/injection -q
      - run: python tools/faithfulness_eval.py --threshold 0.92
      - run: python tools/bias_gate.py --air 0.8 --psi 0.1
      - run: |
          docker build -t wfap-gemini:${{ github.sha }} .
          cosign sign --yes wfap-gemini:${{ github.sha }}
          cosign attest --predicate evidence.json wfap-gemini:${{ github.sha }}
      - run: kubectl apply -f deploy/canary-5pct.yaml
''',
        "adaptiveUxReact": '''// React hook: useAdaptiveUx — skill-tier gating with ethics guardrails
import { useState, useEffect } from "react";

export function useAdaptiveUx(capability) {
  const [tier, setTier] = useState("practitioner");
  const [transparency, setTransparency] = useState(true);

  useEffect(() => {
    fetch(`/api/skill/${capability}`).then(r => r.json()).then(s => {
      setTier(s.tier);
    });
  }, [capability]);

  const reasonCard = (
    <button onClick={() => alert(`UI tier '${tier}' chosen from your skill profile. You can reset under Settings → UX.`)}>
      Why am I seeing this?
    </button>
  );
  return { tier, transparency, reasonCard };
}
''',
        "kafkaWormProducer": '''// signed-telemetry producer (Node)
const { Kafka } = require("kafkajs");
const { sign } = require("./signer-ed25519");
const k = new Kafka({ brokers: process.env.KAFKA_BROKERS.split(",") });
const p = k.producer({ idempotent: true });
async function send(topic, payload) {
  await p.connect();
  const env = { ...payload, ts: new Date().toISOString() };
  env.signature = sign(JSON.stringify(env));
  await p.send({ topic, messages: [{ key: env.callId || env.eventId, value: JSON.stringify(env) }] });
}
module.exports = { send };
''',
    }


def case_studies():
    return [
        {
            "id": "CS-01",
            "title": "Global bank — WorkflowAI Pro on regulated estate",
            "sector": "Banking",
            "summary": "Tier-1 bank deployed WorkflowAI Pro across 38k users with full SR 11-7 + EU AI Act alignment.",
            "outcomes": {
                "users": 38000,
                "modelsRegistered": 412,
                "promptTemplatesPublished": 1840,
                "ragGroundedness": "0.94 avg",
                "geminiBlockedHarmRate": "99.7%",
                "ISO42001": "Certified",
            },
        },
        {
            "id": "CS-02",
            "title": "Pharma — RAG chat for SMEs and regulators",
            "sector": "Life Sciences",
            "summary": "RAG chat over GxP-controlled corpora with zero hallucination tolerance and audit trail.",
            "outcomes": {
                "corpora": 22,
                "monthlyQueries": 1.4e6,
                "hallucinationIncidents": 0,
                "regulatoryEngagement": "FDA + EMA satisfied",
            },
        },
        {
            "id": "CS-03",
            "title": "Public sector — Sovereign-cloud variant",
            "sector": "Government",
            "summary": "G7 ministry deployed sovereign-cloud variant with in-region GeminiService and air-gapped admin.",
            "outcomes": {
                "dataResidency": "100%",
                "treatyDisclosures": 4,
                "redTeamPassRate": "99.3%",
            },
        },
        {
            "id": "CS-04",
            "title": "Insurer — Fairness-aware recommender",
            "sector": "Insurance",
            "summary": "Workflow recommender personalised to claims handlers with strict fairness floor (AIR ≥ 0.85).",
            "outcomes": {
                "AIRAfter": 0.88,
                "handlerProductivity": "+19%",
                "consumerComplaints": "-23%",
            },
        },
        {
            "id": "CS-05",
            "title": "Tech conglomerate — Collaborative prompt engineering at scale",
            "sector": "Technology",
            "summary": "300+ teams onboarded to collaborative prompt registry with PR-style review and CI evals.",
            "outcomes": {
                "templatesActive": 6200,
                "averageReviewTime": "37 min",
                "evalRegressionsBlocked": 184,
                "adoption": "92% of eligible teams",
            },
        },
    ]


def api_endpoints():
    routes = [
        "", "/meta", "/executive-summary", "/summary",
        "/architecture", "/architecture/planes", "/architecture/topology", "/architecture/tenancy",
        "/data-models", "/data-models/:id",
        "/data-flows", "/data-flows/:id",
        "/recommender", "/recommender/active-learning", "/recommender/apis",
        "/adaptive-ux", "/adaptive-ux/skill", "/adaptive-ux/ethics",
        "/rag", "/rag/retrieval", "/rag/faithfulness", "/rag/governance", "/rag/apis",
        "/prompts", "/prompts/lifecycle", "/prompts/collab", "/prompts/lineage", "/prompts/apis",
        "/registry", "/registry/schema", "/registry/rbac", "/registry/tagging", "/registry/apis",
        "/safety-reports", "/safety-reports/:id", "/safety-reports/risks", "/safety-reports/intl-collab",
        "/gemini", "/gemini/gateway", "/gemini/pre-call", "/gemini/post-call", "/gemini/telemetry", "/gemini/adversarial", "/gemini/apis",
        "/tasks-reports", "/tasks-reports/tasks", "/tasks-reports/reports", "/tasks-reports/apis",
        "/strategy", "/strategy/phases", "/strategy/boundaries", "/strategy/integration", "/strategy/kpis", "/strategy/risks",
        "/schemas", "/schemas/:name",
        "/code-examples", "/code-examples/:name",
        "/case-studies", "/case-studies/:id",
        "/modules", "/modules/:id", "/sections/:id",
    ]
    for i in range(1, 13):
        routes.append(f"/m{i}")
    return {"prefix": "/api/wfap-gemini", "routes": routes}


def main():
    data = {
        "meta": meta(),
        "executiveSummary": executive_summary(),
        "M1_architecture": m1_architecture(),
        "M2_dataModels": m2_data_models(),
        "M3_dataFlows": m3_data_flows(),
        "M4_recommender": m4_workflow_recommender(),
        "M5_adaptiveUx": m5_adaptive_ux(),
        "M6_ragChat": m6_rag_chat(),
        "M7_promptCollab": m7_prompt_collab(),
        "M8_modelRegistry": m8_model_registry(),
        "M9_safetyReporting": m9_safety_reporting(),
        "M10_geminiSecurity": m10_gemini_security(),
        "M11_taskReport": m11_task_report(),
        "M12_implementation": m12_implementation_strategy(),
        "schemas": schemas(),
        "codeExamples": code_examples(),
        "caseStudies": case_studies(),
        "apiEndpoints": api_endpoints(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    size_kb = OUT.stat().st_size // 1024
    n_modules = sum(1 for k in data if k.startswith("M") and "_" in k)
    n_sections = sum(len(data[k].get("sections", [])) for k in data if k.startswith("M") and "_" in k)
    print(f"Wrote {OUT} ({size_kb} KB)")
    print(f"Modules: {n_modules} | Sections: {n_sections} | Schemas: {len(data['schemas'])} | "
          f"Code: {len(data['codeExamples'])} | Cases: {len(data['caseStudies'])} | "
          f"Routes: {len(data['apiEndpoints']['routes'])}")


if __name__ == "__main__":
    main()
