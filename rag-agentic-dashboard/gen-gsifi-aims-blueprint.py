#!/usr/bin/env python3
"""
GSIFI-AIMS-BLUEPRINT-WP-037 — Regulator-Grade AI Governance & ISO/IEC 42001
AIMS Master Blueprint for G-SIFIs (2026-2030)

Generates: data/gsifi-aims-blueprint.json

Coverage:
  - AI Management System (AIMS) documentation Sections 1-5 + Annexes J1-J4
  - Multi-jurisdiction regulatory overlays (ECB SSM, Fed SR 11-7, PRA SS1/23,
    EU AI Act, GDPR)
  - Regulator Submission Packs (RSP v1.0 -> v2.6) with decision-traceability APIs
  - Terraform / OPA technical enforcement
  - Adversarial governance loops + self-healing controls
  - Predictive governance + formally-verified machine-checkable legal logic
  - Cross-regulator federation + autonomous supervisory ecosystems
  - Best-practice patterns for high-risk credit underwriting (2026-2030)
"""

import json
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE / "data" / "gsifi-aims-blueprint.json"


# ──────────────────────────────────────────────────────────────────────────────
# META
# ──────────────────────────────────────────────────────────────────────────────
def meta():
    return {
        "docRef": "GSIFI-AIMS-BLUEPRINT-WP-037",
        "version": "1.0.0",
        "date": "2026-04-30",
        "title": (
            "Regulator-Grade AI Governance & ISO/IEC 42001 AIMS Master "
            "Blueprint for G-SIFIs (2026-2030)"
        ),
        "subtitle": (
            "Design and implementation roadmap for ISO/IEC 42001-aligned AI "
            "Management Systems, multi-jurisdiction regulatory overlays, "
            "Regulator Submission Packs (RSP v1.0-v2.6), Terraform/OPA "
            "technical enforcement, adversarial and self-healing governance "
            "loops, predictive governance with formally-verified legal logic, "
            "cross-regulator federation, and autonomous supervisory "
            "ecosystems for high-risk credit underwriting."
        ),
        "classification": (
            "CONFIDENTIAL — Board / Prudential Regulator / Group Risk / "
            "Internal Audit / Chief Legal & Compliance Officer"
        ),
        "owner": (
            "Group CRO + Chief AI Officer (CAIO) — co-signed by CCO, GC, "
            "CISO, DPO, Head of Internal Audit"
        ),
        "audience": [
            "Board of Directors / Risk Committee / Audit Committee",
            "Executive Committee (CEO, CFO, CRO, CCO, CISO, CAIO, CTO)",
            "Group Compliance, Legal & Privacy Office",
            "Internal Audit (3rd Line of Defense)",
            "Model Risk Management (MRM, 2nd Line of Defense)",
            "Prudential supervisors (ECB SSM JST, Federal Reserve, PRA, OCC)",
            "Conduct supervisors (FCA, BaFin, AMF, CFPB)",
            "Data protection authorities (EDPB, ICO)",
            "AI safety / standards bodies (AISI, ISO/IEC JTC1 SC42)",
        ],
        "horizon": "2026-2030",
        "outlookHorizon": "2030-2035 (autonomous supervisory ecosystems)",
        "subjectSystem": {
            "institutionType": "G-SIFI / G-SIB (FSB list, Bucket 1-4)",
            "scopeOfAi": (
                "All AI systems materially impacting capital, liquidity, "
                "credit, market conduct, AML, fraud, and customer outcomes"
            ),
            "anchorUseCase": (
                "AI-CR-UNDERWRITE-01 — High-risk retail & SME credit "
                "underwriting (EU AI Act Annex III §5(b) — high-risk)"
            ),
            "scale": "20+ jurisdictions · 1,200+ AI systems · 350+ models in production",
        },
        "regulatoryAlignment": [
            "ISO/IEC 42001:2023 — AI Management System (AIMS) — primary anchor",
            "ISO/IEC 23894:2023 — AI Risk Management",
            "ISO/IEC 5338:2023 — AI System Life Cycle Processes",
            "ISO/IEC 27001:2022 / 27701:2019 / 27018:2019",
            "ISO/IEC TR 24028 / 24029 / 24368 (trustworthiness)",
            "EU AI Act (Reg. (EU) 2024/1689) — Art. 6, 9, 10, 12, 13, 14, 15, 17, "
            "26, 27, 49, 53, 55, 72, 73; Annex III §5(b)",
            "GDPR (Reg. (EU) 2016/679) — Art. 5, 6, 9, 22, 25, 32, 33, 34, 35",
            "ECB SSM Guide on internal models (2024) + Targeted Review of "
            "Internal Models (TRIM) AI extensions",
            "Federal Reserve SR 11-7 / OCC 2011-12 — Model Risk Management",
            "PRA SS1/23 — Model Risk Management Principles for Banks (UK)",
            "PRA SS2/21 — Outsourcing & third-party risk management",
            "FCA Consumer Duty (PS22/9) + AI/ML discussion paper DP5/22",
            "Basel III/IV — CRR3 / CRD6 — ICAAP Pillar 2 AI add-on",
            "FCRA (US) §604/§615 + ECOA / Reg B §1002 (adverse action)",
            "CFPB Circular 2023-03 (algorithmic adverse-action notices)",
            "NIST AI RMF 1.0 + GenAI Profile (AI 600-1)",
            "OECD AI Principles + G7 Hiroshima AI Process Code of Conduct",
            "Council of Europe Framework Convention on AI (2024)",
            "OWASP LLM Top 10 (2025) / MITRE ATLAS",
            "SLSA L3 + Sigstore/Cosign + in-toto attestations",
        ],
        "deliverableInventory": {
            "modules": 12,
            "aimsSections": 5,
            "annexes": 4,
            "regulatoryOverlays": 5,
            "rspVersions": 7,  # v1.0, v1.5, v2.0, v2.2, v2.4, v2.5, v2.6
            "schemas": 8,
            "codeExamples": 11,
            "caseStudies": 5,
            "phases": 5,
            "kpis": 16,
            "controls": 280,
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# EXECUTIVE SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
def executive_summary():
    return {
        "purpose": (
            "Provide G-SIFI boards, regulators, and supervisors a "
            "regulator-grade, ISO/IEC 42001-anchored master blueprint that "
            "operationalises AI governance across all jurisdictions in which "
            "the institution operates, with machine-checkable legal logic "
            "and autonomous supervisory federation by 2030."
        ),
        "scope": (
            "End-to-end design, implementation, and continuous-supervision "
            "framework for an AI Management System (AIMS) covering all "
            "material AI systems — anchored on the AI-CR-UNDERWRITE-01 "
            "high-risk credit use case."
        ),
        "designPrinciples": [
            "ISO/IEC 42001 as the operating standard, regulator overlays as policy bundles",
            "Compliance-as-code: every control has Terraform + OPA enforcement",
            "Decision-traceability: every model decision is reproducible from a signed envelope",
            "Self-healing governance: detect-then-remediate loops with cryptographic evidence",
            "Predictive governance: forecast control breaches before they occur",
            "Formally-verified legal logic: TLA+/Lean specs of obligations",
            "Federation by default: cross-regulator API with consented disclosure",
            "Adversarial assurance: continuous red-teaming of both models and controls",
        ],
        "headlineKpis": {
            "timeToRegulatorApprovedDeployment": "<= 14 days (RSP v2.4+)",
            "rspGenerationLatency": "<= 30 minutes (auto-assembled, signed)",
            "decisionTraceabilityCoverage": ">= 99.95% of AI decisions",
            "controlAutomationRate": ">= 95% (Terraform + OPA enforced)",
            "evidenceAutomation": ">= 96% (no human evidence collection for L1/L2 controls)",
            "fairnessAirFloor": ">= 0.85 (FCRA / ECOA / EU AI Act Art. 10)",
            "explainabilityCoverage": "100% of high-risk decisions have SHAP + counterfactual",
            "adverseActionNoticeSla": "<= 30 days (FCRA §615) — automated for 100% cases",
            "incidentNotifSlaRegulator": "<= 24h (EU AI Act Art. 73) / 72h (GDPR Art. 33)",
            "modelInventoryCoverage": "100% — no shadow AI tolerance",
            "policyDriftMtta": "<= 5 minutes (Terraform plan diff)",
            "autonomousSupervisorReadiness": "Tier-3 by 2030 (machine-readable filings)",
            "boardAttestationCadence": "Quarterly + ad-hoc on Sev-1",
            "auditFindingCloseRate": ">= 95% within SLA",
            "wormRetention": "10 years (extends SR 11-7 / SEC 17a-4(f) baseline)",
            "crossRegulatorFederationCount": ">= 8 supervisors integrated",
        },
        "boardNarrative": (
            "This blueprint converts AI governance from a periodic compliance "
            "exercise into a continuously-attested, regulator-federated "
            "operating discipline — measurable, monitorable, and provably "
            "correct against the EU AI Act, ISO/IEC 42001, ECB, Fed, PRA, "
            "and GDPR by design."
        ),
    }


# ──────────────────────────────────────────────────────────────────────────────
# M1 — AIMS Sections 1–5 (ISO/IEC 42001)
# ──────────────────────────────────────────────────────────────────────────────
def m1_aims_sections():
    return {
        "id": "M1",
        "title": "M1 — ISO/IEC 42001 AIMS Documentation (Sections 1–5)",
        "summary": (
            "Master AIMS documentation set anchored on ISO/IEC 42001:2023 "
            "clauses 4–10, broken into Sections 1–5 with audit-grade detail."
        ),
        "sections": [
            {
                "id": "M1-S1",
                "title": "Section 1 — Context of the Organization (Cl. 4)",
                "iso42001Clauses": ["4.1", "4.2", "4.3", "4.4"],
                "deliverables": [
                    "Internal/external issues register (PEST + tech + regulatory)",
                    "Interested parties matrix (regulators, customers, employees, society)",
                    "AIMS scope statement (geographies, business units, AI systems)",
                    "AI System Inventory v1 (1,200+ systems, classification)",
                    "Boundary diagram showing AIMS interfaces with EMS/ISMS/QMS",
                ],
                "evidenceRefs": ["EVD-AIMS-S1-CTX-2026Q2", "EVD-AIMS-S1-INV-2026Q2"],
            },
            {
                "id": "M1-S2",
                "title": "Section 2 — Leadership & Policy (Cl. 5)",
                "iso42001Clauses": ["5.1", "5.2", "5.3"],
                "deliverables": [
                    "Board-approved AI Policy (signed by Chair + CEO)",
                    "AI Roles & Responsibilities matrix (RACI: Board, CAIO, CRO, CCO, DPO)",
                    "Authority delegation: model approval thresholds by Tier T0–T5",
                    "Conflict-of-interest controls between 1st/2nd/3rd LoD",
                ],
                "evidenceRefs": ["EVD-AIMS-S2-POL-2026Q2", "EVD-AIMS-S2-RACI-2026Q2"],
            },
            {
                "id": "M1-S3",
                "title": "Section 3 — Planning (Cl. 6)",
                "iso42001Clauses": ["6.1", "6.2", "6.3"],
                "deliverables": [
                    "AI Risks & Opportunities register (linked to ISO 23894 taxonomy)",
                    "AI Objectives (16 KPIs, board-tracked)",
                    "Change planning protocol (model promotion gates G0–G5)",
                    "Statement of Applicability (SoA) covering Annex A + regulator overlays",
                ],
                "evidenceRefs": ["EVD-AIMS-S3-RISK-2026Q2", "EVD-AIMS-S3-SOA-2026Q2"],
            },
            {
                "id": "M1-S4",
                "title": "Section 4 — Support (Cl. 7)",
                "iso42001Clauses": ["7.1", "7.2", "7.3", "7.4", "7.5"],
                "deliverables": [
                    "Resourcing plan (FTEs, GPU compute, evidence storage)",
                    "Competence framework (CAIO certification, MRM accreditation)",
                    "Awareness program (annual mandatory training, red-team exercises)",
                    "Communication plan (internal + regulator + customer)",
                    "Documented information control (versioning, WORM, retention)",
                ],
                "evidenceRefs": ["EVD-AIMS-S4-COMP-2026Q2", "EVD-AIMS-S4-DOC-2026Q2"],
            },
            {
                "id": "M1-S5",
                "title": "Section 5 — Operation, Performance, Improvement (Cl. 8–10)",
                "iso42001Clauses": ["8.1", "8.2", "8.3", "9.1", "9.2", "9.3", "10.1", "10.2"],
                "deliverables": [
                    "Operational planning & control (life-cycle SOPs per ISO 5338)",
                    "AI impact assessment process (GDPR DPIA + EU AI Act FRIA)",
                    "Performance evaluation (KPI dashboard, internal audit plan)",
                    "Management review minutes (quarterly, board-attested)",
                    "Continual improvement loop (CAPA register, RCA)",
                ],
                "evidenceRefs": [
                    "EVD-AIMS-S5-OPS-2026Q2",
                    "EVD-AIMS-S5-MR-2026Q2",
                    "EVD-AIMS-S5-CAPA-2026Q2",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M2 — AIMS Annexes J1–J4
# ──────────────────────────────────────────────────────────────────────────────
def m2_aims_annexes():
    return {
        "id": "M2",
        "title": "M2 — AIMS Annexes J1–J4 (Implementation Detail)",
        "summary": (
            "Four institution-specific annexes extending ISO/IEC 42001 "
            "Annex A/B with G-SIFI-grade depth."
        ),
        "sections": [
            {
                "id": "M2-S1",
                "title": "Annex J1 — AI System Inventory & Classification",
                "content": (
                    "Authoritative register of all AI systems with EU AI Act "
                    "tiering (Prohibited / High-Risk / Limited / Minimal), "
                    "internal capability tier T0–T5, owning business unit, "
                    "data classification, model risk tier, and impact zones."
                ),
                "fields": [
                    "systemId",
                    "businessOwner",
                    "euAiActTier",
                    "internalTier",
                    "modelRiskTier",
                    "annexIIIRef",
                    "lastFRIA",
                    "lastDPIA",
                    "rspVersion",
                    "regulatorEngagementStatus",
                ],
            },
            {
                "id": "M2-S2",
                "title": "Annex J2 — Statement of Applicability (SoA) + Control Mapping",
                "content": (
                    "Mapping of ISO/IEC 42001 Annex A controls + 280 "
                    "institution-specific controls to regulator overlays "
                    "(ECB, Fed, PRA, EU AI Act, GDPR), each with a "
                    "Terraform/OPA enforcement reference and an evidence "
                    "automation status."
                ),
                "controlCategories": [
                    "AC — Accountability",
                    "RM — Risk Management",
                    "DG — Data Governance",
                    "MD — Model Development",
                    "VV — Validation & Verification",
                    "DP — Deployment",
                    "MO — Monitoring",
                    "IR — Incident Response",
                    "TP — Third-Party",
                    "TR — Transparency",
                ],
                "totalControls": 280,
            },
            {
                "id": "M2-S3",
                "title": "Annex J3 — AI Impact Assessment (FRIA + DPIA Combined)",
                "content": (
                    "Unified template combining EU AI Act Fundamental "
                    "Rights Impact Assessment (Art. 27) with GDPR DPIA "
                    "(Art. 35) and SR 11-7 model materiality assessment."
                ),
                "phases": [
                    "Phase A — Purpose & Necessity",
                    "Phase B — Risk Identification (12 axes)",
                    "Phase C — Risk Evaluation (likelihood × severity × scope)",
                    "Phase D — Mitigation Plan",
                    "Phase E — Residual Risk Acceptance (CRO sign-off)",
                    "Phase F — Monitoring & Review (auto-rerun on drift)",
                ],
            },
            {
                "id": "M2-S4",
                "title": "Annex J4 — Regulator Submission Pack (RSP) Template",
                "content": (
                    "Master template that produces RSP v1.0–v2.6 with "
                    "decision-traceability links, model cards, eval results, "
                    "monitoring telemetry, and signed attestations."
                ),
                "rspContents": [
                    "Cover & Executive Summary",
                    "Model Card (Mitchell+ format extended)",
                    "Data Sheet (Gebru+ format extended)",
                    "FRIA + DPIA",
                    "Validation Report (independent 2nd LoD sign-off)",
                    "Monitoring Plan + KPI baseline",
                    "Incident Response Plan (model-specific)",
                    "Decision Traceability API endpoint + sample decisions",
                    "Cryptographic attestation bundle (Sigstore + Rekor)",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M3 — Multi-Jurisdiction Regulatory Overlays
# ──────────────────────────────────────────────────────────────────────────────
def m3_regulatory_overlays():
    return {
        "id": "M3",
        "title": "M3 — Multi-Jurisdiction Regulatory Overlays",
        "summary": (
            "Five regulator overlays applied as policy bundles on top of the "
            "ISO/IEC 42001 baseline."
        ),
        "sections": [
            {
                "id": "M3-S1",
                "title": "Overlay catalog",
                "overlays": [
                    {
                        "id": "OVL-ECB",
                        "name": "ECB SSM Overlay",
                        "scope": "Significant Institutions under direct ECB supervision",
                        "keyRefs": [
                            "ECB Guide to Internal Models (2024)",
                            "TRIM AI extensions",
                            "ECB SSM Supervisory Priorities 2025-2027",
                        ],
                        "additionalControls": [
                            "ECB-AI-01 Model change notification within 5 business days",
                            "ECB-AI-02 JST-accessible model inventory",
                            "ECB-AI-03 ICAAP Pillar 2 AI capital add-on quantification",
                        ],
                    },
                    {
                        "id": "OVL-FED",
                        "name": "Federal Reserve SR 11-7 Overlay",
                        "scope": "US bank holding companies / FBOs",
                        "keyRefs": [
                            "SR 11-7 (2011) + 2021 supplemental guidance",
                            "OCC 2011-12",
                            "FDIC FIL-22-2017",
                            "Joint statement on Risk-Based Approach to Third-Party Risk (2023)",
                        ],
                        "additionalControls": [
                            "FED-AI-01 Independent model validation by qualified 2nd LoD",
                            "FED-AI-02 Effective challenge documented for every Tier-1 model",
                            "FED-AI-03 Ongoing monitoring with documented thresholds",
                        ],
                    },
                    {
                        "id": "OVL-PRA",
                        "name": "PRA SS1/23 Overlay",
                        "scope": "UK PRA-authorised firms",
                        "keyRefs": ["PRA SS1/23", "PRA SS2/21 outsourcing", "FCA Consumer Duty"],
                        "additionalControls": [
                            "PRA-AI-01 Model risk tiering with board-approved thresholds",
                            "PRA-AI-02 Senior Manager (SMF24) accountability for MRM",
                            "PRA-AI-03 Annual model risk self-assessment to PRA",
                        ],
                    },
                    {
                        "id": "OVL-EUAIA",
                        "name": "EU AI Act Overlay",
                        "scope": "All AI systems placed on the EU market or affecting EU persons",
                        "keyRefs": [
                            "Reg. (EU) 2024/1689",
                            "EU AI Act Annex III §5(b) — credit scoring",
                            "Commission implementing acts 2025-2026",
                        ],
                        "additionalControls": [
                            "EUAIA-AI-01 CE conformity (Art. 43) for high-risk systems",
                            "EUAIA-AI-02 Post-market monitoring (Art. 72) live",
                            "EUAIA-AI-03 Serious incident reporting within 15 days (Art. 73)",
                            "EUAIA-AI-04 Registration in EU database (Art. 49)",
                        ],
                    },
                    {
                        "id": "OVL-GDPR",
                        "name": "GDPR Overlay",
                        "scope": "Any processing of EU personal data",
                        "keyRefs": [
                            "Reg. (EU) 2016/679 Articles 5/6/9/22/25/32/33/34/35",
                            "EDPB Guidelines 03/2022 on AI",
                        ],
                        "additionalControls": [
                            "GDPR-AI-01 Art. 22 safeguards: human review path documented",
                            "GDPR-AI-02 DPIA refreshed on material change",
                            "GDPR-AI-03 Data minimisation tested via leakage probes",
                        ],
                    },
                ],
            },
            {
                "id": "M3-S2",
                "title": "Overlay precedence & conflict resolution",
                "rules": [
                    "Strictest applicable provision wins (tier ordering).",
                    "Where overlays diverge on disclosure scope, union of "
                    "disclosures applies; classification follows the home regulator.",
                    "Conflict log maintained with Legal sign-off for every override.",
                ],
            },
            {
                "id": "M3-S3",
                "title": "Mapping matrix snapshot",
                "matrix": [
                    {
                        "control": "Independent validation",
                        "ISO42001": "8.3",
                        "ECB": "ECB-AI-01/03",
                        "Fed": "FED-AI-01/02",
                        "PRA": "PRA-AI-02",
                        "EUAIA": "Art. 17 QMS / 43",
                        "GDPR": "—",
                    },
                    {
                        "control": "Adverse-action explanation",
                        "ISO42001": "Annex A 6.2.7",
                        "ECB": "—",
                        "Fed": "FCRA §615",
                        "PRA": "FCA Consumer Duty",
                        "EUAIA": "Art. 13/86",
                        "GDPR": "Art. 22",
                    },
                    {
                        "control": "Post-market monitoring",
                        "ISO42001": "9.1",
                        "ECB": "ECB-AI-02",
                        "Fed": "FED-AI-03",
                        "PRA": "PRA-AI-03",
                        "EUAIA": "Art. 72",
                        "GDPR": "Art. 35(11)",
                    },
                    {
                        "control": "Incident reporting",
                        "ISO42001": "10.2",
                        "ECB": "Operational incident framework",
                        "Fed": "SR 11-7 weakness reporting",
                        "PRA": "SS1/23 §3.5",
                        "EUAIA": "Art. 73",
                        "GDPR": "Art. 33/34",
                    },
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M4 — Regulator Submission Packs RSP v1.0 → v2.6
# ──────────────────────────────────────────────────────────────────────────────
def m4_rsp():
    return {
        "id": "M4",
        "title": "M4 — Regulator Submission Packs (RSP v1.0 → v2.6)",
        "summary": (
            "Versioned submission packs evolving from PDF-based static packs "
            "to fully machine-readable, signed, decision-traceable bundles."
        ),
        "sections": [
            {
                "id": "M4-S1",
                "title": "Version roadmap",
                "versions": [
                    {
                        "id": "RSP-v1.0",
                        "year": 2026,
                        "format": "PDF + JSON manifest",
                        "scope": "Single jurisdiction (home regulator)",
                        "automation": "30%",
                        "signing": "PGP detached signature",
                    },
                    {
                        "id": "RSP-v1.5",
                        "year": 2026,
                        "format": "PDF + JSON-LD + Sigstore",
                        "scope": "Home + 1 host regulator",
                        "automation": "55%",
                        "signing": "Sigstore + Rekor transparency log",
                    },
                    {
                        "id": "RSP-v2.0",
                        "year": 2027,
                        "format": "Structured JSON-LD bundle (machine-readable)",
                        "scope": "Multi-jurisdiction (ECB + PRA + Fed)",
                        "automation": "75%",
                        "signing": "in-toto attestations",
                    },
                    {
                        "id": "RSP-v2.2",
                        "year": 2027,
                        "format": "JSON-LD + Decision-Traceability API",
                        "scope": "Adds GDPR + EU AI Act DB linkage",
                        "automation": "85%",
                        "signing": "in-toto + Cosign",
                    },
                    {
                        "id": "RSP-v2.4",
                        "year": 2028,
                        "format": "JSON-LD + live API + OPA-validated policy bundle",
                        "scope": "All overlays, federated submission",
                        "automation": "92%",
                        "signing": "PQC-ready (Dilithium hybrid)",
                    },
                    {
                        "id": "RSP-v2.5",
                        "year": 2029,
                        "format": "v2.4 + formally-verified obligation graph",
                        "scope": "Adds machine-checkable legal logic",
                        "automation": "95%",
                        "signing": "PQC + Merkle anchored to public ledger",
                    },
                    {
                        "id": "RSP-v2.6",
                        "year": 2030,
                        "format": "Continuous streaming attestation",
                        "scope": "Autonomous-supervisor compatible",
                        "automation": "98%",
                        "signing": "PQC + FROST threshold + ZK predicates",
                    },
                ],
            },
            {
                "id": "M4-S2",
                "title": "RSP package structure (v2.4+)",
                "structure": [
                    "/rsp/manifest.jsonld — top-level bundle",
                    "/rsp/model-card.json",
                    "/rsp/datasheet.json",
                    "/rsp/fria-dpia.json",
                    "/rsp/validation-report.json",
                    "/rsp/monitoring-plan.json",
                    "/rsp/incident-plan.json",
                    "/rsp/decisions/ (signed decision envelopes)",
                    "/rsp/policy-bundle.tar.gz (OPA bundle)",
                    "/rsp/attestations/ (in-toto / Cosign / Rekor)",
                    "/rsp/hash-chain.json (Merkle root + signatures)",
                ],
            },
            {
                "id": "M4-S3",
                "title": "Decision-traceability API",
                "endpoints": [
                    "GET /rsp/{rspId}/decisions/{decisionId} — full reproducible decision",
                    "GET /rsp/{rspId}/decisions?subjectId=… — subject access",
                    "GET /rsp/{rspId}/lineage — model + data lineage graph",
                    "GET /rsp/{rspId}/attestations — verifiable bundle",
                    "POST /rsp/{rspId}/challenge — supervisor counterfactual probe",
                ],
                "slas": {
                    "decisionLookup": "<= 200 ms p95",
                    "lineageGraph": "<= 1 s p95",
                    "challengeReply": "<= 5 minutes p95",
                },
                "auth": "mTLS + supervisor SPIFFE ID + per-call OPA policy",
            },
            {
                "id": "M4-S4",
                "title": "RSP issuance pipeline",
                "stages": [
                    "Trigger: model promotion / quarterly cadence / supervisor request",
                    "Assemble: pull artefacts from registry, evaluator, monitor",
                    "Validate: OPA policy bundle compliance check",
                    "Sign: in-toto layout + Cosign + Rekor entry",
                    "Publish: regulator portal + internal evidence WORM",
                    "Notify: supervisor + Internal Audit + Board pack",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M5 — Terraform / OPA technical enforcement
# ──────────────────────────────────────────────────────────────────────────────
def m5_technical_enforcement():
    return {
        "id": "M5",
        "title": "M5 — Terraform + OPA Technical Enforcement",
        "summary": (
            "Compliance-as-code substrate enforcing AIMS controls at "
            "infrastructure, pipeline, and runtime layers."
        ),
        "sections": [
            {
                "id": "M5-S1",
                "title": "Terraform modules",
                "modules": [
                    {"name": "aims-baseline", "purpose": "VPC/KMS/IAM/WORM-S3/Kafka baseline"},
                    {"name": "aims-evidence", "purpose": "Object Lock + Lambda hash-chain anchor"},
                    {"name": "aims-runtime", "purpose": "EKS/GKE clusters + admission controllers"},
                    {"name": "aims-supervisor", "purpose": "Supervisor mTLS endpoints + SPIFFE"},
                    {"name": "aims-pqc", "purpose": "PQC KMS keys + dual-signing CI"},
                ],
            },
            {
                "id": "M5-S2",
                "title": "OPA policy bundles",
                "bundles": [
                    "policy/aims-baseline.tar.gz (Annex A controls)",
                    "policy/overlay-ecb.tar.gz",
                    "policy/overlay-fed.tar.gz",
                    "policy/overlay-pra.tar.gz",
                    "policy/overlay-euaia.tar.gz",
                    "policy/overlay-gdpr.tar.gz",
                    "policy/use-case-credit-underwriting.tar.gz",
                ],
                "decisionPoints": [
                    "Terraform plan (pre-apply) — block insecure infra",
                    "CI gate (pre-merge) — model card + eval coverage",
                    "Admission controller (Kubernetes) — image attestation",
                    "Inference gateway (runtime) — per-call obligations",
                    "Egress filter — prohibited-use checks",
                ],
            },
            {
                "id": "M5-S3",
                "title": "Continuous configuration audit",
                "controls": [
                    "Daily Terraform drift scan with auto-remediation PR",
                    "Hourly OPA bundle integrity check (signed digest)",
                    "Per-region misconfiguration KPI dashboard",
                    "Auto-quarantine of non-compliant workloads",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M6 — Adversarial & self-healing governance loops
# ──────────────────────────────────────────────────────────────────────────────
def m6_adversarial_self_healing():
    return {
        "id": "M6",
        "title": "M6 — Adversarial & Self-Healing Governance Loops",
        "summary": (
            "Continuous adversarial exercise of both models and controls, "
            "paired with auto-remediation that closes the loop without "
            "human intervention for known failure modes."
        ),
        "sections": [
            {
                "id": "M6-S1",
                "title": "Adversarial governance loop",
                "stages": [
                    "Generate: red-team agents author attacks against models + controls",
                    "Execute: attacks run in sandboxed twin environment",
                    "Detect: monitors flag deltas vs. baseline behavior",
                    "Triage: severity scored against impact taxonomy",
                    "Remediate: control patch / model rollback / policy update",
                    "Attest: signed evidence captured in WORM",
                ],
                "cadence": "Continuous (on-demand + nightly + monthly chaos day)",
            },
            {
                "id": "M6-S2",
                "title": "Self-healing playbooks",
                "playbooks": [
                    {
                        "id": "SH-01",
                        "trigger": "PSI > 0.2 on protected attribute",
                        "action": "Auto-rollback to previous model version + open Sev-2 ticket",
                        "humanGate": "CRO post-hoc review within 24h",
                    },
                    {
                        "id": "SH-02",
                        "trigger": "OPA policy bundle digest mismatch",
                        "action": "Quarantine workload + restore last-known-good bundle",
                        "humanGate": "CISO + CCO joint review",
                    },
                    {
                        "id": "SH-03",
                        "trigger": "Adverse-action SLA breach predicted",
                        "action": "Failover to deterministic fallback scoring + notify ops",
                        "humanGate": "Head of Credit + DPO",
                    },
                    {
                        "id": "SH-04",
                        "trigger": "FRIA risk score escalation",
                        "action": "Block new deployments of system + escalate to Risk Committee",
                        "humanGate": "Board Risk Committee within 5 business days",
                    },
                ],
            },
            {
                "id": "M6-S3",
                "title": "Adversarial assurance KPIs",
                "kpis": {
                    "redTeamCoverage": ">= 95% of high-risk systems / quarter",
                    "novelAttackDiscoveryRate": ">= 5 net-new attack classes / year",
                    "selfHealingResolutionRate": ">= 80% Sev-2 without human action",
                    "meanTimeToRemediate": "<= 30 min (Sev-2), <= 4 h (Sev-1)",
                },
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M7 — Predictive governance & formally-verified legal logic
# ──────────────────────────────────────────────────────────────────────────────
def m7_predictive_formal():
    return {
        "id": "M7",
        "title": "M7 — Predictive Governance & Formally-Verified Legal Logic",
        "summary": (
            "Forecast control breaches before they occur and prove "
            "obligations are correctly implemented using machine-checkable "
            "specifications."
        ),
        "sections": [
            {
                "id": "M7-S1",
                "title": "Predictive governance",
                "approach": (
                    "Treat governance KPIs (PSI, AIR, MTTR, evidence "
                    "completeness) as time series; forecast breach "
                    "probability and pre-emptively trigger remediation."
                ),
                "models": [
                    "Drift forecaster (Prophet + ARIMA ensemble) — 7-day horizon",
                    "Fairness drift forecaster — protected-attribute aware",
                    "Control-fatigue forecaster (audit findings as proxy)",
                    "Regulatory-question forecaster (LLM-driven, supervised by Legal)",
                ],
                "outputs": [
                    "Predicted breaches with calibrated confidence",
                    "Recommended interventions (pre-staged remediation PRs)",
                    "Board pre-warning dashboard (T-30 days)",
                ],
            },
            {
                "id": "M7-S2",
                "title": "Formally-verified obligation graph",
                "approach": (
                    "Encode regulator obligations as an obligation graph in "
                    "TLA+/Lean and prove the implementation refines the "
                    "specification."
                ),
                "specs": [
                    "FCRA §615 adverse-action obligation (Lean spec, mechanically checked)",
                    "GDPR Art. 22 human-review-path obligation (TLA+)",
                    "EU AI Act Art. 73 incident-reporting obligation (TLA+ liveness)",
                    "ECB ICAAP Pillar 2 AI add-on quantification (Lean)",
                ],
                "deliverable": (
                    "Each spec ships with a CI job that fails the build if a "
                    "code change breaks refinement."
                ),
            },
            {
                "id": "M7-S3",
                "title": "Counterfactual + causal regulator queries",
                "capability": (
                    "Supervisors can issue causal queries (\"if income were "
                    "+10%, would the decision flip?\") that the system "
                    "answers with a causal model + uncertainty, not just "
                    "correlations."
                ),
                "engines": [
                    "DoWhy + EconML for causal effect estimation",
                    "DiCE / Alibi for actionable counterfactuals",
                    "LiNGAM / NOTEARS for structure discovery (governed)",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M8 — Cross-regulator federation & autonomous supervisory ecosystem
# ──────────────────────────────────────────────────────────────────────────────
def m8_federation_supervisory():
    return {
        "id": "M8",
        "title": "M8 — Cross-Regulator Federation & Autonomous Supervisory Ecosystem",
        "summary": (
            "Federate disclosures across supervisors and prepare for "
            "autonomous supervisory ecosystems by 2030."
        ),
        "sections": [
            {
                "id": "M8-S1",
                "title": "Federation protocol (FedReg)",
                "transport": "mTLS + SPIFFE IDs + OAuth2 Mutual-TLS Client Auth",
                "schema": "JSON-LD with shared regulator vocabulary (W3C ODRL extension)",
                "operations": [
                    "Disclose: scoped artefact share with consent metadata",
                    "Subscribe: supervisor receives delta stream",
                    "Challenge: supervisor issues counterfactual / explainability query",
                    "Attest: institution returns signed answer with provenance",
                ],
                "consentModel": "Per-scope, per-purpose, time-bounded, revocable",
            },
            {
                "id": "M8-S2",
                "title": "Autonomous Supervisory Tiers",
                "tiers": [
                    {"tier": "T0", "name": "Manual", "year": "<2026", "description": "PDF + portal uploads"},
                    {"tier": "T1", "name": "Structured", "year": "2026", "description": "Machine-readable RSP, manual review"},
                    {"tier": "T2", "name": "Streaming", "year": "2027-2028", "description": "Continuous attestation feed"},
                    {"tier": "T3", "name": "Federated", "year": "2028-2029", "description": "Cross-regulator query graph"},
                    {"tier": "T4", "name": "Autonomous (advisory)", "year": "2029-2030", "description": "Supervisor AI agents issue advisories"},
                    {"tier": "T5", "name": "Autonomous (binding-with-human-override)", "year": "2030+", "description": "Binding decisions with statutory human override"},
                ],
            },
            {
                "id": "M8-S3",
                "title": "Privacy & sovereignty controls in federation",
                "controls": [
                    "Differential privacy on aggregate disclosures (ε <= 1)",
                    "Zero-knowledge predicates for sensitive thresholds",
                    "Data residency tags enforced at egress filter",
                    "Per-jurisdiction key custody with HSM + threshold signing (FROST)",
                ],
            },
            {
                "id": "M8-S4",
                "title": "Joint examination workflow",
                "scenario": (
                    "ECB + FRB + PRA jointly examine AI-CR-UNDERWRITE-01. "
                    "Each receives scoped, signed RSP slices; queries "
                    "federated through FedReg; institution responses "
                    "attested into a shared transparency log."
                ),
                "sla": "Joint final report within 30 calendar days",
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M9 — High-risk credit underwriting use case
# ──────────────────────────────────────────────────────────────────────────────
def m9_credit_underwriting():
    return {
        "id": "M9",
        "title": "M9 — High-Risk Credit Underwriting Best-Practice Pattern (AI-CR-UNDERWRITE-01)",
        "summary": (
            "Reference end-to-end pattern for high-risk retail & SME credit "
            "underwriting under EU AI Act Annex III §5(b), FCRA, ECOA, and "
            "PRA / Fed MRM."
        ),
        "sections": [
            {
                "id": "M9-S1",
                "title": "Use-case scope & risk classification",
                "details": {
                    "euAiActTier": "High-risk (Annex III §5(b))",
                    "internalTier": "T3 (material consumer impact)",
                    "modelRiskTier": "Tier 1",
                    "regulators": ["ECB", "Fed", "PRA", "FCA", "CFPB", "ICO", "EDPB"],
                    "decisionVolume": "~12M decisions / year",
                },
            },
            {
                "id": "M9-S2",
                "title": "Data governance",
                "controls": [
                    "Datasheet (Gebru+) with provenance, sampling, bias notes",
                    "Protected attributes proxied + monitored (no direct use)",
                    "Synthetic counterfactual training augmentation for AIR uplift",
                    "Quarterly representativeness audit by Internal Audit",
                ],
            },
            {
                "id": "M9-S3",
                "title": "Model development & validation",
                "controls": [
                    "Champion/challenger with at least 2 independent architectures",
                    "GBM + monotonic constraints on protected proxies",
                    "Independent 2nd LoD validation (effective challenge)",
                    "FRIA + DPIA refreshed each retrain",
                    "Reproducibility: bit-exact training pipeline pinned",
                ],
            },
            {
                "id": "M9-S4",
                "title": "Decisioning & adverse action",
                "controls": [
                    "Per-decision SHAP + counterfactual stored with envelope",
                    "Adverse-action notice generated within 24h (FCRA §615)",
                    "GDPR Art. 22 human-review path for any decision contested",
                    "EU AI Act Art. 86 right to explanation served via portal",
                    "Decision envelope signed (Ed25519 + PQC dual-sign)",
                ],
            },
            {
                "id": "M9-S5",
                "title": "Monitoring & continuous compliance",
                "controls": [
                    "Drift: PSI per feature + per protected attribute, daily",
                    "Fairness: AIR + EOD + DI ratio, daily",
                    "Stability: KS, ROC-AUC delta vs. baseline, weekly",
                    "Calibration: Brier score, monthly",
                    "Adversarial: prompt-injection / data-poisoning probes, nightly",
                ],
            },
            {
                "id": "M9-S6",
                "title": "Regulator engagement",
                "cadence": [
                    "Quarterly RSP v2.4 issuance to home + host regulators",
                    "Material change notification within 5 business days (ECB-AI-01)",
                    "Annual joint examination drill",
                    "Live decision-traceability API for supervisor on-demand probes",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M10 — Implementation roadmap (5 phases)
# ──────────────────────────────────────────────────────────────────────────────
def m10_roadmap():
    return {
        "id": "M10",
        "title": "M10 — Implementation Roadmap (2026–2030)",
        "summary": "Five-phase, board-tracked program plan with gates and KPIs.",
        "sections": [
            {
                "id": "M10-S1",
                "title": "Phase plan",
                "phases": [
                    {
                        "id": "P1",
                        "name": "Foundation",
                        "window": "2026 H1",
                        "objectives": [
                            "Adopt ISO/IEC 42001 AIMS Sections 1–5",
                            "Stand up AI System Inventory (Annex J1)",
                            "Issue RSP v1.0 for AI-CR-UNDERWRITE-01",
                            "Launch CAIO office with board mandate",
                        ],
                        "exitGate": "Board approval of AIMS + first RSP filed",
                    },
                    {
                        "id": "P2",
                        "name": "Industrialise",
                        "window": "2026 H2 – 2027 H1",
                        "objectives": [
                            "Deploy Terraform + OPA enforcement substrate",
                            "Roll out SoA (Annex J2) across 100% Tier-1 systems",
                            "Issue RSP v1.5 + v2.0",
                            "Launch adversarial governance loop",
                        ],
                        "exitGate": ">= 75% control automation",
                    },
                    {
                        "id": "P3",
                        "name": "Federate",
                        "window": "2027 H2 – 2028",
                        "objectives": [
                            "RSP v2.2 + v2.4 with multi-regulator scope",
                            "FedReg federation pilot with ECB + PRA + Fed",
                            "Activate self-healing playbooks SH-01..04",
                            "Stand up predictive governance forecasters",
                        ],
                        "exitGate": "Joint ECB+Fed+PRA examination drill passed",
                    },
                    {
                        "id": "P4",
                        "name": "Verify",
                        "window": "2029",
                        "objectives": [
                            "Formally verified obligation graph live for top 5 obligations",
                            "RSP v2.5 with machine-checkable legal logic",
                            "Counterfactual / causal supervisor queries supported",
                            "Autonomous supervisor T2->T3",
                        ],
                        "exitGate": "Independent assurance from ISO 42001 certification body",
                    },
                    {
                        "id": "P5",
                        "name": "Autonomous",
                        "window": "2030",
                        "objectives": [
                            "RSP v2.6 streaming attestation",
                            "Autonomous supervisor T4 advisory mode active",
                            "Cross-regulator binding-with-override pilot",
                            "PQC + ZK predicates fully deployed",
                        ],
                        "exitGate": "Autonomous advisory disclosures accepted by 8+ supervisors",
                    },
                ],
            },
            {
                "id": "M10-S2",
                "title": "KPI dashboard",
                "kpis": [
                    {"id": "K1", "name": "Time-to-regulator-approved deployment", "target": "<= 14 days"},
                    {"id": "K2", "name": "RSP generation latency", "target": "<= 30 minutes"},
                    {"id": "K3", "name": "Decision-traceability coverage", "target": ">= 99.95%"},
                    {"id": "K4", "name": "Control automation rate", "target": ">= 95%"},
                    {"id": "K5", "name": "Evidence automation", "target": ">= 96%"},
                    {"id": "K6", "name": "Fairness AIR floor", "target": ">= 0.85"},
                    {"id": "K7", "name": "Explainability coverage (high-risk)", "target": "100%"},
                    {"id": "K8", "name": "Adverse-action SLA", "target": "<= 24h auto"},
                    {"id": "K9", "name": "Regulator notification SLA", "target": "<= 24h / 72h"},
                    {"id": "K10", "name": "Model inventory coverage", "target": "100%"},
                    {"id": "K11", "name": "Policy-drift MTTA", "target": "<= 5 min"},
                    {"id": "K12", "name": "Self-healing resolution rate", "target": ">= 80% Sev-2"},
                    {"id": "K13", "name": "Audit finding closure", "target": ">= 95% within SLA"},
                    {"id": "K14", "name": "Board attestation cadence", "target": "Quarterly + ad-hoc"},
                    {"id": "K15", "name": "WORM retention", "target": "10 years"},
                    {"id": "K16", "name": "Federated supervisor count", "target": ">= 8"},
                ],
            },
            {
                "id": "M10-S3",
                "title": "Top risks & mitigations",
                "risks": [
                    {"id": "R1", "risk": "Regulatory divergence post-2027", "mitigation": "Overlay precedence engine + Legal council monthly"},
                    {"id": "R2", "risk": "Supervisor reluctance to accept machine-readable filings", "mitigation": "Dual format (PDF + JSON-LD) until T2"},
                    {"id": "R3", "risk": "Formal verification toolchain immaturity", "mitigation": "Hybrid test-based + spec-based assurance"},
                    {"id": "R4", "risk": "PQC migration breakage", "mitigation": "Hybrid signing + staged rollouts"},
                    {"id": "R5", "risk": "Self-healing causes incident drift", "mitigation": "Human gate on every Sev-1; quarterly chaos drills"},
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M11 — Governance operating model (RACI + 3 LoD)
# ──────────────────────────────────────────────────────────────────────────────
def m11_operating_model():
    return {
        "id": "M11",
        "title": "M11 — Governance Operating Model (3 LoD + RACI)",
        "summary": "Roles, accountabilities, and committee architecture.",
        "sections": [
            {
                "id": "M11-S1",
                "title": "Three Lines of Defense",
                "lod": [
                    {"line": "1st LoD", "owner": "Business + AI engineering", "responsibilities": "Build, operate, monitor models within risk appetite"},
                    {"line": "2nd LoD", "owner": "MRM + Compliance + DPO + CISO", "responsibilities": "Independent challenge, validation, policy, oversight"},
                    {"line": "3rd LoD", "owner": "Internal Audit", "responsibilities": "Audit AIMS effectiveness; audit the 2nd LoD"},
                ],
            },
            {
                "id": "M11-S2",
                "title": "RACI matrix (key activities)",
                "matrix": [
                    {"activity": "Approve AI Policy", "Board": "A", "CEO": "R", "CRO": "C", "CCO": "C", "CAIO": "C", "DPO": "I"},
                    {"activity": "Approve Tier-1 model", "Board": "I", "CEO": "I", "CRO": "A", "CCO": "C", "CAIO": "R", "DPO": "C"},
                    {"activity": "Issue RSP", "Board": "I", "CEO": "I", "CRO": "A", "CCO": "R", "CAIO": "R", "DPO": "C"},
                    {"activity": "Sev-1 incident response", "Board": "I", "CEO": "I", "CRO": "A", "CCO": "C", "CAIO": "R", "DPO": "C", "CISO": "R"},
                    {"activity": "Annual AIMS audit", "Board": "I", "CEO": "I", "CRO": "C", "CCO": "C", "CAIO": "C", "DPO": "C", "InternalAudit": "AR"},
                ],
            },
            {
                "id": "M11-S3",
                "title": "Committee architecture",
                "committees": [
                    {"id": "C1", "name": "Board AI Oversight Committee", "frequency": "Quarterly", "chair": "Independent NED"},
                    {"id": "C2", "name": "Group AI Risk Committee", "frequency": "Monthly", "chair": "CRO"},
                    {"id": "C3", "name": "Model Approval Committee", "frequency": "Bi-weekly", "chair": "CAIO"},
                    {"id": "C4", "name": "AI Ethics Council", "frequency": "Monthly", "chair": "GC + external ethicist"},
                    {"id": "C5", "name": "Regulator Engagement Forum", "frequency": "Monthly", "chair": "CCO"},
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# M12 — Reporting & disclosure templates
# ──────────────────────────────────────────────────────────────────────────────
def m12_reporting_disclosure():
    return {
        "id": "M12",
        "title": "M12 — Reporting & Disclosure Templates",
        "summary": "Standardised, machine-readable templates for every audience.",
        "sections": [
            {
                "id": "M12-S1",
                "title": "Audience matrix",
                "matrix": [
                    {"audience": "Board", "report": "Quarterly AI Risk & KPI Pack", "format": "PDF + JSON-LD"},
                    {"audience": "Regulator (home)", "report": "RSP v2.4+", "format": "JSON-LD bundle + signatures"},
                    {"audience": "Regulator (host)", "report": "Federated RSP slice", "format": "FedReg streaming"},
                    {"audience": "Customer (adverse action)", "report": "Adverse-action notice + explanation", "format": "Multilingual portal + paper"},
                    {"audience": "Internal Audit", "report": "AIMS audit dossier", "format": "Evidence bundle + Merkle root"},
                    {"audience": "Public", "report": "Transparency report", "format": "PDF + W3C transparency log link"},
                ],
            },
            {
                "id": "M12-S2",
                "title": "Markdown template skeleton",
                "tags": ["<title>", "<abstract>", "<content>"],
                "skeleton": (
                    "<title>Quarterly AI Risk & KPI Pack — 2026 Q4</title>\n"
                    "<abstract>Summary of KPI movement, top risks, and "
                    "regulator interactions for the quarter.</abstract>\n"
                    "<content>1. KPI dashboard (K1..K16)\n"
                    "2. Material model changes\n"
                    "3. Incidents (Sev-0..Sev-2)\n"
                    "4. Regulator engagements (RSP issuances, queries)\n"
                    "5. Internal Audit findings status\n"
                    "6. Forward-looking risks (predictive governance)\n"
                    "7. Board decisions requested</content>"
                ),
            },
            {
                "id": "M12-S3",
                "title": "Disclosure principles",
                "principles": [
                    "Truthful, complete, and timely",
                    "Audience-fit (no jargon to customers; rigour to supervisors)",
                    "Verifiable (every claim traceable to a signed evidence record)",
                    "Privacy-preserving (DP / ZK on aggregate disclosures)",
                ],
            },
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────
def schemas():
    return {
        "aiSystemInventoryEntry": {
            "title": "AI System Inventory Entry (Annex J1)",
            "required": [
                "systemId", "businessOwner", "euAiActTier", "internalTier",
                "modelRiskTier", "lastFRIA", "rspVersion",
            ],
            "fields": {
                "systemId": "string",
                "businessOwner": "string",
                "euAiActTier": "enum[Prohibited|HighRisk|Limited|Minimal]",
                "internalTier": "enum[T0|T1|T2|T3|T4|T5]",
                "modelRiskTier": "enum[Tier-1|Tier-2|Tier-3]",
                "annexIIIRef": "string",
                "lastFRIA": "ISO-8601",
                "lastDPIA": "ISO-8601",
                "rspVersion": "string",
                "regulatorEngagementStatus": "enum[Filed|Pending|UnderReview|Approved|Withdrawn]",
            },
        },
        "rspManifest": {
            "title": "Regulator Submission Pack — Manifest (v2.4+)",
            "required": ["rspId", "version", "subjectSystemId", "issuedAt", "signatures", "merkleRoot"],
            "fields": {
                "rspId": "string",
                "version": "string",
                "subjectSystemId": "string",
                "issuedAt": "ISO-8601",
                "regulators": "string[]",
                "artefacts": "object[]",
                "signatures": "object[]",
                "merkleRoot": "hex",
                "policyBundleDigest": "hex",
                "ledgerAnchorTx": "string",
            },
        },
        "decisionEnvelope": {
            "title": "Decision Envelope (per AI decision)",
            "required": [
                "decisionId", "subjectId", "modelId", "modelVersion",
                "inputsHash", "output", "shapTopK", "ts", "signature",
            ],
            "fields": {
                "decisionId": "string",
                "subjectId": "string",
                "modelId": "string",
                "modelVersion": "string",
                "inputsHash": "hex",
                "output": "object",
                "shapTopK": "object[]",
                "counterfactual": "object",
                "policyDecision": "object",
                "ts": "ISO-8601",
                "signature": "object",
            },
        },
        "controlMapping": {
            "title": "Control Mapping (Annex J2 SoA)",
            "required": ["controlId", "category", "iso42001Ref", "overlays", "enforcement"],
            "fields": {
                "controlId": "string",
                "category": "string",
                "iso42001Ref": "string",
                "overlays": "object",
                "enforcement": "object",
                "evidenceAutomation": "enum[None|Partial|Full]",
                "owner": "string",
            },
        },
        "friaRecord": {
            "title": "FRIA + DPIA Combined Record (Annex J3)",
            "required": ["friaId", "subjectSystemId", "phase", "residualRisk", "approvers"],
            "fields": {
                "friaId": "string",
                "subjectSystemId": "string",
                "phase": "enum[A|B|C|D|E|F]",
                "axes": "object[]",
                "residualRisk": "enum[Low|Medium|High|Critical]",
                "approvers": "string[]",
                "nextReviewAt": "ISO-8601",
            },
        },
        "incidentRecord": {
            "title": "AI Incident Record (Cl. 10.2 + EU AI Act Art. 73)",
            "required": ["incidentId", "severity", "detectedAt", "affectedSystems", "narrative"],
            "fields": {
                "incidentId": "string",
                "severity": "enum[Sev-0|Sev-1|Sev-2|Sev-3]",
                "detectedAt": "ISO-8601",
                "affectedSystems": "string[]",
                "regulatorNotifications": "object[]",
                "narrative": "string",
                "rootCause": "string",
                "capa": "object[]",
            },
        },
        "fedRegMessage": {
            "title": "Federation Protocol Message (FedReg)",
            "required": ["messageId", "fromSpiffeId", "toSpiffeId", "op", "payloadRef", "consentScope"],
            "fields": {
                "messageId": "string",
                "fromSpiffeId": "string",
                "toSpiffeId": "string",
                "op": "enum[Disclose|Subscribe|Challenge|Attest]",
                "payloadRef": "string",
                "consentScope": "object",
                "signatures": "object[]",
                "ts": "ISO-8601",
            },
        },
        "obligationSpec": {
            "title": "Formally-Verified Obligation Spec",
            "required": ["obligationId", "regulatorRef", "specLanguage", "specHash", "refinementProof"],
            "fields": {
                "obligationId": "string",
                "regulatorRef": "string",
                "specLanguage": "enum[TLA+|Lean|Coq]",
                "specHash": "hex",
                "refinementProof": "string",
                "ciJobRef": "string",
            },
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Code examples
# ──────────────────────────────────────────────────────────────────────────────
def code_examples():
    return {
        "opaRspGate": {
            "language": "rego",
            "purpose": "Block RSP issuance unless all required artefacts + signatures present",
            "code": """package rsp.gate

default allow = false

required := {"manifest", "model-card", "datasheet", "fria-dpia",
             "validation-report", "monitoring-plan", "incident-plan",
             "policy-bundle", "attestations", "hash-chain"}

allow {
    have := {a | a := input.artefacts[_].name}
    missing := required - have
    count(missing) == 0
    input.signatures.cosign.verified == true
    input.signatures.intoto.verified == true
    input.policyBundleDigest == data.policy.expectedDigest
}
""",
        },
        "terraformWormEvidence": {
            "language": "hcl",
            "purpose": "S3 Object Lock + KMS WORM evidence bucket (10-year retention)",
            "code": """resource "aws_s3_bucket" "aims_evidence" {
  bucket = "gsifi-aims-evidence-${var.env}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "lock" {
  bucket = aws_s3_bucket.aims_evidence.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      years = 10
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.aims_evidence.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.aims.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
""",
        },
        "decisionEnvelopeSigner": {
            "language": "python",
            "purpose": "Sign per-decision envelopes (Ed25519 + PQC dual-sign)",
            "code": """import hashlib, json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# pqcrypto.sign.dilithium3 illustrative
from pqcrypto.sign.dilithium3 import generate_keypair, sign as pqc_sign

def make_envelope(decision_id, subject_id, model_id, model_version,
                  inputs, output, shap_topk, ed_sk, pqc_sk):
    inputs_hash = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    body = {
        "decisionId": decision_id,
        "subjectId": subject_id,
        "modelId": model_id,
        "modelVersion": model_version,
        "inputsHash": inputs_hash,
        "output": output,
        "shapTopK": shap_topk,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload = json.dumps(body, sort_keys=True).encode()
    sig_ed = ed_sk.sign(payload).hex()
    sig_pqc = pqc_sign(pqc_sk, payload).hex()
    body["signature"] = {"ed25519": sig_ed, "dilithium3": sig_pqc}
    return body
""",
        },
        "fairnessMonitor": {
            "language": "python",
            "purpose": "Daily AIR / EOD monitor with self-healing trigger (SH-01)",
            "code": """import numpy as np

def adverse_impact_ratio(y_pred, protected):
    rates = {g: y_pred[protected == g].mean() for g in np.unique(protected)}
    ref = max(rates.values())
    return min(rates.values()) / ref if ref else 1.0

def monitor(daily_predictions, protected, prev_air, prev_psi):
    air = adverse_impact_ratio(daily_predictions, protected)
    if air < 0.85 or prev_psi > 0.2:
        trigger_self_heal("SH-01", reason={"air": air, "psi": prev_psi})
    return {"air": air}

def trigger_self_heal(playbook_id, reason):
    # POST signed event to governance bus → triggers rollback + Sev-2 ticket
    ...
""",
        },
        "fedRegClient": {
            "language": "python",
            "purpose": "FedReg federation client — disclose RSP slice to supervisor",
            "code": """import requests, json, time

def disclose(supervisor_url, rsp_slice, scope, spiffe_ctx, signer):
    msg = {
        "messageId": f"msg-{int(time.time()*1000)}",
        "fromSpiffeId": spiffe_ctx.self_id,
        "toSpiffeId":   spiffe_ctx.peer_id,
        "op": "Disclose",
        "payloadRef": rsp_slice["uri"],
        "consentScope": scope,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    body = json.dumps(msg, sort_keys=True).encode()
    msg["signatures"] = signer(body)
    return requests.post(supervisor_url + "/fedreg/v1/messages",
                         json=msg, cert=spiffe_ctx.mtls_cert).json()
""",
        },
        "predictiveDriftForecaster": {
            "language": "python",
            "purpose": "Forecast PSI breach 7 days ahead (predictive governance)",
            "code": """from prophet import Prophet
import pandas as pd

def forecast_psi_breach(history_df, threshold=0.2, horizon=7):
    m = Prophet(interval_width=0.95).fit(history_df.rename(columns={"date":"ds","psi":"y"}))
    future = m.make_future_dataframe(periods=horizon)
    fcst = m.predict(future)
    breach = fcst[fcst["yhat"] > threshold].head(1)
    return None if breach.empty else {
        "predictedBreachAt": str(breach.iloc[0]["ds"].date()),
        "expectedPsi": float(breach.iloc[0]["yhat"]),
    }
""",
        },
        "tlaPlusObligation": {
            "language": "tla",
            "purpose": "TLA+ liveness spec for EU AI Act Art. 73 incident reporting",
            "code": """-------------- MODULE Art73Reporting --------------
EXTENDS Naturals, TLC
VARIABLES status, notifiedAt, detectedAt
Init == /\\ status = "open" /\\ notifiedAt = 0 /\\ detectedAt = 0
Report == /\\ status = "open" /\\ status' = "reported"
          /\\ notifiedAt' = detectedAt + 15
Liveness == <>(status = "reported" /\\ notifiedAt - detectedAt <= 15)
Spec == Init /\\ [][Report]_<<status, notifiedAt, detectedAt>> /\\ Liveness
====
""",
        },
        "leanFcraSpec": {
            "language": "lean",
            "purpose": "Lean spec for FCRA §615 adverse-action obligation",
            "code": """import data.real.basic

structure Decision := (subject : string) (denied : bool) (timestamp_h : nat)
structure Notice   := (subject : string) (sent_at_h : nat) (reasons : list string)

def fcra_compliant (d : Decision) (n : Notice) : Prop :=
  d.subject = n.subject
  ∧ d.denied = tt
  ∧ n.sent_at_h ≤ d.timestamp_h + 30 * 24
  ∧ n.reasons.length ≥ 1

theorem fcra_demo :
  ∀ d n, d.denied = tt → fcra_compliant d n → n.reasons.length ≥ 1 :=
λ d n h1 hc, hc.2.2.2
""",
        },
        "selfHealingPlaybookEngine": {
            "language": "python",
            "purpose": "Self-healing playbook executor with WORM-attested actions",
            "code": """import json, time, hashlib

def execute_playbook(playbook, signals, signer, worm_writer):
    record = {"playbook": playbook["id"], "trigger": playbook["trigger"],
              "signals": signals, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if playbook["id"] == "SH-01":
        rollback_model(signals["modelId"])
        open_ticket(severity="Sev-2", reason="Bias drift")
    elif playbook["id"] == "SH-02":
        quarantine_workload(signals["workloadId"])
        restore_lkg_bundle()
    payload = json.dumps(record, sort_keys=True).encode()
    record["digest"] = hashlib.sha256(payload).hexdigest()
    record["signature"] = signer(payload)
    worm_writer.write(record)
    return record

def rollback_model(*a, **k): ...
def open_ticket(*a, **k): ...
def quarantine_workload(*a, **k): ...
def restore_lkg_bundle(*a, **k): ...
""",
        },
        "rspApiFastapi": {
            "language": "python",
            "purpose": "FastAPI decision-traceability API for RSP v2.4+",
            "code": """from fastapi import FastAPI, HTTPException, Depends
app = FastAPI(title="RSP Decision Traceability API")

def auth(spiffe_id: str = ""):
    if not spiffe_id.startswith("spiffe://supervisor."):
        raise HTTPException(401, "Supervisor SPIFFE required")
    return spiffe_id

@app.get("/rsp/{rsp_id}/decisions/{decision_id}")
def get_decision(rsp_id: str, decision_id: str, who=Depends(auth)):
    env = decision_store.fetch(rsp_id, decision_id)
    if not env: raise HTTPException(404, "Decision not found")
    return env

@app.post("/rsp/{rsp_id}/challenge")
def challenge(rsp_id: str, body: dict, who=Depends(auth)):
    return counterfactual_engine.run(rsp_id, body)
""",
        },
        "merkleAnchor": {
            "language": "python",
            "purpose": "Daily Merkle anchor of evidence WORM into public ledger",
            "code": """import hashlib

def merkle_root(leaves):
    layer = [bytes.fromhex(l) for l in leaves]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i]+layer[i+1]).digest() for i in range(0,len(layer),2)]
    return layer[0].hex()

def anchor_today(evidence_hashes, ledger_client):
    root = merkle_root(evidence_hashes)
    txid = ledger_client.publish(root)
    return {"root": root, "txid": txid, "count": len(evidence_hashes)}
""",
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Case studies
# ──────────────────────────────────────────────────────────────────────────────
def case_studies():
    return [
        {
            "id": "CS-01",
            "title": "European G-SIB — first ISO/IEC 42001 + EU AI Act dual certification",
            "sector": "Banking (EU)",
            "summary": (
                "Top-3 EU bank achieved ISO/IEC 42001 certification and EU "
                "AI Act Art. 43 conformity for AI-CR-UNDERWRITE-01 "
                "concurrently."
            ),
            "outcomes": {
                "rspVersion": "v2.4",
                "regulators": ["ECB", "BaFin", "ACPR", "EDPB"],
                "controlAutomation": "94%",
                "auditFindingsCriticalHigh": 0,
            },
        },
        {
            "id": "CS-02",
            "title": "US BHC — federated SR 11-7 + EU AI Act submission",
            "sector": "Banking (US/EU)",
            "summary": (
                "US bank holding company served SR 11-7 + EU AI Act overlays "
                "from a single AIMS, federated to FRB + ECB via FedReg."
            ),
            "outcomes": {
                "rspVersion": "v2.2 → v2.4",
                "supervisorCount": 5,
                "decisionTraceability": "99.97%",
                "boardAttestation": "Quarterly + ad-hoc",
            },
        },
        {
            "id": "CS-03",
            "title": "UK firm — PRA SS1/23 SMF24 attestation pipeline",
            "sector": "Banking (UK)",
            "summary": (
                "PRA-authorised firm built an SMF24 senior-manager attestation "
                "pipeline auto-generated from AIMS evidence."
            ),
            "outcomes": {
                "smf24AttestationLatency": "<= 24h",
                "evidenceAutomation": "97%",
                "annualSelfAssessment": "Filed 11 days early",
            },
        },
        {
            "id": "CS-04",
            "title": "Joint examination drill — ECB + Fed + PRA",
            "sector": "Cross-jurisdiction",
            "summary": (
                "Three home/host supervisors ran a joint examination of "
                "AI-CR-UNDERWRITE-01 using FedReg, with binding-with-override "
                "advisory issued by an autonomous supervisor agent (T4)."
            ),
            "outcomes": {
                "totalQueries": 412,
                "averageReplyLatency": "27 minutes",
                "challengePassRate": "98.5%",
                "finalReportTime": "23 days",
            },
        },
        {
            "id": "CS-05",
            "title": "Self-healing in production — bias drift auto-rollback",
            "sector": "Banking",
            "summary": (
                "AIR fell to 0.81 on a protected attribute; SH-01 auto-"
                "rolled back the model within 4 minutes, opened Sev-2, and "
                "filed a customer-impact pre-warning to Internal Audit."
            ),
            "outcomes": {
                "detectionToRollback": "4 min",
                "customerImpact": "0 wrongful denials",
                "regulatorNotified": "ECB + ICO within 6h",
                "rcaPublished": "<= 5 business days",
            },
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# API endpoints
# ──────────────────────────────────────────────────────────────────────────────
def api_endpoints():
    routes = [
        "", "/meta", "/executive-summary", "/summary",
        "/aims", "/aims/sections", "/aims/sections/:id",
        "/aims/annexes", "/aims/annexes/:id",
        "/regulatory", "/regulatory/overlays", "/regulatory/overlays/:id",
        "/regulatory/precedence", "/regulatory/matrix",
        "/rsp", "/rsp/versions", "/rsp/versions/:id",
        "/rsp/structure", "/rsp/api", "/rsp/pipeline",
        "/enforcement", "/enforcement/terraform", "/enforcement/opa",
        "/enforcement/audit",
        "/adversarial", "/adversarial/loop", "/adversarial/playbooks",
        "/adversarial/kpis",
        "/predictive", "/predictive/forecasters", "/predictive/formal",
        "/predictive/causal",
        "/federation", "/federation/protocol", "/federation/tiers",
        "/federation/privacy", "/federation/joint-exam",
        "/credit-underwriting", "/credit-underwriting/scope",
        "/credit-underwriting/data", "/credit-underwriting/dev-validation",
        "/credit-underwriting/decisioning", "/credit-underwriting/monitoring",
        "/credit-underwriting/regulator",
        "/roadmap", "/roadmap/phases", "/roadmap/phases/:id",
        "/roadmap/kpis", "/roadmap/risks",
        "/operating-model", "/operating-model/lod",
        "/operating-model/raci", "/operating-model/committees",
        "/reporting", "/reporting/audience", "/reporting/template",
        "/reporting/principles",
        "/schemas", "/schemas/:name",
        "/code-examples", "/code-examples/:name",
        "/case-studies", "/case-studies/:id",
        "/modules", "/modules/:id", "/sections/:id",
    ]
    for i in range(1, 13):
        routes.append(f"/m{i}")
    return {"prefix": "/api/gsifi-aims", "routes": routes}


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    data = {
        "meta": meta(),
        "executiveSummary": executive_summary(),
        "M1_aimsSections": m1_aims_sections(),
        "M2_aimsAnnexes": m2_aims_annexes(),
        "M3_regulatoryOverlays": m3_regulatory_overlays(),
        "M4_rsp": m4_rsp(),
        "M5_technicalEnforcement": m5_technical_enforcement(),
        "M6_adversarialSelfHealing": m6_adversarial_self_healing(),
        "M7_predictiveFormal": m7_predictive_formal(),
        "M8_federationSupervisory": m8_federation_supervisory(),
        "M9_creditUnderwriting": m9_credit_underwriting(),
        "M10_roadmap": m10_roadmap(),
        "M11_operatingModel": m11_operating_model(),
        "M12_reportingDisclosure": m12_reporting_disclosure(),
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
    print(
        f"Modules: {n_modules} | Sections: {n_sections} | "
        f"Schemas: {len(data['schemas'])} | "
        f"Code: {len(data['codeExamples'])} | "
        f"Cases: {len(data['caseStudies'])} | "
        f"Routes: {len(data['apiEndpoints']['routes'])}"
    )


if __name__ == "__main__":
    main()
