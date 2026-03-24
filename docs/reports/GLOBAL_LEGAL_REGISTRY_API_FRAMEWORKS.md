# Global Legal & Registry API Frameworks for Advanced AI Compute & Safety

## International Governance Architecture for Civilization-Scale AI Infrastructure

---

**Document Reference:** LEGAL-GSIFI-WP-010  
**Version:** 1.0.0  
**Classification:** CONFIDENTIAL — Board / C-Suite / Policymakers / International Bodies  
**Date:** 2026-03-24  
**Authors:** Chief Software Architect; General Counsel; VP AI Governance; Chief Scientist  
**Intended Audience:** G-SIFI Board Committees, Policymakers, OECD, GPAI, UN, G20, Legal Advisors, Compute Infrastructure Providers, AI Safety Bodies  
**Companion Documents:** ENERGY-COMPUTE-WP-004, CIV-GSIFI-WP-006, IMPL-GSIFI-WP-005  
**Suite:** WP-IMPL-GSIFI-2026 (Implementation Series)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Global AI Compute Governance Gap](#2-the-global-ai-compute-governance-gap)
3. [Global Compute Registry (GCR) — API Framework v2.0](#3-global-compute-registry-gcr--api-framework-v20)
4. [International Compute Governance Consortium (ICGC) — Legal Framework](#4-international-compute-governance-consortium-icgc--legal-framework)
5. [Legal Frameworks for Advanced AI Systems](#5-legal-frameworks-for-advanced-ai-systems)
6. [Safety Tier Classification System](#6-safety-tier-classification-system)
7. [Cross-Border AI Governance Legal Architecture](#7-cross-border-ai-governance-legal-architecture)
8. [Registry API Technical Specification](#8-registry-api-technical-specification)
9. [Liability Frameworks for AI Systems](#9-liability-frameworks-for-ai-systems)
10. [Intellectual Property Governance for AI](#10-intellectual-property-governance-for-ai)
11. [Data Sovereignty & Cross-Border AI Data Governance](#11-data-sovereignty--cross-border-ai-data-governance)
12. [Financial Sector AI Legal Considerations](#12-financial-sector-ai-legal-considerations)
13. [Implementation Roadmap](#13-implementation-roadmap)
14. [Policy Recommendations](#14-policy-recommendations)

---

## 1. Executive Summary

### 1.1 The Legal & Registry Imperative

Advanced AI compute infrastructure — from current GPU clusters to future AGI-scale facilities — represents a new category of strategic infrastructure that no existing legal framework adequately governs. This whitepaper proposes:

- A **Global Compute Registry (GCR)** with standardized API interfaces for tracking, monitoring, and governing AI compute globally
- An **International Compute Governance Consortium (ICGC)** as the multilateral body overseeing the registry
- **Legal frameworks** for AI liability, intellectual property, data sovereignty, and cross-border governance
- **Safety tier classification** linking compute capability to governance requirements

### 1.2 Key Findings

| Finding | Detail |
|---------|--------|
| **Governance gap** | No international registry or framework for AI compute facilities exists |
| **Compute concentration** | 80% of frontier AI compute controlled by 5 companies in 2 countries |
| **Legal fragmentation** | 40+ national AI governance frameworks with no interoperability standard |
| **Safety threshold** | No agreed international threshold for when AI compute requires safety controls |
| **Liability vacuum** | No established liability framework for autonomous AI decision failures |
| **IP uncertainty** | No settled law on AI-generated intellectual property ownership |
| **Data sovereignty conflicts** | Cross-border AI training creates jurisdictional conflicts |

### 1.3 Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│         GLOBAL AI COMPUTE & SAFETY GOVERNANCE ARCHITECTURE           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ INTERNATIONAL GOVERNANCE                                      │   │
│  │  ICGC (20+ nations) ─── OECD AI Policy Observatory           │   │
│  │  UN AI Advisory Body ─── G20 AI Working Group                 │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ GLOBAL COMPUTE REGISTRY (GCR)                                 │   │
│  │  Registry API v2.0 ─── Safety Tier Classification             │   │
│  │  Compute Facility Database ─── Training Run Registry          │   │
│  │  Model Capability Registry ─── Safety Assessment Records      │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ NATIONAL LEGAL FRAMEWORKS                                     │   │
│  │  EU AI Act + GDPR ─── US EO 14110 + FCRA ─── UK AI Act       │   │
│  │  MAS AI Guidelines ─── HKMA CRAF ─── Basel III                │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ INSTITUTIONAL GOVERNANCE                                      │   │
│  │  G-SIFI AI Governance ─── Sentinel v2.4 ─── NPGARS           │   │
│  │  Kyaw Stack ─── OPA Compliance Engine ─── Kafka WORM          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Global AI Compute Governance Gap

### 2.1 Current State Assessment

| Dimension | Status | Risk Level |
|-----------|--------|-----------|
| **Global compute registry** | Does not exist | Critical |
| **International safety thresholds** | No agreement | Critical |
| **Compute monitoring** | National/voluntary only | High |
| **Cross-border AI training** | Ungoverned | High |
| **Liability framework** | Fragmented/incomplete | High |
| **IP framework** | Unsettled | Medium |
| **Data sovereignty** | Conflicting national laws | High |
| **AGI governance treaty** | Not initiated | Critical (future) |

### 2.2 Compute Landscape (2026)

| Metric | Value | Trend |
|--------|-------|-------|
| Global AI compute (estimated FLOP/s) | 4.2 × 10²⁵ | +120% YoY |
| Frontier training runs (>10²⁶ FLOP) | 12 in 2025 | +300% since 2023 |
| Countries with >1 exaFLOP AI compute | 8 | +3 since 2024 |
| Companies controlling >80% of frontier compute | 5 | Concentrating |
| AI compute electricity consumption | ~1.2% of global | Growing 25% YoY |
| Compute concentration (top 2 countries) | 78% | Stable |
| Countries with AI compute governance laws | 3 (EU, US partial, China) | Growing |

---

## 3. Global Compute Registry (GCR) — API Framework v2.0

### 3.1 Registry Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│               GLOBAL COMPUTE REGISTRY — Architecture                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ API GATEWAY (REST + GraphQL)                                  │   │
│  │  Authentication (mTLS + OAuth2) ─── Rate Limiting             │   │
│  │  Versioning (v2.0) ─── Audit Logging                          │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ REGISTRY SERVICES                                             │   │
│  │                                                                │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │   │
│  │  │ Facility      │  │ Training     │  │ Model            │   │   │
│  │  │ Registry      │  │ Run Registry │  │ Capability       │   │   │
│  │  │ Service       │  │ Service      │  │ Registry         │   │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘   │   │
│  │                                                                │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │   │
│  │  │ Safety        │  │ Compliance   │  │ Analytics        │   │   │
│  │  │ Assessment    │  │ Verification │  │ & Reporting      │   │   │
│  │  │ Service       │  │ Service      │  │ Service          │   │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘   │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ DATA LAYER                                                    │   │
│  │  PostgreSQL (registry) ─── Elasticsearch (search)             │   │
│  │  TimescaleDB (time-series) ─── S3 (documents)                │   │
│  │  Kafka (event streaming) ─── Redis (cache)                    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Registry Data Model

| Entity | Key Fields | Purpose |
|--------|-----------|---------|
| **Facility** | ID, location, operator, capacity (FLOP/s), safety tier, energy source, certifications | Track all AI compute facilities |
| **Training Run** | ID, facility_id, model_id, compute (FLOP), duration, purpose, safety assessment | Register frontier training runs |
| **Model** | ID, creator, capability_level, safety_assessment, deployment_status, benchmark_scores | Track AI model capabilities |
| **Safety Assessment** | ID, model_id, assessor, methodology, results, recommendations, validity_period | Record safety evaluations |
| **Incident** | ID, facility_id/model_id, severity, description, response, lessons_learned | Track AI safety incidents |
| **Compliance Record** | ID, entity_id, framework, status, evidence, audit_date | Track regulatory compliance |

---

## 4. International Compute Governance Consortium (ICGC) — Legal Framework

### 4.1 ICGC Structure

| Component | Description | Membership |
|-----------|-------------|-----------|
| **General Assembly** | All member states, one vote each | 20+ nations (target) |
| **Executive Council** | 7 elected members, rotating | Major AI nations + rotating seats |
| **Technical Secretariat** | Operational management of GCR | Professional staff (50+) |
| **Safety Assessment Board** | Independent safety evaluations | Scientists + engineers |
| **Legal Advisory Panel** | Legal framework development and interpretation | International law experts |
| **Industry Advisory Committee** | Industry engagement and consultation | Major AI companies |
| **Civil Society Observer** | Public accountability and transparency | NGOs, academic institutions |

### 4.2 ICGC Treaty Provisions

| Provision | Description | Enforcement |
|-----------|-------------|-------------|
| **Mandatory Registration** | All compute facilities >10 exaFLOP must register | Sanctions for non-compliance |
| **Training Run Reporting** | Training runs >10²⁶ FLOP must be reported pre-commencement | Pre-registration requirement |
| **Safety Assessment** | Mandatory safety assessment for Safety Tier 3+ systems | Independent assessment body |
| **Incident Reporting** | Mandatory reporting of AI safety incidents within 72 hours | Financial penalties |
| **Information Sharing** | Member states share safety-relevant information | Reciprocal obligation |
| **Mutual Recognition** | Recognition of safety assessments across jurisdictions | Harmonization standards |
| **Emergency Powers** | Coordinated response to catastrophic AI incidents | Supermajority vote |

### 4.3 Membership Requirements

| Requirement | Detail |
|-------------|--------|
| National AI governance framework | Enacted or in legislative process |
| Domestic compute registry | Operational or in development |
| Safety assessment capability | National or recognized third-party |
| Data sharing commitment | Real-time incident data; quarterly compute data |
| Financial contribution | GDP-proportional annual contribution |
| Regulatory cooperation | MoU with 3+ existing members |

---

## 5. Legal Frameworks for Advanced AI Systems

### 5.1 Comparative Legal Analysis

| Dimension | EU | US | UK | Singapore | Hong Kong |
|-----------|-----|-----|-----|-----------|-----------|
| **Primary AI law** | EU AI Act (2024/1689) | EO 14110 (Executive Order) | AI Safety Act (proposed) | MAS AI Guidelines | HKMA CRAF |
| **Regulatory approach** | Risk-based, prescriptive | Voluntary + sector-specific | Principles-based | Principles-based | Risk-based guidance |
| **Scope** | All AI systems in EU market | Federal agencies + dual-use | Cross-sector | Financial sector | Financial sector |
| **Enforcement** | Fines up to 7% global turnover | Agency-specific | Proposed authority | MAS enforcement | HKMA supervisory |
| **AI liability** | Product Liability Directive update | Tort law (evolving) | Common law + reform | Contract/tort | Common law |
| **Compute governance** | Reporting requirements | OSTP reporting | Proposed registry | No specific | No specific |
| **AGI provisions** | Art. 5 (prohibited) + Art. 55 (systemic) | EO 14110 dual-use provisions | Frontier safety duties | Not addressed | Not addressed |

### 5.2 Legal Harmonization Priorities

| Priority | Description | Timeline | Lead Body |
|----------|-------------|----------|-----------|
| **P1** | Mutual recognition of AI safety assessments | 2026–2027 | OECD + ICGC |
| **P2** | Harmonized AI incident reporting standard | 2026–2027 | FSB + ICGC |
| **P3** | Cross-border AI liability framework | 2027–2028 | UNCITRAL + OECD |
| **P4** | International AI IP treaty | 2027–2029 | WIPO |
| **P5** | Global compute safety tier standards | 2026–2028 | ICGC + ISO |
| **P6** | Cross-border data governance for AI training | 2027–2028 | OECD + WTO |
| **P7** | AGI governance treaty framework | 2028–2030 | UN + ICGC |

---

## 6. Safety Tier Classification System

### 6.1 Five-Tier Safety Classification

| Tier | Compute Threshold | Capability Level | Governance Requirements | Example |
|------|------------------|------------------|------------------------|---------|
| **Tier 1: Standard** | <10²³ FLOP | Narrow AI, specific tasks | Standard software governance | Traditional ML models |
| **Tier 2: Enhanced** | 10²³–10²⁵ FLOP | Capable models, broad application | Model risk management, testing, documentation | Mid-size LLMs, domain-specific |
| **Tier 3: High** | 10²⁵–10²⁶ FLOP | Foundation models, general capability | Comprehensive risk management, red-teaming, safety testing, reporting | GPT-4 class, Claude 3.5 class |
| **Tier 4: Critical** | 10²⁶–10²⁸ FLOP | Frontier models, approaching AGI | Full safety assessment, containment planning, international notification | Future frontier models |
| **Tier 5: Existential** | >10²⁸ FLOP | AGI/ASI-scale capability | Full containment, international authorization, democratic mandate | Hypothetical AGI training |

### 6.2 Tier-Specific Legal Requirements

| Requirement | Tier 1 | Tier 2 | Tier 3 | Tier 4 | Tier 5 |
|-------------|--------|--------|--------|--------|--------|
| GCR Registration | Voluntary | Voluntary | **Mandatory** | **Mandatory** | **Mandatory** |
| Pre-training notification | No | No | 90 days | **180 days** | **365 days** |
| Safety assessment | Self | Self/third-party | **Third-party** | **ICGC-approved** | **ICGC-conducted** |
| Red-team testing | Voluntary | Recommended | **Mandatory** | **Mandatory (independent)** | **Mandatory (international)** |
| Incident reporting | Best-effort | 30 days | **72 hours** | **24 hours** | **Immediate** |
| Containment plan | No | No | Recommended | **Mandatory** | **Mandatory + verified** |
| Kill-switch | No | Recommended | **Mandatory** | **Mandatory + HSM** | **Mandatory + multi-party** |
| International coordination | No | No | Voluntary | **Mandatory** | **Mandatory + authorization** |
| Public transparency | No | Voluntary | Recommended | **Mandatory** | **Mandatory + public vote** |

### 6.3 Safety Tier API

```yaml
# GCR Safety Tier Classification API
POST /api/v2/safety-tier/classify
Request:
  compute_flop: 3.2e25
  model_type: "foundation_model"
  training_data_sources: ["web_crawl", "books", "code"]
  intended_use: ["general_purpose", "financial_services"]
  
Response:
  tier: 3
  tier_name: "High"
  requirements:
    registration: "mandatory"
    pre_training_notification: "90_days"
    safety_assessment: "third_party_required"
    red_team: "mandatory"
    incident_reporting: "72_hours"
    containment: "recommended"
    kill_switch: "mandatory"
    international_coordination: "voluntary"
  applicable_frameworks:
    - EU_AI_ACT_GPAI_SYSTEMIC
    - EO_14110_DUAL_USE
    - ICGC_TIER_3_PROTOCOL
```

---

## 7. Cross-Border AI Governance Legal Architecture

### 7.1 Jurisdictional Adapter Pattern

```
┌─────────────────────────────────────────────────────────────────────┐
│           CROSS-BORDER LEGAL GOVERNANCE ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ UNIVERSAL GOVERNANCE CORE                                     │   │
│  │  OECD AI Principles ─── ICGC Standards ─── ISO 42001         │   │
│  │  GCR API v2.0 ─── Safety Tier System                          │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ JURISDICTIONAL ADAPTERS                                       │   │
│  │                                                                │   │
│  │  ┌───────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────┐   │   │
│  │  │ EU Adapter │ │ US       │ │ UK      │ │ APAC Adapter │   │   │
│  │  │            │ │ Adapter  │ │ Adapter │ │              │   │   │
│  │  │ EU AI Act  │ │ EO 14110 │ │ AI Act  │ │ MAS FEAT     │   │   │
│  │  │ GDPR       │ │ FCRA     │ │ PRA     │ │ HKMA CRAF    │   │   │
│  │  │ DORA       │ │ ECOA     │ │ FCA     │ │ PDPA         │   │   │
│  │  │ NIS2       │ │ CCPA     │ │ SMCR    │ │ PIPL         │   │   │
│  │  └───────────┘ └──────────┘ └─────────┘ └──────────────┘   │   │
│  └──────────────────────┬───────────────────────────────────────┘   │
│                          │                                           │
│  ┌──────────────────────▼───────────────────────────────────────┐   │
│  │ LOCAL IMPLEMENTATION                                          │   │
│  │  Sentinel local rules ─── OPA jurisdiction-specific policies  │   │
│  │  NPGARS local templates ─── Local regulatory reporting        │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Conflict Resolution Framework

| Scenario | Principle | Resolution |
|----------|-----------|-----------|
| EU and US requirements conflict | Strictest standard applies | Comply with most restrictive; document deviation for less restrictive |
| Data sovereignty conflict (GDPR vs. CLOUD Act) | Data subject protection primacy | Localization by default; legal challenge of conflicting orders |
| AI liability claim across jurisdictions | Forum selection clause + applicable law | Pre-agreed in service agreements; UNCITRAL model law |
| IP ownership dispute for AI output | Creator jurisdiction law | Contractual assignment; WIPO guidance pending |
| Safety assessment disagreement | Mutual recognition (ICGC) | ICGC arbitration panel; highest-standard applies |

---

## 8. Registry API Technical Specification

### 8.1 API Endpoint Catalog

| Endpoint | Method | Description | Auth | Rate Limit |
|----------|--------|-------------|------|-----------|
| `/api/v2/facilities` | GET | List registered compute facilities | OAuth2 | 100/min |
| `/api/v2/facilities` | POST | Register new compute facility | mTLS + OAuth2 | 10/min |
| `/api/v2/facilities/{id}` | GET | Facility details | OAuth2 | 100/min |
| `/api/v2/facilities/{id}/capacity` | GET | Real-time capacity data | OAuth2 | 60/min |
| `/api/v2/training-runs` | GET | List registered training runs | OAuth2 | 100/min |
| `/api/v2/training-runs` | POST | Register new training run | mTLS + OAuth2 | 10/min |
| `/api/v2/training-runs/{id}` | GET | Training run details | OAuth2 | 100/min |
| `/api/v2/models` | GET | List registered models | OAuth2 | 100/min |
| `/api/v2/models` | POST | Register new model | mTLS + OAuth2 | 10/min |
| `/api/v2/models/{id}/capability` | GET | Model capability assessment | OAuth2 | 60/min |
| `/api/v2/safety-assessments` | GET | List safety assessments | OAuth2 | 100/min |
| `/api/v2/safety-assessments` | POST | Submit safety assessment | mTLS + OAuth2 | 10/min |
| `/api/v2/incidents` | GET | List reported incidents | OAuth2 | 100/min |
| `/api/v2/incidents` | POST | Report new incident | mTLS + OAuth2 | 50/min |
| `/api/v2/safety-tier/classify` | POST | Classify safety tier | OAuth2 | 100/min |
| `/api/v2/compliance` | GET | Compliance status overview | OAuth2 | 60/min |
| `/api/v2/analytics/compute-global` | GET | Global compute analytics | OAuth2 | 30/min |
| `/api/v2/analytics/safety-trends` | GET | Safety trend analytics | OAuth2 | 30/min |

### 8.2 API Security Architecture

| Layer | Control | Implementation |
|-------|---------|----------------|
| Transport | mTLS 1.3 | All API calls encrypted; certificate-based authentication for write operations |
| Authentication | OAuth 2.0 + JWT | Short-lived tokens (15 min); refresh tokens (24 hr); PKCE flow |
| Authorization | RBAC + ABAC | Role-based (member state, operator, assessor) + attribute-based (jurisdiction, tier) |
| Rate Limiting | Token bucket | Per-client, per-endpoint rate limits; burst allowance |
| Audit | Kafka WORM | All API calls logged with full request/response context |
| DDoS Protection | CDN + WAF | Cloudflare/Akamai WAF; geographic filtering for write APIs |

---

## 9. Liability Frameworks for AI Systems

### 9.1 Proposed Liability Architecture

| Liability Tier | AI System Type | Liability Regime | Standard of Care |
|---------------|---------------|------------------|-----------------|
| **Tier A** | Deterministic AI (Stage 1–2) | Product liability (strict) | Defect-based |
| **Tier B** | Statistical/DL AI (Stage 3) | Product liability + negligence | Reasonable care + testing |
| **Tier C** | Foundation models (Stage 4) | Enhanced product liability | Comprehensive testing + monitoring |
| **Tier D** | Agentic AI (Stage 5) | New "AI agent liability" regime | Governance-based: kill-switch, oversight, audit |
| **Tier E** | AGI-class (Stage 7+) | Institutional liability + personal (SMCR-style) | Containment, alignment verification, democratic mandate |

### 9.2 G-SIFI-Specific Liability Considerations

| Risk Area | Current Liability | Proposed Framework | Mitigation |
|-----------|------------------|-------------------|-----------|
| AI credit decisioning errors | Bank liable (FCRA/ECOA) | Strict liability for discriminatory outcomes | UDIF fairness monitoring, adverse action automation |
| AI trading losses | Complex (agent/principal) | Enhanced duty of care for AI-driven trading | Kill-switch, pre-trade checks, circuit breakers |
| AI advisory failures | Suitability liability | Enhanced suitability for AI advice | HA-RAG accuracy controls, human oversight |
| AI AML/KYC failures | Regulatory sanctions | Personal liability for senior managers (SMCR) | Sentinel monitoring, audit trail |
| AI data breach | GDPR fines + civil liability | Joint controller liability for AI systems | Docker Swarm security, encryption, access controls |
| Systemic AI failure | Uncertain | Systemic failure liability (new) | Omni-Sentinel, cross-institutional monitoring |

---

## 10. Intellectual Property Governance for AI

### 10.1 AI IP Framework

| Dimension | Current State | Proposed Framework |
|-----------|--------------|-------------------|
| **AI-generated works (copyright)** | Uncertain; varies by jurisdiction | Creator/deployer retains IP with mandatory AI disclosure |
| **AI-assisted inventions (patent)** | Human inventor required (most jurisdictions) | AI contribution disclosed; human inventor required |
| **Training data IP** | Unresolved (fair use vs. licensing) | Mandatory licensing for commercial AI training (>$10M) |
| **Model weights IP** | Trade secret (proprietary); open-weight models | New "model rights" category with tiered protection |
| **AI-generated financial strategies** | Uncertain | Deployer owns; competitive law applies |

---

## 11. Data Sovereignty & Cross-Border AI Data Governance

### 11.1 Cross-Border Data Governance Framework

| Scenario | EU Rule | US Rule | Resolution |
|----------|---------|---------|-----------|
| AI training with EU personal data | GDPR Chapter V (SCCs, adequacy) | No federal restriction (CCPA applies in CA) | SCCs + DPIA + data minimization |
| Cross-border model deployment | EU AI Act (CE marking for EU market) | EO 14110 (dual-use reporting) | Parallel compliance; CE + OSTP |
| Cross-border AI incident data | GDPR Art. 33 (72-hour breach notification) | State breach laws (varying) | Unified ICGC incident reporting (72-hour) |
| Federated learning across borders | Data stays local (GDPR-compliant) | Generally permitted | Recommended approach for G-SIFIs |

---

## 12. Financial Sector AI Legal Considerations

### 12.1 G-SIFI-Specific Legal Requirements

| Requirement | Source | Implementation | Evidence |
|-------------|--------|----------------|---------|
| Model risk accountability | SR 11-7 + SMCR | Named accountable person for each AI model | SMCR responsibility map |
| Fair lending AI compliance | FCRA §604, ECOA Reg B | Automated adverse action with UDIF fairness monitoring | Adverse action logs, DIR reports |
| Consumer Duty outcomes | FCA Consumer Duty 2023 | HA-RAG + CCaaS outcome monitoring | Consumer outcome dashboards |
| AML/KYC AI governance | AMLD6 + BSA | Sentinel AML rules, audit trail | SAR filings, screening logs |
| Capital adequacy impact | Basel III / CRR2 | AI risk quantification in RWA calculations | Capital impact assessments |
| Market manipulation prevention | MAR/MAD + Dodd-Frank | Algorithmic trading controls, circuit breakers | Pre-trade check logs |
| Operational resilience | DORA (EU) + PRA | AI system resilience testing, DR planning | Resilience test reports |

---

## 13. Implementation Roadmap

### 13.1 Phased Implementation

| Phase | Timeline | Legal | Registry | International |
|-------|----------|-------|----------|---------------|
| **Foundation** | 2026 | Legal analysis complete; liability framework draft | GCR API v1.0 pilot | ICGC founding treaty draft |
| **Pilot** | 2027 | 5-nation mutual recognition MoU | GCR v1.5 (10 nations) | ICGC provisional establishment |
| **Expansion** | 2028 | IP framework proposed to WIPO | GCR v2.0 (20 nations) | ICGC formal establishment |
| **Maturity** | 2029–2030 | AGI governance treaty draft | GCR universal coverage | ICGC full operations |

### 13.2 Investment Requirements

| Component | 2026 | 2027 | 2028 | 2029–2030 | Total |
|-----------|------|------|------|-----------|-------|
| GCR development & operations | $8.4M | $12.6M | $14.2M | $22.0M | $57.2M |
| ICGC establishment | $4.2M | $8.4M | $12.6M | $18.8M | $44.0M |
| Legal framework development | $2.8M | $4.2M | $5.6M | $8.4M | $21.0M |
| National adaptation support | $1.4M | $2.8M | $4.2M | $8.4M | $16.8M |
| **Total** | **$16.8M** | **$28.0M** | **$36.6M** | **$57.6M** | **$139.0M** |

---

## 14. Policy Recommendations

### 14.1 For National Governments

1. **Establish domestic compute registries** compatible with GCR API v2.0 standards.
2. **Enact AI liability legislation** addressing autonomous decision-making failures.
3. **Join ICGC** as founding or early members to shape international standards.
4. **Harmonize AI governance** with existing treaty obligations (trade, data protection).
5. **Fund legal research** on AI liability, IP, and cross-border governance.

### 14.2 For International Bodies

1. **OECD**: Lead GCR API standardization and mutual recognition framework.
2. **UN**: Establish AI governance working group for AGI treaty development.
3. **WIPO**: Commence AI IP treaty negotiations.
4. **WTO**: Address AI compute as a tradeable service under GATS.
5. **FSB**: Integrate GCR data into G-SIFI supervision framework.

### 14.3 For G-SIFIs

1. **Register voluntarily** with emerging compute registries to influence standards.
2. **Adopt GCR API** for internal compute governance as preparation for mandatory compliance.
3. **Implement safety tier** self-classification for all AI systems.
4. **Prepare liability documentation** for AI-driven decisions across jurisdictions.
5. **Engage legal counsel** on AI IP strategy, especially for AI-generated financial innovations.

---

## Appendix: Document Control

| Version | Date | Author | Change Description |
|---------|------|--------|-------------------|
| 1.0.0 | 2026-03-24 | Chief Software Architect | Initial release |

---

*Document Reference: LEGAL-GSIFI-WP-010 | Classification: CONFIDENTIAL | Distribution: Restricted*
