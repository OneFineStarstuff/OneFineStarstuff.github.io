# Kardashev-Scale Energy Futures & Global AI Compute Governance

## A Strategic Whitepaper for Policymakers and G-SIFIs

---

**Document Reference:** ENERGY-COMPUTE-WP-004
**Version:** 1.0.0
**Classification:** CONFIDENTIAL — Board / C-Suite / Policymakers / Energy Regulators
**Date:** 2026-03-22
**Authors:** Chief Software Architect; VP Infrastructure & Sustainability; Head of AI Governance; Chief Scientist
**Intended Audience:** G-SIFI Board Risk Committees, CROs, CTOs, Sustainability Officers, Energy Regulators, Global Policymakers, International Coordination Bodies
**Companion Documents:** GOV-GSIFI-WP-001, ARCH-GSIFI-WP-002, AGI-SAFETY-WP-003, SPEC-AGIGOV-UNIFIED-001

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Kardashev Scale & AI Energy Trajectory](#2-the-kardashev-scale--ai-energy-trajectory)
3. [Global AI Energy Consumption Analysis](#3-global-ai-energy-consumption-analysis)
4. [AI Compute Growth Projections (2025–2040)](#4-ai-compute-growth-projections-20252040)
5. [Energy Infrastructure Requirements for AGI-Scale Compute](#5-energy-infrastructure-requirements-for-agi-scale-compute)
6. [Global Compute Registry (GCR) — Architecture & Governance](#6-global-compute-registry-gcr--architecture--governance)
7. [International Compute Governance Consortium (ICGC)](#7-international-compute-governance-consortium-icgc)
8. [Sustainability & Environmental Governance](#8-sustainability--environmental-governance)
9. [Financial Sector AI Energy Governance](#9-financial-sector-ai-energy-governance)
10. [Compute-Tier Governance & Safety Thresholds](#10-compute-tier-governance--safety-thresholds)
11. [Registry API v2.0 Specification](#11-registry-api-v20-specification)
12. [Legal & Regulatory Frameworks for AI Compute](#12-legal--regulatory-frameworks-for-ai-compute)
13. [Nuclear & Fusion Energy Pathways for AI](#13-nuclear--fusion-energy-pathways-for-ai)
14. [Risk Analysis & Geopolitical Considerations](#14-risk-analysis--geopolitical-considerations)
15. [Investment & Infrastructure Roadmap](#15-investment--infrastructure-roadmap)
16. [Policy Recommendations](#16-policy-recommendations)

---

## 1. Executive Summary

### 1.1 The Energy-Compute Nexus

Artificial intelligence is becoming one of the most significant drivers of global energy demand. As AI systems scale from current foundation models toward AGI-class capabilities, their energy requirements will grow by orders of magnitude — raising fundamental questions about energy infrastructure, environmental sustainability, geopolitical power dynamics, and governance frameworks.

This whitepaper provides:

- **Kardashev-scale analysis** of humanity's energy trajectory as shaped by AI compute demands
- **Quantitative projections** of AI energy consumption from 2025 to 2040
- **Governance frameworks** for global AI compute registration, monitoring, and safety thresholds
- **Sustainability strategies** for AI-intensive financial institutions
- **Policy recommendations** for policymakers navigating the energy-AI nexus

### 1.2 Key Findings

| Finding | Detail |
|---------|--------|
| **Current Kardashev position** | Type 0.73 (planetary energy utilization) |
| **AI electricity share (2025)** | ~1.2% of global electricity consumption |
| **AI electricity share (2030)** | Projected 2.4–3.8% |
| **AI electricity share (2035)** | Projected 4–8% |
| **AGI-scale compute energy** | Estimated 50–200 TWh/year for a single AGI training cluster |
| **Financial sector AI energy** | ~$420M/year across G-SIFIs (2026 estimate) |
| **Carbon intensity challenge** | AI growth could add 0.5–1.5 GtCO₂/year by 2035 without intervention |
| **Governance gap** | No international registry or compute-tier safety framework exists |

### 1.3 Strategic Imperative

> **The governance of AI compute is not merely a technical or environmental concern — it is a civilizational infrastructure challenge that will shape the trajectory of human development for the remainder of this century.**

---

## 2. The Kardashev Scale & AI Energy Trajectory

### 2.1 Kardashev Scale Overview

The Kardashev Scale, proposed by Soviet astronomer Nikolai Kardashev in 1964, classifies civilizations by their energy utilization:

| Type | Energy Utilization | Power Level | Description |
|------|-------------------|-------------|-------------|
| **Type 0** | Sub-planetary | < 10¹⁶ W | Incomplete utilization of home planet's resources |
| **Type I** | Planetary | ~10¹⁶ W (~1.74 × 10¹⁷ W) | Complete utilization of home planet's energy |
| **Type II** | Stellar | ~10²⁶ W (3.8 × 10²⁶ W) | Complete utilization of home star's energy |
| **Type III** | Galactic | ~10³⁶ W | Complete utilization of home galaxy's energy |

### 2.2 Current Human Position: Type 0.73

Using Carl Sagan's interpolation formula:

```
K = (log₁₀(P) - 6) / 10

Where:
  P = total power consumption in watts
  Current global: ~1.8 × 10¹³ W (18 TW)

K = (log₁₀(1.8 × 10¹³) - 6) / 10
K = (13.26 - 6) / 10
K ≈ 0.73
```

### 2.3 AI's Impact on Kardashev Trajectory

AI compute is accelerating humanity's energy consumption growth rate:

```
Kardashev Trajectory Model
══════════════════════════

  Type 0.73 ──── Current (2026)
       │
       │  AI acceleration factor: 1.2–1.5×
       │
  Type 0.75 ──── ~2030 (with AI compute growth)
       │         vs. ~2032 (without AI acceleration)
       │
  Type 0.78 ──── ~2035 (AI-accelerated)
       │
  Type 0.80 ──── ~2040 (AI-accelerated)
       │
       │  ┌──────────────────────────────────┐
       │  │ CRITICAL TRANSITION ZONE          │
       │  │ Type 0.80 → Type I               │
       │  │ Requires: fusion, advanced solar, │
       │  │ orbital energy                    │
       │  │ Timeline: ~2100–2200 (optimistic) │
       │  └──────────────────────────────────┘
       │
  Type I.0 ──── ~2100–2200 (if sustained growth)
```

### 2.4 Energy Scale Comparison

| Entity | Power Consumption | Kardashev Equivalent |
|--------|------------------|---------------------|
| Single GPU (NVIDIA H100) | 700 W | — |
| Single AI training cluster (10K GPUs) | 7 MW | — |
| GPT-4 training run (estimated) | ~50 GWh total | — |
| Large AI data center (2026) | 100–500 MW | — |
| Projected AGI training cluster | 1–5 GW | — |
| Global AI compute (2026) | ~40–60 GW | — |
| Global AI compute (2035, projected) | 200–500 GW | — |
| Earth's total solar irradiance | 1.74 × 10¹⁷ W | Type I baseline |
| Human civilization (total, 2026) | ~18 TW (1.8 × 10¹³ W) | Type 0.73 |

---

## 3. Global AI Energy Consumption Analysis

### 3.1 Current State (2026)

| Category | Power (GW) | Annual Energy (TWh) | % of Global Electricity |
|----------|-----------|--------------------|-----------------------|
| AI training (cloud providers) | 12–18 | 105–158 | 0.35–0.53% |
| AI inference (production) | 18–28 | 158–245 | 0.53–0.82% |
| AI data center cooling & overhead | 8–14 | 70–123 | 0.23–0.41% |
| Edge AI compute | 2–4 | 18–35 | 0.06–0.12% |
| **Total AI electricity** | **40–64** | **351–561** | **~1.2%** |
| Global electricity generation | ~3,200 | ~29,000 | 100% |

### 3.2 Historical Growth Rate

| Year | AI Energy (TWh) | % Global Electricity | YoY Growth |
|------|----------------|---------------------|------------|
| 2020 | ~60 | 0.22% | — |
| 2021 | ~80 | 0.29% | +33% |
| 2022 | ~120 | 0.43% | +50% |
| 2023 | ~180 | 0.64% | +50% |
| 2024 | ~270 | 0.93% | +50% |
| 2025 | ~370 | 1.2% | +37% |
| **2026** | **~470** | **~1.5%** | **+27%** |

### 3.3 Efficiency Trends

| Metric | 2022 | 2024 | 2026 | Trend |
|--------|------|------|------|-------|
| Training efficiency (FLOP/kWh) | 2.1 × 10¹² | 4.8 × 10¹² | 8.2 × 10¹² | +97%/yr |
| Inference efficiency (tokens/kWh) | 180K | 420K | 890K | +122%/yr |
| PUE (best-in-class data centers) | 1.10 | 1.08 | 1.06 | Improving |
| Carbon intensity (gCO₂/kWh compute) | 380 | 310 | 260 | -17%/yr |

> **Critical insight:** Efficiency gains of ~100%/yr are offset by compute demand growth of ~40–50%/yr, resulting in net energy growth of ~25–35%/yr.

---

## 4. AI Compute Growth Projections (2025–2040)

### 4.1 Projection Scenarios

| Scenario | Assumptions | 2030 AI Energy | 2035 AI Energy | 2040 AI Energy |
|----------|-------------|---------------|---------------|---------------|
| **Conservative** | Efficiency gains keep pace; no AGI | 700 TWh (2.4%) | 1,200 TWh (4%) | 1,800 TWh (5.5%) |
| **Moderate** | Continued scaling; early AGI capabilities | 950 TWh (3.2%) | 1,800 TWh (5.8%) | 3,200 TWh (9%) |
| **Aggressive** | AGI achieved; rapid ASI development | 1,100 TWh (3.8%) | 2,500 TWh (8%) | 5,000 TWh (13%) |

### 4.2 Compute Demand by AI Stage

| AI Evolution Stage | Compute Requirement (FLOP) | Estimated Energy per Training Run | Frequency |
|-------------------|---------------------------|----------------------------------|-----------|
| Stage 3 (Deep Learning) | 10¹⁸–10²¹ | 1–100 MWh | Weekly |
| Stage 4 (Foundation Models) | 10²³–10²⁵ | 10–100 GWh | Monthly |
| Stage 5 (Agentic AI) | 10²⁴–10²⁶ | 50–500 GWh | Quarterly |
| Stage 6 (Multi-Agent) | 10²⁵–10²⁷ | 100 GWh–1 TWh | Bi-annual |
| Stage 7 (Proto-AGI) | 10²⁷–10²⁹ | 1–50 TWh | Annual |
| Stage 8 (AGI) | 10²⁹–10³² | 50–200 TWh | Unknown |
| Stage 9-10 (ASI) | >10³² | >200 TWh | Unknown |

### 4.3 Inference vs. Training Energy Split

```
Energy Split Projection
═══════════════════════

  2024:  Training ████████████░░░░ 40%
         Inference ████████████████████████ 60%

  2026:  Training ████████░░░░░░░░ 30%
         Inference ████████████████████████████ 70%

  2030:  Training ██████░░░░░░░░░░ 20%
         Inference ████████████████████████████████ 80%

  2035:  Training ████░░░░░░░░░░░░ 15%
         Inference ██████████████████████████████████ 85%

  Note: Inference grows faster as deployed systems multiply.
        Training remains energy-intensive per run but less frequent.
```

---

## 5. Energy Infrastructure Requirements for AGI-Scale Compute

### 5.1 Infrastructure Gap Analysis

| Requirement | Current Capacity | AGI-Scale Need | Gap |
|-------------|-----------------|---------------|-----|
| Data center power (AI-dedicated) | ~40–60 GW | 200–500 GW | 4–10× |
| Renewable energy for AI | ~30% of AI compute | ≥80% by 2035 | 2.7× |
| Grid interconnection capacity | Regional | Continental | Major upgrade |
| Cooling infrastructure | Air + liquid | Advanced liquid + immersion | Technology shift |
| Power transmission | Existing grid | Dedicated AI power corridors | New infrastructure |
| Energy storage | Limited | 50–100 GWh (for AI load balancing) | Massive expansion |

### 5.2 Data Center Power Density Evolution

| Generation | Year | Power Density (kW/rack) | Cooling Method | Typical Facility Size |
|-----------|------|----------------------|---------------|---------------------|
| Gen 1 (Traditional) | 2015 | 5–10 | Air cooling | 10–50 MW |
| Gen 2 (GPU-Dense) | 2020 | 20–40 | Hybrid air/liquid | 50–100 MW |
| Gen 3 (AI-Optimized) | 2024 | 60–100 | Liquid cooling | 100–300 MW |
| Gen 4 (AI Hyperscale) | 2026 | 100–200 | Immersion | 300 MW–1 GW |
| Gen 5 (AGI-Scale) | 2030+ | 200–500 | Advanced immersion | 1–5 GW |

### 5.3 Power Source Requirements

```
AGI-Scale Data Center Power Mix (Target 2035)
═══════════════════════════════════════════════

  Nuclear (SMR/Fusion)  ████████████████████████████████ 40%
  Solar + Storage       ████████████████████████ 30%
  Wind + Storage        ████████████████ 20%
  Geothermal            ████ 5%
  Grid (fossil backup)  ████ 5%
                        ──────────────────────────────────
  Carbon-free target:   95% by 2035
```

---

## 6. Global Compute Registry (GCR) — Architecture & Governance

### 6.1 Registry Purpose

The Global Compute Registry (GCR) is a proposed international mechanism for:

1. **Tracking** large-scale AI compute resources and training runs globally
2. **Monitoring** compute concentration and systemic risks
3. **Enforcing** safety thresholds based on compute scale
4. **Enabling** international coordination on frontier AI governance
5. **Supporting** sustainability reporting and carbon accounting

### 6.2 Registry Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Global Compute Registry (GCR)                      │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                    Registry Core                              │    │
│  │                                                               │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │    │
│  │  │ Compute      │ │ Training Run │ │ Facility             │ │    │
│  │  │ Resource     │ │ Registry     │ │ Registry             │ │    │
│  │  │ Registry     │ │              │ │                      │ │    │
│  │  │              │ │ ─ FLOP count │ │ ─ Location           │ │    │
│  │  │ ─ GPU/TPU    │ │ ─ Duration   │ │ ─ Power capacity     │ │    │
│  │  │   inventory  │ │ ─ Energy     │ │ ─ Energy source      │ │    │
│  │  │ ─ Capacity   │ │ ─ Purpose    │ │ ─ PUE               │ │    │
│  │  │ ─ Utilization│ │ ─ Safety     │ │ ─ Carbon intensity   │ │    │
│  │  │ ─ Owner      │ │   assessment │ │ ─ Cooling type       │ │    │
│  │  └──────────────┘ └──────────────┘ └──────────────────────┘ │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Threshold    │  │ Safety       │  │ Sustainability            │  │
│  │ Monitor      │  │ Assessment   │  │ Module                    │  │
│  │              │  │ Engine       │  │                           │  │
│  │ ─ Compute    │  │ ─ Risk tier  │  │ ─ Carbon tracking         │  │
│  │   thresholds │  │ ─ Safety     │  │ ─ Renewable %             │  │
│  │ ─ Alerts     │  │   review     │  │ ─ Water usage             │  │
│  │ ─ Escalation │  │   trigger    │  │ ─ ESG reporting           │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                    API Layer (v2.0)                            │    │
│  │  REST + GraphQL │ mTLS │ RBAC │ Rate Limiting                │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.3 Registration Requirements

| Entity Type | Registration Threshold | Required Fields | Reporting Frequency |
|------------|----------------------|----------------|-------------------|
| **AI Training Facility** | >10 MW AI compute capacity | Location, capacity, power source, PUE, owner | Annual + material changes |
| **Large Training Run** | >10²³ FLOP total compute | Model type, FLOP count, energy consumed, safety assessment | Per run |
| **Frontier Training Run** | >10²⁵ FLOP total compute | Extended safety assessment, red-team results, alignment evaluation | Per run + quarterly updates |
| **AGI-Scale Run** | >10²⁷ FLOP total compute | Full safety dossier, international notification, containment plan | Pre-registration required |
| **Compute Provider** | >100 MW AI-dedicated capacity | Capacity, customers (anonymized), utilization, sustainability metrics | Quarterly |

### 6.4 Compute-Tier Classification

| Tier | Compute Range (FLOP) | Governance Level | Safety Requirements |
|------|---------------------|-----------------|-------------------|
| **Tier 1 — Standard** | <10²³ | Self-governance | Standard documentation |
| **Tier 2 — Significant** | 10²³–10²⁵ | Enhanced | Safety assessment, red-team report |
| **Tier 3 — Frontier** | 10²⁵–10²⁷ | Supervised | Full safety dossier, regulator notification |
| **Tier 4 — AGI-Scale** | 10²⁷–10²⁹ | Controlled | International coordination, containment review |
| **Tier 5 — Civilization-Scale** | >10²⁹ | Treaty-governed | Multi-lateral approval, ongoing monitoring |

---

## 7. International Compute Governance Consortium (ICGC)

### 7.1 Proposed Structure

```
┌──────────────────────────────────────────────────────────────────┐
│          International Compute Governance Consortium (ICGC)       │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                    Governing Council                       │    │
│  │  ─ Member state representatives (≥20 founding nations)    │    │
│  │  ─ Rotating chair (2-year term)                          │    │
│  │  ─ Decisions by qualified majority                        │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
│  │ Technical │  │ Safety       │  │ Sustainability│  │ Legal   │ │
│  │ Standards │  │ Assessment   │  │ & Energy      │  │ & Policy│ │
│  │ Committee │  │ Board        │  │ Committee     │  │ Unit    │ │
│  │           │  │              │  │               │  │         │ │
│  │ ─ Compute │  │ ─ Frontier   │  │ ─ Carbon      │  │ ─ Treaty│ │
│  │   metrics │  │   review     │  │   standards   │  │   draft │ │
│  │ ─ API     │  │ ─ Safety     │  │ ─ Renewable   │  │ ─ Dispute│ │
│  │   standards│  │   thresholds │  │   targets     │  │   resol.│ │
│  │ ─ Audit   │  │ ─ Emergency  │  │ ─ Reporting   │  │ ─ Sanct.│ │
│  │   methods │  │   protocols  │  │   standards   │  │   regime│ │
│  └──────────┘  └──────────────┘  └──────────────┘  └─────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                    GCR Operations Center                   │    │
│  │  ─ 24/7 monitoring of registered compute facilities       │    │
│  │  ─ Threshold alert management                             │    │
│  │  ─ International notification system                      │    │
│  │  ─ Emergency coordination desk                            │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### 7.2 ICGC Founding Principles

| # | Principle | Description |
|---|-----------|-------------|
| 1 | **Transparency** | All large-scale AI compute must be registered and reported |
| 2 | **Proportionality** | Governance burden proportional to compute scale and risk |
| 3 | **Inclusivity** | All nations can participate regardless of current AI capability |
| 4 | **Safety First** | Safety considerations override economic or competitive concerns |
| 5 | **Sustainability** | AI compute growth must align with climate commitments |
| 6 | **Sovereignty** | Respect for national sovereignty while ensuring global safety |
| 7 | **Verifiability** | Registry data must be verifiable through independent audit |
| 8 | **Adaptability** | Framework evolves with technology and risk landscape |

### 7.3 Emergency Coordination Protocol

For Tier 4–5 compute events (AGI-scale and above):

```
ICGC Emergency Protocol
═══════════════════════

  Level 1 — Notification (Tier 4 training detected)
  │ ─ Automated alert to ICGC Operations Center
  │ ─ Verification with registrant
  │ ─ Safety dossier review
  │ ─ Timeline: 48 hours
  │
  Level 2 — Assessment (Safety concern identified)
  │ ─ Safety Assessment Board convenes
  │ ─ Independent technical review
  │ ─ Member state consultation
  │ ─ Timeline: 7 days
  │
  Level 3 — Coordination (Material risk confirmed)
  │ ─ Governing Council emergency session
  │ ─ Multi-lateral coordination
  │ ─ Containment recommendations
  │ ─ Timeline: 14 days
  │
  Level 4 — Intervention (Imminent safety threat)
  │ ─ Emergency halt recommendation
  │ ─ Member state enforcement
  │ ─ International notification
  │ ─ Timeline: Immediate
  │
  Level 5 — Global Emergency (Civilizational risk)
  ─ UN Security Council notification
  ─ Global compute suspension recommendation
  ─ International enforcement coordination
  ─ Timeline: Immediate
```

---

## 8. Sustainability & Environmental Governance

### 8.1 AI Carbon Footprint Model

| Component | gCO₂/kWh (2026 avg.) | Annual TWh | Annual MtCO₂ |
|-----------|----------------------|-----------|-------------|
| AI training (cloud) | 260 | 130 | 33.8 |
| AI inference (production) | 220 | 200 | 44.0 |
| Data center overhead | 280 | 95 | 26.6 |
| Edge AI | 310 | 25 | 7.8 |
| **Total AI** | **256 (weighted avg.)** | **450** | **~112** |
| Global electricity emissions | 436 (avg.) | 29,000 | ~12,660 |
| **AI % of global emissions** | — | — | **~0.9%** |

### 8.2 Sustainability Targets

| Target | 2026 (Baseline) | 2028 | 2030 | 2035 |
|--------|-----------------|------|------|------|
| AI renewable energy % | 42% | 55% | 70% | 90% |
| AI carbon intensity (gCO₂/kWh) | 260 | 200 | 130 | 50 |
| PUE (industry average) | 1.20 | 1.15 | 1.10 | 1.06 |
| Water usage (L/kWh) | 1.8 | 1.4 | 1.0 | 0.5 |
| E-waste recycling rate | 65% | 75% | 85% | 95% |

### 8.3 Green AI Governance Controls

| Control ID | Name | Description | Enforcement |
|-----------|------|-------------|-------------|
| **GRN-001** | Carbon budget per model | Maximum CO₂ allocation per training run | OPA policy gate |
| **GRN-002** | Renewable energy minimum | Minimum renewable energy % for AI workloads | Facility attestation |
| **GRN-003** | PUE threshold | Maximum PUE for new AI data centers | Planning permission condition |
| **GRN-004** | Water efficiency standard | Maximum water usage per kWh of AI compute | Facility reporting |
| **GRN-005** | E-waste lifecycle management | Full lifecycle tracking of AI hardware | Asset register |
| **GRN-006** | Carbon offset quality | Standards for carbon offsets claimed against AI emissions | Offset verification |
| **GRN-007** | Efficiency improvement mandate | Year-on-year efficiency improvement targets | Performance reporting |
| **GRN-008** | Sustainability disclosure | Public disclosure of AI energy and carbon metrics | Annual ESG report |

### 8.4 Water Consumption Challenge

AI data centers are significant water consumers, primarily for cooling:

| Cooling Method | Water Usage (L/kWh) | Deployment (2026) | Target (2030) |
|---------------|--------------------|--------------------|---------------|
| Evaporative cooling | 3.0–5.0 | 40% | 15% |
| Hybrid cooling | 1.5–2.5 | 35% | 30% |
| Liquid cooling (direct) | 0.5–1.0 | 20% | 35% |
| Immersion cooling | 0.0–0.2 | 5% | 20% |

---

## 9. Financial Sector AI Energy Governance

### 9.1 G-SIFI AI Energy Profile

| Category | Typical G-SIFI Consumption | Cost ($/year) | Carbon (tCO₂/year) |
|----------|---------------------------|--------------|---------------------|
| Model training (proprietary) | 8–15 GWh | $800K–$1.5M | 2,100–3,900 |
| Model inference (production) | 20–40 GWh | $2M–$4M | 5,200–10,400 |
| Vendor API calls (OpenAI, etc.) | 5–12 GWh (estimated) | $3M–$8M | 1,300–3,120 |
| Data processing & RAG | 10–18 GWh | $1M–$1.8M | 2,600–4,680 |
| Development & testing | 3–8 GWh | $300K–$800K | 780–2,080 |
| **Total per G-SIFI** | **46–93 GWh** | **$7.1M–$16.1M** | **12K–24.2K** |

### 9.2 Financial Sector Sustainability Obligations

| Regulation / Framework | AI Energy Requirement | Status |
|----------------------|----------------------|--------|
| TCFD / ISSB S2 | Disclose AI-related energy and emissions | Mandatory 2026 |
| EU CSRD | Include AI compute in scope 2/3 reporting | Mandatory 2026 |
| PRA Climate SS3/19 | Climate risk from AI energy dependency | Active |
| Basel Green Asset Ratio | AI infrastructure classification | Under development |
| Net Zero Banking Alliance | AI energy in financed emissions pathway | Active |

### 9.3 AI Energy Governance for G-SIFIs

| Governance Measure | Description | Implementation |
|-------------------|-------------|----------------|
| AI energy budget | Annual AI energy allocation per business unit | Board-approved |
| Vendor energy transparency | Require AI vendors to disclose per-query energy | Procurement policy |
| Green AI scoring | Score each AI system on energy efficiency | Model registry attribute |
| Carbon-aware scheduling | Route AI workloads to lower-carbon regions/times | Infrastructure automation |
| Right-sizing governance | Ensure AI model size is proportionate to task | Model Risk Committee review |
| Inference optimization | Mandate inference efficiency targets per model | Performance monitoring |

---

## 10. Compute-Tier Governance & Safety Thresholds

### 10.1 Threshold Framework

| Threshold | FLOP | Power Equivalent | Governance Trigger | Regulatory Action |
|-----------|------|-----------------|-------------------|-------------------|
| **T1 — Reportable** | 10²³ | ~10 GWh/run | Self-reporting to GCR | Documentation |
| **T2 — Significant** | 10²⁴ | ~100 GWh/run | Enhanced safety assessment | Regulator notification |
| **T3 — Frontier** | 10²⁵ | ~1 TWh/run | Full safety dossier + red-team | Regulatory review |
| **T4 — AGI-Threshold** | 10²⁶ | ~10 TWh/run | International notification | Multi-lateral coordination |
| **T5 — Civilization** | 10²⁷ | ~100 TWh/run | ICGC emergency protocol | Treaty governance |

### 10.2 Safety Assessment Requirements by Tier

| Assessment Component | T1 | T2 | T3 | T4 | T5 |
|---------------------|----|----|----|----|-----|
| Model documentation | ✅ | ✅ | ✅ | ✅ | ✅ |
| Risk assessment | — | ✅ | ✅ | ✅ | ✅ |
| Red-team evaluation | — | — | ✅ | ✅ | ✅ |
| Alignment verification | — | — | ✅ | ✅ | ✅ |
| Containment plan | — | — | — | ✅ | ✅ |
| International notification | — | — | — | ✅ | ✅ |
| Kill switch verification | — | — | ✅ | ✅ | ✅ |
| Regulator pre-approval | — | — | — | — | ✅ |
| ICGC coordination | — | — | — | — | ✅ |
| Emergency shutdown readiness | — | — | — | ✅ | ✅ |

---

## 11. Registry API v2.0 Specification

### 11.1 API Overview

```
Global Compute Registry API v2.0
════════════════════════════════

  Base URL: https://registry.icgc.int/api/v2

  Authentication: OAuth 2.0 + mTLS
  Rate Limiting: 1000 req/min (standard), 10000 req/min (premium)
  Format: JSON (default), XML (optional)
  Versioning: URI path versioning
```

### 11.2 Core Endpoints

| Method | Endpoint | Description | Auth Level |
|--------|---------|-------------|------------|
| `POST` | `/facilities` | Register new AI compute facility | Facility Admin |
| `GET` | `/facilities/{id}` | Retrieve facility details | Read Access |
| `PUT` | `/facilities/{id}` | Update facility registration | Facility Admin |
| `GET` | `/facilities` | List/search facilities | Read Access |
| `POST` | `/training-runs` | Register training run | Run Coordinator |
| `GET` | `/training-runs/{id}` | Retrieve training run details | Read Access |
| `PUT` | `/training-runs/{id}/safety` | Submit safety assessment | Safety Reviewer |
| `GET` | `/training-runs/{id}/safety` | Retrieve safety assessment | Read Access |
| `POST` | `/training-runs/{id}/redteam` | Submit red-team report | Red-team Lead |
| `GET` | `/thresholds/current` | Current compute thresholds | Public |
| `GET` | `/sustainability/{facility_id}` | Sustainability metrics | Read Access |
| `POST` | `/alerts` | Report threshold exceedance | System / Admin |
| `GET` | `/alerts/active` | List active alerts | Operations |
| `GET` | `/statistics/global` | Aggregate compute statistics | Public |
| `GET` | `/statistics/energy` | Global AI energy statistics | Public |

### 11.3 Facility Registration Schema

```json
{
  "facility": {
    "id": "GCR-FAC-2026-00142",
    "name": "Nordic AI Compute Center",
    "operator": {
      "name": "Example Corporation",
      "jurisdiction": "SE",
      "lei": "529900EXAMPLE00LEI01"
    },
    "location": {
      "country": "SE",
      "region": "Norrbotten",
      "coordinates": { "lat": 65.58, "lon": 22.15 },
      "gridZone": "SE1"
    },
    "capacity": {
      "totalPowerMW": 250,
      "aiDedicatedMW": 200,
      "peakComputePFLOPS": 1200,
      "gpuCount": 25000,
      "gpuTypes": ["NVIDIA-H100", "NVIDIA-B200"]
    },
    "energy": {
      "primarySources": [
        { "type": "hydroelectric", "percentage": 60 },
        { "type": "wind", "percentage": 30 },
        { "type": "nuclear", "percentage": 10 }
      ],
      "renewablePercentage": 90,
      "pue": 1.08,
      "carbonIntensity_gCO2_kWh": 18,
      "annualEnergy_GWh": 1752
    },
    "cooling": {
      "primaryMethod": "liquid_immersion",
      "waterUsage_L_kWh": 0.15,
      "heatRecovery": true,
      "heatRecoveryMW": 45
    },
    "governance": {
      "computeTier": "T3",
      "registeredDate": "2026-01-15",
      "lastAudit": "2026-03-01",
      "safetyAssessmentStatus": "CURRENT",
      "regulatoryJurisdictions": ["EU", "SE"],
      "complianceFrameworks": ["EU_AI_ACT", "ISO_42001", "CSRD"]
    }
  }
}
```

### 11.4 Training Run Registration Schema

```json
{
  "trainingRun": {
    "id": "GCR-RUN-2026-08923",
    "facility": "GCR-FAC-2026-00142",
    "operator": "Example Corporation",
    "model": {
      "name": "ExampleModel-v5",
      "type": "FOUNDATION_MODEL",
      "architecture": "transformer",
      "parameters": 1.2e12,
      "purpose": "GENERAL_REASONING",
      "intendedDeployment": ["FINANCIAL_SERVICES", "HEALTHCARE"]
    },
    "compute": {
      "totalFLOP": 3.8e25,
      "peakGPUs": 16000,
      "gpuType": "NVIDIA-B200",
      "durationDays": 42,
      "computeTier": "T3"
    },
    "energy": {
      "totalEnergy_GWh": 890,
      "carbonEmissions_tCO2": 16020,
      "renewablePercentage": 90,
      "carbonOffsets_tCO2": 16020,
      "netCarbon_tCO2": 0
    },
    "safety": {
      "preTrainingSafetyReview": "APPROVED",
      "redTeamStatus": "COMPLETED",
      "alignmentAssessment": "PASS",
      "containmentLevel": "STANDARD",
      "killSwitchVerified": true
    },
    "governance": {
      "registeredDate": "2026-02-01",
      "regulatoryNotifications": ["EU_AI_OFFICE"],
      "publicDisclosure": "SUMMARY_ONLY",
      "nextReviewDate": "2026-05-01"
    }
  }
}
```

---

## 12. Legal & Regulatory Frameworks for AI Compute

### 12.1 Current Regulatory Landscape

| Jurisdiction | Compute Governance Measure | Status |
|-------------|--------------------------|--------|
| **EU** | EU AI Act Art. 51-56 (GPAI provisions) | Active (phased) |
| **EU** | CSRD sustainability reporting for AI | Active |
| **US** | EO 14110 §4.2 (reporting of large training runs) | Active |
| **US** | CHIPS Act (semiconductor supply chain) | Active |
| **UK** | AI Safety Institute compute monitoring | Active |
| **China** | Interim Measures for AI (registration requirement) | Active |
| **International** | GPAI (Global Partnership on AI) | Active |
| **International** | OECD AI Principles (compute governance) | Framework only |
| **Proposed** | ICGC treaty (this whitepaper) | Proposed |
| **Proposed** | Global Compute Registry (this whitepaper) | Design phase |

### 12.2 EU AI Act Compute Provisions

| Article | Requirement | Compute Implication |
|---------|-------------|-------------------|
| **Art. 51** | GPAI model obligations | Models trained with >10²⁵ FLOP have systemic risk obligations |
| **Art. 52** | GPAI model transparency | Technical documentation including compute resources used |
| **Art. 53** | GPAI model with systemic risk | Additional safety evaluations, adversarial testing, incident reporting |
| **Art. 55** | Codes of practice | Industry codes for GPAI compute governance |
| **Art. 56** | AI Office oversight | EU AI Office monitoring of GPAI providers |

### 12.3 Legal Harmonization Priorities

| Priority | Area | Target Timeline | Lead Institution |
|----------|------|----------------|-----------------|
| 1 | Common compute measurement standards | 2026 | OECD / ISO |
| 2 | Cross-border training run notification | 2027 | ICGC (proposed) |
| 3 | Mutual recognition of safety assessments | 2027 | EU-US-UK trilateral |
| 4 | International compute registry treaty | 2028 | ICGC (proposed) |
| 5 | AGI-scale compute governance | 2029 | ICGC + UN |

---

## 13. Nuclear & Fusion Energy Pathways for AI

### 13.1 Nuclear Energy for AI Data Centers

| Technology | Power Output | Timeline | Suitability for AI |
|-----------|-------------|----------|-------------------|
| **Existing PWR/BWR** | 1–1.6 GW | Available now | High — baseload, reliable |
| **Small Modular Reactors (SMR)** | 50–300 MW | 2028–2032 | Very High — right-sized for data centers |
| **Advanced Reactors (Gen IV)** | 100 MW–1 GW | 2030–2035 | High — enhanced safety, efficiency |
| **Fusion (tokamak)** | 500 MW–2 GW | 2035–2045 | Transformative — near-unlimited clean energy |
| **Fusion (compact)** | 50–200 MW | 2032–2040 | Very High — co-located with data centers |

### 13.2 Nuclear-AI Data Center Proposals

| Project Type | Configuration | Power | Carbon | Status |
|-------------|--------------|-------|--------|--------|
| **Co-located SMR** | 4× 75 MW SMR + 250 MW data center | 300 MW | Near-zero | Design phase (3 announced) |
| **Existing nuclear site** | Data center on decommissioned plant site | 500 MW–1 GW | Near-zero | 2 operational (US) |
| **Fusion demonstrator** | Compact fusion + research AI cluster | 50 MW | Zero | Concept (2035+) |

### 13.3 Fusion Energy Projections for AI

```
Fusion Energy Timeline for AI Compute
══════════════════════════════════════

  2026: ┤ First fusion ignition demonstrations
        │
  2028: ┤ ITER plasma operations begin
        │
  2030: ┤ First commercial fusion pilot plants announced
        │ AI compute demand: ~200-500 GW
        │
  2032: ┤ Compact fusion prototypes (50-200 MW)
        │ First fusion-powered AI data center (concept)
        │
  2035: ┤ Early commercial fusion (limited scale)
        │ AI compute demand: ~500 GW-1 TW
        │ Fusion contribution to AI: <1%
        │
  2040: ┤ Broader commercial fusion deployment
        │ AI compute demand: ~1-3 TW
        │ Fusion contribution to AI: 5-10%
        │
  2050: ┤ Mature fusion energy sector
        │ Fusion could provide majority of AI energy
        │ Kardashev transition acceleration

  Note: Fusion energy could be the key enabling technology
        for safe transition from Type 0.7 → Type I civilization
```

---

## 14. Risk Analysis & Geopolitical Considerations

### 14.1 AI Compute Geopolitical Risk Matrix

| Risk | Probability | Impact | Current Trend | Mitigation |
|------|-------------|--------|--------------|------------|
| **Compute concentration** (3 US hyperscalers control >60% of AI compute) | High | High | Increasing | International diversification; sovereign compute programs |
| **Semiconductor supply chain** (TSMC dependency) | Medium | Critical | Stable | CHIPS Act; EU Chips Act; diversification |
| **Energy competition** (AI vs. other sectors for grid capacity) | High | High | Increasing | Dedicated AI energy infrastructure; nuclear/fusion |
| **AI compute arms race** (nations competing for advantage) | High | High | Increasing | International coordination; ICGC |
| **Carbon emissions from AI growth** | High | Medium | Increasing | Renewable mandates; efficiency standards |
| **Water stress from data centers** | Medium | Medium | Increasing | Immersion cooling; water-free cooling |
| **Grid stability** (AI load variability) | Medium | High | Emerging | Energy storage; demand response; carbon-aware computing |

### 14.2 Compute Sovereignty Analysis

| Region | AI Compute Capacity (2026 est.) | % Global | Self-Sufficiency | Key Risk |
|--------|-------------------------------|----------|-----------------|----------|
| **United States** | ~45 GW | ~60% | High (chips + energy) | Concentration risk |
| **China** | ~15 GW | ~20% | Medium (chips constrained) | Export controls |
| **European Union** | ~6 GW | ~8% | Low (cloud dependency) | Sovereignty |
| **United Kingdom** | ~2 GW | ~3% | Low | Scale limitation |
| **Rest of APAC** | ~5 GW | ~7% | Varied | Fragmented |
| **Rest of World** | ~2 GW | ~2% | Low | Infrastructure gap |

### 14.3 Scenario Planning

| Scenario | Probability | AI Energy Impact | Governance Response |
|----------|-------------|-----------------|-------------------|
| **Cooperative global governance** | 30% | Managed growth (2.5% by 2030) | ICGC established; balanced development |
| **Fragmented national approaches** | 45% | Inefficient growth (3.5% by 2030) | Duplicated infrastructure; carbon leakage |
| **AI compute arms race** | 20% | Rapid growth (5%+ by 2030) | Energy security crisis; geopolitical tension |
| **AI winter / slowdown** | 5% | Stabilized (1.5% by 2030) | Excess infrastructure; stranded assets |

---

## 15. Investment & Infrastructure Roadmap

### 15.1 Global AI Energy Infrastructure Investment Needs

| Category | 2026–2028 | 2029–2031 | 2032–2035 | Total |
|----------|-----------|-----------|-----------|-------|
| **Renewable energy for AI** | $80B | $120B | $180B | $380B |
| **Nuclear (SMR) for AI** | $20B | $60B | $100B | $180B |
| **Data center infrastructure** | $150B | $200B | $250B | $600B |
| **Grid upgrades** | $40B | $60B | $80B | $180B |
| **Cooling technology** | $10B | $15B | $20B | $45B |
| **Energy storage** | $30B | $50B | $80B | $160B |
| **Fusion R&D** | $15B | $25B | $40B | $80B |
| **GCR & ICGC operations** | $0.5B | $0.8B | $1.2B | $2.5B |
| **Total** | **$345.5B** | **$530.8B** | **$751.2B** | **$1,627.5B** |

### 15.2 G-SIFI AI Energy Investment

| Investment Area | Year 1 | Year 2 | Year 3 | Total |
|----------------|--------|--------|--------|-------|
| Energy efficiency optimization | $2M | $1.5M | $1M | $4.5M |
| Renewable energy procurement | $5M | $4M | $3M | $12M |
| Carbon-aware computing infrastructure | $3M | $2M | $1M | $6M |
| Sustainability reporting systems | $1M | $0.5M | $0.3M | $1.8M |
| GCR compliance & registration | $0.5M | $0.3M | $0.2M | $1M |
| Green AI governance controls | $1M | $0.8M | $0.5M | $2.3M |
| **Total per G-SIFI** | **$12.5M** | **$9.1M** | **$6.0M** | **$27.6M** |

---

## 16. Policy Recommendations

### 16.1 For Global Policymakers

| # | Recommendation | Priority | Timeline |
|---|---------------|----------|----------|
| 1 | **Establish International Compute Governance Consortium (ICGC)** with treaty authority | Critical | 2027 |
| 2 | **Deploy Global Compute Registry (GCR)** with mandatory reporting above Tier 2 | Critical | 2027 |
| 3 | **Set compute-tier safety thresholds** with graduated governance requirements | High | 2026 |
| 4 | **Mandate AI energy and carbon disclosure** for all large AI operators | High | 2026 |
| 5 | **Fund nuclear (SMR) and fusion** R&D specifically for AI energy needs | High | 2026–2030 |
| 6 | **Establish international emergency protocol** for AGI-scale compute events | Medium | 2028 |
| 7 | **Create regulatory sandbox** for testing compute governance frameworks | Medium | 2027 |
| 8 | **Align AI compute governance with climate commitments** (Paris Agreement) | High | 2026 |

### 16.2 For G-SIFIs

| # | Recommendation | Priority | Timeline |
|---|---------------|----------|----------|
| 1 | **Implement AI energy governance** with per-model energy budgets | High | Q3 2026 |
| 2 | **Require vendor energy transparency** in AI procurement | High | Q2 2026 |
| 3 | **Set renewable energy targets** for AI workloads (≥70% by 2028) | High | 2026–2028 |
| 4 | **Deploy carbon-aware computing** to optimize AI workload placement | Medium | Q4 2026 |
| 5 | **Include AI energy in TCFD/ISSB disclosure** | High | 2026 (annual report) |
| 6 | **Participate in ICGC** as founding financial-sector member | Medium | 2027 |
| 7 | **Right-size AI models** — ensure model complexity is proportionate to task | High | Ongoing |
| 8 | **Invest in inference efficiency** — optimize deployed models for energy efficiency | High | Ongoing |

### 16.3 For AI Companies

| # | Recommendation | Priority | Timeline |
|---|---------------|----------|----------|
| 1 | **Register all Tier 2+ training runs** with relevant compute registries | High | 2026 |
| 2 | **Publish per-query energy metrics** for API-served models | High | 2026 |
| 3 | **Commit to 100% renewable energy** for AI compute by 2030 | High | 2026–2030 |
| 4 | **Invest in inference efficiency** to reduce per-query energy | Critical | Ongoing |
| 5 | **Support ICGC establishment** and participate in governance frameworks | Medium | 2027 |
| 6 | **Conduct and publish carbon lifecycle assessments** for frontier models | High | 2026 |

---

**Classification:** CONFIDENTIAL
**Document Reference:** ENERGY-COMPUTE-WP-004 v1.0.0
**Next Review Date:** 2026-06-22

> *"The energy that powers AI will define the trajectory of civilization. Governing this energy wisely — sustainably, equitably, and safely — is among the most consequential decisions of our time."*
