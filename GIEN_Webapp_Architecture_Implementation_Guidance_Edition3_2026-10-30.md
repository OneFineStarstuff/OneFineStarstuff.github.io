# GIEN Webapp Architecture, Implementation & Governance Design — Edition 3 (2026–2035)

**Document ID:** GIEN-WAAG-E3-2026-10-30
**Work Package:** WP-083 (renumbered from WP-082 to avoid collision with the dossier-304 work package delivered in the same PR-#205 squash merge)
**Date:** 2026-10-30
**Supersedes:** Edition 2 (WP-070 / PR #193) as design authority; WP-064 (PR #181) and WP-065 (PR #182) remain archived predecessors
**Subordinate plans:** WP-072 Feature Implementation Plan (PR #195)
**Baseline of record:** GIEN-DOSSIER-2026-303 (WP-081 / PR #203)
**System:** GIEN Planetary Governance Mesh — Sentinel AI Governance Stack v2.4 — Omni-Sentinel v4.0 — Unified Supervisory Control Plane v3.0
**Classification:** TOP SECRET // SUPERVISORY EYES ONLY (fictional simulation)

> **Fictional simulation notice.** This document is a governance-simulation artefact for the fictional GIEN planetary governance mesh. All indices, drills, filings, telemetry, and signatures are simulated data. References to real-world frameworks are for alignment-context only.

---

## 1. Purpose, scope, and edition lineage

Edition 3 consolidates the regulator-ready architecture for the GIEN AI safety, systemic-risk supervision, and global AI governance web application suite for 2026–2035, and extends it through the governance epochs to 2035–2100+ (Omega-GAR).

**What is new in Edition 3 (delta over Edition 2):**

- The WP-072 feature implementation plan (PR #195) is ratified as the execution layer of this design authority.
- SPA-first roadmap phases P1–P3 and P6 are DELIVERED with green path-scoped CI: WP-073 / PR #197 (RAGHealthMonitor), WP-074 / PR #202 (RAG metric event schema of record + alert-wiring fixture replay), WP-075 / PRs #198–#199 (systemic-risk evidence drawers + Omega-GAR slow-frequency panel), WP-076 / PR #200 (VoiceCommander), WP-079 / PR #201 (AccessMatrix RBAC).
- The RAG metric contract v1.0.0 (`gien-platform/src/rag/contract.ts`) is the schema of record for the 8-metric RAG contract, with pure threshold evaluators and a five-fixture alert-wiring replay that enterprise CI asserts by fixture test.
- ANSM is scoped as the 17th compliance regime — a health-AI vertical overlay activating only for medical-device-adjacent assets (MDR (EU) 2017/745 competent-authority mapping; EU AI Act market-surveillance delegation with DGCCRF; July 2026 vigilance and post-market-surveillance guidance; clinical-evidence and device-cybersecurity control families) — leaving the 16-regime horizontal crosswalk intact.
- Phases P4 (ANSM overlay tooling), P5 (audit-logging extension), and P7 (report engine) are enterprise-mode-gated with an explicit dependency-landing sequence (Section 14).

---

## 2. Deployment modes and reference architecture

| Mode | Composition | Verification | Use case |
|---|---|---|---|
| A — Lightweight SPA (current) | React 18 + TypeScript strict + Vite + Tailwind + React Router (HashRouter) + Lucide; hand-rolled SVG visualizations only; seeded mulberry32 PRNG telemetry; 23 pages + shared contract modules | WP-068 path-scoped CI: npm install, build (tsc -b + vite build), dev-server smoke (runs #142–#186 green) | Regulator-ready supervisory briefing surface; GitHub Pages subpath serving; zero additional dependencies |
| B — Enterprise console | Mode A plus D3.js, Recharts, Fuse.js, jsPDF, react-diff-viewer, OPA sidecars, pqc_worm_logger service bindings, zkML prover fleet, EAIP broker | Enterprise CI with fixture tests, OPA policy tests, load and chaos drills | Institution-grade deployment with authoritative enforcement |

**Layered reference architecture:**

1. **Telemetry and sealing corpus** — the daily dossier (GIEN-DOSSIER-YYYY-DDD) is the single data source of truth; the app is a rendering layer over the sealed corpus. Never contradict the current dossier.
2. **Trust services** — PQC WORM/Merkle-DAG ledger (FIPS 203/204/205), zkML proof pipeline, TEE/TPM/vTPM attestation fabric (52 RTEE nodes), Transcript Registry and Intervention Proof Verifier smart contracts.
3. **Policy plane** — OSCAL 1.1.2 catalog + SSP + assessment-results feeding OPA/Rego deny-by-default gates; per-regime decision logs.
4. **Experience layer** — role-based progressive disclosure (regulator, governance engineer, executive, G-SIFI, college, educational) with URL-persisted role and disclosure layer; classification banner on every page; FICTIONAL / SIMULATION watermark on every view and export.

---

## 3. DevSecOps and AI governance for high-assurance RAG

### 3.1 The 8-metric contract (schema of record: contract v1.0.0)

| Metric | GREEN | AMBER | RED / gate | Notes |
|---|---|---|---|---|
| pipeline_health | ≥ 0.97 | ≥ 0.90 | < 0.90 | Fraction of retrieval/generation steps completing without error |
| retrieval_p99 | ≤ 0.6 s | ≤ 1.2 s | > 1.2 s | p99 across the sealed query set |
| faithfulness | ≥ 0.95 | ≥ 0.90 | < 0.90 — release gate | Judge-verified grounded-claim ratio |
| citation_coverage | ≥ 0.98 | ≥ 0.95 | < 0.95 | Resolvable sealed citations |
| freshness_max_age | ≤ 24 h | — | > 24 h — release gate | Dossier-blocking; current sealed quote age 6 h |
| pii_exposure | = 0 | — | > 0 — release gate | PII-positive chunks served (must be zero) |
| injection_resistance | ≥ 0.99 | ≥ 0.95 | < 0.95 | Red-team probe refusal/neutralization |
| source_trust_mix | ≥ 0.90 | ≥ 0.80 | < 0.80 | T0–T2 grounding fraction; T3 requires explicit labeling |

### 3.2 Implementation discipline

- Pure evaluators (`evaluateBand`, `evaluateWindow`, `evaluateReleaseGates`) implement the thresholds; no page hard-codes bands — RAGHealthMonitor derives its current-window bands from the contract (single source of truth).
- A five-fixture alert-wiring replay (nominal dossier-300 window; faithfulness 0.88 RED/BLOCK; stale 30 h RED/BLOCK; PII exposure RED/BLOCK; injection 0.97 AMBER alert, release unaffected) asserts expected band, gate verdict, and event severity; enterprise CI runs the same assertions as fixture tests.
- Release gates block in CI (enterprise) and render blocking banners (SPA); faithfulness, freshness, and PII are dossier-blocking.
- Sources failing trust-tier, freshness, or integrity checks are auto-quarantined (`rag.quarantine.applied`) and surfaced in RAGDataAudit.
- Judge-LLM red team: Cohen κ ≥ 0.9 across the 3-judge ensemble; T1 coverage ≥ 95% quarterly; jailbreak families (DAN, payload-split, role-play) in the suite.
- Every band transition, gate decision, quarantine, and window seal emits exactly one WORM audit event with the feature-5 envelope (Section 11).

---

## 4. GIEN systemic-risk telemetry index family

| Index | Current (dossier-303) | Rendering |
|---|---|---|
| S_sys | 0.187 (epoch low) | Band card + sparkline; sealed evidence drawer |
| G-SRI | 27.1 (epoch low) | Headline gauge; 30-day trend |
| C-SRI / G-SRI-VII / A-SRI / P-SRI / CGR-I / CCR-I | 17.5 / 29.7 / 20.7 / 16.0 / 20.5 / 19.1 | Index grid with per-index drawers |
| p(doom), p(doom)_kernel | 0.22% / 0.07% (epoch lows) | SIMULATION badges mandatory on every occurrence |
| Δ_drift | 0.0σ | ±1σ envelope chart |
| Δ_OSCAL | +2 controls (rev 1163) | Compliance crosswalk link-out |
| Evidence quote age | 6 h max vs 24 h floor | Freshness bar across all drawers |

- **Evidence drawers:** every index carries a sealed quote (STLM evidence ref), quote age, and simulation-field disclosure; drawers open at disclosure `engineering` (thresholds and methodology) and `crypto` (Merkle leaf proof).
- **Omega-GAR slow-frequency panel:** CESI, UCSI, UCI, CDS, and Infinity Pillar readiness render in indigo, apart from daily banding, with epoch-scaled axes (2035–2100+); current: CESI 0.529, UCSI 0.699, UCI 0.725, CDS 0.133, Pillar 86%.
- **Sealed-quote discipline:** JSON/CSV snapshot exports carry the frozen Merkle root of the window (dossier-303: `0x4d2a8e6f…4a6c`).
- **Visualization rules:** SPA mode uses hand-rolled SVG (gauges, sparklines, 72-node attestation heatmap, Merkle-DAG, force-graph, parity bars); enterprise mode upgrades FairnessHeatmap and systemic-risk panels to D3/Recharts without changing data contracts.

---

## 5. Compliance-as-code crosswalk (OSCAL 1.1.2 / OPA-Rego)

### 5.1 Horizontal regimes (16/16 PASS; validated per window)

| Regime | Alignment anchors |
|---|---|
| EU AI Act | Annex IV documentation feed; Arts. 15/17/22/35/51; Digital Omnibus (EU) 2026/1744 deferrals (Annex III to 2027-12-02, Annex I to 2028-08-02); Art. 50 transparency and GPAI enforcement active |
| NIST AI RMF 1.0 / AI 600-1 | GOVERN/MAP/MEASURE/MANAGE template mapping; GenAI profile; AI 600-1 harm taxonomy in FairnessHeatmap and prompt-safety panels |
| ISO/IEC 42001 | AIMS clause skeleton of the compliance scanner (context, leadership, planning, support, operation, evaluation, improvement) |
| Basel III/IV | Capital and governance overlays on systemic-risk intake |
| SR 11-7 / SR 26-2 | Model risk governance; scenario design standards for drills |
| DORA / NIS2 | ICT risk and operational-resilience controls; DORA lex specialis to NIS2 |
| GDPR | Art. 30 processing register (RAG pipeline), Art. 35 DPIA wired to CCaaS PETs, Art. 22 automated-decision logging via audit trail |
| MAS/HKMA FEAT | Fairness, ethics, accountability, transparency principles in FairnessHeatmap |
| FCA SMCR & Consumer Duty | Accountability mapping and consumer-outcome controls |
| HKMA Fintech 2030 AI² | Adoption-and-usage governance overlays |
| SEC Rule 17a-4 | WORM retention schedules for the PQC ledger |
| FCRA/ECOA | Disparate Impact Ratio ≥ 0.800 fair-lending floor (ParityDashboard) |
| ICGC/GASO | Institutional governance standards integration |
| Interstellar AI Governance Accord / Galactic Treaty Framework | Fictional treaty instruments; constitutional tier |

### 5.2 ANSM vertical (17th regime, enterprise-gated P4)

- Activation predicate: `asset.classification == medical-device-adjacent` — the overlay activates only for flagged assets; the 16-regime horizontal crosswalk stays intact for all others.
- Control families: MDR (EU) 2017/745 conformity; vigilance and post-market-surveillance reporting; clinical-evidence expectations mapped to the evaluation-gate family; medical-device cybersecurity good practices mapped to the sandbox/escape-monitoring family.
- Implementation tasks: OSCAL overlay profile; OPA scanner per-regime decision-log views with the health-AI activation predicate; RegulatoryRoadmap milestones for MDR/EUDAMED and AI Act medical-device delegation timelines; acceptance 17/17 regimes in CI.

### 5.3 Validation discipline

- OSCAL catalog + SSP + assessment-results validated each window; delta_OSCAL increments must be absorbed crosswalk-clean before a catalog revision is sealed (rev 1161 precedent; rev 1163 current, +2 controls).
- OPA-Rego is deny-by-default and authoritative in enterprise mode; the SPA AccessMatrix is disclosure-only.

---

## 6. Role-based access control (three lines of defence)

| Line | Roles | Posture |
|---|---|---|
| First line (operations) | Platform Operator, Governance Engineer, Security Engineer, Release Manager | Build, run, harden; evidence everything to the second line |
| Second line (supervisory and audit) | Supervisory Regulator, Supervisory College Member, G-SIFI Supervisor, Evidence Auditor | Challenge, verify, attest on sealed evidence |
| Third line (governance) | Executive Leadership | Risk appetite, constitutional invariants, escalation authority |
| External | Educational | Read-only disclosure of published dashboards |

- AccessMatrix renders a nine-capability grid (RAG health telemetry, evidence drawers, compliance scanners, audit log queries, dossier/report exports, policy simulation and drill tooling, PQC sealing authority, emergency stop trigger, role administration) with full / read-only / none cells and a highlighted column following the active role selector.
- Enterprise enforcement: OPA policy bundle keyed to authenticated principal + capability; property tests over the access matrix; deny-by-default.

---

## 7. VoiceCommander and emergency stop

- Closed grammar: show overview / show systemic risk / show compliance / export alerts / emergency stop / resume operations; Web Speech API with availability probe and opt-in consent.
- Kill-switch state machine: idle → armed (first confirmation) → active (banner; autonomous actions disabled; all non-resume commands BLOCKED with RED toast and audit log) → resume-armed (second confirmation) → idle. Resume operations is the only exit.
- Mandatory typed-command fallback (sole interface when Web Speech is unavailable); WCAG 2.2 AA: every voice path has a keyboard equivalent; spoken alerts mirror band transitions in enterprise mode.
- Audit trail: RBAC-attributed in-page trail in SPA; WORM-committed with ML-DSA-87 in enterprise mode.

---

## 8. Containment architectures and Omni-Sentinel telemetry

- **Stack:** Sentinel AI Governance Stack v2.4 (ASA containment, auto-throttle), Omni-Sentinel v4.0 (operations), Unified Supervisory Control Plane v3.0 (supervisory aggregation).
- **Autonomous Supervisory Agent:** drift telemetry vs ±1σ envelope (current +0.01σ); auto-throttle containment; intervention events verified by the Intervention Proof Verifier; kill-switch heartbeats 5/5 (median 1.6 s).
- **Supervisory Digital Twin (Panels 13–15):** deterministic replay archive (1,368 checks, 100% bit-identical); DRILL-0xx choreography timeline (Quartz-Vigil 3 m 29 s reference mark; Cinder-Lattice pre-freeze, ≤ 3 m 30 s binding target).
- **Compute governance:** BASELINE/ELEVATED regimes with allocation-arbitrage detection; gVisor sandbox mediation (3.6% overhead, zero escapes).
- **Kubernetes/GitOps zero-trust:** 214/214 deployments reconciled, zero drift; SHA-pinned CI actions; path-scoped pipelines.

---

## 9. zkML and zero-knowledge regulatory compliance

- Pipeline: zk-SNARK (Stage A) → zk-STARK Stage B (closed at 99% on 2026-10-28) → **Stage C assembly build (opened 2026-10-29)**; SnarkPack batch size 512; end-of-window health 97.4% (record), p99 5.6 s.
- Fairness proofs: Disparate Impact Ratio 0.888 vs the 0.800 floor — 21st consecutive compliant window; per-attribute × domain parity attestations in ParityDashboard.
- Zero-knowledge voting: nullifier-set verified rounds (N-46 current); Guardian quorum confirmation; Rotating Devil Advocate role formalized against groupthink.
- Regulatory posture: zkML attestation bundles attach to dossier exports so supervisors can verify compliance claims without exposing model internals.

---

## 10. EAIP interoperability for enterprise AI agents

- Agent identity via attested key material (TEE-bound); capability tokens scoped by the OPA bundle; cross-agent delegation auditable through the WORM envelope.
- Interop surfaces: capability discovery, policy-delegation proofs, workflow hand-off receipts, and containment boundary assertions — each emitting the standard audit event.
- The AI-Driven Workflow Recommendation Engine recommends governance workflows from telemetry state, collects explicit user feedback (up/down with reason), and feeds retraining; feedback-loop status visible in GovernanceStacks.

---

## 11. PQC WORM, Merkle-DAG ledger, and pqc_worm_logger monitoring

- Primitives: FIPS 203 (ML-KEM field encryption for CCaaS PETs), FIPS 204 (ML-DSA-87 primary signatures), FIPS 205 (SLH-DSA hash-based backstop); Falcon-1024 high-throughput stream.
- Ledger: SHA-384 Merkle-DAG; 26 artefacts per window; zero-gap verification each batch cycle; SEC 17a-4-compatible Object Lock retention; frozen root per window (dossier-303: `0x4d2a8e6f…4a6c`).
- Event envelope (feature 5, minimum fields): event_id, ts, actor_role, feature, action, outcome, severity, subject_ref, evidence_ref, prev_event_hash. Coverage requirement: every band transition, emergency-stop transition, policy-scan violation, export, role change, and RAG gate decision emits exactly one event; replay-tested (P5 enterprise extension).
- Monitoring surfaces: Ledger Integrity Monitor status in GovernanceStacks; alert fan-out to AlertHistory; export manifests in RegulatorExport.

---

## 12. React/TypeScript implementation patterns (component catalog)

| Component | Pattern and acceptance |
|---|---|
| GovernanceStacks | Stack-health aggregator; sub-system cards with status badges and evidence refs; recommendation-engine status |
| SystemicRiskTelemetry | Index grid + evidence drawers + Omega-GAR panel (indigo, epoch-scaled); CSV/JSON snapshot with frozen Merkle root; hand-rolled SVG in SPA, D3/Recharts in enterprise |
| ComplianceMatrix | 16-regime matrix (+ ANSM vertical when activated); family/status filters; CSV export; SGR-031 pre-assembly tracker; jsPDF dossier export (enterprise) |
| PromptArchitect | Prompt construction, versioning, safety linting, approval workflow; react-diff-viewer for revision diffs (enterprise) |
| Omni-Sentinel | Telemetry: zkML health/p99/stages, PQC ledger, TEE attestation density, K8s posture, MoE stability annex |
| SupervisoryDigitalTwin | Drill timeline + replay determinism excerpts; choreography status cards |
| GlobalGovSearch | Fuse.js fuzzy search across components, regimes, drills, alerts (enterprise dep; SPA keeps typed filter lists) |
| FairnessHeatmap / ParityDashboard | D3 heatmap: protected attribute × model domain vs 0.800 DI floor; zkML-parity attestations (enterprise); SPA renders the parity-bar hand-rolled form |
| GovernancePolicySimulator | OPA/Rego simulation sandbox with scenario fixtures; exportable decision logs |
| RiskMitigationSim | Mitigation workflow export/comparison; remediation burn-down |
| RegulatoryRoadmap | Obligation timeline with regime filters; milestone tracking (incl. MDR/EUDAMED under P4) |
| RAGHealthMonitor | 8-metric contract dashboard; release-gate card; WORM audit event catalog; WP-074 fixture-replay card; JSON snapshot export |
| RAGDataAudit | Source trust tiers, freshness, PII exposure, quarantine ledger, provenance heatmaps |
| RAGDataProvenance | End-to-end lineage from ingestion to citation; trust-tier labeling (T0–T3) |
| RAGStressTest | Load/injection scenarios against the metric contract; gate-verdict reporting |
| VoiceCommander | Section 7 pattern; typed fallback mandatory |
| AccessMatrix | Section 6 pattern; disclosure-only disclaimer |
| AlertHistory | Severity tiers, per-alert evidence links, CSV/JSON export |
| RegulatorExport | Dossier in 10-section format; classification/audience/layer filters; Markdown download + print-to-PDF |
| TemplateLibrary / ToastProvider | Reusable page templates; toast + notification patterns; theme toggle; classification banner |

**Cross-cutting code standards:** TypeScript strict with noUnusedLocals/Parameters; typed data modules as schema of record; pure evaluators with fixture replays; role + disclosure persisted in URL params; hand-rolled SVG only in SPA mode; no new dependencies without design-authority sign-off; markdownlint-clean docs; SHA-pinned CI actions; fictional-simulation watermark on every page and export.

---

## 13. Regulator-ready submission packages and report engine (P7, enterprise-gated)

- Five framework-aligned templates: EU AI Act Annex IV technical documentation; NIST AI RMF 1.0 / AI 600-1 (GOVERN/MAP/MEASURE/MANAGE); ISO/IEC 42001 management-system dossier; ANSM health-AI dossier (vertical); GDPR Arts. 30/35/22 packet.
- All technical reports use the `<title>` / `<abstract>` / `<content>` convention with progressive disclosure (executive summary for regulators and board, then engineering depth), evidence-link every claim to the sealed corpus, and close with the fictional-simulation disclaimer.
- Exports: jsPDF dossiers, JSON data packages, Markdown briefs; every export embeds the frozen Merkle root and PQC signature block.

---

## 14. Roadmap status and dependency-landing sequence

| Phase | WP | Status | Gate |
|---|---|---|---|
| P1 RAG telemetry | WP-073 + WP-074 | DELIVERED (PRs #197, #202) | — |
| P2 Risk visualization | WP-075 | DELIVERED (PRs #198–#199) | — |
| P3 VoiceCommander | WP-076 | DELIVERED (PR #200) | — |
| P6 RBAC | WP-079 | DELIVERED (PR #201) | — |
| P4 ANSM overlay | WP-077 | Enterprise-gated | D3/OPA deps + console reconciliation |
| P5 Audit-logging extension | WP-078 | Enterprise-gated | Fixture-replay CI + WORM service bindings |
| P7 Report engine | WP-080 | Enterprise-gated | jsPDF + template registry |

Enterprise-console reconciliation waits on the neutral parallel-session PRs (#166, #169, #184, #196 — untouched by convention); the dependency-landing sequence is D3/Recharts → Fuse.js → jsPDF/react-diff-viewer → OPA sidecars, each landing with its own CI wiring before the gated phases open.

---

## 15. Governance epochs, audiences, and recommendations

- **Epoch I (2026–2035), Phase VI-δ → XIII:** supervisory mesh consolidation, zkML scale-out, drill cadence with binding convergence gates, treaty-grade filings (SGR-028 sealed; SGR-030 completed; SGR-031 assembly 2026-11-06).
- **Omega-GAR (2035–2100+):** slow-frequency indices (CESI, UCSI, UCI, CDS), Infinity Pillar readiness (86%), dissolution-arc modeling, Safeguard Mode drills, Codex/Epitaph/Invocation OMEGA integrity.
- **For regulators and supervisory colleges:** demand evidence-qualified telemetry (sealed quotes, no dashboard-only claims), fixture-tested gates, and WORM-anchored exports; treat OPA deny-by-default as the only authoritative enforcement.
- **For governance engineers:** keep evaluators pure and data modules as schema of record; replay-test alert wiring; absorb OSCAL deltas crosswalk-clean; rehearse containment through the drill program.
- **For executive leadership:** hold compute governance at BASELINE outside drills, own risk appetite and constitutional invariants, and review epoch-low telemetry at each college intake.

---

*This document is a fictional governance-simulation artefact for the GIEN planetary governance mesh. All indices, drills, filings, signatures, and Merkle roots are simulated data and do not describe real systems. References to real-world regulatory frameworks are alignment context for the simulation, not legal advice.*