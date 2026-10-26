# GIEN GOVERNANCE WEBAPP — IMPLEMENTATION PLAN, TECHNICAL ARCHITECTURE & BEST PRACTICES (2026–2035)

---

**Document ID:** GIEN-GOVAPP-PLAN-2026-001
**Work Package:** WP-064
**Date:** 2026-10-25
**Scope:** Enterprise-scale AI safety, governance dashboards, and systemic-risk management tooling for AGI/ASI containment in the GIEN governance mesh (Epoch I, 2026–2035)
**Stack:** React 18 + TypeScript + Vite + Tailwind CSS + React Router + Lucide React + Recharts + D3.js + Fuse.js + jsPDF + Web Speech API + react-diff-viewer + OPA/Rego + zkML verifiers
**Classification:** TOP SECRET // SUPERVISORY EYES ONLY
**Baseline of Record:** GIEN-DOSSIER-2026-298 (2026-10-25) — Merkle root `0x8c3f5b9e2a7d4c1f8b3e6a9d2c5f7b1e4a8d3c6f9b2e5a7d1c4f8b3e6a9d2c5f`

> **Fictional simulation notice.** This plan is a governance-simulation artefact produced for the fictional GIEN planetary governance mesh. All indices, drills, regimes, signatures, and Merkle roots are simulated data.

---

## SECTION 1 — PURPOSE, AUDIENCE, AND SCOPE

This plan extends the GIEN Governance Webapp Implementation Blueprint (2026–2035) and the AI Agent Interoperability Protocol artefacts already on main, and governs the regulator-ready supervisory web application for the GIEN mesh and Omni-Sentinel stack. The application is a rendering layer over the daily dossier corpus: the latest `GIEN-DOSSIER-YYYY-DDD` baselines are the single source of truth, and no panel may contradict the current dossier.

Audiences follow the established progressive-disclosure model:

- **Tier 1 (regulators and supervisory colleges)** — headline posture, compliance status, submission packages, evidence links.
- **Tier 2 (governance engineers and G-SIFI/LFI institution teams)** — telemetry, cryptographic and ledger detail, drill records, RAG governance.
- **Tier 3 (executive leadership)** — one-page posture, trend summaries, Ω-GAR long-horizon readiness.

In-scope modules: GlobalGovSearch, systemic-risk telemetry and FairnessHeatmap visualizations, GovernancePolicySimulator, RiskMitigationSim, RAGHealthMonitor / RAGDataAudit / RAGStressTest, ComplianceMatrix with OSCAL 1.1.2 validation, Omni-Sentinel and `pqc_worm_logger` WORM audit monitoring, zkML zero-knowledge compliance, EAIP agent interoperability, VoiceCommander with accessibility layers, jsPDF reporting and exports, and the cross-cutting reliability patterns that make the tooling regulator-ready.

---

## SECTION 2 — ARCHITECTURE PRINCIPLES AND REFERENCE ARCHITECTURE

Five binding principles:

1. **Dossier-first data.** All displayed values derive from `src/contracts/baselines.ts`, regenerated from the latest dossier; CI (the governance-artifacts validator) fails the build if the baseline module drifts from the current dossier file on main.
2. **Typed contracts end to end.** No `any` types; every panel consumes typed interfaces defined once in `src/contracts`.
3. **Evidence-linked UI.** Every KPI, alert, and compliance cell deep-links to its evidence artefact (dossier section, Merkle-anchored artefact ID, replay bundle, or OSCAL control); unlinked numbers are forbidden.
4. **Zero-trust and PQC by default.** mTLS between services, PQC-signed seals wherever artefacts are sealed (ML-DSA-87 primary, Falcon-1024 high-throughput, SLH-DSA hash-based backstop, FIPS 203/204/205 conformance).
5. **Accessibility and regulator-readiness first.** WCAG 2.2 AA, classification banner on every page, fictional-simulation disclaimer in every footer, and exports that carry disclaimers and citations.

Reference architecture layers:

| Layer | Contents | Notes |
|---|---|---|
| Presentation | React 18 + TypeScript, Vite, Tailwind, React Router, Lucide React | Theme toggle, ToastProvider, progressive disclosure, role selector |
| Application state | GovernanceContext (role, phase, evaluation window, alert state), module stores | Server-derived state stays normalized; no duplicated truth |
| Domain modules | One folder per module under `src/modules/*`, each self-contained with its own data hooks | See Sections 4–13 |
| Data services | RAG governance corpus service (retrieval over dossiers, filings, artefacts), evidence store client | RAG backend with provenance metadata; see Section 8 |
| Evidence and compliance plane | OSCAL 1.1.2 artifacts, OPA/Rego policy bundles, WORM/Merkle-DAG ledger tie-outs, zk verifiers | Validation status surfaced in UI; see Sections 9–11 |

---

## SECTION 3 — TYPED DATA CONTRACTS AND THE BASELINE MODULE

Core contracts (single definition site in `src/contracts`):

```ts
export type RiskIndexId =
  | "S_sys" | "G-SRI" | "C-SRI" | "G-SRI-VII" | "A-SRI" | "P-SRI"
  | "CGR-I" | "CCR-I" | "p(doom)" | "p(doom)_kernel" | "drift" | "oscal_delta";

export interface IndexReading {
  readonly id: RiskIndexId;
  readonly value: number;
  readonly delta24h: number;
  readonly band: "GREEN" | "AMBER" | "RED";
  readonly evidenceRef: string; // dossier section or artefact ID
}

export interface BaselineSnapshot {
  readonly dossierId: string;       // e.g. "GIEN-DOSSIER-2026-298"
  readonly evaluationWindow: { from: string; to: string };
  readonly merkleRoot: string;      // 0x + 64 lowercase hex, consistent across occurrences
  readonly indices: readonly IndexReading[];
  readonly seals: Readonly<{ mlDsa87: string; falcon1024: string; slhDsa: string }>;
}
```

Baseline table for the current window (dossier 298, sealed — the app renders these exact values):

| Index | Value | Band | Notes |
|---|---|---|---|
| S_sys | 0.186 | 🟢 GREEN | Epoch low |
| G-SRI | 27.3 | 🟢 GREEN | New epoch low; 14th consecutive improving window |
| C-SRI | 17.7 | 🟢 GREEN | Compliance-side risk |
| G-SRI-VII | 30.0 | 🟢 GREEN | Phase VII galactic readiness band |
| A-SRI | 20.9 | 🟢 GREEN | Alignment-side risk |
| P-SRI | 16.2 | 🟢 GREEN | Propagation risk |
| CGR-I | 20.8 | 🟢 GREEN | Constitutional-grade readiness |
| CCR-I | 19.3 | 🟢 GREEN | Cryptographic governance readiness |
| p(doom) | 0.23% | 🟢 GREEN | Epoch low held |
| p(doom)_kernel | 0.08% | 🟢 GREEN | Kernel density estimate |
| Δ_drift | 0.0σ | 🟢 GREEN | Fifth consecutive centered window |

Hash-like artefacts follow the audited fixed format: `0x`-prefixed, 64 lowercase hex characters, Merkle root identical across every occurrence (header, Section 9 certificate, and ledger tie-out panel must match `0x8c3f5b9e2a7d4c1f8b3e6a9d2c5f7b1e4a8d3c6f9b2e5a7d1c4f8b3e6a9d2c5f`).

---

## SECTION 4 — GLOBALGOVSEARCH (FUSE.JS)

Federated fuzzy search across components, the 20 compliance regimes, drills (DRILL-0xx), alerts, artefacts, and dossiers:

- **Index build.** A single `SearchDocument` type with entity kind, title, aliases, tags, trust tier, and evidence reference; the index is built once from the baseline snapshot and module registries, then incrementally patched when alerts arrive.
- **Fuse configuration.** `threshold: 0.3`, `ignoreLocation: true`, keys weighted `title > aliases > tags > body`; `useExtendedSearch` for explicit filters (for example `'kind:drill quartz'`).
- **Ranking.** Fuse score blended with source-trust tier (T1 regulator filings outrank unvetted corpus entries) and recency of the evaluation window.
- **Keyboard and accessibility.** ARIA combobox pattern, full keyboard navigation, highlighted match snippets, and a screen-reader-friendly flat result list.
- **Deep links.** Every result routes to the entity page with the evidence drawer pre-opened; recent searches persist per role.

---

## SECTION 5 — FAIRNESSHEATMAP AND SYSTEMIC-RISK VISUALIZATIONS (D3.JS + RECHARTS)

Two visualization tiers with strict separation of concerns:

- **Recharts for operational time series.** Per-index panels for S_sys, G-SRI, C-SRI and siblings with `ReferenceArea` bands (GREEN/AMBER/RED), threshold markers from the baseline module, and sparklines inside metric cards. Tooltip payloads always include the evidence reference.
- **D3.js for compliance-grade composites.** FairnessHeatmap renders protected attribute × model domain with the Disparate Impact Ratio against the 0.800 fair-lending floor (FCRA/ECOA); current record 0.880, 16th consecutive compliant window. Color scale is perceptually uniform and colorblind-safe; cell tooltips show the underlying zk fairness attestation ID.
- **Accessibility and fallbacks.** Every chart ships a data-table fallback (perceivable by screen readers), `role="img"` with `aria-label` summaries, and reduced-motion variants.
- **Long-horizon separation.** Ω-GAR slow-frequency indices (CESI 0.523, UCSI 0.695, UCI 0.721, CDS 0.135, Infinity Pillar 82%) render in their own long-horizon panel, never mixed with daily telemetry bands.
- **Performance.** Virtualized series windows, memoized selectors, canvas rendering above 10k points, and exported CSV matching the displayed data exactly.

---

## SECTION 6 — GOVERNANCEPOLICYSIMULATOR (SIMULATED OPA/REGO)

Simulation-only policy laboratory — there is no production write path from this module:

- **Editing.** Rego policy editor with template library entries (release gates, index-threshold rules, containment triggers), stored as versioned drafts with change provenance.
- **Evaluation.** Policies compile to WebAssembly (`opa-wasm`) and evaluate against a `BaselineSnapshot` input; verdicts render as PASS/FAIL cards with reason codes and the exact input hash used.
- **Diffing.** `react-diff-viewer` shows policy drafts against the frozen production bundle; OSCAL crosswalk diffs use the same component with control-mapping alignment.
- **Determinism.** Fixed-input evaluation is replayable bit-identically, matching the Panels 13–15 replay-determinism convention (1,341 checks, 100% bit-identical in the current window).
- **Audit.** Each simulated run is logged with a Merkle-anchored artefact ID and surfaced in AlertHistory as informational events.

---

## SECTION 7 — RISKMITIGATIONSIM AND EXPORT/COMPARISON WORKFLOWS

Scenario engine for supervisory what-if analysis:

- **Levers.** Compute-governance regime (BASELINE ↔ ELEVATED), zkML batch and stage parameters, TEE rotation cadence, drill frequency, and containment-threshold tuning — each lever carries its dossier-derived default and guardrails.
- **Projections.** Seeded, deterministic trajectory projection over the selected horizon; identical inputs must reproduce identical trajectories across sessions and exports.
- **Comparison.** Side-by-side baseline vs. scenario view with delta bands, plus multi-scenario overlay; divergences beyond band thresholds are flagged automatically.
- **Exports.** jsPDF comparison report, CSV/JSON trajectory dumps, and a comparison manifest that seals the scenario parameters, seed, baseline dossier ID, and Merkle root so any reviewer can reproduce the run.

---

## SECTION 8 — RAG GOVERNANCE SUITE (RAGHEALTHMONITOR, RAGDATAAUDIT, RAGSTRESSTEST)

The RAG backend is the governance corpus service; these three modules make it supervisable:

- **RAGHealthMonitor.** Retrieval latency (p50/p99), grounding score, citation coverage, hallucination-rate proxy, and source-freshness SLA per query class; threshold breaches raise alerts into AlertHistory with the failing query trace.
- **RAGDataAudit.** Provenance graph and provenance heatmap (D3) over every retrieved chunk: source trust tiers (T1 regulator filings through T4 unvetted), freshness buckets, PII exposure scanner with quarantine workflow, and per-source drill-down to the underlying artefact. Audit trails are append-only.
- **RAGStressTest.** Adversarial retrieval suites — corpus prompt-injection, poisoned-source injection, stale-evidence queries, and cross-tenant leakage probes — executed drill-style with a pass/fail ledger, execution logs, and bit-identical replay verification, mirroring the SDT drill cadence (DRILL-051 "Quartz-Vigil" dry-run in the current window, live execution 2026-10-26).

---

## SECTION 9 — COMPLIANCEMATRIX AND OSCAL 1.1.2 VALIDATION

Cross-jurisdictional matrix with the established minimum regime set: EU AI Act (incl. Annex IV and key Articles), NIST AI RMF 1.0 / AI 600-1, ISO/IEC 42001, Basel III/IV, SR 11-7, SR 26-2, DORA, NIS2, GDPR, MAS/HKMA FEAT, FCA SMCR & Consumer Duty, HKMA Fintech 2030 AI², SEC Rule 17a-4, FCRA/ECOA, ICGC/GASO, Interstellar AI Governance Accord, Galactic Treaty Framework, plus CFE-1.0 and Protocol SGR-028 as fictional treaty instruments.

- **Cell states.** COMPLIANT (green check), PARTIAL (amber), NON-COMPLIANT (red), NOT APPLICABLE (gray), PENDING ASSESSMENT (blue); every cell opens a detail drawer with the OSCAL control mapping, the governing Rego snippet, assessment timestamp, evidence artefacts, and remediation plan when partial.
- **OSCAL 1.1.2 validation.** SSP and assessment-results JSON validated against the OSCAL 1.1.2 schemas on load; catalog revision tie-out (rev 1159, +1 control in the current window) and crosswalk drift scan status rendered inline; validation failures degrade the cell to PENDING and raise an alert.
- **Exports.** Dossier exports aligned with NIST AI RMF 1.0 and ISO/IEC 42001, generated through the Section 14 export pipeline with evidence annexes.

---

## SECTION 10 — OMNI-SENTINEL TELEMETRY AND PQC_WORM_LOGGER WORM AUDIT MONITORING

Stack health panels render the operations side ("Omni-Sentinel = operations, OneFineStarstuff = governance"):

- **Stacks.** Sentinel AI Governance Stack v2.4, Omni-Sentinel Governance Mesh v4.0, and Unified Supervisory Control Plane v3.0 heartbeat cards; zkML pipeline health (96.9% record, p99 6.0 s, Stage B 94%, Stage C pre-build day 5); TEE/RTEE attestation (52/52 nodes, 98.1% record density); Kubernetes/GitOps posture (214/214 deployments, zero reconciliation errors); kill-switch coherence (5/5 nominal, median 1.7 s).
- **WORM ledger monitoring.** `pqc_worm_logger` batch-commit status against the S3 Object Lock bucket, retention compliance (SEC Rule 17a-4), a zero-gap ledger-gap detector (zero ledger gaps is the invariant), and digest verification (SHA-384) per artefact.
- **Merkle tie-out panel.** The app displays the current sealed root and compares it against the live ledger root; a mismatch triggers a RED alert. Transcript Registry counter (437 sealed entries) and evidence quote age (10 h max against the 24 h floor) complete the integrity surface.
- **Signature verification badges.** ML-DSA-87, Falcon-1024, and SLH-DSA verification status chips appear wherever a sealed artefact is rendered; unverifiable artefacts are quarantined, not displayed as compliant.

---

## SECTION 11 — ZKML AND ZERO-KNOWLEDGE-PROOF-BASED REGULATORY COMPLIANCE

Regulators verify without seeing underlying data — the zk layer is the compliance mechanism, not a decoration:

- **Pipeline panels.** Stage A/B/C progress, SnarkPack batch size (512 stable), proving latency trend (p99 6.0 s), and health record (96.9%); vkFMv3 verification-key status is shown beside every proof.
- **Fairness proofs.** Disparate Impact Ratio attestation (0.880 vs. 0.800 floor, 16th consecutive compliant window) rendered with its proof ID and verification result; the FairnessHeatmap consumes only verified proofs.
- **Regulator verification flow.** Independent verification using published vkFMv3 public keys; every compliance assertion derived from a proof displays proof ID, key ID, and verification status as a single unit.
- **Intervention and voting surfaces.** Intervention Proof Verifier challenge panel (0 open challenges, 3,558 verified proofs cumulative) and zero-knowledge voting round status (round N-42 in progress, Guardian quorum, nullifier set verified).

---

## SECTION 12 — EAIP INTEROPERABILITY STANDARDS FOR ENTERPRISE AI AGENTS

The Enterprise AI Interoperability layer extends `AI_AGENT_INTEROPERABILITY_PROTOCOL.md` on main:

- **Identity and attestation.** PQC-signed agent certificates issued per agent class; capability tokens are scoped, expiring, and revocable through the containment plane.
- **Message envelope.** Typed, versioned, replay-protected envelope contracts with schema-registry conformance tests; breaking changes require a new envelope version, never in-place mutation.
- **Containment hooks.** Autonomous Supervisory Agent drift reporting feeds the containment heartbeat (drift +0.01σ inside the Sentinel v2.4 auto-throttle envelope in the current window); kill-switch coherence is enforced end-to-end with a median 1.7 s heartbeat.
- **Zero-trust interop.** mTLS with PQC hybrid handshake for agent-to-service traffic; supervisory event bus carries signed events only; conformance suite runs in CI alongside the governance-artifacts validator.

---

## SECTION 13 — VOICECOMMANDER (WEB SPEECH API) AND ACCESSIBILITY LAYER

Voice control is a first-class supervisory interface, with typed fallback always available:

- **Command grammar.** "show overview", "open compliance matrix", "export alerts", "emergency stop", "resume operations" — a small, enumerable grammar with a published intent table mapped to the same typed actions the UI buttons invoke.
- **Emergency stop protocol.** Two-step confirmation dialog, global kill-switch banner, autonomous actions disabled, event logged in AlertHistory; "resume operations" is the only exit path. The spoken channel can initiate but never silently confirm the stop.
- **Spoken alerts.** Severity-tiered spoken alerts mirrored into an `aria-live` region so assistive technology users receive identical information.
- **Accessibility layer.** WCAG 2.2 AA: full keyboard operability, visible focus, contrast-validated palette, reduced-motion variants, labeled landmarks, axe checks in CI, and the classification banner plus fictional-simulation disclaimer on every view.

---

## SECTION 14 — GOVERNANCE REPORTING AND EXPORTS (JSPDF)

Export catalog (all routes feed the same pipeline):

| Export | Alignment | Format |
|---|---|---|
| Daily supervisory brief | Daily dossier corpus | PDF (jsPDF) |
| ComplianceMatrix dossier | NIST AI RMF 1.0, ISO/IEC 42001 | PDF (jsPDF) |
| AAP-1 assurance claims | CFE-1.0 / SGR-028 | PDF + JSON |
| AlertHistory log | Severity tiers, evidence links | CSV + JSON |
| RiskMitigationSim comparison | Sealed scenario manifest | PDF + JSON |

jsPDF implementation patterns: paginated layout with running classification banner, table of contents for multi-page dossiers, evidence-link annexes, sealed-values footer carrying the dossier ID and Merkle root, and the fictional-simulation disclaimer with Knowledge-topic citations on the final page. Export determinism is a hard requirement — identical inputs must produce byte-stable artefacts so exported reports can be Merkle-anchored like any other sealed artefact.

---

## SECTION 15 — CROSS-CUTTING ENGINEERING PATTERNS AND BEST PRACTICES

- **Reliability.** Module-scoped error boundaries, skeleton states, degraded offline mode that renders the last verified snapshot with a staleness badge, and retry with backoff on evidence fetches. Vite dev-server reliability fixes stay documented in the CHANGELOG.
- **State discipline.** One owner per fact: dossier-derived values live only in the baseline module; module stores hold view state only; server state stays normalized.
- **Testing.** Vitest units, React Testing Library component tests, axe accessibility tests, golden deterministic tests for both simulators, visual regression on chart snapshots, and contract tests asserting the baseline module equals the current dossier file on main.
- **CI and DevSecOps.** eslint and markdownlint, the governance-artifacts validator, zero-drift GitOps deployment, PQC signing where artefacts are sealed, and observability hooks on every panel (per-panel render metrics, OpenTelemetry traces, alert wiring).
- **Performance.** Route-level code splitting, virtualized matrix and alert tables, memoized selectors, and virtualization budgets enforced in CI performance tests.

---

## SECTION 16 — IMPLEMENTATION ROADMAP (2026–2035)

| Phase | Window | Deliverables |
|---|---|---|
| P0 Foundation | Weeks 1–4 | Typed contracts, baseline module, shell, role selector, theme, classification banner |
| P1 Search and telemetry | Weeks 5–8 | GlobalGovSearch, systemic-risk panels with bands, stack health cards |
| P2 Fairness and RAG suites | Weeks 9–14 | FairnessHeatmap, ParityDashboard, RAGHealthMonitor, RAGDataAudit |
| P3 Simulators and stress | Weeks 15–20 | GovernancePolicySimulator, RiskMitigationSim, RAGStressTest, comparison exports |
| P4 Compliance and exports | Weeks 21–26 | ComplianceMatrix, OSCAL validation, jsPDF export catalog, AAP-1 claims |
| P5 Voice and hardening | Weeks 27–30 | VoiceCommander, accessibility audit, observability, performance budgets |
| Mid-term | Through 2027 | Regulator submission builder alignment, EU AI Act full-enforcement readiness (Aug 2027) |
| Long-horizon | 2028–2035 | Epoch I → II transition panels, Ω-GAR slow-frequency stewardship (dissolution arc modeling, Infinity Pillar readiness) |

---

## SECTION 17 — REGULATOR-READINESS CHECKLIST

- Every KPI is evidence-linked; unlinked numbers are treated as build failures.
- Sealed values (Merkle root, PQC signatures) are identical across every occurrence and tie out to the live ledger.
- Classification banner on every page; fictional-simulation disclaimer in every footer and export.
- Progressive-disclosure tiers verified per role (regulator, governance engineer, executive).
- Compliance cells carry OSCAL control mappings and OPA/Rego snippets with validation status.
- Emergency stop and resume operations are demo-able, logged, and reversible only through the defined exit path.
- Simulators are deterministic and reproducible from their sealed manifests.

---

*This document is a fictional governance-simulation artefact for the GIEN planetary governance mesh. All indices, drills, regimes, signatures, and Merkle roots are simulated data and do not describe real systems.*
