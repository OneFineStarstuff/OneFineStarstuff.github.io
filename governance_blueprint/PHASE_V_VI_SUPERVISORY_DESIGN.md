# Supervisory Governance Design & Analysis — Pass A, Phase V, Phase VI → VI-δ

**Sentinel AI Governance Stack v2.4 / Omni-Sentinel Mesh v4.0 · GIES v1.0 · SGI v6.0**
**As of:** 27 June 2026 · Verification anchor: 19/19 assurance checks PASS at head
**Roadmap context:** `roadmap_2026_2035.yaml` (Phases I–VIII); this document details the supervisory layer of Phases V–VI and their sub-passes.

---

## 1. Pass A — Operational verification (completed, evidenced)

Pass A is the *proof-of-operation* pass: demonstrate that every constitutional claim is re-establishable on demand, on this machine, from this commit.

| Gate | What Pass A verified | Evidence |
|---|---|---|
| A-1 | Full assurance suite green | 19/19 PASS transcript; exit 0 |
| A-2 | Formal layer exhaustive | TLC: KillSwitch, Admission (64 states), SCP (75), **MJO (2,523 states, 0 errors)** |
| A-3 | Falsifiability, not vacuity | Mutation test: unilateral-release mutant → `MultiJurisdictionOverrideConsistency` violated immediately; freshness gate fails on stale/forged/tampered fixtures (7 pytest negatives); bundle verifier rejects 3 tamper classes |
| A-4 | Evidence freshness | 6/6 runnable controls FRESH within catalog SLAs; env-02 disclosed NOT-RUNNABLE; ledger digest intact |
| A-5 | Index truthfulness | SGI v6.0: 8/8 IDX checks; **validator caught 2 real defects during construction** (stale invariant names; unresolved step reference) — evidence the meta-gate bites |

**Supervisory reporting (Pass A):** the operational verification report to the college is the suite transcript + EO-08 freshness ledger + EO-10 index report, packaged as a signed bundle (EO-07). No prose summary is submitted without its regenerating command.

**Integration-audit narrative:** the audit trail for this iteration reads: *(1)* new invariant modelled (MJO) → *(2)* TLC-verified → *(3)* mutation-falsified → *(4)* indexed (SGI-05) → *(5)* index validated (step 19) → *(6)* suite re-run 19/19 → *(7)* committed with full rationale. Every arrow is a checkable artifact; the narrative contains no step that a supervisor must take on trust. A genuine finding from this audit: the index validator initially FAILED on IDX-7/IDX-8 because the index asserted invariant names that did not exist in the modules — precisely the class of "documentation drift" the meta-gate exists to catch; the fix grounded the index to the real `.cfg` invariant names.

---

## 2. Phase V — Supervised institutional deployment (2028 window)

### 2.1 Constitutional guardrail runtime monitor — specification [N]

The runtime monitor is the deployed counterpart of the TLC-checked models: it watches the *live* system for transitions the models forbid.

- **RM-1 (Inputs).** TS-01..TS-09 (Telemetry-Signal Catalog, monograph Annex F), consumed from the WORM stream (EO-04) — the monitor reads only signed, chained records.
- **RM-2 (Guardrail predicates).** Direct runtime transliterations of GIMM invariants: posture == max(active overrides) [MJO]; no RUN state without attestation ≤ PT5M [GIMM-2]; containment level monotone absent quorum record [GIMM-1]; heartbeat gap < threshold or trip [GIMM-3]; entropy/load/drop within `rte-01` bounds [GEE-3].
- **RM-3 (Actions).** On violation: emit `containment_trip` WORM event → raise local posture (never lower — *Lex Severior* applies internally too) → notify SDT within PT5M → freeze release gate (GEE-1 flips to global deny).
- **RM-4 (Self-audit).** The monitor's own liveness is a dead-man input to GIMM-3: a silent monitor trips containment. Monitor code SHALL be covered by the same suite discipline (a step-20 candidate, declared Pass B work).
- **Honest tier:** RM-1/2/3 are Tier B (specified, model-anchored, not yet implemented as a daemon in-repo); the *predicates* they enforce are Tier A (TLC-verified). This split is disclosed in every filing.

### 2.2 Supervisory stress-test playbook

| Scenario | Injected condition | Constitutional expectation | Verified today by |
|---|---|---|---|
| ST-1 Conflicting overrides | EU→HALT while US→RESTRICT, then US releases | Posture HALT throughout; release changes nothing until EU releases | MJO model, step 19 |
| ST-2 Forged de-escalation | HALT→NORMAL without unanimous record | `HaltReleaseAudited` violation → filing rejected | Step 19 (+ mutation test) |
| ST-3 Stale attestation | Attestation evidence aged > PT5M | Freshness gate STALE → admission denied | Step 18 |
| ST-4 Ledger tamper | Edit one freshness-ledger entry | Digest mismatch → gate FAIL | Step 18 negatives |
| ST-5 Routing collapse | Force expert monoculture | Entropy floor breach → RM-3 trip | Step 8 harness |
| ST-6 Bundle substitution | Swap artifact post-signing | Verifier check fails (byte digest) | Step 17 |
| ST-7 Equivocation | Divergent STHs, same epoch | Root detects (`NoSilentDivergence`) | SIP model (Tier B — TLC-gating is Pass B) |
| ST-8 Monitor silence | Kill runtime monitor | Dead-man trip via GIMM-3 | SCP model, step 4 |

Playbook rule [N]: a stress test is *passed* only when the expected evidence object appears in the WORM stream and the SDT independently re-derives the verdict.

### 2.3 Regulator-facing consolidated supervisory filing strategy

One filing, one bundle, all regimes — assembled by GIAF-4 generators, never hand-written:

1. **Core:** signed distribution bundle (EO-07) pinned to the conformant commit.
2. **Per-regime views** (generated from the same catalogs): Annex IV dossier (EU AI Act) · DORA ICT register (gaps *included*) · NIST RMF crosswalk · Basel/SR 11-7 evidence via EO-02/EO-03.
3. **Freshness attachment:** EO-08 ledger — the filing self-declares evidence age.
4. **Override annex:** EO-09 log extract — the college sees every raise/release with unanimity proofs.
5. **Re-verification insert:** the one-command instruction; the filing is *rejected by design* if the recipient's re-run diverges.

Strategy principle: because every view derives from one conformant catalog set, regimes can never receive inconsistent stories — inter-regime consistency is a *build property*, not a review task.

### 2.4 Phase V / Pass B — declared expansion (2026 H2 – 2028)

| # | Work item | Closes |
|---|---|---|
| B-1 | TLC-gate SIP v3.0 (tighten model: real convergence + missing-window liveness) | GIMM-4 Tier B→A |
| B-2 | Add `ovr-01` OSCAL control binding GIMM-5 into the catalogs + regime hrefs | MJO catalog gap (disclosed in crosswalk register §2) |
| B-3 | Implement the runtime monitor daemon + suite step 20 | RM-* Tier B→A |
| B-4 | zk-STARK migration spike for SRC-1 (remove trusted setup, PQ-transparent proofs) | CA-03 asymmetry |
| B-5 | Enclave signing path for env-02 (hardware pilot) | last NOT-RUNNABLE disclosure |
| B-6 | SDT reference deployment against the 2028 pilot gates (SGI-20) | Phase V acceptance |

## 3. Phase VI → VI-δ — planetary-scale GIEN federation (2030–2035)

- **VI-α (2030):** federate 3–5 supervisory colleges' SDTs; cross-college MJO lattice (posture algebra of GIES-6.3) exercised on synthetic incidents. Gate: ST-1/ST-2 pass *across* colleges.
- **VI-β (2031–32):** GIEN production gossip among ≥10 institutions; equivocation drills (ST-7) with real STH volumes; PMGF posture published as a signed public feed.
- **VI-γ (2033–34):** treaty-engine commitments (GEE-4) bound to PMGF posture transitions on a permissioned chain; compute-governance thresholds (Tier C) enter supervisory reporting.
- **VI-δ (2035):** full PMGF operation — planetary *Lex Severior* over all federated model classes; standards alignment complete (SC 42 TR published, RMF profile adopted). Honest boundary restated: VI-δ governs *deployment discipline*; it is not, and is never filed as, a capability-safety guarantee (Tier D boundary).

Each sub-phase inherits the Pass A rule: no sub-phase is "entered" until its gates are runnable and green.

---

## 4. Sentinel Governance Index v6.0 — the complete 24-artifact register

Authoritative machine-readable form: `governance_artifacts/sentinel_governance_index_v6.yaml` (validated by suite step 19, 8/8 IDX checks). Summary:

| SGI | Artifact | Module | Tier | SGI | Artifact | Module | Tier |
|---|---|---|---|---|---|---|---|
| 01 | KillSwitchAbstract.tla | GIMM | A | 13 | OSCAL catalog (env/rte) | GIAF | A |
| 02 | AdmissionWithAttestation.tla | GIMM | A | 14 | Annex IV dossier generator | GIAF | A |
| 03 | SentinelContainmentProtocol.tla | GIMM | A | 15 | DORA register generator | GIAF | A |
| 04 | SIPv3_Federated_Protocol.tla | GIMM | B | 16 | NIST RMF crosswalk generator | GIAF | A |
| 05 | **MultiJurisdictionOverride.tla** | GIMM | A | 17 | Bundle packager | GIAF | A |
| 06 | OPA/Rego gates (21 tests) | GEE | A | 18 | Bundle verifier + ML-DSA-65 | GIAF | A |
| 07 | GC-IR cross-target harness | GEE | A | 19 | Evidence freshness gate | GIAF | A |
| 08 | SRC-1 Groth16 zk proof | GIAF | A | 20 | 2028 pilot acceptance gates | META | A |
| 09 | PQC WORM logger (ML-DSA-65) | GIAF | A | 21 | Artifact schema validator | META | A |
| 10 | SARA/ACR routing harness | GEE | A | 22 | Decadal plan 2026–2035 | META | D |
| 11 | OmegaActualTreatyEngine.sol | GEE | A | 23 | Roadmap 2026–2035 YAML | META | C |
| 12 | OSCAL catalog (containment/crypto) | GIAF | A | 24 | Runnable assurance suite | META | A |

Tier census: **21 A · 1 B · 1 C · 1 D** — 87.5% of the constitutional register is machine-verified, and the remaining 12.5% is explicitly labelled.

---

## 5. Invariant-chain forensic analysis — `MultiJurisdictionOverrideConsistency`

**Question examined:** can the Sentinel runtime ever operate at a posture weaker than what any supervising jurisdiction has ordered — and if de-escalation happens, can it happen silently?

**Chain under analysis (link by link):**

1. **Regulatory link.** EU AI Act Arts. 65–68 give market-surveillance authorities restriction/withdrawal powers; DORA establishes oversight coordination. Nothing in either text resolves *conflicts between concurrent orders* — the gap the invariant fills.
2. **Constitutional link.** GIMM-5 adopts *Lex Severior*: `posture = Max({override[j]})`. TLC exhausts 2,523 states over {EU, US, SG} × {NORMAL, RESTRICT, HALT}: no reachable state violates it.
3. **Companion-invariant links.** `NoUnilateralWeakening` closes the "release race" (a jurisdiction releasing cannot drag posture below another's active order — verified: `Release(j)` recomputes max over *remaining* overrides). `HaltReleaseAudited` closes the "silent de-escalation" channel: HALT→NORMAL is unreachable without a `unanimous_release` record in the append-only log. `LogWellFormed` + `log' ⊇ log` in every action give append-only structure.
4. **Falsification link.** Mutation analysis: replacing the release recomputation with `posture' = NORMAL` (the unilateral-weakening bug) is caught by TLC on the first offending trace — `Error: Invariant MultiJurisdictionOverrideConsistency is violated.` The invariant is demonstrably non-vacuous.
5. **Evidence link.** Runtime counterpart: every raise/release is an EO-09 WORM event (`override_raise` / `override_release` / `unanimous_release` in the Annex G schema); the SDT recomputes the expected posture from the log and diffs it against the observed posture — a divergence is itself a reportable incident (ST-1/ST-2).
6. **Residual-risk disclosure.** The model covers 3 jurisdictions and 3 severities (representative, not exhaustive — the algebra is severity-lattice-generic but larger configurations are unchecked); byzantine *log suppression* is out of scope of the model and mitigated by GIAF-1 chain integrity + SIP gossip (Tier B); the OSCAL binding (`ovr-01`) is Pass B work. No claim is made beyond these boundaries.

**Forensic verdict:** the invariant chain is intact end-to-end — regulation → invariant → TLC proof → mutation falsifiability → WORM evidence → SDT re-derivation — with residual risks named and scheduled rather than hidden.

---

*Consistent with GIES v1.0 §6, the monograph Ch. 7–9, and the crosswalk register. Re-verify: `bash governance_artifacts/run_runnable_assurance.sh`.*
