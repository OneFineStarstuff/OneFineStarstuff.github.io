# Runnable Assurance — Sentinel v2.4 Governance Artifacts

This directory upgrades the Sentinel v2.4 governance artifacts from *declarative*
(schemas, prose controls, policy sketches) to **executable and verifiable**. Where
the master reference documents assert that a control "holds," the artifacts here
*prove* it with industry-standard tooling.

> Scope note. These artifacts implement the standards-grounded core (OSCAL 1.1.2,
> OPA/Rego, TLA+/TLC, Circom/Groth16, FIPS 203/204/205 references). AGI/ASI
> *containment* is modelled as a control-and-invariant discipline; speculative
> regime fixtures (ICGC/GACP, GAIRA) remain tagged `feasibility-tier` C/D in the
> OSCAL catalog and are not claimed as settled practice.

## One command

```bash
bash governance_artifacts/run_runnable_assurance.sh
```

Runs all sixteen checks below and fails fast on any error.

## What is proven, and against which control

| # | Check | Tool | Backs OSCAL control | Regime anchor |
|---|-------|------|---------------------|---------------|
| 1 | Release gate + credit gate + confidential-computing attestation gate (PCR_MATCH) | `opa test` (21 tests) | release-gate, `con-07`, `env-01` | SR 11-7, EU AI Act Art. 14/15, ECOA, GDPR Art. 22, DORA |
| 2 | Containment one-way ratchet & terminal-actuation quorum | TLA+ `tlc2.TLC` | `con-04`, `con-07` | EU AI Act Art. 14, DORA resilience testing |
| 3 | Attested admission — no T0 workload runs without fresh valid attestation; TCB rollback / PCR drift force eviction | TLA+ `tlc2.TLC` | `env-01` | EU AI Act Art. 15, DORA ICT risk, NIST AI RMF |
| 4 | Dead-man's-switch containment — one-way ratchet (`TrippedStaysTripped`, `KillSwitchIntegrity`); re-arm only via fresh authenticated heartbeat | TLA+ `tlc2.TLC` (75 states) | `con-04`, `con-07` | EU AI Act Art. 14, DORA resilience |
| 5 | GC-IR cross-target conformance (policy ⇔ circuit ⇔ expectation) | `opa eval` + Circom witness | obligation `ob-ecoa-adverse-reason-codes` | ECOA, GDPR Art. 22, EU AI Act Art. 13 |
| 6 | Systemic-risk concentration bound (HHI) zk proof | Circom + Groth16 (snarkjs) | `cry-05` | Basel op-risk, systemic telemetry |
| 7 | zk-SNARK relayer pipeline — proof → exported Solidity Groth16 verifier (compiles) → ABI calldata for on-chain `verifyProof` | snarkjs + solc 0.8.26 | `cry-05` | Basel op-risk, on-chain settlement |
| 8 | SARA/ACR MoE routing stabilization invariants (entropy / load balance / drop) | Python simulator + pytest | `rte-01` | EU AI Act Art. 15 robustness, SR 11-7 |
| 9 | PQC WORM audit log — real CRYSTALS-Dilithium (ML-DSA-65) signatures + tamper-evident hash chain + S3 Object Lock retention | Python (`dilithium-py`) + pytest | `cry-02` | DORA, EU AI Act Art. 12 logging |
| 10 | OmegaActual contract hardening — both contracts compile (0 warnings); 7 logic tests prove original exploitable & hardened blocks SEC-01..06 | solc 0.8.26 + pytest | `con-07` settlement | EU AI Act Art. 14, DORA |
| 11 | Governance artifact schema validation | Python validator | manifest/schema integrity | OSCAL, evidence logging (EU AI Act Art. 12) |
| 12 | OSCAL catalog conformance — every control's `tla-spec` / `rego-policy` / `circuit` / `simulator` prop resolves to a real in-repo artifact; every regime `#href` resolves to a back-matter anchor (no dangling references); `feasibility-tier ∈ {A,B,C,D}`; `freshness-sla` is a valid ISO-8601 duration (43 cross-reference checks, falsifiable) | Python (`oscal_conformance.py`) + pytest | all `con-*`, `cry-*`, `env-*`, `rte-*` | OSCAL 1.1.2 compliance-as-code integrity (EU AI Act Annex IV, NIST AI RMF, DORA, Basel, SR 11-7) |
| 13 | Annex IV dossier auto-assembly — builds an OSCAL-native 8-section (A–H) EU AI Act technical-documentation dossier from the conformant catalog + live assurance evidence; refuses to run on a non-conformant catalog or unknown control id; never marks a section SATISFIED without a green runnable check | Python (`generate_annex_iv_dossier.py`) + pytest | all controls → Annex IV §A–H | EU AI Act Annex IV technical documentation (auto-assembled deliverable) |
| 14 | DORA ICT-risk register auto-assembly — builds a 5-pillar (P1–P5) DORA register from the same catalog + live evidence; reports P4/P5 as honest coverage gaps; same refusal/honesty guarantees | Python (`generate_dora_ict_register.py`) + pytest | `env-*`, `cry-02`, `con-04/07` → DORA pillars | DORA (Reg. (EU) 2022/2554) ICT-risk register (auto-assembled deliverable) |
| 15 | NIST AI RMF profile crosswalk auto-assembly — builds a 4-function (GOVERN/MAP/MEASURE/MANAGE) crosswalk with per-function coverage analysis from the same catalog + live evidence; same refusal/honesty guarantees | Python (`generate_nist_rmf_crosswalk.py`) + pytest | all controls → NIST AI RMF functions | NIST AI RMF 1.0 coverage crosswalk (auto-assembled deliverable) |
| 16 | Verified distribution-bundle packaging — collects all three regulator deliverables (6 artifacts) into a `dist/` bundle and emits a `MANIFEST.json` with **two** digests per artifact and per bundle: a **`bundle_sha256`** (byte-exact provenance fingerprint of this build — changes each run with the `generated_at` timestamp) and a **`content_digest`** (timestamp-normalized — **stable/reproducible** across regenerations for a given catalog + evidence state). Both recompute from the sorted per-artifact digests; refuses to package on any catalog-conformance failure; reports coverage gaps (DORA P4/P5), never inflates them | Python (`package_distribution_bundle.py`) + pytest | all deliverables → one auditable bundle | Regulator-facing distribution package (assembly-integrity + reproducibility, not a certification) |

### Companion reviews & plan (this iteration)

- `governance_blueprint/IMPLEMENTATION_PLAN_AND_SAFETY_ARCHITECTURE.md` — consolidated
  implementation plan, layered safety architecture, HSM/key-custody design, and the full
  multi-jurisdictional compliance map (EU AI Act, Basel III/IV, NIST AI RMF, ISO/IEC 42001,
  DORA, NIS2, SR 11-7/26-2, GDPR), with A/B/C/D feasibility tiering.
- `governance_blueprint/contracts/SECURITY_REVIEW.md` — Solidity SEC-01..06 + hardened rewrite.
- `governance_blueprint/terraform/` — multi-region confidential-enclave IaC (`terraform validate`
  clean) with KMS CMK + CloudHSM v2 key custody (`env-02`).
- `next-app/DASHBOARD_SECURITY_REVIEW.md` — DASH-01..08 with 5 falsifiable vitest checks.
- `governance_artifacts/rego/POLICY_REVIEW.md` — OPA/Rego review (21/21 tests, recommendations).

### New control groups (`oscal/catalog_sentinel_v24_env_rte.json`)

- **ENV — Confidential Computing & Attested Execution**: `env-01` (hardware-attested
  admission for T0/T1 via SEV-SNP / TDX + vTPM PCR_MATCH; runtime TCB-rollback and
  PCR-drift eviction), `env-02` (enclave-bound ML-DSA key custody).
- **RTE — MoE Routing Stability**: `rte-01` (SARA/ACR stabilization invariants).

## 1. OPA policy tests — `rego/`

- `release_gate.rego` — high-impact release is **deny-by-default**; `allow` requires
  containment `ENFORCED`, dual-control quorum ≥ 2, signed bundle, and both the
  Omni-Sentinel safety control and the SR 11-7 validation control.
- `high_impact_credit.rego` — adverse credit underwriting requires human review,
  ≥ 3 reason codes, fairness within an equal-opportunity delta, verified lineage,
  no active incident.
- `fairness_credit_decision.rego` — the Rego emission target of the GC-IR obligation.

```bash
opa test governance_artifacts/rego/ -v     # 12/12 PASS
```

## 2. TLA+ containment ratchet — `tla/KillSwitchAbstract.tla`

Models containment levels L0 NORMAL → L4 TERMINATED. Autonomous Supervisory Agents
(ASAs) may only *raise* level within L0–L2; lowering the level or actuating the
terminal levels L3/L4 requires a human dual-control quorum. TLC exhaustively checks:

- `TypeOK`, `ASARatchet`, `TerminalNeedsQuorum` (invariants)
- `ASANeverLowers`, `DeEscalationNeedsQuorum` (action properties)

```bash
cd governance_artifacts/tla
java -cp tools/tla2tools.jar tlc2.TLC -config KillSwitchAbstract.cfg KillSwitchAbstract.tla
# -> "Model checking completed. No error has been found." (13 distinct states)
```

## 3. GC-IR cross-target harness — `zk/gcir_harness.py`

The GC-IR design claims a single obligation compiles to multiple targets and that
"any disagreement fails the build." This harness makes that real for
`ob-ecoa-adverse-reason-codes`: it runs each shared fixture through the **Rego**
rule (`opa eval`) and through the **Circom** circuit (real witness generation), then
asserts `rego_allow == circuit_witness_producible == declared_expectation`.

```bash
cd governance_artifacts/zk && python3 gcir_harness.py
# fx-001 allow / fx-002 deny (too few codes) / fx-003 deny (unapproved code) — all agree
```

## 4. SRC-1 systemic-risk concentration proof — `zk/`

`circuits/src1_concentration_bound.circom` proves, in zero knowledge, that the
decision-volume **Herfindahl-Hirschman Index** across foundation-model providers
does not exceed a board-ratified threshold (basis points), with `circuit_tag`
binding the proof to circuit revision SRC-1. The flow runs a dev Powers-of-Tau
ceremony, Groth16 setup, proves the compliant fixture, verifies it, and emits a
`proof_statement.json` conforming to `proof_statement_schema.json`. The negative
test shows an over-concentrated portfolio **cannot** produce a witness.

```bash
cd governance_artifacts/zk && bash run_src1_proof.sh
# -> snarkJS: OK!  (proof verifies); violation fixture rejected (soundness)
```

> The Powers-of-Tau ceremony here is a **development** ceremony and is **not**
> production-secure. A production deployment requires a multi-party trusted setup
> (or a transparent system such as PLONK/STARK as noted in the schema enum).

## 6. Confidential-computing attestation gate — `rego/attestation_gate.rego` + `tla/AdmissionWithAttestation.tla`

The `PCR_MATCH=TRUE` assertion that recurs throughout the master docs is now
*enforced*, not merely stated. The Rego gate (`sentinel.attestation`) admits a
T0/T1 workload only when it presents a SEV-SNP or TDX report with a verified
signature, fresh anti-replay nonce, a launch measurement in the golden registry,
platform TCB at/above the ratified minimum (no rollback), and a vTPM PCR quote
matching the policy digest. The TLA+ spec proves the *temporal* guarantee: across
all 64 initial evidence combinations, no workload reaches `RUNNING` without a
valid attestation, and runtime TCB rollback or PCR drift forces `EVICTED`.

```bash
opa test governance_artifacts/rego/                       # includes 9 attestation tests
cd governance_artifacts/tla
java -cp tools/tla2tools.jar tlc2.TLC -config AdmissionWithAttestation.cfg AdmissionWithAttestation.tla
```

## 7. SARA/ACR MoE routing stabilization — `routing/sara_acr_router.py`

Defines and demonstrates two stack-specific mechanisms (not external standards):
**SARA** (Stabilized Adaptive Routing — load-aware gating bias + temperature) and
**ACR** (Adaptive Capacity Regulation — per-expert capacity factor with overflow
handling). The simulator shows that under skewed gating a naive top-k router
collapses (normalised entropy ≈ 0.38, load ratio ≈ 5.6) and *violates* the
`rte-01` invariants, while SARA+ACR holds entropy ≈ 0.99 and load ratio ≈ 1.25,
*satisfying* all invariants (entropy ≥ 0.80, load ratio ≤ 1.60, drop ≤ 0.02).

```bash
python3 governance_artifacts/routing/sara_acr_router.py
pytest governance_artifacts/routing/test_sara_acr_router.py -q   # 4 tests
```

## 8. PQC WORM audit log — `kafka/pqc_worm_logger_v2.py`

Replaces the original HMAC placeholder with **real CRYSTALS-Dilithium (ML-DSA-65,
FIPS 204)** signatures over canonical batch payloads, linked in a tamper-evident
**hash chain** (`prev_batch_hash`), with an S3 Object Lock COMPLIANCE-mode
retention record per batch. `verify_chain()` re-validates every signature and link
and returns a supervisory-ready report; the demo proves that entry mutation,
batch reordering, and signature forgery are all detected.

```bash
python3 governance_artifacts/kafka/pqc_worm_logger_v2.py
pytest governance_artifacts/kafka/test_pqc_worm_logger_v2.py -q  # 6 tests
```

> ML-DSA-65 here is provided by the pure-Python `dilithium-py` reference
> implementation — correct and FIPS-204-aligned, but **not** constant-time or
> side-channel-hardened. Production signing belongs in the env-02 enclave using a
> validated cryptographic module.

## Reproducing from a clean checkout

```bash
# OPA
curl -sSL -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.70.0/opa_linux_amd64_static && chmod +x /usr/local/bin/opa
# circom 2.1.9 + snarkjs/circomlib
curl -L -o ~/.local/bin/circom https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64 && chmod +x ~/.local/bin/circom
( cd governance_artifacts/zk && npm install )
# TLA+ tools
curl -L -o governance_artifacts/tla/tools/tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
# Python
pip install pyyaml jsonschema dilithium-py
# Run everything
bash governance_artifacts/run_runnable_assurance.sh
```

> Sandbox note: compile circuits with `--O0` if circom raises a `SystemTimeError`
> during constraint simplification (a known clock-skew issue in some containers).
