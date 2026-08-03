# Sentinel AI Governance Stack v2.4 — Implementation Plan, Safety Architecture & Multi-Jurisdictional Compliance

**Subtitle:** Omni-Sentinel Cognitive Execution Environment for G‑SIFI deployment, 2026–2035
**Status of this document:** Engineering plan grounded in the *runnable, verified* artifacts in this
repository. Every architectural claim below links to an artifact that is built, tested, or
model-checked — not to prose. Speculative elements are explicitly tiered.
**Last verification:** all referenced suites green (see §8).

---

## 0. How to read this document (feasibility tiering)

To keep an enterprise audience honest about what exists vs. what is aspirational, every component
carries a tier. This is the same scheme used in the OSCAL catalog (`feasibility-tier`).

| Tier | Meaning | Example in this stack |
|------|---------|-----------------------|
| **A** | Standards-grounded, buildable now with current tooling; verified here. | OPA gates, TLA+ models, Groth16 proof, PQC WORM log, Terraform/CloudHSM, Solidity verifier |
| **B** | Buildable now, but requires real hardware/vendor accounts to exercise end-to-end. | SEV-SNP/TDX live attestation, CloudHSM cluster, multi-region enclave fleet |
| **C** | Plausible 2026–2030; depends on emerging standards or vendor roadmaps. | zk-STARK migration of systemic-risk proofs, ML-DSA on-chain verification at scale |
| **D** | Speculative 2030–2035; modelled as control discipline, **not** claimed as settled practice. | AGI/ASI "containment" as a guaranteed property; ICGC/GACP/GAIRA regime fixtures |

> **Honesty note.** "Containment of a superintelligence" is **not** a solved problem and this stack
> does not claim to solve it. What *is* engineered (Tier A) is a *containment-control discipline*:
> a one-way kill-switch ratchet, attested admission, dual-control actuation, and tamper-evident
> audit — each formally checked. These reduce a class of operational/governance failures; they are
> not a proof of safety for an arbitrarily capable agent (Tier D).

---

## 1. Reference architecture (layers)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ L5  Supervision & Settlement                                              │
│     OmegaActual treaty engine (Solidity) · dead-man's switch · quorum     │
│     zk-SNARK relayer → on-chain Groth16 verifier (systemic-risk proofs)   │
├──────────────────────────────────────────────────────────────────────────┤
│ L4  Governance Decision Plane                                             │
│     OPA/Rego gates: release · high-impact credit · fairness · attestation │
│     GC-IR cross-target conformance (policy ⇔ circuit ⇔ model)             │
├──────────────────────────────────────────────────────────────────────────┤
│ L3  Assurance & Proof                                                     │
│     TLA+/TLC containment & admission invariants · Circom/Groth16 HHI proof│
│     PQC WORM audit (CRYSTALS-Dilithium / ML-DSA-65 + S3 Object Lock)      │
├──────────────────────────────────────────────────────────────────────────┤
│ L2  Model Execution (MoE)                                                 │
│     SARA (stabilized routing) + ACR (adaptive capacity) — collapse guard  │
├──────────────────────────────────────────────────────────────────────────┤
│ L1  Confidential Execution Substrate                                      │
│     SEV-SNP / TDX enclaves · vTPM remote attestation (PCR_MATCH=TRUE)     │
│     enclave-bound key custody (CloudHSM / KMS) · golden measurement reg.  │
├──────────────────────────────────────────────────────────────────────────┤
│ L0  Cloud Infrastructure                                                  │
│     Terraform multi-region · Nitro Enclaves · KMS CMK · CloudHSM v2 · VPC │
└──────────────────────────────────────────────────────────────────────────┘
```

### Layer-to-artifact map (what backs each claim)

| Layer | Artifact (in repo) | Tier | Verified by |
|-------|--------------------|------|-------------|
| L0 | `governance_blueprint/terraform/main.tf` | A/B | `terraform validate` = Success; `fmt -check` clean |
| L1 | `governance_artifacts/rego/attestation_gate.rego` + `tla/AdmissionWithAttestation.tla` | A | `opa test` (7) + TLC |
| L2 | `governance_artifacts/routing/` SARA/ACR simulator | A | pytest invariants |
| L3 | `tla/SentinelContainmentProtocol.tla`, `zk/` Groth16, `kafka/pqc_worm_logger_v2.py` | A | TLC 75 states · snarkjs · pytest |
| L4 | `governance_artifacts/rego/*.rego` | A | `opa test` (21) + GC-IR harness |
| L5 | `contracts/OmegaActualTreatyEngineHardened.sol`, `zk/run_relayer_pipeline.sh` | A/C | solc 0.8.26 · relayer pipeline runs |

---

## 2. Safety architecture (the containment-control discipline)

### 2.1 Dead-man's-switch containment — formally checked
`governance_artifacts/tla/SentinelContainmentProtocol.tla` models the kill-switch as a **one-way
ratchet**: once `containmentTripped` latches TRUE it cannot silently clear. TLC verifies
(75 distinct states, no counterexample):
- `TypeOK`, `NoUnsanctionedHighRisk` — no high-risk action proceeds without sanction;
- `KillSwitchIntegrity` — the switch cannot be reset by an unauthenticated step;
- `TrippedStaysTripped` (temporal) — once tripped, always tripped (re-arm requires a fresh,
  authenticated heartbeat under CASO authority).

This replaces the previously broken spec (`governance_blueprint/SentinelContainmentProtocol.tla`,
now deprecated) which referenced an undefined `Init` and had unreachable invariants.

### 2.2 On-chain enforcement of the same discipline
`contracts/OmegaActualTreatyEngineHardened.sol` (compiles clean, solc 0.8.26, 0 warnings) makes the
discipline tamper-resistant at the settlement layer:
- access-controlled `recordHeartbeat` (was unauthenticated → SEC‑02);
- existence + non-zero-quorum checks on `approveTreaty` (was single-tx ratification of an
  unproposed treaty → SEC‑01);
- latched `containmentTripped` with a CASO-gated `rearm()` requiring a fresh heartbeat —
  the Solidity mirror of `TrippedStaysTripped`.

`contracts/SECURITY_REVIEW.md` documents SEC‑01..06; `contracts/test_contract_logic.py`
(7/7 pass) proves the original is exploitable and the hardened version blocks each attack.

### 2.3 Attested admission (no workload runs un-measured)
`attestation_gate.rego` denies admission unless a fresh, signature-valid SEV‑SNP/TDX report with a
golden launch measurement and `PCR_MATCH=TRUE` is presented, and evicts on TCB rollback / PCR drift.
`tla/AdmissionWithAttestation.tla` proves no T0 workload reaches a running state without a valid
attestation in the same step.

### 2.4 Provable systemic-risk telemetry + relayer
`zk/` builds a Circom/Groth16 proof that a portfolio's HHI concentration is below a bound **without
revealing positions**. `zk/run_relayer_pipeline.sh` closes the loop to on-chain enforcement:
proof → `snarkjs zkey export solidityverifier` → Groth16 verifier (1663 bytes, compiles) →
ABI-encoded `verifyProof(...)` calldata. A zk‑STARK migration (transparent setup, no trusted
ceremony) is the Tier‑C path documented in `RUNNABLE_ASSURANCE.md`.

### 2.5 Tamper-evident audit
`kafka/pqc_worm_logger_v2.py` signs each audit event with real CRYSTALS‑Dilithium (ML‑DSA‑65,
FIPS 204) and chains hashes; retention is enforced via S3 Object Lock (COMPLIANCE mode). This
provides post-quantum non-repudiation for the EU AI Act Art. 12 / DORA logging obligations.

### 2.6 MoE routing stability
SARA + ACR prevent expert collapse (a robustness failure mode). Invariants on routing entropy,
load balance, and drop rate are asserted by a pytest simulator (`rte-01`).

---

## 3. Implementation plan (phased, 2026 → 2035)

### Phase 0 — Foundation & assurance harness (0–6 months) · Tier A
- Stand up `run_runnable_assurance.sh` in CI (already wired: `.github/workflows/runnable-assurance.yml`).
- Ratify OSCAL control catalog (ENV/RTE groups) as the single control source of truth.
- Land OPA gates + TLA+ models + Groth16 proof + PQC WORM logger.
- **Exit criteria:** assurance suite green on every PR; control→proof map complete.

### Phase 1 — Confidential substrate (6–15 months) · Tier B
- Provision Terraform multi-region: VPC, KMS CMK (rotation on), CloudHSM v2 cluster for
  enclave-bound key custody (`env-02`), Nitro/SEV-SNP enclave nodes (IMDSv2, encrypted root).
- Integrate a real attestation verifier (AMD/Intel roots) behind `attestation_gate.rego`.
- Populate the golden measurement registry; wire TCB anti-rollback.
- **Exit criteria:** live `PCR_MATCH=TRUE` admission on real hardware; HSM key custody attested.

### Phase 2 — Governance decision plane in production (12–24 months) · Tier A/B
- Deploy OPA as an admission/decision service; route release + credit + fairness decisions through it.
- Operationalize GC-IR cross-target conformance in CI (policy ⇔ circuit ⇔ model).
- Connect the PQC WORM log to a production Kafka + S3 Object Lock bucket.
- **Exit criteria:** no high-impact release without dual-control quorum + ENFORCED containment.

### Phase 3 — Settlement & systemic-risk relayer (18–30 months) · Tier A/C
- Deploy hardened OmegaActual engine; bind dead-man's switch to operational heartbeats.
- Stand up the zk-SNARK relayer as an attested off-chain agent submitting periodic HHI proofs.
- **Exit criteria:** on-chain Groth16 verification of systemic-risk bound; rearm only via CASO + fresh heartbeat.

### Phase 4 — PQC + zk-STARK migration (24–48 months) · Tier C
- Full ML-DSA / ML-KEM (FIPS 203/204/205) rollout for signing + transport.
- Migrate systemic-risk proofs to zk-STARK (transparent setup) to remove the trusted ceremony.

### Phase 5 — Decadal hardening & frontier-risk posture (2030–2035) · Tier D
- Treat AGI/ASI containment as continuously-reviewed control discipline, not a solved property.
- Maintain the formal models as living artifacts; re-check on every capability step-change.

---

## 4. Multi-jurisdictional compliance mapping

Each row links a regulatory obligation to the **specific artifact** that provides evidence, and the
control IDs in the OSCAL catalog. (Legal mapping is engineering interpretation, not legal advice.)

| Regime / clause | Obligation (summary) | Evidence artifact | Control |
|-----------------|----------------------|-------------------|---------|
| **EU AI Act** Annex IV §2 | Technical documentation of system, risk, robustness | OSCAL catalog + this plan + assurance suite | catalog-wide |
| EU AI Act Art. 12 | Automatic record-keeping / logging | `pqc_worm_logger_v2.py` (Dilithium + WORM) | `cry-02` |
| EU AI Act Art. 13 | Transparency of automated decisions | `fairness_credit_decision.rego` (reason codes) | GC-IR `ob-ecoa-…` |
| EU AI Act Art. 14 | Human oversight | `release_gate.rego` quorum ≥ 2; containment model | `con-04/07` |
| EU AI Act Art. 15 | Accuracy, robustness, cybersecurity | SARA/ACR invariants; attestation gate; Terraform hardening | `rte-01`, `env-01` |
| **Basel III/IV** (op & model risk) | Capital/risk for model & concentration risk | Groth16 HHI concentration proof | `cry-05` |
| **NIST AI RMF** (GOVERN/MAP/MEASURE/MANAGE) | Risk management function | OPA gates + assurance suite + this plan | catalog-wide |
| **ISO/IEC 42001** (AIMS) | AI management system controls | OSCAL controls + policy reviews | A.6/A.7 |
| **DORA** Art. 9/11 | ICT protection & resilience testing | Terraform/HSM; TLA+ resilience; WORM log | `env-01/02` |
| **NIS2** Art. 21 | Cybersecurity risk-management measures | Dashboard hardening (DASH‑03/06); enclave substrate | L0/L1 |
| **SR 11‑7 / SR 26‑2** | Model risk management & validation | `MOD-SR11-7-VAL` control in release gate; credit gate | release-gate |
| **GDPR** Art. 22 | Rights re: automated decisions | reason-code policy + consent ledger | GC-IR |
| **GDPR** Art. 15/30/32 | Access, records, security of processing | consent hash-chain (+ remediation in DASH‑01/02/07) | privacy |

> Speculative regime fixtures (ICGC/GACP, GAIRA) are **Tier D** and remain tagged in the OSCAL
> catalog as not-settled-practice; they are modelled for forward-compatibility only.

---

## 5. HSM & key-custody architecture (Tier B)

- **Root of trust:** AWS CloudHSM v2 cluster (`aws_cloudhsm_v2_cluster` + `_hsm` in `main.tf`),
  FIPS 140‑2 Level 3, for custody of the ML-DSA signing keys (`env-02`).
- **Envelope encryption:** KMS CMK with annual rotation for data-at-rest; enclave root volumes encrypted.
- **Enclave binding:** signing keys are usable only inside an attested enclave (Nitro/SEV-SNP),
  so a compromised host cannot exfiltrate the audit-signing key.
- **Migration:** PQC signer (Dilithium/ML-DSA-65) custody moves from software to HSM in Phase 1.

---

## 6. Security review summary (this turn's reviews)

| Surface | Document | Result |
|---------|----------|--------|
| OmegaActual Solidity contract | `contracts/SECURITY_REVIEW.md` | SEC‑01..06 found; hardened version compiles + 7/7 logic tests |
| Sentinel dashboard (Next.js) | `next-app/DASHBOARD_SECURITY_REVIEW.md` | DASH‑01..08; 5/5 falsifiable evidence tests pass |
| OPA/Rego assurance policies | `governance_artifacts/rego/POLICY_REVIEW.md` | 21/21 tests pass; 3 non-blocking recommendations |

Highest-priority remediations (all Tier A): consent endpoint authz/identity-binding (DASH‑01/02),
chat endpoint authn + limits (DASH‑03), and enforcing the moderation `block` decision (DASH‑05).

---

## 7. Residual risk & explicit limitations
- **Containment is control discipline, not a safety proof** for arbitrarily capable agents (Tier D).
- **Live attestation/HSM/enclave** behaviour (Tier B) is verified only at the IaC/policy layer here;
  end-to-end proof requires real hardware and vendor accounts.
- **Trusted setup:** the Groth16 ceremony is a trust assumption until the zk-STARK migration (Tier C).
- **Dashboard** is an MVP; the High/Medium findings must be closed before any production exposure.

---

## 8. Verification ledger (re-runnable)
| Check | Command | Last result |
|-------|---------|-------------|
| OPA policy tests | `opa test governance_artifacts/rego/` | 21/21 PASS |
| Containment model | `tlc2.TLC SentinelContainmentProtocol` | 75 states, no error |
| Solidity compile | `node governance_blueprint/contracts/compile.js` | both OK, 0 warnings |
| Contract logic | `pytest contracts/test_contract_logic.py` | 7/7 PASS |
| Terraform | `terraform validate` / `fmt -check` | Success / clean |
| zk relayer | `bash governance_artifacts/zk/run_relayer_pipeline.sh` | verifier 1663B, compiles |
| Dashboard evidence | `npx vitest run __tests__/dashboard_security_review.test.ts` | 5/5 PASS |
| Full suite | `bash governance_artifacts/run_runnable_assurance.sh` | see §8 in RUNNABLE_ASSURANCE.md |
