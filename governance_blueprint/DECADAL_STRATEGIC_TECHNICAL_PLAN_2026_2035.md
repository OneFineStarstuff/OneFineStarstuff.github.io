# Decadal Strategic & Technical Plan (2026–2035)
## Sentinel AI Governance Stack v2.4 · Omni-Sentinel Mesh v4.0 · Unified AI Supervisory Control Plane (SCP v3.0)

**Audience:** G‑SIFI and Fortune 500 financial-institution boards, CROs, CISOs, model-risk and
regulatory-affairs leadership, and prudential supervisors.
**Classification:** CONFIDENTIAL — board / supervisory use.
**Status of this document:** Authoritative consolidation of the program. Every technical claim is
anchored to a **runnable, verified artifact in this repository** (see the *Evidence* column in each
table) — not to prose. Where a capability is not yet buildable end-to-end, it is explicitly tiered.
**Verification baseline at issue:** `bash governance_artifacts/run_runnable_assurance.sh` → **11/11 PASS**.

---

## 0. Reading guide — feasibility tiering & honesty discipline

This plan deliberately separates what is *built and verified today* from what is *aspirational*.
Every component carries a tier (the same scheme used in the OSCAL catalog `feasibility-tier`):

| Tier | Meaning | Representative components |
|------|---------|---------------------------|
| **A** | Standards-grounded, buildable now, **verified in-repo**. | OPA/Rego gates, TLA+ models, Groth16 proof, PQC WORM log, Solidity verifier, Terraform/CloudHSM IaC, 24h monitor |
| **B** | Buildable now, needs real hardware/vendor accounts to exercise end-to-end. | Live SEV‑SNP/TDX attestation, CloudHSM cluster, multi-region enclave fleet, production Kafka/S3 WORM |
| **C** | Plausible 2026–2030; depends on emerging standards / vendor roadmaps. | zk‑STARK migration, on-chain ML‑DSA verification at scale, zkML transition-validity at production latency |
| **D** | Speculative 2030–2035; modelled as **control discipline**, not claimed as settled practice. | "Containment of ASI" as a guarantee; ICGC/GASO regime fixtures; federated GIEN clearing utility |

> **Integrity statement (read this first).** Superintelligence *containment* is **not a solved
> problem**, and this program does **not** claim to solve it. What is engineered (Tier A) is a
> *containment-control discipline* — a formally model-checked one-way kill-switch ratchet, attested
> admission, dual-control terminal actuation, and tamper-evident post-quantum audit. These reduce a
> class of operational and governance failure modes; they are **not** a safety proof for an
> arbitrarily capable agent (Tier D). Supervisors and boards should treat Tier C/D items as
> direction-of-travel, contingent on standards and capability evolution.

---

## 1. Executive summary

Over 2026–2035 the program moves a G‑SIFI from *declarative* AI governance (policies, prose,
attestations of intent) to *executable, cryptographically verifiable* governance (policies that
run, invariants that are model-checked, risk claims that carry zero-knowledge proofs, and audit
logs that are post-quantum tamper-evident). The thesis: **as AI systems approach AGI-class
capability inside systemically important institutions, governance must itself become a verifiable
engineering artifact** — auditable by a regulator with the same rigor as a financial control.

Three product layers deliver this:

1. **Sentinel AI Governance Stack v2.4** — the per-institution control plane: zero-trust execution
   on confidential-computing enclaves, OPA/Rego decision gates, TLA+-verified containment,
   StaR-MoE routing stabilization, and PQC WORM audit.
2. **Omni-Sentinel Mesh v4.0** — the institution-internal fabric connecting enclaves, the 24h
   operational monitor (G‑SRI), telemetry attestation, and the dead-man's-switch settlement layer.
3. **Unified AI Supervisory Control Plane (SCP v3.0)** — the supervisor-facing interoperability
   layer (SIP v3.0 / GIEN) that turns per-institution evidence into cross-border prudential
   supervision (zk systemic-risk proofs, OSCAL dossiers, automated regulator APIs).

**What already works (Tier A, verified in this repo):** the entire assurance backbone — 11 runnable
checks covering policy gates, three TLA+ models, the Groth16 systemic-risk proof + relayer, SARA/ACR
routing, the ML‑DSA‑65 WORM log, and the OmegaActual contract hardening — plus the consolidated
implementation plan, three security reviews, and the multi-region confidential-enclave IaC.

---

## 2. Architecture overview (the four control planes)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  SCP v3.0 — Unified AI Supervisory Control Plane            (supervisor-facing)    │
│  SIP v3.0 collective defense · GIEN event clearing · zk systemic-risk proofs       │
│  OSCAL 1.1.2 dossier APIs · automated EU AI Act Annex IV / DORA / Basel delivery   │
├──────────────────────────────────────────────────────────────────────────────────┤
│  Omni-Sentinel Mesh v4.0 — institution fabric             (operations)             │
│  24h monitor (G-SRI) · telemetry attestation · OmegaActual dead-man's switch       │
│  zk-SNARK/zk-STARK relayer pipelines · Merkle-anchored evidence                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│  Sentinel Stack v2.4 — governance decision + assurance     (control)               │
│  OPA/Rego gates · TLA+ containment & admission · StaR-MoE (SARA+ACR)               │
│  PQC WORM (ML-DSA-65 / Dilithium / SPHINCS+) · Circom/Groth16 proofs               │
├──────────────────────────────────────────────────────────────────────────────────┤
│  Confidential substrate + infra                            (zero-trust execution)  │
│  Intel TDX / AMD SEV-SNP enclaves · vTPM PCR_MATCH attestation · CloudHSM/KMS      │
│  Terraform multi-region · Nitro Enclaves · DevSecOps/GitOps (ArgoCD/Flux)          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Component → artifact → evidence map

| Plane | Component | Artifact (in repo) | Tier | Evidence (re-runnable) |
|-------|-----------|--------------------|------|------------------------|
| Infra | Multi-region confidential enclaves + HSM | `governance_blueprint/terraform/main.tf` | A/B | `terraform validate` = Success; `fmt -check` clean |
| Substrate | Attested admission (TDX/SEV-SNP + vTPM PCR_MATCH) | `governance_artifacts/rego/attestation_gate.rego`, `tla/AdmissionWithAttestation.tla` | A | `opa test` (7) + TLC (64 states) |
| Control | Containment one-way ratchet | `tla/SentinelContainmentProtocol.tla`, `tla/KillSwitchAbstract.tla` | A | TLC 75 + 13 states, no error |
| Control | Release / credit / fairness gates | `governance_artifacts/rego/*.rego` | A | `opa test` 21/21 |
| Control | StaR-MoE (SARA + ACR) routing stability | `governance_artifacts/routing/` | A | pytest invariants (entropy/load/drop) |
| Control | PQC WORM audit (ML-DSA-65) | `governance_artifacts/kafka/pqc_worm_logger_v2.py` | A | pytest: sign+chain verify, tamper caught |
| Control | Systemic-risk zk proof (HHI) | `governance_artifacts/zk/` (Circom/Groth16) | A | snarkjs: proof verified, violation rejected |
| Mesh | zk-SNARK relayer pipeline | `governance_artifacts/zk/run_relayer_pipeline.sh` | A/C | exports Solidity verifier (1663B, compiles) + calldata |
| Mesh | 24h operational monitor + G-SRI | `omni_sentinel_24h_monitor.py` (+ `omni_sentinel_cli.py`, `pqc_worm_logger.py`) | A | runs; emits G-SRI + PCR_MATCH checkpoints |
| Mesh | Dead-man's-switch settlement | `governance_blueprint/contracts/OmegaActualTreatyEngineHardened.sol` | A | solc 0.8.26 clean; 7/7 logic tests |
| SCP | GIEN governance event schema | `docs/schemas/gien-governance-event.schema.json` | A | JSON-Schema 2020-12; validated |
| SCP | OSCAL control catalog (ENV/RTE) | `governance_artifacts/oscal/catalog_sentinel_v24_env_rte.json` | A | OSCAL 1.1.2; schema-valid |
| SCP | Compliance map + impl plan | `governance_blueprint/IMPLEMENTATION_PLAN_AND_SAFETY_ARCHITECTURE.md` | A | this doc + that doc cross-linked |

---

## 3. Zero-trust AI governance & TEE architecture (Tier A/B)

**Principle:** no model, agent, or governance decision is trusted by location or network position.
Trust is *earned per workload* via hardware attestation and *re-earned continuously*.

- **Enclaves:** T0/T1 (highest-criticality) workloads run only inside Intel **TDX** or AMD
  **SEV‑SNP** enclaves. The launch measurement (TDX `MRTD` / SNP `MEASUREMENT`) must match a
  **golden value** in the reference-measurement registry.
- **vTPM remote attestation:** the workload must present a vTPM quote whose aggregate PCR digest
  yields **`PCR_MATCH=TRUE`** against the policy-mandated digest. Replayed nonces, invalid report
  signatures, and **TCB rollback** are denied. → enforced by `attestation_gate.rego` (7 passing
  deny tests) and modelled by `AdmissionWithAttestation.tla` (TLC: no T0 workload runs un-attested).
- **Key custody:** signing keys (ML‑DSA) live in **AWS CloudHSM v2** (FIPS 140‑2 L3) and are usable
  only inside an attested enclave; a compromised host cannot exfiltrate them. → `terraform/main.tf`
  (`aws_cloudhsm_v2_cluster`/`_hsm`, KMS CMK rotation, encrypted root volumes, IMDSv2).
- **Runtime posture:** PCR drift or TCB rollback detected at runtime triggers eviction (control
  `env-01`), and the containment ratchet (§5) can latch.

**Tier note:** the *policy and IaC layers are Tier A (verified here)*; live attestation against real
AMD/Intel roots and a running CloudHSM cluster are **Tier B** (need hardware + vendor accounts).

---

## 4. StaR-MoE routing stabilization (Tier A)

Mixture-of-Experts models in production exhibit **expert collapse / routing drift** — a robustness
failure that degrades fairness and accuracy and can mask systemic-risk signals. The program runs
**StaR-MoE** = **SARA** (Stabilized Adaptive Routing) + **ACR** (Adaptive Capacity Regulation):

- SARA bounds per-step routing entropy and prevents a small expert subset from absorbing all load.
- ACR regulates per-expert capacity so overloaded experts shed gracefully rather than dropping tokens.
- **Invariants asserted (control `rte-01`):** routing entropy ≥ floor, load ratio ≤ ceiling, drop
  rate ≈ 0. → `governance_artifacts/routing/` simulator + pytest. Verified output:
  `entropy=0.995 load_ratio=1.250 drop=0.0000`.

This directly serves EU AI Act Art. 15 (robustness/accuracy) and SR 11‑7 (model performance
monitoring).

---

## 5. Containment & safety: TLA+-verified control discipline (Tier A / D)

The **SentinelContainmentProtocol** and **SIP v3.0** safety invariants are formalized in TLA+ and
exhaustively model-checked with TLC.

| Property | Meaning | Model | TLC result |
|----------|---------|-------|------------|
| `TrippedStaysTripped` | Kill-switch is a **one-way ratchet**; once tripped it cannot silently clear | `SentinelContainmentProtocol.tla` | 75 states, no error |
| `KillSwitchIntegrity` | Switch cannot be reset by an unauthenticated step | same | ✓ |
| `NoUnsanctionedHighRisk` | No high-risk action proceeds without sanction | same | ✓ |
| Containment ratchet + terminal-actuation quorum | dual-control on terminal actions | `KillSwitchAbstract.tla` | 13 states, no error |
| Attested admission | no T0 workload runs un-attested | `AdmissionWithAttestation.tla` | 64 states, no error |

**Re-arm discipline:** containment can only be re-armed via a *fresh, authenticated* heartbeat under
CASO authority — mirrored on-chain by `OmegaActualTreatyEngineHardened.rearm()`.

**Honesty (Tier D):** these models prove properties *of the modelled system*. They are a rigorous
operational safety net, **not** a guarantee against a system that can manipulate its own attestation
or operators. The models are *living artifacts*: re-checked on every capability step-change.

---

## 6. Telemetry attestation, G‑SRI & 24h perpetual assurance (Tier A/B)

- **24h monitor** (`omni_sentinel_24h_monitor.py`) computes the **Global Systemic Risk Index
  (G‑SRI)** each interval, verifies TEE/TPM attestation (`PCR_MATCH`), and commits WORM audit
  batches. Verified: it runs, emits checkpoints, and logs via the PQC WORM logger.
- **G‑SRI formulation (v1.1):** a weighted composite of *interconnectedness, substitutability,
  complexity, concentration* (BCBS G‑SIB-style factor families), with a latency/operational penalty.
  Default intervention **threshold = 85.0**; crossing it raises `THRESHOLD_EXCEEDED` and routes to
  the supervisory plane.
- **Perpetual assurance pattern:** continuous attestation + continuous policy evaluation +
  continuous WORM-anchored evidence, so a regulator can pull a verifiable state *at any instant*,
  not just at audit time.

---

## 7. Post-quantum WORM audit logging (Tier A/B)

- **Signatures:** every audit event is signed with **ML‑DSA‑65 (FIPS 204 / CRYSTALS‑Dilithium)**;
  **SPHINCS+ (FIPS 205)** is the stateless-hash-based backstop for long-retention / signer-key-loss
  scenarios. → `pqc_worm_logger_v2.py` (real `dilithium-py` signatures + tamper-evident hash chain).
- **Immutability:** **Kafka** ingest → **S3 with Object Lock (COMPLIANCE mode)** for WORM retention;
  Merkle-anchored batches give compact inclusion proofs.
- **Verified:** signatures + hash chain verify; **tampering is detected** (assurance step 9).
- **Maps to:** EU AI Act Art. 12 (record-keeping), DORA (ICT logging), evidence for SR 11‑7.

---

## 8. Zero-knowledge systemic-risk proofs & relayer pipelines (Tier A → C)

- **SRC‑1 concentration bound:** a Circom/Groth16 circuit proves a portfolio's **HHI concentration
  is below a regulatory bound without revealing positions**. Verified: compliant proof accepted, a
  violation fixture **rejected** (soundness) — assurance step 6.
- **Relayer pipeline:** `run_relayer_pipeline.sh` closes the loop to on-chain enforcement:
  proof → `snarkjs zkey export solidityverifier` → **Solidity Groth16 verifier (1663 bytes,
  compiles)** → ABI-encoded `verifyProof(...)` calldata a relayer submits to the OmegaActual layer.
- **zkML / transition-validity (Tier C):** the same proof discipline extends to *zkML*
  transition-validity circuits — proving a model produced an output under an attested weight-set and
  policy — and to proving state transitions are policy-valid. Production latency is the open problem.
- **Migration to zk‑STARKs (Tier C):** removes the Groth16 trusted-setup ceremony (transparent
  setup), at the cost of larger proofs; planned for Basel/SR systemic proofs in Phase 4.
- **Regulatory anchors:** Basel III/IV (concentration & op risk), SR 11‑7 / **SR 26‑2** (model risk
  governance of the proving pipeline itself).

---

## 9. Compliance-as-code: OSCAL 1.1.2 + OPA/Rego (Tier A)

- **OSCAL 1.1.2** catalogs encode every control machine-readably
  (`oscal/catalog_sentinel_v24_env_rte.json`: ENV + RTE groups, each backed by a runnable artifact).
- **OPA/Rego** gates enforce them at decision time (default-deny, `import rego.v1`, 21/21 tests). The
  fairness gate is one of three **GC‑IR cross-targets** (policy ⇔ Circom circuit ⇔ TLA+ fixture) —
  divergence fails the build (assurance step 5).

### 9.1 Multi-jurisdictional compliance mapping (engineering interpretation, not legal advice)

| Regime / clause | Obligation (summary) | Evidence artifact | Control |
|-----------------|----------------------|-------------------|---------|
| **EU AI Act** Annex IV | Technical documentation of high-risk system | OSCAL catalog + impl plan + this doc | catalog-wide |
| EU AI Act Art. 12 | Automatic record-keeping / logging | PQC WORM logger (Dilithium + WORM) | `cry-02` |
| EU AI Act Art. 13 | Transparency of automated decisions | fairness reason-code policy | GC-IR `ob-ecoa-…` |
| EU AI Act Art. 14 | Human oversight | release gate quorum ≥ 2; containment model | `con-04/07` |
| EU AI Act Art. 15 | Accuracy, robustness, cybersecurity | StaR-MoE invariants; attestation gate; IaC hardening | `rte-01`, `env-01` |
| **NIST AI RMF** (Govern/Map/Measure/Manage) | AI risk-management function | OPA gates + assurance suite + this plan | catalog-wide |
| **ISO/IEC 42001** (AIMS) | AI management system controls | OSCAL controls + policy reviews | A.6/A.7 |
| **Basel III/IV** | Capital/risk: model & concentration risk | Groth16 HHI proof; G-SRI | `cry-05` |
| **DORA** Art. 9/11 | ICT protection & resilience testing | Terraform/HSM; TLA+ resilience; WORM | `env-01/02` |
| **NIS2** Art. 21 | Cybersecurity risk-management measures | enclave substrate; dashboard hardening | infra/L0 |
| **GDPR** Art. 22 | Rights re: automated decisions | reason-code policy + consent ledger | GC-IR |
| **MAS/HKMA FEAT** | Fairness, Ethics, Accountability, Transparency | fairness gate + CAE/interpretability (next-app `lib/ai`) | GC-IR |
| **FCA SMCR** | Senior-manager accountability | named T0/T1 owners (roadmap exit-criteria); dual-control | `con-04` |
| **ECOA** | Adverse-action reason codes | `fairness_credit_decision.rego` (≥ 2 codes) | GC-IR |
| **ICGC / GASO** | (speculative regimes) | tagged `feasibility-tier` D in OSCAL — modelled only | n/a |

---

## 10. Federated collective defense: GIEN & SIP v3.0 (Tier A/C/D)

- **GIEN (Governance Intelligence Exchange Network):** a canonical, signed governance-event record
  (`gien-governance-event.schema.json`) lets institutions and supervisors share *attested* incidents,
  decisions, and overrides with cryptographic provenance — without sharing raw models or PII.
- **SIP v3.0 (Sentinel Interoperability Protocol):** the transport + handshake for collective
  defense — institutions exchange zk systemic-risk proofs and containment signals; supervisors run
  cross-institution correlation. Telemetry latency target ≤ 50 ms (roadmap Phase 4 exit criterion).
- **Tier note:** the event schema and proof formats are Tier A; a *federated clearing utility* across
  many G‑SIFIs and regulators (governance, antitrust, data-residency) is Tier C/D.

---

## 11. DevSecOps / GitOps posture (Tier A/B)

- **GitOps:** desired-state config (OPA bundles, OSCAL catalogs, Terraform, enclave manifests) lives
  in Git; **ArgoCD/Flux** reconcile clusters to the signed, reviewed state — no out-of-band changes.
- **Policy/assurance in CI:** `.github/workflows/runnable-assurance.yml` runs the 11-check suite on
  every PR; a red check blocks merge. This makes the governance controls themselves
  *continuously regression-tested*.
- **Supply-chain:** signed images, SBOMs, and enclave golden-measurement updates flow through the
  same reviewed GitOps path; ML‑DSA signing of release bundles ties deployment to the PQC audit plane.

---

## 12. Security & compliance review patterns (Tier A)

The program institutionalizes *falsifiable* reviews — every finding is backed by a test that fails
on the vulnerable code and passes on the fix:

| Surface | Review | Evidence |
|---------|--------|----------|
| OmegaActual / Omni-Sentinel **Solidity** | `contracts/SECURITY_REVIEW.md` (SEC-01..06) | hardened contract compiles clean; 7/7 logic tests prove exploit & fix |
| **OPA/Rego** policy modules | `governance_artifacts/rego/POLICY_REVIEW.md` | 21/21 tests; default-deny; cross-target checked |
| **React** dashboards | `next-app/DASHBOARD_SECURITY_REVIEW.md` (DASH-01..08) | 5/5 falsifiable vitest checks (IDOR consent, unenforced moderation, etc.) |

These patterns are reusable templates for reviewing any new contract, policy, or UI added over the
decade.

---

## 13. Phased decadal roadmap (2026 → 2035)

This roadmap is the human-readable companion to the machine-readable
`governance_blueprint/roadmap_2026_2035.yaml`, which now carries **all nine phases (0–8) as
first-class segments** — each with `feasibility_tier`, `objectives`, and `exit_criteria` (and, for
the Tier C/D phases, an explicit `gating` precondition). Exit criteria below match that file so the
two cannot drift.

| Phase | Period | Theme | Key objectives | Hard exit criteria | Dominant tier |
|-------|--------|-------|----------------|--------------------|---------------|
| **0** | 2026 H2 | Foundational hardening | AI Constitution v1; full model/agent inventory; Sentinel v2.4 baseline; ML‑DSA PQC audit plane | inventory ≥ 98%; T0/T1 named owners 100%; Annex IV baseline; PQC verify pass | A |
| **1** | 2027 | Policy/spec industrialization | controls → Rego v2; TLA+ on critical workflows; ICGC compute registry; SARA/StaR‑MoE on | T0/T1 policy-gate coverage 100%; traceability complete; MoE drift index ≤ 0.1 | A/B |
| **2** | 2028 | Containment & perpetual assurance | containment rings; 24×7 GAI‑SOC; Red‑Dawn sims; HW kill-switch PCR_MATCH | critical-breach MTTC ≤ 60 s; T0/T1 telemetry 100%; WORM integrity 100%; HW-attest failure ≤ 0.1% | A/B |
| **3** | 2029 | Prudential stress | G‑SRI v1.1; annual Basel-style stress; **zk systemic-risk proofs live**; ACR autonomous compliance routing | stress pack ≤ 20 business days; 0 unresolved criticals; zk verify pass | A/C |
| **4** | 2030 | Supervisory interoperability | **SIP v3.0** collective defense; automated ARRE/VaR OSCAL delivery; **Sentinel/ASI v4.0** full rollout | ≥ 98% supervisory requests via API; manual dossier ≤ 2%; SIP latency ≤ 50 ms | B/C |
| **5** | 2031–2032 | Dynamic risk budgeting | formal-constraint risk budgets with zk proofs | risk-budget breaches provable & bounded | C |
| **6** | 2033 | Shared incident utility | GIEN systemic-incident intelligence utility | multi-institution attested event exchange live | C/D |
| **7** | 2034 | Multi-regulator sandboxes | coordinated simulation sandboxes (NIST AI 600‑1 aligned) | cross-regulator sim cadence established | C/D |
| **8** | 2035 | Near-real-time cross-border supervision | ISO/IEC 42001-certified; ASA deployment | near-real-time cross-border prudential supervision | C/D |

**Sequencing logic:** earlier phases are dominated by Tier A work *already verified in this repo*;
Tier C/D ambitions in 2031+ are gated on standards maturation (zk‑STARK production tooling,
multi-regulator data-sharing law) and explicit go/no-go reviews.

---

## 14. 2028 G‑SIFI pilot deployment (6 months) — the proof point

The decade's credibility hinges on one disciplined pilot. Design:

**Scope:** 1 lead G‑SIFI + 1 prudential supervisor (observer). 2–3 T1 use-cases
(e.g. credit underwriting, AML triage, market-risk model monitoring). One region pair for the
confidential-enclave fleet.

**Timeline (6 months, two-week cadence):**

| Month | Milestone | Acceptance gate |
|-------|-----------|-----------------|
| 1 | Stand up enclave substrate (Terraform), attestation verifier, OPA decision service | `terraform validate` clean in pilot account; first `PCR_MATCH=TRUE` admission |
| 2 | Onboard 2–3 T1 use-cases behind release/credit/fairness gates; wire StaR‑MoE | 100% T1 decisions pass through OPA; MoE drift ≤ 0.1 |
| 3 | Turn on 24h monitor + G‑SRI + PQC WORM (Kafka/S3 Object Lock) | WORM integrity 100%; tamper test detected |
| 4 | Containment dry-runs (Red‑Dawn); dead-man's-switch + rearm rehearsals | MTTC ≤ 60 s; ratchet behaves per TLA+ model |
| 5 | First zk systemic-risk proof (HHI) submitted via relayer; OSCAL dossier auto-assembled | proof verified on-chain (testnet); dossier ≥ 98% automated |
| 6 | Supervisor read-only access to compliance dashboards + GIEN events; pilot report | supervisor signs off on evidence reproducibility |

**Pilot exit / go-decision:** all six gates green + an independent reproduction of
`run_runnable_assurance.sh` (11/11) in the pilot environment.

> **Runnable checklist.** These gates are operationalized as
> `governance_artifacts/pilot/run_pilot_acceptance_gates.py`. It *actually executes* the
> Tier‑A gates (Terraform validate, OPA gates, PQC WORM tamper test, containment TLC, zk
> relayer, full assurance suite) and reports the Tier‑B/hardware gates as `PENDING-EVIDENCE`
> with their precise acceptance criteria — it never fakes a manual gate. Current state:
> **6/6 automated gates PASS**, 6 manual/Tier‑B evidence items outstanding.

**Pilot risks & mitigations:** real attestation hardware lead-time (mitigate: start Tier B
procurement in 2027); supervisor data-residency constraints (mitigate: GIEN shares only signed
events/proofs, never raw data/PII); trusted-setup concern (mitigate: document zk‑STARK migration
path up front).

---

## 15. Supervisory adoption model

Move supervisors from *periodic document review* to *continuous verifiable assurance*:

1. **Observer (pilot, 2028):** read-only dashboards + reproducible assurance suite.
2. **Evidence-consumer (2029–2030):** supervisor pulls OSCAL dossiers and zk proofs via API
   (Phase 3/4 exit criteria: ≥ 98% requests via API, ≤ 2% manual assembly).
3. **Network participant (2031+):** supervisor joins GIEN/SIP for cross-institution correlation and
   coordinated stress sandboxes.

Each step is *opt-in* and backed by the same cryptographic evidence the institution uses internally,
so the supervisor verifies rather than trusts.

---

## 16. Automated compliance dashboards

- **Internal (board/CRO/CISO):** live G‑SRI, attestation health (PCR_MATCH rate), policy-gate
  pass/deny rates, WORM integrity, containment status — sourced from the 24h monitor and OPA decision
  logs. (Implemented as the Sentinel governance console in `next-app/`; its API surface has a
  completed security review with prioritized remediations — see §12.)
- **Supervisory (SCP v3.0):** OSCAL-dossier views, zk-proof verification status, GIEN event stream.
- **Evidence integrity:** every dashboard tile is traceable to a WORM-anchored, ML‑DSA-signed record;
  nothing on a governance dashboard is unbacked.

---

## 17. Program-level KPIs & KRIs

| Metric | Target by phase | Source |
|--------|-----------------|--------|
| Model/agent inventory coverage | ≥ 98% (P0) | inventory system |
| T0/T1 policy-gate coverage | 100% (P1) | OPA decision logs |
| MoE routing drift index | ≤ 0.1 (P1) | StaR-MoE telemetry |
| Critical-breach MTTC | ≤ 60 s (P2) | GAI-SOC |
| WORM audit integrity | 100% (P2) | PQC WORM logger |
| HW-attestation failure rate | ≤ 0.1% (P2) | attestation verifier |
| zk systemic-risk proof verify | pass (P3) | relayer pipeline |
| Supervisory requests via API | ≥ 98% (P4) | SCP v3.0 |
| Assurance suite | 11/11 PASS every PR | CI workflow |

KRIs (escalation triggers): G‑SRI ≥ 85, PCR_MATCH rate < 99.9%, any WORM-chain break, any TLA+
invariant counterexample on a model re-check after a capability change.

---

## 18. Residual risk & explicit limitations

- **Containment is control discipline, not a safety proof** for arbitrarily capable agents (Tier D).
  The TLA+ guarantees hold for the *modelled* system only.
- **Tier B reality gap:** live TDX/SEV‑SNP attestation, CloudHSM, and production Kafka/S3 WORM are
  verified here only at the policy/IaC layer; end-to-end requires hardware + vendor accounts.
- **Trusted setup:** Groth16 systemic-risk proofs carry a ceremony trust assumption until the
  zk‑STARK migration (Tier C, Phase 4+).
- **Dashboard MVP:** the React console's High/Medium findings (DASH‑01/02/03/05) must be closed
  before any production or supervisory exposure.
- **Speculative regimes (ICGC/GASO) and the GIEN clearing utility** are Tier C/D — direction of
  travel, not committed deliverables, and gated on legal/standards evolution.

---

## 19. Verification ledger (everything in this plan is re-runnable)

| Claim | Command | Last result |
|-------|---------|-------------|
| Full assurance suite | `bash governance_artifacts/run_runnable_assurance.sh` | **11/11 PASS** |
| OPA policy tests | `opa test governance_artifacts/rego/` | 21/21 PASS |
| Containment model | TLC `SentinelContainmentProtocol` | 75 states, no error |
| Kill-switch ratchet | TLC `KillSwitchAbstract` | 13 states, no error |
| Attested admission | TLC `AdmissionWithAttestation` | 64 states, no error |
| Systemic-risk zk proof | `bash governance_artifacts/zk/run_src1_proof.sh` | verified; violation rejected |
| zk relayer pipeline | `bash governance_artifacts/zk/run_relayer_pipeline.sh` | verifier 1663B, compiles |
| StaR-MoE routing | `python3 governance_artifacts/routing/sara_acr_router.py` | stabilized, drop=0 |
| PQC WORM | `python3 governance_artifacts/kafka/pqc_worm_logger_v2.py` | sign+chain verify; tamper caught |
| Solidity hardening | `node governance_blueprint/contracts/compile.js` + pytest | 0 warnings; 7/7 |
| Terraform IaC | `terraform validate` (in `governance_blueprint/terraform/`) | Success |
| 24h monitor + G-SRI | `python3 omni_sentinel_24h_monitor.py` | runs; G-SRI + PCR_MATCH checkpoints |

## 20. Cross-references
- `governance_blueprint/IMPLEMENTATION_PLAN_AND_SAFETY_ARCHITECTURE.md` — layered safety architecture & detailed compliance map.
- `governance_artifacts/RUNNABLE_ASSURANCE.md` — the 11-check assurance suite, control-by-control.
- `governance_blueprint/roadmap_2026_2035.yaml` — machine-readable phase/exit-criteria source of truth.
- `governance_blueprint/contracts/SECURITY_REVIEW.md`, `next-app/DASHBOARD_SECURITY_REVIEW.md`, `governance_artifacts/rego/POLICY_REVIEW.md` — security reviews.
- `docs/schemas/gien-governance-event.schema.json` — GIEN canonical event schema.

> **Final integrity note.** This is an engineering and program plan, not legal advice or a safety
> guarantee. Tier A claims are reproducible today; Tier B/C/D items are explicitly contingent. The
> single most important discipline of this program is that **governance evidence is verifiable, not
> asserted** — `run_runnable_assurance.sh` must stay green for the lifetime of the deployment.
