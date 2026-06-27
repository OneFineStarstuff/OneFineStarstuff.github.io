# DORA ICT-Risk Register (auto-assembled, AI-governance scope)

- **Framework:** DORA — Regulation (EU) 2022/2554
- **Generated:** 2026-06-27T12:40:46Z
- **Generator:** `governance_artifacts/oscal/generate_dora_ict_register.py`
- **Source catalogs:** catalog_sentinel_v24_excerpt.json, catalog_sentinel_v24_env_rte.json
- **Catalog conformance:** 43 passed, 0 failed
- **Pillars SATISFIED:** 3/5
- **Coverage gaps:** P4, P5

> **Scope.** This register scopes DORA ICT-risk pillars to the AI-governance control surface of the Sentinel stack only. It is NOT a complete institutional DORA register; enterprise ICT scope (networks, endpoints, core banking) is out of scope here.

> **Integrity statement.** This is a scoped ICT-risk register auto-assembled from OSCAL controls that exist in the named catalogs (conformance verified: 0 failures) and assurance checks executed in this run. A pillar is SATISFIED only when a mapped control's runnable check passed here. Pillars P4/P5 are reported as coverage gaps for this control surface. It is NOT a DORA conformity attestation and does not assert institutional DORA compliance.

## P1 — ICT risk management framework (Arts. 5-16)

**Evidence status:** ✅ SATISFIED

Hardware-attested admission and enclave-bound key custody establish the ICT control baseline for the AI execution environment; PQC-signed evidence protects the integrity of the risk-management record.

| Control | Tier | SLA | Backing check | Result |
|---------|------|-----|---------------|--------|
| `env-01` Hardware-attested admission for T0/T1 workloads | A | PT5M | TLA+ AdmissionWithAttestation (no T0 run without valid attestation) (model-checked) | PASS |
| `env-02` Enclave-bound key custody for evidence signing | B | - | Enclave-bound PQC key custody (hardware-dependent) (organisational-record-PENDING) | n/a (organisational) |
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | P1D | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS |

## P2 — ICT-related incident management, classification & reporting (Arts. 17-23)

**Evidence status:** ✅ SATISFIED

The tamper-evident PQC WORM audit log provides the append-only, cryptographically verifiable incident record DORA requires; containment reachability ensures incidents can be terminally actuated.

| Control | Tier | SLA | Backing check | Result |
|---------|------|-----|---------------|--------|
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | P1D | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS |
| `con-04` Verified kill-switch reachability for contained workloads | A | P1D/P90D | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS |

## P3 — Digital operational resilience testing (Arts. 24-27)

**Evidence status:** ✅ SATISFIED

The containment kill-switch ratchet is verified by model checking (daily reachability) and by quarterly live-actuation testing on canaries — DORA advanced-testing evidence for the terminal AI risk control.

| Control | Tier | SLA | Backing check | Result |
|---------|------|-----|---------------|--------|
| `con-04` Verified kill-switch reachability for contained workloads | A | P1D/P90D | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS |
| `con-07` ASA one-way containment ratchet | A | P7D | TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate) (model-checked) | PASS |

## P4 — ICT third-party risk management (Arts. 28-44)

**Evidence status:** ⏳ PENDING-EVIDENCE  _(coverage gap — no in-scope control)_

Third-party / GPAI-provider assurance (supplier attestation, contractual auditability, exit plans) is an organisational control surface not yet represented by a runnable Sentinel control — reported as a coverage gap.

_No runnable Sentinel control maps to this pillar; this is an organisational / design-stage area outside the modelled surface._

## P5 — Information & intelligence sharing (Art. 45)

**Evidence status:** ⏳ PENDING-EVIDENCE  _(coverage gap — no in-scope control)_

Cross-institution threat/intelligence sharing maps to the GIEN / SIP v3.0 federated layer (Tier C, design-stage); no Tier-A runnable control backs it yet — reported as a coverage gap.

_No runnable Sentinel control maps to this pillar; this is an organisational / design-stage area outside the modelled surface._
