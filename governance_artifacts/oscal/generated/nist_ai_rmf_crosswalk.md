# NIST AI RMF 1.0 Profile Crosswalk (auto-assembled)

- **Framework:** NIST AI RMF 1.0 (NIST AI 100-1)
- **Generated:** 2026-06-27T12:40:56Z
- **Generator:** `governance_artifacts/oscal/generate_nist_rmf_crosswalk.py`
- **Source catalogs:** catalog_sentinel_v24_excerpt.json, catalog_sentinel_v24_env_rte.json
- **Catalog conformance:** 43 passed, 0 failed
- **Functions SATISFIED:** GOVERN, MAP, MEASURE, MANAGE (100.0%)
- **Functions uncovered:** none

> **Scope.** This crosswalk maps NIST AI RMF functions to the AI-governance control surface of the Sentinel stack. NIST AI RMF is voluntary guidance; this is a coverage crosswalk, not a certification. Subcategory-level mapping is summarised, not exhaustive.

> **Integrity statement.** This is a coverage crosswalk auto-assembled from OSCAL controls that exist in the named catalogs (conformance verified: 0 failures) and assurance checks executed in this run. A function is SATISFIED only when a mapped control's runnable check passed here. NIST AI RMF is voluntary guidance; this is a coverage crosswalk, NOT a certification or conformity assessment.

## GOVERN — GOVERN — culture, accountability, policies

**Evidence status:** ✅ SATISFIED (2 control(s))

Governance accountability and the one-way containment authority model (ASA can raise but never lower containment; human dual-control for terminal actuation) implement the GOVERN function's accountability and oversight structures.

| Control | Tier | Backing check | Result | Regimes |
|---------|------|---------------|--------|---------|
| `con-07` ASA one-way containment ratchet | A | TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate) (model-checked) | PASS | EU AI Act Article 14 — Human oversight |
| `con-04` Verified kill-switch reachability for contained workloads | A | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS | EU AI Act Article 14 — Human oversight; DORA — Digital operational resilience testing; Supervisory scenario — kill-switch actuation (SR 26-2 style); ICGC/GACP containment assurance Level 2 (design fixture) |

## MAP — MAP — context, categorisation, risk framing

**Evidence status:** ✅ SATISFIED (1 control(s))

Hardware-attested admission categorises and gates T0/T1 workloads by tier and attestation state, framing the operational risk context before execution.

| Control | Tier | Backing check | Result | Regimes |
|---------|------|---------------|--------|---------|
| `env-01` Hardware-attested admission for T0/T1 workloads | A | TLA+ AdmissionWithAttestation (no T0 run without valid attestation) (model-checked) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; DORA — ICT risk management framework; NIST AI RMF 1.0 — MEASURE function |

## MEASURE — MEASURE — analyse, assess, benchmark, monitor

**Evidence status:** ✅ SATISFIED (3 control(s))

Routing-stability invariants (entropy/load/drop) and the zk systemic-risk concentration bound provide quantitative, continuously-measured trustworthiness metrics; PQC WORM gives the measurement audit trail.

| Control | Tier | Backing check | Result | Regimes |
|---------|------|---------------|--------|---------|
| `rte-01` SARA/ACR routing stabilization invariants | B | SARA/ACR MoE routing stabilization invariants (simulated) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; SR 11-7 — Supervisory guidance on model risk management |
| `cry-05` Systemic-risk concentration bound zk attestation | B | SRC-1 Groth16 systemic-risk concentration bound proof (zk-proven) | PASS | Basel III/IV — Operational risk / SMA; GAIRA systemic-telemetry attestation (design fixture) |
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS | DORA — ICT risk management framework; EU AI Act Article 12 — Record-keeping / automatic logging |

## MANAGE — MANAGE — prioritise, respond, recover

**Evidence status:** ✅ SATISFIED (3 control(s))

The verified kill-switch reachability and one-way containment ratchet are the terminal response/recovery controls; breaches block model promotion, operationalising risk response.

| Control | Tier | Backing check | Result | Regimes |
|---------|------|---------------|--------|---------|
| `con-04` Verified kill-switch reachability for contained workloads | A | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS | EU AI Act Article 14 — Human oversight; DORA — Digital operational resilience testing; Supervisory scenario — kill-switch actuation (SR 26-2 style); ICGC/GACP containment assurance Level 2 (design fixture) |
| `con-07` ASA one-way containment ratchet | A | TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate) (model-checked) | PASS | EU AI Act Article 14 — Human oversight |
| `rte-01` SARA/ACR routing stabilization invariants | B | SARA/ACR MoE routing stabilization invariants (simulated) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; SR 11-7 — Supervisory guidance on model risk management |
