# EU AI Act Annex IV Technical Documentation Dossier (auto-assembled)

- **Annex IV basis:** Regulation (EU) 2024/1689, Annex IV
- **Generated:** 2026-06-29T12:49:50Z
- **Generator:** `governance_artifacts/oscal/generate_annex_iv_dossier.py`
- **Source catalogs:** catalog_sentinel_v24_excerpt.json, catalog_sentinel_v24_env_rte.json
- **Catalog conformance:** 43 passed, 0 failed
- **Sections SATISFIED:** 8/8

> **Integrity statement.** This dossier is auto-assembled only from OSCAL controls that exist in the named catalogs (conformance verified: 0 failures) and from assurance checks executed in this run. A section is marked SATISFIED only when a mapped control's runnable check passed here. It is an assembly-integrity artifact, NOT a conformity assessment, and does not assert the institution is compliant with the EU AI Act.

## Governed models (from registry)

- `gsifi-credit-agent-v7` — credit_underwriting (risk tier: high, status: production)

## Annex IV §A — General system description

**Evidence status:** ✅ SATISFIED

The system is the Sentinel AI Governance Stack v2.4 supervisory control plane mediating high-risk (T0/T1) foundation-model decisions for a G-SIFI. Intended purpose, deployers and risk classification are taken from the model registry; the catalog ENV/RTE/CON/CRY control groups scope the governed surface.

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `env-01` Hardware-attested admission for T0/T1 workloads | A | PT5M | TLA+ AdmissionWithAttestation (no T0 run without valid attestation) (model-checked) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; DORA — ICT risk management framework; NIST AI RMF 1.0 — MEASURE function |
| `rte-01` SARA/ACR routing stabilization invariants | B | P1D | SARA/ACR MoE routing stabilization invariants (simulated) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; SR 11-7 — Supervisory guidance on model risk management |

## Annex IV §B — Design and development specifications

**Evidence status:** ✅ SATISFIED

Routing stability (SARA/ACR) and attested admission are specified as machine-checkable invariants with named TLA+ models and a runnable simulator; design decisions are evidenced by the verified artifacts.

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `rte-01` SARA/ACR routing stabilization invariants | B | P1D | SARA/ACR MoE routing stabilization invariants (simulated) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; SR 11-7 — Supervisory guidance on model risk management |
| `env-01` Hardware-attested admission for T0/T1 workloads | A | PT5M | TLA+ AdmissionWithAttestation (no T0 run without valid attestation) (model-checked) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; DORA — ICT risk management framework; NIST AI RMF 1.0 — MEASURE function |

## Annex IV §C — Data requirements and governance

**Evidence status:** ✅ SATISFIED

Evidence envelopes and consent/lineage records are cryptographically signed and hash-chained; PQC dual-signature (cry-02) protects the governance data plane. Dataset lineage itself is an organisational record (PENDING-EVIDENCE here until the lineage export is attached).

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | P1D | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS | DORA — ICT risk management framework; EU AI Act Article 12 — Record-keeping / automatic logging |

## Annex IV §D — Risk management system

**Evidence status:** ✅ SATISFIED

Systemic-risk concentration (HHI) is bounded by a zk attestation (cry-05) and the global containment ratchet (con-04/con-07) provides the terminal risk control. The G-SRI index drives continuous risk posture.

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `cry-05` Systemic-risk concentration bound zk attestation | B | P3M | SRC-1 Groth16 systemic-risk concentration bound proof (zk-proven) | PASS | Basel III/IV — Operational risk / SMA; GAIRA systemic-telemetry attestation (design fixture) |
| `con-04` Verified kill-switch reachability for contained workloads | A | P1D/P90D | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS | EU AI Act Article 14 — Human oversight; DORA — Digital operational resilience testing; Supervisory scenario — kill-switch actuation (SR 26-2 style); ICGC/GACP containment assurance Level 2 (design fixture) |
| `con-07` ASA one-way containment ratchet | A | P7D | TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate) (model-checked) | PASS | EU AI Act Article 14 — Human oversight |

## Annex IV §E — Post-market monitoring

**Evidence status:** ✅ SATISFIED

Continuous monitoring is provided by the 24h G-SRI monitor and the tamper-evident PQC WORM audit log (cry-02), giving an append-only, verifiable post-market record.

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | P1D | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS | DORA — ICT risk management framework; EU AI Act Article 12 — Record-keeping / automatic logging |

## Annex IV §F — Human oversight measures

**Evidence status:** ✅ SATISFIED

Containment de-escalation and terminal actuation require human dual-control quorum; Autonomous Supervisory Agents can only raise containment, never lower it (con-07 one-way ratchet), with kill-switch reachability verified (con-04).

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `con-07` ASA one-way containment ratchet | A | P7D | TLA+ KillSwitchAbstract one-way ratchet (ASA cannot de-escalate) (model-checked) | PASS | EU AI Act Article 14 — Human oversight |
| `con-04` Verified kill-switch reachability for contained workloads | A | P1D/P90D | TLA+ KillSwitchAbstract reachability / dead-man's switch (model-checked) | PASS | EU AI Act Article 14 — Human oversight; DORA — Digital operational resilience testing; Supervisory scenario — kill-switch actuation (SR 26-2 style); ICGC/GACP containment assurance Level 2 (design fixture) |

## Annex IV §G — Performance and limitations

**Evidence status:** ✅ SATISFIED

Routing-stability thresholds (entropy/load/drop) are explicit and enforced (rte-01); breaches block model-revision promotion. Known limitations and feasibility tiers are carried on each control as OSCAL props.

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `rte-01` SARA/ACR routing stabilization invariants | B | P1D | SARA/ACR MoE routing stabilization invariants (simulated) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; SR 11-7 — Supervisory guidance on model risk management |

## Annex IV §H — Cybersecurity and resilience

**Evidence status:** ✅ SATISFIED

Hardware-attested execution (SEV-SNP/TDX + vTPM PCR_MATCH, env-01), enclave-bound PQC key custody (env-02) and post-quantum signed evidence (cry-02) provide the cybersecurity and operational-resilience posture (aligned to DORA ICT-risk and EU AI Act Art. 15).

| Control | Tier | SLA | Backing check | Result | Regimes |
|---------|------|-----|---------------|--------|---------|
| `env-01` Hardware-attested admission for T0/T1 workloads | A | PT5M | TLA+ AdmissionWithAttestation (no T0 run without valid attestation) (model-checked) | PASS | EU AI Act Article 15 — Accuracy, robustness and cybersecurity; DORA — ICT risk management framework; NIST AI RMF 1.0 — MEASURE function |
| `env-02` Enclave-bound key custody for evidence signing | B | - | Enclave-bound PQC key custody (hardware-dependent) (organisational-record-PENDING) | n/a (organisational) | DORA — ICT risk management framework |
| `cry-02` Hybrid PQC dual-signature on governance event envelopes | A | P1D | PQC WORM audit log (ML-DSA-65 sign + hash chain + tamper detect) (cryptographically-verified) | PASS | DORA — ICT risk management framework; EU AI Act Article 12 — Record-keeping / automatic logging |
