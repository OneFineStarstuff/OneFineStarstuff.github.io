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

Runs all five checks below and fails fast on any error.

## What is proven, and against which control

| # | Check | Tool | Backs OSCAL control | Regime anchor |
|---|-------|------|---------------------|---------------|
| 1 | Deny-by-default release gate + high-impact credit gate | `opa test` (12 tests) | release-gate semantics; `con-07` quorum | SR 11-7, EU AI Act Art. 14, ECOA, GDPR Art. 22 |
| 2 | Containment one-way ratchet & terminal-actuation quorum | TLA+ `tlc2.TLC` | `con-04`, `con-07` | EU AI Act Art. 14, DORA resilience testing |
| 3 | GC-IR cross-target conformance (policy ⇔ circuit ⇔ expectation) | `opa eval` + Circom witness | obligation `ob-ecoa-adverse-reason-codes` | ECOA, GDPR Art. 22, EU AI Act Art. 13 |
| 4 | Systemic-risk concentration bound (HHI) zk proof | Circom + Groth16 (snarkjs) | `cry-05` | Basel op-risk, systemic telemetry |
| 5 | Governance artifact schema validation | Python validator | manifest/schema integrity | OSCAL, evidence logging (EU AI Act Art. 12) |

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
pip install pyyaml jsonschema
# Run everything
bash governance_artifacts/run_runnable_assurance.sh
```

> Sandbox note: compile circuits with `--O0` if circom raises a `SystemTimeError`
> during constraint simplification (a known clock-skew issue in some containers).
