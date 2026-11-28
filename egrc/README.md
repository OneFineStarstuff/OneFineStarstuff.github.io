# EGRC: Evidence-Gated Release Control (v1.0, WP-129)

> FICTIONAL GOVERNANCE SIMULATION: GIEN, Omni-Sentinel, CFE-1.0, Protocol SGR-028,
> and every lever, quorum, and hash in this directory are simulated artefacts.
> Real-world frameworks (EU AI Act, DORA, SEC Rule 17a-4, NIST FIPS 203/204/205,
> SLSA v1.2, OpenSSF OMS, OSCAL 1.1.2, SR 26-2) are cited as design mappings only.

EGRC makes release state changes supervisory acts: no release state change exists
without a sealed evidence trail, a valid quorum, and a frozen cryptographic proof,
and no quarter passes without exactly one deliberate change per track and one
formal acceptance decision.

## Constitutional directives

1. **One Decision.** Exactly one formal exit decision per track per quarter:
   ACCEPT, CONDITIONALLY ACCEPT, or REJECT. Sealed decisions are immutable; a
   quarter ending without a sealed decision defaults to REJECT (fail-closed).
2. **One Quarter.** The unit of change and the unit of judgement are both the
   calendar quarter.
3. **One Lever.** At most one control lever armed and promoted per track per
   quarter. A lever that cannot be stated as one change is not one lever.
4. **Guard the Invariants.** The invariant set holds in every state; weakening
   a control or invariant requires CLASS_1 treatment.
5. **Honor the Quorum.** Promotion authority comes only from signed, replayable,
   WORM-recorded approval artefacts. Quorums fail closed.
6. **Transmit the Proof.** Every transition emits a signed ledger event inside
   its window and transmits on the standing supervisory channels.

## Files

| File | Purpose |
| --- | --- |
| `levers.yaml` | Lever Register: tracks, lever classes, quorum rules, invariant enforcement map, the lever list (seeded with L-Q2027-Q1-01, PROPOSED) |
| `classification.yaml` | Classification manifest for invariant I-10 (SR 26-2 model vs EU AI Act AI-system boundary, with documented NEITHER rationales) |
| `policies/egrc_single_lever.rego` | I-1: one armed/promoted lever per track per quarter |
| `policies/egrc_fail_closed.rego` | I-9 (+ I-4, I-5): missing, malformed, or failed inputs deny; hash format and chain-link checks |
| `policies/egrc_classification.rego` | I-10: recorded, valid classification per component; NEITHER requires rationale |
| `policies/egrc_monotonic.rego` | I-12: no lever weakens an active control or invariant |

## Lever classes and quorums

| Class | Definition | Quorum |
| --- | --- | --- |
| CLASS_3 | Mechanical, reversible, no invariant surface | Two-approval engineering quorum |
| CLASS_2 | Changes enforcement posture on one track | Two-approval engineering quorum plus college notification |
| CLASS_1 | Constitutional scope (invariants, classes, quorum rules, key schedules, control retirement) | Five-of-five college quorum plus rotating devil's advocate review |

## Policy evaluation

Evaluate with OPA (pinned via the fail-closed quorum path, see the WP-119
`opa-pin-proposal` workflow and lever L-Q2027-Q1-01):

```
opa eval -d egrc/policies -i transition-input.json 'data.ecrc.single_lever'
```

All policies default to `allow = false`; an evaluation failure, timeout, or
absent policy denies the transition (I-9). Example transition input:

```json
{
  "transition": "ARM",
  "lever": { "id": "L-Q2027-Q1-01", "track": "T-POLICY", "quarter": "2027-Q1", "effect": "STRENGTHEN" },
  "levers": [],
  "quorum_proof": { "status": "VALID", "artefacts": ["approval-1", "approval-2"] },
  "evidence_bundle": { "merkle_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "chain_linked": true },
  "components": [{ "id": "opa-policy-plane", "classification": "NEITHER", "rationale": "deterministic policy evaluation" }]
}
```

## Quarterly cadence (reference: 2027-Q1)

Proposal freeze 2027-01-04, quorum deadline 2027-01-11, arm and promote
2027-01-15, evidence window to the compendium seal 2027-03-25, exit decision
session 2027-03-29 to 2027-03-31, decision published 2027-03-31.

## Exit decision options

- **ACCEPT.** All Tier-1 criteria pass; invariants held all window; evidence
  complete; zero unremediated deviations; no break-glass events.
- **CONDITIONALLY ACCEPT.** All Tier-1 criteria pass with at most three Tier-2
  deviations, each with an owner, a remediation deadline inside the next
  quarter, and a re-verification step. Break-glass usage forces at least this
  outcome.
- **REJECT.** Any Tier-1 failure, invalid or unreplayable quorum, evidence gap,
  chain break, or the missing-decision default. The lever reverts to its
  pre-arm state and re-enters a later quarter as a fresh lever.

## Deliberate scope boundary

This package ships the register, the classification manifest, and the Rego
encodings only. Wiring the policies into the CI trust-gate workflow is a
separate lever (warn-then-enforce, CLASS_2) so that this PR keeps the one-WP-
per-PR discipline and touches no workflow YAML until the quoting fix in PR
#286 lands. Remaining follow-ups: e2e wiring, quarterly compendium template,
and the vkFMv3-to-vkFMv4 rotation draft (CLASS_1).
