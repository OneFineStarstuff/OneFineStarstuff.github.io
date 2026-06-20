# OPA / Rego Policy Module Review — Sentinel Assurance Set

**Scope:** `governance_artifacts/rego/*.rego` (the policies exercised by the runnable
assurance suite). The broader `artifacts/policies/*.rego` library (EU AI Act, Basel III,
SR 11‑7, GDPR, ISO 42001, NIST AI RMF, OECD, fair lending) is referenced but reviewed
here only for structure, since those are catalogue/reference modules.

**Tooling:** OPA v0.70.0. **Result:** `opa test governance_artifacts/rego/` → **21/21 PASS**.

| Module | Package | Control backing | Posture |
|--------|---------|-----------------|---------|
| `attestation_gate.rego` | `sentinel.attestation` | OSCAL env-01 (HW-attested exec), PCR_MATCH | Strong |
| `release_gate.rego` | `sentinel.release` | SAF-OMNI-001, MOD-SR11-7-VAL, containment | Strong |
| `high_impact_credit.rego` | `gsifi.ai.credit` | SR 11‑7, EU AI Act Art.14, ECOA | Strong |
| `fairness_credit_decision.rego` | `fairness.credit_decision` | GC-IR ob-ecoa-adverse-reason-codes (ECOA / GDPR Art.22 / EU AI Act Art.13) | Strong (cross-target) |

## What is correct (kept)
1. **Fail-closed by construction.** Every decision module declares
   `default allow := false`. Empty/garbage input denies (proven by
   `test_default_deny_on_empty_input`).
2. **`import rego.v1`** everywhere — future-proof against OPA 1.0 syntax breakage;
   no deprecated iteration or implicit `else` ambiguity.
3. **Conjunctive admission.** `release_gate` requires *all* of: high-tier control set,
   dual-control quorum (`>= 2`), `containment.mode == "ENFORCED"`, and verified
   signature bundle. No single-attribute bypass.
4. **Attestation gate is genuinely defensive.** It denies on unsupported platform,
   invalid report signature, replayed nonce, non-golden measurement, **TCB rollback**,
   PCR mismatch, and invalid vTPM quote — each with a dedicated passing test. This is
   the policy-level enforcement of the SEV-SNP/TDX + vTPM story.
5. **Cross-target consistency.** `fairness_credit_decision.rego` is one of three
   emission targets (Rego ⇔ Circom witness ⇔ TLA+ fixture) checked by
   `zk/gcir_harness.py`; divergence fails the build. This is the strongest property
   in the set — the policy cannot silently disagree with the proof circuit.

## Findings / recommendations (non-blocking)
- **POL-01 (Low):** `release_gate.deny` emits a single generic message. For Annex IV
  auditability, prefer one `deny` rule per unmet condition (per-reason messages), as
  `high_impact_credit` already does. Improves explainability of *why* a release blocked.
- **POL-02 (Low):** `attestation_gate` freshness depends on the caller passing
  `nonce_fresh`/`reported_tcb`; the policy correctly checks them but cannot itself
  measure wall-clock freshness. Document that the verifier (not the policy) owns the
  freshness window, so reviewers don't assume the policy is the clock.
- **POL-03 (Info):** The large `artifacts/policies/` library overlaps conceptually with
  the assurance set (e.g. multiple EU AI Act modules). Recommend a single source-of-truth
  map (which module is authoritative for which control) to avoid drift between the
  catalogue policies and the tested assurance policies.

## Verdict
The assurance-set Rego is production-shaped: default-deny, versioned, control-mapped,
fully tested, and — uniquely — cross-checked against the zk circuit and TLA+ model.
The recommendations are quality/auditability improvements, not security gaps.
