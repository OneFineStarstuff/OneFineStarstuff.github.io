package sentinel.gien.release

default allow := false

default reasons := ["release denied: required GIEN controls are incomplete"]

allow if {
  lower_tier_release
}

allow if {
  tier_two_release
}

allow if {
  tier_three_release
}

lower_tier_release if {
  input.model.risk_tier < 2
  input.controls.bbom_signed
  input.controls.policy_bundle_digest != ""
  input.telemetry.gai_soc_enabled
}

tier_two_release if {
  input.model.risk_tier == 2
  input.controls.bbom_signed
  input.controls.sr_11_7_validated
  input.controls.annex_iv_complete
  input.controls.fairness_regression_passed
  input.supervision.quorum >= 2
  input.evidence.worm_receipt_committed
}

tier_three_release if {
  input.model.risk_tier == 3
  input.controls.bbom_signed
  input.controls.sr_11_7_validated
  input.controls.annex_iv_complete
  input.containment.mode == "ENFORCED"
  input.supervision.quorum >= 2
  input.formal_methods.tla_invariants_passed
  input.zk.proof_verified
  input.evidence.worm_receipt_committed
  not input.incident_response.open_severity_one
}

reasons := denial_reasons if {
  not allow
  denial_reasons := [reason |
    required_check := required_checks[_]
    not required_check.pass
    reason := required_check.reason
  ]
}

required_checks := [
  {"pass": input.controls.bbom_signed, "reason": "BBOM signature missing"},
  {"pass": input.controls.annex_iv_complete, "reason": "EU AI Act Annex IV evidence incomplete"},
  {"pass": input.evidence.worm_receipt_committed, "reason": "PQC WORM evidence receipt not committed"},
]
