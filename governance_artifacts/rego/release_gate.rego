package sentinel.release

default allow := false

allow if {
  input.model.risk_tier == "high"
  input.controls["SAF-OMNI-001"] == true
  input.controls["MOD-SR11-7-VAL"] == true
  input.supervision.quorum >= 2
  input.containment.mode == "ENFORCED"
  input.signatures.bundle_verified == true
}

deny contains msg if {
  not allow
  msg := "release blocked: containment/quorum/validation requirements not satisfied"
}
