package aigov.systemic

default allow = false

# Threshold-based allowance for G-SRI
allow if {
  input.gsri < 0.75
  input.validation.approved
  input.monitoring.enabled
  input.attestation.pcr_match == true
}

# Tier 4 (Frontier/AGI) specific requirements
allow if {
  input.risk_tier >= 4
  input.gsri < 0.60 # Stricter for high-impact
  input.validation.approved
  input.safety_case.approved
  input.containment.lab_certified
  input.crisis_simulation.last_run_days <= 90 # More frequent drills
  input.compute_registry.registered
  input.systemic_risk_committee.signoff
  input.jurisdictional_pack.complete
  input.high_assurance_rag.provenance_enforced
  input.attestation.pcr_match == true
}

deny contains msg if {
  input.gsri >= 0.75
  msg := "Systemic risk threshold exceeded: G-SRI breach"
}

deny contains msg if {
  input.risk_tier >= 4
  input.gsri >= 0.60
  msg := "Frontier safety margin breach: G-SRI exceeds 0.60"
}

deny contains msg if {
  input.attestation.pcr_match == false
  msg := "Hardware attestation failed: PCR mismatch detected"
}
