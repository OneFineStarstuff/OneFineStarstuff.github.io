package aigov.release

# Deny by default.
default allow = false

# Baseline requirements for all models.
baseline_requirements {
  input.model_card_exists
  input.security_scan_passed
  input.policy_bundle_hash_approved
}

# Low/medium risk release path.
allow {
  input.risk_tier <= 2
  baseline_requirements
}

# High-risk release path.
allow {
  input.risk_tier >= 3
  baseline_requirements
  input.independent_validation_approved
  input.legal_compliance_approved
  input.explainability_test_passed
  input.human_oversight_plan_approved
}

# Additional controls for frontier/special risk systems.
allow {
  input.risk_tier == 4
  baseline_requirements
  input.independent_validation_approved
  input.legal_compliance_approved
  input.explainability_test_passed
  input.human_oversight_plan_approved
  input.safety_case_approved
  input.containment_controls_verified
  input.executive_signoff
}
