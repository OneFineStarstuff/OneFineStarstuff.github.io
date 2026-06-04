package aigov.eu_ai_act

default allow = false

# Article 14: Human Oversight
allow if {
  input.human_oversight.enabled == true
  input.human_oversight.competency_verified == true
}

# Article 11: Technical Documentation (Annex IV)
allow if {
  input.documentation.annex_iv_complete == true
  input.documentation.last_update_days <= 365
}

# High-Risk System Gating
deny contains msg if {
  input.is_high_risk == true
  not input.human_oversight.enabled
  msg := "EU AI Act Violation: High-risk system requires human oversight (Article 14)"
}

deny contains msg if {
  input.is_high_risk == true
  not input.documentation.annex_iv_complete
  msg := "EU AI Act Violation: Technical documentation (Annex IV) is incomplete (Article 11)"
}
