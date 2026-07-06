package aigov.systemic

default allow = false

allow if {
  input.risk_tier <= 2
  input.validation.approved
  input.monitoring.enabled
}

allow if {
  input.risk_tier == 3
  input.validation.approved
  input.monitoring.enabled
  input.explainability.enabled
  input.change_control.release_approved
}

allow if {
  input.risk_tier >= 4
  input.validation.approved
  input.safety_case.approved
  input.containment.lab_certified
  input.crisis_simulation.last_run_days <= 180
  input.compute_registry.registered
  input.systemic_risk_committee.signoff
  input.jurisdictional_pack.complete
  input.high_assurance_rag.provenance_enforced
}

deny contains msg if {
  input.risk_tier >= 4
  not input.safety_case.approved
  msg := "Frontier deployment blocked: safety case approval missing"
}

deny contains msg if {
  input.risk_tier >= 4
  not input.compute_registry.registered
  msg := "Frontier deployment blocked: compute registry declaration missing"
}

deny contains msg if {
  input.risk_tier >= 4
  input.crisis_simulation.last_run_days > 180
  msg := "Frontier deployment blocked: crisis simulation stale"
}

deny contains msg if {
  input.risk_tier >= 4
  not input.jurisdictional_pack.complete
  msg := "Frontier deployment blocked: jurisdictional compliance pack incomplete"
}

deny contains msg if {
  input.risk_tier >= 4
  not input.high_assurance_rag.provenance_enforced
  msg := "Frontier deployment blocked: high-assurance RAG provenance control missing"
}
