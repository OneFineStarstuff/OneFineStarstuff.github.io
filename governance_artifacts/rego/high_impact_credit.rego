package gsifi.ai.credit

default allow = false

allow if {
  input.model.use_case == "credit_underwriting"
  input.risk_tier == "high"
  input.human_review.completed
  input.explainability.reason_codes_count >= 3
  input.fairness.equal_opportunity_delta <= 0.03
  input.data.lineage.verified
  not input.incident_flags.active
}

deny[msg] if {
  input.model.use_case == "credit_underwriting"
  not input.human_review.completed
  msg := "Human review required for high-impact credit decisions"
}
