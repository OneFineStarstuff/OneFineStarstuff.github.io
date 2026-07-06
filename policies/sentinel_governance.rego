package sentinel.governance

# Block production deploy when mandatory evidence is missing.
deny[msg] {
  input.environment == "prod"
  not input.evidence.annex_iv_complete
  msg := "Annex IV evidence incomplete"
}

deny[msg] {
  input.environment == "prod"
  input.model.card_hash != input.model.approved_hash
  msg := "Model card hash mismatch"
}

deny[msg] {
  input.action.class == "high_risk"
  input.explainability.confidence < input.policy.min_confidence
  msg := "Explainability confidence below minimum"
}
