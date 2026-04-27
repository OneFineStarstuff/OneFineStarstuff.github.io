package sentinel.governance

default allow = false

allow if {
  input.risk_tier != "TIER_3"
  input.policy_checks.passed
  not input.sanctions_block
}

allow if {
  input.risk_tier == "TIER_3"
  input.policy_checks.passed
  input.dual_authorization
  input.human_override_available
  not input.sanctions_block
}

violation[msg] if {
  input.risk_tier == "TIER_3"
  not input.dual_authorization
  msg := "tier_3_requires_dual_authorization"
}

violation[msg] if {
  not input.human_override_available
  msg := "human_override_must_be_available"
}
