package aigov.agent_lifecycle

default allow_deploy = false

allow_deploy {
  input.risk_tier <= 2
}

allow_deploy {
  input.risk_tier >= 3
  input.validation_approved
  input.safety_case_approved
}
