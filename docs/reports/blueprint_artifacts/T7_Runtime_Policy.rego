package sentinel.workflow

# T7 Runtime policy starter for regulated workflows.
default allow = false

# Disallow prohibited tier immediately.
allow if {
  input.risk_tier != "prohibited"
  input.control_id == "POL-01"
  not requires_hitl
}

# Require explicit human approval for rights-impacting decisions.
allow if {
  input.risk_tier != "prohibited"
  requires_hitl
  input.hitl_approved == true
  input.hitl_approver_role == "authorized_reviewer"
}

requires_hitl if {
  input.customer_rights_impact == true
}

requires_hitl if {
  input.confidence_score < 0.90
}
