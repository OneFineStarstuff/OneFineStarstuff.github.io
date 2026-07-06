package governance.release

default allow := false

allow if {
  input.tier in {"Tier-1", "Tier-2", "Tier-3"}
  input.validation.independent
  input.monitoring.enabled
  input.security.supply_chain_attested
}

allow if {
  input.tier == "Tier-4"
  input.validation.independent
  input.monitoring.enabled
  input.security.supply_chain_attested
  input.frontier.containment_certified
  input.frontier.crisis_sim_days <= 90
  input.board.systemic_signoff
}
