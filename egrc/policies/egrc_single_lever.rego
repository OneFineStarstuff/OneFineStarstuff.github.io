package egrc.single_lever

# I-1: at most one lever per track per quarter in ARMED or PROMOTED state.
# Evaluated at every ARM transition. FICTIONAL GOVERNANCE SIMULATION.

deny[msg] {
  input.transition == "ARM"
  other := input.levers[_]
  other.track == input.lever.track
  other.quarter == input.lever.quarter
  other.state == "ARMED"
  msg := sprintf("I-1: track %s already has lever %s ARMED in %s", [other.track, other.lever_id, other.quarter])
}

deny[msg] {
  input.transition == "ARM"
  other := input.levers[_]
  other.track == input.lever.track
  other.quarter == input.lever.quarter
  other.state == "PROMOTED"
  msg := sprintf("I-1: track %s already has lever %s PROMOTED in %s", [other.track, other.lever_id, other.quarter])
}

default allow = false

allow {
  count(deny) == 0
}
