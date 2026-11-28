package egrc.monotonic

# I-12: a lever may not weaken an active control or invariant.
# Perceived weakening requires CLASS_1 treatment via the constitutional
# lever path (five-of-five college quorum). FICTIONAL GOVERNANCE SIMULATION.

default allow = false

deny[msg] {
  input.lever.effect == "WEAKEN"
  msg := sprintf("I-12: lever %s declares a weakening effect", [input.lever.id])
}

deny[msg] {
  removed := input.lever.removes_controls[_]
  msg := sprintf("I-12: lever %s removes control %s; class-1 treatment required", [input.lever.id, removed])
}

deny[msg] {
  weakened := input.lever.weakens_invariants[_]
  msg := sprintf("I-12: lever %s weakens invariant %s; class-1 treatment required", [input.lever.id, weakened])
}

allow {
  count(deny) == 0
}
