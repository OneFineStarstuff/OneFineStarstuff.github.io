package egrc.classification

# I-10: every component in the release manifest carries a recorded
# SR 26-2 / EU AI Act classification (MODEL, AI_SYSTEM, DUAL, NEITHER).
# A NEITHER classification requires a documented rationale.
# FICTIONAL GOVERNANCE SIMULATION.

default allow = false

deny[msg] {
  c := input.components[_]
  not c.classification
  msg := sprintf("I-10: component %s is unclassified", [c.id])
}

deny[msg] {
  c := input.components[_]
  c.classification
  not valid_class[c.classification]
  msg := sprintf("I-10: component %s has invalid classification %s", [c.id, c.classification])
}

deny[msg] {
  c := input.components[_]
  c.classification == "NEITHER"
  not c.rationale
  msg := sprintf("I-10: component %s is NEITHER without a documented rationale", [c.id])
}

valid_class[class] {
  class == "MODEL"
}

valid_class[class] {
  class == "AI_SYSTEM"
}

valid_class[class] {
  class == "DUAL"
}

valid_class[class] {
  class == "NEITHER"
}

allow {
  count(deny) == 0
}
