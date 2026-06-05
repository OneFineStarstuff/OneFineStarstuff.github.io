package aigov.biological_sovereignty

default allow = false

# Biological Sovereignty Guardrails:
# Hard-coded prohibition of intervention in fundamental human biological processes.

allow if {
    input.intervention_type == "MONITORING_ONLY"
    input.informed_consent == true
}

deny contains msg if {
    input.target == "HUMAN_BIOLOGY"
    input.intervention_depth > 0
    not input.emergency_override_active
    msg := "Sovereignty Violation: Unauthorized intervention in human biological systems detected."
}

deny contains msg if {
    input.action == "NEURO_MODULATION"
    msg := "Sovereignty Violation: Neural interface modification is strictly prohibited under Sentinel ASI v4.0 rules."
}
