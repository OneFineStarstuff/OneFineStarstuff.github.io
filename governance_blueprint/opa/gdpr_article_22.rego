package aigov.gdpr

default allow = false

# Article 22: Automated individual decision-making, including profiling
# The data subject shall have the right not to be subject to a decision based solely on automated processing.

allow if {
    input.human_intervention_requested == true
    input.decision_explained == true
}

deny contains msg if {
    input.is_solely_automated == true
    not input.human_intervention_available
    msg := "GDPR Article 22 Violation: Decision based solely on automated processing without human intervention path."
}
