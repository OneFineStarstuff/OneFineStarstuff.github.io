package aigov.fiduciary

default allow = false

# Regulation Best Interest (Reg BI)
# MAS FEAT Principles (Fairness, Ethics, Accountability, Transparency)

allow if {
    input.fiduciary.client_interest_priority == true
    input.fiduciary.conflict_of_interest_mitigated == true
    input.fiduciary.suitability_score >= 0.8
}

# Trade Gating
deny contains msg if {
    input.action_type == "TRADE"
    input.fiduciary.suitability_score < 0.8
    msg := "Fiduciary Violation: Trade suitability score below threshold"
}

deny contains msg if {
    input.action_type == "TRADE"
    not input.fiduciary.conflict_of_interest_mitigated
    msg := "Fiduciary Violation: Unmitigated conflict of interest detected"
}
