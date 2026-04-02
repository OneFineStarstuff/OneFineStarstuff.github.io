# AGMB-GSIFI-WP-016 — SR 11-7 Model Risk Management Policy
# Policy Group: financial-services (28 rules)
# Regulatory Alignment: SR 11-7 §§1-15, FCRA §607/§615, ECOA §701-§706

package ai.governance.sr_11_7

default model_approved = false
default validation_current = false

# Model approval requires all validation steps
model_approved {
    input.model.validation.independent_review == true
    input.model.validation.challenger_model_tested == true
    input.model.documentation.model_card_complete == true
    input.model.monitoring.ongoing_validation_schedule != null
    input.model.risk_tier != "unvalidated"
    validation_current
}

# Validation is current if within 12 months
validation_current {
    input.model.validation.last_validation_date != null
    time.now_ns() - time.parse_rfc3339_ns(input.model.validation.last_validation_date) < 365 * 24 * 60 * 60 * 1000000000
}

deny[msg] {
    input.model.risk_tier == "high"
    not input.model.validation.second_line_review
    msg := sprintf("SR117-001: High-risk model %v requires 2nd-line independent validation (SR 11-7 §4)", [input.model.id])
}

deny[msg] {
    input.model.risk_tier == "high"
    not input.model.validation.challenger_model_tested
    msg := sprintf("SR117-002: High-risk model %v requires challenger model testing (SR 11-7 §5)", [input.model.id])
}

deny[msg] {
    not input.model.documentation.model_card_complete
    msg := sprintf("SR117-003: Model %v requires complete model card documentation (SR 11-7 §7)", [input.model.id])
}

deny[msg] {
    input.model.category == "credit_scoring"
    not input.model.fairness.adverse_action_codes_enabled
    msg := sprintf("FCRA-615: Credit scoring model %v must generate adverse action reason codes (FCRA §615(a))", [input.model.id])
}

deny[msg] {
    input.model.category == "credit_scoring"
    input.model.fairness.disparate_impact < 0.80
    msg := sprintf("ECOA-701: Credit scoring model %v disparate impact %.2f violates equal opportunity (ECOA §701)", [input.model.id, input.model.fairness.disparate_impact])
}
