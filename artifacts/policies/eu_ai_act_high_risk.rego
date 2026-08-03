# AGMB-GSIFI-WP-016 — EU AI Act High-Risk Classification Policy
# Policy Group: ai-risk-classification (28 rules)
# Regulatory Alignment: EU AI Act Art. 6, Art. 9-15, Annex III

package ai.governance.eu_ai_act

import future.keywords.in

default high_risk = false
default compliant = false

# High-risk system categories per Annex III
high_risk_categories := [
    "credit_scoring", "employment_screening",
    "biometric_identification", "critical_infrastructure",
    "education_assessment", "law_enforcement",
    "migration_asylum", "democratic_process",
    "insurance_pricing", "judicial_assistance"
]

high_risk {
    input.system.category in high_risk_categories
}

high_risk {
    input.system.eu_ai_act_annex_iii == true
}

# Compliance checks for high-risk systems
compliant {
    high_risk
    input.documentation.technical_file_complete == true
    input.system.human_oversight_mechanism == true
    input.system.risk_management_system == true
    input.system.data_governance_measures == true
    input.system.transparency_provisions == true
    input.system.accuracy_robustness_cybersecurity == true
    input.system.bias_di >= 0.80
}

compliant {
    not high_risk
}

# Denial rules
deny[msg] {
    high_risk
    not input.documentation.technical_file_complete
    msg := sprintf("EU-AI-ACT-001: System %v classified HIGH-RISK requires complete technical documentation (Art. 11)", [input.system.id])
}

deny[msg] {
    high_risk
    not input.system.human_oversight_mechanism
    msg := sprintf("EU-AI-ACT-002: System %v classified HIGH-RISK requires human oversight mechanism (Art. 14)", [input.system.id])
}

deny[msg] {
    high_risk
    not input.system.risk_management_system
    msg := sprintf("EU-AI-ACT-003: System %v classified HIGH-RISK requires risk management system (Art. 9)", [input.system.id])
}

deny[msg] {
    high_risk
    input.system.bias_di < 0.80
    msg := sprintf("FCRA-ECOA-001: System %v disparate impact ratio %.2f below 0.80 threshold", [input.system.id, input.system.bias_di])
}

deny[msg] {
    high_risk
    not input.documentation.dpia_complete
    msg := sprintf("GDPR-035-001: System %v HIGH-RISK requires Data Protection Impact Assessment (GDPR Art. 35)", [input.system.id])
}
