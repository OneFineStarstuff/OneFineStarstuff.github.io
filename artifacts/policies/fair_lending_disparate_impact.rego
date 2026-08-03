# Fair Lending Disparate Impact Policy
# GAF-GSIFI-WP-017, Domain 5 — Financial Services AI Governance
# Policy Group: PG-06 (Bias & Fairness)
# Regulatory alignment: FCRA ss. 607/615, ECOA ss. 701-706, EU AI Act Art. 10(2)(f)
#
# This policy enforces disparate impact (DI) thresholds for credit scoring AI models
# across all protected classes. DI is calculated as the ratio of the favorable outcome
# rate for the protected group to the favorable outcome rate for the control group.
# The four-fifths (80%) rule is the minimum threshold per EEOC/ECOA guidance.

package fair_lending.disparate_impact

import rego.v1

# Minimum disparate impact threshold (four-fifths rule)
default di_threshold := 0.80

# Enhanced threshold for production models after Q4 2027
enhanced_di_threshold := 0.87

# Protected classes per FCRA/ECOA
protected_classes := [
    "race_ethnicity",
    "sex_gender",
    "age",
    "national_origin",
    "marital_status",
    "religion",
    "color",
    "receipt_of_public_assistance"
]

# DENY: Model fails disparate impact test for any protected class
deny contains msg if {
    some test in input.di_tests
    test.disparate_impact < di_threshold
    msg := sprintf(
        "FCRA/ECOA VIOLATION: Model '%s' fails DI test for protected class '%s' — DI %.3f < threshold %.2f. Adverse action notice required per FCRA ss. 615.",
        [input.model_id, test.protected_class, test.disparate_impact, di_threshold]
    )
}

# DENY: No DI test results provided for a credit scoring model
deny contains msg if {
    input.model_type == "credit_scoring"
    not input.di_tests
    msg := sprintf(
        "ECOA VIOLATION: Credit scoring model '%s' has no disparate impact test results. DI testing is mandatory per ECOA Reg B and EU AI Act Art. 10(2)(f).",
        [input.model_id]
    )
}

# DENY: Missing protected class in DI tests
deny contains msg if {
    input.model_type == "credit_scoring"
    some pc in protected_classes
    not class_tested(pc)
    msg := sprintf(
        "ECOA VIOLATION: Model '%s' missing DI test for protected class '%s'. All protected classes must be tested.",
        [input.model_id, pc]
    )
}

# WARN: Model approaches DI threshold (within 5% of minimum)
warn contains msg if {
    some test in input.di_tests
    test.disparate_impact >= di_threshold
    test.disparate_impact < (di_threshold + 0.05)
    msg := sprintf(
        "DI WARNING: Model '%s' protected class '%s' — DI %.3f is within 5%% of threshold. Recommend remediation.",
        [input.model_id, test.protected_class, test.disparate_impact]
    )
}

# WARN: Model below enhanced threshold (post-2027 target)
warn contains msg if {
    some test in input.di_tests
    test.disparate_impact >= di_threshold
    test.disparate_impact < enhanced_di_threshold
    msg := sprintf(
        "ENHANCED DI: Model '%s' class '%s' — DI %.3f meets minimum but below enhanced target %.2f (Q4 2027 target).",
        [input.model_id, test.protected_class, test.disparate_impact, enhanced_di_threshold]
    )
}

# DENY: No adverse action reason codes for denied applications
deny contains msg if {
    input.model_type == "credit_scoring"
    input.generates_denials == true
    not input.adverse_action_engine_active
    msg := sprintf(
        "FCRA VIOLATION: Model '%s' generates denials without adverse action reason codes. FCRA ss. 615 requires specific reasons for adverse actions.",
        [input.model_id]
    )
}

# DENY: Model documentation older than 12 months
deny contains msg if {
    input.model_type == "credit_scoring"
    input.last_documentation_update_days > 365
    msg := sprintf(
        "SR 11-7 VIOLATION: Model '%s' documentation is %d days old (> 365 day limit). Model documentation must be current per SR 11-7 ss. 7.",
        [input.model_id, input.last_documentation_update_days]
    )
}

# Helper: check if a protected class has been tested
class_tested(pc) if {
    some test in input.di_tests
    test.protected_class == pc
}

# Aggregate: overall DI compliance status
overall_compliance := "PASS" if {
    count(deny) == 0
}

overall_compliance := "FAIL" if {
    count(deny) > 0
}
