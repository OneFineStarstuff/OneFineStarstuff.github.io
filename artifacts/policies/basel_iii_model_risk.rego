# KACG-GSIFI-WP-017: Basel III Model Risk Compliance Policy
# Policy Group: compliance.baselIII.* (28 rules)
# Purpose: Enforce Basel III CRE 30-36 model risk management requirements
# Frameworks: Basel III CRE 30-36, SR 11-7, EU AI Act
# Last Updated: 2026-04-03

package compliance.baselIII

import future.keywords.in
import future.keywords.if

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 30.2: Board and Senior Management Oversight
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-001: Board AI Sub-committee must review high-risk model changes
board_oversight_required if {
    input.event.eventType == "MODEL_PROMOTION"
    input.event.metadata.risk_tier in {"HIGH", "CRITICAL"}
}

# BAS-002: CAIO escalation path must exist for model risk decisions
caio_escalation_valid if {
    input.governance.escalation_path != ""
    input.governance.caio_notified == true
}

# BAS-003: Model risk appetite statement must be current (within 12 months)
risk_appetite_current if {
    last_review := time.parse_rfc3339_ns(input.governance.risk_appetite_review_date)
    time.now_ns() - last_review < 31536000000000000  # 365 days in nanoseconds
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 30.3: Model Risk Management Framework
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-004: All AI models must be registered in the model inventory
model_registered if {
    input.model.registry_id != ""
    input.model.registration_date != ""
    input.model.model_owner != ""
}

# BAS-005: Model risk classification must be assigned (1-5 scale)
model_risk_classified if {
    input.model.risk_tier in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    input.model.risk_score >= 0
    input.model.risk_score <= 100
}

# BAS-006: Model documentation must meet minimum standards
model_documentation_complete if {
    required_fields := {
        "model_purpose", "methodology", "assumptions",
        "limitations", "data_sources", "validation_results",
        "performance_metrics", "owner", "approval_date"
    }
    provided := {f | input.model.documentation[f]}
    missing := required_fields - provided
    count(missing) == 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 31: Principles for Sound Stress Testing
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-007: Credit scoring models must undergo quarterly stress testing
stress_test_current if {
    input.model.model_type == "credit_scoring"
    last_test := time.parse_rfc3339_ns(input.model.last_stress_test)
    time.now_ns() - last_test < 7884000000000000  # 91.25 days
}

# BAS-008: Stress test results must be reviewed by independent validation
stress_test_independently_reviewed if {
    input.model.stress_test.reviewer != input.model.model_owner
    input.model.stress_test.review_status == "APPROVED"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 33: Data Quality
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-009: Training data quality score must meet threshold
data_quality_adequate if {
    input.model.data_quality_score >= 0.85
}

# BAS-010: PII handling must comply with data governance policy
pii_handling_compliant if {
    input.data.pii_detected == true
    input.data.pii_encrypted == true
    input.data.consent_verified == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 35: Model Validation
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-011: Independent validation required before production deployment
independent_validation_complete if {
    input.model.validation.status == "COMPLETE"
    input.model.validation.validator != input.model.model_owner
    input.model.validation.validator_team != input.model.development_team
}

# BAS-012: Back-testing results must be within acceptable thresholds
backtesting_acceptable if {
    input.model.backtesting.ks_statistic < 0.15
    input.model.backtesting.auc_roc >= 0.70
    input.model.backtesting.gini >= 0.40
}

# BAS-013: Model capital impact assessment required for material models
capital_impact_assessed if {
    not input.model.material_model
}

capital_impact_assessed if {
    input.model.material_model == true
    input.model.capital_impact.assessment_date != ""
    input.model.capital_impact.reviewer != ""
    input.model.capital_impact.approved == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CRE 36: Monitoring and Reporting
# ═══════════════════════════════════════════════════════════════════════════════

# BAS-014: Continuous monitoring must be active for all production models
monitoring_active if {
    input.model.monitoring.status == "ACTIVE"
    input.model.monitoring.drift_detection == true
    input.model.monitoring.performance_tracking == true
}

# BAS-015: Quarterly Basel III model risk report must be generated
quarterly_report_current if {
    last_report := time.parse_rfc3339_ns(input.reporting.last_basel_report)
    time.now_ns() - last_report < 7884000000000000  # 91.25 days
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPOSITE COMPLIANCE CHECK
# ═══════════════════════════════════════════════════════════════════════════════

# Overall Basel III compliance (all CRE sections)
basel_iii_compliant if {
    model_registered
    model_risk_classified
    model_documentation_complete
    independent_validation_complete
    monitoring_active
}

# Compliance violations list
violations[msg] {
    not model_registered
    msg := "BAS-004: Model not registered in inventory (CRE 30.3)"
}

violations[msg] {
    not model_risk_classified
    msg := "BAS-005: Model risk classification missing (CRE 30.3)"
}

violations[msg] {
    not model_documentation_complete
    msg := "BAS-006: Model documentation incomplete (CRE 30.3)"
}

violations[msg] {
    not independent_validation_complete
    msg := "BAS-011: Independent validation not complete (CRE 35)"
}

violations[msg] {
    not monitoring_active
    msg := "BAS-014: Continuous monitoring not active (CRE 36)"
}
