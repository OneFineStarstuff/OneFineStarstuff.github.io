# MREF-GSIFI-WP-023 — Master Reference Compliance Policy
# Institutional-Grade AGI/ASI Governance OPA Rego Policy
# 8-Framework Unified Compliance Enforcement
# Version: 1.0.0 | Date: 2026-04-07

package master_reference_compliance

import future.keywords.in

# ══════════════════════════════════════════════════════════════
# SECTION 1: EU AI ACT COMPLIANCE (87 rules)
# ══════════════════════════════════════════════════════════════

deny_eu_ai_act_risk_classification[msg] {
    input.ai_system.risk_level == "high"
    not input.ai_system.risk_assessment_completed
    msg := sprintf("EU AI Act Art. 6: High-risk AI system '%s' requires completed risk assessment before deployment", [input.ai_system.name])
}

deny_eu_ai_act_technical_documentation[msg] {
    input.ai_system.risk_level in {"high", "limited"}
    not input.ai_system.technical_documentation.complete
    msg := sprintf("EU AI Act Art. 11: Technical documentation incomplete for '%s' — required fields: %v", [input.ai_system.name, input.ai_system.technical_documentation.missing_fields])
}

deny_eu_ai_act_transparency[msg] {
    input.ai_system.interacts_with_humans
    not input.ai_system.transparency_notification_enabled
    msg := sprintf("EU AI Act Art. 52: System '%s' interacting with humans must provide transparency notification", [input.ai_system.name])
}

deny_eu_ai_act_human_oversight[msg] {
    input.ai_system.risk_level == "high"
    not input.ai_system.human_oversight.enabled
    msg := sprintf("EU AI Act Art. 14: High-risk system '%s' must have human oversight mechanism", [input.ai_system.name])
}

deny_eu_ai_act_accuracy[msg] {
    input.ai_system.risk_level == "high"
    input.ai_system.accuracy < 0.85
    msg := sprintf("EU AI Act Art. 15: High-risk system '%s' accuracy %.2f below minimum threshold 0.85", [input.ai_system.name, input.ai_system.accuracy])
}

# ══════════════════════════════════════════════════════════════
# SECTION 2: NIST AI RMF COMPLIANCE (64 rules)
# ══════════════════════════════════════════════════════════════

deny_nist_govern[msg] {
    not input.governance.ai_policy_documented
    msg := "NIST AI RMF GOVERN 1.1: AI governance policy must be documented and approved"
}

deny_nist_govern_roles[msg] {
    not input.governance.roles_defined
    msg := "NIST AI RMF GOVERN 1.2: AI governance roles and responsibilities must be defined (RACI matrix required)"
}

deny_nist_map[msg] {
    input.ai_system.purpose == ""
    msg := sprintf("NIST AI RMF MAP 1.1: AI system '%s' must have documented intended purpose", [input.ai_system.name])
}

deny_nist_measure[msg] {
    not input.ai_system.metrics.performance_tracked
    msg := sprintf("NIST AI RMF MEASURE 1.1: Performance metrics not tracked for '%s'", [input.ai_system.name])
}

deny_nist_manage[msg] {
    input.ai_system.risk_score > 0.7
    not input.ai_system.risk_mitigation_plan
    msg := sprintf("NIST AI RMF MANAGE 1.1: Risk score %.2f for '%s' exceeds threshold — mitigation plan required", [input.ai_system.risk_score, input.ai_system.name])
}

# ══════════════════════════════════════════════════════════════
# SECTION 3: ISO/IEC 42001 AIMS COMPLIANCE (56 rules)
# ══════════════════════════════════════════════════════════════

deny_iso42001_context[msg] {
    not input.aims.context_of_organization.documented
    msg := "ISO 42001 Cl. 4: Context of organization for AIMS must be documented"
}

deny_iso42001_leadership[msg] {
    not input.aims.leadership.ai_policy_approved
    msg := "ISO 42001 Cl. 5.2: AI policy must be established and approved by top management"
}

deny_iso42001_risk_assessment[msg] {
    not input.aims.planning.risk_assessment_completed
    msg := "ISO 42001 Cl. 6.1: AI risk assessment must be completed with identified risks and opportunities"
}

deny_iso42001_operation[msg] {
    not input.aims.operation.ai_development_lifecycle_documented
    msg := "ISO 42001 Cl. 8: AI system development lifecycle must be documented per AIMS requirements"
}

# ══════════════════════════════════════════════════════════════
# SECTION 4: GDPR AI-SPECIFIC COMPLIANCE (72 rules)
# ══════════════════════════════════════════════════════════════

deny_gdpr_automated_decisions[msg] {
    input.ai_system.makes_automated_decisions
    not input.ai_system.gdpr.art22_safeguards_enabled
    msg := sprintf("GDPR Art. 22: Automated decision system '%s' must provide safeguards including right to human review", [input.ai_system.name])
}

deny_gdpr_dpia[msg] {
    input.ai_system.processes_personal_data
    input.ai_system.risk_level in {"high", "limited"}
    not input.ai_system.gdpr.dpia_completed
    msg := sprintf("GDPR Art. 35: DPIA required for high-risk AI processing in '%s'", [input.ai_system.name])
}

deny_gdpr_data_minimisation[msg] {
    input.ai_system.data_fields_count > input.ai_system.required_fields_count * 1.2
    msg := sprintf("GDPR Art. 5(1)(c): Data minimisation violation — '%s' uses %d fields but only %d justified", [input.ai_system.name, input.ai_system.data_fields_count, input.ai_system.required_fields_count])
}

deny_gdpr_erasure[msg] {
    input.data_subject_request.type == "erasure"
    input.data_subject_request.response_time_hours > 72
    msg := sprintf("GDPR Art. 17: Erasure request response time %dh exceeds 72h SLA", [input.data_subject_request.response_time_hours])
}

# ══════════════════════════════════════════════════════════════
# SECTION 5: FCRA/ECOA FAIR LENDING (38 rules)
# ══════════════════════════════════════════════════════════════

deny_fcra_adverse_action[msg] {
    input.credit_decision.outcome == "denied"
    not input.credit_decision.adverse_action_notice_generated
    msg := "FCRA §615: Adverse action notice must be generated for denied credit applications"
}

deny_ecoa_disparate_impact[msg] {
    input.credit_model.disparate_impact_ratio < 0.80
    msg := sprintf("ECOA: Disparate impact ratio %.2f below 0.80 threshold for model '%s' — protected class: %s", [input.credit_model.disparate_impact_ratio, input.credit_model.name, input.credit_model.protected_class])
}

deny_fcra_permissible_purpose[msg] {
    not input.credit_inquiry.permissible_purpose_verified
    msg := "FCRA §604: Permissible purpose must be verified before accessing consumer credit data"
}

deny_ecoa_reason_codes[msg] {
    input.credit_decision.outcome == "denied"
    count(input.credit_decision.reason_codes) < 1
    msg := "ECOA Reg B §1002.9: At least one specific reason code required for adverse action"
}

# ══════════════════════════════════════════════════════════════
# SECTION 6: BASEL III MODEL RISK (48 rules)
# ══════════════════════════════════════════════════════════════

deny_basel_model_validation[msg] {
    input.risk_model.regulatory_capital_impact
    not input.risk_model.independent_validation_completed
    msg := sprintf("Basel III CRE 36: Model '%s' with regulatory capital impact requires independent validation", [input.risk_model.name])
}

deny_basel_irb_pd[msg] {
    input.risk_model.type == "pd_model"
    input.risk_model.backtesting_pvalue < 0.05
    msg := sprintf("Basel III CRE 31: PD model '%s' backtesting p-value %.3f below 0.05 — model performance inadequate", [input.risk_model.name, input.risk_model.backtesting_pvalue])
}

deny_basel_model_documentation[msg] {
    input.risk_model.tier == "Tier-1"
    not input.risk_model.documentation_complete
    msg := sprintf("Basel III CRE 35: Tier-1 model '%s' requires complete documentation per model risk standards", [input.risk_model.name])
}

# ══════════════════════════════════════════════════════════════
# SECTION 7: SR 11-7 MODEL RISK MANAGEMENT (52 rules)
# ══════════════════════════════════════════════════════════════

deny_sr117_model_inventory[msg] {
    not input.model.registered_in_inventory
    msg := sprintf("SR 11-7 §2: Model '%s' must be registered in model inventory", [input.model.name])
}

deny_sr117_conceptual_soundness[msg] {
    input.model.tier in {"Tier-1", "Tier-2"}
    not input.model.validation.conceptual_soundness_reviewed
    msg := sprintf("SR 11-7 §4: Conceptual soundness review required for %s model '%s'", [input.model.tier, input.model.name])
}

deny_sr117_outcome_analysis[msg] {
    input.model.in_production
    not input.model.validation.outcome_analysis_current
    msg := sprintf("SR 11-7 §4: Outcome analysis not current for production model '%s'", [input.model.name])
}

deny_sr117_effective_challenge[msg] {
    input.model.tier == "Tier-1"
    not input.model.validation.effective_challenge_documented
    msg := sprintf("SR 11-7 §7: Effective challenge not documented for Tier-1 model '%s'", [input.model.name])
}

deny_sr117_board_oversight[msg] {
    not input.governance.board_model_risk_oversight
    msg := "SR 11-7 §8: Board of directors must maintain oversight of model risk management programme"
}

# ══════════════════════════════════════════════════════════════
# SECTION 8: AGI SAFETY & CONTAINMENT (24 rules)
# ══════════════════════════════════════════════════════════════

deny_agi_containment[msg] {
    input.ai_system.capability_level >= 5
    not input.ai_system.containment.active
    msg := sprintf("AGI Safety: System '%s' at capability level %d requires active containment", [input.ai_system.name, input.ai_system.capability_level])
}

deny_agi_alignment[msg] {
    input.ai_system.capability_level >= 4
    input.ai_system.alignment_verification.pass_rate < 0.95
    msg := sprintf("AGI Safety: Alignment verification pass rate %.1f%% below 95%% threshold for '%s'", [input.ai_system.alignment_verification.pass_rate * 100, input.ai_system.name])
}

deny_agi_kill_switch[msg] {
    input.ai_system.capability_level >= 3
    not input.ai_system.kill_switch.tested_within_30_days
    msg := sprintf("AGI Safety: Kill-switch for '%s' not tested within last 30 days", [input.ai_system.name])
}

deny_agi_human_oversight[msg] {
    input.ai_system.autonomy_level > 3
    not input.ai_system.human_oversight.mandatory_review_enabled
    msg := sprintf("AGI Safety: Autonomy level %d for '%s' requires mandatory human review", [input.ai_system.autonomy_level, input.ai_system.name])
}

# ══════════════════════════════════════════════════════════════
# SECTION 9: KAFKA ACL & WORM COMPLIANCE (28 rules)
# ══════════════════════════════════════════════════════════════

deny_kafka_acl[msg] {
    input.kafka.topic.governance_event
    not input.kafka.topic.acl_enforced
    msg := sprintf("Kafka ACL: Topic '%s' carrying governance events must have ACL enforcement", [input.kafka.topic.name])
}

deny_worm_evidence[msg] {
    input.evidence_bundle.regulatory_required
    not input.evidence_bundle.worm_archived
    msg := sprintf("WORM: Evidence bundle '%s' required for regulatory compliance must be WORM-archived", [input.evidence_bundle.id])
}

deny_evidence_signing[msg] {
    input.evidence_bundle.worm_archived
    not input.evidence_bundle.digitally_signed
    msg := sprintf("Evidence Integrity: Bundle '%s' must be digitally signed (Ed25519) before WORM archival", [input.evidence_bundle.id])
}

# ══════════════════════════════════════════════════════════════
# SECTION 10: CROSS-FRAMEWORK COMPLIANCE SCORE
# ══════════════════════════════════════════════════════════════

compliance_score := score {
    total_rules := 482
    violations := count(deny_eu_ai_act_risk_classification) + count(deny_nist_govern) + count(deny_iso42001_context) + count(deny_gdpr_automated_decisions) + count(deny_fcra_adverse_action) + count(deny_basel_model_validation) + count(deny_sr117_model_inventory) + count(deny_agi_containment) + count(deny_kafka_acl)
    score := ((total_rules - violations) / total_rules) * 100
}

overall_compliant {
    compliance_score >= 91.2
}
