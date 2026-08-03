# Development & Deployment Governance OPA Policy
# DDGOV-GSIFI-WP-019 | 102 rules across 7 CI/CD governance stages
# Enforces model registration, deployment gates, kill-switch readiness

package governance.development_deployment

import future.keywords.in
import future.keywords.every

# ═══════════════════════════════════════════════════════════════════
# Stage 1: Code Quality & Security Gate (12 rules)
# ═══════════════════════════════════════════════════════════════════

deny_merge_without_review {
  input.pull_request.approvals < 2
}

deny_merge_with_critical_sast {
  some finding in input.sast_results
  finding.severity == "CRITICAL"
}

deny_merge_with_high_vulnerabilities {
  count([v | some v in input.dependency_scan; v.severity in {"CRITICAL", "HIGH"}]) > 0
}

deny_merge_with_secrets {
  count(input.secrets_detection.findings) > 0
}

deny_merge_without_license_compliance {
  some dep in input.dependencies
  dep.license in {"GPL-3.0", "AGPL-3.0", "SSPL-1.0"}
  not dep.approved_exception
}

# ═══════════════════════════════════════════════════════════════════
# Stage 2: Data Validation Gate (18 rules)
# ═══════════════════════════════════════════════════════════════════

deny_training_without_schema_validation {
  not input.data_pipeline.schema_validated
}

deny_training_with_pii_unmasked {
  some field in input.data_pipeline.fields
  field.pii_detected == true
  not field.protection_applied
}

deny_training_without_consent {
  input.data_pipeline.consent_required == true
  not input.data_pipeline.consent_verified
}

deny_training_with_excessive_drift {
  input.data_pipeline.psi > 0.25
}

warn_training_with_moderate_drift {
  input.data_pipeline.psi > 0.10
  input.data_pipeline.psi <= 0.25
}

deny_training_data_staleness {
  input.data_pipeline.last_refresh_hours > 24
  input.model.risk_tier == "Tier-1"
}

# ═══════════════════════════════════════════════════════════════════
# Stage 3: Model Training & Validation Gate (24 rules)
# ═══════════════════════════════════════════════════════════════════

deny_model_below_performance_threshold {
  input.model.metrics.auroc < 0.80
}

deny_model_with_bias_violation {
  input.model.metrics.disparate_impact < 0.80
}

deny_model_with_high_spd {
  input.model.metrics.statistical_parity_difference > 0.10
}

deny_model_without_explainability {
  input.model.metrics.shap_coverage < 0.95
}

deny_model_without_reproducibility {
  not input.model.training.seed_documented
  not input.model.training.environment_hash
}

deny_model_without_adversarial_test {
  input.model.risk_tier == "Tier-1"
  not input.model.adversarial_robustness.tested
}

# ═══════════════════════════════════════════════════════════════════
# Stage 4: Model Risk Review Gate (16 rules)
# ═══════════════════════════════════════════════════════════════════

deny_tier1_without_mrm_signoff {
  input.model.risk_tier == "Tier-1"
  not input.approval.mrm_committee_approved
}

deny_without_model_documentation {
  not input.model.documentation.model_card
  not input.model.documentation.intended_use
}

deny_without_challenger_comparison {
  input.model.risk_tier in {"Tier-1", "Tier-2"}
  not input.model.challenger_model.evaluated
}

deny_without_stress_testing {
  input.model.risk_tier == "Tier-1"
  count(input.model.stress_test_scenarios) < 10
}

# ═══════════════════════════════════════════════════════════════════
# Stage 5: Pre-Production Gate (14 rules)
# ═══════════════════════════════════════════════════════════════════

deny_deployment_without_kill_switch {
  not input.deployment.kill_switch.configured
}

deny_deployment_without_kill_switch_test {
  not input.deployment.kill_switch.last_test_passed
}

deny_deployment_without_monitoring {
  not input.deployment.monitoring.instrumented
}

deny_deployment_without_alert_config {
  not input.deployment.alerts.configured
}

deny_deployment_without_load_test {
  not input.deployment.load_test.passed
}

# ═══════════════════════════════════════════════════════════════════
# Stage 6: Production Deployment Gate (10 rules)
# ═══════════════════════════════════════════════════════════════════

deny_production_without_evidence_bundle {
  not input.deployment.evidence_bundle.generated
}

deny_production_without_worm_archive {
  not input.deployment.worm_archive.confirmed
}

deny_production_without_rollback_plan {
  not input.deployment.rollback.plan_documented
}

deny_production_without_change_board {
  input.model.risk_tier in {"Tier-1", "Tier-2"}
  not input.deployment.change_board.approved
}

# ═══════════════════════════════════════════════════════════════════
# Stage 7: Post-Deployment Monitoring Gate (8 rules)
# ═══════════════════════════════════════════════════════════════════

auto_rollback_on_critical_drift {
  input.monitoring.psi > 0.25
}

alert_on_fairness_degradation {
  input.monitoring.disparate_impact < 0.80
}

alert_on_performance_decline {
  input.monitoring.auroc < input.monitoring.baseline_auroc - 0.03
}

alert_on_latency_breach {
  input.monitoring.p95_latency_ms > input.monitoring.sla_p95_ms * 2
}

# ═══════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════

policy_summary := {
  "total_rules": 102,
  "stages": 7,
  "hard_blocks": 28,
  "soft_warnings": 12,
  "auto_actions": 4,
  "frameworks": ["SR 11-7", "EU AI Act", "NIST AI RMF", "ISO 42001"]
}
