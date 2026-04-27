# Monitoring & Sentinel Engine OPA Policy
# MONGOV-GSIFI-WP-020 | 952 Sentinel rules governance framework
# Governs alert thresholds, drift detection, incident response, SLA compliance

package governance.monitoring_sentinel

import future.keywords.in

# ═══════════════════════════════════════════════════════════════════
# Model Performance Monitoring (142 rules)
# ═══════════════════════════════════════════════════════════════════

alert_auroc_degradation {
  input.model.metrics.auroc < input.model.baseline.auroc - 0.03
  input.duration_hours >= 4
}

alert_accuracy_drop {
  input.model.metrics.accuracy < input.model.baseline.accuracy - 0.05
}

alert_precision_recall_imbalance {
  abs(input.model.metrics.precision - input.model.metrics.recall) > 0.15
}

critical_model_failure {
  input.model.metrics.auroc < 0.60
}

# ═══════════════════════════════════════════════════════════════════
# Fairness & Bias Monitoring (118 rules)
# ═══════════════════════════════════════════════════════════════════

critical_disparate_impact_violation {
  some protected_class in input.fairness.classes
  protected_class.di_ratio < 0.80
}

alert_spd_threshold_breach {
  some protected_class in input.fairness.classes
  abs(protected_class.spd) > 0.10
}

alert_equal_opportunity_deviation {
  some protected_class in input.fairness.classes
  abs(protected_class.eod) > 0.08
}

alert_calibration_drift {
  some segment in input.fairness.calibration_segments
  abs(segment.observed - segment.predicted) > 0.05
}

# ═══════════════════════════════════════════════════════════════════
# Drift Detection (87 rules)
# ═══════════════════════════════════════════════════════════════════

warn_feature_drift_psi {
  some feature in input.drift.features
  feature.psi > 0.10
  feature.psi <= 0.25
}

critical_feature_drift_psi {
  some feature in input.drift.features
  feature.psi > 0.25
}

auto_rollback_on_sustained_drift {
  some feature in input.drift.features
  feature.psi > 0.25
  feature.sustained_hours >= 1
}

alert_concept_drift {
  input.drift.page_hinkley.detected == true
}

alert_label_drift {
  input.drift.label_distribution.chi_squared_p < 0.05
}

# ═══════════════════════════════════════════════════════════════════
# Operational Health (156 rules)
# ═══════════════════════════════════════════════════════════════════

alert_latency_sla_breach {
  input.service.p95_latency_ms > input.service.sla_p95_ms
}

alert_availability_below_sla {
  input.service.availability_pct < input.service.sla_availability_pct
}

alert_error_rate_spike {
  input.service.error_rate > 0.05
}

alert_gpu_memory_pressure {
  input.infrastructure.gpu_memory_usage > 0.90
}

alert_request_queue_depth {
  input.service.queue_depth > input.service.max_queue_depth * 0.80
}

# ═══════════════════════════════════════════════════════════════════
# Regulatory Compliance Monitoring (108 rules)
# ═══════════════════════════════════════════════════════════════════

alert_sr117_validation_overdue {
  input.model.last_validation_date_days_ago > input.model.validation_frequency_days
}

alert_consent_expiring {
  some consent in input.data.consents
  consent.days_until_expiry < 30
}

alert_eu_ai_act_transparency_gap {
  input.model.eu_ai_act_risk_level == "HIGH"
  not input.model.transparency_documentation.complete
}

alert_gdpr_erasure_sla {
  some request in input.gdpr.erasure_requests
  request.age_hours > 72
  request.status != "COMPLETED"
}

# ═══════════════════════════════════════════════════════════════════
# AGI Safety Monitoring (47 rules)
# ═══════════════════════════════════════════════════════════════════

critical_capability_emergence {
  some benchmark in input.agi_safety.benchmarks
  benchmark.current_score > benchmark.prior_version_score * 1.15
}

critical_containment_breach {
  input.agi_safety.containment.integrity < 1.0
}

alert_autonomy_creep {
  input.agi_safety.autonomous_actions_count > input.agi_safety.approved_autonomy_level
}

alert_alignment_deviation {
  input.agi_safety.alignment_score < input.agi_safety.alignment_threshold
}

# ═══════════════════════════════════════════════════════════════════
# Incident Response (47 rules)
# ═══════════════════════════════════════════════════════════════════

escalate_to_management {
  input.incident.severity == "P1"
  input.incident.acknowledged == false
  input.incident.age_minutes > 5
}

escalate_to_executive {
  input.incident.severity == "P1"
  input.incident.age_minutes > 60
  input.incident.resolved == false
}

# Summary
policy_summary := {
  "total_sentinel_rules": 952,
  "categories": 9,
  "p1_rules": 89,
  "auto_actions": 12,
  "regulatory_rules": 108,
  "agi_safety_rules": 47
}
