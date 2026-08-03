# KACG-GSIFI-WP-017: NIST AI RMF Governance Policy
# Policy Group: compliance.nistAiRmf.* (38 rules)
# Purpose: Enforce NIST AI Risk Management Framework requirements
#          for AI system governance, mapping, measurement, and management
# Framework: NIST AI RMF 1.0 (January 2023)
# Last Updated: 2026-04-03

package compliance.nist_ai_rmf

import future.keywords.in
import future.keywords.if

# ═══════════════════════════════════════════════════════════════════════════════
# GOVERN Function — Organizational AI Governance
# ═══════════════════════════════════════════════════════════════════════════════

# RULE NIST-G-001: GOVERN 1.1 — Legal and regulatory requirements identified
# Requires AI systems to have documented regulatory mapping
govern_1_1_regulatory_mapping if {
    input.aiSystem.regulatoryMapping != null
    count(input.aiSystem.regulatoryMapping.frameworks) >= 1
    input.aiSystem.regulatoryMapping.lastReviewDate != ""
}

# RULE NIST-G-002: GOVERN 1.2 — Trustworthy AI characteristics integrated
# Requires documented trustworthiness characteristics
govern_1_2_trustworthy_characteristics if {
    characteristics := input.aiSystem.trustworthiness
    characteristics.valid == true
    characteristics.explainability != null
    characteristics.fairness != null
    characteristics.privacy != null
    characteristics.security != null
    characteristics.safety != null
    characteristics.accountability != null
    characteristics.transparency != null
}

# RULE NIST-G-003: GOVERN 2.1 — Roles and responsibilities defined
# Requires RACI matrix for AI system governance
govern_2_1_roles_defined if {
    raci := input.aiSystem.governance.raci
    count(raci.roles) >= 3
    some role in raci.roles
    role.type == "ACCOUNTABLE"
}

# RULE NIST-G-004: GOVERN 2.2 — AI risk management integrated into enterprise risk
govern_2_2_enterprise_risk_integration if {
    input.aiSystem.riskManagement.integratedWithEnterprise == true
    input.aiSystem.riskManagement.riskFrameworkAlignment != ""
}

# RULE NIST-G-005: GOVERN 3.1 — Decision-making documented for AI lifecycle
govern_3_1_lifecycle_decisions if {
    lifecycle := input.aiSystem.lifecycle
    lifecycle.designDecisions != null
    lifecycle.deploymentDecisions != null
    lifecycle.monitoringDecisions != null
}

# RULE NIST-G-006: GOVERN 4.1 — Organizational practices for AI risk management
govern_4_1_org_practices if {
    practices := input.aiSystem.governance.practices
    practices.policyInfrastructure == true
    practices.trainingProgram == true
    practices.incidentResponse == true
    practices.auditSchedule != ""
}

# RULE NIST-G-007: GOVERN 4.2 — Organizational teams have AI risk awareness
govern_4_2_risk_awareness if {
    training := input.aiSystem.governance.training
    training.completionRate >= 0.80
    training.lastAssessmentDate != ""
}

# RULE NIST-G-008: GOVERN 5.1 — Organizational AI risk tolerance documented
govern_5_1_risk_tolerance if {
    tolerance := input.aiSystem.riskManagement.tolerance
    tolerance.documented == true
    tolerance.maxAcceptableRiskScore >= 0
    tolerance.approvedByBoard == true
}

# RULE NIST-G-009: GOVERN 6.1 — Policies and procedures in place
# Kafka-specific: Verify OPA policy coverage for governance decisions
govern_6_1_policies_in_place if {
    input.aiSystem.governance.opaPolicyCoverage >= 0.90
    input.aiSystem.governance.sentinelRules >= 800
    input.aiSystem.governance.policyVersioning == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAP Function — Contextual AI Risk Mapping
# ═══════════════════════════════════════════════════════════════════════════════

# RULE NIST-M-001: MAP 1.1 — Intended purposes documented
map_1_1_intended_purpose if {
    purpose := input.aiSystem.purpose
    purpose.description != ""
    purpose.intendedUse != ""
    purpose.limitations != null
    count(purpose.limitations) >= 1
}

# RULE NIST-M-002: MAP 1.2 — Interdisciplinary AI stakeholders identified
map_1_2_stakeholders if {
    stakeholders := input.aiSystem.stakeholders
    count(stakeholders) >= 3
    some s in stakeholders
    s.role == "DOMAIN_EXPERT"
}

# RULE NIST-M-003: MAP 1.5 — Deployment environment documented
map_1_5_deployment_env if {
    env := input.aiSystem.deployment
    env.environment != ""
    env.infrastructure != ""
    env.scalingRequirements != null
}

# RULE NIST-M-004: MAP 1.6 — Broader impacts considered
map_1_6_broader_impacts if {
    impacts := input.aiSystem.impactAssessment
    impacts.socialImpact != null
    impacts.environmentalImpact != null
    impacts.economicImpact != null
    impacts.assessmentDate != ""
}

# RULE NIST-M-005: MAP 2.1 — AI system categorized by risk
map_2_1_risk_categorization if {
    risk := input.aiSystem.riskCategorization
    risk.level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk.methodology != ""
    risk.lastAssessmentDate != ""
}

# RULE NIST-M-006: MAP 2.3 — Data quality and relevance documented
# Kafka-specific: Verify data governance for AI training/inference streams
map_2_3_data_quality if {
    data := input.aiSystem.dataGovernance
    data.qualityScore >= 0.85
    data.piiDetectionRate >= 0.997
    data.dataLineageDocumented == true
}

# RULE NIST-M-007: MAP 3.1 — Benefits and costs documented
map_3_1_benefits_costs if {
    analysis := input.aiSystem.costBenefitAnalysis
    analysis.documented == true
    analysis.netPresentValue != null
    analysis.lastReviewDate != ""
}

# RULE NIST-M-008: MAP 3.5 — Existing safeguards and controls identified
map_3_5_safeguards if {
    controls := input.aiSystem.controls
    count(controls) >= 5
    some c in controls
    c.type == "KILL_SWITCH"
    some c2 in controls
    c2.type == "HUMAN_OVERSIGHT"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MEASURE Function — Risk Assessment & Analysis
# ═══════════════════════════════════════════════════════════════════════════════

# RULE NIST-ME-001: MEASURE 1.1 — Appropriate metrics identified
measure_1_1_metrics if {
    metrics := input.aiSystem.metrics
    count(metrics) >= 5
    some m in metrics
    m.category == "FAIRNESS"
    some m2 in metrics
    m2.category == "PERFORMANCE"
    some m3 in metrics
    m3.category == "SECURITY"
}

# RULE NIST-ME-002: MEASURE 2.1 — Evaluations conducted regularly
measure_2_1_evaluations if {
    eval := input.aiSystem.evaluation
    eval.frequency in ["CONTINUOUS", "WEEKLY", "MONTHLY"]
    eval.lastEvaluationDate != ""
    eval.automated == true
}

# RULE NIST-ME-003: MEASURE 2.3 — AI system performance validated
# Kafka-specific: Verify model performance monitoring via Kafka streams
measure_2_3_performance_validation if {
    perf := input.aiSystem.performance
    perf.validated == true
    perf.validationMethod != ""
    perf.kafkaMonitoringEnabled == true
    perf.driftDetectionEnabled == true
}

# RULE NIST-ME-004: MEASURE 2.5 — AI system tested for biases
measure_2_5_bias_testing if {
    bias := input.aiSystem.biasTesting
    bias.disparateImpactRatio >= 0.80
    bias.testingFrequency in ["CONTINUOUS", "WEEKLY", "MONTHLY"]
    bias.lastTestDate != ""
    count(bias.protectedAttributes) >= 3
}

# RULE NIST-ME-005: MEASURE 2.6 — AI system evaluated for safety
measure_2_6_safety_evaluation if {
    safety := input.aiSystem.safetyEvaluation
    safety.completed == true
    safety.killSwitchTested == true
    safety.failsafeMode != ""
    safety.lastEvaluationDate != ""
}

# RULE NIST-ME-006: MEASURE 2.7 — AI system security evaluated
measure_2_7_security_evaluation if {
    security := input.aiSystem.securityEvaluation
    security.penetrationTestDate != ""
    security.vulnerabilityScan == true
    security.adversarialRobustness != null
}

# RULE NIST-ME-007: MEASURE 2.11 — Fairness assessed
measure_2_11_fairness if {
    fairness := input.aiSystem.fairnessAssessment
    fairness.completed == true
    fairness.disparateImpactRatio >= 0.80
    fairness.equalOpportunityDifference <= 0.10
    count(fairness.protectedClasses) >= 3
}

# RULE NIST-ME-008: MEASURE 3.1 — Risk tracking approaches
measure_3_1_risk_tracking if {
    tracking := input.aiSystem.riskTracking
    tracking.riskRegisterMaintained == true
    tracking.reviewFrequency in ["WEEKLY", "MONTHLY", "QUARTERLY"]
    tracking.escalationProcedure != ""
}

# RULE NIST-ME-009: MEASURE 4.1 — Measurement approaches for identified risks
# Kafka-specific: Evidence bundles generated for all risk measurements
measure_4_1_evidence_generation if {
    evidence := input.aiSystem.evidenceGeneration
    evidence.enabled == true
    evidence.wormStorageEnabled == true
    evidence.signatureAlgorithm == "Ed25519"
    evidence.retentionYears >= 7
}

# ═══════════════════════════════════════════════════════════════════════════════
# MANAGE Function — Risk Response & Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

# RULE NIST-MA-001: MANAGE 1.1 — Risk treatments planned and implemented
manage_1_1_risk_treatments if {
    treatments := input.aiSystem.riskTreatments
    count(treatments) >= 1
    every treatment in treatments {
        treatment.status in ["IMPLEMENTED", "IN_PROGRESS", "PLANNED"]
        treatment.owner != ""
    }
}

# RULE NIST-MA-002: MANAGE 1.3 — Responses to identified risks
manage_1_3_risk_response if {
    response := input.aiSystem.riskResponse
    response.incidentResponsePlan == true
    response.escalationMatrix != null
    response.meanTimeToResponseMinutes <= 15
}

# RULE NIST-MA-003: MANAGE 2.1 — Resources allocated for AI risk management
manage_2_1_resources if {
    resources := input.aiSystem.riskResources
    resources.budgetAllocated == true
    resources.teamSize >= 3
    resources.toolsProvisioned == true
}

# RULE NIST-MA-004: MANAGE 2.2 — Mechanisms for feedback about AI system performance
# Kafka-specific: Verify Kafka-based feedback loop for continuous monitoring
manage_2_2_feedback_mechanisms if {
    feedback := input.aiSystem.feedbackMechanisms
    feedback.kafkaStreamEnabled == true
    feedback.humanInLoopGates == true
    feedback.confidenceThreshold >= 0.75
    feedback.alertingEnabled == true
}

# RULE NIST-MA-005: MANAGE 3.1 — AI risks and benefits continuously monitored
manage_3_1_continuous_monitoring if {
    monitoring := input.aiSystem.continuousMonitoring
    monitoring.enabled == true
    monitoring.metricsCount >= 10
    monitoring.alertRulesCount >= 5
    monitoring.dashboardAvailable == true
}

# RULE NIST-MA-006: MANAGE 3.2 — Pre-defined events trigger review
manage_3_2_trigger_events if {
    triggers := input.aiSystem.reviewTriggers
    count(triggers) >= 3
    some t in triggers
    t.event == "DRIFT_DETECTED"
    some t2 in triggers
    t2.event == "BIAS_THRESHOLD_EXCEEDED"
}

# RULE NIST-MA-007: MANAGE 4.1 — Risk treatment status monitored
manage_4_1_treatment_monitoring if {
    monitoring := input.aiSystem.treatmentMonitoring
    monitoring.trackingEnabled == true
    monitoring.reportingFrequency in ["WEEKLY", "MONTHLY"]
    monitoring.dashboardIntegration == true
}

# RULE NIST-MA-008: MANAGE 4.2 — AI system decommissioning documented
manage_4_2_decommissioning if {
    decom := input.aiSystem.decommissioningPlan
    decom.documented == true
    decom.dataDispositionPlan != ""
    decom.evidenceArchivalPlan != ""
    decom.regulatoryNotificationRequired != null
}

# ═══════════════════════════════════════════════════════════════════════════════
# Aggregate Compliance Score
# ═══════════════════════════════════════════════════════════════════════════════

# Count passing GOVERN rules
govern_pass_count := count([1 |
    govern_1_1_regulatory_mapping
]) + count([1 |
    govern_1_2_trustworthy_characteristics
]) + count([1 |
    govern_2_1_roles_defined
]) + count([1 |
    govern_2_2_enterprise_risk_integration
]) + count([1 |
    govern_3_1_lifecycle_decisions
]) + count([1 |
    govern_4_1_org_practices
]) + count([1 |
    govern_4_2_risk_awareness
]) + count([1 |
    govern_5_1_risk_tolerance
]) + count([1 |
    govern_6_1_policies_in_place
])

govern_total := 9

# Count passing MAP rules
map_pass_count := count([1 |
    map_1_1_intended_purpose
]) + count([1 |
    map_1_2_stakeholders
]) + count([1 |
    map_1_5_deployment_env
]) + count([1 |
    map_1_6_broader_impacts
]) + count([1 |
    map_2_1_risk_categorization
]) + count([1 |
    map_2_3_data_quality
]) + count([1 |
    map_3_1_benefits_costs
]) + count([1 |
    map_3_5_safeguards
])

map_total := 8

# Summary for API consumption
nist_compliance_summary := {
    "framework": "NIST AI RMF 1.0",
    "docRef": "KACG-GSIFI-WP-017",
    "governScore": sprintf("%d/%d", [govern_pass_count, govern_total]),
    "mapScore": sprintf("%d/%d", [map_pass_count, map_total]),
    "totalRules": 38,
    "kafkaIntegrationRules": 5,
    "timestamp": time.now_ns()
}
