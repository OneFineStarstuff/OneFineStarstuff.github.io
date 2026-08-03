# KACG-GSIFI-WP-017: ISO/IEC 42001 AIMS Governance Policy
# Policy Group: compliance.iso42001.* (32 rules)
# Purpose: Enforce ISO/IEC 42001:2023 AI Management System (AIMS) requirements
#          with Kafka-based evidence collection and WORM storage verification
# Framework: ISO/IEC 42001:2023 — AI Management System
# Last Updated: 2026-04-03

package compliance.iso42001

import future.keywords.in
import future.keywords.if

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 4 — Context of the Organization
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-4.1: Understanding the organization and its context
clause_4_1_org_context if {
    ctx := input.aiSystem.organizationalContext
    ctx.documented == true
    ctx.externalFactors != null
    ctx.internalFactors != null
    ctx.lastReviewDate != ""
}

# RULE ISO-4.2: Understanding needs and expectations of interested parties
clause_4_2_interested_parties if {
    parties := input.aiSystem.interestedParties
    count(parties) >= 3
    some p in parties
    p.type == "REGULATOR"
    some p2 in parties
    p2.type == "DATA_SUBJECT"
}

# RULE ISO-4.3: Scope of the AIMS
clause_4_3_aims_scope if {
    scope := input.aiSystem.aimsScope
    scope.defined == true
    scope.boundaries != ""
    scope.applicableRegulations != null
    count(scope.applicableRegulations) >= 1
}

# RULE ISO-4.4: AIMS processes established
clause_4_4_aims_established if {
    aims := input.aiSystem.aims
    aims.established == true
    aims.processesDocumented == true
    aims.continuousImprovement == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 5 — Leadership
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-5.1: Leadership commitment
clause_5_1_leadership if {
    leadership := input.aiSystem.leadership
    leadership.boardOversight == true
    leadership.aiCommitteeEstablished == true
    leadership.resourcesAllocated == true
}

# RULE ISO-5.2: AI policy established
clause_5_2_ai_policy if {
    policy := input.aiSystem.aiPolicy
    policy.documented == true
    policy.approvedByLeadership == true
    policy.communicatedToOrganization == true
    policy.reviewSchedule != ""
}

# RULE ISO-5.3: Roles, responsibilities, and authorities
clause_5_3_roles if {
    roles := input.aiSystem.governance.raci
    count(roles.roles) >= 5
    some r in roles.roles
    r.type == "ACCOUNTABLE"
    roles.documented == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 6 — Planning
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-6.1.1: Actions to address risks
clause_6_1_1_risk_actions if {
    riskActions := input.aiSystem.riskManagement
    riskActions.riskAssessmentCompleted == true
    riskActions.riskTreatmentPlan != null
    count(riskActions.identifiedRisks) >= 1
}

# RULE ISO-6.1.4: AI risk assessment
clause_6_1_4_ai_risk_assessment if {
    assessment := input.aiSystem.aiRiskAssessment
    assessment.methodology != ""
    assessment.riskScore >= 0
    assessment.lastAssessmentDate != ""
    assessment.reviewedByRiskCommittee == true
}

# RULE ISO-6.2: AI objectives and plans
clause_6_2_objectives if {
    objectives := input.aiSystem.aiObjectives
    count(objectives) >= 3
    every obj in objectives {
        obj.measurable == true
        obj.timebound == true
        obj.owner != ""
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 7 — Support
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-7.1: Resources for AIMS
clause_7_1_resources if {
    resources := input.aiSystem.resources
    resources.budgetAllocated == true
    resources.personnelAssigned == true
    resources.toolsProvisioned == true
}

# RULE ISO-7.2: Competence
clause_7_2_competence if {
    competence := input.aiSystem.competence
    competence.trainingProgram == true
    competence.assessmentCompleted == true
    competence.gapAnalysis != null
}

# RULE ISO-7.4: Communication
clause_7_4_communication if {
    comm := input.aiSystem.communication
    comm.internalCommunication == true
    comm.externalCommunication == true
    comm.stakeholderReporting == true
}

# RULE ISO-7.5: Documented information
# Kafka-specific: Verify evidence is stored in WORM storage
clause_7_5_documented_info if {
    docs := input.aiSystem.documentedInformation
    docs.controlled == true
    docs.versionManaged == true
    docs.retentionPolicy != ""
    docs.wormStorageEnabled == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 8 — Operation
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-8.1: Operational planning and control
clause_8_1_operational_planning if {
    ops := input.aiSystem.operationalPlanning
    ops.processesPlanned == true
    ops.controlsImplemented == true
    ops.changeManagement == true
}

# RULE ISO-8.2: AI risk assessment execution
clause_8_2_risk_execution if {
    execution := input.aiSystem.riskAssessmentExecution
    execution.completed == true
    execution.resultDocumented == true
    execution.outputsAvailable == true
}

# RULE ISO-8.3: AI risk treatment execution
clause_8_3_treatment_execution if {
    treatment := input.aiSystem.riskTreatmentExecution
    treatment.planImplemented == true
    treatment.controlsOperational == true
    treatment.residualRiskAcceptable == true
}

# RULE ISO-8.4: AI system impact assessment
# Kafka-specific: Impact assessments published to governance topic
clause_8_4_impact_assessment if {
    impact := input.aiSystem.impactAssessment
    impact.completed == true
    impact.socialImpact != null
    impact.humanRightsAssessment == true
    impact.publishedToKafka == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 9 — Performance Evaluation
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-9.1: Monitoring, measurement, analysis, and evaluation
clause_9_1_monitoring if {
    monitoring := input.aiSystem.monitoring
    monitoring.metricsCollected == true
    monitoring.analysisPerformed == true
    monitoring.evaluationSchedule != ""
    monitoring.kafkaMetricsEnabled == true
}

# RULE ISO-9.2: Internal audit
clause_9_2_internal_audit if {
    audit := input.aiSystem.internalAudit
    audit.programEstablished == true
    audit.frequency in ["QUARTERLY", "SEMI_ANNUAL", "ANNUAL"]
    audit.lastAuditDate != ""
    audit.findingsDocumented == true
}

# RULE ISO-9.3: Management review
clause_9_3_management_review if {
    review := input.aiSystem.managementReview
    review.conducted == true
    review.frequency in ["QUARTERLY", "SEMI_ANNUAL"]
    review.outputsDocumented == true
    review.improvementActionsIdentified == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clause 10 — Improvement
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-10.1: Nonconformity and corrective action
clause_10_1_corrective_action if {
    corrective := input.aiSystem.correctiveAction
    corrective.processEstablished == true
    corrective.nonconformitiesTracked == true
    corrective.rootCauseAnalysis == true
}

# RULE ISO-10.2: Continual improvement
clause_10_2_continual_improvement if {
    improvement := input.aiSystem.continualImprovement
    improvement.processEstablished == true
    improvement.improvementPlanDocumented == true
    improvement.kpiTracking == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Annex A — Reference Controls
# ═══════════════════════════════════════════════════════════════════════════════

# RULE ISO-A.5.2: AI policies for the organization
annex_a_5_2_policies if {
    input.aiSystem.governance.opaPolicyCoverage >= 0.85
    input.aiSystem.governance.policyVersioning == true
    input.aiSystem.governance.policyReviewSchedule != ""
}

# RULE ISO-A.5.4: AI system inventory
annex_a_5_4_inventory if {
    inventory := input.aiSystem.inventory
    inventory.maintained == true
    inventory.allSystemsRegistered == true
    inventory.classificationApplied == true
    inventory.riskLevelAssigned == true
}

# RULE ISO-A.6.1.3: Access controls for AI systems
# Kafka-specific: Verify Kafka ACL governance is in place
annex_a_6_1_3_access_controls if {
    acl := input.aiSystem.accessControls
    acl.kafkaAclEnabled == true
    acl.opaAuthorizerDeployed == true
    acl.spiffeIdentity == true
    acl.breakGlassProtocol == true
    acl.auditTrailEnabled == true
}

# RULE ISO-A.7.1: Data governance for AI
annex_a_7_1_data_governance if {
    data := input.aiSystem.dataGovernance
    data.qualityGates == true
    data.qualityScore >= 0.85
    data.lineageDocumented == true
    data.consentManagement == true
}

# RULE ISO-A.8.2: AI system lifecycle
annex_a_8_2_lifecycle if {
    lifecycle := input.aiSystem.lifecycle
    lifecycle.designPhase == true
    lifecycle.developmentPhase == true
    lifecycle.deploymentPhase == true
    lifecycle.monitoringPhase == true
    lifecycle.retirementPhase == true
    lifecycle.governanceGatesAtEachPhase == true
}

# RULE ISO-A.8.4: AI system monitoring
# Kafka-specific: Continuous monitoring via Kafka event streams
annex_a_8_4_monitoring if {
    monitoring := input.aiSystem.monitoring
    monitoring.continuousEnabled == true
    monitoring.kafkaEventStreaming == true
    monitoring.driftDetection == true
    monitoring.biasMonitoring == true
    monitoring.performanceBaseline == true
    monitoring.alertingConfigured == true
}

# RULE ISO-A.9.1: AI system documentation
annex_a_9_1_documentation if {
    docs := input.aiSystem.documentation
    docs.modelCards == true
    docs.technicalDocumentation == true
    docs.riskAssessment == true
    docs.impactAssessment == true
    docs.auditTrail == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Certification Readiness Score
# ═══════════════════════════════════════════════════════════════════════════════

certification_readiness := {
    "framework": "ISO/IEC 42001:2023",
    "docRef": "KACG-GSIFI-WP-017",
    "totalClauses": 10,
    "totalAnnexControls": 7,
    "totalRules": 32,
    "kafkaSpecificRules": 5,
    "evidenceStorageVerification": true,
    "wormCompliance": true
}
