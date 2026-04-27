# KACG-GSIFI-WP-017: EU AI Act Kafka Enforcement Policy
# Policy Group: compliance.euAiAct.kafka.* (28 rules)
# Purpose: Enforce EU AI Act requirements specific to Kafka-based AI governance
#          infrastructure, including Art. 9 (Risk Management), Art. 10 (Data),
#          Art. 12 (Record-Keeping), Art. 13 (Transparency), Art. 14 (Human Oversight)
# Framework: EU AI Act (Regulation (EU) 2024/1689)
# Last Updated: 2026-04-03

package compliance.eu_ai_act.kafka

import future.keywords.in
import future.keywords.if

# =====================================================================
# Article 6 - Classification of High-Risk AI Systems
# =====================================================================

# RULE EUAIA-K-001: AI system risk classification
art_6_classification if {
    input.aiSystem.riskClassification in ["HIGH_RISK", "LIMITED_RISK", "MINIMAL_RISK"]
    input.aiSystem.classificationJustification != ""
    input.aiSystem.classificationDate != ""
    input.aiSystem.classificationPublishedToKafka == true
}

# =====================================================================
# Article 9 - Risk Management System
# =====================================================================

# RULE EUAIA-K-002: Continuous risk management via Kafka streams
art_9_1_risk_management if {
    rm := input.aiSystem.riskManagement
    rm.continuousProcess == true
    rm.kafkaRiskEventsEnabled == true
    rm.riskAssessmentFrequency in ["CONTINUOUS", "WEEKLY", "MONTHLY"]
}

# RULE EUAIA-K-003: Risk identification and analysis
art_9_2_risk_identification if {
    risks := input.aiSystem.identifiedRisks
    count(risks) >= 1
    every risk in risks {
        risk.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        risk.mitigation != ""
    }
}

# RULE EUAIA-K-004: Risk mitigation measures
art_9_4_risk_mitigation if {
    input.aiSystem.riskMitigation.measuresImplemented == true
    input.aiSystem.riskMitigation.residualRiskAcceptable == true
    input.aiSystem.riskMitigation.testingCompleted == true
}

# =====================================================================
# Article 10 - Data and Data Governance
# =====================================================================

# RULE EUAIA-K-005: Training data governance via Kafka
art_10_1_data_governance if {
    data := input.aiSystem.dataGovernance
    data.qualityScore >= 0.85
    data.relevanceAssessed == true
    data.representativenessAssessed == true
    data.freeOfErrors == true
    data.completenessScore >= 0.90
}

# RULE EUAIA-K-006: Data quality monitoring via Kafka streams
art_10_2_data_monitoring if {
    monitoring := input.aiSystem.dataMonitoring
    monitoring.kafkaEnabled == true
    monitoring.piiDetectionRate >= 0.997
    monitoring.dataQualityGatesActive == true
    monitoring.biasDetectionEnabled == true
}

# RULE EUAIA-K-007: Training data documentation
art_10_5_data_documentation if {
    docs := input.aiSystem.dataDocumentation
    docs.datasetDescription != ""
    docs.collectionMethodology != ""
    docs.preprocessingSteps != null
    docs.statisticalProperties != null
}

# =====================================================================
# Article 12 - Record-Keeping (Kafka WORM)
# =====================================================================

# RULE EUAIA-K-008: Automatic event logging to Kafka WORM
art_12_1_record_keeping if {
    logging := input.aiSystem.recordKeeping
    logging.kafkaWormEnabled == true
    logging.retentionYears >= 10
    logging.eventTypes != null
    count(logging.eventTypes) >= 5
}

# RULE EUAIA-K-009: Log completeness validation
art_12_2_log_completeness if {
    logs := input.aiSystem.loggingCompleteness
    logs.inferenceEventsLogged == true
    logs.trainingEventsLogged == true
    logs.governanceDecisionsLogged == true
    logs.biasAlertsLogged == true
    logs.driftDetectionsLogged == true
}

# RULE EUAIA-K-010: Tamper-evident audit trail
art_12_3_tamper_evident if {
    audit := input.aiSystem.auditTrail
    audit.hashChainEnabled == true
    audit.hashAlgorithm == "SHA-256"
    audit.merkleTreeSealing == true
    audit.sealFrequency in ["HOURLY", "PER_BATCH"]
    audit.signatureAlgorithm == "Ed25519"
}

# RULE EUAIA-K-011: Evidence retention per EU AI Act
art_12_retention if {
    retention := input.aiSystem.retention
    retention.minimumYears >= 10
    retention.wormStorageMode == "COMPLIANCE"
    retention.legalHoldCapable == true
}

# =====================================================================
# Article 13 - Transparency and Provision of Information
# =====================================================================

# RULE EUAIA-K-012: System transparency documentation
art_13_1_transparency if {
    transparency := input.aiSystem.transparency
    transparency.modelCard == true
    transparency.technicalDocumentation == true
    transparency.userInstructions == true
    transparency.limitationsDocumented == true
}

# RULE EUAIA-K-013: Automated decision explanation
art_13_explanation if {
    explain := input.aiSystem.explainability
    explain.enabled == true
    explain.method != ""
    explain.confidenceScoreProvided == true
}

# =====================================================================
# Article 14 - Human Oversight
# =====================================================================

# RULE EUAIA-K-014: Human oversight mechanisms
art_14_1_human_oversight if {
    oversight := input.aiSystem.humanOversight
    oversight.enabled == true
    oversight.overrideCapability == true
    oversight.killSwitchAvailable == true
    oversight.confidenceThreshold >= 0.75
}

# RULE EUAIA-K-015: Kill-switch via Kafka events
art_14_killswitch if {
    ks := input.aiSystem.killSwitch
    ks.kafkaTopicEnabled == true
    ks.topicName == "ai.killswitch.events"
    ks.permanentRetention == true
    ks.minInsyncReplicas >= 3
    ks.responseTtlMs <= 500
}

# RULE EUAIA-K-016: Human-in-the-loop gates
art_14_human_in_loop if {
    hil := input.aiSystem.humanInLoop
    hil.gatesConfigured == true
    hil.confidenceThreshold >= 0.75
    hil.escalationPath != ""
    hil.kafkaEscalationEnabled == true
}

# =====================================================================
# Article 15 - Accuracy, Robustness, and Cybersecurity
# =====================================================================

# RULE EUAIA-K-017: Accuracy monitoring via Kafka
art_15_1_accuracy if {
    accuracy := input.aiSystem.accuracy
    accuracy.monitoringEnabled == true
    accuracy.kafkaMetricsEnabled == true
    accuracy.baselineDocumented == true
    accuracy.driftAlertThreshold != null
}

# RULE EUAIA-K-018: Robustness and adversarial testing
art_15_4_robustness if {
    robustness := input.aiSystem.robustness
    robustness.adversarialTesting == true
    robustness.failsafeMode != ""
    robustness.redundancyConfigured == true
}

# RULE EUAIA-K-019: Cybersecurity measures
art_15_5_cybersecurity if {
    security := input.aiSystem.cybersecurity
    security.mtlsEnabled == true
    security.spiffeIdentity == true
    security.encryptionAtRest == true
    security.encryptionInTransit == true
    security.penetrationTestDate != ""
}

# =====================================================================
# Article 17 - Quality Management System
# =====================================================================

# RULE EUAIA-K-020: Quality management documented
art_17_quality_management if {
    qms := input.aiSystem.qualityManagement
    qms.documented == true
    qms.regulatoryCompliance == true
    qms.riskManagementIntegrated == true
    qms.testingProcedures == true
    qms.changeManagement == true
}

# =====================================================================
# Article 26 - Obligations of Deployers
# =====================================================================

# RULE EUAIA-K-021: Deployer monitoring obligations
art_26_deployer_monitoring if {
    deployer := input.deployer
    deployer.monitoringEnabled == true
    deployer.incidentReportingProcess == true
    deployer.usageConsistentWithInstructions == true
}

# =====================================================================
# Article 61 - Post-Market Monitoring
# =====================================================================

# RULE EUAIA-K-022: Post-market monitoring via Kafka
art_61_post_market if {
    pms := input.aiSystem.postMarketMonitoring
    pms.planDocumented == true
    pms.kafkaMonitoringEnabled == true
    pms.driftDetectionEnabled == true
    pms.incidentDetection == true
    pms.reportingFrequency != ""
}

# =====================================================================
# Article 62 - Reporting of Serious Incidents
# =====================================================================

# RULE EUAIA-K-023: Incident reporting via Kafka WORM
art_62_incident_reporting if {
    incident := input.aiSystem.incidentReporting
    incident.processDocumented == true
    incident.maxReportingHours <= 72
    incident.kafkaIncidentTopicEnabled == true
    incident.wormRetentionEnabled == true
    incident.regulatorNotificationProcess == true
}

# =====================================================================
# Kafka-Specific Enforcement Controls
# =====================================================================

# RULE EUAIA-K-024: All governance topics configured
kafka_governance_topics if {
    topics := input.kafkaTopics
    required_topics := {
        "ai.inference.events",
        "ai.training.events",
        "ai.governance.decisions",
        "ai.bias.alerts",
        "ai.drift.detections",
        "ai.killswitch.events",
        "ai.compliance.evidence"
    }
    every t in required_topics {
        some topic in topics
        topic.name == t
    }
}

# RULE EUAIA-K-025: ACL enforcement active
kafka_acl_enforcement if {
    input.kafkaConfig.aclEnforcementEnabled == true
    input.kafkaConfig.opaAuthorizerDeployed == true
    input.kafkaConfig.defaultDeny == true
}

# RULE EUAIA-K-026: Schema registry enforced
kafka_schema_enforcement if {
    input.kafkaConfig.schemaRegistryEnabled == true
    input.kafkaConfig.schemaCompatibilityMode == "BACKWARD"
    input.kafkaConfig.schemaValidationOnProduce == true
}

# RULE EUAIA-K-027: WORM evidence storage operational
kafka_worm_operational if {
    worm := input.wormStorage
    worm.objectLockEnabled == true
    worm.retentionMode == "COMPLIANCE"
    worm.retentionDays >= 3652
    worm.durability == "99.999999999%"
}

# RULE EUAIA-K-028: Evidence signing operational
kafka_evidence_signing if {
    signing := input.evidenceSigning
    signing.enabled == true
    signing.algorithm == "Ed25519"
    signing.hsmBacked == true
    signing.latencyMs <= 300
}

# Compliance Summary
eu_ai_act_kafka_summary := {
    "framework": "EU AI Act (Regulation (EU) 2024/1689)",
    "docRef": "KACG-GSIFI-WP-017",
    "totalRules": 28,
    "kafkaSpecificRules": 12,
    "articlesTargeted": ["6", "9", "10", "12", "13", "14", "15", "17", "26", "61", "62"],
    "wormRetentionYears": 10,
    "killSwitchTopicConfigured": true,
    "evidenceSigningEnabled": true,
    "schemaRegistryEnforced": true
}
