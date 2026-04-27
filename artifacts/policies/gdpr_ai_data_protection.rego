# KACG-GSIFI-WP-017: GDPR AI Data Protection Policy
# Policy Group: data.privacy.gdpr.* (26 rules)
# Purpose: Enforce GDPR requirements for AI systems processing personal data,
#          including automated decision-making (Art. 22), right to erasure (Art. 17),
#          and record keeping (Art. 30) via Kafka WORM audit infrastructure
# Framework: GDPR (Regulation (EU) 2016/679)
# Last Updated: 2026-04-03

package data.privacy.gdpr

import future.keywords.in
import future.keywords.if

# Article 5 - Principles Relating to Processing

# RULE GDPR-5.1a: Lawfulness, fairness, and transparency
art_5_1a_lawful_processing if {
    processing := input.dataProcessing
    processing.legalBasis in ["CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTERESTS"]
    processing.fairnessAssessed == true
    processing.transparencyNotice == true
}

# RULE GDPR-5.1b: Purpose limitation
art_5_1b_purpose_limitation if {
    input.dataProcessing.purposes != null
    count(input.dataProcessing.purposes) >= 1
    every purpose in input.dataProcessing.purposes {
        purpose.specified == true
        purpose.documented == true
    }
}

# RULE GDPR-5.1c: Data minimization
art_5_1c_data_minimization if {
    input.dataProcessing.minimizationAssessed == true
    input.dataProcessing.unnecessaryFieldsRemoved == true
}

# RULE GDPR-5.1d: Accuracy
art_5_1d_accuracy if {
    input.dataProcessing.accuracyMeasures == true
    input.dataProcessing.dataQualityScore >= 0.85
    input.dataProcessing.rectificationProcessExists == true
}

# RULE GDPR-5.1e: Storage limitation
art_5_1e_storage_limitation if {
    input.dataProcessing.retentionPolicy != ""
    input.dataProcessing.retentionScheduleDocumented == true
    input.dataProcessing.automaticDeletion == true
}

# RULE GDPR-5.1f: Integrity and confidentiality
art_5_1f_integrity if {
    security := input.dataProcessing.security
    security.encryptionAtRest == true
    security.encryptionInTransit == true
    security.accessControlEnforced == true
}

# RULE GDPR-5.2: Accountability
art_5_2_accountability if {
    input.dataProcessing.controllerIdentified == true
    input.dataProcessing.processingRecordsKept == true
    input.dataProcessing.dpiaCompleted == true
}

# Article 13/14 - Transparency for AI Systems

# RULE GDPR-13: Information to data subjects
art_13_transparency if {
    notice := input.dataProcessing.transparencyNotice
    notice.controllerIdentity != ""
    notice.processingPurposes != null
    notice.legalBasis != ""
    notice.retentionPeriod != ""
    notice.dataSubjectRights != null
    notice.automatedDecisionMaking != null
}

# Article 17 - Right to Erasure (Kafka ai.erasure.requests topic)

# RULE GDPR-17.1: Erasure request processing
art_17_1_erasure_processing if {
    erasure := input.erasureCapability
    erasure.supportedSystems != null
    count(erasure.supportedSystems) >= 1
    erasure.maxProcessingDays <= 30
    erasure.kafkaErasureTopicEnabled == true
    erasure.verificationProcess == true
}

# RULE GDPR-17.2: Erasure notification to recipients
art_17_2_erasure_notification if {
    input.erasureCapability.recipientNotification == true
    input.erasureCapability.downstreamSystemsNotified == true
}

# Article 22 - Automated Decision-Making

# RULE GDPR-22.1: Rights related to automated decision-making
art_22_1_automated_decisions if {
    ai_decision := input.automatedDecisionMaking
    ai_decision.humanInLoopAvailable == true
    ai_decision.explainabilityEnabled == true
    ai_decision.contestMechanism == true
}

# RULE GDPR-22.3: Suitable safeguards for automated decisions
art_22_3_safeguards if {
    safeguards := input.automatedDecisionMaking.safeguards
    safeguards.humanReviewProcess == true
    safeguards.rightToContestDecision == true
    safeguards.biasMitigation == true
    safeguards.confidenceThreshold >= 0.75
}

# Article 25 - Data Protection by Design and by Default

# RULE GDPR-25.1: Data protection by design
art_25_1_by_design if {
    design := input.dataProtectionByDesign
    design.privacyImpactConsidered == true
    design.minimizationByDefault == true
    design.pseudonymizationApplied == true
    design.encryptionImplemented == true
}

# RULE GDPR-25.2: Data protection by default
art_25_2_by_default if {
    defaults := input.dataProtectionByDefault
    defaults.minimalDataCollection == true
    defaults.restrictedAccessByDefault == true
    defaults.limitedRetentionByDefault == true
}

# Article 30 - Records of Processing (Kafka WORM)

# RULE GDPR-30.1: Controller record of processing
art_30_1_processing_records if {
    records := input.processingRecords
    records.controllerName != ""
    records.processingPurposes != null
    records.categoriesOfDataSubjects != null
    records.categoriesOfPersonalData != null
    records.recipientCategories != null
    records.retentionPeriods != null
    records.securityMeasures != null
    records.kafkaWormStorageEnabled == true
    records.retentionYears >= 5
}

# Article 32 - Security of Processing

# RULE GDPR-32.1: Appropriate technical and organizational measures
art_32_1_security if {
    security := input.securityMeasures
    security.pseudonymization == true
    security.encryptionAtRest == true
    security.encryptionInTransit == true
    security.confidentiality == true
    security.integrity == true
    security.availability == true
    security.resilience == true
    security.regularTesting == true
}

# Article 35 - DPIA

# RULE GDPR-35: DPIA for high-risk AI processing
art_35_dpia if {
    dpia := input.dpia
    dpia.completed == true
    dpia.systematicDescription == true
    dpia.necessityAssessment == true
    dpia.riskAssessment == true
    dpia.mitigationMeasures != null
    dpia.dpoConsulted == true
    dpia.approvalDate != ""
}

# PII Detection for Kafka Streams

# RULE GDPR-PII-001: PII detection rate meets threshold
pii_detection_threshold if {
    input.piiDetection.detectionRate >= 0.997
    input.piiDetection.scanEnabled == true
    input.piiDetection.realTimeScanning == true
}

# RULE GDPR-PII-002: PII masking enforcement
pii_masking_enforcement if {
    input.piiDetection.maskingEnabled == true
    input.piiDetection.maskingAppliedBeforePublish == true
}

# RULE GDPR-CONSENT-001: Consent changes tracked via Kafka
consent_tracking if {
    consent := input.consentManagement
    consent.kafkaTopicEnabled == true
    consent.topicName == "ai.consent.changes"
    consent.transactional == true
    consent.retentionYears >= 5
}

# Compliance Summary
gdpr_compliance_summary := {
    "framework": "GDPR (EU) 2016/679",
    "docRef": "KACG-GSIFI-WP-017",
    "totalRules": 26,
    "kafkaSpecificRules": 5,
    "articlesTargeted": ["5", "13", "14", "17", "22", "25", "30", "32", "35"],
    "piiDetectionThreshold": 0.997,
    "erasureTopicEnabled": true,
    "consentTopicEnabled": true,
    "wormRetentionYears": 5
}
