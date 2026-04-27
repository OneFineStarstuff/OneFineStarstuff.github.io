# OECD AI Principles Governance Policy
# Document: FSAI-GSIFI-WP-018
# Version: 1.0.0
# Date: 2026-04-06
# Purpose: Enforce OECD AI Principles (2019, updated 2024) alignment
# Principles: Inclusive growth, Human values, Transparency, Robustness, Accountability
# Rules: 18

package oecd_ai_principles

import future.keywords.in

# Principle 1: Inclusive Growth, Sustainable Development, and Well-being
rule_OECD_001 {
  input.ai_system.impact_assessment.inclusive_growth_score >= 0.70
}

rule_OECD_002 {
  input.ai_system.impact_assessment.sustainability_review == true
}

# Principle 2: Human-Centred Values and Fairness
rule_OECD_003 {
  input.ai_system.fairness.disparate_impact_ratio >= 0.80
}

rule_OECD_004 {
  input.ai_system.fairness.protected_attributes_tested >= 5
}

rule_OECD_005 {
  input.ai_system.human_oversight.enabled == true
}

# Principle 3: Transparency and Explainability
rule_OECD_006 {
  input.ai_system.transparency.model_card_published == true
}

rule_OECD_007 {
  input.ai_system.transparency.explainability_method != ""
}

rule_OECD_008 {
  input.ai_system.transparency.data_provenance_documented == true
}

rule_OECD_009 {
  input.ai_system.transparency.algorithmic_impact_assessment == true
}

# Principle 4: Robustness, Security, and Safety
rule_OECD_010 {
  input.ai_system.robustness.adversarial_testing == true
}

rule_OECD_011 {
  input.ai_system.robustness.drift_monitoring_enabled == true
}

rule_OECD_012 {
  input.ai_system.robustness.fallback_mechanism == true
}

rule_OECD_013 {
  input.ai_system.security.penetration_tested == true
}

rule_OECD_014 {
  input.ai_system.robustness.psi_threshold <= 0.25
}

# Principle 5: Accountability
rule_OECD_015 {
  input.ai_system.accountability.raci_defined == true
}

rule_OECD_016 {
  input.ai_system.accountability.audit_trail_enabled == true
}

rule_OECD_017 {
  input.ai_system.accountability.incident_response_plan == true
}

rule_OECD_018 {
  input.ai_system.accountability.regulatory_reporting_enabled == true
}

# Summary
oecd_summary = {
  "total_rules": 18,
  "principles_covered": 5,
  "alignment": "OECD AI Principles (2019, updated 2024)"
}
