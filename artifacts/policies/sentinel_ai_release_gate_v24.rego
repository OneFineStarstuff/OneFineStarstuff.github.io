package sentinel.release.v24

import rego.v1

default allow := false

required_evidence := {
  "annex_iv_complete",
  "model_validation_approved",
  "containment_ready",
  "zk_verified",
  "bbom_current",
  "owner_attested",
}

model_validation_approved if {
  input.model_validation.status == "approved"
}

zk_proof_verified if {
  input.zk.last_verified
}

allow if {
  count(deny) == 0
}

deny contains msg if {
  input.risk_tier == "tier_1_high_risk"
  not input.annex_iv_complete
  msg := "tier-1 high-risk release requires complete Annex IV dossier"
}

deny contains msg if {
  input.uses_gpai
  not input.gpai_supplier_due_diligence_complete
  msg := "GPAI-dependent release requires supplier due diligence and systemic-risk screening"
}

deny contains msg if {
  not model_validation_approved
  msg := "model validation must be approved before regulated deployment"
}

deny contains msg if {
  input.autonomy_level >= 3
  not input.containment.egress_default_deny
  msg := "high-agency agent requires default-deny egress containment"
}

deny contains msg if {
  input.autonomy_level >= 3
  not input.containment.kill_switch_tested
  msg := "high-agency agent requires tested kill switch"
}

deny contains msg if {
  input.risk_tier == "tier_1_high_risk"
  not zk_proof_verified
  msg := "tier-1 high-risk release requires verified ZK compliance proof metadata"
}

deny contains msg if {
  input.g_sri_score >= 75
  not input.board_risk_committee_exception
  msg := "systemic-risk deployment requires board risk committee exception"
}

evidence_status[e] := "present" if {
  e := required_evidence[_]
  input.evidence[e]
}

evidence_status[e] := "missing" if {
  e := required_evidence[_]
  not input.evidence[e]
}
