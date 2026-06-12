package sentinel.systemic_risk

# Guardrails for Sentinel v2.4 (2026-2035)
# Enforces G-SRI thresholds and PQC audit requirements.

default allow = false

# Allow if risk is low and audit plane is secure
allow {
    input.g_sri_score < 0.75
    input.audit_plane.pqc_enabled == true
    input.audit_plane.signature_scheme == "ML-DSA-65"
    input.execution_plane.confidential_enclave == true
    input.execution_plane.vtpm_attested == true
}

# Critical breach containment
deny[msg] {
    input.g_sri_score >= 0.90
    msg := "CRITICAL SYSTEMIC RISK BREACH: Initiating autonomous kill-switch."
}

# Operational oversight requirement for high-risk tiers
deny[msg] {
    input.risk_tier == "high"
    input.supervision.quorum < 2
    msg := "Insufficient supervisory quorum for high-risk model action."
}
