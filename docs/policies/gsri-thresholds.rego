package sentinel.gsri

import future.keywords.if

default allow_inference = false

# Thresholds defined in G-SRI Methodology v1
thresholds := {
    "low": 0.40,
    "elevated": 0.70,
    "high": 0.90
}

# Inference gating based on systemic risk
allow_inference if {
    input.g_sri_score <= thresholds.low
}

# Elevated risk requires Red Dawn isolation
allow_inference if {
    input.g_sri_score > thresholds.low
    input.g_sri_score <= thresholds.elevated
    input.environment == "AIR_GAPPED_SANDBOX"
}

# High risk requires Dual-ASA + Multi-Jurisdiction Weight Synthesis
allow_inference if {
    input.g_sri_score > thresholds.elevated
    input.g_sri_score <= thresholds.high
    count(input.asa_authorizations) >= 2
    input.weight_shard_count >= 3
}

# Systemic Critical (>0.90) is always blocked regardless of authorizations
# unless explicitly overridden by ICGC Global Safety Anchor
