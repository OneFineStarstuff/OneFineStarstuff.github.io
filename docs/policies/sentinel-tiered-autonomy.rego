package sentinel.governance

import future.keywords.if

default allow = false

# Basic allow logic
allow if {
    not violation
}

# Violation: Tier 3 (ASI-class) requires dual authorization
violation[msg] if {
    input.risk_tier == "tier-3"
    count(input.authorizations) < 2
    msg := "Tier 3 workloads require dual-ASA authorization"
}

# Violation: GAI-SOC telemetry must be connected
violation[msg] if {
    input.telemetry_status != "CONNECTED"
    msg := "Telemetry link to GAI-SOC is broken; emergency containment triggered"
}

# Violation: G-SRI Index exceeds threshold
violation[msg] if {
    input.g_sri_index > 0.85
    msg := "Systemic Risk Index (G-SRI) exceeds safety threshold"
}

# Containment Invariant: Human override availability
human_override_must_be_available if {
    input.override_ready == true
}

tier_3_requires_dual_authorization if {
    input.risk_tier == "tier-3"
}
