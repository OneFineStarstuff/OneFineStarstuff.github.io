# Autonomous Agent Governance — DEPTHS Classification Policy
# GAF-GSIFI-WP-017, Domain 6/7 — AGI Safety & Master Blueprint
# Policy Group: PG-07 (Autonomous Agent)
# Regulatory alignment: EU AI Act Art. 6-9 (high-risk), NIST AI RMF GOVERN/MANAGE
#
# Enforces the DEPTHS (Deployment Evaluation Protocol for Trustworthy Hybrid Systems)
# classification and corresponding governance controls for autonomous AI agents.
# Levels L0 (Tool) through L5 (Self-multiplying) have escalating requirements.

package agent_governance.depths

import rego.v1

# DEPTHS Classification Levels
depths_levels := {
    "L0": {"name": "Tool", "max_autonomy": "none", "requires_kill_switch": false, "requires_board_approval": false, "requires_behavioral_sidecar": false, "requires_gascf": false},
    "L1": {"name": "Assistant", "max_autonomy": "suggestion", "requires_kill_switch": true, "requires_board_approval": false, "requires_behavioral_sidecar": false, "requires_gascf": false},
    "L2": {"name": "Executor", "max_autonomy": "approved_actions", "requires_kill_switch": true, "requires_board_approval": false, "requires_behavioral_sidecar": false, "requires_gascf": false},
    "L3": {"name": "Collaborator", "max_autonomy": "independent_in_scope", "requires_kill_switch": true, "requires_board_approval": false, "requires_behavioral_sidecar": true, "requires_gascf": false},
    "L4": {"name": "Depths-class", "max_autonomy": "self_directed_in_domain", "requires_kill_switch": true, "requires_board_approval": true, "requires_behavioral_sidecar": true, "requires_gascf": true},
    "L5": {"name": "Self-multiplying", "max_autonomy": "spawn_sub_agents", "requires_kill_switch": true, "requires_board_approval": true, "requires_behavioral_sidecar": true, "requires_gascf": true}
}

# CARDINAL INVARIANT: Self-multiplying agents MUST NEVER have write access to Tier 0
deny contains msg if {
    input.agent.depth_level == "L5"
    some access in input.agent.system_access
    access.tier == 0
    access.permission == "write"
    msg := sprintf(
        "CARDINAL INVARIANT VIOLATION: Agent '%s' (L5 Self-multiplying) has write access to Tier 0 system '%s'. Self-multiplying agents shall NEVER receive write access to identity systems, kill-switch mechanisms, or governance policy engines.",
        [input.agent.agent_id, access.system_name]
    )
}

# DENY: L4+ agent without board approval
deny contains msg if {
    level := input.agent.depth_level
    depths_levels[level].requires_board_approval
    not input.agent.board_approval_granted
    msg := sprintf(
        "GOVERNANCE VIOLATION: Agent '%s' (DEPTHS %s/%s) requires Board AI Sub-committee approval before deployment. No approval on record.",
        [input.agent.agent_id, level, depths_levels[level].name]
    )
}

# DENY: Agent without kill-switch when required
deny contains msg if {
    level := input.agent.depth_level
    depths_levels[level].requires_kill_switch
    not input.agent.kill_switch_enabled
    msg := sprintf(
        "SAFETY VIOLATION: Agent '%s' (DEPTHS %s) requires kill-switch capability. Kill-switch not enabled. Required latency: 50-280ms.",
        [input.agent.agent_id, level]
    )
}

# DENY: L3+ agent without behavioral sidecar
deny contains msg if {
    level := input.agent.depth_level
    depths_levels[level].requires_behavioral_sidecar
    not input.agent.behavioral_sidecar_active
    msg := sprintf(
        "GOVERNANCE VIOLATION: Agent '%s' (DEPTHS %s) requires behavioral sidecar monitoring via EAIP. Sidecar not active.",
        [input.agent.agent_id, level]
    )
}

# DENY: L4+ agent without GASCF certification
deny contains msg if {
    level := input.agent.depth_level
    depths_levels[level].requires_gascf
    not input.agent.gascf_certified
    msg := sprintf(
        "CERTIFICATION VIOLATION: Agent '%s' (DEPTHS %s) requires GASCF certification (Level 3+) before deployment.",
        [input.agent.agent_id, level]
    )
}

# DENY: Kill-switch latency exceeds maximum
deny contains msg if {
    input.agent.kill_switch_enabled
    input.agent.kill_switch_latency_ms > 280
    msg := sprintf(
        "SAFETY VIOLATION: Agent '%s' kill-switch latency %dms exceeds maximum 280ms. Kill-switch must respond within 50-280ms per governance policy.",
        [input.agent.agent_id, input.agent.kill_switch_latency_ms]
    )
}

# DENY: Agent scope exceeds classification level
deny contains msg if {
    level := input.agent.depth_level
    level_idx := level_to_index(level)
    behavior_idx := autonomy_to_index(input.agent.observed_autonomy)
    behavior_idx > level_idx
    msg := sprintf(
        "SCOPE VIOLATION: Agent '%s' (DEPTHS %s) exhibiting autonomy level '%s' which exceeds its classification. Escalate to VP AI Safety.",
        [input.agent.agent_id, level, input.agent.observed_autonomy]
    )
}

# WARN: Agent approaching scope boundary
warn contains msg if {
    input.agent.scope_utilization_pct > 85
    msg := sprintf(
        "SCOPE WARNING: Agent '%s' scope utilization at %d%%. Consider preemptive scope review.",
        [input.agent.agent_id, input.agent.scope_utilization_pct]
    )
}

# DENY: No audit trail for L2+ agents
deny contains msg if {
    level := input.agent.depth_level
    level_to_index(level) >= 2
    not input.agent.audit_trail_active
    msg := sprintf(
        "AUDIT VIOLATION: Agent '%s' (DEPTHS %s) requires complete audit trail logging. Audit trail not active.",
        [input.agent.agent_id, level]
    )
}

# Helper: Map DEPTHS level to numeric index
level_to_index(level) := idx if {
    mapping := {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
    idx := mapping[level]
}

# Helper: Map observed autonomy to numeric index
autonomy_to_index(autonomy) := idx if {
    mapping := {"none": 0, "suggestion": 1, "approved_actions": 2, "independent_in_scope": 3, "self_directed_in_domain": 4, "spawn_sub_agents": 5}
    idx := mapping[autonomy]
}
