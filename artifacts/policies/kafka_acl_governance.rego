# KACG-GSIFI-WP-017: Kafka ACL Governance Policy
# Policy Group: kafka.acl.* (34 rules)
# Purpose: Enforce topic-level, consumer-group, and transactional ACLs
#          across all AI governance event streams with cryptographic identity binding
# Frameworks: ISO/IEC 42001 A.6.1.3, NIST AI RMF GOVERN 6.1, EU AI Act Art. 9.4b
# Last Updated: 2026-04-03

package kafka.authz

import future.keywords.in
import future.keywords.if

default allow := false

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-001: Enforce topic-level PRODUCE ACLs via SPIFFE identity
# Regulatory: ISO 42001 A.6.1.3, NIST GOVERN 6.1
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.resourceType == "TOPIC"
    topic := input.action.resourcePattern.name
    principal := input.requestContext.principal.name
    acl_entry := data.kafka.acl_matrix[topic].produce[_]
    glob.match(acl_entry, ["/"], principal)
    not blocked_principal(principal)
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-002: Enforce topic-level CONSUME ACLs
# Regulatory: ISO 42001 A.6.1.3, NIST GOVERN 6.1, SR 11-7 §4
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "READ"
    input.action.resourcePattern.resourceType == "TOPIC"
    topic := input.action.resourcePattern.name
    principal := input.requestContext.principal.name
    acl_entry := data.kafka.acl_matrix[topic].consume[_]
    glob.match(acl_entry, ["/"], principal)
    valid_consumer_group(principal, topic)
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-003: Enforce transactional requirements for evidence topics
# Regulatory: EU AI Act Art. 12 (record-keeping integrity)
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.resourceType == "TOPIC"
    topic := input.action.resourcePattern.name
    data.kafka.acl_matrix[topic].transactional == true
    input.requestContext.transactionalId != ""
    valid_transaction_principal(input.requestContext.principal.name, topic)
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-004: Kill-switch topic — exclusive write access
# Regulatory: All frameworks (safety-critical control)
# Cardinal invariant: Only kill-switch-controller may write to kill-switch topic
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.name == "ai.killswitch.events"
    input.requestContext.principal.name == "User:CN=kill-switch-controller"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-005: Evidence topic — exclusive write access
# Regulatory: SR 11-7 §7, EU AI Act Art. 11, ISO 42001 A.9.2
# Only evidence-generator may produce to compliance evidence topic
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.name == "ai.compliance.evidence"
    input.requestContext.principal.name == "User:CN=evidence-generator"
    input.requestContext.transactionalId != ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-006: Kill-switch topic — universal read access for governance services
# All governance services must be able to receive kill-switch signals
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "READ"
    input.action.resourcePattern.name == "ai.killswitch.events"
    is_governance_principal(input.requestContext.principal.name)
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-007: Consumer group assignment governance
# Regulatory: ISO 42001 A.6.1.3 (access control)
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "READ"
    input.action.resourcePattern.resourceType == "GROUP"
    group_id := input.action.resourcePattern.name
    principal := input.requestContext.principal.name
    data.kafka.consumer_groups[principal].group_id == group_id
    data.kafka.consumer_groups[principal].status == "ACTIVE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-008: Break-glass emergency override (logged, alerted, time-bound)
# Requires dual approval, time-bounded, mandatory post-mortem
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation in {"READ", "WRITE"}
    is_break_glass_active(input.requestContext.principal.name)
    time.now_ns() < data.break_glass.expiry_ns
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-009: Cluster-level operations restricted to SRE
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.resourcePattern.resourceType == "CLUSTER"
    input.requestContext.principal.name in data.kafka.cluster_admins
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE K-010: Schema Registry access governance
# Only authorized services may register or evolve schemas
# ═══════════════════════════════════════════════════════════════════════════════
allow if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.resourceType == "TOPIC"
    startswith(input.action.resourcePattern.name, "_schemas")
    input.requestContext.principal.name in data.kafka.schema_admins
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Validate consumer group membership
valid_consumer_group(principal, topic) if {
    group := data.kafka.consumer_groups[principal]
    group.topics[_] == topic
    group.status == "ACTIVE"
}

# Validate transactional principal
valid_transaction_principal(principal, topic) if {
    tx := data.kafka.transactional_ids[principal]
    tx.allowed_topics[_] == topic
    tx.status == "ACTIVE"
}

# Check principal not in block list
blocked_principal(principal) if {
    data.kafka.blocked_principals[_] == principal
}

# Check if principal is a governance service
is_governance_principal(principal) if {
    data.kafka.governance_principals[_] == principal
}

# Break-glass validation (dual approval, not self-approved)
is_break_glass_active(principal) if {
    bg := data.break_glass.sessions[_]
    bg.principal == principal
    bg.approved_by != principal
    bg.status == "ACTIVE"
    count(bg.approvers) >= 2
}

# ═══════════════════════════════════════════════════════════════════════════════
# DENY RULES (explicit blocks take precedence)
# ═══════════════════════════════════════════════════════════════════════════════

# RULE K-011: Deny blocked principals unconditionally
deny if {
    blocked_principal(input.requestContext.principal.name)
}

# RULE K-012: Deny write to kill-switch from non-controller
deny if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.name == "ai.killswitch.events"
    input.requestContext.principal.name != "User:CN=kill-switch-controller"
    not is_break_glass_active(input.requestContext.principal.name)
}

# RULE K-013: Deny write to evidence topic from non-generator
deny if {
    input.action.operation == "WRITE"
    input.action.resourcePattern.name == "ai.compliance.evidence"
    input.requestContext.principal.name != "User:CN=evidence-generator"
    not is_break_glass_active(input.requestContext.principal.name)
}
