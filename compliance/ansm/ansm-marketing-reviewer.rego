# ANSM marketing-compliance reviewer profile (WP-108).
# First domain-specific compliance-as-code profile beyond finance:
# promotional material for medicinal products under ANSM oversight, with
# GDPR handling for healthcare-professional (HCP) data.
#
# Fictional governance simulation artefact; deny-by-default by design.
package gien.compliance.ansm

import future.keywords.in

default allow := false

material := input.material

# Deny unless the submission carries a substantiation evidence digest.
deny[msg] {
    not material.substantiation_digest
    msg := "ANSM-R1: promotional material lacks a substantiation evidence digest"
}

# Deny off-label claims: every claim must be inside the approved SmPC scope.
deny[msg] {
    some claim in material.claims
    not claim.in_approved_scope
    msg := sprintf("ANSM-R2: off-label claim detected: %v", [claim.text])
}

# Deny missing mandatory safety information on consumer-facing material.
deny[msg] {
    material.audience == "consumer"
    not material.mandatory_safety_information
    msg := "ANSM-R3: consumer-facing material lacks mandatory safety information"
}

# Deny unredacted HCP personal data (GDPR minimisation).
deny[msg] {
    some r in material.references
    r.contains_hcp_personal_data
    not r.redacted
    msg := sprintf("ANSM-R4: unredacted HCP personal data in reference %v", [r.id])
}

# Deny unpublished transparency metadata (EU AI Act transparency alignment).
deny[msg] {
    not material.ai_assistance_disclosed
    msg := "ANSM-R5: AI assistance in material preparation not disclosed"
}

allow {
    count(deny) == 0
}
