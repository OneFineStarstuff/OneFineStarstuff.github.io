package sentinel.release

import rego.v1

# Backs OSCAL release-gate semantics: deny-by-default on high-impact autonomous
# release unless containment ENFORCED + dual-control quorum + signed bundle +
# required controls (Omni-Sentinel safety + SR 11-7 validation) are satisfied.

compliant_input := {
	"model": {"risk_tier": "high"},
	"controls": {"SAF-OMNI-001": true, "MOD-SR11-7-VAL": true},
	"supervision": {"quorum": 2},
	"containment": {"mode": "ENFORCED"},
	"signatures": {"bundle_verified": true},
}

test_allow_when_all_controls_met if {
	allow with input as compliant_input
}

test_deny_when_quorum_insufficient if {
	not allow with input as object.union(compliant_input, {"supervision": {"quorum": 1}})
	count(deny) > 0 with input as object.union(compliant_input, {"supervision": {"quorum": 1}})
}

test_deny_when_containment_not_enforced if {
	not allow with input as object.union(compliant_input, {"containment": {"mode": "MONITOR"}})
}

test_deny_when_validation_control_false if {
	not allow with input as object.union(
		compliant_input,
		{"controls": {"SAF-OMNI-001": true, "MOD-SR11-7-VAL": false}},
	)
}

test_deny_when_signatures_unverified if {
	not allow with input as object.union(compliant_input, {"signatures": {"bundle_verified": false}})
}

test_default_deny_on_empty_input if {
	not allow with input as {}
	count(deny) > 0 with input as {}
}
