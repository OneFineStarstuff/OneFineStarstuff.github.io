package gsifi.ai.credit

import rego.v1

# Backs ECOA / GDPR Art. 22 / EU AI Act Art. 13 obligations: high-impact credit
# underwriting requires human review, >=3 reason codes, fairness within
# equal-opportunity delta, verified lineage, and no active incident.

base := {
	"model": {"use_case": "credit_underwriting"},
	"risk_tier": "high",
	"human_review": {"completed": true},
	"explainability": {"reason_codes_count": 3},
	"fairness": {"equal_opportunity_delta": 0.02},
	"data": {"lineage": {"verified": true}},
	"incident_flags": {"active": false},
}

test_allow_when_all_conditions_met if {
	allow with input as base
}

test_deny_message_when_no_human_review if {
	not allow with input as object.union(base, {"human_review": {"completed": false}})
	count(deny) > 0 with input as object.union(base, {"human_review": {"completed": false}})
}

test_block_when_too_few_reason_codes if {
	not allow with input as object.union(base, {"explainability": {"reason_codes_count": 2}})
}

test_block_when_fairness_delta_exceeded if {
	not allow with input as object.union(base, {"fairness": {"equal_opportunity_delta": 0.05}})
}

test_block_when_lineage_unverified if {
	not allow with input as object.union(base, {"data": {"lineage": {"verified": false}}})
}

test_block_when_incident_active if {
	not allow with input as object.union(base, {"incident_flags": {"active": true}})
}
