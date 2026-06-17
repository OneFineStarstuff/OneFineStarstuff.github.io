package fairness.credit_decision

import rego.v1

# GC-IR obligation ob-ecoa-adverse-reason-codes (governance_artifacts/zk/gcir_obligation_example.yaml):
#   Adverse, fully-automated credit decisions MUST carry >=2 approved reason codes.
# Regimes: ECOA, GDPR Art. 22, EU AI Act Art. 13.
#
# This is the `rego` emission target of the GC-IR obligation. The cross-target
# harness (zk/gcir_harness.py) runs the SAME fixtures through this rule, through
# the Circom witness (SRC-fair-1), and against the TLA+ AdverseGate fixture
# expectations; any disagreement fails the build.

# Approved reason-code set (data.approved_reason_codes in GC-IR).
approved_reason_codes := {"RC01", "RC02", "RC03", "RC04", "RC05", "RC06", "RC07"}

default allow := false

# allow == the decision is COMPLIANT with the obligation.
# Non-adverse or non-fully-automated decisions are out of scope -> compliant by default.
allow if {
	not in_scope
}

allow if {
	in_scope
	count(input.decision.reason_codes) >= 2
	every rc in input.decision.reason_codes {
		approved_reason_codes[rc]
	}
}

in_scope if {
	input.decision.outcome == "adverse"
	input.decision.automation_level == "full"
}

deny contains "insufficient_reason_codes" if {
	in_scope
	count(input.decision.reason_codes) < 2
}

deny contains "unapproved_reason_code" if {
	in_scope
	some rc in input.decision.reason_codes
	not approved_reason_codes[rc]
}
