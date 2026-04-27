package sentinel.ai.governance

default allow := false

authorized_tiers := {"L1", "L2", "L3"}
prohibited_use_cases := {
	"social_scoring",
	"biometric_mass_surveillance",
	"fully_automated_credit_denial_without_recourse",
}

required_docs := {
	"model_card",
	"system_card",
	"validation_report",
}

# Primary decision
allow if {
	valid_tier
	not prohibited
	docs_complete
	validation_gate_passed
	human_oversight_gate_passed
	runtime_resilience_gate_passed
}

valid_tier if {
	input.model.risk_tier in authorized_tiers
}

prohibited if {
	input.use_case in prohibited_use_cases
}

docs_complete if {
	missing_docs_count == 0
}

missing_docs_count := count({d | d := required_docs[_]; not input.artifacts[d]})

validation_gate_passed if {
	input.model.risk_tier == "L1"
}

validation_gate_passed if {
	input.model.risk_tier != "L1"
	input.validation.independent == true
	input.validation.status == "pass"
	input.validation.challenger_coverage >= 0.8
}

human_oversight_gate_passed if {
	input.model.risk_tier == "L1"
}

human_oversight_gate_passed if {
	input.model.risk_tier != "L1"
	input.oversight.human_in_loop == true
	input.oversight.contestation_path == true
	input.oversight.sla_hours <= 72
}

runtime_resilience_gate_passed if {
	input.runtime.policy_logging_enabled == true
	input.runtime.kill_switch_armed == true
	input.runtime.incident_channel_registered == true
}

# Exposed diagnostics
risk_level := "critical" if {
	input.model.risk_tier == "L3"
}

risk_level := "high" if {
	input.model.risk_tier == "L2"
}

risk_level := "moderate" if {
	input.model.risk_tier == "L1"
}

deny_reasons[reason] if {
	not valid_tier
	reason := "Model risk tier is missing or invalid"
}

deny_reasons[reason] if {
	prohibited
	reason := "Use case is prohibited by policy"
}

deny_reasons[reason] if {
	missing_docs_count > 0
	reason := sprintf("Required artifacts missing (%v)", [missing_docs_count])
}

deny_reasons[reason] if {
	not validation_gate_passed
	reason := "Independent validation/challenger standards not met"
}

deny_reasons[reason] if {
	not human_oversight_gate_passed
	reason := "Human oversight and contestation requirements not met"
}

deny_reasons[reason] if {
	not runtime_resilience_gate_passed
	reason := "Runtime resilience controls (logging/kill switch/incident channel) missing"
}
