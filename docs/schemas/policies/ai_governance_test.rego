package sentinel.ai.governance

test_allow_for_l2_when_all_controls_present if {
	allow with input as {
		"use_case": "credit_underwriting_support",
		"model": {"risk_tier": "L2"},
		"artifacts": {"model_card": true, "system_card": true, "validation_report": true},
		"validation": {"independent": true, "status": "pass", "challenger_coverage": 0.9},
		"oversight": {"human_in_loop": true, "contestation_path": true, "sla_hours": 24},
		"runtime": {"policy_logging_enabled": true, "kill_switch_armed": true, "incident_channel_registered": true},
	}
}

test_deny_for_prohibited_use_case if {
	not allow with input as {
		"use_case": "social_scoring",
		"model": {"risk_tier": "L2"},
		"artifacts": {"model_card": true, "system_card": true, "validation_report": true},
		"validation": {"independent": true, "status": "pass", "challenger_coverage": 0.9},
		"oversight": {"human_in_loop": true, "contestation_path": true, "sla_hours": 24},
		"runtime": {"policy_logging_enabled": true, "kill_switch_armed": true, "incident_channel_registered": true},
	}
}

test_deny_for_missing_artifacts if {
	not allow with input as {
		"use_case": "credit_underwriting_support",
		"model": {"risk_tier": "L2"},
		"artifacts": {"model_card": true, "system_card": false, "validation_report": false},
		"validation": {"independent": true, "status": "pass", "challenger_coverage": 0.9},
		"oversight": {"human_in_loop": true, "contestation_path": true, "sla_hours": 24},
		"runtime": {"policy_logging_enabled": true, "kill_switch_armed": true, "incident_channel_registered": true},
	}
}

test_deny_for_weak_challenger_coverage if {
	not allow with input as {
		"use_case": "credit_underwriting_support",
		"model": {"risk_tier": "L3"},
		"artifacts": {"model_card": true, "system_card": true, "validation_report": true},
		"validation": {"independent": true, "status": "pass", "challenger_coverage": 0.3},
		"oversight": {"human_in_loop": true, "contestation_path": true, "sla_hours": 24},
		"runtime": {"policy_logging_enabled": true, "kill_switch_armed": true, "incident_channel_registered": true},
	}
}
