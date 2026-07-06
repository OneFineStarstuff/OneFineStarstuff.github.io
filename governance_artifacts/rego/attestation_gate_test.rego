package sentinel.attestation

import rego.v1

# Golden reference registry injected as data.reference for tests.
ref := {
	"approved_measurements": {
		"sha384:golden-snp-measurement-aaa",
		"sha384:golden-tdx-mrtd-bbb",
	},
	"expected_pcr_digest": "sha256:policy-pcr-digest-001",
	"min_tcb": 7,
}

good_snp := {"attestation": {
	"platform": "SEV-SNP",
	"report_valid": true,
	"measurement": "sha384:golden-snp-measurement-aaa",
	"reported_tcb": 8,
	"nonce_fresh": true,
	"vtpm": {"quote_valid": true, "pcr_digest": "sha256:policy-pcr-digest-001"},
	"workload_tier": "T0",
}}

test_admit_valid_snp_with_pcr_match if {
	allow with input as good_snp with data.reference as ref
	pcr_match with input as good_snp with data.reference as ref
}

test_admit_valid_tdx if {
	inp := {"attestation": object.union(good_snp.attestation, {
		"platform": "TDX",
		"measurement": "sha384:golden-tdx-mrtd-bbb",
	})}
	allow with input as inp with data.reference as ref
}

test_deny_unsupported_platform if {
	inp := {"attestation": object.union(good_snp.attestation, {"platform": "SGX-legacy"})}
	not allow with input as inp with data.reference as ref
	"unsupported_platform" in deny with input as inp with data.reference as ref
}

test_deny_invalid_report_signature if {
	inp := {"attestation": object.union(good_snp.attestation, {"report_valid": false})}
	not allow with input as inp with data.reference as ref
	"report_signature_invalid" in deny with input as inp with data.reference as ref
}

test_deny_replayed_nonce if {
	inp := {"attestation": object.union(good_snp.attestation, {"nonce_fresh": false})}
	not allow with input as inp with data.reference as ref
	"stale_or_replayed_nonce" in deny with input as inp with data.reference as ref
}

test_deny_measurement_not_golden if {
	inp := {"attestation": object.union(good_snp.attestation, {"measurement": "sha384:rogue-image"})}
	not allow with input as inp with data.reference as ref
	"measurement_not_in_golden_registry" in deny with input as inp with data.reference as ref
}

test_deny_tcb_rollback if {
	inp := {"attestation": object.union(good_snp.attestation, {"reported_tcb": 6})}
	not allow with input as inp with data.reference as ref
	"tcb_below_minimum" in deny with input as inp with data.reference as ref
}

test_deny_pcr_mismatch if {
	inp := {"attestation": object.union(
		good_snp.attestation,
		{"vtpm": {"quote_valid": true, "pcr_digest": "sha256:TAMPERED"}},
	)}
	not allow with input as inp with data.reference as ref
	"pcr_mismatch" in deny with input as inp with data.reference as ref
	pcr_match_attribute == "PCR_MATCH=FALSE" with input as inp with data.reference as ref
}

test_deny_vtpm_quote_invalid if {
	inp := {"attestation": object.union(
		good_snp.attestation,
		{"vtpm": {"quote_valid": false, "pcr_digest": "sha256:policy-pcr-digest-001"}},
	)}
	not allow with input as inp with data.reference as ref
	"pcr_mismatch" in deny with input as inp with data.reference as ref
}
