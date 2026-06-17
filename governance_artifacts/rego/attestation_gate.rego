package sentinel.attestation

import rego.v1

# Confidential-computing admission gate for the Omni-Sentinel execution
# environment. Backs OSCAL control env-01 (hardware-attested execution) and the
# PCR_MATCH=TRUE assertion used throughout the master reference docs.
#
# A T0/T1 workload may be ADMITTED only if it presents a fresh, structurally
# valid hardware attestation whose measured launch state matches a golden value
# from the approved reference-measurement registry, AND (for vTPM) whose PCR
# quote matches the expected policy digest.
#
# Inputs (input.attestation):
#   platform           "SEV-SNP" | "TDX"
#   report_valid       bool   - signature chain verified against AMD/Intel roots
#   measurement        string - launch measurement (SNP MEASUREMENT / TDX MRTD)
#   reported_tcb       int    - platform TCB / SVN reported in the report
#   nonce_fresh        bool   - verifier nonce echoed and within freshness window
#   vtpm:
#     quote_valid      bool   - vTPM quote signature verified against AK cert
#     pcr_digest       string - aggregate PCR digest from the quote
#   workload_tier      "T0".."T4"
#
# data.reference (golden registry, supplied at eval time via -d/-i bundle):
#   approved_measurements   set of approved launch measurements
#   expected_pcr_digest     the policy-mandated aggregate PCR digest
#   min_tcb                 minimum acceptable platform TCB/SVN

default allow := false

supported_platforms := {"SEV-SNP", "TDX"}

# PCR_MATCH is the single named predicate the docs reference.
pcr_match if {
	input.attestation.vtpm.quote_valid == true
	input.attestation.vtpm.pcr_digest == data.reference.expected_pcr_digest
}

measurement_approved if {
	data.reference.approved_measurements[input.attestation.measurement]
}

tcb_ok if {
	input.attestation.reported_tcb >= data.reference.min_tcb
}

allow if {
	supported_platforms[input.attestation.platform]
	input.attestation.report_valid == true
	input.attestation.nonce_fresh == true
	measurement_approved
	tcb_ok
	pcr_match
}

# Structured, machine-actionable denial reasons for SOC dashboards.
deny contains "unsupported_platform" if {
	not supported_platforms[input.attestation.platform]
}

deny contains "report_signature_invalid" if {
	input.attestation.report_valid != true
}

deny contains "stale_or_replayed_nonce" if {
	input.attestation.nonce_fresh != true
}

deny contains "measurement_not_in_golden_registry" if {
	not measurement_approved
}

deny contains "tcb_below_minimum" if {
	not tcb_ok
}

deny contains "pcr_mismatch" if {
	not pcr_match
}

# A convenience attribute SOC tooling can emit verbatim.
pcr_match_attribute := "PCR_MATCH=TRUE" if pcr_match

pcr_match_attribute := "PCR_MATCH=FALSE" if not pcr_match
