package egrc.fail_closed

# I-9 (+ I-4, I-5): any missing, malformed, or failed input denies the
# transition. Fail-closed by construction: allow requires a complete,
# valid input. FICTIONAL GOVERNANCE SIMULATION.

default allow = false

deny[msg] {
  not input.quorum_proof
  msg := "I-9: quorum proof absent"
}

deny[msg] {
  input.quorum_proof
  input.quorum_proof.status != "VALID"
  msg := sprintf("I-9: quorum proof status %s", [input.quorum_proof.status])
}

deny[msg] {
  not input.evidence_bundle
  msg := "I-9: evidence bundle reference absent"
}

deny[msg] {
  input.evidence_bundle
  not re_match("^0x[0-9a-f]{64}$", input.evidence_bundle.merkle_root)
  msg := "I-4/I-9: merkle_root is not 0x plus exactly 64 lowercase hex characters"
}

deny[msg] {
  input.evidence_bundle
  input.evidence_bundle.chain_linked != true
  msg := "I-5/I-9: evidence bundle is not chain-linked to the prior window root"
}

allow {
  count(deny) == 0
}
