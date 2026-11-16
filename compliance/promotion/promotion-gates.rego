# Promotion gate policy (WP-110, per the WP-091 evidence contract).
# Deny-by-default OPA-Rego gate for promoting webapp/telemetry releases and
# compliance profile changes in the GIEN governance pipeline. A change may be
# promoted only when the sealed-evidence, band, and honesty invariants hold.
#
# Fictional governance simulation artefact; deny-by-default by design.
package gien.promotion

default allow := false

change := input.change

# PROMO-R1: the change must declare a work package (one WP per PR).
deny[msg] {
    not change.work_package
    msg := "PROMO-R1: change does not declare a work package"
}

# PROMO-R2: the change must reference the sealed dossier corpus it renders.
deny[msg] {
    not change.sealed_dossier_id
    msg := "PROMO-R2: change does not reference a sealed dossier corpus"
}

# PROMO-R3: the sealed corpus must carry its frozen Merkle root.
deny[msg] {
    not change.merkle_root
    msg := "PROMO-R3: no frozen Merkle root provided for the sealed corpus"
}

# PROMO-R4: Merkle roots are 0x-prefixed, 64 lowercase hex characters.
deny[msg] {
    root := change.merkle_root
    not re_match(`^0x[0-9a-f]{64}$`, root)
    msg := sprintf("PROMO-R4: Merkle root is not 0x-prefixed 64 lowercase hex: %v", [root])
}

# PROMO-R5 (WP-096): every touched artefact must link an evidence digest.
deny[msg] {
    some a in change.artefacts
    not a.digest
    msg := sprintf("PROMO-R5: artefact %v lacks an evidence digest", [a.path])
}

# PROMO-R6: artefact digests are 0x-prefixed, 64 lowercase hex characters.
deny[msg] {
    some a in change.artefacts
    digest := a.digest
    not re_match(`^0x[0-9a-f]{64}$`, digest)
    msg := sprintf("PROMO-R6: artefact %v digest is not 0x-prefixed 64 lowercase hex", [a.path])
}

# PROMO-R7: no promotion while any systemic-risk index is out of band.
deny[msg] {
    some i in change.index_bands
    i.band != "GREEN"
    msg := sprintf("PROMO-R7: index %v is %v at promotion time", [i.key, i.band])
}

# PROMO-R8: the evidence honesty declaration must be present.
deny[msg] {
    not change.evidence_honesty
    msg := "PROMO-R8: evidence honesty declaration missing"
}

# PROMO-R9: the static corpus cannot recompute the WORM root; overclaiming fails.
deny[msg] {
    change.evidence_honesty.root_recomputable == true
    msg := "PROMO-R9: root_recomputable must remain false for the static corpus (honesty model)"
}

# PROMO-R10: touched compliance profiles must evaluate pass under OPA.
deny[msg] {
    some p in change.compliance_profiles
    p.evaluation != "pass"
    msg := sprintf("PROMO-R10: compliance profile %v evaluation is %v", [p.name, p.evaluation])
}

# PROMO-R11: advisory-to-enforced promotions require college adjudication.
deny[msg] {
    some p in change.compliance_profiles
    p.promotion == "advisory_to_enforced"
    not p.college_adjudication_complete
    msg := sprintf("PROMO-R11: profile %v advisory-to-enforced promotion lacks college adjudication", [p.name])
}

allow {
    count(deny) == 0
}
