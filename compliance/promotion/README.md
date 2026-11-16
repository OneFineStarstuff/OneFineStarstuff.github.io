# Promotion gates (WP-110)

Deny-by-default OPA-Rego promotion gate for the GIEN governance pipeline, per the
WP-091 evidence contract. Fictional governance simulation artefact.

## Policy

    compliance/promotion/promotion-gates.rego  (package gien.promotion)

Rules PROMO-R1..R11:

| Rule | Invariant |
| --- | --- |
| PROMO-R1 | Change declares a work package (one WP per PR) |
| PROMO-R2 | Change references the sealed dossier corpus |
| PROMO-R3 | Frozen Merkle root present |
| PROMO-R4 | Merkle root is 0x-prefixed 64 lowercase hex |
| PROMO-R5 | Every touched artefact links an evidence digest (WP-096) |
| PROMO-R6 | Artefact digests are 0x-prefixed 64 lowercase hex |
| PROMO-R7 | No promotion while any systemic-risk index is out of band |
| PROMO-R8 | Evidence honesty declaration present |
| PROMO-R9 | root_recomputable stays false for the static corpus (honesty model) |
| PROMO-R10 | Touched compliance profiles evaluate pass under OPA |
| PROMO-R11 | Advisory-to-enforced profile promotions require college adjudication |

## Input contract

    {
      "change": {
        "work_package": "WP-110",
        "sealed_dossier_id": "GIEN-DOSSIER-2026-320",
        "merkle_root": "0x...",
        "artefacts": [{ "path": "...", "digest": "0x..." }],
        "index_bands": [{ "key": "g_sri", "band": "GREEN" }],
        "evidence_honesty": { "root_recomputable": false },
        "compliance_profiles": [
          { "name": "ansm-marketing-reviewer", "evaluation": "pass", "promotion": "none" }
        ]
      }
    }

## Evaluate

    opa eval -d compliance/promotion/promotion-gates.rego -i input.json data.gien.promotion

Wire as a CI promotion stage: promote only when the allow decision is true and the
deny set is empty. Rule PROMO-R11 is the gate that keeps the ANSM profile (WP-108)
advisory until the college adjudication completes.

*Fictional-simulation disclaimer: GIEN, Omni-Sentinel and all indices, filings,
signatures and Merkle roots referenced here are simulated artefacts and do not
describe real systems.*
