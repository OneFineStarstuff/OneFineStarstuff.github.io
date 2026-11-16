# ANSM marketing-compliance profile (WP-108)

First domain-specific compliance-as-code profile beyond finance: a deny-by-default
OPA/Rego policy for promotional material of medicinal products under ANSM oversight,
with GDPR minimisation for HCP data and EU AI Act transparency alignment.

## Mapping

| Rule | Requirement | Regime anchor |
|---|---|---|
| ANSM-R1 | Substantiation evidence digest present | ANSM advertising rules; OSCAL seed catalog control ANSM-1 |
| ANSM-R2 | No off-label claims (approved SmPC scope) | ANSM advertising rules; OSCAL ANSM-2 |
| ANSM-R3 | Mandatory safety information on consumer material | ANSM + EU pharmacovigilance; OSCAL ANSM-3 |
| ANSM-R4 | HCP personal data redacted | GDPR Art. 5(1)(c) minimisation; OSCAL GDPR-5 |
| ANSM-R5 | AI assistance disclosed | EU AI Act transparency; OSCAL EUAIA-13 |

## Usage

    opa eval -d compliance/ansm/ansm-marketing-reviewer.rego -i material.json data.gien.compliance.ansm

Gate decisions are written to the evidence ledger; the profile is advisory in the
M3 compliance matrix until college adjudication promotes it to enforced.

*Fictional-simulation disclaimer: this profile is a governance-simulation artefact and does not constitute legal or regulatory advice.*
