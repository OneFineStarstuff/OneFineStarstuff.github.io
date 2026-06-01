# Governance Artifacts Validation

This folder contains machine-readable governance artifacts for the
`AGI_ASI_GSIFI_Blueprint_2026_2030.md` strategy package.

## Files
- `control_library.yaml`
- `model_registry.json`
- `annex_iv_dossier_template.yaml`
- `board_kpi_kri_dashboard_schema.json`
- `containment_runbooks.yaml`
- `incident_taxonomy_gaics.json`
- `rego/high_impact_credit.rego`
- `validate_artifacts.py`

## Local validation
```bash
python3 governance_artifacts/validate_artifacts.py
python3 governance_artifacts/validate_artifacts.py --json
python3 governance_artifacts/validate_artifacts.py --quiet
python3 governance_artifacts/validate_artifacts.py --quiet --output artifacts/validator-output.json
python3 governance_artifacts/validate_artifacts.py --list-checks
python3 governance_artifacts/validate_artifacts.py --list-checks --json
python3 governance_artifacts/validate_artifacts.py --json --check validate_control_library
python3 governance_artifacts/validate_artifacts.py --version
python3 governance_artifacts/validate_artifacts.py --version --json
python3 -m unittest discover -s tests -p "test_validate_artifacts.py"
```

## Validation scope
- Required-key checks for JSON/YAML artifacts.
- Basic consistency checks (non-empty controls, model metadata fields).
- Rego policy token checks for expected governance constraints.
- JSON output payloads include `generated_at_utc` for audit traceability.

## CI
Validation is executed on every pull request and push to `main` via:
- `.github/workflows/governance-artifacts-validate.yml`
