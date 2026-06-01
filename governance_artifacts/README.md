# Governance Artifacts Runbook

## Purpose
This directory provides machine-readable governance controls, policies, schemas, and fixtures for Sentinel v2.4 release gating.

## Local validation
Run the deterministic validator directly:

```bash
python tools/validate_governance_artifacts.py
```

Or run the full local validation bundle:

```bash
./tools/run_governance_gates.sh
```

Notes:
- The script always runs pytest/schema/invariant checks.
- OPA checks run only when `opa` is installed locally.

## CI entrypoints
- Primary workflow: `.github/workflows/sentinel-governance-gates.yml` (single consolidated `governance-gates` job)


For CI-equivalent local runs (strict OPA; auto-downloads OPA if missing):

```bash
STRICT_OPA=1 ./tools/run_governance_gates.sh --strict-opa
```

You can pin OPA download version with `OPA_VERSION` (default `v1.7.1`).

Binary cache location can be customized with `OPA_CACHE_DIR` (default `~/.cache/sentinel-governance`).

Optional integrity check: set `OPA_SHA256` to enforce downloaded binary checksum verification.

CI and local use the same runner script (`tools/run_governance_gates.sh`) to minimize validation drift.

The gate runner emits `/tmp/sentinel_governance_validation_report.json` for machine-readable evidence.

The report includes `opa_status` (`pass`, `fail`, or `skipped`) for policy gate traceability.

If the runner fails after the validator starts, it updates the report with `status: fail` and a failed runner step diagnostic before exiting.

The report also includes `runner_status` to distinguish validator success from end-to-end gate completion.
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
