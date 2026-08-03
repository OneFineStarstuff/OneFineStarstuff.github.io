# Blueprint Artifact Starter Pack

This folder contains regulator-submission starter templates referenced by the
2026–2030 AGI/ASI governance blueprint.

## Files

- `T1_Executive_Attestation.md` — executive sign-off template.
- `T2_Control_Crosswalk.csv` — control-to-framework mapping starter.
- `T3_Model_Risk_Register.csv` — model inventory/risk register starter.
- `T4_Incident_Notification_Playbook.md` — incident notification workflow starter.
- `T5_RedTeam_Closure_Report.md` — red-team closure evidence template.
- `T6_Evidence_Manifest.json` — machine-readable evidence manifest example.
- `T6_Evidence_Manifest.schema.json` — JSON Schema for manifest validation.
- `T7_Runtime_Policy.rego` — starter Rego runtime policy.
- `T8_Kafka_Audit_ACL_Example.yaml` — starter Kafka ACL policy.
- `T9_K8s_NetworkPolicy_Example.yaml` — starter Kubernetes NetworkPolicy.

## Validation examples

Install validator dependencies first:

```bash
python -m pip install --disable-pip-version-check -r scripts/requirements-blueprint-validator.txt
```

```bash
python -m json.tool docs/reports/blueprint_artifacts/T6_Evidence_Manifest.json >/dev/null
python scripts/validate_blueprint_artifacts.py
python scripts/validate_blueprint_artifacts.py --json
python scripts/validate_blueprint_artifacts.py --base-dir docs/reports/blueprint_artifacts
bash scripts/run_blueprint_artifact_checks.sh
bash scripts/run_blueprint_artifact_checks.sh --list-checks
bash scripts/run_blueprint_artifact_checks.sh --help
bash scripts/run_blueprint_artifact_checks.sh --skip-pytest --output-json /tmp/blueprint-validation.json
pytest -q tests/test_validate_blueprint_artifacts.py tests/test_run_blueprint_artifact_checks.py
```

## Validator coverage

`validate_blueprint_artifacts.py` checks file presence, CSV headers + sample row semantics (risk tier/date formats), evidence manifest contract + schema keyword constraints + timestamp format, schema metadata, runtime policy guardrails, and YAML parsing + required semantics for Kafka ACL and Kubernetes NetworkPolicy examples. Use `--json` for machine-readable output in pipelines, and `--base-dir` to validate an alternate artifact directory.

## Validator check IDs

The validator emits results with these stable check names:

- `presence`
- `manifest_structure`
- `manifest_timestamp`
- `schema_metadata`
- `schema_contract`
- `schema_constraints`
- `csv_semantics`
- `rego_guardrails`
- `yaml_examples`


Tip: run `bash scripts/run_blueprint_artifact_checks.sh` for the same sequence used in CI (including dependency installation).


Use `bash scripts/run_blueprint_artifact_checks.sh --skip-install` to skip dependency installation if your environment is already prepared.


For quick smoke checks without running tests, use `bash scripts/run_blueprint_artifact_checks.sh --skip-pytest`.


Use `--output-json <path>` to control where JSON validation results are written.
