# Governance Artifact Validation

This folder contains machine-readable governance artifacts and validation tooling for the 2026–2030 AGI/ASI governance blueprint.

## Local validation

```bash
python -m pip install -r docs/schemas/requirements-governance.txt
make governance-deps-check
yamllint -c .yamllint docs/schemas/agi_asi_governance_profile_2026_2030.yaml
python -m json.tool docs/schemas/compliance_control_mapping.json > /dev/null
python docs/schemas/governance_artifacts_validation.py
python docs/schemas/validate_artifact_inventory.py
opa fmt --fail docs/schemas/policies/ai_governance.rego
opa fmt --fail docs/schemas/policies/ai_governance_test.rego
opa test docs/schemas/policies/ai_governance.rego docs/schemas/policies/ai_governance_test.rego
python docs/schemas/test_governance_artifacts_validation.py -v
python docs/schemas/test_validation_deps.py -v
python docs/schemas/test_generate_evidence_bundle.py -v
python docs/schemas/generate_evidence_bundle.py
# Optional: include generation timestamp
python docs/schemas/generate_evidence_bundle.py --include-timestamp
python docs/schemas/verify_evidence_bundle.py
python docs/schemas/validate_evidence_manifest.py
python docs/schemas/run_governance_checks.py --max-tail-chars 1200 --timeout-seconds 300
# Optional diagnostic mode: keep running checks after a failure
python docs/schemas/run_governance_checks.py --continue-on-failure
python docs/schemas/validate_run_report.py
python docs/schemas/check_generated_artifacts.py
```

## Files
- `agi_asi_governance_profile_2026_2030.yaml`: governance profile.
- `agi_asi_governance_profile.schema.json`: schema for governance profile.
- `compliance_control_mapping.json`: control crosswalk.
- `compliance_control_mapping.schema.json`: schema for control crosswalk.
- `governance_artifacts_validation.py`: schema + semantic validator.
- `_validation_deps.py`: shared dependency loader for schema validators.
- `check_dependencies.py`: preflight checker for required Python governance dependencies.
- `validate_artifact_inventory.py`: validates inventory paths listed in the blueprint report.
- `policies/ai_governance.rego`: enforcement policy.
- `policies/ai_governance_test.rego`: policy unit tests.
- `testdata/invalid_profile_missing_framework.yaml`: negative fixture for framework coverage checks.
- `testdata/invalid_control_bad_domain.json`: negative fixture for control-domain mismatch checks.
- `generate_evidence_bundle.py`: generates evidence manifest with hashes and file sizes.
- `test_generate_evidence_bundle.py`: unit test for evidence manifest generation.
- `verify_evidence_bundle.py`: verifies manifest hashes/sizes against current files.
- `test_verify_evidence_bundle.py`: unit test for manifest verification and tamper detection.
- `evidence_bundle_manifest.schema.json`: schema for evidence manifest structure.
- `validate_evidence_manifest.py`: schema validation for the evidence manifest.
- `test_validate_evidence_manifest.py`: unit tests for evidence manifest schema validation.
- `test_validation_deps.py`: unit tests for dependency failure messaging consistency.
- `run_governance_checks.py`: runs all governance checks and emits machine-readable report.
- `validation_run_report.json`: generated execution report with command status/output tails plus optional `passed_checks`/`failed_checks` summary counters.
- `check_generated_artifacts.py`: verifies generated files are up to date and committed.
- `validation_run_report.schema.json`: schema for machine-readable run report.
- `validate_run_report.py`: validates run report against schema.
- `test_validate_run_report.py`: unit tests for run report schema validation.
- `test_run_governance_checks.py`: unit tests for run report runner options, fail-fast/continue behavior, and output normalization.
- `test_check_dependencies.py`: unit tests for dependency preflight checks and install hints.
- `CONTRIBUTING.md`: contribution and pre-PR checklist for governance artifacts.
- `.pre-commit-config.yaml`: optional pre-commit hooks for governance checks.

The validator supports explicit paths (`--yaml`, `--json`, `--yaml-schema`, `--json-schema`) for integration into alternate pipelines.

`make governance-deps-check` can be used as a fast preflight to verify required Python validation dependencies (`pyyaml`, `jsonschema`) are installed before running schema-dependent checks. The underlying checker (`check_dependencies.py`) also supports `--repo-root` and `--requirements` for custom environment bootstrap hints and emits repo-local install paths using the `$REPO_ROOT/...` token for deterministic output.

By default, evidence manifests are deterministic (no timestamp) to minimize unnecessary diffs.

`run_governance_checks.py` executes commands from repository root, redacts absolute repository paths in captured output tails, adds `timed_out` metadata per check, and supports `--continue-on-failure` for full diagnostic runs.

For contribution workflow details, see `docs/schemas/CONTRIBUTING.md`.
