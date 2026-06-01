# Changelog

## Version 1.2.0
- Added regulator-ready AGI/ASI governance blueprint for 2026–2030 at `docs/reports/REGULATOR_READY_AGI_ASI_BLUEPRINT_2026_2030.md`.
- Added machine-readable regulator artifacts under `docs/reports/artifacts/`:
  - `gsifi_governance_policy_profile_2030.yaml`
  - `tier3_annex_iv_evidence_template.json`
  - `tiered_release_gate.rego`
- Added regulator artifact validator `scripts/validate_regulator_blueprint_artifacts.py` with human-readable, `--list-checks`, and `--json` output modes plus configurable `--base-dir`.
- Extended `scripts/run_blueprint_artifact_checks.sh` to execute regulator checks, support `--regulator-base-dir` and `--regulator-output-json`, and expose regulator checks in `--list-checks` mode.
- Added/updated pytest coverage:
  - `tests/test_validate_regulator_blueprint_artifacts.py`
  - `tests/test_run_blueprint_artifact_checks.py`
- Added operator documentation for validator commands in `QUICK_ACTION_GUIDE.md`.

## Version 1.1.0
- Added enterprise AI governance artifact package under `docs/artifacts/` with YAML source, canonical JSON export, JSON Schema contract, and example templates.
- Added governance tooling scripts for export, validation, and JUnit result summarization:
  - `scripts/export_governance_artifact_json.py`
  - `scripts/validate_governance_artifact.py`
  - `scripts/summarize_governance_test_results.py`
- Added Makefile-driven governance checks (`build-governance-json`, `check-governance-json-clean`, `validate-governance`, `test-governance-ci`, `summarize-governance-tests`).
- Added governance CI workflow (`.github/workflows/governance-artifact-validation.yml`) with summary publishing and test artifact upload.
- Added pytest coverage for exporter/validator/summarizer and pinned governance dev dependencies in `requirements-dev.txt`.

## Version 1.0.1
- Integrated NLP, CV, and Speech Processor modules.
- Added OAuth2 authentication.
- Implemented asynchronous processing for improved performance.
- Enhanced logging with loguru.
- Ensured compatibility with Jupyter notebooks using nest_asyncio.
