# Changelog

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
