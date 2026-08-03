# Contributing: Governance Artifacts

This repository includes a machine-readable governance bundle used for audit and regulatory workflows.

## Before opening a PR

1. Install prerequisites:
   ```bash
   python -m pip install -r docs/schemas/requirements-governance.txt
   ```
2. Run the full governance check chain:
   ```bash
   make governance-deps-check
   make governance-validate
   make governance-artifact-inventory
   make governance-policy-test
   make governance-validator-test
   make governance-evidence-manifest
   make governance-evidence-verify
   make governance-evidence-schema
   make governance-report
   make governance-report-schema
   make governance-check-generated
   ```
3. Ensure generated files are committed:
   - `docs/schemas/evidence_bundle_manifest.json`
   - `docs/schemas/validation_run_report.json`

## Notes on deterministic reports

- `make governance-report` runs `run_governance_checks.py --max-tail-chars 1200` and applies per-command timeouts (default 300s).
- For debugging CI failures, run `python docs/schemas/run_governance_checks.py --continue-on-failure` to capture all failing/passing checks in one report.
- The run report redacts absolute repository paths to `$REPO_ROOT`, records `timed_out` per check, and may include `passed_checks`/`failed_checks` summary counters for quick triage.

## Optional pre-commit setup

```bash
pip install pre-commit
pre-commit install
```

Pre-commit hooks are defined in `.pre-commit-config.yaml` and run governance checks automatically.
