# Governance Artifact Validation

Run the validator from repository root:

```bash
python3 governance_blueprint/validation/validate_artifacts.py
```

Machine-readable report (for CI parsers):

```bash
python3 governance_blueprint/validation/validate_artifacts.py --json
```

Run validator self-tests (stdlib `unittest`):

```bash
python3 governance_blueprint/validation/selftest_validate_artifacts.py
python3 governance_blueprint/validation/selftest_run_validation_suite.py
```

Run full suite (manifest check + validator + lint + dashboard check + self-tests):

```bash
python3 governance_blueprint/validation/run_validation_suite.py
```

Optional full suite execution report (includes per-step statuses and embedded validator JSON):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --json-report governance-artifact-validation-report.json --suite-report governance-validation-suite-report.json
```

Quiet mode (less log noise in local scripts):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --quiet
```

Lint validation Python sources:

```bash
python3 governance_blueprint/validation/lint_python_sources.py
```

Validate dashboard wiring:

```bash
python3 governance_blueprint/validation/validate_dashboard_links.py
```

Generate/update artifact manifest:

```bash
python3 governance_blueprint/validation/generate_artifact_manifest.py
```

Refresh manifest timestamp explicitly (optional):

```bash
python3 governance_blueprint/validation/generate_artifact_manifest.py --stamp-now
```

Check artifact manifest freshness (CI-friendly):

```bash
python3 governance_blueprint/validation/generate_artifact_manifest.py --check
```

What the validator checks:
- Required headers and non-empty values in `control_mapping_matrix.csv`.
- Required top-level fields and property definitions in `evidence_event_schema.json`.
- Structural expectations in `opa/release_gate.rego` (baseline block + tiered `allow` rules).
- Required roadmap tokens and indentation sanity in `roadmap_2026_2030.yaml`.
- SHA-256 integrity verification using `artifact_manifest.json`.
- Python syntax compile checks across `governance_blueprint/validation/*.py`.
- Dashboard navigation link checks between whitepaper and blueprint pages.

CI automation:
- GitHub Actions workflow: `.github/workflows/governance-artifacts-ci.yml`.
- Runs `run_validation_suite.py` on PRs/pushes that touch governance blueprint assets.
- Optional local git hook enforcement via `.pre-commit-config.yaml`.

Optional local pre-commit setup:

- The included hook runs a fast check path (`--skip-selftest --quiet`) for better commit ergonomics.
- Full coverage remains enforced in CI and available locally via `make gov-suite` / `make gov-suite-ci`.


```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

This validator is intentionally dependency-light (standard library only) so it can run in minimal CI environments.

Convenience Make targets (repo root):

```bash
make gov-manifest
make gov-manifest-check
make gov-validate
make gov-validate-json
make gov-lint
make gov-dashboard-check
make gov-selftest
make gov-suite
make gov-suite-json
make gov-suite-report
make gov-suite-ci
make gov-clean
```


Note: The suite runner invokes scripts via the active Python interpreter (`sys.executable`) to avoid PATH/interpreter drift across local/CI environments.

Make targets honor `PYTHON` (default: `python3`) so teams can pin an interpreter explicitly when needed.


Exit code conventions (run_validation_suite.py):
- `0`: all checks passed.
- Any other non-zero code: propagated from an invoked check command (for example manifest/check/selftest failure codes).
- `3`: validator JSON output was malformed when `--json-report` was requested.


`make gov-suite-ci` runs the suite in quiet report mode, matching the CI workflow command line.


Optional: run through all steps even after failures (captures a fuller suite report):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --no-fail-fast --suite-report governance-validation-suite-report.json
```
