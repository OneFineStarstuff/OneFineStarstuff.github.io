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
python3 governance_blueprint/validation/selftest_generate_artifact_manifest.py
python3 governance_blueprint/validation/selftest_run_validation_suite.py
python3 -m unittest discover governance_blueprint/validation -p 'selftest_*.py'
```

Equivalent convenience target:

```bash
make gov-selftest
```

Discover/run all validator selftests via unittest pattern:

```bash
make gov-selftest-discover
```

Note: default `python -m unittest discover` uses pattern `test*.py`; this repo's validator tests use `selftest_*.py`, so pass `-p "selftest_*.py"` (or use the Make target above).

Run full suite (manifest check + validator + lint + dashboard check + self-tests):

```bash
python3 governance_blueprint/validation/run_validation_suite.py
```

Optional full suite execution report (includes per-step statuses and embedded validator JSON):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --json-report governance-artifact-validation-report.json --suite-report governance-validation-suite-report.json
```

The generated report files are intentionally git-ignored:
- `governance-artifact-validation-report.json`
- `governance-validation-suite-report.json`

Quiet mode (less log noise in local scripts):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --quiet
```


Optional explicit OPA binary pinning (recommended in CI if OPA is available):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --opa-bin /path/to/opa
python3 governance_blueprint/validation/validate_artifacts.py --opa-bin /path/to/opa
# Enforce OPA presence (fail fast if unavailable)
python3 governance_blueprint/validation/run_validation_suite.py --require-opa --opa-bin /path/to/opa
python3 governance_blueprint/validation/validate_artifacts.py --require-opa --opa-bin /path/to/opa
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
- Required headers and minimum row count in `regulatory_playbook_mapping_2026_2035.csv`.
- Required baseline framework coverage in `regulatory_playbook_mapping_2026_2035.csv` (case-insensitive match), including:
  - `EU AI Act Annex IV`
  - `NIST AI RMF 1.0`
  - `ISO IEC 42001 AIMS`
  - `Basel III IV`
  - `UK SMCR`
  - `ICGC compute governance`
- Required top-level fields and property definitions in `evidence_event_schema.json`.
- Structural expectations in `opa/release_gate.rego` (baseline block + tiered `allow` rules).
- Required roadmap tokens and indentation sanity in `roadmap_2026_2030.yaml`.
- Required segment names/order and extension markers in `roadmap_2026_2035.yaml`.
- Required semantic roadmap tokens in `roadmap_2026_2035.yaml` for horizon and target thresholds:
  - `start: 2026-07-01`, `end: 2035-12-31`
  - `critical_breach_mttc_seconds_max: 90`
  - `supervisory_requests_via_api_pct: 95`
  - `manual_dossier_assembly_pct_max: 5`
- SHA-256 integrity verification using `artifact_manifest.json`.
- Structural expectations in `opa/release_gate.rego` and `opa/systemic_risk_guardrails.rego`, plus optional OPA parse checks when `opa` is installed (or when `OPA_BIN` is set).
- Required schema/shape checks for `compliance_profile_2026.json` and `annex_iv_technical_documentation_template.json`.
- Required roadmap tokens and indentation sanity in `roadmap_2026_2030.yaml` plus phased checks in `rollout_plan_2026_2030.yaml`.
- Structural coverage check for `REGULATOR_READY_AGI_ASI_TECHNICAL_REPORT_2026_2030.md` (`<title>/<abstract>/<content>` and required section anchors).
- Manifest schema checks (`package`, semver `version`, UTC `generated_utc`, artifacts maps) and SHA-256 integrity verification across governance + root-level external report artifacts.
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

Docs/schemas validation target (repo root):

```bash
make governance-schema-validate
```


Note: The suite runner invokes scripts via the active Python interpreter (`sys.executable`) to avoid PATH/interpreter drift across local/CI environments.

Make targets honor `PYTHON` (default: `python3`) so teams can pin an interpreter explicitly when needed.


Exit code conventions (run_validation_suite.py):
- `0`: all checks passed.
- Any other non-zero code: propagated from an invoked check command (for example manifest/check/selftest failure codes).
- `3`: validator JSON output was malformed when `--json-report` was requested.
- `4`: no selftests were discovered while selftests were required (i.e., without `--skip-selftest`).


Manifest package/version note:
- `governance_blueprint/artifact_manifest.json` is generated by `generate_artifact_manifest.py`.
- Current package metadata version is `1.4.0`, which includes 2026–2035 roadmap and regulatory mapping artifacts.


`make gov-suite-ci` runs the suite in quiet report mode, matching the CI workflow command line.


Optional: run through all steps even after failures (captures a fuller suite report):

```bash
python3 governance_blueprint/validation/run_validation_suite.py --no-fail-fast --suite-report governance-validation-suite-report.json
```
