# Learnings - GSIFI Governance Asset Validation Refactor

## Key Patterns
- **Dual-Layer Validation:** When using JSON Schema validation in a
  context where existing tests expect very specific error messages,
  it can be effective to implement a "lightweight" manual validation
  layer for basic structure (required fields, basic types) before
  invoking the full schema validator.
- **Robust Schema Validator Acquisition:** Using
  `importlib.util.find_spec` and `importlib.import_module` to
  optionally load `jsonschema` allows the script to run in
  environments where the library might be missing, falling back to
  basic validation without crashing.

## Repository-Specific Procedures
- **CI Cleanup:** This repository contains a large number of
  boilerplate GitHub Actions workflows. Remove irrelevant generic
  templates if their corresponding manifest files (e.g., `Cargo.toml`,
  `pom.xml`) are not present at the root.
- **Linting Standards:** The project enforces strict PEP8 (Flake8),
  Black formatting, and Pylint 10/10 score.

## Successful Solutions
- Refactored `scripts/validate_gsifi_governance_assets.py` to fix 2
  failed tests related to JSON Schema error handling.
- Resolved CI failures by adding `.github/labeler.yml` and pruning
  irrelevant workflows.
- Achieved a 10/10 Pylint score on the modified script while
  maintaining 100% test pass rate.
