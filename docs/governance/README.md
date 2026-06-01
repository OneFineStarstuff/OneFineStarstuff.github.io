# Governance Documentation Index

## Primary artifacts

- `AGI_ASI_GSIFI_Blueprint_2026_2030.md`: Strategic governance blueprint
  for AGI/ASI controls, assurance, containment, and supervisory artifacts in
  G‑SIFIs.
- `LINTING_NOTES.md`: Rationale for markdownlint strategy used for long-form
  governance policy files.

## Local validation quickstart

- Lint strict governance index docs:
  - `bash scripts/lint_governance_docs.sh`
- Lint all governance docs (with `.markdownlintignore` respected):
  - `bash scripts/lint_governance_docs.sh all`
- Run helper behavior tests:
  - `bash tests/test_lint_governance_docs.sh`
- Run full local governance-doc checks:
  - `make governance-docs-check`

## CI behavior

The workflow `.github/workflows/governance-docs-lint.yml` runs:

1. `bash -n scripts/lint_governance_docs.sh`
2. `shellcheck scripts/lint_governance_docs.sh`
3. `shellcheck tests/test_lint_governance_docs.sh`
4. `make governance-docs-check`
