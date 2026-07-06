# Documentation Index

## Governance

- See `docs/governance/README.md` for the AGI/ASI governance blueprint,
  supporting templates, and linting notes used for G‑SIFI policy artifacts.

## Linting

- Markdown linting is enabled by default (`.markdownlint.json`).
- Long-form governance policy files are explicitly listed in
  `.markdownlintignore` to preserve dense regulatory tables/checklists.

## Validation Commands

- `scripts/lint_governance_docs.sh` verifies required ignore entries and lints
  governance index docs (`strict`, default).
- `scripts/lint_governance_docs.sh all` lints all governance markdown files
  while honoring `.markdownlintignore`.
