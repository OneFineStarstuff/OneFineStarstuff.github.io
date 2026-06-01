# Linting Notes for Governance Blueprint Documentation

This repository keeps markdownlint enabled by default via `.markdownlint.json`.

The following long-form governance documents are excluded in
`.markdownlintignore`:

- `docs/governance/AGI_ASI_GSIFI_Blueprint_2026_2030.md`
- `docs/governance/LINTING_NOTES.md`

Rationale:

- The blueprint intentionally uses dense regulatory tables and compact
  checklist formatting.
- Reflowing all lines/headings/lists to satisfy strict markdown style rules
  would reduce readability for control owners and supervisors.

This linting approach preserves strict linting for general Markdown content
while allowing policy-heavy governance artifacts to keep implementation-focused
layout.


Tooling note: the helper script uses `markdownlint-cli@0.39.0` via `npx` when a local `markdownlint-cli` binary is not available.
