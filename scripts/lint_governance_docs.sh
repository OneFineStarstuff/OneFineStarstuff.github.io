#!/usr/bin/env bash
set -euo pipefail

IGNORE_FILE=".markdownlintignore"
MODE="${1:-strict}"

if [[ "$MODE" != "strict" && "$MODE" != "all" ]]; then
  echo "Usage: $0 [strict|all]" >&2
  exit 2
fi

if [[ ! -f "$IGNORE_FILE" ]]; then
  echo "Missing $IGNORE_FILE" >&2
  exit 1
fi

# Ensure expected governance long-form docs remain explicitly ignored.
for required in \
  "docs/governance/AGI_ASI_GSIFI_Blueprint_2026_2030.md" \
  "docs/governance/LINTING_NOTES.md"; do
  if [[ ! -f "$required" ]]; then
    echo "Missing required governance file: $required" >&2
    exit 1
  fi
  if ! grep -Fxq "$required" "$IGNORE_FILE"; then
    echo "Missing ignore entry: $required" >&2
    exit 1
  fi
done

# Prefer local markdownlint-cli if installed; fallback to npx.
if command -v markdownlint-cli >/dev/null 2>&1; then
  LINT_CMD=(markdownlint-cli)
elif command -v npx >/dev/null 2>&1; then
  LINT_CMD=(npx -y markdownlint-cli@0.39.0)
else
  echo "Neither markdownlint-cli nor npx is available" >&2
  exit 1
fi

if [[ "$MODE" == "all" ]]; then
  # Lint all governance markdown files; ignore file exclusions still apply.
  "${LINT_CMD[@]}" docs/governance/*.md docs/README.md
  echo "Governance markdown lint checks passed (all mode) and ignore list verified."
else
  # Lint strict-governed docs (index/readme files).
  "${LINT_CMD[@]}" docs/README.md docs/governance/README.md
  echo "Governance markdown lint checks passed (strict mode) and ignore list verified."
fi
