#!/usr/bin/env sh
# WP-119 (A1 companion): reject Math.random references in governed source code.
# Standalone comment lines are excluded to avoid documentation-only false positives.
# Acceptance: exit 0 when no code-line reference remains; exit 1 otherwise.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
SCAN_ROOT=${DETERMINISM_SCAN_ROOT:-"$REPO_ROOT/webapp/src"}

if [ ! -d "$SCAN_ROOT" ]; then
  echo "ERROR: determinism scan root does not exist: $SCAN_ROOT" >&2
  exit 2
fi

HITS=$(
  grep -rn "Math[[:space:]]*\\.[[:space:]]*random" "$SCAN_ROOT" \
    --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" |
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/[*]|[*]|[*]/)' || true
)

if [ -z "$HITS" ]; then
  echo "DETERMINISTIC: no executable-line Math.random references in $SCAN_ROOT"
  exit 0
fi

echo "NODETERMINISM: Math.random found in governed code:"
printf '%s\n' "$HITS"
exit 1
