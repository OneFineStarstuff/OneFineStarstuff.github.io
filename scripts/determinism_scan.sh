#!/usr/bin/env sh
# WP-119 (A1 companion): enforced determinism scan; complements lint/eslint.gien.cjs (A1).
# grep-based so the gate is parser-independent (core ESLint cannot parse .tsx alone).
# Acceptance: exit 0 when no Math.random exists in governed sources; exit 1 otherwise.
set -eu
cd "$(dirname "$0")/.."
HITS=$(grep -rn "Math\.random" webapp/src --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" || true)
if [ -z "$HITS" ]; then
  echo "DETERMINISTIC: no Math.random in webapp/src"
  exit 0
fi
echo "NODETERMINISM: Math.random found in governed code:"
echo "$HITS"
exit 1
