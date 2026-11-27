#!/usr/bin/env sh
# Regression tests for scripts/determinism_scan.sh.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCANNER="$SCRIPT_DIR/determinism_scan.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

COMMENT_ROOT="$TMP_ROOT/comments"
mkdir -p "$COMMENT_ROOT"
cat > "$COMMENT_ROOT/comments.ts" <<'EOF'
/**
 * The forbidden API is documented here: Math.random().
 */
// Math.random()
/* Math.random() */
EOF

if DETERMINISM_SCAN_ROOT="$COMMENT_ROOT" sh "$SCANNER"; then
  echo "PASS: comment-only references do not fail the scan"
else
  echo "FAIL: comment-only references must not fail the scan" >&2
  exit 1
fi

CODE_ROOT="$TMP_ROOT/code"
mkdir -p "$CODE_ROOT"
cat > "$CODE_ROOT/actual.ts" <<'EOF'
export const value = Math.random();
EOF

if DETERMINISM_SCAN_ROOT="$CODE_ROOT" sh "$SCANNER"; then
  echo "FAIL: executable Math.random usage must fail the scan" >&2
  exit 1
else
  echo "PASS: executable Math.random usage is rejected"
fi
