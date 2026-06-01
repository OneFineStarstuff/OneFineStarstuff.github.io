#!/usr/bin/env bash
set -euo pipefail

SCRIPT="scripts/lint_governance_docs.sh"
IGNORE_FILE=".markdownlintignore"
BACKUP_FILE="${IGNORE_FILE}.bak.test"
TMP_DIR="$(mktemp -d)"

cleanup() {
  if [[ -f "$BACKUP_FILE" ]]; then
    mv -f "$BACKUP_FILE" "$IGNORE_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Usage should fail for unsupported mode.
if "$SCRIPT" unsupported >"$TMP_DIR/out.txt" 2>"$TMP_DIR/err.txt"; then
  echo "Expected unsupported mode to fail" >&2
  exit 1
fi
if ! grep -q "Usage:" "$TMP_DIR/err.txt"; then
  echo "Expected usage message for unsupported mode" >&2
  exit 1
fi

# Missing ignore file should fail fast.
mv -f "$IGNORE_FILE" "$BACKUP_FILE"
if "$SCRIPT" strict >"$TMP_DIR/missing_out.txt" 2>"$TMP_DIR/missing_err.txt"; then
  echo "Expected missing ignore file check to fail" >&2
  exit 1
fi
if ! grep -q "Missing .markdownlintignore" "$TMP_DIR/missing_err.txt"; then
  echo "Expected missing ignore message" >&2
  exit 1
fi
mv -f "$BACKUP_FILE" "$IGNORE_FILE"


# Missing required ignore entry should fail fast.
cp "$IGNORE_FILE" "$TMP_DIR/original_ignore.txt"
# Remove one required line in-place by filtering.
grep -Fvx "docs/governance/LINTING_NOTES.md" "$TMP_DIR/original_ignore.txt" > "$IGNORE_FILE"
if "$SCRIPT" strict >"$TMP_DIR/missing_entry_out.txt" 2>"$TMP_DIR/missing_entry_err.txt"; then
  echo "Expected missing ignore entry check to fail" >&2
  exit 1
fi
if ! grep -q "Missing ignore entry" "$TMP_DIR/missing_entry_err.txt"; then
  echo "Expected missing ignore entry message" >&2
  exit 1
fi
cp "$TMP_DIR/original_ignore.txt" "$IGNORE_FILE"


# Missing required governance file should fail fast.
mv -f "docs/governance/LINTING_NOTES.md" "$TMP_DIR/LINTING_NOTES.md.bak"
if "$SCRIPT" strict >"$TMP_DIR/missing_file_out.txt" 2>"$TMP_DIR/missing_file_err.txt"; then
  echo "Expected missing governance file check to fail" >&2
  exit 1
fi
if ! grep -q "Missing required governance file" "$TMP_DIR/missing_file_err.txt"; then
  echo "Expected missing required governance file message" >&2
  exit 1
fi
mv -f "$TMP_DIR/LINTING_NOTES.md.bak" "docs/governance/LINTING_NOTES.md"

# Happy-path checks.
"$SCRIPT" strict >"$TMP_DIR/strict.txt"
"$SCRIPT" all >"$TMP_DIR/all.txt"

grep -q "passed" "$TMP_DIR/strict.txt"
grep -q "passed" "$TMP_DIR/all.txt"

echo "lint governance script tests passed"
