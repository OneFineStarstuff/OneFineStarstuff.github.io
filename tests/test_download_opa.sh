#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOAD_SCRIPT="$ROOT/tools/download_and_verify_opa.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_CURL="$TMP_DIR/fake-curl"
cat > "$FAKE_CURL" <<'FAKE_CURL_EOF'
#!/usr/bin/env bash
set -euo pipefail
attempt_file="${CURL_ATTEMPT_FILE:?CURL_ATTEMPT_FILE is required}"
payload="${CURL_TEST_PAYLOAD:?CURL_TEST_PAYLOAD is required}"
failures="${CURL_TEST_FAILURES:-0}"
output=""
while (( $# )); do
  case "$1" in
    --output|-o)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$output" ]] || exit 64
attempt=0
if [[ -f "$attempt_file" ]]; then
  attempt="$(cat "$attempt_file")"
fi
attempt=$((attempt + 1))
printf '%s' "$attempt" > "$attempt_file"
if (( attempt <= failures )); then
  exit 22
fi
printf '%s' "$payload" > "$output"
FAKE_CURL_EOF
chmod +x "$FAKE_CURL"

URL="https://www.openpolicyagent.org/downloads/v1.7.1/opa_linux_amd64_static"
PAYLOAD="deterministic OPA test payload"
EXPECTED_SHA256="$(printf '%s' "$PAYLOAD" | sha256sum | awk '{print $1}')"
DEST="$TMP_DIR/cache/opa"
mkdir -p "$(dirname "$DEST")"

# RED/GREEN: two transient HTTP failures must be retried and the third
# successful download must be checksum-verified before an executable is installed.
CURL_BIN="$FAKE_CURL" \
SLEEP_BIN=true \
CURL_ATTEMPT_FILE="$TMP_DIR/retry.attempts" \
CURL_TEST_PAYLOAD="$PAYLOAD" \
CURL_TEST_FAILURES=2 \
OPA_DOWNLOAD_MAX_ATTEMPTS=3 \
OPA_DOWNLOAD_RETRY_DELAY_SECONDS=0 \
  bash "$DOWNLOAD_SCRIPT" "$URL" "$DEST" "$EXPECTED_SHA256"

[[ "$(cat "$TMP_DIR/retry.attempts")" == "3" ]]
[[ -x "$DEST" ]]
[[ "$(cat "$DEST")" == "$PAYLOAD" ]]

# A bad checksum must fail closed and must not leave a cached executable.
BAD_DEST="$TMP_DIR/cache/opa-bad"
if CURL_BIN="$FAKE_CURL" \
   SLEEP_BIN=true \
   CURL_ATTEMPT_FILE="$TMP_DIR/bad.attempts" \
   CURL_TEST_PAYLOAD="$PAYLOAD" \
   CURL_TEST_FAILURES=0 \
   OPA_DOWNLOAD_MAX_ATTEMPTS=1 \
   OPA_DOWNLOAD_RETRY_DELAY_SECONDS=0 \
     bash "$DOWNLOAD_SCRIPT" "$URL" "$BAD_DEST" "$(printf '0%.0s' {1..64})"; then
  echo "Expected checksum mismatch to fail" >&2
  exit 1
fi
[[ ! -e "$BAD_DEST" ]]

# Exhausting the retry budget must fail and leave no partial cache file.
EXHAUSTED_DEST="$TMP_DIR/cache/opa-exhausted"
if CURL_BIN="$FAKE_CURL" \
   SLEEP_BIN=true \
   CURL_ATTEMPT_FILE="$TMP_DIR/exhausted.attempts" \
   CURL_TEST_PAYLOAD="$PAYLOAD" \
   CURL_TEST_FAILURES=9 \
   OPA_DOWNLOAD_MAX_ATTEMPTS=3 \
   OPA_DOWNLOAD_RETRY_DELAY_SECONDS=0 \
     bash "$DOWNLOAD_SCRIPT" "$URL" "$EXHAUSTED_DEST" "$EXPECTED_SHA256"; then
  echo "Expected exhausted retries to fail" >&2
  exit 1
fi
[[ "$(cat "$TMP_DIR/exhausted.attempts")" == "3" ]]
[[ ! -e "$EXHAUSTED_DEST" ]]

shopt -s nullglob
PARTIALS=("$TMP_DIR"/cache/opa*.tmp.*)
[[ "${#PARTIALS[@]}" -eq 0 ]]

echo "OPA download retry and integrity tests passed"
