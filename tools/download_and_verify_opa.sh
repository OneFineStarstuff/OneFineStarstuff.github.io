#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <url> <destination> <expected-sha256>" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 64
fi

url="$1"
destination="$2"
expected_sha256="${3,,}"
max_attempts="${OPA_DOWNLOAD_MAX_ATTEMPTS:-5}"
retry_delay="${OPA_DOWNLOAD_RETRY_DELAY_SECONDS:-2}"
curl_bin="${CURL_BIN:-curl}"
sleep_bin="${SLEEP_BIN:-sleep}"

if [[ ! "$expected_sha256" =~ ^[a-f0-9]{64}$ ]]; then
  echo "A valid 64-character SHA-256 digest is required." >&2
  exit 64
fi
if [[ ! "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "OPA_DOWNLOAD_MAX_ATTEMPTS must be a positive integer." >&2
  exit 64
fi
if [[ ! "$retry_delay" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "OPA_DOWNLOAD_RETRY_DELAY_SECONDS must be a non-negative number." >&2
  exit 64
fi

destination_dir="$(dirname "$destination")"
mkdir -p "$destination_dir"
temporary_file="$(mktemp "${destination}.tmp.XXXXXX")"
cleanup() {
  rm -f "$temporary_file"
}
trap cleanup EXIT INT TERM

downloaded=0
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  if "$curl_bin" \
    --fail \
    --silent \
    --show-error \
    --location \
    --connect-timeout 15 \
    --max-time 180 \
    --output "$temporary_file" \
    "$url"; then
    downloaded=1
    break
  fi

  rm -f "$temporary_file"
  if (( attempt < max_attempts )); then
    printf 'OPA download attempt %s/%s failed; retrying.\n' "$attempt" "$max_attempts" >&2
    "$sleep_bin" "$retry_delay"
  fi
done

if (( downloaded == 0 )); then
  echo "OPA download failed after $max_attempts attempts." >&2
  exit 1
fi

actual_sha256="$(sha256sum "$temporary_file" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "OPA checksum mismatch: expected $expected_sha256 got $actual_sha256" >&2
  exit 1
fi

chmod 0755 "$temporary_file"
mv -f "$temporary_file" "$destination"
trap - EXIT INT TERM
echo "OPA download verified (SHA-256 $actual_sha256)." >&2
