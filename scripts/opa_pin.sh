#!/usr/bin/env sh
# A6 (WP-114): OPA bundle pinning, fail-closed while the checksum file is unfilled or mismatched.
# Acceptance: pinned OPA release verified by checksum; bundle built from compliance/;
# bundle checksum printed for the CI job summary. Unverified downloads never execute.
set -eu
cd "$(dirname "$0")/.."
PIN_FILE=scripts/opa-pinned.sha256
[ -s "$PIN_FILE" ] || { echo "FAIL: $PIN_FILE missing or empty; fill it from the official OPA checksums page at pin time."; exit 1; }
PIN_VERSION=$(sed -n '1s/^version=//p' "$PIN_FILE")
PIN_WANT=$(sed -n '2s/^sha256=//p' "$PIN_FILE")
[ -n "$PIN_VERSION" ] && [ -n "$PIN_WANT" ] || { echo "FAIL: pin file must carry version= and sha256= lines."; exit 1; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "https://openpolicyagent.org/downloads/v$PIN_VERSION/opa_linux_amd64_static" -o "$TMP/opa"
printf '%s  %s\n' "$PIN_WANT" "$TMP/opa" | sha256sum -c - || { echo "FAIL: OPA checksum mismatch; refusing to pin an unverified binary."; exit 1; }
chmod +x "$TMP/opa"
"$TMP/opa" version
mkdir -p bundles
"$TMP/opa" build -b compliance/ -o bundles/gien-compliance.tar.gz
sha256sum bundles/gien-compliance.tar.gz
echo "OPA bundle built from pinned OPA v$PIN_VERSION; record the bundle checksum in the CI job summary."
