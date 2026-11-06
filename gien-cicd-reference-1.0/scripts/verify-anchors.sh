#!/usr/bin/env bash
set -euo pipefail
: "${EVIDENCE_DIR:?Set EVIDENCE_DIR}"
: "${EXPECTED_SIGNER:?Set exact/appropriately constrained OIDC certificate identity}"
: "${EXPECTED_OIDC_ISSUER:?Set OIDC issuer}"
: "${WORM_BUCKET:?Set WORM bucket}"
: "${WORM_KEY:?Set exact archive object key}"
: "${WORM_SIGNATURE_KEY:?Set exact Sigstore bundle object key}"
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 127; }
command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required" >&2; exit 127; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 127; }
cosign verify-blob --bundle "$EVIDENCE_DIR/anchors/evidence-root.sigstore.json" --certificate-identity "$EXPECTED_SIGNER" --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" "$EVIDENCE_DIR/root.txt"
verify_worm_object() {
  local key="$1" local_file="$2" label="$3"
  local prefix="$EVIDENCE_DIR/anchors/${label}"
  aws s3api head-object --bucket "$WORM_BUCKET" --key "$key" > "${prefix}-head.json"
  local version_id mode retain_until
  version_id="$(jq -er '.VersionId' "${prefix}-head.json")"
  mode="$(jq -er '.ObjectLockMode' "${prefix}-head.json")"
  retain_until="$(jq -er '.ObjectLockRetainUntilDate' "${prefix}-head.json")"
  [[ "$mode" == "COMPLIANCE" ]] || { echo "Expected COMPLIANCE Object Lock mode for $key, found $mode" >&2; return 2; }
  local retain_epoch now_epoch
  retain_epoch="$(date -u -d "$retain_until" +%s)"
  now_epoch="$(date -u +%s)"
  (( retain_epoch > now_epoch )) || { echo "WORM retention has expired for $key" >&2; return 2; }
  local downloaded="${prefix}-download"
  aws s3api get-object --bucket "$WORM_BUCKET" --key "$key" --version-id "$version_id" "$downloaded" > "${prefix}-get.json"
  local local_sha remote_sha
  local_sha="$(sha256sum "$local_file" | awk '{print $1}')"
  remote_sha="$(sha256sum "$downloaded" | awk '{print $1}')"
  [[ "$local_sha" == "$remote_sha" ]] || { echo "Downloaded WORM object differs from local $label file" >&2; return 2; }
  printf '%s verified: mode=%s retain-until=%s version=%s\n' "$label" "$mode" "$retain_until" "$version_id"
}
LOCAL_ARCHIVE="$(find "$EVIDENCE_DIR/anchors" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
[[ -n "$LOCAL_ARCHIVE" ]] || { echo "Local evidence archive not found" >&2; exit 2; }
verify_worm_object "$WORM_KEY" "$LOCAL_ARCHIVE" "worm-archive"
verify_worm_object "$WORM_SIGNATURE_KEY" "$EVIDENCE_DIR/anchors/evidence-root.sigstore.json" "worm-signature"
printf 'Rekor signature bundle verified. Independently review bucket configuration and administrative audit records.\n'
