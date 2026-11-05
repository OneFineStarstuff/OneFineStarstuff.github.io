#!/usr/bin/env bash
set -euo pipefail
: "${EVIDENCE_DIR:?Set EVIDENCE_DIR to verified evidence bundle directory}"
: "${WORM_BUCKET:?Set pre-created Object Lock bucket}"
: "${WORM_PREFIX:=gien/deployments}"
: "${RETAIN_UNTIL:?Set retention timestamp, e.g. 2031-11-04T00:00:00Z}"
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 127; }
command -v aws >/dev/null 2>&1 || { echo "AWS CLI is required" >&2; exit 127; }
[[ -s "$EVIDENCE_DIR/root.txt" && -s "$EVIDENCE_DIR/manifest.json" ]] || { echo "Evidence bundle is incomplete" >&2; exit 2; }
node --experimental-strip-types "$(dirname "$0")/verify-evidence.ts" --bundle "$EVIDENCE_DIR"
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 127; }
DEPLOYMENT_ID="$(jq -er '.deployment.id' "$EVIDENCE_DIR/manifest.json")"
ROOT="$(cat "$EVIDENCE_DIR/root.txt")"
[[ "$ROOT" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid Merkle root" >&2; exit 2; }
OUT="$EVIDENCE_DIR/anchors"
mkdir -p "$OUT"
cosign sign-blob --yes --bundle "$OUT/evidence-root.sigstore.json" "$EVIDENCE_DIR/root.txt"
ARCHIVE="$OUT/${DEPLOYMENT_ID}-${ROOT}.tar.gz"
TAR_TMP="$(mktemp "${TMPDIR:-/tmp}/gien-evidence.XXXXXX.tar")"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -cf "$TAR_TMP" -C "$EVIDENCE_DIR" contents manifest.json root.txt
gzip -n -c "$TAR_TMP" > "$ARCHIVE"
rm -f "$TAR_TMP"
KEY="$WORM_PREFIX/$DEPLOYMENT_ID/$ROOT.tar.gz"
aws s3api put-object --bucket "$WORM_BUCKET" --key "$KEY" --body "$ARCHIVE" --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$RETAIN_UNTIL" > "$OUT/worm-put-object.json"
aws s3api put-object --bucket "$WORM_BUCKET" --key "$WORM_PREFIX/$DEPLOYMENT_ID/$ROOT.sigstore.json" --body "$OUT/evidence-root.sigstore.json" --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$RETAIN_UNTIL" > "$OUT/worm-signature-put-object.json"
printf 'Anchoring submitted. Rekor evidence is in the Cosign bundle; WORM object key: %s\n' "$KEY"
printf 'Verify the signature, inclusion proof, bucket policy, object version and retention independently.\n'
