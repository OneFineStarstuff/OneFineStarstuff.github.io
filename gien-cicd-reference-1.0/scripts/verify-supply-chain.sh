#!/usr/bin/env bash
set -euo pipefail
: "${IMAGE_REF:?Set immutable IMAGE_REF, e.g. ghcr.io/org/api@sha256:<64 hex>}"
: "${SLSA_PROVENANCE_BUNDLE:?Set path to the Sigstore bundle containing the SLSA provenance}"
: "${SLSA_SIGNER_SPEC:?Set narrowly scoped signer specification understood by the installed slsa-verifier}"
: "${EXPECTED_BUILDER_ID:?Set expected SLSA builder ID}"
: "${EXPECTED_IMAGE_SIGNER:?Set expected Cosign certificate identity}"
: "${EXPECTED_OIDC_ISSUER:?Set expected OIDC issuer}"
command -v slsa-verifier >/dev/null 2>&1 || { echo "slsa-verifier is required" >&2; exit 127; }
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 127; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 127; }
[[ "$IMAGE_REF" =~ @sha256:[a-f0-9]{64}$ ]] || { echo "IMAGE_REF must be immutable and digest-qualified" >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
slsa-verifier build --require-signatures --signer "$SLSA_SIGNER_SPEC" --level 3 --print-provenance "$SLSA_PROVENANCE_BUNDLE" > "$TMP/verified-provenance.json"
EXPECTED_DIGEST="${IMAGE_REF##*@sha256:}"
jq -e --arg digest "$EXPECTED_DIGEST" --arg builder "$EXPECTED_BUILDER_ID" '(.subject | any(.digest.sha256 == $digest)) and ((.predicate.runDetails.builder.id // .predicate.builder.id) == $builder)' "$TMP/verified-provenance.json" >/dev/null || { echo "SLSA statement subject digest or builder ID does not match expected values" >&2; exit 2; }
cosign verify --certificate-identity "$EXPECTED_IMAGE_SIGNER" --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" "$IMAGE_REF" > "$TMP/image-signature-verification.json"
printf 'PASS: SLSA Build L3 provenance, expected builder, subject digest and image signature identity verified.\n'
printf 'NOTE: This harness does not validate Pact, SBOM vulnerability thresholds, Kubernetes admission or change approvals; verify those evidence items separately.\n'
