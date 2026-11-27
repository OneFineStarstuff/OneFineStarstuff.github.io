#!/usr/bin/env bash
set -euo pipefail
: "${PACT_BROKER_BASE_URL:?Set Pact Broker URL}"
: "${PACTICIPANT:?Set Pact participant name}"
: "${PACT_VERSION:?Set deployed version, normally full Git SHA}"
: "${PACT_ENVIRONMENT:=production}"
: "${DEPLOYMENT_ID:?Set the actual deployment identifier}"
: "${IMAGE_DIGEST:?Set the actual deployed image digest}"
command -v pact-broker >/dev/null 2>&1 || { echo "pact-broker CLI is required" >&2; exit 127; }
[[ "$IMAGE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "IMAGE_DIGEST must be sha256:<64 lowercase hex>" >&2; exit 2; }
pact-broker record-deployment \
  --pacticipant "$PACTICIPANT" \
  --version "$PACT_VERSION" \
  --environment "$PACT_ENVIRONMENT" \
  --broker-base-url "$PACT_BROKER_BASE_URL"
printf 'Recorded Pact deployment %s: %s %s %s %s\n' "$DEPLOYMENT_ID" "$PACTICIPANT" "$PACT_VERSION" "$PACT_ENVIRONMENT" "$IMAGE_DIGEST"
