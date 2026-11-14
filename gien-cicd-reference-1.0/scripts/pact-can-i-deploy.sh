#!/usr/bin/env bash
set -euo pipefail
: "${PACT_BROKER_BASE_URL:?Set Pact Broker URL}"
: "${PACTICIPANT:?Set Pact participant name}"
: "${PACT_VERSION:?Set immutable participant version, normally full Git SHA}"
: "${PACT_ENVIRONMENT:=production}"
command -v pact-broker >/dev/null 2>&1 || { echo "pact-broker CLI is required" >&2; exit 127; }
pact-broker can-i-deploy \
  --pacticipant "$PACTICIPANT" \
  --version "$PACT_VERSION" \
  --to-environment "$PACT_ENVIRONMENT" \
  --broker-base-url "$PACT_BROKER_BASE_URL"
