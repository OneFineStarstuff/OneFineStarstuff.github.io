#!/usr/bin/env bash
set -euo pipefail

make governance-evidence-manifest
make governance-evidence-verify
make governance-evidence-schema
make governance-report-schema
make governance-check-generated
