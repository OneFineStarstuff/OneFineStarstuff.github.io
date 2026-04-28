#!/usr/bin/env bash
set -euo pipefail

SKIP_INSTALL=0
LIST_CHECKS=0
SKIP_PYTEST=0
OUTPUT_JSON="/tmp/blueprint-validation.json"

usage() {
  echo "Usage: $0 [--skip-install] [--list-checks] [--skip-pytest] [--output-json <path>]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --skip-install)
      SKIP_INSTALL=1
      shift
      ;;
    --list-checks)
      LIST_CHECKS=1
      shift
      ;;
    --skip-pytest)
      SKIP_PYTEST=1
      shift
      ;;
    --output-json)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --output-json" >&2
        usage >&2
        exit 2
      fi
      OUTPUT_JSON="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$SKIP_INSTALL" -ne 1 ]]; then
  PYTHON_MODULES=("yaml")
  if [[ "$SKIP_PYTEST" -ne 1 ]]; then
    PYTHON_MODULES+=("pytest")
  fi

  REQUIRED_MODULES="$(IFS=,; echo "${PYTHON_MODULES[*]}")"
  if ! REQUIRED_MODULES="${REQUIRED_MODULES}" python - <<'PY'
import importlib.util
import os

required = [pkg for pkg in os.environ["REQUIRED_MODULES"].split(",") if pkg]
missing = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]
raise SystemExit(1 if missing else 0)
PY
  then
    python -m pip install --disable-pip-version-check -r scripts/requirements-blueprint-validator.txt >/dev/null
  fi
fi

if [[ "$LIST_CHECKS" -eq 1 ]]; then
  python scripts/validate_blueprint_artifacts.py --list-checks
  exit 0
fi

python -m json.tool docs/reports/blueprint_artifacts/T6_Evidence_Manifest.json >/dev/null
python scripts/validate_blueprint_artifacts.py
python scripts/validate_blueprint_artifacts.py --json >"${OUTPUT_JSON}"
python -m json.tool "${OUTPUT_JSON}" >/dev/null
python scripts/validate_blueprint_artifacts.py --base-dir docs/reports/blueprint_artifacts

if [[ "$SKIP_PYTEST" -ne 1 ]]; then
  pytest -q tests/test_validate_blueprint_artifacts.py tests/test_run_blueprint_artifact_checks.py
fi
