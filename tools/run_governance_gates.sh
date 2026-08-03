#!/usr/bin/env bash
set -euo pipefail

STRICT_OPA="${STRICT_OPA:-0}"
OPA_VERSION="${OPA_VERSION:-v1.7.1}"
OPA_CACHE_DIR="${OPA_CACHE_DIR:-${HOME}/.cache/sentinel-governance}"
REPORT_PATH="${REPORT_PATH:-/tmp/sentinel_governance_validation_report.json}"
if [[ "${1:-}" == "--strict-opa" ]]; then
  STRICT_OPA=1
fi

mark_failure_report() {
  local failed_line="$1"
  local exit_code="$2"
  python - "$REPORT_PATH" "$failed_line" "$exit_code" <<'PYINNER'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
failed_line = sys.argv[2]
exit_code = sys.argv[3]
report = json.loads(report_path.read_text()) if report_path.exists() else {}
report["status"] = "fail"
report["runner_status"] = "fail"
report.setdefault("error", f"governance gate runner failed at line {failed_line} with exit code {exit_code}")
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2) + "\n")
PYINNER
}

trap 'status=$?; mark_failure_report "$LINENO" "$status"; exit "$status"' ERR

python tools/validate_governance_artifacts.py --report "$REPORT_PATH"
pytest -q tests/governance/test_governance_artifacts.py

verify_checksum() {
  local bin_path="$1"
  local expected_sha256="${OPA_SHA256:-}"
  if [[ -z "$expected_sha256" ]]; then
    return 0
  fi
  local actual_sha256
  actual_sha256="$(sha256sum "$bin_path" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    python - "$REPORT_PATH" "$expected_sha256" "$actual_sha256" <<'PYINNER'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
expected = sys.argv[2]
actual = sys.argv[3]
report = json.loads(report_path.read_text()) if report_path.exists() else {}
report["status"] = "fail"
report["opa_status"] = "fail"
report["error"] = f"OPA checksum mismatch: expected {expected} got {actual}"
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2) + "\n")
PYINNER
    echo "OPA checksum mismatch: expected $expected_sha256 got $actual_sha256" >&2
    exit 1
  fi
}

ensure_opa() {
  if command -v opa >/dev/null 2>&1; then
    local opa_path
    opa_path="$(command -v opa)"
    verify_checksum "$opa_path"
    echo "$opa_path"
    return 0
  fi

  if [[ "$STRICT_OPA" != "1" ]]; then
    return 1
  fi

  mkdir -p "$OPA_CACHE_DIR"
  local cached_opa="$OPA_CACHE_DIR/opa_${OPA_VERSION}_linux_amd64_static"
  local url="https://www.openpolicyagent.org/downloads/${OPA_VERSION}/opa_linux_amd64_static"

  if [[ ! -x "$cached_opa" ]]; then
    echo "OPA not found. Downloading ${OPA_VERSION} to ${cached_opa}..." >&2
    curl -fsSL "$url" -o "$cached_opa"
    chmod +x "$cached_opa"
  else
    echo "Using cached OPA binary at ${cached_opa}" >&2
  fi

  verify_checksum "$cached_opa"
  echo "$cached_opa"
}

OPA_BIN="$(ensure_opa || true)"
OPA_STATUS="skipped"
if [[ -n "$OPA_BIN" ]]; then
  "$OPA_BIN" eval --format=raw --data governance_artifacts/rego/release_gate.rego \
    --input governance_artifacts/conftest/release_gate_policy_test.yaml \
    'data.sentinel.release.allow' | rg -n '^true$'
  "$OPA_BIN" eval --format=raw --data governance_artifacts/rego/release_gate.rego \
    --input governance_artifacts/conftest/release_gate_policy_deny_test.yaml \
    'data.sentinel.release.allow' | rg -n '^false$'
  OPA_STATUS="pass"
elif [[ "$STRICT_OPA" == "1" ]]; then
  OPA_STATUS="fail"
  python - <<PY
import json
from pathlib import Path
p=Path("$REPORT_PATH")
d=json.loads(p.read_text()) if p.exists() else {}
d["status"]="fail"
d["opa_status"]="fail"
d["error"]="OPA unavailable in strict mode"
p.write_text(json.dumps(d, indent=2)+"\n")
PY
  echo "OPA unavailable and strict mode enabled; failing." >&2
  exit 1
else
  echo "OPA not found; skipping OPA eval in local run" >&2
fi

python - <<PY
import json
from pathlib import Path
p=Path("$REPORT_PATH")
d=json.loads(p.read_text()) if p.exists() else {}
d["opa_status"]="$OPA_STATUS"
d["runner_status"]="pass"
p.write_text(json.dumps(d, indent=2)+"\n")
PY
