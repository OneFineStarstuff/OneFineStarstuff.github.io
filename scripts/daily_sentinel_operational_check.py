#!/usr/bin/env python3
"""Daily Sentinel AI v2.4 DevSecOps operational checks.

The checker is intentionally dependency-light so it can run from CI, a jump host,
or an auditor workstation. It validates four evidence planes used by the
Omni-Sentinel Cognitive Execution Environment:

* Sentinel telemetry/dashboard reachability
* Global Systemic Risk Index (G-SRI) threshold evidence
* PQC WORM logger S3 Object Lock commit evidence
* TEE/TPM attestation evidence, including PCR_MATCH

The command exits non-zero whenever a required check is RED. Optional dashboard
reachability can be skipped for offline evidence-pack validation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

UTC = dt.timezone.utc
DEFAULT_DASHBOARD_URL = "https://sentinel.internal.g-sifi.local"
DEFAULT_STALENESS_MINUTES = 30
DEFAULT_WORM_MAX_LAG_SECONDS = 900
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


class CheckError(RuntimeError):
    """Raised when operational evidence cannot be validated."""


@dataclass(frozen=True)
class CheckResult:
    """Single operational check result."""

    name: str
    status: str
    summary: str
    remediation: str = ""

    @property
    def is_failure(self) -> bool:
        return self.status == FAIL

    def to_dict(self) -> dict[str, str]:
        """Return a stable machine-readable representation."""
        return asdict(self)


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from *path*."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CheckError(f"unable to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CheckError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CheckError(f"{path} must contain a JSON object")
    return data


def parse_utc_timestamp(value: object, field_name: str) -> dt.datetime:
    """Parse a strict UTC timestamp ending in Z."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CheckError(
            f"{field_name} must be an ISO-8601 UTC timestamp ending in 'Z'"
        )
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CheckError(
            f"{field_name} is not a valid ISO-8601 timestamp: {value}"
        ) from exc
    return parsed.astimezone(UTC)


def require_fresh(
    timestamp: dt.datetime, max_age_minutes: int, field_name: str
) -> None:
    """Require *timestamp* to be no older than *max_age_minutes*."""
    now = dt.datetime.now(UTC)
    age = now - timestamp
    if age < dt.timedelta(seconds=-60):
        raise CheckError(f"{field_name} is from the future: {timestamp.isoformat()}")
    if age > dt.timedelta(minutes=max_age_minutes):
        age_minutes = int(age.total_seconds() // 60)
        raise CheckError(
            f"{field_name} is stale: {age_minutes} minutes old; "
            f"maximum allowed is {max_age_minutes} minutes"
        )


def _ssl_context(insecure_tls: bool) -> ssl.SSLContext | None:
    """Build the TLS context for dashboard checks."""
    if not insecure_tls:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _open_dashboard(
    url: str,
    method: str,
    timeout_seconds: float,
    context: ssl.SSLContext | None,
) -> int:
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(
        request, timeout=timeout_seconds, context=context
    ) as resp:
        return resp.getcode()


def check_dashboard(
    url: str, timeout_seconds: float, insecure_tls: bool
) -> CheckResult:
    """Check Sentinel telemetry/dashboard reachability.

    Some dashboard endpoints reject HEAD even when their health route is usable, so
    HTTP 405/501 automatically falls back to GET before declaring the check RED.
    """
    context = _ssl_context(insecure_tls)
    try:
        status = _open_dashboard(url, "HEAD", timeout_seconds, context)
    except urllib.error.HTTPError as exc:
        if exc.code not in {405, 501}:
            return CheckResult(
                "sentinel_dashboard",
                FAIL,
                f"{url} returned HTTP {exc.code}",
                "Restore the Sentinel dashboard/API upstream and capture Envoy/service health evidence.",
            )
        try:
            status = _open_dashboard(url, "GET", timeout_seconds, context)
        except urllib.error.HTTPError as get_exc:
            return CheckResult(
                "sentinel_dashboard",
                FAIL,
                f"{url} returned HTTP {get_exc.code} after HEAD fallback",
                "Restore the Sentinel dashboard/API upstream and capture Envoy/service health evidence.",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as get_exc:
            return CheckResult(
                "sentinel_dashboard",
                FAIL,
                f"{url} is unreachable after HEAD fallback: {get_exc}",
                "Validate DNS, mTLS, Envoy upstream health, service discovery, and Sentinel pod readiness.",
            )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return CheckResult(
            "sentinel_dashboard",
            FAIL,
            f"{url} is unreachable: {exc}",
            "Validate DNS, mTLS, Envoy upstream health, service discovery, and Sentinel pod readiness.",
        )
    if 200 <= status < 300:
        return CheckResult("sentinel_dashboard", PASS, f"{url} returned HTTP {status}")
    return CheckResult(
        "sentinel_dashboard",
        FAIL,
        f"{url} returned non-success HTTP {status}",
        "Treat telemetry as degraded until a 2xx dashboard/API health result is restored.",
    )


def check_gsri(evidence: dict[str, Any], max_age_minutes: int) -> CheckResult:
    """Validate Global Systemic Risk Index evidence."""
    timestamp = parse_utc_timestamp(evidence.get("timestamp_utc"), "gsri.timestamp_utc")
    require_fresh(timestamp, max_age_minutes, "gsri.timestamp_utc")
    value = evidence.get("current_value")
    threshold = evidence.get("threshold")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise CheckError("gsri.current_value must be numeric")
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
        raise CheckError("gsri.threshold must be numeric")
    policy_version = evidence.get("policy_version")
    if not isinstance(policy_version, str) or not policy_version.strip():
        raise CheckError("gsri.policy_version must be a non-empty string")
    signed = (
        evidence.get("signed") is True or evidence.get("signature_verified") is True
    )
    if value < threshold and signed:
        return CheckResult(
            "gsri_threshold",
            PASS,
            f"G-SRI {value:.4f} is below threshold {threshold:.4f} under {policy_version}",
        )
    if not signed:
        return CheckResult(
            "gsri_threshold",
            FAIL,
            "G-SRI evidence signature is not verified",
            "Regenerate the G-SRI bundle with signer identity, policy version, and WORM pointer.",
        )
    return CheckResult(
        "gsri_threshold",
        FAIL,
        f"G-SRI {value:.4f} is at or above threshold {threshold:.4f}",
        "Open the systemic-risk escalation path and apply containment/reduction controls before green reporting.",
    )


def check_worm(
    evidence: dict[str, Any],
    max_age_minutes: int,
    max_lag_seconds: int,
    expected_bucket: str | None = None,
    require_compliance_mode: bool = False,
) -> CheckResult:
    """Validate PQC WORM logger S3 Object Lock commit evidence."""
    timestamp = parse_utc_timestamp(evidence.get("timestamp_utc"), "worm.timestamp_utc")
    require_fresh(timestamp, max_age_minutes, "worm.timestamp_utc")
    required_strings = [
        "logger_name",
        "bucket",
        "object_key",
        "object_version_id",
        "object_lock_mode",
        "retention_until_utc",
        "merkle_root",
        "pqc_signature_alg",
    ]
    missing = [
        key
        for key in required_strings
        if not isinstance(evidence.get(key), str) or not evidence.get(key)
    ]
    if missing:
        raise CheckError(f"worm evidence missing non-empty string fields: {missing}")
    if evidence["logger_name"] != "pqc_worm_logger.py":
        raise CheckError("worm.logger_name must be pqc_worm_logger.py")
    if expected_bucket and evidence["bucket"] != expected_bucket:
        return CheckResult(
            "pqc_worm_logger",
            FAIL,
            f"WORM bucket {evidence['bucket']!r} does not match expected bucket {expected_bucket!r}",
            "Route WORM batches to the designated S3 Object Lock bucket and regenerate commit evidence.",
        )
    if evidence.get("batch_status") != "committed":
        return CheckResult(
            "pqc_worm_logger",
            FAIL,
            f"WORM batch status is {evidence.get('batch_status')!r}",
            "Drain/replay the WORM queue and verify the next committed object version under Object Lock.",
        )
    mode = str(evidence["object_lock_mode"]).upper()
    allowed_modes = (
        {"COMPLIANCE"} if require_compliance_mode else {"COMPLIANCE", "GOVERNANCE"}
    )
    if mode not in allowed_modes:
        required_mode = (
            "COMPLIANCE" if require_compliance_mode else "COMPLIANCE or GOVERNANCE"
        )
        raise CheckError(f"worm.object_lock_mode must be {required_mode}")
    if evidence.get("pqc_signature_verified") is not True:
        return CheckResult(
            "pqc_worm_logger",
            FAIL,
            "WORM PQC signature has not been verified",
            "Verify the ML-DSA signature over the batch manifest before accepting the WORM evidence.",
        )
    retention_until = parse_utc_timestamp(
        evidence["retention_until_utc"], "worm.retention_until_utc"
    )
    if retention_until <= dt.datetime.now(UTC):
        raise CheckError("worm.retention_until_utc must be in the future")
    lag = evidence.get("commit_lag_seconds")
    if not isinstance(lag, int) or isinstance(lag, bool) or lag < 0:
        raise CheckError("worm.commit_lag_seconds must be a non-negative integer")
    if lag > max_lag_seconds:
        return CheckResult(
            "pqc_worm_logger",
            FAIL,
            f"WORM commit lag {lag}s exceeds {max_lag_seconds}s SLO",
            "Investigate queue backlog, S3/KMS errors, network path, and CloudTrail put-object evidence.",
        )
    return CheckResult(
        "pqc_worm_logger",
        PASS,
        f"{evidence['logger_name']} committed {evidence['object_key']} version {evidence['object_version_id']} with {mode} Object Lock",
    )


def check_attestation(evidence: dict[str, Any], max_age_minutes: int) -> CheckResult:
    """Validate TEE/TPM attestation evidence."""
    timestamp = parse_utc_timestamp(
        evidence.get("timestamp_utc"), "attestation.timestamp_utc"
    )
    require_fresh(timestamp, max_age_minutes, "attestation.timestamp_utc")
    if evidence.get("PCR_MATCH") is not True:
        return CheckResult(
            "tee_tpm_attestation",
            FAIL,
            f"PCR_MATCH is {evidence.get('PCR_MATCH')!r}",
            "Quarantine the node/workload, collect TPM quote details, and compare against the approved PCR policy.",
        )
    tee_status = evidence.get("tee_status")
    if tee_status not in {"trusted", "verified"}:
        return CheckResult(
            "tee_tpm_attestation",
            FAIL,
            f"TEE status is {tee_status!r}",
            "Deny production routing until enclave/workload measurement is verified by the attestation service.",
        )
    required_strings = ["node_id", "pcr_policy_hash", "tpm_quote_id", "verifier_id"]
    missing = [
        key
        for key in required_strings
        if not isinstance(evidence.get(key), str) or not evidence.get(key)
    ]
    if missing:
        raise CheckError(
            f"attestation evidence missing non-empty string fields: {missing}"
        )
    if evidence.get("attestation_signature_verified") is not True:
        return CheckResult(
            "tee_tpm_attestation",
            FAIL,
            "TEE/TPM attestation signature has not been verified",
            "Verify the TPM quote signature and attestation-service signature before accepting PCR_MATCH.",
        )
    return CheckResult(
        "tee_tpm_attestation",
        PASS,
        f"PCR_MATCH=TRUE for node {evidence['node_id']} using verifier {evidence['verifier_id']}",
    )


def overall_status(results: list[CheckResult]) -> str:
    """Return the aggregate RED/AMBER/GREEN status for *results*."""
    if any(result.is_failure for result in results):
        return "RED"
    if any(result.status == WARN for result in results):
        return "AMBER"
    return "GREEN"


def render_markdown(results: list[CheckResult]) -> str:
    """Render check results as a concise Markdown report."""
    lines = [
        "# Daily Sentinel AI v2.4 Operational Check",
        "",
        f"Overall status: **{overall_status(results)}**",
        "",
        "| Check | Status | Summary |",
        "|---|---:|---|",
    ]
    for result in results:
        lines.append(f"| {result.name} | {result.status} | {result.summary} |")
    remediations = [result for result in results if result.remediation]
    if remediations:
        lines.extend(["", "## Required remediation", ""])
        for result in remediations:
            lines.append(f"- **{result.name}:** {result.remediation}")
    return "\n".join(lines) + "\n"


def render_json(results: list[CheckResult]) -> str:
    """Render check results as machine-readable JSON."""
    payload = {
        "generated_at_utc": dt.datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "overall_status": overall_status(results),
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2)


def result_from_check(name: str, check: Callable[[], CheckResult]) -> CheckResult:
    """Convert an individual check exception into its own RED result."""
    try:
        return check()
    except CheckError as exc:
        return CheckResult(
            name,
            FAIL,
            str(exc),
            "Regenerate the evidence item and rerun the daily check.",
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Sentinel AI v2.4 daily operational checks"
    )
    parser.add_argument("--dashboard-url", default=DEFAULT_DASHBOARD_URL)
    parser.add_argument("--dashboard-timeout", type=float, default=5.0)
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="Disable TLS certificate validation for dashboard check",
    )
    parser.add_argument(
        "--skip-dashboard",
        action="store_true",
        help="Skip live dashboard reachability check",
    )
    parser.add_argument(
        "--gsri-evidence",
        type=Path,
        required=True,
        help="JSON evidence for G-SRI threshold state",
    )
    parser.add_argument(
        "--worm-evidence",
        type=Path,
        required=True,
        help="JSON evidence for pqc_worm_logger.py S3 Object Lock commit",
    )
    parser.add_argument(
        "--expected-worm-bucket",
        help="Designated S3 Object Lock bucket expected for WORM commits",
    )
    parser.add_argument(
        "--require-compliance-object-lock",
        action="store_true",
        help="Reject GOVERNANCE mode and require COMPLIANCE Object Lock",
    )
    parser.add_argument(
        "--attestation-evidence",
        type=Path,
        required=True,
        help="JSON evidence for TEE/TPM attestation",
    )
    parser.add_argument(
        "--max-age-minutes", type=int, default=DEFAULT_STALENESS_MINUTES
    )
    parser.add_argument(
        "--worm-max-lag-seconds", type=int, default=DEFAULT_WORM_MAX_LAG_SECONDS
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of Markdown",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    results: list[CheckResult] = []
    if not args.skip_dashboard:
        results.append(
            check_dashboard(
                args.dashboard_url, args.dashboard_timeout, args.insecure_tls
            )
        )
    else:
        results.append(
            CheckResult(
                "sentinel_dashboard", WARN, "dashboard reachability skipped by operator"
            )
        )
    results.append(
        result_from_check(
            "gsri_threshold",
            lambda: check_gsri(load_json(args.gsri_evidence), args.max_age_minutes),
        )
    )
    results.append(
        result_from_check(
            "pqc_worm_logger",
            lambda: check_worm(
                load_json(args.worm_evidence),
                args.max_age_minutes,
                args.worm_max_lag_seconds,
                args.expected_worm_bucket,
                args.require_compliance_object_lock,
            ),
        )
    )
    results.append(
        result_from_check(
            "tee_tpm_attestation",
            lambda: check_attestation(
                load_json(args.attestation_evidence), args.max_age_minutes
            ),
        )
    )

    if args.json:
        print(render_json(results))
    else:
        print(render_markdown(results))
    return 1 if any(result.is_failure for result in results) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
