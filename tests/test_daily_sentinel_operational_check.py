import datetime as dt
import json
from pathlib import Path

import pytest

import scripts.daily_sentinel_operational_check as checker


def utc_now_z() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def future_z(days: int = 365) -> str:
    return (
        (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def valid_gsri() -> dict:
    return {
        "timestamp_utc": utc_now_z(),
        "current_value": 0.41,
        "threshold": 0.7,
        "policy_version": "gsri-risk-appetite-2026.05",
        "signed": True,
    }


def valid_worm() -> dict:
    return {
        "timestamp_utc": utc_now_z(),
        "logger_name": "pqc_worm_logger.py",
        "batch_status": "committed",
        "bucket": "sentinel-object-lock-audit",
        "object_key": "audit/2026/05/29/batch-0001.jsonl",
        "object_version_id": "3HL4kqtJlcpXrof3vjVBH40Nrjfkd",
        "object_lock_mode": "COMPLIANCE",
        "retention_until_utc": future_z(),
        "merkle_root": "sha256:abc123",
        "pqc_signature_alg": "ML-DSA-65",
        "pqc_signature_verified": True,
        "commit_lag_seconds": 42,
    }


def valid_attestation() -> dict:
    return {
        "timestamp_utc": utc_now_z(),
        "PCR_MATCH": True,
        "tee_status": "trusted",
        "node_id": "sentinel-prod-01",
        "pcr_policy_hash": "sha256:def456",
        "tpm_quote_id": "quote-20260529-0001",
        "verifier_id": "attestor-v2.4.3",
        "attestation_signature_verified": True,
    }


def test_check_gsri_passes_when_signed_and_below_threshold() -> None:
    result = checker.check_gsri(valid_gsri(), max_age_minutes=30)
    assert result.status == checker.PASS
    assert "below threshold" in result.summary


def test_check_gsri_fails_when_unsigned() -> None:
    evidence = valid_gsri()
    evidence["signed"] = False
    result = checker.check_gsri(evidence, max_age_minutes=30)
    assert result.status == checker.FAIL
    assert "signature is not verified" in result.summary


def test_check_gsri_fails_when_above_threshold() -> None:
    evidence = valid_gsri()
    evidence["current_value"] = 0.99
    result = checker.check_gsri(evidence, max_age_minutes=30)
    assert result.status == checker.FAIL
    assert "at or above" in result.summary


def test_check_worm_passes_for_committed_object_lock_batch() -> None:
    result = checker.check_worm(valid_worm(), max_age_minutes=30, max_lag_seconds=900)
    assert result.status == checker.PASS
    assert "Object Lock" in result.summary


def test_check_worm_fails_for_lag_breach() -> None:
    evidence = valid_worm()
    evidence["commit_lag_seconds"] = 901
    result = checker.check_worm(evidence, max_age_minutes=30, max_lag_seconds=900)
    assert result.status == checker.FAIL
    assert "exceeds" in result.summary


def test_check_worm_rejects_wrong_logger_name() -> None:
    evidence = valid_worm()
    evidence["logger_name"] = "other.py"
    with pytest.raises(checker.CheckError, match="pqc_worm_logger.py"):
        checker.check_worm(evidence, max_age_minutes=30, max_lag_seconds=900)


def test_check_worm_fails_for_expected_bucket_mismatch() -> None:
    evidence = valid_worm()
    result = checker.check_worm(
        evidence,
        max_age_minutes=30,
        max_lag_seconds=900,
        expected_bucket="different-object-lock-bucket",
    )
    assert result.status == checker.FAIL
    assert "does not match expected bucket" in result.summary


def test_check_worm_fails_when_pqc_signature_not_verified() -> None:
    evidence = valid_worm()
    evidence["pqc_signature_verified"] = False
    result = checker.check_worm(evidence, max_age_minutes=30, max_lag_seconds=900)
    assert result.status == checker.FAIL
    assert "PQC signature" in result.summary


def test_check_attestation_passes_for_pcr_match() -> None:
    result = checker.check_attestation(valid_attestation(), max_age_minutes=30)
    assert result.status == checker.PASS
    assert "PCR_MATCH=TRUE" in result.summary


def test_check_attestation_fails_for_pcr_mismatch() -> None:
    evidence = valid_attestation()
    evidence["PCR_MATCH"] = False
    result = checker.check_attestation(evidence, max_age_minutes=30)
    assert result.status == checker.FAIL
    assert "PCR_MATCH" in result.summary


def test_check_attestation_fails_when_signature_not_verified() -> None:
    evidence = valid_attestation()
    evidence["attestation_signature_verified"] = False
    result = checker.check_attestation(evidence, max_age_minutes=30)
    assert result.status == checker.FAIL
    assert "signature" in result.summary


def test_parse_utc_timestamp_requires_z_suffix() -> None:
    with pytest.raises(checker.CheckError, match="ending in 'Z'"):
        checker.parse_utc_timestamp("2026-05-29T12:00:00+00:00", "timestamp_utc")


def test_main_returns_zero_for_valid_offline_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gsri = write_json(tmp_path / "gsri.json", valid_gsri())
    worm = write_json(tmp_path / "worm.json", valid_worm())
    attestation = write_json(tmp_path / "attestation.json", valid_attestation())

    rc = checker.main(
        [
            "--skip-dashboard",
            "--gsri-evidence",
            str(gsri),
            "--worm-evidence",
            str(worm),
            "--attestation-evidence",
            str(attestation),
        ]
    )

    assert rc == 0
    assert "Overall status: **AMBER**" in capsys.readouterr().out


def test_main_returns_nonzero_when_evidence_is_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = valid_gsri()
    stale["timestamp_utc"] = "2026-01-01T00:00:00Z"
    gsri = write_json(tmp_path / "gsri.json", stale)
    worm = write_json(tmp_path / "worm.json", valid_worm())
    attestation = write_json(tmp_path / "attestation.json", valid_attestation())

    rc = checker.main(
        [
            "--skip-dashboard",
            "--gsri-evidence",
            str(gsri),
            "--worm-evidence",
            str(worm),
            "--attestation-evidence",
            str(attestation),
        ]
    )

    assert rc == 1
    assert "gsri_threshold" in capsys.readouterr().out


def test_main_continues_after_individual_evidence_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_gsri = write_json(tmp_path / "bad-gsri.json", {"timestamp_utc": "not-z"})
    worm = write_json(tmp_path / "worm.json", valid_worm())
    attestation = write_json(tmp_path / "attestation.json", valid_attestation())

    rc = checker.main(
        [
            "--skip-dashboard",
            "--gsri-evidence",
            str(bad_gsri),
            "--worm-evidence",
            str(worm),
            "--attestation-evidence",
            str(attestation),
        ]
    )

    output = capsys.readouterr().out
    assert rc == 1
    assert "gsri_threshold" in output
    assert "pqc_worm_logger | PASS" in output
    assert "tee_tpm_attestation | PASS" in output


def test_json_output_contains_overall_status_and_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gsri = write_json(tmp_path / "gsri.json", valid_gsri())
    worm = write_json(tmp_path / "worm.json", valid_worm())
    attestation = write_json(tmp_path / "attestation.json", valid_attestation())

    rc = checker.main(
        [
            "--skip-dashboard",
            "--json",
            "--gsri-evidence",
            str(gsri),
            "--worm-evidence",
            str(worm),
            "--attestation-evidence",
            str(attestation),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["overall_status"] == "AMBER"
    assert len(payload["results"]) == 4
