import json
import subprocess
import sys
from pathlib import Path


def test_cli_module_invocation_succeeds() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "scripts.validate_gsifi_governance_assets"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "All GSIFI governance artifact checks passed." in result.stdout


def test_cli_returns_nonzero_for_bad_schema(tmp_path: Path) -> None:
    schema_path = tmp_path / "bad-schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps({"type": "object", "required": ["foo"], "properties": {"foo": {"type": "string"}}}))
    sample_path.write_text(json.dumps({"bar": "x"}))

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.validate_gsifi_governance_assets",
            "--schema",
            str(schema_path),
            "--sample",
            str(sample_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "VALIDATION FAILED" in result.stderr
