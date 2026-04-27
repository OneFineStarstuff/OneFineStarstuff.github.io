from pathlib import Path
import json
import subprocess
import sys


def test_manifest_script_generates_expected_structure(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts/examples").mkdir(parents=True, exist_ok=True)
    (root / "docs/artifacts/schemas").mkdir(parents=True, exist_ok=True)

    files = {
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml": "a: 1\n",
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json": "{}\n",
        "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json": "{}\n",
        "docs/artifacts/examples/cicd_policy_gate_manifest.yaml": "required_gates: []\n",
        "docs/artifacts/examples/regulator_report_template.xml": "<title>x</title><abstract>y</abstract><content></content>",
    }

    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    script = Path(__file__).resolve().parent / "scripts" / "generate_governance_manifest.py"
    out = "docs/artifacts/manifest.json"
    result = subprocess.run(
        [sys.executable, str(script), "--root", str(root), "--output", out],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    manifest = json.loads((root / out).read_text())
    assert manifest["algorithm"] == "sha256"
    assert len(manifest["entries"]) == 5
    assert all("sha256" in e for e in manifest["entries"])


def test_manifest_script_verify_mode_detects_stale_manifest(tmp_path):
    root = tmp_path / "repo"
    (root / "docs/artifacts/examples").mkdir(parents=True, exist_ok=True)
    (root / "docs/artifacts/schemas").mkdir(parents=True, exist_ok=True)

    files = {
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml": "a: 1\n",
        "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json": "{}\n",
        "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json": "{}\n",
        "docs/artifacts/examples/cicd_policy_gate_manifest.yaml": "required_gates: []\n",
        "docs/artifacts/examples/regulator_report_template.xml": "<title>x</title><abstract>y</abstract><content></content>",
    }
    for rel, c in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(c)

    script = Path(__file__).resolve().parent / "scripts" / "generate_governance_manifest.py"
    out = "docs/artifacts/manifest.json"

    # generate clean manifest
    subprocess.run([sys.executable, str(script), "--root", str(root), "--output", out], check=True)

    # mutate tracked file and verify catches staleness
    (root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml").write_text("a: 2\n")
    result = subprocess.run([sys.executable, str(script), "--root", str(root), "--output", out, "--verify"], capture_output=True, text=True)

    assert result.returncode != 0
    assert "manifest is stale" in (result.stdout + result.stderr).lower()
