import json
from pathlib import Path
from tools.validate_ai_governance_artifacts import run_validation, ROOT

def test_repro(tmp_path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    bbom = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    arre["evidence_hashes"] = ["dup", "dup"]

    (bbom_dir / "good_bbom.json").write_text(json.dumps(bbom), encoding="utf-8")
    (arre_dir / "bad_arre.json").write_text(json.dumps(arre), encoding="utf-8")

    print(f"BBOM dir: {bbom_dir}")
    print(f"ARRE dir: {arre_dir}")

    errors, summary = run_validation(str(bbom_dir), [str(arre_dir)])
    print(f"Errors: {errors}")
    print(f"Summary: {summary}")
    assert any("duplicate evidence_hashes" in err for err in errors)

if __name__ == "__main__":
    import tempfile
    import shutil
    tmp = Path(tempfile.mkdtemp())
    try:
        test_repro(tmp)
    finally:
        shutil.rmtree(tmp)
