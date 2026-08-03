"""Build checksum manifest for governance artifacts.

Supports reproducible timestamps via SOURCE_DATE_EPOCH.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ARTIFACTS_DIR = Path(__file__).resolve().parent

if __package__ in (None, ""):
    from manifest_utils import load_manifest_targets_from_dir, sha256_file, timestamp_iso8601
else:
    from .manifest_utils import load_manifest_targets_from_dir, sha256_file, timestamp_iso8601


def load_manifest_targets() -> list[str]:
    return load_manifest_targets_from_dir(ARTIFACTS_DIR)


def build_manifest_payload() -> dict:
    manifest = {
        "version": "1.1",
        "generated_at": timestamp_iso8601(),
        "files": {},
    }
    for rel in load_manifest_targets():
        manifest["files"][rel] = sha256_file(ARTIFACTS_DIR / rel)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or check artifact checksum manifest")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if manifest is out of date")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    return parser.parse_args()


def emit(args: argparse.Namespace, payload: dict) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(payload["message"])


def run_cli(args: argparse.Namespace) -> int:
    try:
        out = ARTIFACTS_DIR / "artifact-manifest-v1.json"
        payload = build_manifest_payload()
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

        if args.check:
            if not out.exists():
                emit(args, {"status": "error", "message": "Manifest missing. Run: python artifacts/build_manifest.py"})
                return 1
            try:
                existing = json.loads(out.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                emit(args, {"status": "error", "message": "Manifest file is invalid JSON. Run: python artifacts/build_manifest.py"})
                return 1
            if not isinstance(existing, dict):
                emit(args, {"status": "error", "message": "Manifest file has invalid structure. Run: python artifacts/build_manifest.py"})
                return 1
            if existing.get("version") != payload.get("version") or existing.get("files") != payload.get("files"):
                emit(args, {"status": "error", "message": "Manifest is out of date. Run: python artifacts/build_manifest.py"})
                return 1
            emit(args, {"status": "ok", "message": "Manifest is up to date."})
            return 0

        out.write_text(rendered, encoding="utf-8")
        emit(args, {"status": "ok", "message": f"Wrote {out}"})
        return 0
    except ValueError as exc:
        emit(args, {"status": "error", "message": str(exc)})
        return 1


def main() -> None:
    args = parse_args()
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()
