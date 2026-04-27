"""Shared utilities for manifest target and checksum handling."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath


def load_manifest_targets_from_dir(artifacts_dir: Path) -> list[str]:
    targets_path = artifacts_dir / "manifest-targets-v1.json"
    try:
        data = json.loads(targets_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("manifest-targets-v1.json is missing") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("manifest-targets-v1.json is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("manifest-targets-v1.json must contain an object")
    if data.get("version") != "1.0":
        raise ValueError("manifest-targets-v1.json version must be 1.0")
    files = data.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("manifest-targets-v1.json must contain a non-empty files list")
    if any(not isinstance(item, str) for item in files):
        raise ValueError("manifest-targets-v1.json files entries must be strings")
    if len(set(files)) != len(files):
        raise ValueError("manifest-targets-v1.json contains duplicate file entries")
    for item in files:
        if "\\" in item:
            raise ValueError("manifest-targets-v1.json files entries must use POSIX-style separators")
        normalized = PurePosixPath(item)
        if not item.strip():
            raise ValueError("manifest-targets-v1.json files entries must be non-empty")
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError("manifest-targets-v1.json files entries must be safe relative paths")
        target_path = artifacts_dir / normalized.as_posix()
        if not target_path.exists() or not target_path.is_file():
            raise ValueError(f"manifest-targets-v1.json references missing file: {item}")
    return files


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def timestamp_iso8601() -> str:
    source_date_epoch = os.getenv("SOURCE_DATE_EPOCH")
    if source_date_epoch is not None:
        dt = datetime.fromtimestamp(int(source_date_epoch), tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.replace(microsecond=0).isoformat()
