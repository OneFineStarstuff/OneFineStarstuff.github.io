#!/usr/bin/env python3
"""Shared dependency helpers for governance validation scripts."""
from __future__ import annotations


INSTALL_HINT = "python -m pip install -r docs/schemas/requirements-governance.txt"


def require_jsonschema():
    """Return Draft202012Validator or raise SystemExit with a consistent message."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise SystemExit(f"[FAIL] jsonschema package is required. Install with: {INSTALL_HINT}") from exc
    return Draft202012Validator
