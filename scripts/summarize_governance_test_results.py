#!/usr/bin/env python3
"""Summarize governance JUnit test results for local/CI reporting."""

from __future__ import annotations

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

TOOL_VERSION = "1.0.0"


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize governance JUnit XML test results")
    parser.add_argument(
        "--report",
        default="artifacts/test-results/governance-tests.xml",
        help="Path to JUnit XML report",
    )
    parser.add_argument("--version", action="version", version=f"summarize_governance_test_results.py {TOOL_VERSION}")
    args = parser.parse_args()

    path = Path(args.report)
    if not path.exists():
        raise SystemExit(f"ERROR: report not found: {path}")

    root = ET.fromstring(path.read_text())
    # handle both <testsuite> root and <testsuites>/<testsuite>
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise SystemExit("ERROR: could not locate testsuite node")

    tests = int(suite.attrib.get("tests", 0))
    failures = int(suite.attrib.get("failures", 0))
    errors = int(suite.attrib.get("errors", 0))
    skipped = int(suite.attrib.get("skipped", 0))

    summary = (
        f"Governance tests: {tests} total | "
        f"{failures} failures | {errors} errors | {skipped} skipped"
    )
    print(summary)


if __name__ == "__main__":
    main()
