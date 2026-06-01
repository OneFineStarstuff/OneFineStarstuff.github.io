#!/usr/bin/env python3
"""Run GSIFI governance validation and tests with a concise summary."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or '') + (proc.stderr or '')
    return proc.returncode, out.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Run GSIFI governance checks')
    parser.add_argument('--junitxml', default='', help='Optional junit xml output path for pytest')
    parser.add_argument('--emit-json', default='', help='Optional path to write machine-readable run summary JSON')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    test_files = [
        'test_governance_snippets.py',
        'test_validate_governance_artifacts.py',
        'test_run_gsifi_governance_checks.py',
        'test_generate_gsifi_governance_report.py',
        'test_daily_gsifi_governance_workflow.py',
    ]
    pytest_cmd = ['pytest', '-q', *test_files]
    if args.junitxml:
        pytest_cmd = ['pytest', '-q', f'--junitxml={args.junitxml}', *test_files]

    commands = [
        [sys.executable, 'tools/validate_governance_artifacts.py'],
        pytest_cmd,
    ]

    failures: list[str] = []
    results: list[dict[str, object]] = []
    for cmd in commands:
        rc, out = run(cmd)
        print(f"$ {' '.join(cmd)}")
        if out:
            print(out)
        print('-' * 60)
        results.append({'command': cmd, 'returncode': rc, 'output': out})
        if rc != 0:
            failures.append(' '.join(cmd))

    if args.emit_json:
        Path(args.emit_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.emit_json).write_text(json.dumps({'status': 'failed' if failures else 'passed', 'results': results}, indent=2) + '\n', encoding='utf-8')

    if failures:
        print('FAILED COMMANDS:')
        for cmd in failures:
            print(f'- {cmd}')
        return 1

    print('All GSIFI governance checks passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
