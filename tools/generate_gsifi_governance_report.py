#!/usr/bin/env python3
"""Generate a markdown summary from GSIFI governance run evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument('--summary-json', default='artifacts/test-results/gsifi-governance-run-summary.json')
    p.add_argument('--output', default='artifacts/test-results/gsifi-governance-run-summary.md')
    return p.parse_args()


def main() -> int:
    args = parse_args()
    summary = json.loads(Path(args.summary_json).read_text(encoding='utf-8'))

    lines = ['# GSIFI Governance Check Summary', '']
    lines.append(f"Status: **{summary.get('status', 'unknown')}**")
    lines.append('')
    lines.append('| Command | Return code |')
    lines.append('|---|---:|')
    for item in summary.get('results', []):
        cmd = ' '.join(item.get('command', []))
        rc = item.get('returncode', '')
        lines.append(f'| `{cmd}` | {rc} |')

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Wrote {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
