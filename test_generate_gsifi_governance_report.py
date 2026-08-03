import json
from pathlib import Path

import tools.generate_gsifi_governance_report as report


def test_generate_markdown_summary_from_json(tmp_path, monkeypatch):
    summary_json = tmp_path / 'summary.json'
    summary_md = tmp_path / 'summary.md'

    summary_json.write_text(
        json.dumps(
            {
                'status': 'passed',
                'results': [
                    {'command': ['python', 'tool.py'], 'returncode': 0, 'output': 'ok'},
                    {'command': ['pytest', '-q'], 'returncode': 0, 'output': '13 passed'},
                ],
            }
        ),
        encoding='utf-8',
    )

    monkeypatch.setattr(
        report,
        'parse_args',
        lambda: type('Args', (), {'summary_json': str(summary_json), 'output': str(summary_md)})(),
    )

    rc = report.main()
    assert rc == 0
    assert summary_md.exists()

    content = summary_md.read_text(encoding='utf-8')
    assert '# GSIFI Governance Check Summary' in content
    assert 'Status: **passed**' in content
    assert '`python tool.py`' in content
    assert '`pytest -q`' in content
