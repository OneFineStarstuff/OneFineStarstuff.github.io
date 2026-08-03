import json

import tools.run_gsifi_governance_checks as runner


def test_build_parser_defaults():
    parser = runner.build_parser()
    args = parser.parse_args([])
    assert args.junitxml == ''
    assert args.emit_json == ''


def test_main_emits_json_summary(tmp_path, monkeypatch):
    out_json = tmp_path / 'run-summary.json'

    def fake_run(cmd):
        return 0, f'OK: {" ".join(cmd)}'

    monkeypatch.setattr(runner, 'run', fake_run)

    rc = runner.main(['--emit-json', str(out_json)])

    assert rc == 0
    assert out_json.exists()

    payload = json.loads(out_json.read_text(encoding='utf-8'))
    assert payload['status'] == 'passed'
    assert isinstance(payload['results'], list)
    assert len(payload['results']) == 2
    assert all('command' in item and 'returncode' in item for item in payload['results'])
