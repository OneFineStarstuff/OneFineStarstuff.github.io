from pathlib import Path


def test_workflow_contains_required_check_steps_and_artifacts():
    wf = Path('.github/workflows/daily-gsifi-governance-validation.yml').read_text(encoding='utf-8')

    required_fragments = [
        'name: daily-gsifi-governance-validation',
        'workflow_dispatch:',
        'make daily-gsifi-governance-pycompile',
        'make daily-gsifi-governance-ci',
        'make daily-gsifi-governance-report',
        'artifacts/test-results/gsifi-governance-tests.xml',
        'artifacts/test-results/gsifi-governance-run-summary.json',
        'artifacts/test-results/gsifi-governance-run-summary.md',
        'requirements-governance-checks.txt',
    ]

    for fragment in required_fragments:
        assert fragment in wf
