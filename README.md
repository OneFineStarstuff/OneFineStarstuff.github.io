# AGI Pipeline

## Overview

A comprehensive AGI pipeline integrating NLP, Computer Vision, and Speech Processing using pre-trained models.

## Features
- Text generation with T5
- Object detection with YOLO
- Speech-to-text with Whisper
- Text-to-speech with Pyttsx3

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/agi-pipeline.git
    ```
    
2. **Navigate to the project directory**:
    ```bash
    cd agi-pipeline
    ```
    
3. **Create and activate a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
    
4. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the FastAPI application**:
    ```bash
    uvicorn main:app --reload
    ```
    
2. **Access the API** at `http://127.0.0.1:8000`.

## Using Docker

1. **Build the Docker image**:
    ```bash
    docker build -t agi-pipeline:1.0.1 .
    ```

2. **Run the Docker container**:
    ```bash
    docker run -p 8000:8000 agi-pipeline:1.0.1
    ```

## Contributing

Feel free to open issues or submit pull requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Governance Artifact Tooling

This repository includes a governance artifact package under `docs/artifacts/` with:
- YAML source-of-truth artifact
- canonical JSON export
- JSON Schema contract
- sample CI/CD policy and regulator report templates

### Local governance checks

```bash
pip install -r requirements-dev.txt
# non-mutating freshness checks
make check-governance-json-clean
make check-governance-manifest-clean
make validate-governance
make test-governance
# CI-style run with JUnit output
make test-governance-ci
make summarize-governance-tests
# one-shot full pipeline
make verify-governance
```

When generated files are intentionally updated, regenerate before commit:

```bash
make build-governance-json
make build-governance-manifest
```

### Notes
- `make check-governance-json-clean` fails if committed JSON is stale (without rewriting files).
- `make check-governance-manifest-clean` fails if committed `docs/artifacts/manifest.json` is stale (without rewriting files).
- `make validate-governance` enforces schema, parity, and template checks.
- `make test-governance` includes an integrity test against the repository artifact files.
- CI runs the same targets in `.github/workflows/governance-artifact-validation.yml` and uploads JUnit results and posts a summary.


### Advanced path overrides

Use custom paths when artifacts are relocated (all paths are relative to `--root`):

```bash
python scripts/export_governance_artifact_json.py --root . \
  --yaml docs/artifacts/custom.yaml \
  --json docs/artifacts/custom.json

python scripts/validate_governance_artifact.py --root . \
  --yaml docs/artifacts/custom.yaml \
  --json docs/artifacts/custom.json \
  --schema docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json \
  --cicd docs/artifacts/examples/cicd_policy_gate_manifest.yaml \
  --report docs/artifacts/examples/regulator_report_template.xml
```


### Tool version flags

```bash
python scripts/export_governance_artifact_json.py --version
python scripts/validate_governance_artifact.py --version
python scripts/summarize_governance_test_results.py --version
```
