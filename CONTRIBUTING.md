# Contributing to AGI Pipeline

Thank you for your interest in contributing to the AGI Pipeline project! We welcome contributions from the community to help improve and expand the capabilities of this modular AGI framework.

## How to Contribute

### 1. Reporting Bugs
If you find a bug, please open an issue on GitHub with a detailed description of the problem, steps to reproduce it, and any relevant logs or screenshots.

### 2. Suggesting Features
We encourage feature requests! Please open an issue to discuss your ideas before starting work.

### 3. Pull Requests
1. Fork the repository.
2. Create a new branch for your feature or bugfix: `git checkout -b feature/your-feature-name`.
3. Make your changes and ensure they follow our coding standards.
4. Run tests to verify your changes.
5. Submit a pull request with a clear description of what your changes do.

## Development Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/OneFineStarstuff/AGI-Pipeline.git
   cd AGI-Pipeline
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

## Coding Standards

To maintain high code quality, we enforce the following standards:

- **Formatting**: We use [Black](https://github.com/psf/black) for code formatting.
- **Imports**: We use [isort](https://pycqa.github.io/isort/) to sort imports.
- **Linting**: We aim for a [Pylint](https://www.pylint.org/) score of 10/10.

Before submitting a PR, please run the following commands:
```bash
black .
isort .
pylint --rcfile=.pylintrc your_module.py
```

## Testing

We use [pytest](https://docs.pytest.org/) for testing. Ensure all tests pass before submitting a PR:
```bash
python3 -m pytest
```

## Governance Artifacts

If your contribution affects governance artifacts, please ensure you update the manifest and validate the artifacts:
```bash
make verify-governance
```
