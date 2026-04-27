.PHONY: deps manifest-check validate check-all test all

PYTHON ?= python

deps:
	$(PYTHON) -m pip install -r requirements-artifacts.txt

manifest-check:
	$(PYTHON) build_manifest.py --check --json

validate:
	$(PYTHON) validate_artifacts.py --json

check-all:
	$(PYTHON) check_all.py --json

test:
	cd .. && $(PYTHON) -m pytest -q unit_tests/test_artifacts_validation.py

# `check-all` already runs semantic validation and manifest verification.
all: manifest-check check-all test
