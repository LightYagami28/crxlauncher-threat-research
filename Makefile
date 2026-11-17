.PHONY: venv lint check test

venv:
	python -m venv .venv
	.venv/bin/python -m pip install --require-hashes --only-binary :all: -r requirements.txt

lint:
	.venv/bin/yamllint -c .yamllint rules .github

check:
	.venv/bin/python scripts/check_artifacts.py

test:
	.venv/bin/python -m unittest discover -s tests -v
