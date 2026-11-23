# CRXLauncher: Threat Intelligence, Vulnerability Dossier & Forensic Analysis

![CI](https://github.com/LightYagami28/crxlauncher-threat-research/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/LightYagami28/crxlauncher-threat-research)
![Stars](https://img.shields.io/github/stars/LightYagami28/crxlauncher-threat-research)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)

Static threat-intelligence artifacts (IOCs, STIX bundles, Sigma rules, YARA
rules) for the CRXLauncher Chrome extension research project, plus the tooling
that validates their integrity.

## Installazione

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary :all: -r requirements.txt
```

## Utilizzo

```bash
python scripts/check_artifacts.py
```

The checker exits with code `0` when every artifact (IOC list, STIX bundle,
Sigma and YARA rules) is valid, and with code `1` otherwise.

## Sviluppo

```bash
python -m pip install --only-binary :all: bandit==1.9.4 coverage==7.17.4 mypy==2.4.1 pip-audit==2.10.1 pytest==9.2.0 pytest-cov==7.1.0 ruff==0.17.6 types-PyYAML==6.0.12.20261122
ruff check .
ruff format --check .
mypy
python -m pytest tests --cov=scripts --cov-report=term-missing
bandit -r scripts tests
pip-audit -r requirements.txt
```

## Contribuzione

Vedi [CONTRIBUTING.md](CONTRIBUTING.md). Per nuovi artefatti:

1. Aggiornare `threat-intel/iocs.json` (fonte di verità) e
   `threat-intel/iocs.csv`.
2. Aggiornare `threat-intel/stix_bundle.json`.
3. Aggiungere/aggiornare le regole in `rules/`.
4. Eseguire `python scripts/check_artifacts.py` e la suite pytest.

## Sicurezza

Vedi [SECURITY.md](SECURITY.md).
