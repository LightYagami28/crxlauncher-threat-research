# FAQ

## What is in this repository?
Detection rules (YARA, Sigma), IOC lists (CSV, JSON, STIX 2.1), a research report and a disclosure
dossier about the CRXLauncher browser extension. See [README.md](README.md).

## Does it contain the extension or any payload?
No. Distributing the extension or any payload is out of scope ([SPEC.md](SPEC.md)).

## How do I check that the artifacts are consistent?
```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary :all: -r requirements.txt
.venv/bin/yamllint -c .yamllint rules .github
.venv/bin/python scripts/check_artifacts.py
.venv/bin/python -m unittest discover -s tests -v
```
On Windows use `.venv\Scripts\python`. The same steps run in CI.

## Why are the rules not "verified against the live extension" in CI?
CI validates format and consistency (IOC syntax, CSV/JSON agreement, STIX fields, Sigma and YARA
syntax). Re-checking the extension itself is a manual step, tracked in [ROADMAP.md](ROADMAP.md).

## Is the proof-of-concept page dangerous?
`poc/postmessage_audit.html` only sends a status request through the page bridge to an installed
and active extension. It does nothing if the extension is absent.

## How do I report an error or a false positive?
Open an issue, or ask in the Discussions. For vulnerabilities in the repository itself see
[SECURITY.md](SECURITY.md).
