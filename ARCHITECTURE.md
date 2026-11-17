# Architecture

This is a research repository, not an application. The pieces and how they relate:

| Path | Role |
|---|---|
| `RESEARCH_REPORT.md`, `CRXLauncher_Deep_Forensic_Analysis_2026.pdf` | The analysis itself |
| `SPEC.md` | Scope, constraints, roadmap, open decisions |
| `threat-intel/iocs.json` | Source of truth for indicators (most complete) |
| `threat-intel/iocs.csv` | Flat export; every row must appear in the JSON |
| `threat-intel/stix_bundle.json` | Same indicators as STIX 2.1 objects |
| `rules/crxlauncher.yar` | YARA rule |
| `rules/sigma_*.yml` | Sigma rules (filesystem and network) |
| `poc/postmessage_audit.html` | Page that probes the `postMessage` bridge |
| `scripts/check_artifacts.py` | Static validation of IOC, STIX, Sigma and YARA files |
| `tests/test_artifacts.py` | Unit tests for the validator |

## Validation flow

`check_artifacts.py` loads `iocs.json` and `iocs.csv`, validates value formats (extension id,
domains, IP addresses), checks CSV rows against the JSON, validates STIX identifiers and required
fields, and compiles the YARA rule with `yara-x`. CI (`.github/workflows/ci.yml`) runs `yamllint`
on `rules` and `.github`, then the validator, then the tests with coverage.
