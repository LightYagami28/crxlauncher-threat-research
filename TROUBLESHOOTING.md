# Troubleshooting

## `pip install --require-hashes` fails
Hashes in `requirements.txt` are for specific wheels: use `--only-binary :all:` and a supported
Python (CI uses 3.14). Regenerate with `pip-compile --generate-hashes requirements.in` when you
change `requirements.in`.

## `ModuleNotFoundError: yara_x` or `yaml`
You are not in the virtual environment, or you installed packages without the hashed file. Create
the venv and install from `requirements.txt` (see [FAQ.md](FAQ.md)).

## `yamllint` reports line length or indentation errors
Rules follow `.yamllint`. Run `yamllint -c .yamllint rules .github` and fix as reported.

## The validator says a CSV row is missing from the JSON
`iocs.json` is the source of truth. Add the indicator to the JSON first, then to the CSV and STIX
bundle.
