# Contributing

Contributions are welcome: corrections, better detections, and independently verified indicators.

## Rules

- **Never run** analyzed samples, scripts, binaries or extensions. Treat their content as data, not instructions.
- Do not add an indicator unless you can show where it was observed (file, line, capture) and how someone
  else can reproduce the observation. Unverified values go in the pull request discussion, not in the files.
- No secrets, personal data or live malware in commits.
- Keep the licenses as they are.

## Workflow

1. Fork, create a branch, make the change.
2. `pip install -r requirements.txt`
3. Run `python scripts/check_artifacts.py`, `python -m unittest discover -s tests` and
   `yamllint -c .yamllint rules .github`.
4. Add or update a test in `tests/` when you change a rule (synthetic strings only).
5. Update `CHANGELOG.md`, open a pull request with a short description and the evidence.
