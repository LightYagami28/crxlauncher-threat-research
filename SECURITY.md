# Security policy

## Scope

This repository contains documentation and detection content, not running
software. Relevant reports:
an incorrect indicator that could block legitimate services, a rule that is
unsafe to deploy, or sensitive
data committed by mistake.

## Reporting

Use GitHub private vulnerability reporting for this repository (Security tab,
"Report a vulnerability").
Do not open a public issue for sensitive data.

## Findings about the analyzed extension

Findings on CRXLauncher itself were sent through the Chrome Web Store Trust and
Safety channel; see the
README. Do not send samples or exploit code to this repository.

## HTTPS

This repository contains no active network URL using plain HTTP. The two
`http://*/*` occurrences in `RESEARCH_REPORT.md` are Chrome extension **match
patterns**: they document which requests the analyzed extension is allowed to
observe, they are not requests made by this repository. Rewriting them as
`https://` would alter the recorded evidence, so they are kept as-is.

## Static analysis status (2026-11-21)

Before the fixes Codacy reported 109 findings:
1 Error, 7 Warning, 101 Info. No suppression was added
and no test assertion was removed.

- `Lizard_ccn-critical` (1 Error): `check_csv_rows` had a
  complexity of 17. The function is now split into three
  helpers that build the value sets, check one row and
  collect the errors; each is below the threshold.
- `Prospector_pydocstyle` (49): docstring conventions
  D213/D413/D406, formatting only.
- `markdownlint_MD013` (27) and `MD022` (17): line length
  and blank lines around headings in the Markdown files.
- `PyLintPython3_W0621` (4): pytest methods reuse the
  fixture parameter name from the module scope.
- `Lizard_ccn-medium` (2): `is_valid_domain` and
  `check_ioc_values` are above the advisory threshold
  (9 and 10 against 8) but below the critical one.
- `Prospector_vulture` (1): object used only by a test.
