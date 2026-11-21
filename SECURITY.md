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
