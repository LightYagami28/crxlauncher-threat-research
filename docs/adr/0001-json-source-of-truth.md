# 0001 - Indicators live in JSON, other formats derive from it

Status: accepted

## Context

The same indicators are published as JSON, CSV and STIX 2.1 and can drift apart.

## Decision

`threat-intel/iocs.json` is the most complete source; `check_artifacts.py` fails
if a CSV row is not in the JSON and validates the STIX bundle.

## Consequences

Add or change an indicator in the JSON first; CI catches inconsistencies.
