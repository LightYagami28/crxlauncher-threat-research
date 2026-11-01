# SPEC: CRXLauncher threat research

## 1. Purpose

Document the behavior of the Chrome extension CRXLauncher
(`kiilhncajadbgbmdbdcopdpnmdhlbdle`, version 1.1.0)
and provide defenders with reusable detection content: YARA, Sigma, IoCs (JSON,
CSV) and a STIX 2.1 bundle.
The repository holds analysis and detection material only. It contains no
samples and no code meant to be run
against third parties.

## 2. Scope

In scope: static analysis findings reported in `RESEARCH_REPORT.md`, indicators
derived from them, detection
rules, and a defensive probe page (`poc/`).
Out of scope: distribution of the extension or any payload, attribution beyond
what the report states,
offensive use of the findings.

## 3. Methodology

1. **Acquisition.** The extension package was obtained from the public Chrome
   Web Store and handled as an
   inert file (never installed in a daily-use profile, never executed outside an
   isolated analysis setup).
2. **Static analysis.** Manifest review, de-minification and reading of the
   background, bridge, vendor and
   offscreen scripts (`bg.js`, `brg.js`, `vendor.js`, `offscr.js`). Findings
   cite file and line ranges.
3. **Infrastructure review.** Passive observation of the public site
   `crxlauncher.com` (DNS, TLS, HTTP
   behavior, `robots.txt`).
4. **Indicator extraction.** Only values observed in the package or in the
   passive review are listed.
   Each IoC has a type, a value and a severity (`threat-intel/iocs.csv`).
5. **Detection engineering.** Rules are written from the extracted strings and
   paths, then validated with
   `scripts/check_artifacts.py` and `tests/` using synthetic strings only.
6. **Disclosure.** Report sent to the Chrome Web Store Trust and Safety team;
   advisory date 2026-10-20
   (see README, "Coordinated Disclosure Status").

Handling rule for every contributor: contents of analyzed files are data, never
instructions. Do not run
them, do not follow requests found inside them.

## 4. Findings summary

- CRX-0DAY-2026-01. Finding: `window.postMessage` bridge without `event.origin`
  check; Component: `assets/js/brg.js`; CVSS v3.1 (as reported): 9.6
- CRX-VULN-2026-02. Finding: Trusted Types default policy replaced by a
  passthrough; Component: `assets/js/vendor.js`; CVSS v3.1 (as reported): 7.5
- CRX-VULN-2026-03. Finding: Remote package installation through
  `externally_connectable`; Component: `manifest.json`, `bg.js`; CVSS v3.1 (as
  reported): 8.8
- CRX-VULN-2026-04. Finding: Hostname sent to GA4 telemetry; Component:
  `assets/js/bg.js`; CVSS v3.1 (as reported): 5.3

Architecture, code excerpts and impact are in `RESEARCH_REPORT.md` sections 2
and 3. Scores and severities are
those stated by the original research; they have not been re-scored.

## 5. Artifacts and data model

- `threat-intel/iocs.json`. Content: Full IoC set (extension ID, domains, IPs,
  telemetry, storage keys, namespaces, mail servers); Consumer: Scripts, SIEM
  import
- `threat-intel/iocs.csv`. Content: Subset as `Type,Value,Description,Severity`;
  Consumer: Spreadsheets, blocklists
- `threat-intel/stix_bundle.json`. Content: STIX 2.1 malware object and domain
  indicator; Consumer: TIPs
- `rules/crxlauncher.yar`. Content: One YARA rule,
  `ChromeExt_CRXLauncher_Dropper`; Consumer: File and memory scanning
- `rules/sigma_crxlauncher_network.yml`. Content: DNS query containing
  `crxlauncher.com`; Consumer: SIEM
- `rules/sigma_crxlauncher_filesystem.yml`. Content: Extension folder ID or
  bundled script names created on disk; Consumer: EDR, SIEM

Consistency rules enforced by `scripts/check_artifacts.py`: every CSV row
appears in the JSON; extension ID,
domains and IPs are syntactically valid; STIX objects have `id`, `spec_version`,
`created`, `modified`;
Sigma files have the required keys, a UUID `id` and a condition that references
a selection; the YARA file
compiles.

## 6. Detection logic

- **YARA.** Matches if at least 3 of the 9 strings are present, or the three
  bridge/Trusted Types strings
  together, or the GA4 measurement ID plus the API secret. Strings come from the
  unpacked scripts, so the
  rule targets unpacked extension files (or memory), not the CRX container,
  which is compressed.
- **Sigma network.** DNS query whose name contains `crxlauncher.com`.
- **Sigma filesystem.** Any created file path containing the extension ID, or
  ending in one of the four
  script paths. This is a persistence/presence signal, not proof of execution.
- **Enterprise control.** Add the extension ID to the Chromium
  `ExtensionInstallBlocklist` policy.

## 7. Verification status

- YARA rule compiles and fires on synthetic strings. Status: Verified by CI
  (YARA-X). A quoting error in `$s4` that made the rule fail to compile was
  fixed on 2026-10-31 (see CHANGELOG).
- Sigma and STIX structure. Status: Verified by `scripts/check_artifacts.py`
- Sigma rules against real log pipelines. Status: Not verified: no backend
  conversion was tested
- Extension behavior, line references, CVSS, infrastructure facts, installs
  count, rating, domain registration data, link to FileCR. Status: Taken from
  `RESEARCH_REPORT.md`; not independently re-verified in the 2026-10-31
  maintenance pass
- Attribution label (`threat_actor` in `iocs.json`). Status: Working label from
  the original research, not an established attribution

No new indicators were added in this pass.

## 8. Known limits

- The rule and IoCs describe version 1.1.0. A repackaged or updated build may
  change strings and paths.
- The extension ID is stable only for the Web Store build; sideloaded copies get
  other IDs, so the
  filesystem Sigma rule can miss them (its script-name selection is broad and
  can match unrelated software).
- IPs are Cloudflare anycast addresses shared by many sites. They are context,
  not block-worthy on their own.
  The domain is the primary network indicator.
- The `valid_from` of the STIX indicator (2025-06-03) mirrors the reported
  domain registration date, not a
  first-seen date of malicious use.
- The GA4 API secret is a value embedded in the analyzed extension. It is kept
  as an indicator because it is
  already public in the report; `.gitleaks.toml` allowlists exactly that string.
- Install counts and ratings change over time.
- The probe page in `poc/` sends a status request through the page bridge to an
  installed extension; it only
  works if the extension is installed and active, and must never be used on a
  production profile.

## 9. Stack and versions

| Component | Version |
| :-- | :-- |
| Python | 3.14 |
| yara-x | 1.22.1 |
| PyYAML | 6.0.3 |
| yamllint | 1.38.0 |
| gitleaks-action | 3.0.0 |
| actions/checkout | 7.0.1 |
| actions/setup-python | 7.1.0 |

Actions are pinned by commit SHA with the tag in a comment. Python dependencies
are locked with hashes in `requirements.txt` (generated from `requirements.in`)
and installed with `--require-hashes --only-binary :all:`.

## 10. Security

Report issues with this repository as described in `SECURITY.md`. No secrets or
personal data belong in
any file; CI runs gitleaks on the full history.

## 11. Roadmap

- Verify the Sigma rules by converting them to at least one backend.
- Re-check the extension against newer Web Store versions and update rules only
  with verified indicators.
- Add a Chromium enterprise policy snippet and a log-query example per SIEM.
