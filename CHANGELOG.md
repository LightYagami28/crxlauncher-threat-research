# Changelog

## 2026-10-31

### Fixed
- `rules/crxlauncher.yar`: unescaped double quotes in `$s4` made the rule fail to compile; quotes escaped.
- `threat-intel/stix_bundle.json`: added the `created` and `modified` fields required by STIX 2.1.
- README: removed the reference to the deleted `DISCLOSURE_NOTICE.md`; the GA4 API secret is no longer repeated there.

### Added
- `SPEC.md`, `CONTRIBUTING.md`, `SECURITY.md`, this changelog.
- `scripts/check_artifacts.py` and tests on synthetic data.
- CI: yamllint, validation, tests and gitleaks (actions pinned by SHA, dependencies locked with hashes); `.gitleaks.toml`, `.yamllint`.

No new indicators were added.

## 2026-10-20
- Initial release.
