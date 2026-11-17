# Roadmap

Open items, as of 2026-11-16. The research plan itself is in [SPEC.md](SPEC.md#roadmap).

1. Raise the coverage of `scripts/check_artifacts.py` to 100% and keep it in CI.
2. Validate the Sigma rules by converting them to at least one backend (`sigma-cli`).
3. Add a Chromium enterprise policy snippet and an example SIEM query.
4. Re-check the extension against the latest Web Store version and update rules only with
   verified indicators.
5. Align the README wording with the evidence in the report (see "Open decisions" in SPEC.md).
6. Record the vendor's response to the disclosure in README and CHANGELOG once confirmed.
7. Port the YARA rules into the Sentinella scanner.
8. Redact the GA4 secret of the analysed extension in the published material.
9. Decide whether `poc/` stays in the public repository.
