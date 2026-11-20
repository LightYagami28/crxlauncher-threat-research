"""Pytest test suite for the CRXLauncher artifact static validator."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
import yara_x

import scripts.check_artifacts as artifact_checker

VALID_UUID = "3c891e44-59bb-41a2-8921-18274acb9011"
SIGMA_OK = """title: t
id: 3c891e44-59bb-41a2-8921-18274acb9011
status: test
description: d
logsource: {product: windows}
detection:
  selection: {Image: x}
  condition: selection
level: low
"""


@pytest.fixture(scope="module")
def iocs() -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Load the repository IOC artifacts (JSON source of truth + CSV rows)."""
    return artifact_checker.load_iocs(artifact_checker.ROOT)


@pytest.fixture(scope="module")
def stix_bundle() -> dict[str, Any]:
    """Load the repository STIX bundle."""
    path = artifact_checker.ROOT / "threat-intel" / "stix_bundle.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scanner() -> yara_x.Scanner:
    """Compile the repository YARA rule once per test module."""
    source = (artifact_checker.ROOT / "rules" / "crxlauncher.yar").read_text(
        encoding="utf-8"
    )
    return yara_x.Scanner(artifact_checker.compile_yara(source))


class TestIocValidation:
    """Validation of the IOC data structures."""

    def test_valid_values_produce_no_errors(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """Well-formed domains, IPs and extension ids yield no error."""
        data, _rows = iocs
        assert artifact_checker.check_ioc_values(data) == []
        assert artifact_checker.check_extension_id(data) == []

    @pytest.mark.parametrize(
        ("domain", "should_be_valid"),
        [
            ("NON VALIDO", False),
            ("bad domain", False),
            ("esempio.com", True),
            ("sub.example.co.uk", True),
        ],
    )
    def test_domain_validation(self, domain: str, should_be_valid: bool) -> None:
        """Domain validation accepts valid hostnames and rejects malformed ones."""
        assert artifact_checker.is_valid_domain(domain) is should_be_valid

    @pytest.mark.parametrize(
        ("ip_address", "should_be_valid"),
        [
            ("999.1.1.1", False),
            ("192.0.2.1", True),
            ("not-an-ip", False),
            ("2001:db8::1", True),
        ],
    )
    def test_ip_validation(self, ip_address: str, should_be_valid: bool) -> None:
        """IP validation accepts parseable addresses and rejects garbage."""
        assert artifact_checker.is_valid_ip_address(ip_address) is should_be_valid

    @pytest.mark.parametrize(
        ("extension_id", "should_be_valid"),
        [
            ("a" * 32, True),
            ("xyz", False),
            ("A" * 32, False),
        ],
    )
    def test_extension_id_validation(
        self, extension_id: str, should_be_valid: bool
    ) -> None:
        """Extension ids must be 32 lowercase ``[a-p]`` characters."""
        assert artifact_checker.is_valid_extension_id(extension_id) is should_be_valid


class TestChecker:
    """Cross-file IOC consistency checks."""

    def test_csv_extra_row_is_detected(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """A CSV row missing from the JSON source of truth is reported."""
        data, rows = iocs
        rows = rows + [
            {
                "Type": "Domain",
                "Value": "esempio.invalid",
                "Description": "",
                "Severity": "",
            },
        ]
        assert artifact_checker.check_iocs(data, rows)

    def test_consistent_iocs_are_valid(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """The shipped IOC set must be internally consistent."""
        assert artifact_checker.check_iocs(*iocs) == []


class TestStix:
    """STIX bundle validation."""

    def test_inconsistent_id_is_detected(self) -> None:
        """STIX ids must start with the object type and hold a valid UUID."""
        errors = artifact_checker.check_stix_id(
            {"type": "malware", "id": "tool--" + VALID_UUID}
        )
        assert len(errors) == 1

    def test_invalid_uuid_is_detected(self) -> None:
        """Malformed STIX UUIDs are reported."""
        errors = artifact_checker.check_stix_id(
            {"type": "malware", "id": "malware--nope"}
        )
        assert errors and "UUID non valido" in errors[0]

    def test_incomplete_bundle_is_detected(self) -> None:
        """Bundles with wrong type or incomplete indicators are reported."""
        indicator = {
            "type": "indicator",
            "id": f"indicator--{VALID_UUID}",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
        }
        errors = artifact_checker.check_stix({"type": "altro", "objects": [indicator]})
        assert errors == [
            "STIX: type deve essere 'bundle'",
            f"STIX: indicator incompleto indicator--{VALID_UUID}",
        ]
        incomplete = {k: v for k, v in indicator.items() if k != "pattern"}
        assert artifact_checker.check_stix_object(incomplete)


class TestSigma:
    """Sigma rule validation."""

    def check(self, text: str, tmp_path: Path) -> list[str]:
        """Write a temporary Sigma rule and validate it."""
        path = tmp_path / "rule.yml"
        path.write_text(text, encoding="utf-8")
        return artifact_checker.check_sigma(path)

    def test_valid_rule_has_no_errors(self, tmp_path: Path) -> None:
        """The minimal complete Sigma rule passes validation."""
        assert self.check(SIGMA_OK, tmp_path) == []

    def test_invalid_id_and_condition(self, tmp_path: Path) -> None:
        """Invalid UUID ids and conditions without selections are reported."""
        text = SIGMA_OK.replace(VALID_UUID, "non-uuid").replace(
            "condition: selection", "condition: altro"
        )
        errors = self.check(text, tmp_path)
        assert len(errors) == 2

    def test_missing_keys_are_reported(self, tmp_path: Path) -> None:
        """Missing mandatory keys are reported."""
        errors = self.check("title: t\n", tmp_path)
        assert any("chiavi mancanti" in error for error in errors)

    def test_non_mapping_document_is_reported(self, tmp_path: Path) -> None:
        """Documents that are not mappings produce a validation error."""
        assert self.check("", tmp_path)
        assert self.check("- a\n", tmp_path)
        assert self.check("detection: [a]\n", tmp_path)


class TestYara:
    """YARA rule compilation and scanning."""

    def test_harmless_text_does_not_match(self, scanner: yara_x.Scanner) -> None:
        """Ordinary console output must not trigger any rule."""
        assert list(scanner.scan(b"console.log('hello world');").matching_rules) == []

    def test_synthetic_strings_match(self, scanner: yara_x.Scanner) -> None:
        """The three synthetic marker strings trigger the dropper rule."""
        data = (
            b"__crxlauncher_window_communication "
            b"__crxlauncher_runtime_message__ pre_cl_loglevel__v3"
        )
        assert [match.identifier for match in scanner.scan(data).matching_rules] == [
            "ChromeExt_CRXLauncher_Dropper"
        ]

    def test_single_string_is_not_enough(self, scanner: yara_x.Scanner) -> None:
        """A single marker fragment must not trigger the rule."""
        assert (
            list(scanner.scan(b"__crxlauncher_window_communication").matching_rules)
            == []
        )


class TestMain:
    """End-to-end entry point of the validator."""

    def test_main_returns_zero_for_valid_repo(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The shipped artifact set must validate cleanly."""
        caplog.set_level(logging.INFO)
        assert artifact_checker.main() == 0
        assert "OK" in caplog.text

    def test_main_returns_one_for_broken_yara(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A YARA compile failure must produce a failing exit code."""

        def broken(source: str) -> yara_x.Pattern:
            raise yara_x.CompileError("boom")

        monkeypatch.setattr(artifact_checker, "compile_yara", broken)
        assert artifact_checker.main() == 1
