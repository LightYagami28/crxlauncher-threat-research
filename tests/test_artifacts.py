"""Test della validazione statica degli artefatti di threat intelligence."""

from __future__ import annotations

import json
import logging
import time
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


def verify(condition: object, message: str = "condizione non soddisfatta") -> None:
    """Segnala un fallimento esplicito senza usare ``assert`` nei test."""
    if not condition:
        pytest.fail(message)


@pytest.fixture(scope="module")
def iocs() -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Carica la fonte di verità JSON e le righe CSV degli IOC."""
    return artifact_checker.load_iocs(artifact_checker.ROOT)


@pytest.fixture(scope="module")
def stix_bundle() -> dict[str, Any]:
    """Carica il bundle STIX presente nel repository."""
    path = artifact_checker.ROOT / "threat-intel" / "stix_bundle.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scanner() -> yara_x.Scanner:
    """Compila una volta la regola YARA del repository."""
    source = (artifact_checker.ROOT / "rules" / "crxlauncher.yar").read_text(encoding="utf-8")
    return yara_x.Scanner(artifact_checker.compile_yara(source))


class TestIocValidation:
    """Validazione della struttura degli IOC."""

    def test_valid_values_produce_no_errors(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """Dominio, IP e ID estensione ben formati non producono errori."""
        data, _rows = iocs
        verify(artifact_checker.check_ioc_values(data) == [])
        verify(artifact_checker.check_extension_id(data) == [])

    @pytest.mark.parametrize(
        ("domain", "should_be_valid"),
        [
            ("NON VALIDO", False),
            ("bad domain", False),
            ("esempio.com", True),
            ("sub.example.co.uk", True),
            ("", False),
            ("a" * 254, False),
            ("a." * 130, False),
            ("a" * 64 + ".com", False),
            ("a_1.example.com", False),
            ("sub..example.com", False),
            ("sub.example.c", False),
            ("sub.example.c0m", False),
        ],
    )
    def test_domain_validation(self, domain: str, should_be_valid: bool) -> None:
        """La validazione accetta host validi e respinge quelli malformati."""
        verify(artifact_checker.is_valid_domain(domain) is should_be_valid)

    def test_domain_validation_is_linear_on_pathological_input(self) -> None:
        """Input patologico (etichette ripetute + suffisso non valido): tempo lineare."""

        def elapsed(labels: int, repeats: int = 200) -> float:
            candidate = "a." * labels + "!"
            start = time.perf_counter()
            for _ in range(repeats):
                verify(artifact_checker.is_valid_domain(candidate) is False)
            return time.perf_counter() - start

        # 121 e 241 caratteri: entrambi entro il limite di 253, il secondo
        # ha il doppio delle etichette. Un motore con backtracking crescerebbe
        # molto piu che linearmente (o esploderebbe); qui il rapporto resta
        # vicino a 2, con un tetto assoluto generoso contro errori di timing.
        small = elapsed(60)
        large = elapsed(120)
        verify(large < 1.0)
        verify(large < small * 10)

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
        """La validazione accetta indirizzi IP validi e respinge il resto."""
        verify(artifact_checker.is_valid_ip_address(ip_address) is should_be_valid)

    @pytest.mark.parametrize(
        ("extension_id", "should_be_valid"),
        [
            ("a" * 32, True),
            ("xyz", False),
            ("A" * 32, False),
        ],
    )
    def test_extension_id_validation(self, extension_id: str, should_be_valid: bool) -> None:
        """L'ID estensione deve avere 32 caratteri ``[a-p]`` minuscoli."""
        verify(artifact_checker.is_valid_extension_id(extension_id) is should_be_valid)


class TestChecker:
    """Coerenza degli IOC tra i file."""

    def test_csv_extra_row_is_detected(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """Una riga CSV assente dalla fonte JSON viene segnalata."""
        data, rows = iocs
        rows = [
            *rows,
            {
                "Type": "Domain",
                "Value": "esempio.invalid",
                "Description": "",
                "Severity": "",
            },
        ]
        verify(artifact_checker.check_iocs(data, rows))

    def test_consistent_iocs_are_valid(
        self, iocs: tuple[dict[str, Any], list[dict[str, str]]]
    ) -> None:
        """Gli IOC presenti nel repository sono coerenti."""
        verify(artifact_checker.check_iocs(*iocs) == [])


class TestStix:
    """Validazione del bundle STIX."""

    def test_inconsistent_id_is_detected(self) -> None:
        """L'ID STIX deve iniziare col tipo e contenere un UUID valido."""
        errors = artifact_checker.check_stix_id({"type": "malware", "id": "tool--" + VALID_UUID})
        verify(len(errors) == 1)

    def test_invalid_uuid_is_detected(self) -> None:
        """Gli UUID STIX malformati vengono segnalati."""
        errors = artifact_checker.check_stix_id({"type": "malware", "id": "malware--nope"})
        verify(errors and "UUID non valido" in errors[0])

    def test_incomplete_bundle_is_detected(self) -> None:
        """Bundle col tipo sbagliato o indicatori incompleti vengono segnalati."""
        indicator = {
            "type": "indicator",
            "id": f"indicator--{VALID_UUID}",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
        }
        errors = artifact_checker.check_stix({"type": "altro", "objects": [indicator]})
        verify(
            errors
            == [
                "STIX: type deve essere 'bundle'",
                f"STIX: indicator incompleto indicator--{VALID_UUID}",
            ]
        )
        incomplete = {key: value for key, value in indicator.items() if key != "pattern"}
        verify(artifact_checker.check_stix_object(incomplete))


class TestSigma:
    """Validazione delle regole Sigma."""

    def check(self, text: str, tmp_path: Path) -> list[str]:
        """Scrive una regola Sigma temporanea e la valida."""
        path = tmp_path / "rule.yml"
        path.write_text(text, encoding="utf-8")
        return artifact_checker.check_sigma(path)

    def test_valid_rule_has_no_errors(self, tmp_path: Path) -> None:
        """La regola Sigma completa supera la validazione."""
        verify(self.check(SIGMA_OK, tmp_path) == [])

    def test_invalid_id_and_condition(self, tmp_path: Path) -> None:
        """UUID non valido e condizione senza selection vengono segnalati."""
        text = SIGMA_OK.replace(VALID_UUID, "non-uuid").replace(
            "condition: selection", "condition: altro"
        )
        errors = self.check(text, tmp_path)
        verify(len(errors) == 2)

    def test_missing_keys_are_reported(self, tmp_path: Path) -> None:
        """Le chiavi obbligatorie mancanti vengono segnalate."""
        errors = self.check("title: t\n", tmp_path)
        verify(any("chiavi mancanti" in error for error in errors))

    def test_non_mapping_document_is_reported(self, tmp_path: Path) -> None:
        """I documenti che non sono mapping producono un errore."""
        verify(self.check("", tmp_path))
        verify(self.check("- a\n", tmp_path))
        verify(self.check("detection: [a]\n", tmp_path))


class TestYara:
    """Compilazione e scansione della regola YARA."""

    def test_harmless_text_does_not_match(self, scanner: yara_x.Scanner) -> None:
        """L'output ordinario non deve attivare alcuna regola."""
        verify(list(scanner.scan(b"console.log('hello world');").matching_rules) == [])

    def test_synthetic_strings_match(self, scanner: yara_x.Scanner) -> None:
        """Le tre stringhe sintetiche attivano la regola dropper."""
        data = (
            b"__crxlauncher_window_communication "
            b"__crxlauncher_runtime_message__ pre_cl_loglevel__v3"
        )
        verify(
            [match.identifier for match in scanner.scan(data).matching_rules]
            == ["ChromeExt_CRXLauncher_Dropper"]
        )

    def test_single_string_is_not_enough(self, scanner: yara_x.Scanner) -> None:
        """Una singola stringa sintetica non attiva la regola."""
        verify(list(scanner.scan(b"__crxlauncher_window_communication").matching_rules) == [])


class TestMain:
    """Punto di ingresso end-to-end del validatore."""

    def test_main_returns_zero_for_valid_repo(self, caplog: pytest.LogCaptureFixture) -> None:
        """L'insieme di artefatti distribuito supera la validazione."""
        caplog.set_level(logging.INFO)
        verify(artifact_checker.main() == 0)
        verify("OK" in caplog.text)

    def test_main_returns_one_for_broken_yara(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Un errore di compilazione YARA produce un codice di uscita fallente."""

        def broken(source: str) -> yara_x.Rules:
            raise yara_x.CompileError("boom")

        monkeypatch.setattr(artifact_checker, "compile_yara", broken)
        verify(artifact_checker.main() == 1)
