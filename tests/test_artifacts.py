"""Test su dati innocui: stringhe sintetiche, nessun campione reale e nessuna esecuzione."""
import importlib.util
import json
import unittest
from pathlib import Path

import yara_x

_SPEC = importlib.util.spec_from_file_location(
    "check_artifacts", Path(__file__).resolve().parent.parent / "scripts/check_artifacts.py")
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("check_artifacts non caricabile")
ca = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ca)


class RepoArtifacts(unittest.TestCase):
    """Gruppo RepoArtifacts."""

    def test_iocs_coerenti(self):
        """Test iocs coerenti."""
        self.assertEqual(ca.check_iocs(*ca.load_iocs()), [])

    def test_stix_valido(self):
        """Test stix valido."""
        stix = ca.ROOT / "threat-intel/stix_bundle.json"
        b = json.loads(stix.read_text(encoding="utf-8"))
        self.assertEqual(ca.check_stix(b), [])

    def test_sigma_validi(self):
        """Test sigma validi."""
        for p in (ca.ROOT / "rules").glob("*.yml"):
            self.assertEqual(ca.check_sigma(p), [], p.name)


class Checker(unittest.TestCase):
    """Gruppo Checker."""

    def test_csv_non_nel_json_viene_rilevato(self):
        """Test csv non nel json viene rilevato."""
        data, rows = ca.load_iocs()
        extra = {"Type": "Domain", "Value": "esempio.invalid", "Description": "", "Severity": ""}
        rows = rows + [extra]
        self.assertTrue(ca.check_iocs(data, rows))

    def test_stix_senza_created_viene_rilevato(self):
        """Test stix senza created viene rilevato."""
        bundle = {"type": "bundle", "objects": [{"type": "malware", "spec_version": "2.1",
                  "id": "malware--3c891e44-59bb-41a2-8921-18274acb9011"}]}
        self.assertTrue(ca.check_stix(bundle))


class YaraRule(unittest.TestCase):
    """Gruppo YaraRule."""

    @classmethod
    def setUpClass(cls):
        """Setupclass."""
        cls.scanner = yara_x.Scanner(ca.compile_yara())

    def hits(self, data):
        """Hits."""
        return [m.identifier for m in self.scanner.scan(data).matching_rules]

    def test_testo_innocuo_non_corrisponde(self):
        """Test testo innocuo non corrisponde."""
        self.assertEqual(self.hits(b"console.log('hello world');"), [])

    def test_tre_stringhe_sintetiche_corrispondono(self):
        """Test tre stringhe sintetiche corrispondono."""
        data = (b"__crxlauncher_window_communication "
                b"__crxlauncher_runtime_message__ pre_cl_loglevel__v3")
        self.assertEqual(self.hits(data), ["ChromeExt_CRXLauncher_Dropper"])

    def test_una_sola_stringa_non_basta(self):
        """Test una sola stringa non basta."""
        self.assertEqual(self.hits(b"__crxlauncher_window_communication"), [])


if __name__ == "__main__":
    unittest.main()
