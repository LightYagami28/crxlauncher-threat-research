"""Test su dati innocui: stringhe sintetiche, nessun campione reale e nessuna esecuzione."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_artifacts as ca  # noqa: E402


class RepoArtifacts(unittest.TestCase):
    def test_iocs_coerenti(self):
        self.assertEqual(ca.check_iocs(*ca.load_iocs()), [])

    def test_stix_valido(self):
        b = json.loads((ca.ROOT / "threat-intel/stix_bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(ca.check_stix(b), [])

    def test_sigma_validi(self):
        for p in (ca.ROOT / "rules").glob("*.yml"):
            self.assertEqual(ca.check_sigma(p), [], p.name)


class Checker(unittest.TestCase):
    def test_csv_non_nel_json_viene_rilevato(self):
        data, rows = ca.load_iocs()
        rows = rows + [{"Type": "Domain", "Value": "esempio.invalid", "Description": "", "Severity": ""}]
        self.assertTrue(ca.check_iocs(data, rows))

    def test_stix_senza_created_viene_rilevato(self):
        bundle = {"type": "bundle", "objects": [{"type": "malware", "spec_version": "2.1",
                  "id": "malware--3c891e44-59bb-41a2-8921-18274acb9011"}]}
        self.assertTrue(ca.check_stix(bundle))


class YaraRule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yara_x
        cls.scanner = yara_x.Scanner(ca.compile_yara())

    def hits(self, data):
        return [m.identifier for m in self.scanner.scan(data).matching_rules]

    def test_testo_innocuo_non_corrisponde(self):
        self.assertEqual(self.hits(b"console.log('hello world');"), [])

    def test_tre_stringhe_sintetiche_corrispondono(self):
        data = b"__crxlauncher_window_communication __crxlauncher_runtime_message__ pre_cl_loglevel__v3"
        self.assertEqual(self.hits(data), ["ChromeExt_CRXLauncher_Dropper"])

    def test_una_sola_stringa_non_basta(self):
        self.assertEqual(self.hits(b"__crxlauncher_window_communication"), [])


if __name__ == "__main__":
    unittest.main()
