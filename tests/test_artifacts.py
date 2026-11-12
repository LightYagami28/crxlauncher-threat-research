"""Test su dati innocui: stringhe sintetiche, nessun campione reale e nessuna esecuzione."""
import importlib.util
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yara_x  # pyright: ignore[reportMissingImports]  # installato da requirements.txt

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


class IocValues(unittest.TestCase):
    """Valori IOC malformati."""

    def test_dominio_ip_e_id_non_validi(self):
        """Dominio, IP ed extension_id malformati vengono segnalati."""
        data = {"domains": ["NON VALIDO"], "ip_addresses": ["999.1.1.1"],
                "extension_id": "xyz"}
        errs = ca.check_ioc_values(data)
        self.assertEqual(len(errs), 3, errs)

    def test_valori_validi(self):
        """Valori ben formati non generano errori."""
        data = {"domains": ["esempio.invalid"], "ip_addresses": ["192.0.2.1"],
                "extension_id": "a" * 32}
        self.assertEqual(ca.check_ioc_values(data), [])

    def test_tipo_csv_sconosciuto(self):
        """Un tipo CSV non previsto viene segnalato."""
        errs = ca.check_csv_rows({}, [{"Type": "Boh", "Value": "x"}])
        self.assertEqual(errs, ["tipo CSV sconosciuto: Boh"])


class StixObjects(unittest.TestCase):
    """Oggetti STIX malformati."""

    def test_id_incoerente(self):
        """Un id che non inizia col tipo viene segnalato."""
        errs = ca.check_stix_id({"type": "malware", "id": "tool--" + VALID_UUID})
        self.assertEqual(len(errs), 1)

    def test_uuid_non_valido(self):
        """Un UUID malformato viene segnalato."""
        errs = ca.check_stix_id({"type": "malware", "id": "malware--nope"})
        self.assertIn("UUID non valido", errs[0])

    def test_bundle_e_indicator_incompleti(self):
        """Tipo bundle errato e indicator senza pattern vengono segnalati."""
        obj = {"type": "indicator", "id": "indicator--" + VALID_UUID,
               "spec_version": "2.1", "created": "x", "modified": "x"}
        errs = ca.check_stix({"type": "altro", "objects": [obj]})
        self.assertEqual(len(errs), 2, errs)

    def test_spec_version_mancante(self):
        """Senza spec_version 2.1 l'oggetto viene segnalato."""
        errs = ca.check_stix_fields({"id": "x", "created": "x", "modified": "x"})
        self.assertEqual(len(errs), 1)


class SigmaRules(unittest.TestCase):
    """Regole Sigma sintetiche scritte in una cartella temporanea."""

    def check(self, text):
        """Scrive la regola e restituisce gli errori."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "r.yml"
            path.write_text(text, encoding="utf-8")
            return ca.check_sigma(path)

    def test_regola_valida(self):
        """La regola minima completa passa."""
        self.assertEqual(self.check(SIGMA_OK), [])

    def test_id_e_condition_errati(self):
        """Id non UUID e condition senza selection vengono segnalati."""
        text = SIGMA_OK.replace(VALID_UUID, "non-uuid").replace(
            "condition: selection", "condition: altro")
        self.assertEqual(len(self.check(text)), 2)

    def test_chiavi_mancanti(self):
        """Le chiavi obbligatorie assenti vengono segnalate."""
        errs = self.check("title: t\n")
        self.assertTrue(any("chiavi mancanti" in e for e in errs), errs)

    def test_file_non_mappa(self):
        """Un file vuoto o una lista non fanno crashare il controllo."""
        self.assertEqual(len(self.check("")), 1)
        self.assertEqual(len(self.check("- a\n")), 1)
        self.assertEqual(len(self.check("detection: [a]\n")), 1)


class Main(unittest.TestCase):
    """Esecuzione completa del validatore."""

    def test_main_ok(self):
        """Sul repo il validatore esce con 0 e stampa OK."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ca.main(), 0)
        self.assertIn("OK", out.getvalue())

    def test_main_con_errori(self):
        """Un errore di compilazione YARA porta a uscita 1."""
        def broken():
            return yara_x.compile("rule x { condition: nonesiste }")

        out = io.StringIO()
        with mock.patch.object(ca, "compile_yara", broken), contextlib.redirect_stdout(out):
            self.assertEqual(ca.main(), 1)
        self.assertIn("YARA non compila", out.getvalue())


if __name__ == "__main__":
    unittest.main()
