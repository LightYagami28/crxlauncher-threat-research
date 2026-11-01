"""Validazione statica degli artefatti del repo (IOC, STIX, Sigma, YARA).

Legge solo file di testo del repo come dati: non esegue nulla di ciò che contengono.
Uso: python scripts/check_artifacts.py   (exit 1 se ci sono errori)
"""
import csv
import ipaddress
import json
import re
import sys
import uuid
from pathlib import Path

import yaml
import yara_x

ROOT = Path(__file__).resolve().parent.parent
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")
EXT_ID_RE = re.compile(r"^[a-p]{32}$")
SIGMA_KEYS = {"title", "id", "status", "description", "logsource", "detection", "level"}


def load_iocs(root=ROOT):
    """Carica iocs.json e iocs.csv."""
    data = json.loads((root / "threat-intel/iocs.json").read_text(encoding="utf-8"))
    with (root / "threat-intel/iocs.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return data, rows


def _bad_ip(ip):
    """True se la stringa non è un indirizzo IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return True
    return False


def check_ioc_values(data):
    """Valida formato di extension_id, domini e IP."""
    errs = [f"dominio non valido: {d}" for d in data.get("domains", []) if not DOMAIN_RE.match(d)]
    errs += [f"IP non valido: {ip}" for ip in data.get("ip_addresses", []) if _bad_ip(ip)]
    return errs + check_extension_id(data)


def check_extension_id(data):
    """Valida l'ID dell'estensione."""
    if EXT_ID_RE.match(data.get("extension_id", "")):
        return []
    return ["extension_id non valido (32 caratteri a-p)"]


def check_csv_rows(data, rows):
    """Ogni riga CSV deve comparire nel JSON (il JSON è la fonte più completa)."""
    json_values = {
        "Extension ID": {data.get("extension_id")},
        "Domain": set(data.get("domains", [])),
        "IP Address": set(data.get("ip_addresses", [])),
        "GA4 ID": {data.get("telemetry", {}).get("measurement_id")},
        "Storage Key": set(data.get("storage_keys", [])),
        "Namespace": set(data.get("window_message_namespaces", [])),
    }
    errs = []
    for r in rows:
        known = json_values.get(r["Type"])
        if known is None:
            errs.append(f"tipo CSV sconosciuto: {r['Type']}")
        elif r["Value"] not in known:
            errs.append(f"CSV non presente nel JSON: {r['Type']} {r['Value']}")
    return errs


def check_iocs(data, rows):
    """Valida gli IOC e la coerenza CSV/JSON."""
    return check_ioc_values(data) + check_csv_rows(data, rows)


def check_stix_id(o):
    """Valida id e UUID di un oggetto STIX."""
    t = o.get("type", "?")
    if not str(o.get("id", "")).startswith(t + "--"):
        return [f"STIX: id incoerente con il tipo ({t})"]
    try:
        uuid.UUID(o["id"].split("--", 1)[1])
    except ValueError:
        return [f"STIX: UUID non valido in {o['id']}"]
    return []


def check_stix_fields(o):
    """Valida versione e campi obbligatori di un oggetto STIX."""
    errs = []
    if o.get("spec_version") != "2.1":
        errs.append(f"STIX: spec_version mancante in {o.get('id')}")
    errs += [f"STIX: campo obbligatorio '{k}' mancante in {o.get('id')}"
             for k in ("created", "modified") if k not in o]
    return errs


def check_stix_object(o):
    """Valida un singolo oggetto STIX."""
    errs = check_stix_id(o) + check_stix_fields(o)
    if o.get("type") == "indicator" and not {"pattern", "pattern_type", "valid_from"} <= o.keys():
        errs.append(f"STIX: indicator incompleto {o.get('id')}")
    return errs


def check_stix(bundle):
    """Valida il bundle STIX 2.1."""
    errs = []
    if bundle.get("type") != "bundle":
        errs.append("STIX: type deve essere 'bundle'")
    for o in bundle.get("objects", []):
        errs += check_stix_object(o)
    return errs


def _sigma_id_ok(doc):
    """True se l'id della regola Sigma è un UUID."""
    try:
        uuid.UUID(str(doc.get("id")))
    except ValueError:
        return False
    return True


def check_sigma(path):
    """Valida una regola Sigma."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    det = doc.get("detection", {})
    cond = det.get("condition")
    checks = [
        (SIGMA_KEYS - set(doc), f"{path.name}: chiavi mancanti {sorted(SIGMA_KEYS - set(doc))}"),
        (not _sigma_id_ok(doc), f"{path.name}: id non è un UUID"),
        (not cond or not any(n in cond for n in set(det) - {"condition"}),
         f"{path.name}: condition non referenzia alcuna selection"),
    ]
    return [msg for bad, msg in checks if bad]


def compile_yara(root=ROOT):
    """Compila la regola YARA del repo."""
    return yara_x.compile((root / "rules/crxlauncher.yar").read_text(encoding="utf-8"))


def collect_errors():
    """Raccoglie gli errori di tutte le validazioni."""
    errs = check_iocs(*load_iocs())
    stix = ROOT / "threat-intel/stix_bundle.json"
    errs += check_stix(json.loads(stix.read_text(encoding="utf-8")))
    for p in sorted((ROOT / "rules").glob("*.yml")):
        errs += check_sigma(p)
    try:
        compile_yara()
    except yara_x.CompileError as e:
        errs.append(f"YARA non compila: {e}")
    return errs


def main():
    """Esegue tutte le validazioni; restituisce il codice di uscita."""
    errs = collect_errors()
    for e in errs:
        print("ERRORE:", e)
    print("OK" if not errs else f"{len(errs)} errori")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
