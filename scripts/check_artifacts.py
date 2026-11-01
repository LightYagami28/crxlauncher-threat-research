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


def check_iocs(data, rows):
    """Valida gli IOC e la coerenza CSV/JSON."""
    errs = []
    if not EXT_ID_RE.match(data.get("extension_id", "")):
        errs.append("extension_id non valido (32 caratteri a-p)")
    for d in data.get("domains", []):
        if not DOMAIN_RE.match(d):
            errs.append(f"dominio non valido: {d}")
    for ip in data.get("ip_addresses", []):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            errs.append(f"IP non valido: {ip}")
    # ogni riga CSV deve comparire nel JSON (il JSON è la fonte più completa)
    json_values = {
        "Extension ID": {data.get("extension_id")},
        "Domain": set(data.get("domains", [])),
        "IP Address": set(data.get("ip_addresses", [])),
        "GA4 ID": {data.get("telemetry", {}).get("measurement_id")},
        "Storage Key": set(data.get("storage_keys", [])),
        "Namespace": set(data.get("window_message_namespaces", [])),
    }
    for r in rows:
        known = json_values.get(r["Type"])
        if known is None:
            errs.append(f"tipo CSV sconosciuto: {r['Type']}")
        elif r["Value"] not in known:
            errs.append(f"CSV non presente nel JSON: {r['Type']} {r['Value']}")
    return errs


def check_stix_object(o):
    """Valida un singolo oggetto STIX."""
    errs = []
    t = o.get("type", "?")
    if not str(o.get("id", "")).startswith(t + "--"):
        errs.append(f"STIX: id incoerente con il tipo ({t})")
    else:
        try:
            uuid.UUID(o["id"].split("--", 1)[1])
        except ValueError:
            errs.append(f"STIX: UUID non valido in {o['id']}")
    if o.get("spec_version") != "2.1":
        errs.append(f"STIX: spec_version mancante in {o.get('id')}")
    for k in ("created", "modified"):
        if k not in o:
            errs.append(f"STIX: campo obbligatorio '{k}' mancante in {o.get('id')}")
    if t == "indicator" and not {"pattern", "pattern_type", "valid_from"} <= o.keys():
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


def check_sigma(path):
    """Valida una regola Sigma."""
    errs = []
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = SIGMA_KEYS - set(doc)
    if missing:
        errs.append(f"{path.name}: chiavi mancanti {sorted(missing)}")
    try:
        uuid.UUID(str(doc.get("id")))
    except ValueError:
        errs.append(f"{path.name}: id non è un UUID")
    cond = doc.get("detection", {}).get("condition")
    names = set(doc.get("detection", {})) - {"condition"}
    if not cond or not any(n in cond for n in names):
        errs.append(f"{path.name}: condition non referenzia alcuna selection")
    return errs


def compile_yara(root=ROOT):
    """Compila la regola YARA del repo."""
    return yara_x.compile((root / "rules/crxlauncher.yar").read_text(encoding="utf-8"))


def main():
    """Esegue tutte le validazioni; restituisce il codice di uscita."""
    errs = check_iocs(*load_iocs())
    stix = ROOT / "threat-intel/stix_bundle.json"
    errs += check_stix(json.loads(stix.read_text(encoding="utf-8")))
    for p in sorted((ROOT / "rules").glob("*.yml")):
        errs += check_sigma(p)
    try:
        compile_yara()
    except yara_x.CompileError as e:
        errs.append(f"YARA non compila: {e}")
    for e in errs:
        print("ERRORE:", e)
    print("OK" if not errs else f"{len(errs)} errori")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
