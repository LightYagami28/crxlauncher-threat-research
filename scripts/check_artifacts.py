"""Static validation of the CRXLauncher threat-intelligence artifacts.

The checker consumes only the plain-text artifacts stored in the repository
(``threat-intel/iocs.json``, ``threat-intel/iocs.csv``,
``threat-intel/stix_bundle.json``, ``rules/*.yml`` and ``rules/*.yar``).
It validates identifier shapes, value formats and cross-file consistency.
It never executes or interprets the content it inspects.

Command-line interface::

    python scripts/check_artifacts.py
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any, Final

import yaml
import yara_x

logger = logging.getLogger(__name__)

ROOT: Final[Path] = Path(__file__).resolve().parent.parent

# I domini sono validati con splitting e controlli lineari sulle singole
# etichette: il vecchio motivo annidato ([a-z0-9-]{1,63}\.)+ poteva
# innescare backtracking. Nessuna regex con quantificatori annidati.
DOMAIN_LABEL_CHARS: Final[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
DOMAIN_MAX_LENGTH: Final[int] = 253
DOMAIN_LABEL_MAX_LENGTH: Final[int] = 63
DOMAIN_TLD_MIN_LENGTH: Final[int] = 2
EXTENSION_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-p]{32}$")
STIX_SPEC_VERSION: Final[str] = "2.1"
STIX_BUNDLE_TYPE: Final[str] = "bundle"
SIGMA_REQUIRED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "title",
        "id",
        "status",
        "description",
        "logsource",
        "detection",
        "level",
    }
)

type IOCData = dict[str, Any]
type CSVRow = dict[str, str]
type STIXObject = dict[str, Any]
type SigmaRuleDocument = dict[str, Any]


def is_valid_domain(domain: str) -> bool:
    """Return ``True`` when *domain* is a syntactically valid hostname.

    The check walks the string once (``split`` plus per-label membership
    tests), so its cost is linear in the input length and no backtracking is
    possible. A hostname has one or more labels of 1-63 characters from
    ``[a-z0-9-]`` followed by a lowercase alphabetic TLD of at least two
    characters; the total length is capped at 253 characters.

    Args:
        domain: Candidate domain name to validate.

    Returns:
        ``True`` if the domain matches the DNS hostname grammar.
    """
    if not 1 <= len(domain) <= DOMAIN_MAX_LENGTH:
        return False
    parts = domain.split(".")
    if len(parts) < DOMAIN_TLD_MIN_LENGTH:
        return False
    for label in parts[:-1]:
        if not 1 <= len(label) <= DOMAIN_LABEL_MAX_LENGTH:
            return False
        if any(char not in DOMAIN_LABEL_CHARS for char in label):
            return False
    tld = parts[-1]
    return len(tld) >= DOMAIN_TLD_MIN_LENGTH and all("a" <= char <= "z" for char in tld)


def is_valid_ip_address(value: str) -> bool:
    """Return ``True`` when *value* is a parseable IPv4 or IPv6 address.

    Args:
        value: Candidate IP address expressed as a string.

    Returns:
        ``True`` when :func:`ipaddress.ip_address` accepts the value.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_valid_extension_id(extension_id: str) -> bool:
    """Return ``True`` when *extension_id* has the CRX extension shape.

    Args:
        extension_id: Candidate extension identifier.

    Returns:
        ``True`` when the identifier matches the lowercase ``[a-p]{32}`` pattern.
    """
    return bool(EXTENSION_ID_RE.match(extension_id))


def check_ioc_values(data: IOCData) -> list[str]:
    """Validate the IOC fields of a threat-intelligence entry.

    Args:
        data: Parsed content of ``threat-intel/iocs.json``.

    Returns:
        List of human-readable validation error messages (empty when valid).
    """
    errors: list[str] = [
        f"dominio non valido: {domain}"
        for domain in data.get("domains") or []
        if not is_valid_domain(str(domain))
    ]
    errors.extend(
        f"IP non valido: {ip_address}"
        for ip_address in data.get("ip_addresses") or []
        if not is_valid_ip_address(str(ip_address))
    )
    errors.extend(
        f"extension_id non valido: {extension_id}"
        for extension_id in [str(data.get("extension_id") or "")]
        if not is_valid_extension_id(extension_id)
    )
    return errors


def check_extension_id(data: IOCData) -> list[str]:
    """Validate the raw extension identifier field.

    Args:
        data: Parsed content of ``threat-intel/iocs.json``.

    Returns:
        List of validation error messages (empty when valid).
    """
    extension_id = str(data.get("extension_id") or "")
    if is_valid_extension_id(extension_id):
        return []
    return [f"extension_id non valido (32 caratteri a-p): {extension_id}"]


def check_csv_rows(data: IOCData, rows: list[CSVRow]) -> list[str]:
    """Check that every CSV IOC row is covered by the JSON source of truth.

    Args:
        data: Parsed content of ``threat-intel/iocs.json``.
        rows: Rows read from ``threat-intel/iocs.csv``.

    Returns:
        List of validation error messages (empty when consistent).
    """
    json_values: dict[str, set[str]] = {
        "Extension ID": {str(data.get("extension_id") or "")},
        "Domain": {str(domain) for domain in data.get("domains") or []},
        "IP Address": {str(ip_address) for ip_address in data.get("ip_addresses") or []},
        "GA4 ID": {str((data.get("telemetry") or {}).get("measurement_id") or "")},
        "Storage Key": {str(key) for key in data.get("storage_keys") or []},
        "Namespace": {str(namespace) for namespace in data.get("window_message_namespaces") or []},
    }
    errors: list[str] = []
    for row in rows:
        row_type = row.get("Type")
        known = json_values.get(row_type) if row_type is not None else None
        if known is None:
            errors.append(f"tipo CSV sconosciuto: {row_type}")
            continue
        if str(row.get("Value") or "") not in known:
            errors.append(f"CSV non presente nel JSON: {row_type} {row.get('Value')}")
    return errors


def check_iocs(data: IOCData, rows: list[CSVRow]) -> list[str]:
    """Validate IOC values and CSV/JSON consistency.

    Args:
        data: Parsed content of ``threat-intel/iocs.json``.
        rows: Rows read from ``threat-intel/iocs.csv``.

    Returns:
        List of validation error messages (empty when valid).
    """
    return check_ioc_values(data) + check_csv_rows(data, rows)


def check_stix_id(obj: STIXObject) -> list[str]:
    """Validate the ``id`` field of a STIX object.

    Args:
        obj: STIX object mapping.

    Returns:
        List of validation error messages (empty when valid).
    """
    errors: list[str] = []
    obj_type = str(obj.get("type") or "?")
    obj_id = str(obj.get("id") or "")
    if not obj_id.startswith(f"{obj_type}--"):
        errors.append(f"STIX: id incoerente con il tipo ({obj_type})")
    try:
        uuid.UUID(obj_id.split("--", 1)[1])
    except ValueError:
        errors.append(f"STIX: UUID non valido in {obj_id}")
    return errors


def check_stix_fields(obj: STIXObject) -> list[str]:
    """Validate the mandatory fields of a STIX object.

    Args:
        obj: STIX object mapping.

    Returns:
        List of validation error messages (empty when valid).
    """
    errors: list[str] = []
    obj_id = str(obj.get("id") or "")
    if obj.get("spec_version") != STIX_SPEC_VERSION:
        errors.append(f"STIX: spec_version mancante in {obj_id}")
    errors.extend(
        f"STIX: campo obbligatorio '{field}' mancante in {obj_id}"
        for field in ("created", "modified")
        if field not in obj
    )
    return errors


def check_stix_object(obj: STIXObject) -> list[str]:
    """Validate a single STIX object.

    Args:
        obj: STIX object mapping.

    Returns:
        List of validation error messages (empty when valid).
    """
    errors = check_stix_id(obj) + check_stix_fields(obj)
    if obj.get("type") == "indicator" and not {
        "pattern",
        "pattern_type",
        "valid_from",
    }.issubset(obj):
        errors.append(f"STIX: indicator incompleto {obj.get('id')}")
    return errors


def check_stix(bundle: STIXObject) -> list[str]:
    """Validate a STIX 2.1 bundle.

    Args:
        bundle: Parsed STIX bundle mapping.

    Returns:
        List of validation error messages (empty when valid).
    """
    errors: list[str] = []
    if bundle.get("type") != STIX_BUNDLE_TYPE:
        errors.append(f"STIX: type deve essere '{STIX_BUNDLE_TYPE}'")
    for obj in bundle.get("objects") or []:
        errors.extend(check_stix_object(obj))
    return errors


def _sigma_id_ok(doc: SigmaRuleDocument) -> bool:
    """Return ``True`` when the rule identifier is a valid UUID.

    Args:
        doc: Parsed Sigma rule mapping.

    Returns:
        ``True`` when a UUID can be parsed from ``id``.
    """
    try:
        uuid.UUID(str(doc.get("id") or ""))
    except ValueError:
        return False
    return True


def _sigma_condition_ok(detection: dict[str, Any]) -> bool:
    """Return ``True`` when the condition references at least one selection.

    Args:
        detection: Parsed ``detection`` mapping of the Sigma rule.

    Returns:
        ``True`` when a selection key is referenced in the condition.
    """
    condition = detection.get("condition")
    if not condition:
        return False
    selections = set(detection) - {"condition"}
    return bool(selections & set(str(condition).split()))


def check_sigma(path: Path) -> list[str]:
    """Validate a Sigma rule file.

    Args:
        path: Path of the ``.yml`` rule to validate.

    Returns:
        List of validation error messages (empty when valid).
    """
    doc = _load_yaml(path)
    if not isinstance(doc, dict):
        return [f"{path.name}: il file non contiene una mappa YAML"]
    errors = check_sigma_document(doc, path.name)
    detection = doc.get("detection") or {}
    if not isinstance(detection, dict) or not _sigma_condition_ok(detection):
        errors.append(f"{path.name}: condition non referenzia alcuna selection")
    return errors


def check_sigma_document(doc: SigmaRuleDocument, source: str) -> list[str]:
    """Validate the required keys and identifier of a Sigma rule.

    Args:
        doc: Parsed Sigma rule mapping.
        source: Logical source name used in error messages.

    Returns:
        List of validation error messages (empty when valid).
    """
    errors: list[str] = []
    missing = SIGMA_REQUIRED_KEYS - set(doc)
    if missing:
        errors.append(f"{source}: chiavi mancanti {sorted(missing)}")
    if not _sigma_id_ok(doc):
        errors.append(f"{source}: id non e un UUID")
    return errors


def compile_yara(source: str) -> yara_x.Rules:
    """Compile a YARA rule source string.

    Args:
        source: YARA rule source code.

    Returns:
        Compiled :class:`yara_x.Rules` ready for scanning.

    Raises:
        yara_x.CompileError: When the rule source does not compile.
    """
    return yara_x.compile(source)


def load_iocs(root: Path) -> tuple[IOCData, list[CSVRow]]:
    """Load and parse the IOC artifacts.

    Args:
        root: Repository root directory.

    Returns:
        Tuple ``(iocs_json, iocs_csv_rows)``.

    Raises:
        FileNotFoundError: When an artifact is missing.
        json.JSONDecodeError: When the JSON document is malformed.
    """
    data = json.loads((root / "threat-intel" / "iocs.json").read_text(encoding="utf-8"))
    with (root / "threat-intel" / "iocs.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return data, rows


def _load_yaml(path: Path) -> Any:
    """Read and parse a YAML document.

    Args:
        path: File to read.

    Returns:
        Parsed YAML document (any type).

    Raises:
        yaml.YAMLError: When the document is not valid YAML.
    """
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def collect_errors(root: Path) -> list[str]:
    """Collect all validation errors of the artifact set.

    Args:
        root: Repository root directory.

    Returns:
        List of human-readable error messages (empty when everything is valid).
    """
    errors: list[str] = check_iocs(*load_iocs(root))
    stix = json.loads((root / "threat-intel" / "stix_bundle.json").read_text(encoding="utf-8"))
    errors.extend(check_stix(stix))
    for path in sorted((root / "rules").glob("*.yml")):
        errors.extend(check_sigma(path))
    for path in sorted((root / "rules").glob("*.yar")):
        try:
            compile_yara(path.read_text(encoding="utf-8"))
        except yara_x.CompileError as exc:
            logger.exception("YARA rule %s failed to compile: %s", path.name, exc)
            errors.append(f"YARA non compila: {path.name}: {exc}")
    return errors


def main() -> int:
    """Run every artifact validation and report the outcome.

    Returns:
        Process exit code: ``0`` when all artifacts are valid, ``1`` otherwise.
    """
    errors = collect_errors(ROOT)
    if errors:
        for error in errors:
            logger.error("ARTIFACT ERROR: %s", error)
        logger.error("%d errori di validazione trovati", len(errors))
        return 1
    logger.info("OK: tutti gli artefatti sono validi")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
