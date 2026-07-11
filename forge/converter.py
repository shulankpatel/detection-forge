# forge/converter.py
from __future__ import annotations

import hashlib
from pathlib import Path
from xml.etree import ElementTree as ET

# pySigma core may not be installed in all environments (e.g. offline CI bootstrap
# or local dev without the optional dependency). Import defensively so this module
# is always import-safe; convert_rule() raises a clear error if it is actually used
# without pySigma present.
try:
    from sigma.collection import SigmaCollection

    _PYSIGMA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when pySigma is absent
    SigmaCollection = None  # type: ignore[assignment]
    _PYSIGMA_AVAILABLE = False

_BACKENDS = {}

if _PYSIGMA_AVAILABLE:
    try:
        from sigma.backends.splunk import SplunkBackend

        _BACKENDS["splunk"] = (SplunkBackend, "spl")
    except ImportError:
        pass
    try:
        from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend

        _BACKENDS["elastic"] = (LuceneBackend, "ndjson")
    except ImportError:
        pass
    try:
        from sigma.backends.kusto import KustoBackend

        # KustoBackend emits KQL for Microsoft Sentinel / Defender XDR / Azure Data Explorer.
        _BACKENDS["sentinel"] = (KustoBackend, "kql")
    except ImportError:
        pass

# Wazuh backend is always available (pure Python XML generation).
_BACKENDS["wazuh"] = ("wazuh_native", "xml")

AVAILABLE_BACKENDS = list(_BACKENDS)


def _to_wazuh_xml(rule) -> str:
    """Convert a Sigma Rule to native Wazuh XML format."""
    # Generate a deterministic numeric ID: hash rule UUID, take last 5 digits, offset by 910000
    rule_hash = int(hashlib.md5(rule.id.encode()).hexdigest(), 16)
    rule_id = 910000 + (rule_hash % 90000)

    # Map level to Wazuh severity: low→5, medium→8, high→12, critical→15
    level_map = {"low": 5, "medium": 8, "high": 12, "critical": 15}
    level = level_map.get(rule.raw.get("level", "medium"), 8)

    # Extract ATT&CK techniques for the MITRE group tag
    attack_str = ",".join(rule.attack_techniques)

    # Build field patterns from detection selections
    fields = []
    for sel_name, sel_dict in rule.detection.items():
        if sel_name == "condition":
            continue
        for key, values in sel_dict.items():
            field, _, modifier = key.partition("|")
            # Normalize values to list
            val_list = values if isinstance(values, list) else [values]

            # Build PCRE2 pattern based on modifier
            if modifier == "endswith":
                patterns = [f"(?i)\\\\{v}$" for v in val_list]
            elif modifier == "contains":
                patterns = [f"(?i){v}" for v in val_list]
            elif modifier == "startswith":
                patterns = [f"(?i)^{v}" for v in val_list]
            elif modifier == "re":
                patterns = val_list
            else:  # equality
                patterns = [f"(?i)^{v}$" for v in val_list]

            pattern = "|".join(patterns)
            field_elem = ET.Element("field", name=field, type="pcre2")
            field_elem.text = pattern
            fields.append(field_elem)

    # Build the rule element
    rule_elem = ET.Element("rule", id=str(rule_id), level=str(level))

    # Add field checks
    for field_elem in fields:
        rule_elem.append(field_elem)

    # Add description
    desc_elem = ET.SubElement(rule_elem, "description")
    desc_elem.text = rule.title

    # Add group (tactic/technique tags)
    group_elem = ET.SubElement(rule_elem, "group")
    group_elem.text = f"detection-forge,attack,{attack_str.lower()},"

    # Add MITRE mapping
    mitre_elem = ET.SubElement(rule_elem, "mitre")
    for tech in rule.attack_techniques:
        id_elem = ET.SubElement(mitre_elem, "id")
        id_elem.text = tech

    # Wrap in group element
    group_wrapper = ET.Element("group", name=f"detection-forge,{attack_str.lower()},")
    group_wrapper.append(rule_elem)

    # Convert to pretty-printed XML string
    xml_str = ET.tostring(group_wrapper, encoding="unicode")
    # Add simple pretty-printing
    xml_str = xml_str.replace("><", ">\n<")
    return f"<?xml version=\"1.0\"?>\n{xml_str}"


def convert_rule(rule, backend_name: str) -> str:
    if backend_name == "wazuh":
        return _to_wazuh_xml(rule)

    if not _PYSIGMA_AVAILABLE:
        raise RuntimeError("pySigma is not installed")
    if backend_name not in _BACKENDS:
        raise ValueError(f"backend '{backend_name}' not available; have {AVAILABLE_BACKENDS}")
    backend_cls, _ext = _BACKENDS[backend_name]
    if backend_cls == "wazuh_native":
        raise ValueError("wazuh backend requires pySigma (reached unreachable code)")
    collection = SigmaCollection.from_yaml(rule.path.read_text())
    queries = backend_cls().convert(collection)
    return "\n".join(queries)


def build_all(rules, dist_dir: Path) -> dict[str, int]:
    counts = {}
    if not AVAILABLE_BACKENDS:
        print("[info] no pySigma backends available; skipping conversion")
        return counts
    for backend_name, (_cls, ext) in _BACKENDS.items():
        out_dir = Path(dist_dir) / backend_name
        for rule in rules:
            try:
                query = convert_rule(rule, backend_name)
            except Exception as exc:  # one bad rule must not abort the whole backend
                print(f"[warn] {rule.id} -> {backend_name}: {exc}")
                continue
            # Create the backend dir lazily, only once we have output to write, so a
            # backend that yields zero successful conversions leaves no empty dir.
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{rule.path.stem}.{ext}").write_text(query + "\n")
            counts[backend_name] = counts.get(backend_name, 0) + 1
    return counts
