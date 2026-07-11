# forge/exporter.py
from __future__ import annotations

import json
from pathlib import Path

from forge.loader import load_all
from forge.converter import AVAILABLE_BACKENDS, convert_rule
from forge.coverage import build_layer
from forge.compliance import _CONTROLS

# Static ATT&CK metadata for the techniques this project covers (id -> (name, tactic)).
TECHNIQUES = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1053.003": ("Cron", "Persistence"),
    "T1566": ("Phishing", "Initial Access"),
    "T1078.004": ("Cloud Accounts", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1562.008": ("Disable Cloud Logs", "Defense Evasion"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1021.004": ("SSH", "Lateral Movement"),
}
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
]
BACKENDS = ["splunk", "sentinel", "elastic", "wazuh"]


def _platform(rule) -> str:
    parts = set(rule.path.parts)
    for p in ("windows", "aws", "azure", "linux"):
        if p in parts:
            return p
    return rule.logsource.get("product", "other")


def _attack(rule) -> list:
    out = []
    for tid in rule.attack_techniques:
        name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
        out.append({"id": tid, "name": name, "tactic": tactic})
    return out


def _tests(rule, fixtures_dir) -> dict:
    base = Path(fixtures_dir) / rule.id

    def load(kind):
        p = base / f"{kind}.json"
        if not p.exists():
            return []
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else [data]

    return {"positive": load("positive"), "negative": load("negative")}


def _conversions(rule) -> dict:
    out = {}
    for backend in BACKENDS:
        if backend in AVAILABLE_BACKENDS:
            try:
                out[backend] = convert_rule(rule, backend)
            except Exception:
                out[backend] = ""
    return out


def _compliance(rule) -> dict:
    nist, soc2 = [], []
    for tid in rule.attack_techniques:
        if tid in _CONTROLS:
            nist.extend(_CONTROLS[tid]["nist"])
            soc2.extend(_CONTROLS[tid]["soc2"])
    return {"nist": sorted(set(nist)), "soc2": sorted(set(soc2))}


def build_export_data(rules_dir, fixtures_dir) -> dict:
    rules = load_all(rules_dir)
    detections = []
    for rule in rules:
        detections.append({
            "id": rule.id,
            "title": rule.title,
            "description": rule.raw.get("description", ""),
            "level": rule.raw.get("level", ""),
            "platform": _platform(rule),
            "logsource": rule.logsource,
            "attack": _attack(rule),
            "compliance": _compliance(rule),
            "sigma": rule.path.read_text(),
            "tests": _tests(rule, fixtures_dir),
            "conversions": _conversions(rule),
        })

    layer = build_layer(rules)
    techniques, present = [], []
    for t in layer["techniques"]:
        tid = t["techniqueID"]
        name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
        techniques.append({"id": tid, "name": name, "tactic": tactic, "score": t["score"]})
        if tactic not in present:
            present.append(tactic)
    tactics = [t for t in TACTIC_ORDER if t in present] + [t for t in present if t not in TACTIC_ORDER]

    return {
        "stats": {
            "detections": len(detections),
            "techniques": len(techniques),
            "backends": BACKENDS,
        },
        "backends_available": list(AVAILABLE_BACKENDS),
        "coverage": {"tactics": tactics, "techniques": techniques},
        "detections": detections,
    }


def write_export(data, out_path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2))
    return out
