# forge/compliance.py
"""ATT&CK technique to compliance control mapping (NIST 800-53 / SOC 2).

Static mapping of ATT&CK techniques to security compliance controls.
Useful for demonstrating how detection coverage maps to compliance requirements.
"""
from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict

# Static mapping: ATT&CK technique ID -> {nist: [...], soc2: [...]}
_CONTROLS = {
    "T1059.001": {"nist": ["AC-6", "AU-12", "SI-3", "SI-4"], "soc2": ["CC6.1", "CC7.2"]},
    "T1059": {"nist": ["AC-6", "SI-3", "SI-4"], "soc2": ["CC6.1", "CC7.2"]},
    "T1003.001": {"nist": ["AC-6", "IA-5", "SC-28"], "soc2": ["CC6.1", "CC6.7"]},
    "T1053.005": {"nist": ["CM-6", "AU-12", "SI-4"], "soc2": ["CC6.1", "CC8.1"]},
    "T1053.003": {"nist": ["CM-6", "AU-12", "SI-4"], "soc2": ["CC6.1", "CC8.1"]},
    "T1566": {"nist": ["AT-2", "SI-3", "SI-8"], "soc2": ["CC6.1", "CC7.2"]},
    "T1078.004": {"nist": ["AC-2", "AC-6", "IA-2"], "soc2": ["CC6.1", "CC6.3"]},
    "T1078": {"nist": ["AC-2", "IA-2", "IA-5"], "soc2": ["CC6.1", "CC6.3"]},
    "T1562.008": {"nist": ["AU-9", "CM-6", "SI-4"], "soc2": ["CC7.2", "A1.1"]},
    "T1098": {"nist": ["AC-2", "AC-6", "AU-9"], "soc2": ["CC6.3", "CC6.8"]},
    "T1548.003": {"nist": ["AC-6", "CM-6", "AU-12"], "soc2": ["CC6.1", "CC6.3"]},
    "T1021.004": {"nist": ["AC-17", "AU-12", "SC-8"], "soc2": ["CC6.1", "CC6.6"]},
}


def build_compliance_layer(rules) -> dict:
    """Aggregate compliance controls from all rules' ATT&CK techniques.

    Returns:
        dict with:
        - techniques: [{id, nist: [...], soc2: [...]}, ...]
        - controls: {nist: [...], soc2: [...]} (unique controls across all rules)
    """
    technique_map = {}
    nist_set, soc2_set = set(), set()

    for rule in rules:
        for tech in rule.attack_techniques:
            if tech not in technique_map and tech in _CONTROLS:
                controls = _CONTROLS[tech]
                technique_map[tech] = {
                    "id": tech,
                    "nist": sorted(controls["nist"]),
                    "soc2": sorted(controls["soc2"]),
                }
                nist_set.update(controls["nist"])
                soc2_set.update(controls["soc2"])

    return {
        "techniques": sorted(technique_map.values(), key=lambda x: x["id"]),
        "controls": {
            "nist": sorted(nist_set),
            "soc2": sorted(soc2_set),
        },
    }


def write_compliance_report(rules, dist_dir: Path) -> Path:
    """Write compliance mapping report to dist/compliance-report.json."""
    out = Path(dist_dir) / "compliance-report.json"
    out.write_text(json.dumps(build_compliance_layer(rules), indent=2))
    return out
