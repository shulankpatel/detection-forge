# forge/coverage.py
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path


def build_layer(rules) -> dict:
    counter: Counter[str] = Counter()
    for rule in rules:
        for tech in rule.attack_techniques:
            counter[tech] += 1
    techniques = [
        {"techniqueID": tid, "score": n, "comment": f"{n} detection(s)"}
        for tid, n in sorted(counter.items())
    ]
    return {
        "name": "detection-forge coverage",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by detection-forge rules.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffe6e6", "#ff0000"], "minValue": 0, "maxValue": 5},
    }


def write_layer(rules, dist_dir: Path) -> Path:
    out = Path(dist_dir) / "attack-navigator-layer.json"
    out.write_text(json.dumps(build_layer(rules), indent=2))
    return out
