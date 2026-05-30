# forge/loader.py
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml

class RuleValidationError(ValueError):
    pass

@dataclass
class Rule:
    id: str
    title: str
    logsource: dict
    detection: dict
    tags: list[str]
    path: Path
    raw: dict = field(default_factory=dict)

    @property
    def attack_techniques(self) -> list[str]:
        out = []
        for t in self.tags:
            if t.lower().startswith("attack.t"):
                out.append(t.split(".", 1)[1].upper())
        return out

REQUIRED = ("id", "title", "logsource", "detection", "tags")

def load_rule(path: Path) -> Rule:
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict):
        raise RuleValidationError(f"{path}: not a YAML mapping")
    for key in REQUIRED:
        if key not in data or data[key] in (None, "", [], {}):
            raise RuleValidationError(f"{path}: missing required field '{key}'")
    if "condition" not in data["detection"]:
        raise RuleValidationError(f"{path}: detection has no 'condition'")
    return Rule(
        id=str(data["id"]),
        title=data["title"],
        logsource=data["logsource"],
        detection=data["detection"],
        tags=list(data["tags"]),
        path=Path(path),
        raw=data,
    )

def load_all(rules_dir: Path) -> list[Rule]:
    return [load_rule(p) for p in sorted(Path(rules_dir).rglob("*.yml"))]
