# tests/test_rules.py
import json
from pathlib import Path

import pytest

from forge.loader import load_all
from forge.validator import matches

ROOT = Path(__file__).resolve().parent.parent
RULES = load_all(ROOT / "rules")
FIX = Path(__file__).parent / "fixtures"


def _events(rule_id, kind):
    p = FIX / rule_id / f"{kind}.json"
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else [data]


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_rule_has_fixtures(rule):
    assert _events(rule.id, "positive"), f"{rule.id}: no positive fixtures"
    assert _events(rule.id, "negative") is not None


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_positive_events_fire(rule):
    for ev in _events(rule.id, "positive"):
        assert matches(rule.detection, ev) is True, f"{rule.id} should fire on {ev}"


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_negative_events_do_not_fire(rule):
    for ev in _events(rule.id, "negative"):
        assert matches(rule.detection, ev) is False, f"{rule.id} false-positive on {ev}"
