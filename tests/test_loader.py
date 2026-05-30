# tests/test_loader.py
import pytest
from pathlib import Path
from forge.loader import load_rule, Rule, RuleValidationError

FIX = Path(__file__).parent / "fixtures" / "_loader"

def test_load_valid_rule_returns_rule():
    rule = load_rule(FIX / "valid.yml")
    assert isinstance(rule, Rule)
    assert rule.id == "00000000-0000-0000-0000-000000000001"
    assert rule.title == "Test Rule"
    assert rule.attack_techniques == ["T1059.001"]
    assert "selection" in rule.detection

def test_load_rule_missing_tags_raises():
    with pytest.raises(RuleValidationError, match="tags"):
        load_rule(FIX / "missing_tags.yml")
