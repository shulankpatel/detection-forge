# tests/test_coverage.py
from forge.coverage import build_layer


def test_layer_has_tagged_techniques():
    rules = [type("R", (), {"attack_techniques": ["T1059.001"]})(),
             type("R", (), {"attack_techniques": ["T1003.001", "T1059.001"]})()]
    layer = build_layer(rules)
    ids = {t["techniqueID"]: t for t in layer["techniques"]}
    assert "T1059.001" in ids
    assert "T1003.001" in ids
    assert ids["T1059.001"]["score"] == 2  # covered by two rules
    assert layer["domain"] == "enterprise-attack"
