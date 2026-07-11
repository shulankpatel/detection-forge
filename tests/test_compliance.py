# tests/test_compliance.py
from pathlib import Path
from forge.compliance import build_compliance_layer, write_compliance_report

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
FIX = ROOT / "tests" / "fixtures"


def test_compliance_layer_has_techniques():
    import sys
    sys.path.insert(0, str(ROOT))
    from forge.loader import load_all
    rules = load_all(RULES)
    layer = build_compliance_layer(rules)
    assert "techniques" in layer
    assert "controls" in layer
    assert len(layer["techniques"]) > 0
    assert "T1059.001" in [t["id"] for t in layer["techniques"]]


def test_technique_has_controls():
    import sys
    sys.path.insert(0, str(ROOT))
    from forge.loader import load_all
    rules = load_all(RULES)
    layer = build_compliance_layer(rules)
    for tech in layer["techniques"]:
        assert "id" in tech
        assert "nist" in tech
        assert "soc2" in tech
        assert isinstance(tech["nist"], list)
        assert isinstance(tech["soc2"], list)
        assert len(tech["nist"]) > 0 or len(tech["soc2"]) > 0


def test_compliance_report_written(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT))
    from forge.loader import load_all
    rules = load_all(RULES)
    out = write_compliance_report(rules, tmp_path)
    assert out.exists()
    assert out.suffix == ".json"
    import json
    data = json.loads(out.read_text())
    assert "techniques" in data
    assert "controls" in data
