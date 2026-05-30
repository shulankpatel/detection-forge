# tests/test_export.py
from pathlib import Path
from forge.exporter import build_export_data

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
FIX = ROOT / "tests" / "fixtures"

def test_export_has_eight_detections():
    data = build_export_data(RULES, FIX)
    assert data["stats"]["detections"] == 8
    assert len(data["detections"]) == 8
    assert data["stats"]["backends"] == ["splunk", "sentinel", "elastic", "wazuh"]

def test_each_detection_has_required_keys():
    data = build_export_data(RULES, FIX)
    for d in data["detections"]:
        for key in ("id", "title", "description", "level", "platform",
                    "logsource", "attack", "sigma", "tests", "conversions"):
            assert key in d, f"{d.get('id')} missing {key}"
        assert isinstance(d["conversions"], dict)        # may be empty offline
        assert isinstance(d["attack"], list) and d["attack"]
        assert d["sigma"].strip()
        assert set(d["tests"]) == {"positive", "negative"}
        assert d["tests"]["positive"]                    # at least one positive event

def test_platforms_detected():
    data = build_export_data(RULES, FIX)
    plats = {d["platform"] for d in data["detections"]}
    assert {"windows", "aws", "azure"} <= plats

def test_coverage_present():
    data = build_export_data(RULES, FIX)
    assert data["coverage"]["techniques"]
    assert data["coverage"]["tactics"]
    ids = {t["id"] for t in data["coverage"]["techniques"]}
    assert "T1059.001" in ids
    assert all("name" in t and "tactic" in t and "score" in t
               for t in data["coverage"]["techniques"])
