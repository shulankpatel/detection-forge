# tests/test_ingest.py
from forge.ingest import extract_iocs, extract_attack

SAMPLE = (
    "The attacker exploited CVE-2024-1234 and ran:\n"
    "    powershell.exe -nop -enc ZQBjAGgAbwA=\n"
    "Dropped C:\\Users\\Public\\evil.exe "
    "(sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855).\n"
    "C2 at hxxp://malicious[.]example[.]com/gate.php and IP 203.0.113.5.\n"
    "Persistence: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
    "Mapped to ATT&CK T1059.001 and T1547.001.\n"
)

def test_extract_attack_ids():
    assert sorted(extract_attack(SAMPLE)) == ["T1059.001", "T1547.001"]

def test_extract_attack_dedupes_and_uppercases():
    assert extract_attack("t1059.001 T1059.001 T1059.001") == ["T1059.001"]

def test_extract_hash_ip_cve():
    iocs = extract_iocs(SAMPLE)
    assert iocs["sha256"] == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert iocs["ipv4"] == ["203.0.113.5"]
    assert iocs["cve"] == ["CVE-2024-1234"]

def test_extract_refanged_url_and_domain():
    iocs = extract_iocs(SAMPLE)
    assert "http://malicious.example.com/gate.php" in iocs["url"]
    assert "malicious.example.com" in iocs["domain"]

def test_extract_filepath_regkey_cmdline():
    iocs = extract_iocs(SAMPLE)
    assert "C:\\Users\\Public\\evil.exe" in iocs["filepath"]
    assert any(r.startswith("HKLM\\Software") for r in iocs["regkey"])
    assert any("powershell.exe -nop -enc" in c for c in iocs["cmdline"])

def test_domain_extraction_skips_filenames():
    # evil.exe and gate.php must NOT be treated as domains
    iocs = extract_iocs(SAMPLE)
    assert "evil.exe" not in iocs["domain"]
    assert "gate.php" not in iocs["domain"]

import json
from pathlib import Path
from forge.ingest import draft_rule, make_fixtures, ingest
from forge.loader import load_rule
from forge.validator import matches

def _iocs():
    return {
        "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "cmdline": ["powershell.exe -nop -enc ZQBjAGgAbwA="],
        "filepath": ["C:\\Users\\Public\\evil.exe"],
        "regkey": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "domain": ["malicious.example.com"], "ipv4": ["203.0.113.5"], "url": [], "email": [],
        "sha1": [], "md5": [], "cve": ["CVE-2024-1234"],
    }

def test_draft_rule_is_loader_valid(tmp_path):
    rule = draft_rule("https://example.com/report", _iocs(), ["T1059.001"])
    p = tmp_path / "r.yml"
    import yaml
    p.write_text(yaml.safe_dump(rule, sort_keys=False))
    loaded = load_rule(p)  # raises if invalid
    assert loaded.attack_techniques == ["T1059.001"]
    assert "ingested.auto-extracted" in rule["tags"]
    assert rule["status"] == "experimental"
    assert rule["references"] == ["https://example.com/report"]
    assert rule["detection"]["condition"] == "1 of them"

def test_draft_rule_id_is_deterministic():
    a = draft_rule("https://x.com/a", _iocs(), [])
    b = draft_rule("https://x.com/a", _iocs(), [])
    assert a["id"] == b["id"]

def test_no_indicators_raises():
    import pytest
    with pytest.raises(ValueError):
        draft_rule("https://x.com/a", {"cve": ["CVE-2024-1"]}, [])  # cve is not a detection field

def test_sanity_fixtures_fire_correctly():
    rule = draft_rule("https://example.com/report", _iocs(), ["T1059.001"])
    pos, neg = make_fixtures(rule)
    assert pos and all(matches(rule["detection"], e) for e in pos)
    assert all(not matches(rule["detection"], e) for e in neg)

def test_ingest_writes_rule_and_fixtures(tmp_path):
    text = ("powershell.exe -nop -enc ZQBjAGgAbwA=\n"
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "ATT&CK T1059.001\n")
    res = ingest(text, "https://example.com/report", tmp_path / "rules", tmp_path / "fix")
    assert Path(res["rule"]).exists()
    loaded = load_rule(res["rule"])
    fx = (tmp_path / "fix" / loaded.id)
    pos = json.loads((fx / "positive.json").read_text())
    neg = json.loads((fx / "negative.json").read_text())
    assert all(matches(loaded.detection, e) for e in pos)
    assert all(not matches(loaded.detection, e) for e in neg)
