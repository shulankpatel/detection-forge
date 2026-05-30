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
