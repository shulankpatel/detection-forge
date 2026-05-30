# detection-forge `ingest` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `forge ingest <url>` — extract IOCs + ATT&CK IDs from a threat report and draft a reviewable Sigma rule (plus sanity fixtures) into `rules/ingested/`, which then flows through the existing convert/test/website pipeline.

**Architecture:** A new stdlib-only `forge/ingest.py` (fetch → strip HTML → regex-extract indicators → draft a Sigma dict → write rule + fixtures), wired into the CLI as a new `ingest` subcommand. No new runtime dependencies; tests are fully offline (a committed sample report + pytest `tmp_path`).

**Tech Stack:** Python 3.9+, stdlib `urllib`/`html.parser`/`re`/`uuid`, PyYAML (already a dep), pytest.

---

## Environment notes (carry into every task)
- Python **3.9** — `from __future__ import annotations` at the top of `forge/ingest.py`. No 3.10+ syntax.
- **Offline:** system `python3` (pytest + PyYAML present). Run `python3 -m pytest`. Tests must NOT hit the network — they pass text/files directly to the functions.
- Work on branch `build/ingest`. Commit per task with the messages shown.

## File Structure
| Path | Responsibility |
|------|----------------|
| `forge/ingest.py` | Extraction + drafting: `extract_iocs`, `extract_attack`, `load_source`, `to_plain_text`, `draft_rule`, `make_fixtures`, `ingest`. |
| `forge/cli.py` (modify) | Add the `ingest` subcommand. |
| `tests/test_ingest.py` | Unit + end-to-end tests (offline). |
| `tests/fixtures/_ingest/sample_report.html` | Committed sample report with known IOCs + ATT&CK IDs. |

---

## Task 1: Indicator + ATT&CK extraction (pure text)

**Files:**
- Create: `forge/ingest.py`
- Test: `tests/test_ingest.py`

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_ingest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'forge.ingest'`.

- [ ] **Step 3: Write the extraction implementation**

```python
# forge/ingest.py
from __future__ import annotations

import re

# Re-fang common defanging so indicators match.
def _refang(text: str) -> str:
    return (
        text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        .replace("[:]", ":").replace("hxxps", "https").replace("hxxp", "http")
        .replace("hXXps", "https").replace("hXXp", "http")
    )

# File extensions that the domain regex would otherwise mis-match as TLDs.
_FILE_EXT = {
    "exe", "dll", "php", "ps1", "js", "vbs", "bat", "cmd", "txt", "html", "htm",
    "doc", "docx", "xls", "xlsx", "pdf", "zip", "rar", "png", "jpg", "gif", "py",
    "sys", "bin", "dat", "tmp", "log", "json", "xml", "aspx", "jsp",
}
_CMD_HINTS = (
    "powershell", "cmd.exe", "cmd /", "schtasks", "rundll32", "regsvr32",
    "wscript", "cscript", "mshta", "certutil", "bitsadmin", "wmic", "net use",
)
_PATTERNS = {
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"https?://[^\s\"'<>)\]]+",
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "regkey": r"\bHK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]+",
    "filepath": r"\b[A-Za-z]:\\[^\s\"'<>|]+",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
}

def _dedupe(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def extract_attack(text: str) -> list:
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)
    return _dedupe(i.upper() for i in ids)

def extract_iocs(text: str) -> dict:
    text = _refang(text)
    iocs = {}
    for name, pat in _PATTERNS.items():
        iocs[name] = _dedupe(re.findall(pat, text))
    # domains: drop anything whose final label is a known file extension,
    # and drop bare domains already contained in an extracted URL or email.
    blob = " ".join(iocs["url"] + iocs["email"])
    iocs["domain"] = [
        d for d in iocs["domain"]
        if d.rsplit(".", 1)[-1].lower() not in _FILE_EXT and d not in blob
    ]
    # command lines: whole lines that mention a known shell / LOLBin.
    iocs["cmdline"] = _dedupe(
        ln.strip() for ln in text.splitlines()
        if any(h in ln.lower() for h in _CMD_HINTS) and ln.strip()
    )
    return iocs
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_ingest.py -v`
Expected: PASS (6 passed). If a regex needs a tweak to match the asserted values, adjust the pattern (not the test).

- [ ] **Step 5: Commit**

```bash
git add forge/ingest.py tests/test_ingest.py
git commit -m "feat: add IOC + ATT&CK extraction for forge ingest"
```

---

## Task 2: Draft a rule + sanity fixtures + orchestration

**Files:**
- Modify: `forge/ingest.py`
- Test: `tests/test_ingest.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_ingest.py
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_ingest.py -v`
Expected: FAIL — `ImportError: cannot import name 'draft_rule'`.

- [ ] **Step 3: Add the implementation to `forge/ingest.py`**

```python
# append to forge/ingest.py
import json
import uuid
from pathlib import Path
import yaml

# IOC type -> (selection name, Sigma field expression)
_FIELD_MAP = [
    (("sha256", "sha1", "md5"), "selection_hash", "Hashes|contains"),
    (("cmdline",), "selection_cmdline", "CommandLine|contains"),
    (("filepath",), "selection_file", "Image|endswith"),
    (("regkey",), "selection_registry", "TargetObject|contains"),
    (("domain", "ipv4", "url"), "selection_network", "DestinationHostname|contains"),
]

def _label(source_ref: str) -> str:
    m = re.search(r"https?://([^/]+)", source_ref)
    return m.group(1) if m else source_ref[:40]

def draft_rule(source_ref: str, iocs: dict, attack: list, title=None) -> dict:
    selections = {}
    for types, name, field in _FIELD_MAP:
        values = []
        for t in types:
            values.extend(iocs.get(t, []))
        if values:
            selections[name] = {field: _dedupe(values)}
    if not selections:
        raise ValueError("no actionable indicators found to draft a rule")
    if any(n in selections for n in ("selection_hash", "selection_cmdline", "selection_file")):
        logsource = {"product": "windows", "category": "process_creation"}
    elif "selection_registry" in selections:
        logsource = {"product": "windows", "category": "registry_event"}
    else:
        logsource = {"category": "network_connection"}
    tags = ["ingested.auto-extracted"] + [f"attack.{t.lower()}" for t in attack]
    return {
        "title": title or f"Indicators from {_label(source_ref)}",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, source_ref)),
        "status": "experimental",
        "description": (
            f"Auto-drafted by `forge ingest` from {source_ref}. "
            "REVIEW REQUIRED: verify the logsource and field mappings."
        ),
        "references": [source_ref],
        "logsource": logsource,
        "detection": {**selections, "condition": "1 of them"},
        "level": "medium",
        "tags": tags,
    }

def make_fixtures(rule: dict):
    detection = rule["detection"]
    positive = {}
    for name, sel in detection.items():
        if name == "condition":
            continue
        for key, vals in sel.items():
            field = key.split("|")[0]
            positive[field] = vals[0] if isinstance(vals, list) else vals
        break  # one satisfied selection is enough for `1 of them`
    return [positive], [{}]  # empty event matches nothing -> does not fire

def ingest(text: str, source_ref: str, out_dir, fixtures_dir) -> dict:
    iocs = extract_iocs(text)
    attack = extract_attack(text)
    rule = draft_rule(source_ref, iocs, attack)
    slug = (re.sub(r"[^a-z0-9]+", "-", _label(source_ref).lower()).strip("-") or "report")[:50]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rule_path = out / f"{slug}.yml"
    banner = (
        f"# AUTO-EXTRACTED by `forge ingest` from {source_ref} - REVIEW REQUIRED.\n"
        "# Indicators were extracted literally from the source; verify logsource\n"
        "# and field mappings before trusting this detection.\n"
    )
    rule_path.write_text(banner + yaml.safe_dump(rule, sort_keys=False))
    pos, neg = make_fixtures(rule)
    fx = Path(fixtures_dir) / rule["id"]
    fx.mkdir(parents=True, exist_ok=True)
    (fx / "positive.json").write_text(json.dumps(pos, indent=2))
    (fx / "negative.json").write_text(json.dumps(neg, indent=2))
    return {"rule": rule_path, "id": rule["id"], "iocs": iocs, "attack": attack}
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m pytest tests/test_ingest.py -v`
Expected: PASS (all Task 1 + Task 2 tests green).

- [ ] **Step 5: Commit**

```bash
git add forge/ingest.py tests/test_ingest.py
git commit -m "feat: draft Sigma rule + sanity fixtures from extracted indicators"
```

---

## Task 3: `forge ingest` CLI + sample report + end-to-end test

**Files:**
- Modify: `forge/cli.py`
- Create: `tests/fixtures/_ingest/sample_report.html`
- Test: `tests/test_ingest.py`

- [ ] **Step 1: Add `load_source` + `to_plain_text` to `forge/ingest.py`**

```python
# append to forge/ingest.py
import html.parser
import urllib.request

_MAX_BYTES = 2_000_000

class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip = 0
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())

def to_plain_text(raw: str) -> str:
    if "<" in raw and ">" in raw:
        p = _TextExtractor()
        p.feed(raw)
        return "\n".join(p.parts)
    return raw

def load_source(url=None, file=None, text=None):
    provided = [x for x in (url, file, text) if x]
    if len(provided) != 1:
        raise ValueError("provide exactly one of: url, file, text")
    if text:
        return text, "inline-text"
    if file:
        p = Path(file)
        return p.read_text(errors="replace"), str(p)
    req = urllib.request.Request(url, headers={"User-Agent": "detection-forge-ingest"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec - user-supplied URL, local CLI
        return resp.read(_MAX_BYTES).decode("utf-8", errors="replace"), url
```

- [ ] **Step 2: Write the sample report fixture**

Create `tests/fixtures/_ingest/sample_report.html`:
```html
<html><head><style>.x{color:red}</style></head><body>
<h1>Threat Report: ExampleStealer</h1>
<p>The actor exploited CVE-2024-1234, then executed:</p>
<pre><code>powershell.exe -nop -w hidden -enc ZQBjAGgAbwAgAGgAaQA=</code></pre>
<p>It dropped C:\Users\Public\evil.exe (sha256
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) and beaconed to
hxxp://malicious[.]example[.]com/gate.php (203.0.113.5).</p>
<p>Persistence: HKLM\Software\Microsoft\Windows\CurrentVersion\Run</p>
<p>Techniques: T1059.001, T1547.001.</p>
<script>console.log("ignored")</script>
</body></html>
```

- [ ] **Step 3: Write the end-to-end test**

```python
# append to tests/test_ingest.py
from forge.ingest import load_source, to_plain_text

def test_end_to_end_from_html_file(tmp_path):
    raw, ref = load_source(file="tests/fixtures/_ingest/sample_report.html")
    text = to_plain_text(raw)
    assert "console.log" not in text          # script stripped
    assert "powershell.exe" in text
    res = ingest(text, "https://example.com/examplestealer", tmp_path / "rules", tmp_path / "fix")
    loaded = load_rule(res["rule"])
    assert loaded.attack_techniques == ["T1059.001", "T1547.001"]
    assert res["iocs"]["sha256"]
    pos = json.loads((tmp_path / "fix" / loaded.id / "positive.json").read_text())
    assert all(matches(loaded.detection, e) for e in pos)
```

- [ ] **Step 4: Add the `ingest` subcommand to `forge/cli.py`**

Add the subparser (next to build/test/coverage/export):
```python
    ing = sub.add_parser("ingest", help="draft a detection from a threat report URL or file")
    ing.add_argument("url", nargs="?", help="report URL (or use --file)")
    ing.add_argument("--file", help="read a saved report from a local file instead of a URL")
    ing.add_argument("--out", help="output dir for the draft rule (default: rules/ingested)")
    ing.add_argument("--fixtures", help="fixtures dir (default: tests/fixtures)")
```
Add the handler branch in `main` (after `export`):
```python
    elif args.cmd == "ingest":
        from forge.ingest import load_source, to_plain_text, ingest as run_ingest
        raw, ref = load_source(url=args.url, file=args.file)
        text = to_plain_text(raw)
        out_dir = args.out or (RULES / "ingested")
        fx_dir = args.fixtures or (ROOT / "tests" / "fixtures")
        res = run_ingest(text, ref, out_dir, fx_dir)
        found = {k: len(v) for k, v in res["iocs"].items() if v}
        print(f"Drafted {res['rule']}")
        print(f"  source : {ref}")
        print(f"  IOCs   : {found}")
        print(f"  ATT&CK : {res['attack']}")
        print("  NOTE   : status=experimental - REVIEW the draft (and its field mappings) before trusting it.")
        return 0
```

- [ ] **Step 5: Verify CLI + full suite**

Run:
```bash
python3 -m forge.cli ingest --file tests/fixtures/_ingest/sample_report.html --out /tmp/ing_rules --fixtures /tmp/ing_fix
python3 -m pytest -q
```
Expected: the CLI prints the drafted rule path + found IOCs/ATT&CK; full suite green (existing 43 + new ingest tests, 1 skipped converter test). The committed `rules/` set is unchanged (the CLI wrote to `/tmp`).

- [ ] **Step 6: Commit**

```bash
git add forge/ingest.py forge/cli.py tests/test_ingest.py tests/fixtures/_ingest/sample_report.html
git commit -m "feat: add 'forge ingest' CLI (report -> reviewable draft detection)"
```

---

## Task 4: Document the command in the README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an "Ingest a report" subsection** under Quickstart describing:
```markdown
### Draft a detection from a threat report
```bash
python3 -m forge.cli ingest https://some-vendor.com/threat-report
# or from a saved file:  python3 -m forge.cli ingest --file report.html
```
This extracts indicators (IOCs) and ATT&CK technique IDs from the report and writes a
**reviewable** Sigma draft to `rules/ingested/` (with sanity test events). It's
`status: experimental` — review the field mappings, then it converts to all four SIEMs and
joins the catalog like any other rule. Rule-based extraction (no AI): it captures
explicitly-stated indicators/techniques, not free-form behavioral prose.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document 'forge ingest' in the README"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** `load_source`/`to_plain_text` (T3); `extract_iocs` all types + defang + filename-skip (T1); `extract_attack` (T1); `draft_rule` format incl. always-present `ingested.auto-extracted` tag, deterministic uuid5 id, `1 of them`, references, experimental (T2); IOC→field map (T2 `_FIELD_MAP`); `make_fixtures` sanity events (T2); `ingest` writes to `rules/ingested/` + fixtures (T2); CLI subcommand (T3); committed sample fixture + offline tests writing to tmp (T1–T3); README docs (T4). All spec sections map to a task. ✔
- **Placeholder scan:** none — every step has complete code/commands.
- **Type consistency:** `extract_iocs(text)->dict`, `extract_attack(text)->list`, `draft_rule(source_ref, iocs, attack)`, `make_fixtures(rule)->([pos],[neg])`, `ingest(text, source_ref, out_dir, fixtures_dir)->dict`, `load_source(...)->(raw, ref)`, `to_plain_text(raw)->str` used consistently across tasks and tests. ✔
- **Non-pollution:** the CLI/tests write drafts to `/tmp` or `tmp_path`, so the committed `rules/` stays the curated 8 and existing `test_export`/`test_rules` expectations are unchanged. ✔
- **Offline/3.9:** stdlib-only; `from __future__ import annotations`; tests never touch the network. ✔
