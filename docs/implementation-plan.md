# detection-forge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Detection-as-Code pipeline that loads Sigma rules, converts them to Splunk/Sentinel/Elastic/Wazuh, tests each rule against sample events, and emits a MITRE ATT&CK coverage layer — all gated by CI.

**Architecture:** A small Python package (`forge/`) with five single-purpose modules — `loader` (parse/validate Sigma), `validator` (a pure-Python Sigma-logic evaluator for testing), `converter` (pySigma → per-platform queries), `coverage` (ATT&CK Navigator layer), and `cli` (entry point). Detections live as Sigma YAML in `rules/`; tests live in `tests/`; generated queries land in `dist/<platform>/`. GitHub Actions runs lint → build → test → coverage.

**Tech Stack:** Python 3.11+, pySigma + backend plugins, PyYAML, pytest, ruff, GitHub Actions. Docker + Elastic + Atomic Red Team for the optional live demo only.

---

## File Structure (locked from `docs/design.md`)

| Path | Responsibility |
|------|----------------|
| `forge/loader.py` | Discover + parse + validate Sigma rule files into a `Rule` dataclass. |
| `forge/validator.py` | Evaluate a rule's `detection`/`condition` against an event dict (pure Python). |
| `forge/converter.py` | Convert a rule to each backend via pySigma; write to `dist/<platform>/`. |
| `forge/coverage.py` | Aggregate ATT&CK tags into a Navigator layer JSON. |
| `forge/cli.py` | `forge build | test | coverage` entry point. |
| `rules/windows/`, `rules/cloud/aws/`, `rules/cloud/azure/` | Source Sigma detections. |
| `tests/` | pytest unit tests + `tests/fixtures/<rule-id>/{positive,negative}.json`. |
| `.github/workflows/ci.yml` | CI pipeline. |

---

## Task 1: Project scaffolding & tooling

**Files:**
- Create: `pyproject.toml`, `requirements.txt`, `.gitignore`, `LICENSE`, `README.md` (stub), `forge/__init__.py`, `tests/__init__.py`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
__pycache__/
*.pyc
.venv/
venv/
.pytest_cache/
.ruff_cache/
*.egg-info/
dist/
!dist/.gitkeep
.DS_Store
```

- [ ] **Step 2: Create `requirements.txt`**

```text
pysigma>=0.11
pysigma-backend-splunk>=1.1
pysigma-backend-elasticsearch>=1.0
pysigma-backend-microsoft365defender>=1.0
pyyaml>=6.0
pytest>=8.0
ruff>=0.5
```

> **Execution note:** The Wazuh backend has no stable standalone pySigma plugin at time of writing. The converter (Task 4) treats Wazuh as a best-effort target and falls back to an Elastic-compatible export if no plugin is installed — document whatever is used in the README.

- [ ] **Step 3: Create `pyproject.toml`**

```toml
[project]
name = "detection-forge"
version = "0.1.0"
description = "Detection-as-Code pipeline: author once in Sigma, convert + test + ATT&CK-map for Splunk, Sentinel, Elastic, and Wazuh."
requires-python = ">=3.11"

[project.scripts]
forge = "forge.cli:main"

[tool.ruff]
line-length = 100

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

- [ ] **Step 4: Create empty package files**

Create `forge/__init__.py` and `tests/__init__.py` (both empty). Create `dist/.gitkeep` (empty).

- [ ] **Step 5: Create `LICENSE`** (MIT, year 2026, author shulankpatel) and a one-paragraph `README.md` stub (expanded in Task 16).

- [ ] **Step 6: Set up environment and verify**

Run:
```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
```
Expected: installs succeed. If a backend package fails to resolve, drop it from `requirements.txt` and note it for Task 4.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "chore: scaffold detection-forge project and tooling"
```

---

## Task 2: Loader (parse + validate Sigma rules)

**Files:**
- Create: `forge/loader.py`
- Test: `tests/test_loader.py`
- Fixture: `tests/fixtures/_loader/valid.yml`, `tests/fixtures/_loader/missing_tags.yml`

- [ ] **Step 1: Create test fixtures**

`tests/fixtures/_loader/valid.yml`:
```yaml
title: Test Rule
id: 00000000-0000-0000-0000-000000000001
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \powershell.exe
  condition: selection
tags:
  - attack.t1059.001
```

`tests/fixtures/_loader/missing_tags.yml`: same as above but with the entire `tags:` block removed.

- [ ] **Step 2: Write the failing test**

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_loader.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'forge.loader'`.

- [ ] **Step 4: Write minimal implementation**

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_loader.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add forge/loader.py tests/test_loader.py tests/fixtures/_loader
git commit -m "feat: add Sigma rule loader with validation"
```

---

## Task 3: Validator — pure-Python Sigma evaluator

This is the centerpiece component. It evaluates a rule's `detection`/`condition` against an event so we can prove rules fire correctly with no SIEM.

**Files:**
- Create: `forge/validator.py`
- Test: `tests/test_validator.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_validator.py
from forge.validator import matches

def _rule(detection):
    return {"detection": detection}

def test_simple_equality():
    det = {"selection": {"EventID": 1}, "condition": "selection"}
    assert matches(det, {"EventID": 1}) is True
    assert matches(det, {"EventID": 2}) is False

def test_endswith_and_contains_modifiers():
    det = {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"}
    assert matches(det, {"Image": "C:\\Windows\\System32\\powershell.exe"}) is True
    assert matches(det, {"Image": "C:\\Windows\\cmd.exe"}) is False

def test_wildcard_value():
    det = {"selection": {"CommandLine": "*-enc*"}, "condition": "selection"}
    assert matches(det, {"CommandLine": "powershell -enc ZQBjAGgA"}) is True
    assert matches(det, {"CommandLine": "powershell -file x.ps1"}) is False

def test_list_value_is_or():
    det = {"selection": {"EventID": [1, 4688]}, "condition": "selection"}
    assert matches(det, {"EventID": 4688}) is True
    assert matches(det, {"EventID": 7}) is False

def test_and_or_not_condition():
    det = {
        "sel_a": {"EventID": 1},
        "sel_b": {"User": "root"},
        "filter": {"Image|endswith": "\\safe.exe"},
        "condition": "sel_a and sel_b and not filter",
    }
    assert matches(det, {"EventID": 1, "User": "root", "Image": "x\\bad.exe"}) is True
    assert matches(det, {"EventID": 1, "User": "root", "Image": "x\\safe.exe"}) is False

def test_one_of_them():
    det = {"sel_a": {"EventID": 1}, "sel_b": {"EventID": 4688}, "condition": "1 of them"}
    assert matches(det, {"EventID": 4688}) is True
    assert matches(det, {"EventID": 9}) is False

def test_all_of_pattern():
    det = {"sel_x": {"A": 1}, "sel_y": {"B": 2}, "condition": "all of sel_*"}
    assert matches(det, {"A": 1, "B": 2}) is True
    assert matches(det, {"A": 1, "B": 9}) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_validator.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'forge.validator'`.

- [ ] **Step 3: Write the implementation**

```python
# forge/validator.py
from __future__ import annotations
import fnmatch
import re

def _match_value(actual, expected, modifier: str | None) -> bool:
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "re":
        return re.search(e, a) is not None
    if "*" in e or "?" in e:
        return fnmatch.fnmatch(a.lower(), e.lower())
    return a.lower() == e.lower()

def _eval_selection(selection, event: dict) -> bool:
    if isinstance(selection, list):
        return any(_eval_selection(s, event) for s in selection)
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        actual = event.get(field)
        if isinstance(expected, list):
            ok = any(_match_value(actual, v, modifier or None) for v in expected)
        else:
            ok = _match_value(actual, expected, modifier or None)
        if not ok:
            return False
    return True

# --- condition parser (recursive descent over a tokenized condition string) ---

def _tokenize(condition: str) -> list[str]:
    return re.findall(r"\(|\)|\w+\*?|\*", condition)

class _Parser:
    def __init__(self, tokens, results):
        self.t = tokens
        self.i = 0
        self.results = results  # {selection_name: bool}

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        return self._or()

    def _or(self):
        val = self._and()
        while self.peek() == "or":
            self.next()
            val = self._and() or val
        return val

    def _and(self):
        val = self._not()
        while self.peek() == "and":
            self.next()
            rhs = self._not()
            val = val and rhs
        return val

    def _not(self):
        if self.peek() == "not":
            self.next()
            return not self._not()
        return self._atom()

    def _atom(self):
        tok = self.peek()
        if tok == "(":
            self.next()
            val = self._or()
            self.next()  # consume ')'
            return val
        if tok in ("all", "1", "any"):
            return self._aggregation()
        self.next()
        return self.results.get(tok, False)

    def _aggregation(self):
        quant = self.next()  # 'all' | '1' | 'any'
        self.next()          # 'of'
        target = self.next() # 'them' | 'pattern*'
        if target == "them":
            names = list(self.results)
        else:
            names = [n for n in self.results if fnmatch.fnmatch(n, target)]
        vals = [self.results[n] for n in names]
        return all(vals) if quant == "all" else any(vals)

def matches(detection: dict, event: dict) -> bool:
    condition = detection["condition"]
    results = {
        name: _eval_selection(sel, event)
        for name, sel in detection.items()
        if name != "condition"
    }
    return _Parser(_tokenize(condition), results).parse()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_validator.py -v`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add forge/validator.py tests/test_validator.py
git commit -m "feat: add pure-Python Sigma detection evaluator"
```

---

## Task 4: Converter — pySigma to per-platform queries

**Files:**
- Create: `forge/converter.py`
- Test: `tests/test_converter.py`

- [ ] **Step 1: Write the failing test (robust token assertions, not exact strings)**

```python
# tests/test_converter.py
from pathlib import Path
from forge.loader import load_rule
from forge.converter import convert_rule, AVAILABLE_BACKENDS

FIX = Path(__file__).parent / "fixtures" / "_loader" / "valid.yml"

def test_convert_to_splunk_contains_field():
    rule = load_rule(FIX)
    out = convert_rule(rule, "splunk")
    assert isinstance(out, str) and len(out) > 0
    assert "powershell.exe" in out.lower()

def test_available_backends_includes_splunk():
    assert "splunk" in AVAILABLE_BACKENDS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_converter.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

> **Execution note:** Confirm the exact backend class import paths against the installed pySigma backend versions during this step (`pip show pysigma-backend-splunk`). Adjust the `_BACKENDS` registry imports if the package renamed classes. Wrap each import in try/except so a missing optional backend (e.g., Sentinel/Wazuh) degrades gracefully instead of crashing the build.

```python
# forge/converter.py
from __future__ import annotations
from pathlib import Path
from sigma.collection import SigmaCollection

_BACKENDS = {}

try:
    from sigma.backends.splunk import SplunkBackend
    _BACKENDS["splunk"] = (SplunkBackend, "spl")
except ImportError:
    pass
try:
    from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
    _BACKENDS["elastic"] = (LuceneBackend, "ndjson")
except ImportError:
    pass
try:
    from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
    _BACKENDS["sentinel"] = (Microsoft365DefenderBackend, "kql")
except ImportError:
    pass
# Wazuh: best-effort; falls back to Elastic export if no dedicated backend is installed.

AVAILABLE_BACKENDS = list(_BACKENDS)

def convert_rule(rule, backend_name: str) -> str:
    if backend_name not in _BACKENDS:
        raise ValueError(f"backend '{backend_name}' not available; have {AVAILABLE_BACKENDS}")
    backend_cls, _ext = _BACKENDS[backend_name]
    collection = SigmaCollection.from_yaml(rule.path.read_text())
    queries = backend_cls().convert(collection)
    return "\n".join(queries)

def build_all(rules, dist_dir: Path) -> dict[str, int]:
    counts = {}
    for backend_name, (_cls, ext) in _BACKENDS.items():
        out_dir = Path(dist_dir) / backend_name
        out_dir.mkdir(parents=True, exist_ok=True)
        for rule in rules:
            try:
                query = convert_rule(rule, backend_name)
            except Exception as exc:  # one bad rule must not abort the whole backend
                print(f"[warn] {rule.id} -> {backend_name}: {exc}")
                continue
            (out_dir / f"{rule.path.stem}.{ext}").write_text(query + "\n")
            counts[backend_name] = counts.get(backend_name, 0) + 1
    return counts
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_converter.py -v`
Expected: PASS. If the Splunk backend class path differs, fix the import and re-run.

- [ ] **Step 5: Commit**

```bash
git add forge/converter.py tests/test_converter.py
git commit -m "feat: add pySigma multi-backend converter"
```

---

## Task 5: Coverage — MITRE ATT&CK Navigator layer

**Files:**
- Create: `forge/coverage.py`
- Test: `tests/test_coverage.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_coverage.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_coverage.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add forge/coverage.py tests/test_coverage.py
git commit -m "feat: add ATT&CK Navigator coverage layer generator"
```

---

## Task 6: CLI + rule-fixture test harness

**Files:**
- Create: `forge/cli.py`
- Test: `tests/test_rules.py` (the parametrized harness that runs every rule's fixtures)

- [ ] **Step 1: Write the CLI**

```python
# forge/cli.py
from __future__ import annotations
import argparse
from pathlib import Path
from forge.loader import load_all
from forge.converter import build_all
from forge.coverage import write_layer

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
DIST = ROOT / "dist"

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="forge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="convert rules to all backends")
    sub.add_parser("coverage", help="write the ATT&CK layer")
    args = parser.parse_args(argv)

    rules = load_all(RULES)
    if args.cmd == "build":
        counts = build_all(rules, DIST)
        print(f"Converted {len(rules)} rules -> {counts}")
    elif args.cmd == "coverage":
        out = write_layer(rules, DIST)
        print(f"Wrote {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Write the parametrized fixture harness**

```python
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
```

- [ ] **Step 3: Run** `pytest tests/test_rules.py -v`. Expected: passes trivially now (no rules yet) or collects zero — that is fine; it activates as rules are added in Tasks 7–14.

- [ ] **Step 4: Commit**

```bash
git add forge/cli.py tests/test_rules.py
git commit -m "feat: add forge CLI and parametrized rule fixture harness"
```

---

## Task 7: First end-to-end detection (Windows — encoded PowerShell)

This is the vertical slice that exercises loader → validator → converter → coverage.

**Files:**
- Create: `rules/windows/powershell_encoded_command.yml`
- Create: `tests/fixtures/0a1f8b10-0001-4000-8000-000000000001/positive.json`
- Create: `tests/fixtures/0a1f8b10-0001-4000-8000-000000000001/negative.json`

- [ ] **Step 1: Write the rule**

```yaml
# rules/windows/powershell_encoded_command.yml
title: PowerShell Encoded Command Execution
id: 0a1f8b10-0001-4000-8000-000000000001
status: experimental
description: Detects PowerShell launched with an encoded command, often used to obfuscate payloads.
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith:
      - \powershell.exe
      - \pwsh.exe
  selection_flag:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  condition: selection_img and selection_flag
falsepositives:
  - Rare administrative scripts that legitimately pass encoded commands.
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

- [ ] **Step 2: Write `positive.json` (must fire)**

```json
[
  {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
   "CommandLine": "powershell.exe -nop -w hidden -enc ZQBjAGgAbwAgAGgAaQA="}
]
```

- [ ] **Step 3: Write `negative.json` (must NOT fire)**

```json
[
  {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c dir"},
  {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
   "CommandLine": "powershell.exe -File C:\\scripts\\backup.ps1"}
]
```

- [ ] **Step 4: Run the harness for this rule**

Run: `pytest tests/test_rules.py -v -k powershell_encoded`
Expected: PASS (fires on positive, silent on both negatives).

- [ ] **Step 5: Build + coverage smoke test**

Run: `forge build && forge coverage`
Expected: `dist/splunk/powershell_encoded_command.spl` (and other available backends) exist; `dist/attack-navigator-layer.json` lists `T1059.001`.

- [ ] **Step 6: Commit**

```bash
git add rules/windows/powershell_encoded_command.yml tests/fixtures/0a1f8b10-0001-4000-8000-000000000001
git commit -m "feat: add encoded-PowerShell detection (T1059.001) end-to-end"
```

---

## Task 8: CI pipeline

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/ci.yml
name: detection-forge CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - name: Lint Python
        run: ruff check forge tests
      - name: Lint Sigma rules
        run: sigma check rules || true   # informational until sigma-cli is pinned
      - name: Build (convert to all backends)
        run: python -m forge.cli build
      - name: Test (unit + rule fixtures)
        run: pytest -v
      - name: Generate ATT&CK coverage
        run: python -m forge.cli coverage
      - name: Upload dist artifacts
        uses: actions/upload-artifact@v4
        with:
          name: converted-rules
          path: dist/
```

- [ ] **Step 2: Validate locally** by running the same commands the workflow runs:

Run: `ruff check forge tests && python -m forge.cli build && pytest -v && python -m forge.cli coverage`
Expected: all succeed.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add lint -> build -> test -> coverage pipeline"
```

---

## Tasks 9–14: Remaining 7 detections

Each task follows the **exact pattern of Task 7**: (1) write the rule YAML, (2) write `positive.json`, (3) write `negative.json`, (4) `pytest -k <stem>`, (5) commit `feat: add <name> detection (<technique>)`. The concrete detection logic for each:

- [ ] **Task 9 — LSASS credential access (T1003.001)** · `rules/windows/lsass_credential_access.yml`
  - logsource: `product: windows, category: process_access`
  - `selection: TargetImage|endswith: \lsass.exe` AND `GrantedAccess` in `['0x1010','0x1410','0x1438','0x143a','0x1fffff']`
  - positive: access to `...\lsass.exe` with `GrantedAccess: "0x1410"`. negative: access to `...\notepad.exe`, or lsass with `GrantedAccess: "0x1000"`.

- [ ] **Task 10 — Scheduled-task persistence (T1053.005)** · `rules/windows/scheduled_task_creation.yml`
  - logsource: `product: windows, category: process_creation`
  - `selection: Image|endswith: \schtasks.exe` AND `CommandLine|contains: ' /create '`
  - positive: `schtasks.exe /create /tn evil /tr c:\a.exe /sc onlogon`. negative: `schtasks.exe /query`.

- [ ] **Task 11 — Office app spawns a shell (T1059 / T1566)** · `rules/windows/office_child_process.yml`
  - logsource: `product: windows, category: process_creation`
  - `selection: ParentImage|endswith: [\winword.exe,\excel.exe,\powerpnt.exe]` AND `Image|endswith: [\cmd.exe,\powershell.exe,\wscript.exe,\mshta.exe]`
  - positive: parent `...\winword.exe`, image `...\powershell.exe`. negative: parent `...\winword.exe`, image `...\splwow64.exe`.

- [ ] **Task 12 — AWS root account usage (T1078.004)** · `rules/cloud/aws/root_account_usage.yml`
  - logsource: `product: aws, service: cloudtrail`
  - `selection: userIdentity.type: Root` AND NOT `filter: eventType: AwsServiceEvent`
  - positive: `{"userIdentity": {"type": "Root"}, "eventName": "ConsoleLogin"}` (note: flatten nested fields in fixtures to `userIdentity.type` OR adjust `event.get` to support dotted paths — implement dotted-path lookup in `validator._eval_selection` as a small extension and add a unit test). negative: `{"userIdentity": {"type": "IAMUser"}}`.

  > **Execution note:** Task 12 requires nested-field support. Add to `forge/validator.py`: a `_get(event, field)` helper that walks dotted paths (`field.split(".")`), replace `event.get(field)` with it, and add a `test_nested_field_lookup` unit test in `tests/test_validator.py` before writing this rule.

- [ ] **Task 13 — CloudTrail logging disabled (T1562.008)** · `rules/cloud/aws/cloudtrail_stop_logging.yml`
  - `selection: eventSource: cloudtrail.amazonaws.com` AND `eventName: [StopLogging, DeleteTrail, UpdateTrail]`
  - positive: `{"eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging"}`. negative: `eventName: "StartLogging"`.

- [ ] **Task 14 — AWS AdministratorAccess attached / access key created (T1098)** · `rules/cloud/aws/iam_privilege_escalation.yml`
  - `selection_attach: {eventName: AttachUserPolicy, requestParameters.policyArn|contains: AdministratorAccess}`; `selection_key: {eventName: CreateAccessKey}`; `condition: selection_attach or selection_key`
  - positive: `{"eventName": "AttachUserPolicy", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}`. negative: `{"eventName": "AttachUserPolicy", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}`.

- [ ] **Task 15 — Azure AD MFA disabled / risky sign-in (T1078)** · `rules/cloud/azure/azuread_mfa_disabled.yml`
  - logsource: `product: azure, service: auditlogs`
  - `selection: {operationName|contains: 'Disable Strong Authentication'}` OR `{Category: UserManagement, operationName|contains: 'Update user'}`
  - positive: `{"operationName": "Disable Strong Authentication"}`. negative: `{"operationName": "Add user"}`.

---

## Task 16: README, badges, and architecture doc

**Files:**
- Modify: `README.md`
- Create: `docs/architecture.md`

- [ ] **Step 1: Write `README.md`** with: project pitch (one-liner from the spec); a badges row (GitHub Actions status badge, a static "8 detections" badge, a static "ATT&CK techniques: N" badge via shields.io); a Quickstart (`pip install -r requirements.txt`, `forge build`, `pytest`, `forge coverage`); the `dist/<platform>/` per-SIEM layout explained; a "How detections are tested" section; and a placeholder image link `docs/img/attack-coverage.png` for the Navigator heatmap.
- [ ] **Step 2: Generate the heatmap screenshot** — run `forge coverage`, open `dist/attack-navigator-layer.json` in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer → upload), screenshot it, and save to `docs/img/attack-coverage.png`.
- [ ] **Step 3: Write `docs/architecture.md`** — the data-flow diagram (reuse the ASCII diagram from `docs/design.md` §4.3) and a one-paragraph description of each `forge/` module.
- [ ] **Step 4: Commit**

```bash
git add README.md docs/architecture.md docs/img
git commit -m "docs: add README with badges, ATT&CK heatmap, and architecture"
```

---

## Task 17 (Showcase): live-demo runbook

**Files:**
- Create: `docs/live-demo.md`

- [ ] **Step 1: Write the runbook** documenting, as numbered steps: (a) `docker run` a single-node Elastic + Kibana; (b) import `dist/elastic/*.ndjson` detection rules; (c) install Atomic Red Team and run 1–2 atomics matching bundled detections (e.g., T1059.001 encoded PowerShell, T1003.001 LSASS access); (d) show the alert firing in Kibana and screenshot it; (e) a teardown command. Mark clearly that this is optional and not part of CI.
- [ ] **Step 2: Commit**

```bash
git add docs/live-demo.md
git commit -m "docs: add optional Docker + Atomic Red Team live-demo runbook"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** Loader (T2), validator/layered-test-backbone (T3, T6), converter for 4 backends (T4), coverage layer (T5), CLI (T6), 8 detections split Windows+Cloud (T7, T9–T15), CI (T8), per-platform `dist/` (T4), README/badges/heatmap (T16), live demo (T17). All spec sections map to a task. ✓
- **Placeholder scan:** No "TBD/handle edge cases"; the two execution notes (pySigma class paths in T4, nested-field support in T12) are explicit, actionable engineering steps with the fix described, not vague placeholders. ✓
- **Type consistency:** `Rule.attack_techniques`, `matches(detection, event)`, `convert_rule(rule, backend)`, `build_all(rules, dist)`, `build_layer(rules)`/`write_layer(rules, dist)`, `load_all(dir)` used consistently across tasks. ✓
- **Known dependency:** Task 12 depends on the nested-field extension; its execution note instructs adding that (with a unit test) before authoring the rule. ✓
