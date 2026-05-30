# detection-forge Website Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a GitHub Pages website that showcases detection-forge — a hero, an interactive detection catalog (Sigma + 4 SIEM conversions + tests per rule), and an on-page ATT&CK heatmap — generated from the repo and auto-deployed.

**Architecture:** A new `forge export` command reuses the existing engine to emit `site/data.json`; a dependency-free static frontend (`site/index.html` + `assets/app.js` + `assets/styles.css`) renders it client-side; a `pages.yml` workflow regenerates the data (with pySigma) and deploys to GitHub Pages.

**Tech Stack:** Python 3.9+ (exporter), vanilla HTML/CSS/JS (no framework/Node), GitHub Actions + Pages. Offline: pytest + PyYAML present; pySigma absent (conversions populate in CI).

---

## Environment notes (carry into every task)
- Local Python is **3.9** — any new module using new-style hints starts with `from __future__ import annotations`.
- **Offline:** use system `python3`; run tests with `python3 -m pytest`. pySigma is not installed locally, so `conversions` will be empty maps locally and populate in CI — the exporter and tests must tolerate this.
- Work on branch `build/website` (the executor creates it). Commit per task with the messages shown.

## File Structure
| Path | Responsibility |
|------|----------------|
| `forge/exporter.py` | Build the `data.json` dict from rules, fixtures, conversions, coverage. |
| `forge/cli.py` (modify) | Add the `export` subcommand. |
| `tests/test_export.py` | Verify the export structure. |
| `tests/test_site.py` | Smoke-check the static frontend wiring. |
| `site/index.html` | Page shell + section containers. |
| `site/assets/styles.css` | Dark SOC theme + responsive layout. |
| `site/assets/app.js` | Fetch `data.json`; render hero/catalog/heatmap. |
| `.gitignore` (modify) | Ignore the generated `site/data.json`. |
| `.github/workflows/pages.yml` | Build (with pySigma) + deploy to Pages. |
| `README.md` (modify) | Link the live site. |

---

## Task 1: `forge export` — generate `site/data.json`

**Files:**
- Create: `forge/exporter.py`
- Modify: `forge/cli.py`
- Modify: `.gitignore`
- Test: `tests/test_export.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_export.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'forge.exporter'`.

- [ ] **Step 3: Write the implementation**

```python
# forge/exporter.py
from __future__ import annotations

import json
from pathlib import Path

from forge.loader import load_all
from forge.converter import AVAILABLE_BACKENDS, convert_rule
from forge.coverage import build_layer

# Static ATT&CK metadata for the techniques this project covers (id -> (name, tactic)).
TECHNIQUES = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1566": ("Phishing", "Initial Access"),
    "T1078.004": ("Cloud Accounts", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1562.008": ("Disable Cloud Logs", "Defense Evasion"),
    "T1098": ("Account Manipulation", "Persistence"),
}
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
]
BACKENDS = ["splunk", "sentinel", "elastic", "wazuh"]


def _platform(rule) -> str:
    parts = set(rule.path.parts)
    for p in ("windows", "aws", "azure"):
        if p in parts:
            return p
    return rule.logsource.get("product", "other")


def _attack(rule) -> list:
    out = []
    for tid in rule.attack_techniques:
        name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
        out.append({"id": tid, "name": name, "tactic": tactic})
    return out


def _tests(rule, fixtures_dir) -> dict:
    base = Path(fixtures_dir) / rule.id

    def load(kind):
        p = base / f"{kind}.json"
        if not p.exists():
            return []
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else [data]

    return {"positive": load("positive"), "negative": load("negative")}


def _conversions(rule) -> dict:
    out = {}
    for backend in BACKENDS:
        if backend in AVAILABLE_BACKENDS:
            try:
                out[backend] = convert_rule(rule, backend)
            except Exception:
                out[backend] = ""
    return out


def build_export_data(rules_dir, fixtures_dir) -> dict:
    rules = load_all(rules_dir)
    detections = []
    for rule in rules:
        detections.append({
            "id": rule.id,
            "title": rule.title,
            "description": rule.raw.get("description", ""),
            "level": rule.raw.get("level", ""),
            "platform": _platform(rule),
            "logsource": rule.logsource,
            "attack": _attack(rule),
            "sigma": rule.path.read_text(),
            "tests": _tests(rule, fixtures_dir),
            "conversions": _conversions(rule),
        })

    layer = build_layer(rules)
    techniques, present = [], []
    for t in layer["techniques"]:
        tid = t["techniqueID"]
        name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
        techniques.append({"id": tid, "name": name, "tactic": tactic, "score": t["score"]})
        if tactic not in present:
            present.append(tactic)
    tactics = [t for t in TACTIC_ORDER if t in present] + [t for t in present if t not in TACTIC_ORDER]

    return {
        "stats": {
            "detections": len(detections),
            "techniques": len(techniques),
            "backends": BACKENDS,
        },
        "backends_available": list(AVAILABLE_BACKENDS),
        "coverage": {"tactics": tactics, "techniques": techniques},
        "detections": detections,
    }


def write_export(data, out_path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_export.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Add the `export` subcommand to the CLI**

In `forge/cli.py`, add a subparser and handler. Add `sub.add_parser("export", help="generate site/data.json for the website")` alongside the existing subparsers, and add this branch in `main` (after the `coverage` branch):

```python
    elif args.cmd == "export":
        from forge.exporter import build_export_data, write_export
        data = build_export_data(RULES, ROOT / "tests" / "fixtures")
        out = write_export(data, ROOT / "site" / "data.json")
        print(f"Wrote {out} ({data['stats']['detections']} detections, "
              f"{len(data['backends_available'])} live backends)")
```

- [ ] **Step 6: Ignore the generated data file**

Append to `.gitignore`:
```gitignore
site/data.json
```

- [ ] **Step 7: Verify CLI + full suite**

Run:
```bash
python3 -m forge.cli export && python3 -c "import json;d=json.load(open('site/data.json'));print(d['stats'])"
python3 -m pytest -q
```
Expected: writes `site/data.json` with `{'detections': 8, ...}`; full suite green (41 passed, 1 skipped — 37 prior + 4 new export tests).

- [ ] **Step 8: Commit**

```bash
git add forge/exporter.py forge/cli.py tests/test_export.py .gitignore
git commit -m "feat: add 'forge export' to generate site data.json"
```

---

## Task 2: Static frontend (functional)

**Files:**
- Create: `site/index.html`, `site/assets/styles.css`, `site/assets/app.js`
- Test: `tests/test_site.py`

- [ ] **Step 1: Write the failing smoke test**

```python
# tests/test_site.py
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"

def test_index_references_assets():
    html = (SITE / "index.html").read_text()
    assert "assets/app.js" in html
    assert "assets/styles.css" in html
    for anchor in ("stats", "catalog", "heatmap", "filter-platform", "filter-tactic"):
        assert f'id="{anchor}"' in html, f"missing #{anchor}"

def test_app_fetches_data_and_renders():
    js = (SITE / "assets" / "app.js").read_text()
    assert "data.json" in js
    for fn in ("renderStats", "renderCatalog", "renderHeatmap", "applyFilters"):
        assert fn in js, f"missing {fn}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_site.py -v`
Expected: FAIL — `FileNotFoundError` (site files don't exist).

- [ ] **Step 3: Create `site/index.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>detection-forge — Detection-as-Code catalog</title>
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
  <header class="hero">
    <h1>detection-forge</h1>
    <p class="tagline">Write a detection once in Sigma — get tested, ATT&amp;CK-mapped queries for Splunk, Sentinel, Elastic &amp; Wazuh, automatically.</p>
    <div id="stats" class="stats"></div>
    <div class="cta">
      <a class="btn primary" href="https://github.com/shulankpatel/detection-forge">View on GitHub</a>
      <a class="btn" href="#catalog-section">Browse detections</a>
    </div>
  </header>
  <main>
    <section id="catalog-section">
      <h2>Detection catalog</h2>
      <div class="filters">
        <label>Platform <select id="filter-platform"></select></label>
        <label>Tactic <select id="filter-tactic"></select></label>
      </div>
      <div id="catalog" class="grid"></div>
    </section>
    <section id="coverage-section">
      <h2>MITRE ATT&amp;CK coverage</h2>
      <div id="heatmap" class="heatmap"></div>
    </section>
  </main>
  <footer>
    <p>Built with <a href="https://github.com/shulankpatel/detection-forge">detection-forge</a> · MIT</p>
  </footer>
  <script src="assets/app.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create `site/assets/app.js`**

```javascript
// site/assets/app.js
const PLATFORM_LABELS = { windows: "Windows", aws: "AWS", azure: "Azure" };
const BACKEND_TABS = [
  ["sigma", "Sigma"], ["splunk", "Splunk"], ["sentinel", "Sentinel"],
  ["elastic", "Elastic"], ["wazuh", "Wazuh"], ["tests", "Tests"],
];
let DATA = null;

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function init() {
  try {
    const res = await fetch("data.json");
    DATA = await res.json();
  } catch (e) {
    document.getElementById("catalog").innerHTML =
      '<p class="empty">Could not load data.json. Run <code>python3 -m forge.cli export</code> first.</p>';
    return;
  }
  renderStats(DATA);
  renderFilters(DATA);
  renderCatalog(DATA.detections);
  renderHeatmap(DATA.coverage);
}

function renderStats(data) {
  const s = data.stats;
  document.getElementById("stats").innerHTML = `
    <div class="stat"><span class="num">${s.detections}</span><span class="lbl">Detections</span></div>
    <div class="stat"><span class="num">${s.techniques}</span><span class="lbl">ATT&amp;CK techniques</span></div>
    <div class="stat"><span class="num">${s.backends.length}</span><span class="lbl">SIEM targets</span></div>`;
}

function renderFilters(data) {
  const platforms = ["all", ...new Set(data.detections.map(d => d.platform))];
  const tactics = ["all", ...new Set(data.detections.flatMap(d => d.attack.map(a => a.tactic)))];
  const pf = document.getElementById("filter-platform");
  const tf = document.getElementById("filter-tactic");
  pf.innerHTML = platforms.map(p =>
    `<option value="${esc(p)}">${p === "all" ? "All platforms" : esc(PLATFORM_LABELS[p] || p)}</option>`).join("");
  tf.innerHTML = tactics.map(t =>
    `<option value="${esc(t)}">${t === "all" ? "All tactics" : esc(t)}</option>`).join("");
  pf.addEventListener("change", applyFilters);
  tf.addEventListener("change", applyFilters);
}

function applyFilters() {
  const p = document.getElementById("filter-platform").value;
  const t = document.getElementById("filter-tactic").value;
  renderCatalog(DATA.detections.filter(d =>
    (p === "all" || d.platform === p) &&
    (t === "all" || d.attack.some(a => a.tactic === t))));
}

function renderCatalog(detections) {
  const root = document.getElementById("catalog");
  if (!detections.length) { root.innerHTML = '<p class="empty">No detections match.</p>'; return; }
  root.innerHTML = detections.map((d, i) => cardHTML(d, i)).join("");
  detections.forEach((d, i) => wireCard(d, i));
}

function cardHTML(d, i) {
  const chips = d.attack.map(a => `<span class="chip">${esc(a.id)}</span>`).join("");
  return `
  <article class="card" data-i="${i}">
    <header>
      <span class="platform ${esc(d.platform)}">${esc(PLATFORM_LABELS[d.platform] || d.platform)}</span>
      <span class="level">${esc(d.level)}</span>
    </header>
    <h3>${esc(d.title)}</h3>
    <p class="desc">${esc(d.description)}</p>
    <div class="chips">${chips}</div>
    <div class="tabs" hidden></div>
  </article>`;
}

function wireCard(d, i) {
  const card = document.querySelector(`.card[data-i="${i}"]`);
  const tabsEl = card.querySelector(".tabs");
  card.addEventListener("click", () => {
    if (!tabsEl.hidden) { tabsEl.hidden = true; card.classList.remove("open"); return; }
    tabsEl.innerHTML =
      `<div class="tab-bar">` +
      BACKEND_TABS.map(([k, label], idx) =>
        `<button class="tab-btn${idx === 0 ? " active" : ""}" data-tab="${k}">${label}</button>`).join("") +
      `</div><div class="tab-body"></div>`;
    tabsEl.hidden = false;
    card.classList.add("open");
    tabsEl.addEventListener("click", e => e.stopPropagation());
    const body = tabsEl.querySelector(".tab-body");
    const show = key => { body.innerHTML = tabContent(d, key); wireCopy(body); };
    tabsEl.querySelectorAll(".tab-btn").forEach(btn =>
      btn.addEventListener("click", () => {
        tabsEl.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        show(btn.dataset.tab);
      }));
    show("sigma");
  });
}

function tabContent(d, key) {
  if (key === "sigma") return codeBlock(d.sigma);
  if (key === "tests") {
    return `<h4>Should fire</h4>${codeBlock(JSON.stringify(d.tests.positive, null, 2))}` +
           `<h4>Should NOT fire</h4>${codeBlock(JSON.stringify(d.tests.negative, null, 2))}`;
  }
  const q = d.conversions[key];
  if (!q) return '<p class="note">This conversion is generated during the GitHub Pages build (requires pySigma).</p>';
  return codeBlock(q);
}

function codeBlock(text) {
  return `<div class="codewrap"><button class="copy">Copy</button><pre><code>${esc(text)}</code></pre></div>`;
}

function wireCopy(scope) {
  scope.querySelectorAll(".copy").forEach(btn =>
    btn.addEventListener("click", () => {
      const code = btn.parentElement.querySelector("code").textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(code);
      btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy"), 1200);
    }));
}

function renderHeatmap(coverage) {
  document.getElementById("heatmap").innerHTML = coverage.tactics.map(tactic => {
    const cells = coverage.techniques.filter(t => t.tactic === tactic).map(t =>
      `<div class="cell s${Math.min(t.score, 3)}" title="${esc(t.id)} ${esc(t.name)} — ${t.score} detection(s)">
         <span class="tid">${esc(t.id)}</span><span class="tname">${esc(t.name)}</span></div>`).join("");
    return `<div class="col"><h4>${esc(tactic)}</h4>${cells}</div>`;
  }).join("");
}

document.addEventListener("DOMContentLoaded", init);
```

- [ ] **Step 5: Create `site/assets/styles.css` (functional base — polished in Task 3)**

```css
:root { --bg:#0b0f14; --panel:#141b24; --ink:#e6edf3; --muted:#8b98a5; --accent:#3fb950; --line:#222c38; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 system-ui, sans-serif; }
a { color:var(--accent); }
.hero { text-align:center; padding:4rem 1rem 2rem; }
.hero h1 { font-size:2.5rem; margin:0; }
.tagline { color:var(--muted); max-width:46rem; margin:1rem auto; }
.stats { display:flex; gap:1.5rem; justify-content:center; margin:1.5rem 0; flex-wrap:wrap; }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:1rem 1.5rem; }
.stat .num { display:block; font-size:2rem; font-weight:700; color:var(--accent); }
.stat .lbl { color:var(--muted); font-size:.85rem; }
.btn { display:inline-block; padding:.6rem 1.1rem; border:1px solid var(--line); border-radius:6px; text-decoration:none; margin:.25rem; }
.btn.primary { background:var(--accent); color:#08240f; font-weight:600; border-color:var(--accent); }
main { max-width:72rem; margin:0 auto; padding:1rem; }
h2 { border-bottom:1px solid var(--line); padding-bottom:.4rem; }
.filters { display:flex; gap:1rem; margin:1rem 0; flex-wrap:wrap; }
.filters select { background:var(--panel); color:var(--ink); border:1px solid var(--line); border-radius:6px; padding:.4rem; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(20rem,1fr)); gap:1rem; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:1rem; cursor:pointer; }
.card.open { outline:1px solid var(--accent); }
.card header { display:flex; justify-content:space-between; font-size:.8rem; color:var(--muted); }
.platform { text-transform:uppercase; letter-spacing:.05em; }
.chips { margin-top:.5rem; }
.chip { display:inline-block; background:#0d2818; color:var(--accent); border-radius:4px; padding:.1rem .4rem; font-size:.75rem; margin:.1rem; font-family:monospace; }
.tabs { margin-top:1rem; }
.tab-bar { display:flex; flex-wrap:wrap; gap:.25rem; }
.tab-btn { background:var(--bg); color:var(--muted); border:1px solid var(--line); border-radius:5px; padding:.3rem .6rem; cursor:pointer; }
.tab-btn.active { color:var(--accent); border-color:var(--accent); }
.codewrap { position:relative; }
.copy { position:absolute; top:.4rem; right:.4rem; font-size:.75rem; cursor:pointer; background:var(--panel); color:var(--ink); border:1px solid var(--line); border-radius:4px; }
pre { background:#05080b; border:1px solid var(--line); border-radius:6px; padding:1rem; overflow:auto; }
code { font-family:ui-monospace,Menlo,monospace; font-size:.85rem; }
.note { color:var(--muted); font-style:italic; }
.heatmap { display:flex; gap:.75rem; overflow-x:auto; padding-bottom:1rem; }
.heatmap .col { min-width:9rem; }
.heatmap .col h4 { font-size:.8rem; color:var(--muted); }
.cell { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:.5rem; margin:.3rem 0; }
.cell .tid { display:block; font-family:monospace; color:var(--accent); font-size:.8rem; }
.cell .tname { font-size:.8rem; }
.cell.s1 { background:#10331d; } .cell.s2 { background:#15522b; } .cell.s3 { background:#1d7a3e; }
footer { text-align:center; color:var(--muted); padding:2rem; }
@media (max-width:600px){ .hero h1{font-size:2rem;} }
```

- [ ] **Step 6: Run smoke tests + local render check**

Run:
```bash
python3 -m pytest tests/test_site.py -v
python3 -m forge.cli export && python3 -m http.server -d site 8000 &
sleep 1 && python3 -c "import urllib.request as u; print('200' if u.urlopen('http://localhost:8000').status==200 else 'FAIL')"
kill %1 2>/dev/null || true
```
Expected: tests pass; homepage returns 200. (Conversion tabs show the "generated on deploy" note locally — expected.)

- [ ] **Step 7: Commit**

```bash
git add site/index.html site/assets/styles.css site/assets/app.js tests/test_site.py
git commit -m "feat: add static website (hero, catalog, ATT&CK heatmap)"
```

---

## Task 3: Visual polish (frontend-design skill)

**Files:** Modify `site/assets/styles.css` and, only if needed, `site/index.html` markup.

- [ ] **Step 1: Invoke the frontend-design skill** to elevate the site to the spec's **dark SOC/terminal aesthetic** — refined typography, a confident accent, polished cards/tabs, a strong ATT&CK heatmap, syntax-style code coloring, smooth focus/hover states, and full mobile responsiveness. Make it look production-grade and distinctive (no generic template look).

- [ ] **Step 2: PRESERVE the data contract** — `app.js` depends on these and they must keep working: element ids `#stats`, `#catalog`, `#heatmap`, `#filter-platform`, `#filter-tactic`; classes `.card`, `.tabs`, `.tab-bar`, `.tab-btn(.active)`, `.tab-body`, `.codewrap`, `.copy`, `.chip`, `.cell.s1/.s2/.s3`, `.platform`, `.stat .num/.lbl`. If you rename anything, update `app.js` in the same task and re-run the smoke tests.

- [ ] **Step 3: Verify**

Run:
```bash
python3 -m pytest tests/test_site.py tests/test_export.py -v
python3 -m forge.cli export && python3 -m http.server -d site 8000 &
sleep 1 && python3 -c "import urllib.request as u; print(u.urlopen('http://localhost:8000').status)"
kill %1 2>/dev/null || true
```
Expected: smoke + export tests pass; homepage 200. Visually confirm hero, catalog cards expand with tabs, and the heatmap renders.

- [ ] **Step 4: Commit**

```bash
git add site/
git commit -m "style: polish website to dark SOC theme (frontend-design)"
```

---

## Task 4: GitHub Pages deploy workflow + README link

**Files:**
- Create: `.github/workflows/pages.yml`
- Modify: `README.md`

- [ ] **Step 1: Create the workflow**

```yaml
# .github/workflows/pages.yml
name: Deploy website to GitHub Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: pages
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: pip install -r requirements-backends.txt || echo "conversion backends optional/unavailable"
      - name: Generate site data (with conversions)
        run: python -m forge.cli export
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 2: Add a live-site link near the top of `README.md`**

Add this line directly under the badges row:
```markdown
**🔗 Live site:** https://shulankpatel.github.io/detection-forge/
```

- [ ] **Step 3: Validate the workflow YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/pages.yml')); print('pages yaml ok')"`
Expected: `pages yaml ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/pages.yml README.md
git commit -m "ci: add GitHub Pages deploy workflow; link live site in README"
```

- [ ] **Step 5: One-time Pages enablement (documented for the human operator)**

After merge + push, the repo owner enables Pages once: **Repo → Settings → Pages → Build and deployment → Source → "GitHub Actions"**. The next push to `main` (or a manual `workflow_dispatch`) then deploys to `https://shulankpatel.github.io/detection-forge/`. The controller will surface this step to the user at hand-off; it cannot be done from the CLI.

---

## Self-Review (completed by plan author)

- **Spec coverage:** `forge export` + data.json schema (T1); hero/catalog/heatmap frontend (T2); conversions-only-when-available + "generated on deploy" note (T1 `_conversions`, T2 `tabComponent`); dark SOC polish (T3); Pages deploy + one-time enablement + live URL (T4); local preview (T2 S6); tests (T1, T2). All spec sections map to a task. ✔
- **Placeholder scan:** No TBD/vague items; T3 names the skill, the exact aesthetic goal, and the precise selectors to preserve — actionable, not a placeholder. ✔
- **Type/contract consistency:** `build_export_data(rules_dir, fixtures_dir)`, `write_export(data, path)`, `convert_rule(rule, backend)`, `AVAILABLE_BACKENDS`, `build_layer(rules)["techniques"][].techniqueID/score` used consistently. Frontend element ids/classes emitted in T2 match the smoke test (T2 S1) and the preserve-list (T3 S2). ✔
- **Offline-safe:** export tolerates empty `conversions`; tests assert `conversions` is a dict (possibly empty); frontend shows a note when a conversion is absent. ✔
