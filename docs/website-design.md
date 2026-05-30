# detection-forge Website — Design Document

- **Status:** Approved (design phase)
- **Date:** 2026-05-29
- **Author:** shulankpatel
- **Builds on:** the detection-forge pipeline (`docs/design.md`)

---

## 1. Overview

A **GitHub Pages website** that showcases the detection-forge project in the browser,
auto-built from the repository. URL: **`https://shulankpatel.github.io/detection-forge/`**.

Three parts:
1. **Landing / hero** — pitch, key stats (8 detections, 9 ATT&CK techniques, 4 SIEMs),
   buttons to the GitHub repo and to the catalog.
2. **Interactive detection catalog** — one card per detection, filterable by platform and
   ATT&CK tactic. Each card expands to tabs: **Sigma source · Splunk · Sentinel · Elastic ·
   Wazuh · Test events**. This makes the "write once → deploy to every SIEM" value visible.
3. **ATT&CK coverage heatmap** — the project's techniques rendered as a colored matrix
   directly on the page (no external Navigator required).

---

## 2. Goals and Non-Goals

### Goals
- Give a recruiter-friendly, **browser-viewable** front door to the project.
- Show each detection's Sigma source **and** its converted query for all four SIEMs.
- Render ATT&CK coverage visually on-page.
- Auto-deploy on every push to `main` (free, zero-infra, via GitHub Pages).
- Reuse the existing engine — no duplicate logic.

### Non-Goals (YAGNI)
- No backend, server, database, or user accounts.
- No CMS or authoring UI (detections are still authored as Sigma in `rules/`).
- No framework/Node toolchain — plain static site.
- No server-side search (client-side filtering only).

---

## 3. Architecture

```
rules/*.yml  +  tests/fixtures/*  +  forge.converter  +  forge.coverage
        │
        ▼
  forge export   (new CLI subcommand)
        │  writes
        ▼
  site/data.json   ──read by──▶   site/index.html + assets/app.js + assets/styles.css
        │                                   (renders hero, catalog, heatmap client-side)
        ▼
  .github/workflows/pages.yml  ──build (with pySigma) + deploy──▶  GitHub Pages
```

### Components (single responsibility each)
| Component | File | Responsibility |
|-----------|------|----------------|
| **Exporter** | `forge/exporter.py` + `forge export` in `forge/cli.py` | Build `site/data.json` from rules, fixtures, conversions, coverage. |
| **Page shell** | `site/index.html` | Static HTML structure + section containers. |
| **Styles** | `site/assets/styles.css` | Dark SOC theme, responsive layout. |
| **App** | `site/assets/app.js` | Fetch `data.json`; render hero, catalog (filter + tabs), heatmap. |
| **Deploy** | `.github/workflows/pages.yml` | Generate data with pySigma, publish `site/` to Pages. |

---

## 4. The `forge export` command + `data.json` schema

`forge export [--out site/data.json]` loads all rules, attaches test fixtures, runs the
converter for each available backend, and computes ATT&CK coverage. Conversions are
included **only for backends pySigma can load** (so offline the `conversions` maps may be
empty; in CI they are fully populated).

```json
{
  "stats": { "detections": 8, "techniques": 9, "backends": ["splunk","sentinel","elastic","wazuh"] },
  "backends_available": ["splunk","sentinel","elastic","wazuh"],
  "coverage": {
    "tactics": ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access"],
    "techniques": [ { "id":"T1059.001","name":"PowerShell","tactic":"Execution","score":1 } ]
  },
  "detections": [
    {
      "id": "0a1f8b10-0001-4000-8000-000000000001",
      "title": "PowerShell Encoded Command Execution",
      "description": "Detects PowerShell launched with an encoded command...",
      "level": "high",
      "platform": "windows",
      "logsource": { "product": "windows", "category": "process_creation" },
      "attack": [ { "id":"T1059.001","name":"PowerShell","tactic":"Execution" } ],
      "sigma": "<raw YAML source of the rule file>",
      "tests": { "positive": [ {..} ], "negative": [ {..} ] },
      "conversions": { "splunk": "<query>", "sentinel": "<query>", "elastic": "<query>", "wazuh": "<query>" }
    }
  ]
}
```

- **Platform** is derived from `logsource` / rule path (`windows`, `aws`, `azure`).
- **ATT&CK technique name + tactic** come from a small static map embedded in the exporter
  (the project's techniques are a known, finite set); tactic also cross-checked against the
  rule's `attack.<tactic>` tags.
- `conversions` is `{}` for a backend that is unavailable at generation time.

---

## 5. Frontend (sections + interactions)

- **Hero:** project title, one-line pitch, stat chips (detections / techniques / SIEMs),
  buttons: "View on GitHub", "Browse detections".
- **Catalog:** a filter bar (platform: All/Windows/AWS/Azure; tactic dropdown) + a responsive
  card grid. Each card shows title, platform badge, ATT&CK chips, severity. Selecting a card
  opens a detail panel/modal with **tabs**: Sigma · Splunk · Sentinel · Elastic · Wazuh ·
  Tests. Code shown in styled `<pre><code>` blocks with a "copy" button. If a conversion is
  empty, the tab shows a small "generated on deploy" note.
- **Coverage heatmap:** tactics as columns, technique cells colored by `score` (ATT&CK-style
  gradient). Hover shows technique id + name + detection count.
- **How it works:** a short styled version of the pipeline diagram.
- **Footer:** repo link, MIT license, "Built with detection-forge".

All rendering is client-side from `data.json`; no build step for the frontend itself.

---

## 6. Deployment

`.github/workflows/pages.yml` (separate from the existing CI workflow):
- Triggers: push to `main` + manual `workflow_dispatch`.
- Permissions: `pages: write`, `id-token: write`.
- **build job:** checkout → setup-python 3.11 → `pip install -r requirements.txt` →
  `pip install -r requirements-backends.txt || echo "backends optional"` →
  `python -m forge.cli export` → `actions/upload-pages-artifact` with `path: site`.
- **deploy job:** `needs: build`, environment `github-pages`, `actions/deploy-pages`.

**One-time manual setup (documented for the user):** Repo → Settings → Pages → Build and
deployment → Source → **GitHub Actions**. After that, every push to `main` redeploys.

---

## 7. Look & Feel

Dark, modern **SOC/terminal aesthetic**: near-black background, a single accent color, code
in monospace with syntax-style coloring, ATT&CK-style heat gradient for the coverage matrix,
generous spacing, fully responsive (mobile-friendly cards/tabs). Built to a high bar using
the frontend-design skill. No generic template look.

---

## 8. Local Preview

```bash
python3 -m forge.cli export
python3 -m http.server -d site 8000   # then open http://localhost:8000
```
Offline, the page renders fully except the four SIEM-conversion tabs (which need pySigma and
populate in CI). The Sigma source, ATT&CK chips, test events, and heatmap all preview locally.

---

## 9. Testing

- `tests/test_export.py`: run `forge export` to a temp path; assert valid JSON, exactly 8
  detections, required keys present per detection (`id,title,sigma,attack,tests,conversions`),
  `stats.detections == 8`, and that `conversions` is always a dict (possibly empty).
- The existing test suite must stay green (37 passed, 1 skipped offline).
- Frontend: a minimal smoke check that `index.html` references `assets/app.js`,
  `assets/styles.css`, and fetches `data.json`; visual verification via local preview.

---

## 10. Build Phases

1. `forge/exporter.py` + `forge export` subcommand + `tests/test_export.py`.
2. Frontend scaffold: `index.html`, `assets/styles.css`, `assets/app.js` rendering hero +
   catalog + heatmap from `data.json`.
3. Visual polish to a high bar (dark SOC theme, responsive, copy buttons, code styling).
4. `pages.yml` workflow; document the one-time Pages enablement; deploy.

---

## 11. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| SIEM conversions need pySigma (only in CI). | Exporter includes them when available; frontend shows a graceful note otherwise; live site (CI build) has them. Documented. |
| GitHub Pages must be enabled once by hand. | Documented one-time step; deploy workflow ready so it works immediately after. |
| Frontend complexity creeping toward a framework. | Explicit non-goal; vanilla HTML/CSS/JS only. |
| `data.json` drifting from rules. | It is generated from `rules/` on every deploy — never hand-edited. |
