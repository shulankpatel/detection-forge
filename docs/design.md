# detection-forge — Design Document

- **Status:** Approved (design phase)
- **Date:** 2026-05-29
- **Author:** shulankpatel
- **Project type:** Detection-as-Code (DaC) pipeline / security portfolio project

---

## 1. Overview

**detection-forge** is a Detection-as-Code pipeline. A security analyst authors a
detection rule **once** in the vendor-neutral [Sigma](https://github.com/SigmaHQ/sigma)
format. A continuous-integration (CI) pipeline then automatically:

1. **Validates** the rule (syntax + schema + required metadata).
2. **Converts** it into native queries for four SIEM/XDR platforms — Splunk (SPL),
   Microsoft Sentinel (KQL), Elastic, and Wazuh — each written to its own folder.
3. **Tests** that the rule actually works: it fires on malicious sample events and
   stays quiet on benign ones.
4. **Maps** the rule to the MITRE ATT&CK framework and regenerates a coverage heatmap.

The build only passes if every rule is valid and every test is green — detections
are treated like software.

### One-line pitch
> Write a detection once in Sigma; get tested, ATT&CK-mapped, deploy-ready rules for
> Splunk, Sentinel, Elastic, and Wazuh — automatically.

---

## 2. Goals and Non-Goals

### Goals
- Demonstrate **detection engineering** as a disciplined, testable, version-controlled
  practice (the modern industry standard).
- Bridge **Blue Team / SOC** and **Cloud Security** by shipping detections for both
  Windows endpoints and cloud audit logs.
- Be **reproducible by anyone**: `git clone`, `pip install`, `pytest` — no paid tooling,
  no mandatory infrastructure.
- Produce **portfolio-grade artifacts**: a clean README with badges, an ATT&CK coverage
  heatmap, and a blog-ready write-up.
- Showcase the author's **Python engineering** through a small, well-structured engine
  with real unit tests.

### Non-Goals (v1 — explicitly out of scope, YAGNI)
- A web UI or hosted service. (Outputs are files + an ATT&CK Navigator layer.)
- Supporting every SIEM in existence — only the four chosen backends.
- A full, general-purpose Sigma condition-grammar engine — the validator supports the
  Sigma features the bundled rules actually use, and is extended as new rules need them.
- Automatically deploying rules into a live SIEM. (The live demo is a documented,
  optional, manual showcase — not part of the automated pipeline.)
- Real-time alerting / SOAR response automation.

---

## 3. Background — Why This Project

Compliance frameworks and SOC job requirements increasingly expect analysts to **write
and maintain detections as code**: version-controlled in git, converted to the team's
SIEM, and tested in CI before deployment. Senior SOC interviews now commonly include a
"write a Sigma or KQL rule that catches behavior X" exercise. Most junior candidates
have, at best, screenshots of a SIEM lab. A working, tested, multi-backend DaC pipeline
is a strong differentiator that maps directly to mid/senior detection-engineering work.

---

## 4. Architecture

### 4.1 Components

| Component | File | Responsibility | Depends on |
|-----------|------|----------------|------------|
| **Loader** | `forge/loader.py` | Discover Sigma rule files, parse YAML, validate schema + required metadata (id, title, `tags` with ATT&CK, logsource). | PyYAML |
| **Converter** | `forge/converter.py` | Convert each validated rule to SPL / KQL / Elastic / Wazuh and write to `dist/<platform>/`. | pySigma + backend plugins |
| **Validator** | `forge/validator.py` | Evaluate a rule's `detection`/`condition` logic against positive/negative sample events; assert correct firing. | (pure Python) |
| **Coverage** | `forge/coverage.py` | Aggregate ATT&CK `tags` across all rules; emit a MITRE ATT&CK Navigator layer JSON. | (pure Python) |
| **CLI** | `forge/cli.py` | Entry point: `forge build`, `forge test`, `forge coverage`. | argparse / click |

Each component has one clear purpose, a small public interface, and can be unit-tested
in isolation.

### 4.2 Folder structure

```
detection-forge/
├── rules/                      # authored ONCE here (source of truth)
│   ├── windows/                #   Sysmon / Windows Event Log detections
│   └── cloud/
│       ├── aws/                #   CloudTrail detections
│       └── azure/              #   Entra ID / Azure AD detections
├── forge/                      # the Python engine (the author's code)
│   ├── __init__.py
│   ├── loader.py
│   ├── converter.py
│   ├── validator.py
│   ├── coverage.py
│   └── cli.py
├── tests/                      # pytest + per-rule sample events
│   ├── test_loader.py
│   ├── test_converter.py       #   golden-file: rule -> expected query
│   ├── test_validator.py
│   ├── test_coverage.py
│   └── fixtures/
│       └── <rule-id>/
│           ├── positive.json   #   event(s) that SHOULD fire
│           └── negative.json   #   event(s) that should NOT fire
├── dist/                       # GENERATED output, bifurcated per platform
│   ├── splunk/                 #   *.spl / savedsearches.conf
│   ├── sentinel/               #   *.kql
│   ├── elastic/                #   *.ndjson / rule JSON
│   ├── wazuh/                  #   *.xml
│   └── attack-navigator-layer.json
├── docs/
│   ├── design.md               #   this document
│   ├── architecture.md         #   diagram + component walkthrough
│   └── live-demo.md            #   Docker + Atomic Red Team showcase runbook
├── .github/workflows/ci.yml    # lint -> convert -> test -> coverage
├── README.md
├── LICENSE                     # MIT
├── pyproject.toml
├── requirements.txt
└── .gitignore
```

The `dist/` layout is intentionally **bifurcated by platform** so a Splunk-only team
takes `dist/splunk/`, a KQL user takes `dist/sentinel/`, etc. — each backend's rules
are independently usable.

### 4.3 Data flow

```
author Sigma rule (ATT&CK tags + sample events)
        │  git push
        ▼
  ┌── CI pipeline (.github/workflows/ci.yml) ──────────────┐
  │  loader     → validate every rule                       │
  │  converter  → emit queries to dist/<platform>/          │
  │  validator  → run positive/negative samples, assert     │
  │  coverage   → regenerate attack-navigator-layer.json    │
  └─────────────────────────────────────────────────────────┘
        │  pass only if all rules valid AND all tests green
        ▼
  README badges update · ATT&CK heatmap · deploy-ready dist/
```

---

## 5. SIEM Backends and Output Layout

| Backend | Conversion target | Output in `dist/` |
|---------|-------------------|-------------------|
| Splunk | SPL (Splunk search) | `dist/splunk/*.spl` |
| Microsoft Sentinel | KQL (Kusto) | `dist/sentinel/*.kql` |
| Elastic | Lucene / ES\|QL | `dist/elastic/*.ndjson` |
| Wazuh | Wazuh rule XML (or Elastic-compatible fallback) | `dist/wazuh/*.xml` |

> **Note:** exact pySigma backend plugin names/versions are pinned during Phase 2 when
> the converter is implemented; if a backend plugin is unavailable or immature, the
> design records the substitute used (e.g., an Elastic-compatible export for Wazuh).

---

## 6. Validation Strategy (Layered)

### 6.1 Backbone — automated, reproducible, no infrastructure (v1)
`forge/validator.py` implements a focused Sigma-logic evaluator in pure Python. For each
rule it reads the `detection:` selections and `condition:` and evaluates them against
sample JSON events:
- `tests/fixtures/<rule-id>/positive.json` — the rule **must** match (true positive).
- `tests/fixtures/<rule-id>/negative.json` — the rule **must not** match (no false positive).

This runs anywhere with only `pip install` and is executed by `pytest` in CI. The
evaluator supports the Sigma features the bundled rules use (field equality, `contains`,
`startswith`/`endswith`, wildcards, `and`/`or`/`not`, `1 of`/`all of`) and is extended as
new rules require.

### 6.2 Showcase — documented, optional, manual
`docs/live-demo.md` is a runbook to:
1. Spin up Elastic in Docker.
2. Load the converted rules from `dist/elastic/`.
3. Run a couple of [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
   tests to generate real attack telemetry.
4. Screenshot the alerts firing.

This produces the "live SIEM" evidence for the blog write-up but is **not** required to
run or pass the repo's CI.

---

## 7. Starter Detections (8)

Each ships ATT&CK-tagged with `positive.json` + `negative.json` fixtures.

**Windows (Sysmon / Security Event Log):**
1. Encoded PowerShell command — `T1059.001`
2. LSASS credential access (mimikatz-style) — `T1003.001`
3. Scheduled-task persistence — `T1053.005`
4. Office application spawning a shell — `T1566` / `T1059`

**Cloud (AWS CloudTrail / Azure AD):**
5. AWS root-account usage — `T1078.004`
6. CloudTrail `StopLogging` (defense evasion) — `T1562.008`
7. AWS `AdministratorAccess` attached / access key created — `T1098`
8. Azure AD MFA disabled / risky sign-in — `T1078`

This set is deliberately split across **endpoint** and **cloud** telemetry to bridge the
Blue Team and Cloud Security focus areas in a single repository.

---

## 8. MITRE ATT&CK Coverage

Every rule carries `tags: [attack.tXXXX...]`. `forge/coverage.py` aggregates these and
emits `dist/attack-navigator-layer.json`, loadable directly in the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to render a coverage
heatmap. A screenshot of this heatmap is the visual centerpiece of the README.

---

## 9. CI/CD Pipeline

`.github/workflows/ci.yml`, triggered on every push and pull request:

1. Checkout + set up Python + install dependencies.
2. **Lint:** `sigma check` on all rules + `ruff` on Python.
3. **Build:** `forge build` → conversions written to `dist/`.
4. **Test:** `pytest` → unit tests + every rule's positive/negative fixtures.
5. **Coverage:** `forge coverage` → regenerate the ATT&CK layer.
6. Fail the build if any rule is invalid or any test fails.

README badges: build status, rule count, and number of ATT&CK techniques covered.

---

## 10. Tech Stack

- **Python 3.11+** — engine + tests
- **pySigma** + backend plugins — rule conversion
- **PyYAML** — rule parsing
- **pytest** — test harness
- **ruff** — linting; **mypy** optional for typing
- **GitHub Actions** — CI
- **Docker + Elastic + Atomic Red Team** — live demo only (not in CI)

---

## 11. Testing Strategy

- **Unit tests** for loader, converter (golden-file: rule → expected query string),
  validator, and coverage.
- **Rule fixtures** — positive/negative sample events per detection.
- **CI gates** — lint, tests, successful conversion, and coverage regeneration must all
  pass before merge.

---

## 12. Build Phases / Milestones

| Phase | Deliverable |
|-------|-------------|
| 1 | Repo skeleton, tooling, CI scaffold, and **one** rule working end-to-end (vertical slice: author → convert → test → coverage). |
| 2 | Converter for all four backends + the validator evaluator. |
| 3 | Author the 8 starter detections + their test fixtures. |
| 4 | ATT&CK coverage layer + README, badges, and `docs/architecture.md`. |
| 5 | *(Showcase)* `docs/live-demo.md` runbook. |

Estimated effort: ~3–5 weekends for a polished v1.

---

## 13. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| A pySigma backend plugin is immature or missing (esp. Wazuh). | Pin versions in Phase 2; document any substitute (e.g., Elastic-compatible export) directly in the README and §5. |
| Writing a full Sigma condition parser balloons scope. | Scope the validator to the features the bundled rules use; grow it rule-by-rule. Documented as a non-goal. |
| Sample events drift from real-world log schemas. | Base fixtures on documented field names (Sysmon schema, AWS CloudTrail record format, Azure AD sign-in schema) and cite sources in fixtures. |
| Project reads as "just glue around a CLI." | Engine + test harness are first-class, unit-tested Python; conversion leans on pySigma but orchestration/validation/coverage are original. |

---

## 14. Future Work (post-v1)

- Add Linux (auditd) detections.
- A "compliance overlay" mapping detections to NIST 800-53 / SOC 2 controls via MITRE
  CTID mappings (links toward the GRC focus area — a natural follow-on project).
- Automated rule deployment to a live SIEM via API.
- A simple HTML coverage dashboard generated in CI.
