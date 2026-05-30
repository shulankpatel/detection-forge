# Architecture

detection-forge is a small, single-purpose engine: it turns ATT&CK-tagged Sigma rules into tested, per-platform SIEM queries and an ATT&CK coverage map. Authoring happens once under `rules/`; everything in `dist/` is generated. The whole flow runs in CI on every push.

## Data flow

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

## Modules

Each module in `forge/` has one clear responsibility and a small public interface, so it can be unit-tested in isolation.

- **`forge/loader.py`** — Discovers Sigma rule files (`rules/**/*.yml`), parses the YAML, and validates each rule against the required schema: `id`, `title`, `logsource`, `detection` (with a `condition`), and ATT&CK `tags`. It returns `Rule` dataclasses and exposes `attack_techniques`, which extracts the `attack.tXXXX` technique IDs from the tags. Invalid rules raise `RuleValidationError`. Depends only on PyYAML.

- **`forge/validator.py`** — A pure-Python Sigma-logic evaluator. `matches(detection, event)` evaluates a rule's `detection` selections and `condition` string against a single JSON event. It supports field equality, the `contains` / `startswith` / `endswith` / `re` modifiers, glob wildcards, nested (dotted) field lookups, the boolean operators `and` / `or` / `not`, grouping with parentheses, and the `1 of` / `all of` aggregations. This is the engine behind the per-rule positive/negative fixture tests and needs no third-party dependencies.

- **`forge/converter.py`** — Converts each validated rule into per-platform queries via pySigma and its backend plugins, writing them under `dist/<platform>/` (Splunk SPL, Sentinel KQL, Elastic NDJSON, Wazuh). pySigma and its backends are imported defensively, so the module is always import-safe; if a backend is missing it is simply skipped, and `build_all` creates each backend's output directory lazily so a backend that yields no output leaves no empty directory. A single failing rule is logged and skipped rather than aborting the whole backend.

- **`forge/coverage.py`** — Aggregates ATT&CK technique tags across all rules and emits a MITRE ATT&CK Navigator layer (`dist/attack-navigator-layer.json`), scoring each technique by how many detections cover it. Pure Python.

- **`forge/cli.py`** — The command-line entry point (`forge build`, `forge coverage`, also runnable as `python -m forge.cli ...`). It loads all rules once, then dispatches to the converter or the coverage generator. Built on `argparse`.

## Output layout

The `dist/` tree is intentionally **bifurcated by platform** — `dist/splunk/`, `dist/sentinel/`, `dist/elastic/`, `dist/wazuh/` — so each consuming team takes only the format it uses, plus the shared `dist/attack-navigator-layer.json` coverage map.
