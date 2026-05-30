# detection-forge `ingest` — Design Document

- **Status:** Approved (design phase)
- **Date:** 2026-05-30
- **Author:** shulankpatel
- **Builds on:** the detection-forge pipeline (`docs/design.md`) and `forge export` (`docs/website-design.md`)

---

## 1. Overview

`forge ingest <url>` reads a threat-intelligence report (a blog post or vendor write-up),
**extracts the indicators and ATT&CK technique IDs that are explicitly present in the
text**, and drafts a reviewable Sigma rule from them. That draft is written into
`rules/ingested/` and then flows through everything detection-forge already does:
validated, converted to Splunk / Sentinel / Elastic / Wazuh, tested, and shown on the
website. A human reviews and refines the draft before it is trusted.

This is a **rule-based** extractor (no AI/LLM, no API key, deterministic). It captures
what a report states explicitly — it does not interpret free-form behavioral prose.

### One-line pitch
> Paste a threat report URL; get a reviewable, multi-SIEM detection drafted from its
> indicators and ATT&CK mappings.

---

## 2. Goals and Non-Goals

### Goals
- Turn an explicit-indicator report into a **valid, reviewable Sigma draft** in seconds.
- Reuse the existing engine end-to-end (loader → converter → tests → website).
- Zero new runtime dependencies (Python stdlib only).
- Honest output: every draft is `status: experimental`, cites its source, and carries a
  "review required" banner.

### Non-Goals (v1, YAGNI)
- **No AI/LLM** (explicitly chosen). No interpretation of behavioral prose.
- **No PDF parsing** (would add a dependency) — roadmap.
- **No auto-promotion / auto-commit** — a human always reviews before trusting a draft.
- No live network calls in the test suite (tests use a local sample report fixture).

---

## 3. Architecture

```
<url> ──fetch──▶ plain text ──┬─ extract_iocs() ──▶ indicators by type
                              └─ extract_attack() ─▶ ATT&CK technique IDs
                                        │
                                draft_rule() ──▶ Sigma rule (dict)
                                        │
                                write_draft() ──▶ rules/ingested/<slug>.yml
                                                  tests/fixtures/<id>/{positive,negative}.json
                                        │
                          (existing pipeline) loader → converter → tests → forge export → website
```

### New component — `forge/ingest.py` (single responsibility: report → draft)
| Function | Responsibility |
|----------|----------------|
| `load_source(url=None, file=None, text=None)` | Return raw text from a URL (`urllib` GET), a local file, or a passed string. Exactly one source. |
| `to_plain_text(html)` | Strip HTML to text + collect `<code>`/`<pre>` blocks, via stdlib `html.parser`. |
| `extract_iocs(text)` | Return `{type: [values]}` for IPv4, domain, url, md5, sha1, sha256, filepath, regkey, cve, email, cmdline. Stdlib `re`. Dedupe; defang-aware (`hxxp`, `[.]`). (IPv6 extraction is roadmap — a reliable IPv6 regex is fiddly and prone to false matches like MAC addresses.) |
| `extract_attack(text)` | Return deduped, uppercased technique IDs matching `T\d{4}(\.\d{3})?` (e.g. `T1059.001`). The technique name/tactic is attached later by the exporter. |
| `draft_rule(source_ref, iocs, attack, title=None)` | Build a valid Sigma rule dict (see §4). |
| `make_fixtures(rule)` | Return `(positive, negative)` sanity events (see §5). |
| `ingest(source_ref, text, out_dir, fixtures_dir)` | Orchestrate: extract → draft → write rule + fixtures; return the written paths. |

### CLI
`forge ingest <url> [--file PATH] [--out rules/ingested] [--fixtures tests/fixtures]`
added to `forge/cli.py` next to build/test/coverage/export. Prints a summary (counts of
IOCs/techniques found, the written paths, and a "REVIEW before trusting" reminder).

---

## 4. Drafted rule format

```yaml
# AUTO-EXTRACTED by `forge ingest` from https://example.com/report — REVIEW REQUIRED.
# Indicators and ATT&CK IDs were extracted literally from the source; verify the
# logsource and field mappings below before trusting this detection.
title: Indicators from example.com report
id: 7f3c…             # uuid5(URL) — deterministic, so re-ingesting is idempotent
status: experimental
description: Auto-drafted by forge ingest from the cited source. Review required.
references:
  - https://example.com/report
logsource:
  product: windows          # best-guess default — REVIEW
  category: process_creation
detection:
  selection_hash:
    Hashes|contains:
      - <sha256…>
  selection_cmdline:
    CommandLine|contains:
      - <command string from the report>
  condition: 1 of them
level: medium
tags:
  - attack.t1059.001        # from extracted ATT&CK IDs
  - ingested.auto-extracted # always present, so the rule is loader-valid even with no ATT&CK ID
```

- `id = uuid5(NAMESPACE_URL, source_ref)` — deterministic and valid.
- One named selection per IOC type that yielded values; `condition: 1 of them`.
- `tags` always includes `ingested.auto-extracted` (guarantees the loader's non-empty
  `tags` requirement even when a report has no explicit ATT&CK ID), plus any `attack.t*`
  found.

### IOC → Sigma field mapping (heuristic best-guess; reviewer refines)
| Indicator | Field | Default logsource |
|-----------|-------|-------------------|
| md5/sha1/sha256 | `Hashes\|contains` | process_creation |
| command-line string | `CommandLine\|contains` | process_creation |
| file path | `Image\|endswith` | process_creation |
| registry key | `TargetObject\|contains` | registry_event |
| ip / domain / url | `DestinationHostname\|contains` | network |
| cve / email | recorded in `description` (not a detection field) | — |

The single best-guess `logsource` is intentionally conservative; the reviewer corrects it.
This ambiguity is exactly why the chosen workflow is "reviewable draft," not "trusted output."

---

## 5. Sanity fixtures (keep the test harness green)

`make_fixtures(rule)` produces:
- **positive.json** — one synthetic event carrying a value from one selection (e.g.,
  `{"CommandLine": "<an extracted command>"}`) so the rule **fires** (`1 of them` → true).
- **negative.json** — a benign event lacking every indicator (e.g.,
  `{"CommandLine": "powershell -File C:\\\\ok.ps1"}`) so the rule **does not fire**.

These are *sanity* fixtures (they prove the rule is well-formed and matches its own
indicator), explicitly flagged for the reviewer to replace with realistic events.

---

## 6. Integration with the existing pipeline

- Drafts in `rules/ingested/` are picked up automatically by `load_all` → they appear in
  the converter, `forge export` / `data.json`, the ATT&CK coverage, and the **website
  catalog** (optionally badged "auto-extracted"). No pipeline changes required.
- Because the ingester also writes matching fixtures, drafts satisfy the existing
  `tests/test_rules.py` harness (fires on positive, quiet on negative).

---

## 7. Network & testing

- `forge ingest <url>` performs a network fetch **only when you run it** — it is a local,
  interactive authoring command, **not** part of CI.
- **Tests never hit the network.** A committed sample report fixture
  (`tests/fixtures/_ingest/sample_report.html`) with known IOCs + ATT&CK IDs is fed to
  `ingest(...)` writing into a pytest `tmp_path`. Tests assert: expected IOCs/techniques
  extracted; the produced YAML is loader-valid (`forge.loader.load_rule`); the positive
  fixture makes it fire and the negative does not (`forge.validator.matches`). Conversion
  is verified in CI where pySigma is present (skipped offline, like the other converter test).
- The committed rule set stays the curated 8 — the ingester is exercised in isolation
  (tmp dir), so existing tests (`test_export`, `test_rules`) keep their current expectations.

---

## 8. Build Phases

1. `forge/ingest.py`: `extract_iocs` + `extract_attack` (pure-text, fully unit-tested).
2. `draft_rule` + `make_fixtures` + `ingest` orchestration + `load_source`/`to_plain_text`.
3. `forge ingest` CLI subcommand.
4. The committed sample-report fixture + `tests/test_ingest.py`.
5. *(Optional)* website badge for auto-extracted rules.

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Indicator → field/logsource mapping is ambiguous. | Conservative best-guess defaults + `status: experimental` + mandatory human review (the chosen workflow). |
| A report has no explicit ATT&CK ID. | `ingested.auto-extracted` tag is always added so the rule stays loader-valid; ATT&CK chips simply absent. |
| Fetching arbitrary URLs (SSRF/large pages). | Local CLI run by the user against sources they choose; a size cap on fetched bytes; tests use a local fixture, never the network. |
| Defanged indicators (`hxxp`, `1[.]2[.]3[.]4`). | `extract_iocs` re-fangs common patterns before matching. |
| Drafts diluting the curated rule set. | Drafts are isolated under `rules/ingested/`, clearly `experimental`, and never auto-committed. |
