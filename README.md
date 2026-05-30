# detection-forge

**Write a detection once in Sigma; get tested, ATT&CK-mapped, deploy-ready rules for Splunk, Sentinel, Elastic, and Wazuh — automatically.**

<!-- After pushing to GitHub, update the username/repo in the badge URL below to match your fork (e.g. github.com/<you>/<repo>). -->
[![CI](https://github.com/shulankpatel/detection-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/shulankpatel/detection-forge/actions/workflows/ci.yml)
![Detections](https://img.shields.io/badge/Detections-8-blue)
![ATT&CK techniques](https://img.shields.io/badge/ATT%26CK_techniques-9-red)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**🔗 Live site:** https://shulankpatel.github.io/detection-forge/

## What it does

detection-forge is a **Detection-as-Code** pipeline. You author each detection once as a [Sigma](https://github.com/SigmaHQ/sigma) rule — tagged with its MITRE ATT&CK technique and shipped with sample events — and the engine converts it into per-platform queries for Splunk, Microsoft Sentinel (KQL via the pySigma Microsoft 365 Defender backend; usable in Microsoft Sentinel / Defender XDR advanced hunting), Elastic, and Wazuh,\* unit-tests its logic against the sample events, and aggregates every rule into a MITRE ATT&CK Navigator coverage layer. Every rule is validated and **tested in CI** on each push, so detections that no longer fire correctly (or stop converting) break the build instead of silently rotting in production.

<sub>\* *Elastic/OpenSearch-compatible queries for the Wazuh indexer; a native Wazuh XML backend is on the roadmap.*</sub>

## Quickstart

```bash
git clone https://github.com/shulankpatel/detection-forge.git
cd detection-forge

# Run the detection tests — no install needed beyond pytest + pyyaml (both stdlib-adjacent).
python3 -m pytest          # or: python3 -m forge.cli test

# Build per-platform queries into dist/, and (re)generate the ATT&CK coverage layer.
python3 -m forge.cli build
python3 -m forge.cli coverage
```

- `pip install -e .` registers the short `forge` command, so you can run `forge build` / `forge test` / `forge coverage` instead of `python3 -m forge.cli ...`.
- Converting rules to actual SIEM queries needs the pySigma backends: `pip install -r requirements-backends.txt`. This is done automatically in CI; without the backends, `forge build` simply reports that no backends are available and skips conversion (tests still pass).

## How detections are tested

The test backbone is **pure Python** and needs no SIEM and no network. `forge/validator.py` is a focused Sigma-logic evaluator: for each rule it reads the `detection:` selections and `condition:` and evaluates them against sample JSON events:

- `tests/fixtures/<rule-id>/positive.json` — events the rule **must** match (true positive).
- `tests/fixtures/<rule-id>/negative.json` — events the rule **must not** match (no false positive).

`pytest` parametrizes over every rule's fixtures, so adding a detection automatically adds its true-positive/false-positive assertions. The evaluator supports the Sigma features the bundled rules use — field equality, `contains`, `startswith`/`endswith`, wildcards, nested (dotted) field lookups, and `and`/`or`/`not` plus `1 of` / `all of`.

Conversion to SIEM queries is validated in **CI**, where the pySigma backends are installed. Be aware that the converter's test (`tests/test_converter.py`) **skips locally when pySigma is not installed** — you'll see `1 skipped` in that case. That is expected; the conversion path is exercised in CI.

## Repository layout

Detections are authored **once** under `rules/` (the source of truth) and the engine emits generated, deploy-ready queries under `dist/`, **bifurcated per SIEM** so each team takes only what it needs:

```
rules/                       author once (Sigma YAML, ATT&CK-tagged)
  windows/                     Sysmon / Windows Event Log
  cloud/aws/                   CloudTrail
  cloud/azure/                 Entra ID / Azure AD
        │  forge build
        ▼
dist/
  splunk/    *.spl             Splunk SPL
  sentinel/  *.kql             Microsoft Sentinel KQL (Microsoft 365 Defender backend)
  elastic/   *.ndjson          Elastic detection rules
  wazuh/     *.txt             Elastic/OpenSearch-compatible query for the Wazuh indexer*
  attack-navigator-layer.json  aggregated ATT&CK coverage
```

<sub>\* *Elastic/OpenSearch-compatible queries for the Wazuh indexer; a native Wazuh XML backend is on the roadmap.*</sub>

A Splunk-only team takes `dist/splunk/`; a KQL user takes `dist/sentinel/`; and so on. See [`docs/architecture.md`](docs/architecture.md) for the data-flow diagram and a walkthrough of each engine module.

## ATT&CK coverage

The 8 bundled detections cover 9 ATT&CK techniques:

| ATT&CK ID | Technique | Detection | Platform |
|-----------|-----------|-----------|----------|
| T1059.001 | PowerShell | Encoded PowerShell command execution | Splunk, Sentinel, Elastic, Wazuh |
| T1003.001 | OS Credential Dumping: LSASS Memory | LSASS memory credential access | Splunk, Sentinel, Elastic, Wazuh |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task creation via `schtasks` | Splunk, Sentinel, Elastic, Wazuh |
| T1059 | Command and Scripting Interpreter | Office application spawning a command shell | Splunk, Sentinel, Elastic, Wazuh |
| T1566 | Phishing | Office application spawning a command shell | Splunk, Sentinel, Elastic, Wazuh |
| T1078.004 | Valid Accounts: Cloud Accounts | AWS root account usage | Splunk, Sentinel, Elastic, Wazuh |
| T1562.008 | Impair Defenses: Disable Cloud Logs | AWS CloudTrail logging disabled or tampered | Splunk, Sentinel, Elastic, Wazuh |
| T1098 | Account Manipulation | AWS IAM privilege escalation (policy attach / access key) | Splunk, Sentinel, Elastic, Wazuh |
| T1078 | Valid Accounts | Azure AD multi-factor authentication disabled | Splunk, Sentinel, Elastic, Wazuh |

<sub>\* *Wazuh = Elastic/OpenSearch-compatible queries for the Wazuh indexer; a native Wazuh XML backend is on the roadmap.* The converter emits a query for every registered backend on every rule. Cloud-log detections are typically deployed in Splunk/Sentinel/Elastic, while the Wazuh/OpenSearch query is provided for teams whose indexer holds those logs.</sub>

The aggregated coverage layer is generated to [`dist/attack-navigator-layer.json`](dist/attack-navigator-layer.json). To view the interactive heatmap, open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) and choose **Open Existing Layer → Upload from local**, then select that JSON file. (Optionally, save a screenshot of the rendered heatmap to `docs/img/attack-coverage.png` for your write-up.)

## Roadmap

- Linux (auditd) detections.
- A compliance overlay mapping detections to NIST 800-53 / SOC 2 controls via MITRE CTID mappings.
- Automated rule deployment to a live SIEM via API.

## License

[MIT](LICENSE) © 2026 shulankpatel
