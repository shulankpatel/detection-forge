"""Validate detections against REAL attack telemetry, not hand-authored fixtures.

Each mapped rule must fire on at least one event in a genuine malicious sample
from EVTX-ATTACK-SAMPLES. Samples are fetched by ``scripts/fetch_samples.py``
(gitignored, GPL-licensed, not redistributed); these tests skip cleanly when the
samples are absent so the core suite never depends on a network fetch.

This is the difference between "I wrote a fixture that makes my rule pass" and
"my rule fires on a real Mimikatz/meterpreter LSASS dump."
"""
from pathlib import Path

import pytest

from forge.evtx_source import parse_evtx
from forge.loader import load_all
from forge.validator import matches

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
RULES = {r.path.stem: r for r in load_all(ROOT / "rules")}

# rule stem -> a real EVTX-ATTACK-SAMPLES file that genuinely triggers it.
REAL_TELEMETRY = {
    "scheduled_task_creation": "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
    "lsass_credential_access": "CA_sysmon_hashdump_cmd_meterpreter.evtx",
}


@pytest.mark.parametrize("stem,sample", sorted(REAL_TELEMETRY.items()))
def test_rule_fires_on_real_attack_telemetry(stem, sample):
    sample_path = SAMPLES / sample
    if not sample_path.exists():
        pytest.skip(f"sample not fetched: {sample} (run: python3 scripts/fetch_samples.py)")
    rule = RULES[stem]
    events = parse_evtx(sample_path)
    hits = [e for e in events if matches(rule.detection, e)]
    assert hits, f"{stem} did not fire on any of {len(events)} real events in {sample}"
