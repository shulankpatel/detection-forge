#!/usr/bin/env python3
"""Fetch the real attack-telemetry samples used by tests/test_real_telemetry.py.

Downloads specific EVTX files from EVTX-ATTACK-SAMPLES into ./samples/. Those
files are GPL-3.0 and are NOT redistributed in this repo (samples/ is gitignored);
we fetch them on demand instead. CI runs this before the test step, so detections
are validated against genuine attack telemetry on every push.

Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0)

Usage:
    python3 scripts/fetch_samples.py
"""
from __future__ import annotations

import sys
import urllib.parse
import urllib.request
from pathlib import Path

RAW_BASE = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

# local filename -> upstream path within EVTX-ATTACK-SAMPLES
SAMPLES = {
    "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx": (
        "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
    ),
    "CA_sysmon_hashdump_cmd_meterpreter.evtx": (
        "Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx"
    ),
}


def fetch() -> int:
    """Download any missing samples. Returns the number of failures."""
    SAMPLES_DIR.mkdir(exist_ok=True)
    failures = 0
    for local, upstream in sorted(SAMPLES.items()):
        dest = SAMPLES_DIR / local
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[skip] {local} (already present)")
            continue
        url = RAW_BASE + urllib.parse.quote(upstream)
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (trusted host)
                data = resp.read()
            dest.write_bytes(data)
            print(f"[ok]   {local} ({len(data)} bytes)")
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"[fail] {local}: {exc}", file=sys.stderr)
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(1 if fetch() else 0)
