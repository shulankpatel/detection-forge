# Real attack-telemetry validation

Most detection portfolios test rules against fixtures the author wrote by hand.
That proves a rule fires on the events you *imagined*, not on what an attacker
*actually does*. detection-forge closes that gap: selected rules are validated
against genuine malicious telemetry from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), parsed
straight out of real `.evtx` files.

## How it works

1. `scripts/fetch_samples.py` downloads specific attack samples into `samples/`
   (GPL-3.0, fetched not vendored — see `samples/README.md`).
2. `forge/evtx_source.py` parses each `.evtx` into flat event dicts.
3. `tests/test_real_telemetry.py` runs the existing Sigma rules — via the same
   pure-Python evaluator used everywhere else — against those real events and
   asserts each mapped rule fires on at least one of them.

This runs in CI on every push. No SIEM, no VM.

## What it caught (and this is the point)

Validating against real telemetry immediately surfaced a real detection gap.

**Rule:** `lsass_credential_access` (T1003.001 — LSASS memory access)
**Sample:** `CA_sysmon_hashdump_cmd_meterpreter.evtx` (meterpreter hashdump)

The rule's `GrantedAccess` allowlist was `[0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff]`
— the classic Mimikatz masks. But the real meterpreter dump opened LSASS with:

```
SourceImage:  \\VBOXSVR\HTools\voice_mail.msg.exe
TargetImage:  C:\Windows\system32\lsass.exe
GrantedAccess: 0x001f1fff
```

`0x001f1fff` was **not** in the allowlist. The rule silently missed a real
credential-dumping technique. A hand-written fixture would never have caught
this, because I'd have written the fixture to match the rule I already had.

**Fix:** added the broad-access masks meterpreter/comsvcs MiniDump actually use
(`0x1f1fff` and its leading-zero log form `0x001f1fff`, plus `0x1f3fff`), with a
comment citing the sample. The existing fixture tests still pass (no regression),
and the rule now fires on the real dump.

## Current coverage

| Rule | Technique | Real sample | Result |
|------|-----------|-------------|--------|
| `scheduled_task_creation` | T1053.005 | `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx` | fires ✓ |
| `lsass_credential_access` | T1003.001 | `CA_sysmon_hashdump_cmd_meterpreter.evtx` | fires after tuning ✓ |

Extending coverage is just adding a `{rule_stem: sample_file}` entry to
`REAL_TELEMETRY` in the test and the corresponding download to
`scripts/fetch_samples.py`.
