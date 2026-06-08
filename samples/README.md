# Real attack-telemetry samples

This directory holds real Windows `.evtx` attack telemetry used to validate
detections against genuine adversary activity (not hand-authored fixtures).

**The `.evtx` files here are not committed.** They come from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), which
is licensed **GPL-3.0**. To keep this repository MIT-clean we do not redistribute
them; instead they are fetched on demand:

```bash
python3 scripts/fetch_samples.py
```

CI runs that script before the test step, so `tests/test_real_telemetry.py`
validates every mapped rule against real telemetry on each push. When the samples
are absent (e.g. offline, or a fresh clone before fetching), those tests skip
cleanly and the rest of the suite is unaffected.

Credit: EVTX-ATTACK-SAMPLES by [@sbousseaden](https://github.com/sbousseaden).
