# detection-forge

A Detection-as-Code pipeline: author detections once in [Sigma](https://github.com/SigmaHQ/sigma), then automatically convert, test, and ATT&CK-map them for Splunk, Sentinel, Elastic, and Wazuh — all gated by CI. Detection rules live as Sigma YAML, are validated and unit-tested against sample events by a pure-Python evaluator, converted to per-platform queries via pySigma, and aggregated into a MITRE ATT&CK Navigator coverage layer.

> Full documentation is expanded in a later task.
