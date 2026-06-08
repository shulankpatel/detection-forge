"""Parse real Windows EVTX attack telemetry into flat event dicts that
``forge.validator.matches()`` can evaluate Sigma detections against.

This lets detections be validated against genuine attack samples (e.g.
EVTX-ATTACK-SAMPLES) rather than only hand-authored fixtures — the difference
between "I think this rule works" and "this rule fires on a real Mimikatz dump."
"""
from __future__ import annotations

from xml.etree import ElementTree as ET


def _local(tag: str) -> str:
    """Strip any XML namespace prefix from an element tag (``{ns}Name`` -> ``Name``)."""
    return tag.rsplit("}", 1)[-1]


def flatten_record(xml_string: str) -> dict:
    """Flatten one Windows Event XML record into a ``{field: value}`` dict.

    Pulls ``EventID`` from ``<System>`` and every ``<Data Name="...">`` from
    ``<EventData>``, keyed by the ``Name`` attribute — exactly how Sysmon fields
    (Image, CommandLine, TargetImage, GrantedAccess, ...) appear in the log.
    Namespace-agnostic so it works on raw EVTX XML and stripped XML alike.
    """
    root = ET.fromstring(xml_string)
    event: dict = {}
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "EventID" and el.text:
            event["EventID"] = el.text.strip()
        elif tag == "Data":
            name = el.get("Name")
            if name:
                event[name] = el.text
    return event


def parse_evtx(path) -> list[dict]:
    """Parse a Windows ``.evtx`` file into a list of flattened event dicts.

    Requires the optional ``python-evtx`` dependency (``pip install python-evtx``).
    Malformed records are skipped rather than aborting the whole file.
    """
    try:
        import Evtx.Evtx as evtx  # lazy import: only needed to read real files
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError(
            "parse_evtx requires python-evtx — install it with: pip install python-evtx"
        ) from exc

    events: list[dict] = []
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                events.append(flatten_record(record.xml()))
            except ET.ParseError:
                continue
    return events
