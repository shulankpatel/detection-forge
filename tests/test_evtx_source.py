"""Tests for forge.evtx_source — turning real Windows EVTX records into flat
event dicts the Sigma validator can match against."""
from pathlib import Path

import pytest

from forge.evtx_source import flatten_record, parse_evtx

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SCHTASK_SAMPLE = SAMPLES / "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"

# A namespaced Sysmon process-creation (EventID 1) record, mirroring real EVTX XML.
SYSMON_PROC_CREATE = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    "<System><EventID>1</EventID>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>"
    "<EventData>"
    '<Data Name="Image">C:\\Windows\\System32\\schtasks.exe</Data>'
    '<Data Name="CommandLine">"schtasks.exe" /Create /sc MINUTE /TN x /F</Data>'
    '<Data Name="ParentImage">C:\\Windows\\System32\\mshta.exe</Data>'
    "</EventData></Event>"
)


def test_flatten_extracts_event_id():
    ev = flatten_record(SYSMON_PROC_CREATE)
    assert ev["EventID"] == "1"


def test_flatten_extracts_eventdata_fields_by_name():
    ev = flatten_record(SYSMON_PROC_CREATE)
    assert ev["Image"].endswith("schtasks.exe")
    assert ev["ParentImage"].endswith("mshta.exe")
    assert "/Create" in ev["CommandLine"]


def test_flatten_handles_xml_without_namespace():
    xml = (
        "<Event><System><EventID>10</EventID></System>"
        '<EventData><Data Name="TargetImage">C:\\Windows\\system32\\lsass.exe</Data>'
        '<Data Name="GrantedAccess">0x1410</Data></EventData></Event>'
    )
    ev = flatten_record(xml)
    assert ev["EventID"] == "10"
    assert ev["TargetImage"].endswith("lsass.exe")
    assert ev["GrantedAccess"] == "0x1410"


@pytest.mark.skipif(
    not SCHTASK_SAMPLE.exists(),
    reason="EVTX sample not fetched (run: python3 scripts/fetch_samples.py)",
)
def test_parse_evtx_yields_real_events():
    events = parse_evtx(SCHTASK_SAMPLE)
    assert len(events) > 0
    # the sample contains a real schtasks.exe process-creation event
    assert any((e.get("Image") or "").lower().endswith("schtasks.exe") for e in events)
