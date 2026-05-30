# tests/test_validator.py
from forge.validator import matches

def _rule(detection):
    return {"detection": detection}

def test_simple_equality():
    det = {"selection": {"EventID": 1}, "condition": "selection"}
    assert matches(det, {"EventID": 1}) is True
    assert matches(det, {"EventID": 2}) is False

def test_endswith_and_contains_modifiers():
    det = {"selection": {"Image|endswith": "\\powershell.exe"}, "condition": "selection"}
    assert matches(det, {"Image": "C:\\Windows\\System32\\powershell.exe"}) is True
    assert matches(det, {"Image": "C:\\Windows\\cmd.exe"}) is False

def test_wildcard_value():
    det = {"selection": {"CommandLine": "*-enc*"}, "condition": "selection"}
    assert matches(det, {"CommandLine": "powershell -enc ZQBjAGgA"}) is True
    assert matches(det, {"CommandLine": "powershell -file x.ps1"}) is False

def test_list_value_is_or():
    det = {"selection": {"EventID": [1, 4688]}, "condition": "selection"}
    assert matches(det, {"EventID": 4688}) is True
    assert matches(det, {"EventID": 7}) is False

def test_and_or_not_condition():
    det = {
        "sel_a": {"EventID": 1},
        "sel_b": {"User": "root"},
        "filter": {"Image|endswith": "\\safe.exe"},
        "condition": "sel_a and sel_b and not filter",
    }
    assert matches(det, {"EventID": 1, "User": "root", "Image": "x\\bad.exe"}) is True
    assert matches(det, {"EventID": 1, "User": "root", "Image": "x\\safe.exe"}) is False

def test_one_of_them():
    det = {"sel_a": {"EventID": 1}, "sel_b": {"EventID": 4688}, "condition": "1 of them"}
    assert matches(det, {"EventID": 4688}) is True
    assert matches(det, {"EventID": 9}) is False

def test_all_of_pattern():
    det = {"sel_x": {"A": 1}, "sel_y": {"B": 2}, "condition": "all of sel_*"}
    assert matches(det, {"A": 1, "B": 2}) is True
    assert matches(det, {"A": 1, "B": 9}) is False


def test_nested_field_lookup():
    det = {"selection": {"userIdentity.type": "Root"}, "condition": "selection"}
    assert matches(det, {"userIdentity": {"type": "Root"}}) is True
    assert matches(det, {"userIdentity": {"type": "IAMUser"}}) is False
    assert matches(det, {"other": 1}) is False
