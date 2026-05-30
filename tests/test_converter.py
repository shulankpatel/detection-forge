# tests/test_converter.py
from pathlib import Path

import pytest

from forge.loader import load_rule
from forge.converter import convert_rule, AVAILABLE_BACKENDS

FIX = Path(__file__).parent / "fixtures" / "_loader" / "valid.yml"


def test_convert_to_splunk_contains_field():
    if "splunk" not in AVAILABLE_BACKENDS:
        pytest.skip("splunk backend not installed")
    rule = load_rule(FIX)
    out = convert_rule(rule, "splunk")
    assert isinstance(out, str) and len(out) > 0
    assert "powershell.exe" in out.lower()


def test_available_backends_is_list():
    assert isinstance(AVAILABLE_BACKENDS, list)


def test_unavailable_backend_raises():
    rule = load_rule(FIX)
    with pytest.raises((ValueError, RuntimeError)):
        convert_rule(rule, "definitely_not_a_backend")
