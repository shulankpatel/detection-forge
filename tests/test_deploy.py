# tests/test_deploy.py
import os
from pathlib import Path
import pytest
from forge.deploy import deploy

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
DIST = ROOT / "dist"


def test_deploy_dry_run_splunk(tmp_path):
    """Dry-run doesn't need env vars, just returns preview."""
    results = deploy("splunk", None, tmp_path, dry_run=True)
    assert isinstance(results, list)
    for r in results:
        assert "rule_id" in r
        assert "backend" in r
        assert "status" in r
        assert "message" in r
        assert r["backend"] == "splunk"


def test_deploy_dry_run_elastic(tmp_path):
    """Dry-run doesn't need env vars, just returns preview."""
    results = deploy("elastic", None, tmp_path, dry_run=True)
    assert isinstance(results, list)
    for r in results:
        assert r["backend"] == "elastic"


def test_deploy_dry_run_sentinel(tmp_path):
    """Dry-run doesn't need env vars, just returns preview."""
    results = deploy("sentinel", None, tmp_path, dry_run=True)
    assert isinstance(results, list)
    for r in results:
        assert r["backend"] == "sentinel"


def test_deploy_unknown_backend_raises():
    """Unknown backend raises ValueError."""
    with pytest.raises(ValueError, match="unknown backend"):
        deploy("unknown_backend", None, DIST, dry_run=True)


def test_deploy_live_splunk_missing_env_vars(tmp_path):
    """Live deploy without env vars raises ValueError."""
    # Clear env vars
    old_url = os.environ.pop("SPLUNK_URL", None)
    old_token = os.environ.pop("SPLUNK_TOKEN", None)
    try:
        with pytest.raises(ValueError, match="required environment variable"):
            deploy("splunk", None, tmp_path, dry_run=False)
    finally:
        if old_url:
            os.environ["SPLUNK_URL"] = old_url
        if old_token:
            os.environ["SPLUNK_TOKEN"] = old_token
