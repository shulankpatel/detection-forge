# forge/deploy.py
"""Automated deployment to live SIEM platforms (Splunk, Elastic, Sentinel).

Supports dry-run mode for safe preview of what would be deployed.
Configuration via environment variables:
  - Splunk:   SPLUNK_URL, SPLUNK_TOKEN
  - Elastic:  ELASTIC_URL, ELASTIC_TOKEN
  - Sentinel: SENTINEL_WORKSPACE_ID, SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_TOKEN
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path


def _get_env(key, default=None, required=True):
    """Get env var, raise clear error if required and missing."""
    val = os.environ.get(key)
    if val is None:
        if required:
            raise ValueError(f"required environment variable not set: {key}")
        return default
    return val


def deploy_to_splunk(rules, dist_dir: Path, dry_run=False) -> list[dict]:
    """Deploy to Splunk saved searches.

    Config: SPLUNK_URL (e.g., https://splunk.example.com:8089), SPLUNK_TOKEN
    Endpoint: POST /servicesNS/nobody/search/saved/searches
    """
    base_url = _get_env("SPLUNK_URL", default="https://localhost:8089", required=not dry_run)
    token = _get_env("SPLUNK_TOKEN", default="demo-token", required=not dry_run)
    if base_url and not base_url.endswith("/"):
        base_url = base_url + "/"

    results = []
    spl_dir = Path(dist_dir) / "splunk"
    if not spl_dir.exists():
        return [{"rule_id": "n/a", "backend": "splunk", "status": "skipped", "message": "no SPL rules generated"}]

    for rule_file in spl_dir.glob("*.spl"):
        rule_id = rule_file.stem
        query = rule_file.read_text().strip()
        endpoint = f"{base_url}servicesNS/nobody/search/saved/searches"

        result = {
            "rule_id": rule_id,
            "backend": "splunk",
            "status": "pending",
            "message": "",
        }

        if dry_run:
            result["status"] = "dry-run"
            result["message"] = f"POST {endpoint}\nContent-Type: application/x-www-form-urlencoded\nAuthorization: Bearer {token[:20]}...\n\nname={rule_id}&search={query[:80]}..."
            results.append(result)
            continue

        try:
            body = f"name={rule_id}&search={urllib.parse.quote(query)}".encode()
            req = urllib.request.Request(
                endpoint,
                data=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    result["status"] = "deployed"
                else:
                    result["status"] = "failed"
                    result["message"] = f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            result["status"] = "failed"
            result["message"] = f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        results.append(result)

    return results


def deploy_to_elastic(rules, dist_dir: Path, dry_run=False) -> list[dict]:
    """Deploy to Elastic detection engine.

    Config: ELASTIC_URL (e.g., https://elastic.example.com:9200), ELASTIC_TOKEN
    Endpoint: PUT /_security/detection_engine/rules
    """
    base_url = _get_env("ELASTIC_URL", default="https://localhost:9200", required=not dry_run)
    token = _get_env("ELASTIC_TOKEN", default="demo-token", required=not dry_run)
    if base_url and not base_url.endswith("/"):
        base_url = base_url + "/"

    results = []
    ndjson_dir = Path(dist_dir) / "elastic"
    if not ndjson_dir.exists():
        return [{"rule_id": "n/a", "backend": "elastic", "status": "skipped", "message": "no Elastic rules generated"}]

    for rule_file in ndjson_dir.glob("*.ndjson"):
        rule_id = rule_file.stem
        rule_content = rule_file.read_text().strip()
        endpoint = f"{base_url}_security/detection_engine/rules"

        result = {
            "rule_id": rule_id,
            "backend": "elastic",
            "status": "pending",
            "message": "",
        }

        if dry_run:
            result["status"] = "dry-run"
            result["message"] = f"PUT {endpoint}\nAuthorization: Bearer {token[:20]}...\nContent-Type: application/json\n\n{rule_content[:100]}..."
            results.append(result)
            continue

        try:
            req = urllib.request.Request(
                endpoint,
                data=rule_content.encode(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="PUT",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    result["status"] = "deployed"
                else:
                    result["status"] = "failed"
                    result["message"] = f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            result["status"] = "failed"
            result["message"] = f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        results.append(result)

    return results


def deploy_to_sentinel(rules, dist_dir: Path, dry_run=False) -> list[dict]:
    """Deploy to Microsoft Sentinel analytics rules.

    Config: SENTINEL_WORKSPACE_ID, SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_TOKEN
    Endpoint: PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules/{ruleId}
    """
    workspace_id = _get_env("SENTINEL_WORKSPACE_ID", required=not dry_run)
    subscription_id = _get_env("SENTINEL_SUBSCRIPTION_ID", required=not dry_run)
    resource_group = _get_env("SENTINEL_RESOURCE_GROUP", required=not dry_run)
    token = _get_env("SENTINEL_TOKEN", required=not dry_run)

    results = []
    kql_dir = Path(dist_dir) / "sentinel"
    if not kql_dir.exists():
        return [{"rule_id": "n/a", "backend": "sentinel", "status": "skipped", "message": "no Sentinel rules generated"}]

    base_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/"
        f"resourceGroups/{resource_group}/"
        f"providers/Microsoft.OperationalInsights/workspaces/{workspace_id}/"
        f"providers/Microsoft.SecurityInsights/alertRules/"
    )

    for rule_file in kql_dir.glob("*.kql"):
        rule_id = rule_file.stem
        query = rule_file.read_text().strip()
        endpoint = f"{base_url}{rule_id}?api-version=2021-10-01"

        result = {
            "rule_id": rule_id,
            "backend": "sentinel",
            "status": "pending",
            "message": "",
        }

        if dry_run:
            result["status"] = "dry-run"
            result["message"] = f"PUT {endpoint}\nAuthorization: Bearer {token[:20]}...\nContent-Type: application/json\n\nRuleID={rule_id}, Query={query[:80]}..."
            results.append(result)
            continue

        rule_payload = {
            "kind": "Scheduled",
            "properties": {
                "displayName": rule_id,
                "description": f"Detection rule {rule_id}",
                "severity": "Medium",
                "enabled": True,
                "query": query,
                "queryFrequency": "PT5M",
                "queryPeriod": "PT5M",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False,
            },
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(rule_payload).encode(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="PUT",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    result["status"] = "deployed"
                else:
                    result["status"] = "failed"
                    result["message"] = f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            result["status"] = "failed"
            result["message"] = f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        results.append(result)

    return results


def deploy(backend: str, rules, dist_dir: Path, dry_run=False) -> list[dict]:
    """Dispatcher: route to correct SIEM backend."""
    if backend == "splunk":
        return deploy_to_splunk(rules, dist_dir, dry_run)
    elif backend == "elastic":
        return deploy_to_elastic(rules, dist_dir, dry_run)
    elif backend == "sentinel":
        return deploy_to_sentinel(rules, dist_dir, dry_run)
    else:
        raise ValueError(f"unknown backend: {backend}; supported: splunk, elastic, sentinel")
