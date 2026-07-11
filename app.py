#!/usr/bin/env python3
"""
detection-forge web server with threat ingestion API.

Serves the static website and provides REST API for threat report ingestion.
Usage: python3 app.py
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS

from forge.loader import load_all
from forge.ingest import load_source, to_plain_text, ingest

app = Flask(__name__, static_folder="site/assets", static_url_path="/assets")
CORS(app)

ROOT = Path(__file__).resolve().parent
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "tests" / "fixtures"
SITE_DIR = ROOT / "site"


@app.route("/")
def index():
    """Serve the main detection catalog page."""
    return send_from_directory(SITE_DIR, "index.html")


@app.route("/data.json")
def data():
    """Serve the exported detection data."""
    data_file = SITE_DIR / "data.json"
    if data_file.exists():
        return send_from_directory(SITE_DIR, "data.json")
    return jsonify({"error": "data.json not found. Run: python3 -m forge.cli export"}), 404


@app.route("/assets/<path:filename>")
def assets(filename):
    """Serve static assets (CSS, JS)."""
    return send_from_directory("site/assets", filename)


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """
    Threat report ingestion API.

    POST /api/ingest with JSON body:
    {
      "source": "url" | "text" | "file",
      "content": "<url>" | "<text>" | "<base64-encoded-file-content>",
      "filename": "optional filename for files"
    }

    Returns:
    {
      "status": "success" | "error",
      "rule_id": "uuid",
      "title": "extracted rule title",
      "description": "auto-generated description",
      "iocs": {ioc_type: [values]},
      "attack_techniques": ["T1059.001", ...],
      "sigma_yaml": "full Sigma YAML rule",
      "conversions": {
        "splunk": "SPL query",
        "sentinel": "KQL query",
        "elastic": "Elastic query",
        "wazuh": "Wazuh XML"
      }
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "no JSON body"}), 400

        source_type = data.get("source")  # "url", "text", or "file"
        content = data.get("content")  # URL string, text string, or base64 file content
        filename = data.get("filename", "uploaded_report")

        if not source_type or not content:
            return jsonify({"status": "error", "message": "missing 'source' or 'content'"}), 400

        # Load the threat report
        try:
            if source_type == "url":
                raw, ref = load_source(url=content)
            elif source_type == "text":
                raw, ref = load_source(text=content)
            elif source_type == "file":
                # Decode base64 file content
                import base64
                try:
                    file_bytes = base64.b64decode(content)
                    raw = file_bytes.decode("utf-8", errors="replace")
                    ref = filename
                except Exception as e:
                    return jsonify({"status": "error", "message": f"failed to decode file: {e}"}), 400
            else:
                return jsonify({"status": "error", "message": f"unknown source type: {source_type}"}), 400
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400

        # Extract plain text (strip HTML if needed)
        text = to_plain_text(raw)

        # Create temp directories for ingest output
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_rules = Path(tmpdir) / "rules"
            tmp_fixtures = Path(tmpdir) / "fixtures"

            # Run ingest
            try:
                result = ingest(text, ref, tmp_rules, tmp_fixtures)
            except ValueError as e:
                return jsonify({"status": "error", "message": str(e)}), 400

            # Load the generated rule and convert it
            rule_path = result["rule"]
            from forge.loader import load_rule
            from forge.converter import convert_rule, AVAILABLE_BACKENDS
            from forge.exporter import _attack, _compliance

            rule = load_rule(rule_path)

            # Generate conversions
            conversions = {}
            for backend in ["splunk", "sentinel", "elastic", "wazuh"]:
                if backend in AVAILABLE_BACKENDS:
                    try:
                        conversions[backend] = convert_rule(rule, backend)
                    except Exception as e:
                        conversions[backend] = f"[conversion failed: {e}]"
                else:
                    conversions[backend] = "[backend not available]"

            # Build response
            return jsonify({
                "status": "success",
                "rule_id": rule.id,
                "title": rule.title,
                "description": rule.raw.get("description", ""),
                "level": rule.raw.get("level", "medium"),
                "logsource": rule.logsource,
                "iocs": result["iocs"],
                "attack_techniques": result["attack"],
                "compliance": _compliance(rule),
                "sigma_yaml": rule.path.read_text(),
                "conversions": conversions,
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"internal error: {str(e)}"}), 500


@app.route("/api/rules", methods=["GET"])
def api_rules():
    """Get all detection rules metadata."""
    try:
        rules = load_all(RULES_DIR)
        return jsonify({
            "count": len(rules),
            "rules": [
                {
                    "id": r.id,
                    "title": r.title,
                    "techniques": r.attack_techniques,
                }
                for r in rules
            ],
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    print("Starting detection-forge web server...")
    print(f"📚 Detection Catalog: http://localhost:{port}")
    print(f"🔍 Threat Ingest API: POST http://localhost:{port}/api/ingest")
    print(f"📊 Rules API: http://localhost:{port}/api/rules")
    print("")
    app.run(debug=debug, host="0.0.0.0", port=port)
