# forge/cli.py
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from forge.loader import load_all
from forge.converter import build_all
from forge.coverage import write_layer

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
DIST = ROOT / "dist"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="forge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="convert rules to all backends")
    sub.add_parser("test", help="run the detection test suite via pytest")
    sub.add_parser("coverage", help="write the ATT&CK layer")
    sub.add_parser("compliance", help="generate compliance control mapping (NIST 800-53 / SOC 2)")
    sub.add_parser("export", help="generate site/data.json for the website")
    dep = sub.add_parser("deploy", help="deploy rules to live SIEM (dry-run mode by default)")
    dep.add_argument("--backend", required=True, choices=["splunk", "elastic", "sentinel"],
                    help="SIEM backend to deploy to")
    dep.add_argument("--dry-run", action="store_true", default=True,
                    help="preview deploy without making changes (default: true)")
    dep.add_argument("--execute", action="store_true",
                    help="actually deploy (requires env vars: SPLUNK_URL/TOKEN, ELASTIC_URL/TOKEN, etc.)")
    ing = sub.add_parser("ingest", help="draft a detection from a threat report URL or file")
    ing.add_argument("url", nargs="?", help="report URL (or use --file)")
    ing.add_argument("--file", help="read a saved report from a local file instead of a URL")
    ing.add_argument("--out", help="output dir for the draft rule (default: rules/ingested)")
    ing.add_argument("--fixtures", help="fixtures dir (default: tests/fixtures)")
    args = parser.parse_args(argv)

    if args.cmd == "test":
        return subprocess.call([sys.executable, "-m", "pytest", "-v"], cwd=ROOT)

    rules = load_all(RULES)
    if args.cmd == "build":
        counts = build_all(rules, DIST)
        print(f"Converted {len(rules)} rules -> {counts}")
    elif args.cmd == "coverage":
        out = write_layer(rules, DIST)
        print(f"Wrote {out}")
    elif args.cmd == "compliance":
        from forge.compliance import write_compliance_report
        out = write_compliance_report(rules, DIST)
        print(f"Wrote {out}")
    elif args.cmd == "deploy":
        from forge.deploy import deploy
        dry_run = not args.execute
        try:
            results = deploy(args.backend, rules, DIST, dry_run=dry_run)
            mode = "dry-run" if dry_run else "live"
            print(f"Deploy to {args.backend} ({mode}):")
            for r in results:
                status_marker = "✓" if r["status"] == "deployed" else "○" if r["status"] == "dry-run" else "✗"
                print(f"  {status_marker} {r['rule_id']:40s} {r['status']:12s}")
                if r.get("message"):
                    for line in r["message"].split("\n"):
                        print(f"      {line}")
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif args.cmd == "export":
        from forge.exporter import build_export_data, write_export
        data = build_export_data(RULES, ROOT / "tests" / "fixtures")
        out = write_export(data, ROOT / "site" / "data.json")
        print(f"Wrote {out} ({data['stats']['detections']} detections, "
              f"{len(data['backends_available'])} live backends)")
    elif args.cmd == "ingest":
        from forge.ingest import load_source, to_plain_text, ingest as run_ingest
        try:
            raw, ref = load_source(url=args.url, file=args.file)
            text = to_plain_text(raw)
            out_dir = args.out or (RULES / "ingested")
            fx_dir = args.fixtures or (ROOT / "tests" / "fixtures")
            res = run_ingest(text, ref, out_dir, fx_dir)
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        found = {k: len(v) for k, v in res["iocs"].items() if v}
        print(f"Drafted {res['rule']}")
        print(f"  source : {ref}")
        print(f"  IOCs   : {found}")
        print(f"  ATT&CK : {res['attack']}")
        print("  NOTE   : status=experimental - REVIEW the draft (and its field mappings) before trusting it.")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
