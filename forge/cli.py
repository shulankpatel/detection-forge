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
    sub.add_parser("export", help="generate site/data.json for the website")
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
