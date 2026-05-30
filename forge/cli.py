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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
