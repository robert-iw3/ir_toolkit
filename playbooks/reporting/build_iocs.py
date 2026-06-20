#!/usr/bin/env python3
"""Emit IOCs.json from a collection folder in the ANALYSIS stage.

Runs right after adjudication so the eradication hand-off (which re-blocks known-bad
C2) never depends on report generation having been run. Reporting reuses the same
extraction, so the two never drift.

Usage: build_iocs.py --host-folder DIR [--incident-id ID]
"""
import argparse
import sys

import generate_reports as gr


def main(argv=None):
    p = argparse.ArgumentParser(description="Emit IOCs.json (analysis stage).")
    p.add_argument("--host-folder", required=True)
    p.add_argument("--incident-id", default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    path = gr.emit_iocs(args.host_folder, args.incident_id)
    if not args.quiet:
        print(f"[+] {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
