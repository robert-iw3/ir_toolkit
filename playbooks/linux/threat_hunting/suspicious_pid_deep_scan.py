#!/usr/bin/env python3
"""
suspicious_pid_deep_scan.py - ground-truth YARA + mwcp_parsers follow-up for every PID
the static scan (edr_hunt.py / analyze_memory_linux.py) already flagged.

The static scan's own findings are the trigger, not a prior YARA hit: several
mwcp_parsers families need no YARA/heuristic hit to fire at all, so gating a carve+mwcp
pass on "already had a YARA hit" leaves them unable to ever see the bytes for a PID
flagged by a completely different mechanism (a hidden-process check, a credential-
access finding, a GOT/PLT hook). This reads EDR_Report_*.json and Memory_Findings_*.json
for every PID already named in a finding, deep-scans each one via
linux_yara_worker.py's carve-all mode (every VMA carved unconditionally, YARA re-run
against the same PID list), then runs memory_enrich.py's full enrichment (IOC sweep +
capa/floss + mwcp_parsers) against the carved output.

Usage:
    suspicious_pid_deep_scan.py --report-dir DIR --image PATH [--symbols DIR]
                                [--yara-rules FILE.yarc] [--proc-timeout S]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
_PID_RE = re.compile(r'PID[:\s]+(\d+)')
# Finding Types that are ALREADY a YARA/mwcp_parsers result -- excluded when building the
# target-PID set so a deep-scan doesn't immediately re-trigger itself on its own output.
_ALREADY_DEEP_TYPES = (
    "YARA", "mwcp", "C2 Config", "Ransomware Indicators", "Cloud SaaS", "Delivery Stager",
    "Anti-Analysis", "DNS Tunneling", "SSH Backdoor Artifact", "Cryptominer Config",
    "Botnet Config", "BPFDoor Config", "Exfiltration Channel",
)


def suspicious_pids(report_dir):
    """Every PID mentioned in a static-scan finding's Target field, from BOTH
    EDR_Report_*.json (edr_hunt.py, live-host) and Memory_Findings_*.json
    (analyze_memory_linux.py, image-derived)."""
    pids = set()
    for pattern in ("EDR_Report_*.json", "Memory_Findings_*.json"):
        for fp in glob.glob(os.path.join(report_dir, pattern)):
            try:
                with open(fp, encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            for finding in (data or []):
                ftype = str(finding.get("Type", ""))
                if any(tag in ftype for tag in _ALREADY_DEEP_TYPES):
                    continue
                m = _PID_RE.search(str(finding.get("Target", "")))
                if m:
                    pids.add(m.group(1))
    return pids


def already_deep_scanned(report_dir):
    """PIDs a prior deep-scan run already covered -- resumable across re-runs the same
    way linux_yara_worker.py's own JSONL is."""
    done = set()
    for fp in glob.glob(os.path.join(report_dir, "_deep_scan_*.jsonl")):
        try:
            with open(fp, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if rec.get("t") == "result":
                        done.add(str(rec.get("pid")))
        except OSError:
            continue
    return done


def find_compiled_ruleset(report_dir):
    candidates = sorted(glob.glob(os.path.join(report_dir, "_yara_compiled_*.yarc")),
                        key=os.path.getmtime, reverse=True)
    return candidates[0] if candidates else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report-dir", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--symbols", default="-")
    ap.add_argument("--stamp", default=datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--yara-rules", default=None,
                    help="compiled .yarc (default: the most recent _yara_compiled_*.yarc "
                         "already in --report-dir)")
    ap.add_argument("--proc-timeout", type=int, default=180)
    ap.add_argument("--carve-dir", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    pids = suspicious_pids(args.report_dir) - already_deep_scanned(args.report_dir)
    if not pids:
        if not args.quiet:
            print("[deep-scan] no new suspicious PIDs to follow up")
        return 0
    if not args.quiet:
        print(f"[deep-scan] {len(pids)} suspicious PID(s) from the static scan: {sorted(pids, key=int)}")

    yarc = args.yara_rules or find_compiled_ruleset(args.report_dir)
    worker = os.path.join(HERE, "linux_yara_worker.py")
    have_yara = bool(yarc and os.path.isfile(yarc) and os.path.isfile(worker))
    if not have_yara and not args.quiet:
        print("[deep-scan] no compiled YARA ruleset available -- skipping the YARA re-scan, "
             "carving still runs so mwcp_parsers gets ground-truth bytes", file=sys.stderr)

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
    carve_dir = args.carve_dir or os.path.join(repo_root, "tools", "binja", "data",
                                               f"deepscan_{args.stamp}")
    os.makedirs(carve_dir, exist_ok=True)

    if have_yara:
        jsonl = os.path.join(args.report_dir, f"_deep_scan_{args.stamp}.jsonl")
        env = dict(os.environ)
        env["IR_CARVE_DIR"] = carve_dir
        env["IR_CARVE_ALL_VADS"] = "1"
        if not args.quiet:
            print(f"[deep-scan] YARA + unconditional carve for {len(pids)} PID(s) -> {carve_dir}")
        subprocess.run([sys.executable, worker, args.image, yarc, jsonl, args.symbols,
                        str(args.proc_timeout), ",".join(sorted(pids, key=int))],
                       env=env, check=False)

    enrich = os.path.join(HERE, "memory_enrich.py")
    if not os.path.isdir(carve_dir) or not glob.glob(os.path.join(carve_dir, "*.bin")):
        if not args.quiet:
            print("[deep-scan] nothing carved -- skipping mwcp_parsers/capa/floss enrichment")
        return 0
    if os.path.isfile(enrich):
        if not args.quiet:
            print(f"[deep-scan] mwcp_parsers + IOC/capa/floss enrichment against {carve_dir}")
        r = subprocess.run([sys.executable, enrich, "--carve-dir", carve_dir,
                            "--out-dir", args.report_dir, "--stamp", f"deepscan_{args.stamp}"]
                           + (["--quiet"] if args.quiet else []), check=False)
        return r.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
