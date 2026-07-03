"""Calibrate the IsolationForest noise-filter baseline from live report data.

The noise filter's benign baseline (models/noise_filter.py _benign_baseline())
is entirely synthetic -- authored from the worked examples in the investigation
guide, not from what this environment's processes actually look like. This
script extracts REAL feature vectors from collected reports and adds them to
the baseline the forest trains on, so it reflects the installed software and
OS version rather than a hand-picked example set.

Ground truth is deterministic, not ML-derived: a finding is only harvested as
"verified benign" if it independently passes the same rule-based checks the
noise filter already uses at runtime to close a PID without ML at all --
Rule 1b (SECURITY-PROC key material) or Rule 2 (M13 structural benign
profile) in noise_filter.py, AND the process path passes the path-legitimacy
check. This avoids the circular-training trap of using the forest's own past
verdicts as label truth: every harvested vector is backed by an auditable,
non-ML rule that fired independently.

Usage:
  python -m playbooks.windows.investigation.calibrate_baseline reports/<hostname> [...]
  python -m playbooks.windows.investigation.calibrate_baseline reports/<hostname> --replace

Output: playbooks/windows/investigation/models/observed_baseline.json
  Merged by default (new report data adds to what's already calibrated).
  --replace clears prior calibration and recomputes from only the given reports.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

from .engine import _parse_pid_process
from .models.features import extract_m13_signals, process_feature_vector
from .models.noise_filter import _check_path_legitimacy, _check_m13_benign_profile

_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'models', 'observed_baseline.json')

# Cap per-process-name harvested vectors so one noisy host doesn't dominate
# the calibration set relative to processes seen on fewer hosts.
_MAX_PER_PROCESS = 25


def _load_json(path: str) -> list:
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)


def _extract_path(details: str) -> str:
    m = re.search(r'[Pp]ath=([^\s,;]+)|ImagePath=([^\s,;]+)', details)
    return (m.group(1) or m.group(2)) if m else ''


def _extract_parent(details: str) -> str:
    m = re.search(r'[Pp]arent=([^\s,;]+)|PPID.*\(([^)]+)\)', details)
    return ((m.group(1) or m.group(2)) if m else '') or ''


def _harvest_from_report(report_dir: str) -> Tuple[List[dict], int, int]:
    """Return (harvested_rows, total_m13_findings, verified_benign_count)."""
    mem_file = None
    for pattern in ('Memory_Findings_*.json', 'Combined_Findings_*.json'):
        matches = sorted(glob.glob(os.path.join(report_dir, pattern)), key=os.path.getmtime, reverse=True)
        if matches:
            mem_file = matches[0]
            break
    if not mem_file:
        return [], 0, 0

    findings = _load_json(mem_file)
    m13_findings = [f for f in findings if 'Dormant Beacon' in f.get('Type', '')]

    rows: List[dict] = []
    verified = 0
    for f in m13_findings:
        target  = f.get('Target', '')
        details = f.get('Details', '')
        pid, process, _ = _parse_pid_process(target)
        if not process:
            continue
        path   = _extract_path(details)
        parent = _extract_parent(details)

        path_check = _check_path_legitimacy(process, path)
        if path_check is not None and path_check[0] is False:
            continue  # provably wrong path -- never harvest as benign

        m13 = extract_m13_signals(details)
        benign_reason = _check_m13_benign_profile(m13)
        is_security_key_material = (
            'SECURITY-PROC' in details and
            m13.get('adj_anon_exec') is False and
            m13.get('mz_remnant') is False and
            (m13.get('size') or 999999) < 65536
        )
        if not (benign_reason or is_security_key_material):
            continue

        vec = process_feature_vector(process, path, parent, m13)
        verified += 1
        rows.append({
            'process': process,
            'vector': vec,
            'source': os.path.basename(mem_file),
            'reason': benign_reason or 'SECURITY-PROC key material',
        })

    return rows, len(m13_findings), verified


def calibrate(report_dirs: List[str], replace: bool = False) -> Dict[str, int]:
    existing: List[dict] = []
    if not replace and os.path.exists(_OUTPUT_PATH):
        with open(_OUTPUT_PATH, encoding='utf-8') as f:
            existing = json.load(f).get('rows', [])

    all_rows = list(existing)
    stats = {'reports_scanned': 0, 'm13_findings_seen': 0, 'verified_benign': 0}

    for report_dir in report_dirs:
        rows, total, verified = _harvest_from_report(report_dir)
        stats['reports_scanned'] += 1
        stats['m13_findings_seen'] += total
        stats['verified_benign'] += verified
        all_rows.extend(rows)
        print(f'  [+] {report_dir}: {verified}/{total} M13 findings verified benign '
              f'(structural rule match, not ML-derived)')

    # Deduplicate identical vectors, then cap per-process count.
    seen = set()
    deduped = []
    for r in all_rows:
        key = (r['process'], tuple(round(x, 4) for x in r['vector']))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    by_process: Dict[str, List[dict]] = defaultdict(list)
    for r in deduped:
        by_process[r['process']].append(r)
    capped = []
    for process, rows in by_process.items():
        capped.extend(rows[:_MAX_PER_PROCESS])

    os.makedirs(os.path.dirname(_OUTPUT_PATH), exist_ok=True)
    with open(_OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump({'rows': capped}, f, indent=2)

    stats['total_calibrated_vectors'] = len(capped)
    stats['unique_processes'] = len(by_process)
    return stats


def main() -> None:
    args = sys.argv[1:]
    replace = '--replace' in args
    report_dirs = [a for a in args if not a.startswith('--')]
    if not report_dirs:
        print('Usage: python -m playbooks.windows.investigation.calibrate_baseline <reports/DIR> [...] [--replace]')
        sys.exit(1)

    stats = calibrate(report_dirs, replace=replace)
    print(f'\n[Calibration] {stats}')
    print(f'[Calibration] Written to {_OUTPUT_PATH}')


if __name__ == '__main__':
    main()
