"""Live investigation engine runner.

Reads existing IR Toolkit report output from reports/<hostname>/ and runs the
ML investigation engine + multi-source correlator against the collected data.

Inputs (auto-discovered from reports/<hostname>/):
  Memory_Findings_*.json        -- memory_forensic.py findings (primary)
  Combined_Findings_*.json      -- all-source findings (Memory + other)
  EDR_Report_*.json             -- EDR behavioral findings
  Adjudication_*.json           -- adjudication enrichment (CommandLine, SHA256,
                                   ParentPid, ParentName, Network, SigStatus)
  YARA_Pivot_TP.json            -- YARA true-positive hits (structural, not by family)
  Persistence_Findings_*.json   -- persistence mechanisms
  RemoteAccess_Findings_*.json  -- remote access findings
  mwcp_scan_log.txt             -- mwcp config-extraction log (carved-region scan)

Output (written alongside existing reports in reports/<hostname>/):
  ML_Correlation_<hostname>_<timestamp>.json  -- machine-readable full report
  ML_Correlation_<hostname>_<timestamp>.md    -- analyst-readable markdown report
  ML_Correlation_<hostname>_<timestamp>.csv   -- summary CSV for triage

Usage:
  python -m playbooks.windows.investigation.live_runner reports/<hostname>
  python -m playbooks.windows.investigation.live_runner reports/  # all subdirs
"""
from __future__ import annotations

import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .engine import investigate, _parse_pid_process
from .correlator import correlate, CorrelationVerdict, CrossSourceSignal
from .verdict import Verdict, VerdictLabel
from .process_tree import load_from_snapshot, load_from_adjudication, ProcessNode
from .chain_builder import build_chains, AttackChain
from .ttp_patterns import match_patterns, TTPMatch


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _latest(pattern: str) -> Optional[str]:
    """Return the most-recently-modified file matching glob pattern, or None."""
    matches = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return matches[0] if matches else None


def _all_matches(pattern: str) -> List[str]:
    return sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)


def _load_json(path: str) -> Any:
    # utf-8-sig handles BOM (PowerShell/Windows often writes UTF-8 with BOM)
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Format adapters -- convert each report type to what the correlator expects
# ---------------------------------------------------------------------------

def _parse_edr_pid(target: str) -> Tuple[int, str]:
    """EDR_Report Target format: 'ProcessName (PID NNNN)' -- reversed from memory."""
    m = re.search(r'\(PID\s+(\d+)\)', target, re.IGNORECASE)
    if m:
        pid = int(m.group(1))
        proc = re.sub(r'\s*\(PID\s+\d+\)', '', target).strip()
        return pid, proc
    # Try memory format as fallback: 'PID NNNN (ProcessName)'
    m2 = re.match(r'PID\s+(\d+)\s+\(([^)]+)\)', target)
    if m2:
        return int(m2.group(1)), m2.group(2)
    return 0, target


def _parse_adj_pid(target: str) -> Tuple[int, str]:
    """Adjudication Target: 'PID NNNN (ProcessName)'"""
    m = re.match(r'PID\s+(\d+)\s+\(([^)]+)\)', target)
    if m:
        return int(m.group(1)), m.group(2)
    return 0, target


def _edr_findings_to_events(edr_findings: List[dict]) -> List[dict]:
    """
    EDR_Report_*.json is in findings format, not deep_sensor_ml format.
    Convert it: extract pid, process, and infer behavioral signals from
    Type/Details/Severity to produce edr_events the correlator can score.

    De-duplication: a process with 100+ identical DLL findings (e.g. MSIX apps)
    must not inflate its weight by 100x. We take the highest-severity event per
    (pid, finding_type) pair and cap the total per-PID EDR event count at 3 so
    that the correlator sees representative signals, not repetition.
    """
    severity_z = {'Critical': 5.5, 'High': 4.2, 'Medium': 2.5, 'Low': 1.0}

    # Group by (pid, ftype) and keep only the highest-severity entry per group
    best: Dict[Tuple[int, str], dict] = {}
    for f in edr_findings:
        target = f.get('Target', '')
        pid, proc = _parse_edr_pid(target)
        if not pid:
            continue
        ftype = f.get('Type', '')
        severity = f.get('Severity', 'Low')
        key = (pid, ftype)
        prev = best.get(key)
        if prev is None or (severity_z.get(severity, 0) > severity_z.get(prev.get('Severity', 'Low'), 0)):
            best[key] = dict(f, _pid=pid, _proc=proc)

    # Now convert, capping at 3 events per PID (prevent amplification from noisy processes)
    per_pid: Dict[int, List[dict]] = defaultdict(list)
    for (pid, ftype), f in best.items():
        per_pid[pid].append(f)

    events = []
    for pid, pid_events in per_pid.items():
        # Sort by severity descending so we keep the most important events
        pid_events.sort(
            key=lambda e: severity_z.get(e.get('Severity', 'Low'), 0), reverse=True
        )
        for f in pid_events[:3]:   # cap at 3 per PID
            proc     = f['_proc']
            severity = f.get('Severity', 'Low')
            ftype    = f.get('Type', '')
            details  = f.get('Details', '')
            z        = severity_z.get(severity, 1.0)

            score = 0.2
            confidence = 0.0
            reason = ''
            if 'Inject' in ftype or 'Hollowing' in ftype or 'Hook' in ftype:
                score = 0.65
                confidence = 80.0
                reason = f'EDR: {ftype}'
            elif 'Network' in ftype or 'External' in ftype:
                score = 0.55
                confidence = 75.0
                reason = f'EDR: unexpected network from {proc}'
            elif 'Offensive' in ftype or 'Suspicious' in ftype:
                score = 0.50
                confidence = 72.0
                reason = f'EDR: {ftype}'
            elif 'YARA' in ftype:
                score = 0.60
                confidence = 78.0
                reason = f'EDR: YARA alert for {proc}'

            events.append({
                'pid': pid,
                'process': proc,
                'z_score': z,
                'isolation_score': score,
                'velocity': 0.0,
                'entropy': 0.0,
                'confidence': confidence,
                'alert_reason': reason,
                'event_type': ftype,
                'details': details,
            })
    return events


def _adjudication_to_eventlogs(adj_entries: List[dict]) -> List[dict]:
    """
    Adjudication_*.json has rich per-target data. Extract event-log-equivalent
    signals: CommandLine, ParentPid, ParentName, Network, SigStatus.
    These proxy for 4688 (process create) and 4624 (network logon) entries.
    """
    logs = []
    for entry in adj_entries:
        target = entry.get('Target', '')
        pid, proc = _parse_adj_pid(target)
        if not pid:
            continue

        cmd     = entry.get('CommandLine', '') or ''
        parent  = entry.get('ParentName', '')  or ''
        user    = entry.get('Owner', '') or 'SYSTEM'
        network = entry.get('Network', '') or ''
        sig     = entry.get('SigStatus', '') or ''
        path    = entry.get('SubjectPath', '') or ''
        verdict = entry.get('Verdict', '') or ''

        # Already adjudicated as FP by the workflow -- don't re-litigate
        if verdict in ('False Positive', 'Benign', 'Noise'):
            continue

        if cmd or parent:
            logs.append({
                'EventID': 4688,
                'pid': pid,
                'CommandLine': cmd,
                'ParentProcessName': parent,
                'SubjectUserName': user,
                'LogonType': 0,
                'ServiceName': '',
                'ServiceFileName': '',
                'NewProcessId': 0,
                '_adj_sig': sig,
                '_adj_path': path,
                '_adj_verdict': verdict,
            })
        if network and network not in ('', '0.0.0.0:0 Listen'):
            # Check for external/lateral connection
            loopback = re.match(r'127\.|::1|0\.0\.0\.0', network)
            if not loopback:
                logs.append({
                    'EventID': 4624,
                    'pid': pid,
                    'CommandLine': '',
                    'ParentProcessName': '',
                    'SubjectUserName': user,
                    'LogonType': 3,
                    'ServiceName': '',
                    'ServiceFileName': '',
                    'NewProcessId': 0,
                    '_network': network,
                    '_adj_verdict': verdict,
                })
    return logs


def _yara_tp_to_findings(yara_entries: List[dict]) -> List[dict]:
    """YARA_Pivot_TP.json: {pid, proc, score, rules} -> findings format."""
    findings = []
    for y in yara_entries:
        pid   = y.get('pid', 0)
        proc  = y.get('proc', '')
        rules = y.get('rules', [])
        score = y.get('score', 0)
        if not pid:
            continue
        rule_str = ', '.join(rules)
        # STRUCTURAL classification -- presence in the finding set signals anon exec context
        findings.append({
            'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Severity': 'High' if score >= 3 else 'Medium',
            'Type': 'YARA Hit (Memory)',
            'Target': f'PID {pid} ({proc})',
            'Details': (
                f'YARA | {rules[0] if rules else "Unknown"} | fired in ANONYMOUS exec region. '
                f'{len(rules)} rule(s) matched (score={score}). '
                f'Rules: {rule_str}. Region is private, no backing file.'
            ),
            'MITRE': 'T1027',
        })
    return findings


def _persistence_to_eventlogs(persistence: List[dict]) -> List[dict]:
    """Persistence_Findings_*.json -> approximate 7045/4688 event log entries."""
    logs = []
    for f in persistence:
        target  = f.get('Target', '')
        details = f.get('Details', '')
        ftype   = f.get('Type', '')
        severity = f.get('Severity', 'Medium')

        # Service-based persistence -> Event 7045 proxy
        if 'Service' in ftype or 'service' in details.lower():
            svc_name_m = re.search(r'Name[=:]\s*([^\s,;]+)', details, re.IGNORECASE)
            svc_path_m = re.search(r'Path[=:]\s*([^\s,;]+)', details, re.IGNORECASE)
            svc_name = svc_name_m.group(1) if svc_name_m else target
            svc_path = svc_path_m.group(1) if svc_path_m else ''
            pid_m = re.search(r'PID\s+(\d+)', target)
            pid = int(pid_m.group(1)) if pid_m else 0
            logs.append({
                'EventID': 7045,
                'pid': pid,
                'CommandLine': '',
                'ParentProcessName': '',
                'SubjectUserName': 'SYSTEM',
                'LogonType': 0,
                'ServiceName': svc_name,
                'ServiceFileName': svc_path,
                'NewProcessId': 0,
            })
        # Scheduled task, registry run key -> 4688 proxy
        elif severity in ('High', 'Critical'):
            cmd_m = re.search(r'(?:Command|Value|Cmd)[=:]\s*(.+?)(?:,|\s*$)', details, re.IGNORECASE)
            cmd = cmd_m.group(1) if cmd_m else details[:150]
            logs.append({
                'EventID': 4688,
                'pid': 0,
                'CommandLine': cmd,
                'ParentProcessName': '',
                'SubjectUserName': 'SYSTEM',
                'LogonType': 0,
                'ServiceName': '',
                'ServiceFileName': '',
                'NewProcessId': 0,
            })
    return logs


# mwcp_scan_log.txt line format:
#   [TIMESTAMP UTC] [MATCH|CLEAN] filename (TYPE) parsers=P1,P2,... [field=[...] ...]
_MWCP_LOG_LINE = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<verdict>MATCH|CLEAN)\]\s+(?P<file>\S+)\s+'
    r'\((?P<ftype>[^)]+)\)\s+parsers=(?P<parsers>\S+)(?:\s+(?P<rest>.*))?$'
)
_MWCP_FIELD = re.compile(r'(\w+)=(\[[^\]]*\])')
# Carved-region filenames observed: {label}_{proc}_{pid}_{hexaddr}.bin
_MWCP_PID_FROM_FILE = re.compile(r'_(\d+)_[0-9a-fA-F]+\.\w+$')

# mwcp's generic mutex parser run against managed-code memory routinely reports
# WinAPI import names and raw hex/digit padding as "mutex" -- not real handles.
_JUNK_MUTEX = re.compile(r'^[0-9a-fA-F]{6,}$|^1+$|^f+$', re.IGNORECASE)

# CLR/.NET namespace strings (e.g. "System.IO", "Json.Net") mismatch generic
# address-pattern parsers over decoded PowerShell/.NET assembly memory.
_CLR_NAMESPACE = re.compile(r'^[A-Z][A-Za-z0-9]*(\.[A-Z][A-Za-z0-9]*)+$')

# Legitimate Microsoft telemetry/update endpoints embedded in PowerShell's own
# signed binary -- not C2 infrastructure when found via generic byte scanning.
_BENIGN_DOMAINS = frozenset({
    'aka.ms', 'microsoft.com', 'windowsupdate.com', 'msftconnecttest.com',
    'nuget.org', 'powershellgallery.com', 'schemas.microsoft.com',
})

_ADDRESS_SHAPE = re.compile(
    r'(?P<ipv4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|'
    r'(?P<url>[a-z][a-z0-9+.-]*://[^\s\'"]+)|'
    r'(?P<domain>[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,})',
    re.IGNORECASE,
)


def _domain_of(addr: str) -> str:
    m = re.search(r'://([^/\s]+)', addr)
    host = m.group(1) if m else addr
    return host.split(':')[0].lower().rstrip('\x01').strip()


def _is_valid_address(addr: str) -> bool:
    """Network-shaped AND not proven scanner noise for this data source."""
    if _CLR_NAMESPACE.match(addr):
        return False
    m = _ADDRESS_SHAPE.search(addr)
    if not m:
        return False
    if m.group('url') or m.group('domain'):
        domain = _domain_of(addr)
        if domain in _BENIGN_DOMAINS or any(domain.endswith('.' + d) for d in _BENIGN_DOMAINS):
            return False
    return True


def _parse_mwcp_field_list(raw: str) -> List[str]:
    return [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", raw)]


def _parse_mwcp_log(path: str) -> List[dict]:
    """Parse mwcp_scan_log.txt into hit dicts the correlator can score.

    Filters MATCH entries down to artifacts that survive noise checks: address
    values that are actually network-shaped (not CLR namespace strings or known
    Microsoft telemetry domains baked into PowerShell.exe itself), and mutex
    values that aren't raw hex/digit padding. Entries with nothing surviving are
    dropped entirely -- see the CLEAN/MATCH breakdown in the log itself for how
    much of this scan is parser noise from scanning managed-code memory.
    """
    hits: List[dict] = []
    if not os.path.exists(path):
        return hits
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _MWCP_LOG_LINE.match(line.strip())
            if not m or m.group('verdict') != 'MATCH':
                continue
            fname = m.group('file')
            rest = m.group('rest') or ''

            fields: Dict[str, List[str]] = {}
            for fm in _MWCP_FIELD.finditer(rest):
                fields[fm.group(1)] = _parse_mwcp_field_list(fm.group(2))

            addresses = [a for a in fields.get('address', []) if _is_valid_address(a)]
            mutexes   = [mx for mx in fields.get('mutex', []) if not _JUNK_MUTEX.match(mx)]
            passwords = fields.get('password', [])

            if not (addresses or mutexes or passwords):
                continue

            pid_m = _MWCP_PID_FROM_FILE.search(fname)
            pid = int(pid_m.group(1)) if pid_m else 0
            if not pid:
                continue

            hits.append({
                'file': fname, 'pid': pid,
                'address': addresses, 'mutex': mutexes, 'password': passwords,
            })
    return hits


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def run_on_directory(report_dir: str) -> Optional[str]:
    """
    Run ML investigation engine against all data in report_dir.
    Returns path to the JSON output file, or None if no memory findings found.
    """
    hostname = os.path.basename(os.path.normpath(report_dir))
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')

    print(f'\n[ML-Engine] Running investigation on {hostname} ({report_dir})')

    # --- Load memory findings (required) ---
    mem_file = _latest(os.path.join(report_dir, 'Memory_Findings_*.json'))
    if not mem_file:
        # Fall back to Combined_Findings if no dedicated memory file
        mem_file = _latest(os.path.join(report_dir, 'Combined_Findings_*.json'))
    if not mem_file:
        print(f'  [SKIP] No Memory_Findings or Combined_Findings in {report_dir}')
        return None

    findings: List[dict] = _load_json(mem_file)
    # Combined_Findings may include non-memory findings -- filter to memory-relevant
    memory_findings = [
        f for f in findings
        if (f.get('Source', 'Memory') in ('Memory', '', None) or
            any(kw in f.get('Type', '') for kw in
                ('Memory', 'Shellcode', 'Beacon', 'Hook', 'Hollow', 'YARA', 'ntdll',
                 'Thread', 'Inject', 'CLR', 'COM', 'PPID', 'PEB', 'Ekko')))
    ]
    print(f'  [+] Memory findings: {len(memory_findings)} (from {os.path.basename(mem_file)})')

    # --- Load YARA TP and add as additional findings ---
    yara_file = os.path.join(report_dir, 'YARA_Pivot_TP.json')
    yara_findings = []
    if os.path.exists(yara_file):
        yara_data = _load_json(yara_file)
        yara_findings = _yara_tp_to_findings(yara_data)
        print(f'  [+] YARA TP entries: {len(yara_data)} -> {len(yara_findings)} findings')
    all_findings = memory_findings + yara_findings

    # --- Load EDR report ---
    edr_file = _latest(os.path.join(report_dir, 'EDR_Report_*.json'))
    edr_events: List[dict] = []
    if edr_file:
        edr_raw = _load_json(edr_file)
        edr_events = _edr_findings_to_events(edr_raw)
        print(f'  [+] EDR events: {len(edr_events)} (from {os.path.basename(edr_file)})')

    # --- Load mwcp config-extraction log ---
    mwcp_file = os.path.join(report_dir, 'mwcp_scan_log.txt')
    mwcp_hits = _parse_mwcp_log(mwcp_file)
    if os.path.exists(mwcp_file):
        print(f'  [+] mwcp hits: {len(mwcp_hits)} surviving noise filter (from mwcp_scan_log.txt)')

    # --- Load Adjudication as event log proxy ---
    adj_file = _latest(os.path.join(report_dir, 'Adjudication_*.json'))
    event_logs: List[dict] = []
    if adj_file:
        adj_raw = _load_json(adj_file)
        # Exclude already-adjudicated FPs (don't re-work the adjudication)
        event_logs = _adjudication_to_eventlogs(adj_raw)
        print(f'  [+] Adjudication proxy events: {len(event_logs)} (from {os.path.basename(adj_file)})')

    # --- Load Persistence findings as event log proxy ---
    pers_file = _latest(os.path.join(report_dir, 'Persistence_Findings_*.json'))
    if pers_file:
        pers_raw = _load_json(pers_file)
        pers_logs = _persistence_to_eventlogs(pers_raw)
        event_logs.extend(pers_logs)
        print(f'  [+] Persistence proxy events: {len(pers_logs)} (from {os.path.basename(pers_file)})')

    # --- Load collected Windows event logs (authoritative, when present) ---
    # EventLog_*.json: list of parsed entries with EventID plus per-event fields
    # (CommandLine, ParentProcessName, ServiceName, ServiceFileName, LogonType,
    # SubjectUserName, NewProcessId/pid, TimeCreated).
    for log_file in _all_matches(os.path.join(report_dir, 'EventLog_*.json')):
        try:
            entries = _load_json(log_file)
        except (ValueError, OSError) as exc:
            print(f'  [!] Skipping unreadable event log {os.path.basename(log_file)}: {exc}')
            continue
        if isinstance(entries, list):
            valid = [e for e in entries if isinstance(e, dict) and
                     (e.get('EventID') or e.get('event_id'))]
            event_logs.extend(valid)
            print(f'  [+] Event log entries: {len(valid)} (from {os.path.basename(log_file)})')

    # --- Load prior adjudication for miss-detection comparison ---
    # The miss-detection pass finds cases where:
    #   ML says suspicious (TP or UNDET with pos_weight > 0)
    #   Prior workflow said benign/FP
    # These are the objective "misses" that deserve second-look.
    prior_adj: Dict[int, str] = {}     # pid -> prior verdict label
    prior_adj_raw: List[dict] = []
    if adj_file:
        prior_adj_raw = _load_json(adj_file) if not event_logs else adj_raw
        for entry in prior_adj_raw:
            target  = entry.get('Target', '')
            pid, _  = _parse_adj_pid(target)
            verdict = entry.get('Verdict', '') or entry.get('label', '')
            if pid and verdict:
                # Keep the most-severe verdict per PID (TP > UNDET > FP > Benign)
                if pid not in prior_adj or verdict in ('True Positive', 'Malicious'):
                    prior_adj[pid] = verdict

    # Fallback: adjudication files without a Verdict field (older schema) leave
    # prior_adj empty. Use Memory_Enrichment true_positive_pids instead: any PID
    # with findings that the prior workflow did NOT escalate to TP was implicitly
    # closed -- that is the comparison baseline for miss detection.
    if not prior_adj:
        enr_file = _latest(os.path.join(report_dir, 'Memory_Enrichment_*.json'))
        if enr_file:
            enr = _load_json(enr_file)
            tp_pids = set(enr.get('true_positive_pids', []) or [])
            finding_pids = set()
            for f in all_findings:
                pid, _, _ = _parse_pid_process(f.get('Target', ''))
                if pid:
                    finding_pids.add(pid)
            for pid in finding_pids:
                prior_adj[pid] = 'True Positive' if pid in tp_pids else 'Not Escalated'
            print(f'  [+] Prior verdicts from enrichment: {len(tp_pids)} TP PIDs, '
                  f'{len(finding_pids) - len(tp_pids & finding_pids)} implicitly closed '
                  f'(from {os.path.basename(enr_file)})')

    # --- Process lineage tree ---
    # Prefer a dedicated snapshot (covers all processes); fall back to the
    # partial lineage embedded in adjudication entries (ParentPid/ParentName).
    proc_tree: Dict[int, ProcessNode] = {}
    tree_file = _latest(os.path.join(report_dir, 'ProcessTree_*.json'))
    if tree_file:
        proc_tree = load_from_snapshot(_load_json(tree_file))
        print(f'  [+] Process tree: {len(proc_tree)} processes '
              f'(from {os.path.basename(tree_file)})')
    elif prior_adj_raw:
        proc_tree = load_from_adjudication(prior_adj_raw)
        linked = sum(1 for n in proc_tree.values() if n.ppid)
        print(f'  [+] Process tree (partial, from adjudication): '
              f'{len(proc_tree)} processes, {linked} with parent links')

    # --- Run engine ---
    print(f'  [*] Running memory investigation ({len(all_findings)} findings)...')
    mem_verdicts = investigate(all_findings)

    tp_count   = sum(1 for v in mem_verdicts if v.is_tp)
    fp_count   = sum(1 for v in mem_verdicts if v.label == VerdictLabel.FALSE_POSITIVE)
    noise_count = sum(1 for v in mem_verdicts if v.label == VerdictLabel.NOISE_CLOSED)
    undet_count = sum(1 for v in mem_verdicts if v.label == VerdictLabel.UNDETERMINED)
    print(f'  [*] Memory verdicts: {len(mem_verdicts)} PIDs -- '
          f'TP={tp_count} FP={fp_count} NOISE={noise_count} UNDET={undet_count}')

    # --- Run multi-source correlator ---
    print(f'  [*] Running multi-source correlation...')
    correlation_results = correlate(
        all_findings,
        mwcp_hits  = mwcp_hits,
        edr_events = edr_events,
        event_logs = event_logs,
    )

    tp_corr   = sum(1 for cv in correlation_results if cv.label == VerdictLabel.TRUE_POSITIVE)
    undet_corr = sum(1 for cv in correlation_results if cv.label == VerdictLabel.UNDETERMINED)
    print(f'  [*] Correlation results: {len(correlation_results)} PIDs -- '
          f'TP={tp_corr} UNDET={undet_corr}')

    # --- Chain-of-events reconstruction for suspicious PIDs ---
    chains = build_chains(correlation_results, proc_tree, event_logs=event_logs)
    if chains:
        print(f'  [*] Attack chains built: {len(chains)}')

    # --- Named TTP pattern matching (independent of TP/UNDET threshold) ---
    ttp_matches = match_patterns(correlation_results, chains=chains)
    if ttp_matches:
        print(f'  [*] TTP pattern matches: {len(ttp_matches)}')

    # --- Build report ---
    report = _build_report(hostname, ts, mem_file, correlation_results, mem_verdicts,
                           prior_adj=prior_adj, chains=chains, ttp_matches=ttp_matches)

    # --- Write outputs ---
    base_name = f'ML_Correlation_{hostname}_{ts}'
    json_path = os.path.join(report_dir, base_name + '.json')
    md_path   = os.path.join(report_dir, base_name + '.md')
    csv_path  = os.path.join(report_dir, base_name + '.csv')

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=_json_serial)

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(_render_markdown(report, hostname, ts))

    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        _write_csv(f, report)

    print(f'  [+] Reports written:')
    print(f'      {json_path}')
    print(f'      {md_path}')
    print(f'      {csv_path}')

    return json_path


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def _json_serial(obj):
    if hasattr(obj, 'value'):
        return obj.value
    if hasattr(obj, '__dict__'):
        return vars(obj)
    return str(obj)


_PRIOR_CLOSED_LABELS = frozenset({
    'False Positive', 'Benign', 'Noise', 'FP', 'benign', 'false positive', 'noise',
    # Enrichment fallback: PID had findings but was never escalated to TP
    'Not Escalated',
})

_PRIOR_TP_LABELS = frozenset({'True Positive', 'Malicious'})

def _build_report(hostname: str, ts: str, source_file: str,
                  correlation_results: List[CorrelationVerdict],
                  mem_verdicts: List[Verdict],
                  prior_adj: Optional[Dict[int, str]] = None,
                  chains: Optional[List[AttackChain]] = None,
                  ttp_matches: Optional[List[TTPMatch]] = None) -> dict:
    """Build structured report dict for JSON/MD/CSV output."""

    summary = {
        'hostname': hostname,
        'generated': ts,
        'source_file': os.path.basename(source_file),
        'total_pids': len(correlation_results),
        'true_positive': sum(1 for cv in correlation_results if cv.label == VerdictLabel.TRUE_POSITIVE),
        'undetermined': sum(1 for cv in correlation_results if cv.label == VerdictLabel.UNDETERMINED),
        'false_positive': sum(1 for cv in correlation_results
                              if cv.label == VerdictLabel.FALSE_POSITIVE),
        'noise_closed': sum(1 for cv in correlation_results
                            if cv.label == VerdictLabel.NOISE_CLOSED),
    }

    # True positives (highest priority)
    tps = []
    for cv in sorted(correlation_results,
                     key=lambda x: x.positive_weight, reverse=True):
        if cv.label != VerdictLabel.TRUE_POSITIVE:
            continue
        mem_v = cv.memory_verdict
        tps.append({
            'pid': cv.pid,
            'process': cv.process,
            'positive_weight': round(cv.positive_weight, 2),
            'sources': _source_summary(cv.signals),
            'memory_verdict': mem_v.label.value if mem_v else None,
            'positive_dims': (
                [{'module': d.source_module, 'name': d.name, 'rationale': d.rationale}
                 for d in mem_v.dimensions if d.positive] if mem_v else []
            ),
            'rationale': cv.rationale,
            'mitre': _extract_mitre(cv.memory_verdict),
            'prior_adj': (prior_adj or {}).get(cv.pid, ''),
        })

    # Undetermined with positive signals (needs more data)
    undets = []
    for cv in correlation_results:
        if cv.label != VerdictLabel.UNDETERMINED:
            continue
        undets.append({
            'pid': cv.pid,
            'process': cv.process,
            'positive_weight': round(cv.positive_weight, 2),
            'sources': _source_summary(cv.signals),
            'rationale': cv.rationale,
            'prior_adj': (prior_adj or {}).get(cv.pid, ''),
        })

    # Noise closed (confirmed benign)
    noise = [
        {'pid': cv.pid, 'process': cv.process, 'noise_score': cv.memory_verdict.noise_score
         if cv.memory_verdict else None}
        for cv in correlation_results if cv.label == VerdictLabel.NOISE_CLOSED
    ]

    # -------------------------------------------------------------------------
    # MISSES DETECTION
    # Find cases where:
    #   ML says TP or UNDET-with-positive-signals (something suspicious)
    #   Prior workflow said Benign/FP (was closed)
    # These are the objective second-look candidates the engine is designed to surface.
    # -------------------------------------------------------------------------
    misses = []
    if prior_adj:
        for cv in correlation_results:
            prior = prior_adj.get(cv.pid, '')
            ml_suspicious = (
                cv.label == VerdictLabel.TRUE_POSITIVE or
                (cv.label == VerdictLabel.UNDETERMINED and cv.positive_weight > 0)
            )
            prior_closed = prior in _PRIOR_CLOSED_LABELS
            if ml_suspicious and prior_closed:
                mem_v = cv.memory_verdict
                misses.append({
                    'pid': cv.pid,
                    'process': cv.process,
                    'ml_verdict': cv.label.value,
                    'ml_positive_weight': round(cv.positive_weight, 2),
                    'prior_adj_verdict': prior,
                    'sources': _source_summary(cv.signals),
                    'positive_dims': (
                        [{'module': d.source_module, 'name': d.name, 'rationale': d.rationale[:200]}
                         for d in mem_v.dimensions if d.positive] if mem_v else []
                    ),
                    'rationale': cv.rationale[:800],
                })
        summary['potential_misses'] = len(misses)

    # -------------------------------------------------------------------------
    # UNCONFIRMED PRIOR TPs -- the inverse check.
    # Find cases where the prior workflow called a PID True Positive but the ML
    # engine, working from memory evidence alone, does NOT reach the TP threshold.
    # This does not mean the prior call was wrong -- it may rest on evidence the
    # ML engine doesn't see (event log, EDR, analyst judgment). It does mean the
    # TP is not independently memory-grounded, which is worth documenting either
    # way: as corroboration to add if real, or as a call worth revisiting if not.
    # -------------------------------------------------------------------------
    unconfirmed_tps = []
    if prior_adj:
        for cv in correlation_results:
            prior = prior_adj.get(cv.pid, '')
            if prior in _PRIOR_TP_LABELS and cv.label != VerdictLabel.TRUE_POSITIVE:
                mem_v = cv.memory_verdict
                unconfirmed_tps.append({
                    'pid': cv.pid,
                    'process': cv.process,
                    'ml_verdict': cv.label.value,
                    'ml_positive_weight': round(cv.positive_weight, 2),
                    'prior_adj_verdict': prior,
                    'sources': _source_summary(cv.signals),
                    'positive_dims': (
                        [{'module': d.source_module, 'name': d.name, 'rationale': d.rationale[:200]}
                         for d in mem_v.dimensions if d.positive] if mem_v else []
                    ),
                    'rationale': cv.rationale[:800],
                })
        summary['unconfirmed_prior_tps'] = len(unconfirmed_tps)

    # Attack chains: lineage + ordered evidence timeline per suspicious PID
    chain_dicts = []
    for c in (chains or []):
        chain_dicts.append({
            'root_pid': c.root_pid,
            'root_process': c.root_process,
            'verdict': c.verdict,
            'lineage': c.lineage,
            'related_pids': c.related_pids,
            'stages_present': c.stages_present,
            'events': [
                {'timestamp': e.timestamp, 'pid': e.pid, 'process': e.process,
                 'stage': e.stage, 'source': e.source, 'mitre': e.mitre,
                 'description': e.description}
                for e in c.events
            ],
            'narrative': c.narrative,
        })

    ttp_dicts = [
        {'pattern': m.pattern, 'pid': m.pid, 'process': m.process,
         'mitre': m.mitre, 'confidence': m.confidence,
         'evidence': m.evidence, 'description': m.description}
        for m in (ttp_matches or [])
    ]
    summary['ttp_pattern_matches'] = len(ttp_dicts)

    return {
        'summary': summary,
        'true_positives': tps,
        'undetermined': undets,
        'noise_closed': noise,
        'potential_misses': misses,
        'unconfirmed_prior_tps': unconfirmed_tps,
        'attack_chains': chain_dicts,
        'ttp_pattern_matches': ttp_dicts,
    }


def _source_summary(signals: List[CrossSourceSignal]) -> Dict[str, int]:
    pos_by_source: Dict[str, int] = defaultdict(int)
    for s in signals:
        if s.positive:
            pos_by_source[s.source] += 1
    return dict(pos_by_source)


def _extract_mitre(mem_v: Optional[Verdict]) -> List[str]:
    if not mem_v:
        return []
    mitre = set()
    for f in mem_v.findings:
        m = f.get('MITRE', '')
        if m:
            mitre.add(m.split()[0])
    return sorted(mitre)


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def _render_markdown(report: dict, hostname: str, ts: str) -> str:
    summary = report['summary']
    tps     = report['true_positives']
    undets  = report['undetermined']
    noise   = report['noise_closed']

    lines = [
        f'# ML Correlation Report -- {hostname}',
        f'',
        f'Generated: {ts}  |  Source: {summary["source_file"]}',
        f'',
        f'## Summary',
        f'',
        f'| Verdict | Count |',
        f'|---------|-------|',
        f'| TRUE_POSITIVE | {summary["true_positive"]} |',
        f'| UNDETERMINED  | {summary["undetermined"]} |',
        f'| FALSE_POSITIVE | {summary["false_positive"]} |',
        f'| NOISE_CLOSED  | {summary["noise_closed"]} |',
        f'| **Total PIDs** | **{summary["total_pids"]}** |',
        f'',
    ]

    if tps:
        lines += ['## True Positives', '']
        for tp in tps:
            src_str = ' '.join(f'{k}:{v}' for k, v in tp['sources'].items())
            lines += [
                f'### PID {tp["pid"]} -- {tp["process"]}',
                f'',
                f'**Weight:** {tp["positive_weight"]:.1f}  |  '
                f'**Sources:** {src_str}  |  '
                f'**MITRE:** {", ".join(tp["mitre"])}',
                f'',
            ]
            if tp['positive_dims']:
                lines.append('**Positive dimensions:**')
                lines.append('')
                for d in tp['positive_dims']:
                    lines.append(f'- M{d["module"]} `{d["name"]}`: {d["rationale"][:200]}')
                lines.append('')
            lines += [
                '<details>',
                '<summary>Full rationale</summary>',
                '',
                '```',
                tp['rationale'],
                '```',
                '',
                '</details>',
                '',
            ]

    if undets:
        lines += ['## Undetermined (Needs More Evidence)', '']
        lines += ['| PID | Process | Weight | Sources |',
                  '|-----|---------|--------|---------|']
        for u in undets:
            src_str = ' '.join(f'{k}:{v}' for k, v in u['sources'].items()) or '(none)'
            lines.append(f'| {u["pid"]} | {u["process"]} | {u["positive_weight"]:.1f} | {src_str} |')
        lines.append('')

    if noise:
        lines += ['## Noise Closed (Confirmed Benign Background)', '']
        lines += ['| PID | Process | Noise Score |',
                  '|-----|---------|-------------|']
        for n in noise:
            score = f'{n["noise_score"]:.3f}' if n['noise_score'] is not None else 'n/a'
            lines.append(f'| {n["pid"]} | {n["process"]} | {score} |')
        lines.append('')

    misses = report.get('potential_misses', [])
    if misses:
        lines += [
            '## Potential Misses (ML suspicious, Prior workflow closed)',
            '',
            '> These PIDs were closed by the prior adjudication workflow but the ML engine',
            '> found structural or behavioral signals that challenge that closure.',
            '> Each entry requires analyst review before confirmation.',
            '',
            '| PID | Process | ML Verdict | ML Weight | Prior Adj | Sources |',
            '|-----|---------|-----------|-----------|-----------|---------|',
        ]
        for m in misses:
            src_str = ' '.join(f'{k}:{v}' for k, v in m['sources'].items()) or '(memory)'
            lines.append(
                f'| {m["pid"]} | {m["process"]} | {m["ml_verdict"]} | '
                f'{m["ml_positive_weight"]:.1f} | {m["prior_adj_verdict"]} | {src_str} |'
            )
        lines.append('')
        for m in misses:
            if not m['positive_dims']:
                continue
            lines += [
                f'### Miss: PID {m["pid"]} ({m["process"]})',
                f'',
                f'**Prior verdict:** {m["prior_adj_verdict"]}  |  '
                f'**ML verdict:** {m["ml_verdict"]} (weight={m["ml_positive_weight"]:.1f})',
                '',
                '**Suspicious signals:**',
                '',
            ]
            for d in m['positive_dims']:
                lines.append(f'- M{d["module"]} `{d["name"]}`: {d["rationale"][:200]}')
            lines.append('')

    unconfirmed = report.get('unconfirmed_prior_tps', [])
    if unconfirmed:
        lines += [
            '## Unconfirmed Prior True Positives (inverse check)',
            '',
            '> These PIDs were called True Positive by the prior adjudication workflow, but',
            '> the ML engine cannot independently confirm them from memory evidence alone.',
            '> This does not mean the prior call was wrong -- it may rest on evidence outside',
            '> memory (event log, EDR, analyst judgment). It means the TP is not yet',
            '> memory-grounded: either document the corroborating evidence, or revisit the call.',
            '',
            '| PID | Process | ML Verdict | ML Weight | Sources |',
            '|-----|---------|-----------|-----------|---------|',
        ]
        for u in unconfirmed:
            src_str = ' '.join(f'{k}:{v}' for k, v in u['sources'].items()) or '(memory)'
            lines.append(
                f'| {u["pid"]} | {u["process"]} | {u["ml_verdict"]} | '
                f'{u["ml_positive_weight"]:.1f} | {src_str} |'
            )
        lines.append('')

    ttp_matches = report.get('ttp_pattern_matches', [])
    if ttp_matches:
        lines += [
            '## Named TTP Pattern Matches',
            '',
            '> Recognized technique shapes, matched independently of TP/UNDETERMINED',
            '> threshold -- a match on a below-threshold PID is itself a second-look signal.',
            '',
            '| PID | Process | Pattern | MITRE | Confidence |',
            '|-----|---------|---------|-------|------------|',
        ]
        for t in ttp_matches:
            lines.append(
                f'| {t["pid"]} | {t["process"]} | {t["pattern"]} | '
                f'{", ".join(t["mitre"])} | {t["confidence"]} |'
            )
        lines.append('')
        for t in ttp_matches:
            lines += [
                f'### {t["pattern"]}: PID {t["pid"]} ({t["process"]})',
                '',
                t['description'],
                '',
            ]
            if t['evidence']:
                lines.append('**Evidence:** ' + ', '.join(f'`{e}`' for e in t['evidence']))
                lines.append('')

    chains = report.get('attack_chains', [])
    if chains:
        lines += [
            '## Attack Chains',
            '',
            '> Lineage and evidence timeline for each suspicious PID.',
            '> Stages present across multiple sources = stronger chain;',
            '> missing stages = the evidence still needed to confirm or refute.',
            '',
        ]
        for c in chains:
            lines += [
                f'### Chain: PID {c["root_pid"]} -- {c["root_process"]} ({c["verdict"]})',
                '',
                f'**Stages:** {" -> ".join(c["stages_present"]) or "(none)"}',
                '',
                '```',
                c['narrative'],
                '```',
                '',
            ]

    lines += [
        '---',
        '',
        '_Generated by IR Toolkit ML Correlation Engine._',
        '_Structural and behavioral detection -- no named malware families required._',
        '_"Potential Misses" are SECOND-LOOK candidates, not confirmed findings._',
    ]

    return '\n'.join(lines)


def _write_csv(f, report: dict) -> None:
    w = csv.writer(f)
    w.writerow(['Verdict', 'PID', 'Process', 'PositiveWeight', 'Sources', 'MITRE', 'PriorAdj'])
    for tp in report['true_positives']:
        src = ';'.join(f'{k}:{v}' for k, v in tp['sources'].items())
        w.writerow(['TRUE_POSITIVE', tp['pid'], tp['process'],
                    tp['positive_weight'], src, ';'.join(tp['mitre']), tp.get('prior_adj', '')])
    for u in report['undetermined']:
        src = ';'.join(f'{k}:{v}' for k, v in u['sources'].items())
        w.writerow(['UNDETERMINED', u['pid'], u['process'],
                    u['positive_weight'], src, '', u.get('prior_adj', '')])
    for n in report['noise_closed']:
        w.writerow(['NOISE_CLOSED', n['pid'], n['process'], '', '', '', ''])
    for m in report.get('potential_misses', []):
        src = ';'.join(f'{k}:{v}' for k, v in m['sources'].items())
        w.writerow(['POTENTIAL_MISS', m['pid'], m['process'],
                    m['ml_positive_weight'], src, '', m['prior_adj_verdict']])
    for t in report.get('ttp_pattern_matches', []):
        w.writerow([f'TTP_PATTERN:{t["pattern"]}', t['pid'], t['process'],
                    '', '', ';'.join(t['mitre']), t['confidence']])
    for u in report.get('unconfirmed_prior_tps', []):
        src = ';'.join(f'{k}:{v}' for k, v in u['sources'].items())
        w.writerow(['UNCONFIRMED_PRIOR_TP', u['pid'], u['process'],
                    u['ml_positive_weight'], src, '', u['prior_adj_verdict']])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python -m playbooks.windows.investigation.live_runner <reports/DIR> [...]')
        sys.exit(1)

    paths = sys.argv[1:]
    for path in paths:
        if not os.path.isdir(path):
            print(f'[SKIP] Not a directory: {path}')
            continue

        # If path is the top-level reports/ dir, recurse one level
        subdirs = [d for d in os.listdir(path)
                   if os.path.isdir(os.path.join(path, d))
                   and not d.startswith('.') and not d.startswith('_')]
        mem_here = glob.glob(os.path.join(path, 'Memory_Findings_*.json'))

        if mem_here:
            run_on_directory(path)
        elif subdirs:
            for sub in subdirs:
                sub_path = os.path.join(path, sub)
                mem_sub = glob.glob(os.path.join(sub_path, 'Memory_Findings_*.json'))
                if mem_sub:
                    run_on_directory(sub_path)
        else:
            print(f'[SKIP] No Memory_Findings found in {path}')


if __name__ == '__main__':
    main()
