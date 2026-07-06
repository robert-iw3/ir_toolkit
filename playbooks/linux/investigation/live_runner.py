"""Live investigation engine runner (Linux).

Reads existing IR Toolkit report output from reports/<hostname>/ and runs the
investigation engine + multi-source correlator against the collected data.

Inputs (auto-discovered from reports/<hostname>/):
  EDR_Report_*.json             -- edr_hunt.py live-host findings (primary)
  Memory_Findings_*.json        -- analyze_memory_linux.py volatility findings
  Memory_Findings_enrich_*.json -- memory_enrich.py IOC/C2-config findings
  Combined_Findings_*.json      -- all-source merge (used as a fallback if
                                   the per-source files above aren't present)
  Journal_Findings_*.json       -- journal_analysis.py findings
  Container_Findings_*.json     -- container_hunt.py findings
  RemoteAccess_Findings_*.json  -- remote_access_triage.py findings
  Adjudication_*.json           -- adjudicate.py enrichment (Verdict, SHA256,
                                   ParentPid/ParentName, PkgOwner, PathTrust)
  ProcessTree_*.json             -- dedicated ps-shaped lineage snapshot, if present

Every one of these files is already in the common {Timestamp, Severity, Type,
Target, Details, MITRE} schema (see correlator.py's docstring for why Linux
doesn't need per-source format adapters the way the Windows engine does).

Output (written alongside existing reports in reports/<hostname>/):
  Investigation_<hostname>_<timestamp>.json  -- machine-readable full report
  Investigation_<hostname>_<timestamp>.md    -- analyst-readable markdown report
  Investigation_<hostname>_<timestamp>.csv   -- summary CSV for triage

Usage:
  python -m playbooks.linux.investigation.live_runner reports/<hostname>
  python -m playbooks.linux.investigation.live_runner reports/   # all subdirs
"""
from __future__ import annotations

import csv
import glob
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .correlator import correlate, CorrelationVerdict, CrossSourceSignal
from .verdict import VerdictLabel, HOST_SCOPE_PID
from .process_tree import load_from_snapshot, load_from_adjudication, ProcessNode
from .chain_builder import build_chains, AttackChain
from .ttp_patterns import match_patterns, TTPMatch


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _latest(pattern: str) -> Optional[str]:
    matches = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return matches[0] if matches else None


def _all_matches(pattern: str) -> List[str]:
    return sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)


def _load_json(path: str) -> Any:
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)


def _load_json_list(path: str) -> List[dict]:
    try:
        data = _load_json(path)
    except (ValueError, OSError) as exc:
        print(f'  [!] Skipping unreadable {os.path.basename(path)}: {exc}')
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def run_on_directory(report_dir: str) -> Optional[str]:
    """Run the investigation engine against all data in report_dir. Returns
    path to the JSON output file, or None if no usable findings were found."""
    hostname = os.path.basename(os.path.normpath(report_dir))
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    print(f'\n[Investigation] Running on {hostname} ({report_dir})')

    # --- Primary findings: EDR + Memory (+ enrichment), else Combined as fallback ---
    edr_file = _latest(os.path.join(report_dir, 'EDR_Report_*.json'))
    mem_file = _latest(os.path.join(report_dir, 'Memory_Findings_[0-9]*.json'))
    enrich_file = _latest(os.path.join(report_dir, 'Memory_Findings_enrich_*.json'))

    primary: List[dict] = []
    sources_loaded = []
    if edr_file:
        primary.extend(_load_json_list(edr_file))
        sources_loaded.append(os.path.basename(edr_file))
    if mem_file:
        primary.extend(_load_json_list(mem_file))
        sources_loaded.append(os.path.basename(mem_file))
    if enrich_file:
        primary.extend(_load_json_list(enrich_file))
        sources_loaded.append(os.path.basename(enrich_file))

    if not primary:
        combined_file = _latest(os.path.join(report_dir, 'Combined_Findings_*.json'))
        if combined_file:
            primary = _load_json_list(combined_file)
            sources_loaded.append(os.path.basename(combined_file))

    if not primary:
        print(f'  [SKIP] No EDR_Report/Memory_Findings/Combined_Findings in {report_dir}')
        return None
    print(f'  [+] Primary findings: {len(primary)} (from {", ".join(sources_loaded)})')

    # --- Secondary collector sources ---
    journal_findings: List[dict] = []
    journal_file = _latest(os.path.join(report_dir, 'Journal_Findings_*.json'))
    if journal_file:
        journal_findings = _load_json_list(journal_file)
        print(f'  [+] Journal findings: {len(journal_findings)} (from {os.path.basename(journal_file)})')

    container_findings: List[dict] = []
    container_file = _latest(os.path.join(report_dir, 'Container_Findings_*.json'))
    if container_file:
        container_findings = _load_json_list(container_file)
        if container_findings:
            print(f'  [+] Container findings: {len(container_findings)} (from {os.path.basename(container_file)})')

    remote_access_findings: List[dict] = []
    ra_file = _latest(os.path.join(report_dir, 'RemoteAccess_Findings_*.json'))
    if ra_file:
        remote_access_findings = _load_json_list(ra_file)
        if remote_access_findings:
            print(f'  [+] Remote-access findings: {len(remote_access_findings)} (from {os.path.basename(ra_file)})')

    # Per-PID thread (TID) inventory (thread_inventory.py) -- shares the same
    # PID-target convention as EDR_Report, so it merges straight into primary
    # rather than needing its own correlate() parameter.
    thread_file = _latest(os.path.join(report_dir, 'Thread_Inventory_*.json'))
    if thread_file:
        thread_findings = _load_json_list(thread_file)
        if thread_findings:
            primary.extend(thread_findings)
            print(f'  [+] Thread inventory: {len(thread_findings)} (from {os.path.basename(thread_file)})')

    # --- Adjudication (prior verdicts + process lineage fallback) ---
    adj_file = _latest(os.path.join(report_dir, 'Adjudication_*.json'))
    adj_raw: List[dict] = []
    prior_adj: Dict[int, str] = {}
    if adj_file:
        adj_raw = _load_json_list(adj_file)
        for entry in adj_raw:
            pid = entry.get('Pid')
            verdict = entry.get('Verdict', '')
            if pid and verdict:
                try:
                    pid_i = int(pid)
                except (TypeError, ValueError):
                    continue
                if pid_i not in prior_adj or verdict in ('Likely True Positive', 'True Positive'):
                    prior_adj[pid_i] = verdict
        print(f'  [+] Adjudication proxy: {len(adj_raw)} entries, {len(prior_adj)} with a PID '
              f'(from {os.path.basename(adj_file)})')

    # --- Process lineage tree ---
    proc_tree: Dict[int, ProcessNode] = {}
    tree_file = _latest(os.path.join(report_dir, 'ProcessTree_*.json'))
    if tree_file:
        proc_tree = load_from_snapshot(_load_json_list(tree_file))
        print(f'  [+] Process tree: {len(proc_tree)} processes (from {os.path.basename(tree_file)})')
    elif adj_raw:
        proc_tree = load_from_adjudication(adj_raw)
        linked = sum(1 for n in proc_tree.values() if n.ppid)
        print(f'  [+] Process tree (partial, from adjudication): {len(proc_tree)} processes, '
              f'{linked} with parent links')

    # --- Run correlator (merges + runs the tiered-evidence engine) ---
    print(f'  [*] Running investigation engine...')
    correlation_results = correlate(
        primary, journal_findings=journal_findings, container_findings=container_findings,
        remote_access_findings=remote_access_findings, adjudication_entries=adj_raw,
    )
    tp_count = sum(1 for cv in correlation_results if cv.label == VerdictLabel.TRUE_POSITIVE)
    fp_count = sum(1 for cv in correlation_results if cv.label == VerdictLabel.FALSE_POSITIVE)
    noise_count = sum(1 for cv in correlation_results if cv.label == VerdictLabel.NOISE_CLOSED)
    undet_count = sum(1 for cv in correlation_results if cv.label == VerdictLabel.UNDETERMINED)
    print(f'  [*] Verdicts: {len(correlation_results)} PID(s) -- '
          f'TP={tp_count} FP={fp_count} NOISE={noise_count} UNDET={undet_count}')

    # --- Chain-of-events + named TTP patterns ---
    chains = build_chains(correlation_results, proc_tree)
    if chains:
        print(f'  [*] Attack chains built: {len(chains)}')
    ttp_matches = match_patterns(correlation_results, chains=chains)
    if ttp_matches:
        print(f'  [*] TTP pattern matches: {len(ttp_matches)}')

    # --- Build + write report ---
    report = _build_report(hostname, ts, ', '.join(sources_loaded), correlation_results,
                           prior_adj=prior_adj, chains=chains, ttp_matches=ttp_matches)

    base_name = f'Investigation_{hostname}_{ts}'
    json_path = os.path.join(report_dir, base_name + '.json')
    md_path = os.path.join(report_dir, base_name + '.md')
    csv_path = os.path.join(report_dir, base_name + '.csv')

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=_json_serial)
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(_render_markdown(report, hostname, ts))
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        _write_csv(f, report)

    print(f'  [+] Reports written:\n      {json_path}\n      {md_path}\n      {csv_path}')
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


_PRIOR_CLOSED_LABELS = frozenset({'False Positive', 'Likely False Positive'})
_PRIOR_TP_LABELS = frozenset({'Likely True Positive', 'True Positive'})


def _source_summary(signals: List[CrossSourceSignal]) -> Dict[str, int]:
    pos_by_source: Dict[str, int] = defaultdict(int)
    for s in signals:
        if s.positive:
            pos_by_source[s.source] += 1
    return dict(pos_by_source)


def _extract_mitre(cv: CorrelationVerdict) -> List[str]:
    mitre = set()
    for f in (cv.memory_verdict.findings if cv.memory_verdict else []):
        m = f.get('MITRE', '')
        if m:
            mitre.add(m.split()[0].rstrip(','))
    return sorted(mitre)


def _build_report(hostname: str, ts: str, source_desc: str,
                  correlation_results: List[CorrelationVerdict],
                  prior_adj: Optional[Dict[int, str]] = None,
                  chains: Optional[List[AttackChain]] = None,
                  ttp_matches: Optional[List[TTPMatch]] = None) -> dict:
    summary = {
        'hostname': hostname, 'generated': ts, 'source_files': source_desc,
        'total_pids': len(correlation_results),
        'true_positive': sum(1 for cv in correlation_results if cv.label == VerdictLabel.TRUE_POSITIVE),
        'undetermined': sum(1 for cv in correlation_results if cv.label == VerdictLabel.UNDETERMINED),
        'false_positive': sum(1 for cv in correlation_results if cv.label == VerdictLabel.FALSE_POSITIVE),
        'noise_closed': sum(1 for cv in correlation_results if cv.label == VerdictLabel.NOISE_CLOSED),
    }

    tps = []
    for cv in sorted(correlation_results, key=lambda x: x.positive_weight, reverse=True):
        if cv.label != VerdictLabel.TRUE_POSITIVE:
            continue
        mem_v = cv.memory_verdict
        tps.append({
            'pid': cv.pid, 'process': cv.process, 'positive_weight': round(cv.positive_weight, 2),
            'sources': _source_summary(cv.signals), 'memory_verdict': mem_v.label.value if mem_v else None,
            'positive_dims': ([{'module': d.source_module, 'name': d.name, 'rationale': d.rationale}
                               for d in mem_v.dimensions if d.positive] if mem_v else []),
            'rationale': cv.rationale, 'mitre': _extract_mitre(cv),
            'prior_adj': (prior_adj or {}).get(cv.pid, ''),
        })

    undets = []
    for cv in correlation_results:
        if cv.label != VerdictLabel.UNDETERMINED:
            continue
        undets.append({
            'pid': cv.pid, 'process': cv.process, 'positive_weight': round(cv.positive_weight, 2),
            'sources': _source_summary(cv.signals), 'rationale': cv.rationale,
            'prior_adj': (prior_adj or {}).get(cv.pid, ''),
        })

    noise = [
        {'pid': cv.pid, 'process': cv.process,
         'noise_score': cv.memory_verdict.noise_score if cv.memory_verdict else None}
        for cv in correlation_results if cv.label == VerdictLabel.NOISE_CLOSED
    ]

    misses = []
    if prior_adj:
        for cv in correlation_results:
            prior = prior_adj.get(cv.pid, '')
            ml_suspicious = (cv.label == VerdictLabel.TRUE_POSITIVE or
                            (cv.label == VerdictLabel.UNDETERMINED and cv.positive_weight > 0))
            if ml_suspicious and prior in _PRIOR_CLOSED_LABELS:
                mem_v = cv.memory_verdict
                misses.append({
                    'pid': cv.pid, 'process': cv.process, 'engine_verdict': cv.label.value,
                    'engine_positive_weight': round(cv.positive_weight, 2), 'prior_adj_verdict': prior,
                    'positive_dims': ([{'module': d.source_module, 'name': d.name, 'rationale': d.rationale[:200]}
                                       for d in mem_v.dimensions if d.positive] if mem_v else []),
                    'rationale': cv.rationale[:800],
                })
        summary['potential_misses'] = len(misses)

    unconfirmed_tps = []
    if prior_adj:
        for cv in correlation_results:
            prior = prior_adj.get(cv.pid, '')
            if prior in _PRIOR_TP_LABELS and cv.label != VerdictLabel.TRUE_POSITIVE:
                mem_v = cv.memory_verdict
                unconfirmed_tps.append({
                    'pid': cv.pid, 'process': cv.process, 'engine_verdict': cv.label.value,
                    'engine_positive_weight': round(cv.positive_weight, 2), 'prior_adj_verdict': prior,
                    'positive_dims': ([{'module': d.source_module, 'name': d.name, 'rationale': d.rationale[:200]}
                                       for d in mem_v.dimensions if d.positive] if mem_v else []),
                    'rationale': cv.rationale[:800],
                })
        summary['unconfirmed_prior_tps'] = len(unconfirmed_tps)

    chain_dicts = []
    for c in (chains or []):
        chain_dicts.append({
            'root_pid': c.root_pid, 'root_process': c.root_process, 'verdict': c.verdict,
            'lineage': c.lineage, 'related_pids': c.related_pids, 'stages_present': c.stages_present,
            'events': [{'timestamp': e.timestamp, 'pid': e.pid, 'process': e.process,
                       'stage': e.stage, 'source': e.source, 'mitre': e.mitre,
                       'description': e.description} for e in c.events],
            'narrative': c.narrative,
        })

    ttp_dicts = [{'pattern': m.pattern, 'pid': m.pid, 'process': m.process, 'mitre': m.mitre,
                 'confidence': m.confidence, 'evidence': m.evidence, 'description': m.description}
                for m in (ttp_matches or [])]
    summary['ttp_pattern_matches'] = len(ttp_dicts)

    return {
        'summary': summary, 'true_positives': tps, 'undetermined': undets, 'noise_closed': noise,
        'potential_misses': misses, 'unconfirmed_prior_tps': unconfirmed_tps,
        'attack_chains': chain_dicts, 'ttp_pattern_matches': ttp_dicts,
    }


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def _render_markdown(report: dict, hostname: str, ts: str) -> str:
    summary, tps, undets, noise = report['summary'], report['true_positives'], report['undetermined'], report['noise_closed']

    lines = [
        f'# Investigation Report -- {hostname}', '',
        f'Generated: {ts}  |  Source: {summary["source_files"]}', '',
        '## Summary', '', '| Verdict | Count |', '|---------|-------|',
        f'| TRUE_POSITIVE | {summary["true_positive"]} |',
        f'| UNDETERMINED  | {summary["undetermined"]} |',
        f'| FALSE_POSITIVE | {summary["false_positive"]} |',
        f'| NOISE_CLOSED  | {summary["noise_closed"]} |',
        f'| **Total PIDs (incl. host-scope)** | **{summary["total_pids"]}** |', '',
    ]

    if tps:
        lines += ['## True Positives', '']
        for tp in tps:
            src_str = ' '.join(f'{k}:{v}' for k, v in tp['sources'].items())
            pid_label = 'host/kernel-scope' if tp['pid'] == HOST_SCOPE_PID else f'PID {tp["pid"]}'
            lines += [f'### {pid_label} -- {tp["process"]}', '',
                     f'**Weight:** {tp["positive_weight"]:.1f}  |  **Sources:** {src_str}  |  '
                     f'**MITRE:** {", ".join(tp["mitre"])}', '']
            if tp['positive_dims']:
                lines.append('**Positive dimensions:**')
                lines.append('')
                for d in tp['positive_dims']:
                    lines.append(f'- M{d["module"]} `{d["name"]}`: {d["rationale"][:200]}')
                lines.append('')
            lines += ['<details>', '<summary>Full rationale</summary>', '', '```',
                     tp['rationale'], '```', '', '</details>', '']

    if undets:
        lines += ['## Undetermined (Needs More Evidence)', '',
                  '| PID | Process | Weight | Sources |', '|-----|---------|--------|---------|']
        for u in undets:
            src_str = ' '.join(f'{k}:{v}' for k, v in u['sources'].items()) or '(none)'
            pid_label = 'host' if u['pid'] == HOST_SCOPE_PID else str(u['pid'])
            lines.append(f'| {pid_label} | {u["process"]} | {u["positive_weight"]:.1f} | {src_str} |')
        lines.append('')

    if noise:
        lines += ['## Noise Closed (Confirmed Benign Background)', '',
                  '| PID | Process | Noise Score |', '|-----|---------|-------------|']
        for n in noise:
            score = f'{n["noise_score"]:.3f}' if n['noise_score'] is not None else 'n/a'
            lines.append(f'| {n["pid"]} | {n["process"]} | {score} |')
        lines.append('')

    misses = report.get('potential_misses', [])
    if misses:
        lines += ['## Potential Misses (Engine suspicious, Prior adjudication closed)', '',
                  '> These PIDs were closed by adjudicate.py but the investigation engine found',
                  '> structural or behavioral signals that challenge that closure.', '',
                  '| PID | Process | Engine Verdict | Weight | Prior Adj |',
                  '|-----|---------|----------------|--------|-----------|']
        for m in misses:
            lines.append(f'| {m["pid"]} | {m["process"]} | {m["engine_verdict"]} | '
                         f'{m["engine_positive_weight"]:.1f} | {m["prior_adj_verdict"]} |')
        lines.append('')

    unconfirmed = report.get('unconfirmed_prior_tps', [])
    if unconfirmed:
        lines += ['## Unconfirmed Prior True Positives (inverse check)', '',
                  '> Called Likely/True Positive by adjudicate.py, but the engine cannot',
                  '> independently confirm from these findings alone. Not necessarily wrong --',
                  '> may rest on evidence outside this engine\'s scope.', '',
                  '| PID | Process | Engine Verdict | Weight |', '|-----|---------|----------------|--------|']
        for u in unconfirmed:
            lines.append(f'| {u["pid"]} | {u["process"]} | {u["engine_verdict"]} | '
                         f'{u["engine_positive_weight"]:.1f} |')
        lines.append('')

    ttp_matches = report.get('ttp_pattern_matches', [])
    if ttp_matches:
        lines += ['## Named TTP Pattern Matches', '',
                  '| PID | Process | Pattern | MITRE | Confidence |',
                  '|-----|---------|---------|-------|------------|']
        for t in ttp_matches:
            lines.append(f'| {t["pid"]} | {t["process"]} | {t["pattern"]} | '
                         f'{", ".join(t["mitre"])} | {t["confidence"]} |')
        lines.append('')
        for t in ttp_matches:
            lines += [f'### {t["pattern"]}: PID {t["pid"]} ({t["process"]})', '', t['description'], '']
            if t['evidence']:
                lines.append('**Evidence:** ' + ', '.join(f'`{e}`' for e in t['evidence']))
                lines.append('')

    chains = report.get('attack_chains', [])
    if chains:
        lines += ['## Attack Chains', '']
        for c in chains:
            pid_label = 'host/kernel' if c['root_pid'] == HOST_SCOPE_PID else f'PID {c["root_pid"]}'
            lines += [f'### Chain: {pid_label} -- {c["root_process"]} ({c["verdict"]})', '',
                     f'**Stages:** {" -> ".join(c["stages_present"]) or "(none)"}', '',
                     '```', c['narrative'], '```', '']

    lines += ['---', '', '_Generated by IR Toolkit Linux Investigation Engine._',
             '_Structural and behavioral detection -- no named malware families required._']
    return '\n'.join(lines)


def _write_csv(f, report: dict) -> None:
    w = csv.writer(f)
    w.writerow(['Verdict', 'PID', 'Process', 'PositiveWeight', 'Sources', 'MITRE', 'PriorAdj'])
    for tp in report['true_positives']:
        src = ';'.join(f'{k}:{v}' for k, v in tp['sources'].items())
        w.writerow(['TRUE_POSITIVE', tp['pid'], tp['process'], tp['positive_weight'], src,
                   ';'.join(tp['mitre']), tp.get('prior_adj', '')])
    for u in report['undetermined']:
        src = ';'.join(f'{k}:{v}' for k, v in u['sources'].items())
        w.writerow(['UNDETERMINED', u['pid'], u['process'], u['positive_weight'], src, '', u.get('prior_adj', '')])
    for n in report['noise_closed']:
        w.writerow(['NOISE_CLOSED', n['pid'], n['process'], '', '', '', ''])
    for m in report.get('potential_misses', []):
        w.writerow(['POTENTIAL_MISS', m['pid'], m['process'], m['engine_positive_weight'], '',
                   '', m['prior_adj_verdict']])
    for t in report.get('ttp_pattern_matches', []):
        w.writerow([f'TTP_PATTERN:{t["pattern"]}', t['pid'], t['process'], '', '',
                   ';'.join(t['mitre']), t['confidence']])
    for u in report.get('unconfirmed_prior_tps', []):
        w.writerow(['UNCONFIRMED_PRIOR_TP', u['pid'], u['process'], u['engine_positive_weight'],
                   '', '', u['prior_adj_verdict']])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python -m playbooks.linux.investigation.live_runner <reports/DIR> [...]')
        sys.exit(1)

    for path in sys.argv[1:]:
        if not os.path.isdir(path):
            print(f'[SKIP] Not a directory: {path}')
            continue

        subdirs = [d for d in os.listdir(path)
                  if os.path.isdir(os.path.join(path, d)) and not d.startswith('.') and not d.startswith('_')]
        has_here = (glob.glob(os.path.join(path, 'EDR_Report_*.json')) or
                   glob.glob(os.path.join(path, 'Memory_Findings_*.json')) or
                   glob.glob(os.path.join(path, 'Combined_Findings_*.json')))

        if has_here:
            run_on_directory(path)
        elif subdirs:
            for sub in subdirs:
                sub_path = os.path.join(path, sub)
                has_sub = (glob.glob(os.path.join(sub_path, 'EDR_Report_*.json')) or
                          glob.glob(os.path.join(sub_path, 'Memory_Findings_*.json')) or
                          glob.glob(os.path.join(sub_path, 'Combined_Findings_*.json')))
                if has_sub:
                    run_on_directory(sub_path)
        else:
            print(f'[SKIP] No EDR_Report/Memory_Findings/Combined_Findings found in {path}')


if __name__ == '__main__':
    main()
