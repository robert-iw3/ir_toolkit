"""Chain-of-events reconstruction.

Per-PID verdicts answer WHICH process is suspicious. The attack chain answers
HOW: what spawned it, what it spawned, what it did, and in what order. Each
chain links evidence across sources (memory findings, event log proxies,
process lineage) into a timeline an analyst can verify step by step.

Chains are built for every focus PID (TP verdicts and prior-workflow-closed
PIDs the engine flags as suspicious). A chain with corroborated stages across
multiple sources is strong evidence; a chain with a single stage tells the
analyst exactly what evidence is still missing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .correlator import CorrelationVerdict
from .verdict import VerdictLabel
from .process_tree import ProcessNode, ancestors, descendants


# Finding Type -> kill-chain stage. Mechanism-based, not family-based.
_TYPE_STAGE = [
    (r'External Network Connection',             'command-and-control'),
    (r'Dormant Beacon',                          'defense-evasion'),
    (r'Shellcode Thread|Manually-Mapped',        'execution'),
    (r'Injected Memory|Hollowing',               'injection'),
    (r'ntdll Syscall|Hook',                      'defense-evasion'),
    (r'Ekko',                                    'defense-evasion'),
    (r'PPID Orphan|PEB CommandLine',             'masquerading'),
    (r'CLR Execute-Assembly',                    'execution'),
    (r'COM VTable',                              'persistence'),
    (r'YARA',                                    'payload-identification'),
    (r'Hidden Process',                          'defense-evasion'),
    (r'Suspicious Command',                      'execution'),
]

_EVENTID_STAGE = {
    4688: 'execution',
    7045: 'persistence',
    4624: 'lateral-movement',
}


@dataclass
class ChainEvent:
    timestamp: str
    pid: int
    process: str
    stage: str
    description: str
    mitre: str = ''
    source: str = 'memory'   # memory | eventlog | lineage


@dataclass
class AttackChain:
    root_pid: int
    root_process: str
    verdict: str
    lineage: List[str]                 # ancestor labels, root-most last
    events: List[ChainEvent]
    related_pids: List[int]            # descendants with their own findings
    stages_present: List[str]
    narrative: str


def _stage_for_type(ftype: str) -> str:
    for pattern, stage in _TYPE_STAGE:
        if re.search(pattern, ftype, re.IGNORECASE):
            return stage
    return 'unclassified'


def _finding_events(pid: int, process: str, findings: List[dict]) -> List[ChainEvent]:
    events = []
    for f in findings:
        ftype = f.get('Type', '')
        events.append(ChainEvent(
            timestamp=f.get('Timestamp', ''),
            pid=pid,
            process=process,
            stage=_stage_for_type(ftype),
            description=f'{ftype}: {f.get("Details", "")[:180]}',
            mitre=f.get('MITRE', ''),
            source='memory',
        ))
    return events


def _eventlog_events(pid: int, process: str, entries: List[dict]) -> List[ChainEvent]:
    events = []
    for e in entries:
        event_id = e.get('EventID', 0)
        stage = _EVENTID_STAGE.get(event_id, 'unclassified')
        if event_id == 4688:
            desc = (f'Process creation: cmd={e.get("CommandLine", "")[:120]} '
                    f'parent={e.get("ParentProcessName", "")}')
        elif event_id == 7045:
            desc = (f'Service installed: {e.get("ServiceName", "")} '
                    f'path={e.get("ServiceFileName", "")}')
        elif event_id == 4624:
            desc = (f'Network logon: user={e.get("SubjectUserName", "")} '
                    f'type={e.get("LogonType", "")}')
        else:
            desc = f'Event {event_id}'
        events.append(ChainEvent(
            timestamp=str(e.get('TimeCreated', '') or ''),
            pid=pid, process=process, stage=stage,
            description=desc, source='eventlog',
        ))
    return events


def _narrative(chain_events: List[ChainEvent], lineage: List[str],
               root_label: str, related: List[ProcessNode]) -> str:
    lines = []
    if lineage:
        lines.append('Lineage: ' + ' -> '.join(reversed(lineage)) + f' -> {root_label}')
    else:
        lines.append(f'Lineage: unknown (no process tree data) -> {root_label}')
    if related:
        lines.append('Spawned: ' + ', '.join(n.label() for n in related[:8]))
    stages = [e.stage for e in chain_events]
    ordered_unique = list(dict.fromkeys(stages))
    lines.append('Observed stages: ' + (' -> '.join(ordered_unique) if ordered_unique else 'none'))
    for e in chain_events[:20]:
        ts = e.timestamp or 'unknown-time'
        lines.append(f'  [{ts}] ({e.source}) {e.process} PID {e.pid} [{e.stage}] {e.description[:140]}')
    return '\n'.join(lines)


def build_chains(correlation_results: List[CorrelationVerdict],
                 tree: Dict[int, ProcessNode],
                 event_logs: Optional[List[dict]] = None,
                 focus_pids: Optional[Set[int]] = None) -> List[AttackChain]:
    """Build an attack chain per focus PID.

    focus_pids defaults to: TP verdicts plus UNDETERMINED with positive weight
    (the same set miss-detection compares against prior verdicts).
    """
    event_logs = event_logs or []
    logs_by_pid: Dict[int, List[dict]] = {}
    for e in event_logs:
        pid = e.get('pid', 0) or e.get('NewProcessId', 0)
        if pid:
            logs_by_pid.setdefault(pid, []).append(e)

    if focus_pids is None:
        focus_pids = {
            cv.pid for cv in correlation_results
            if cv.label == VerdictLabel.TRUE_POSITIVE or
               (cv.label == VerdictLabel.UNDETERMINED and cv.positive_weight > 0)
        }

    cv_by_pid = {cv.pid: cv for cv in correlation_results}
    chains: List[AttackChain] = []

    for pid in sorted(focus_pids):
        cv = cv_by_pid.get(pid)
        if cv is None:
            continue
        process = cv.process

        anc = ancestors(tree, pid)
        desc = descendants(tree, pid)
        # Descendants only matter for the chain if they have evidence of their own
        related = [n for n in desc
                   if n.pid in cv_by_pid or n.pid in logs_by_pid]

        events: List[ChainEvent] = []
        events.extend(_finding_events(pid, process,
                                      cv.all_evidence.get('memory', [])))
        events.extend(_eventlog_events(pid, process, logs_by_pid.get(pid, [])))
        for n in related:
            rel_cv = cv_by_pid.get(n.pid)
            if rel_cv:
                events.extend(_finding_events(n.pid, n.name,
                                              rel_cv.all_evidence.get('memory', [])))
            events.extend(_eventlog_events(n.pid, n.name, logs_by_pid.get(n.pid, [])))

        events.sort(key=lambda e: e.timestamp or '9999')
        stages = list(dict.fromkeys(e.stage for e in events))
        lineage_labels = [n.label() for n in anc]

        node = tree.get(pid)
        root_label = node.label() if node else f'{process} (PID {pid})'

        chains.append(AttackChain(
            root_pid=pid,
            root_process=process,
            verdict=cv.label.value,
            lineage=lineage_labels,
            events=events,
            related_pids=[n.pid for n in related],
            stages_present=stages,
            narrative=_narrative(events, lineage_labels, root_label, related),
        ))

    return chains
