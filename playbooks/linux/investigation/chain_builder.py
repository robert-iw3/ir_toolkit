"""Chain-of-events reconstruction (Linux).

Per-PID verdicts answer WHICH process is suspicious. The attack chain answers
HOW: what spawned it, what it spawned, what it did, and in what order. Stage
mapping follows the same kill-chain vocabulary as the Windows engine so
reports read consistently across platforms, but the Type->stage table is
tailored to Linux mechanisms (kernel rootkit hooks, eBPF/io_uring anti-EDR,
namespace escape, SSH backdoors, cryptominer deployment).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .correlator import CorrelationVerdict
from .verdict import VerdictLabel, HOST_SCOPE_PID
from .process_tree import ProcessNode, ancestors, descendants

_TYPE_STAGE = [
    (r'External Connection|C2 Endpoint|Tor C2|eBPF Network C2',    'command-and-control'),
    (r'C2 Config Recovered|BPFDoor Config|Botnet Config',          'command-and-control'),
    (r'Cryptominer|Crypto Miner',                                  'impact'),
    (r'Deleted Running Binary|memfd|Execution From Writable',      'defense-evasion'),
    (r'Injected Memory|malfind|Implant-Backed Mapping',            'execution'),
    (r'Reverse Shell|Offensive Tooling|Webshell|Suspicious Process','execution'),
    (r'Hidden Kernel Module|IDT Hook|Netfilter Hook|VFS fops Hook|'
     r'Kernel .text Inline Hook|Kernel Timer Hook|Kernel Thread Hook|'
     r'modprobe_path|uevent_helper|core_pattern',                  'defense-evasion'),
    (r'Credential Override|UID0 Account|Empty Password',           'privilege-escalation'),
    (r'eBPF|io_uring',                                             'defense-evasion'),
    (r'Namespace Escape|Bind Mount|Container Host Namespace|'
     r'Docker Socket Mount|Privileged Container',                  'privilege-escalation'),
    (r'Cron Persistence|Systemd Persistence|udev Rule|rc\.local|'
     r'Autostart|Shell Init Backdoor|Scheduled at-job',            'persistence'),
    (r'SSH Backdoor Artifact|SSH Forced-Command|authorized_keys|'
     r'SSH Key',                                                   'persistence'),
    (r'YARA|Memory Capabilities',                                  'payload-identification'),
    (r'Hidden Process',                                            'defense-evasion'),
    (r'Linker Hijack|Library Preload|Suspicious Loaded Library',   'persistence'),
    (r'Process Name Mismatch|Spoofed Process|Implant-Path',        'masquerading'),
    (r'Ptrace Attachment',                                         'credential-access'),
    (r'SUID|Dangerous.*Capability',                                'privilege-escalation'),
    (r'Audit Rules Cleared|Log File Truncated|Journal|Shell History',  'defense-evasion'),
]


@dataclass
class ChainEvent:
    timestamp: str
    pid: int
    process: str
    stage: str
    description: str
    mitre: str = ''
    source: str = 'memory'


@dataclass
class AttackChain:
    root_pid: int
    root_process: str
    verdict: str
    lineage: List[str]
    events: List[ChainEvent]
    related_pids: List[int]
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
            timestamp=f.get('Timestamp', ''), pid=pid, process=process,
            stage=_stage_for_type(ftype),
            description=f'{ftype}: {f.get("Details", "")[:180]}',
            mitre=f.get('MITRE', ''), source='memory',
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
                 focus_pids: Optional[Set[int]] = None) -> List[AttackChain]:
    """Build an attack chain per focus PID. focus_pids defaults to TP verdicts
    plus UNDETERMINED with positive weight, same as the Windows engine, but
    always includes HOST_SCOPE_PID if it independently reached TP/UNDETERMINED
    (kernel rootkit / persistence findings have no owning process but are
    still worth a narrative)."""
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

        if pid == HOST_SCOPE_PID:
            anc, desc, related = [], [], []
        else:
            anc = ancestors(tree, pid)
            desc = descendants(tree, pid)
            related = [n for n in desc if n.pid in cv_by_pid]

        events: List[ChainEvent] = []
        events.extend(_finding_events(pid, process, cv.all_evidence.get('memory', [])))
        for n in related:
            rel_cv = cv_by_pid.get(n.pid)
            if rel_cv:
                events.extend(_finding_events(n.pid, n.name, rel_cv.all_evidence.get('memory', [])))

        events.sort(key=lambda e: e.timestamp or '9999')
        stages = list(dict.fromkeys(e.stage for e in events))
        lineage_labels = [n.label() for n in anc]

        node = tree.get(pid)
        root_label = node.label() if node else f'{process} (PID {pid})' if pid else process

        chains.append(AttackChain(
            root_pid=pid, root_process=process, verdict=cv.label.value,
            lineage=lineage_labels, events=events,
            related_pids=[n.pid for n in related], stages_present=stages,
            narrative=_narrative(events, lineage_labels, root_label, related),
        ))

    return chains
