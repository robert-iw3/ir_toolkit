"""LotL TTP pattern matching -- named technique shapes across sources.

The correlator's weight threshold answers "is this suspicious enough for a
TP verdict." This module answers a different question: "does the evidence
combination match a KNOWN technique shape," independent of whether the
generic threshold was crossed. A pattern match on an UNDETERMINED PID is
itself a second-look signal -- the shape is recognizable even if the raw
weight fell short.

Patterns are defined by dimension names (from engine.py modules), chain
stages (from chain_builder.py), and event log content. Matching is
mechanism-based: e.g. "UNIFORM memory + anonymous-exec thread in the same
PID" is the CobaltStrike-style beacon SHAPE regardless of which YARA family
(if any) fired.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .correlator import CorrelationVerdict
from .chain_builder import AttackChain
from .verdict import Dimension


@dataclass
class TTPMatch:
    pattern: str
    pid: int
    process: str
    mitre: List[str]
    confidence: str          # 'high' | 'medium'
    evidence: List[str]
    description: str


def _dim_names(cv: CorrelationVerdict, positive: Optional[bool] = None) -> List[str]:
    mem_v = cv.memory_verdict
    if not mem_v:
        return []
    return [d.name for d in mem_v.dimensions if positive is None or d.positive == positive]


def _has(cv: CorrelationVerdict, *substrings: str, positive: bool = True) -> bool:
    names = _dim_names(cv, positive=positive)
    return any(any(s in n for s in substrings) for n in names)


def _dim_rationale(cv: CorrelationVerdict, substring: str) -> str:
    mem_v = cv.memory_verdict
    if not mem_v:
        return ''
    for d in mem_v.dimensions:
        if substring in d.name:
            return d.rationale
    return ''


_LOLBIN_LOADERS = re.compile(
    r'\b(wmic|mshta|rundll32|regsvr32|cscript|wscript|certutil|installutil|msbuild)\.exe\b',
    re.IGNORECASE,
)
_ENCODED_OR_DOWNLOAD = re.compile(
    r'-enc|-EncodedCommand|frombase64string|downloadstring|downloadfile|invoke-webrequest|iex\s*\(',
    re.IGNORECASE,
)


def _match_beacon(cv: CorrelationVerdict) -> Optional[TTPMatch]:
    """UNIFORM memory region + anonymous-exec thread in the same process.

    The structural shape of a Cobalt Strike / Sliver-style beacon: encrypted
    payload staged in a UNIFORM byte-distribution region, executed via a
    thread outside any loaded module. Family-agnostic -- matches unnamed
    implants with the same mechanism.
    """
    if _has(cv, 'CV_UNIFORM', 'AdjAnonExec') and \
            _has(cv, 'AnonExecThread', 'CrossProcessThread', 'MZ_InAnonExec', 'ShellcodeThread'):
        return TTPMatch(
            pattern='beacon-in-uniform-region', pid=cv.pid, process=cv.process,
            mitre=['T1055', 'T1027'], confidence='high',
            evidence=[n for n in _dim_names(cv, positive=True)
                      if any(s in n for s in ('CV_UNIFORM', 'AdjAnonExec', 'AnonExecThread',
                                               'CrossProcessThread', 'MZ_InAnonExec', 'ShellcodeThread'))],
            description=(f'PID {cv.pid} ({cv.process}): UNIFORM byte-distribution region '
                         'combined with a thread executing outside any loaded module -- '
                         'structural shape of an encrypted beacon payload staged and executed '
                         'in memory, independent of named family signature.'),
        )
    return None


def _match_ekko_sleep(cv: CorrelationVerdict, chain: Optional[AttackChain]) -> Optional[TTPMatch]:
    """UNIFORM memory + corroborated thread-pool pattern + no live network at snapshot.

    Sleep-obfuscation techniques (Ekko, Foliage) decrypt a beacon into a
    UNIFORM region, run it via ntdll-backed pool threads, then re-encrypt and
    go quiet -- so the snapshot often shows no active connection even though
    the process is a live implant.
    """
    if not _has(cv, 'CV_UNIFORM', 'AdjAnonExec'):
        return None
    if not _has(cv, 'Ekko_Corroborated'):
        return None
    has_network = chain is not None and 'command-and-control' in chain.stages_present
    return TTPMatch(
        pattern='sleep-obfuscation', pid=cv.pid, process=cv.process,
        mitre=['T1055', 'T1027'], confidence='high' if not has_network else 'medium',
        evidence=[n for n in _dim_names(cv, positive=True)
                  if any(s in n for s in ('CV_UNIFORM', 'AdjAnonExec', 'Ekko_Corroborated'))],
        description=(f'PID {cv.pid} ({cv.process}): UNIFORM beacon region corroborated by an '
                     'ntdll-backed thread-pool pattern -- matches Ekko/Foliage sleep-obfuscation. '
                     + ('No live network connection at snapshot time is EXPECTED for this '
                        'technique (beacon re-encrypts and sleeps between check-ins), not '
                        'evidence of benignity.' if not has_network else
                        'Live network connection present alongside the sleep pattern.')),
    )


def _match_wmi_persistence(cv: CorrelationVerdict, chain: Optional[AttackChain]) -> Optional[TTPMatch]:
    """A persistence-stage event referencing WMI, chained to execution for this PID."""
    if chain is None or 'persistence' not in chain.stages_present:
        return None
    wmi_events = [e for e in chain.events
                  if e.stage == 'persistence' and 'wmi' in e.description.lower()]
    if not wmi_events or 'execution' not in chain.stages_present:
        return None
    return TTPMatch(
        pattern='wmi-persistence-to-execution', pid=cv.pid, process=cv.process,
        mitre=['T1546.003'], confidence='medium',
        evidence=[e.description[:160] for e in wmi_events],
        description=(f'PID {cv.pid} ({cv.process}): WMI-related persistence event chained to '
                     'process execution -- WMI event subscription launching a consumer process '
                     'is a common fileless persistence mechanism that evades autorun scans.'),
    )


def _match_lolbin_loader(cv: CorrelationVerdict, chain: Optional[AttackChain]) -> Optional[TTPMatch]:
    """A LOLBin with an encoded/download command line, chained to anon-exec in this PID or a child."""
    if chain is None:
        return None
    loader_events = [
        e for e in chain.events
        if e.source == 'eventlog' and _LOLBIN_LOADERS.search(e.description)
        and _ENCODED_OR_DOWNLOAD.search(e.description)
    ]
    if not loader_events:
        return None
    has_exec = _has(cv, 'AnonExecThread', 'CrossProcessThread', 'AnonExecRegion', 'ShellcodeThread')
    if not has_exec:
        return None
    return TTPMatch(
        pattern='lolbin-loader', pid=cv.pid, process=cv.process,
        mitre=['T1218', 'T1055'], confidence='high',
        evidence=[e.description[:160] for e in loader_events],
        description=(f'PID {cv.pid} ({cv.process}): signed system binary invoked with an '
                     'encoded or download command line, followed by code execution outside '
                     'any loaded module -- LOLBin used as a loader stage, not for its '
                     'legitimate function.'),
    )


def _match_ppid_spoof_with_exec(cv: CorrelationVerdict) -> Optional[TTPMatch]:
    """Lineage anomaly (PID reuse / suspicious orphan) co-occurring with anon-exec in the child."""
    if not _has(cv, 'PID_Reuse', 'SuspiciousOrphan'):
        return None
    if not _has(cv, 'AnonExecThread', 'CrossProcessThread', 'ShellcodeThread'):
        return None
    return TTPMatch(
        pattern='ppid-spoof-with-execution', pid=cv.pid, process=cv.process,
        mitre=['T1134', 'T1055'], confidence='high',
        evidence=[n for n in _dim_names(cv, positive=True)
                  if any(s in n for s in ('PID_Reuse', 'SuspiciousOrphan', 'AnonExecThread',
                                           'CrossProcessThread', 'ShellcodeThread'))],
        description=(f'PID {cv.pid} ({cv.process}): parent-process lineage does not match the '
                     'claimed PPID (spoofing or PID recycling), and the process also executes '
                     'code outside any loaded module -- lineage deception paired with active '
                     'injection, not a benign PID-reuse coincidence.'),
    )


def _match_lsass_credential_access(cv: CorrelationVerdict) -> Optional[TTPMatch]:
    """lsass.exe with an unattributed thread AND independent memory corroboration."""
    if 'lsass' not in cv.process.lower():
        return None
    has_thread_anomaly = _has(cv, 'AnonExecThread', 'CrossProcessThread', positive=True) or \
                          _has(cv, 'PEB_Unlinked_Thread', positive=False)
    has_corroboration = _has(cv, 'YARA_AnonExec', 'YARA_Hit', 'MZ_Header', 'MZ_InAnonExec')
    if not (has_thread_anomaly and has_corroboration):
        return None
    return TTPMatch(
        pattern='lsass-credential-access', pid=cv.pid, process=cv.process,
        mitre=['T1003.001'], confidence='high',
        evidence=(
            [n for n in _dim_names(cv, positive=True)
             if any(s in n for s in ('AnonExecThread', 'CrossProcessThread',
                                      'YARA_AnonExec', 'YARA_Hit', 'MZ_Header', 'MZ_InAnonExec'))] +
            [n for n in _dim_names(cv, positive=False) if 'PEB_Unlinked' in n]
        ),
        description=(f'PID {cv.pid} ({cv.process}): thread/memory anomaly in lsass.exe '
                     'corroborated by an independent structural signal (YARA hit in anonymous '
                     'region, or MZ header) -- consistent with a credential-dumping tool '
                     'attaching to or injecting into LSASS rather than routine EDR/AV hooking.'),
    )


_MATCHERS = [
    _match_beacon,
]
_MATCHERS_WITH_CHAIN = [
    _match_ekko_sleep,
    _match_wmi_persistence,
    _match_lolbin_loader,
]
_MATCHERS_SIMPLE = [
    _match_ppid_spoof_with_exec,
    _match_lsass_credential_access,
]


def match_patterns(correlation_results: List[CorrelationVerdict],
                   chains: Optional[List[AttackChain]] = None) -> List[TTPMatch]:
    """Run every named pattern against every PID with memory evidence.

    Runs independent of the correlator's TP/UNDETERMINED threshold -- a
    pattern match on a below-threshold PID is itself a second-look signal.
    """
    chain_by_pid: Dict[int, AttackChain] = {c.root_pid: c for c in (chains or [])}
    matches: List[TTPMatch] = []

    for cv in correlation_results:
        if not cv.memory_verdict or not cv.memory_verdict.dimensions:
            continue
        chain = chain_by_pid.get(cv.pid)

        for fn in _MATCHERS:
            m = fn(cv)
            if m:
                matches.append(m)
        for fn in _MATCHERS_WITH_CHAIN:
            m = fn(cv, chain)
            if m:
                matches.append(m)
        for fn in _MATCHERS_SIMPLE:
            m = fn(cv)
            if m:
                matches.append(m)

    return matches
