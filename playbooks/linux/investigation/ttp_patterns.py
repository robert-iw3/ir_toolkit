"""Named TTP pattern matching (Linux) -- technique shapes across sources.

Matching is mechanism-based, independent of the generic TP/UNDETERMINED
threshold: a pattern match on a below-threshold PID is itself a second-look
signal, same philosophy as the Windows engine's ttp_patterns.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .correlator import CorrelationVerdict
from .chain_builder import AttackChain
from .verdict import HOST_SCOPE_PID


@dataclass
class TTPMatch:
    pattern: str
    pid: int
    process: str
    mitre: List[str]
    confidence: str
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


def _match_miner_rootkit(cv: CorrelationVerdict, host_cv: Optional[CorrelationVerdict]) -> Optional[TTPMatch]:
    """Kernel rootkit signal (host-scope, HOST_SCOPE_PID) + cryptominer config
    on a PID -- the Kinsing/kdevtmpfsi-class compromise that
    WORKFLOW-INVESTIGATION-LINUX.md documents as the dominant real-world Linux
    intrusion shape. These two facts live on DIFFERENT verdicts (a kernel
    module has no owning PID; the miner does), so this checks across both
    rather than one verdict's own dimensions."""
    if cv.pid == HOST_SCOPE_PID:
        return None
    mem_v = cv.memory_verdict
    miner_dims = [d for d in (mem_v.dimensions if mem_v else [])
                  if d.positive and 'Cryptominer' in d.rationale]
    if not miner_dims:
        return None
    if host_cv is None or not _has(host_cv, 'M5_KernelRootkit'):
        return None
    return TTPMatch(
        pattern='miner-rootkit-deployment', pid=cv.pid, process=cv.process,
        mitre=['T1496', 'T1014'], confidence='high',
        evidence=(_dim_names(host_cv, positive=True) and
                 [n for n in _dim_names(host_cv, positive=True) if 'M5_' in n]) +
                 [n for n in _dim_names(cv, positive=True) if 'M18_' in n],
        description=(f'PID {cv.pid} ({cv.process}): host-scope kernel rootkit signal co-occurs '
                     'with a recovered cryptominer configuration on this process -- the '
                     'Kinsing/kdevtmpfsi-class shape that dominates real-world Linux compromises: '
                     'hide the miner\'s process footprint with an LKM rootkit, deploy the miner '
                     'for resource hijacking.'),
    )


def _match_bpfdoor_activation(cv: CorrelationVerdict, host_cv: Optional[CorrelationVerdict]) -> Optional[TTPMatch]:
    """A recovered BPFDoor magic-sequence artifact (PID-scoped: tied to the
    carved region of a specific process) paired with the live kernel-level
    eBPF+netfilter hook correlation (host-scope: analyze_memory_linux.py's
    correlate_ebpf_c2() targets the eBPF program names, not a PID) -- static
    config AND live activation both present, not just one or the other.
    These two facts live on different verdicts, so this checks across both."""
    if cv.pid == HOST_SCOPE_PID:
        return None
    has_config = any(d.positive and 'BPFDoor' in d.name
                     for d in (cv.memory_verdict.dimensions if cv.memory_verdict else []))
    if not has_config:
        return None
    if host_cv is None or not _has(host_cv, 'M7_eBPF_C2_Correlated'):
        return None
    return TTPMatch(
        pattern='bpfdoor-magic-packet-c2', pid=cv.pid, process=cv.process,
        mitre=['T1205.002', 'T1014'], confidence='high',
        evidence=[n for n in _dim_names(cv, positive=True) if 'M18_' in n] +
                 [n for n in _dim_names(host_cv, positive=True) if 'M7_' in n],
        description=(f'PID {cv.pid} ({cv.process}): BPFDoor magic-packet trigger sequence '
                     'recovered from a static/carved copy of this process AND the host-scope '
                     'live kernel-level eBPF-hook/netfilter-hook co-occurrence independently '
                     'confirmed -- both the wire-protocol artifact and the live activation '
                     'mechanism are present.'),
    )


def _match_ssh_backdoor_persistence(cv: CorrelationVerdict, host_cv: Optional[CorrelationVerdict]) -> Optional[TTPMatch]:
    """Keyutils/network capability-mismatch backdoor (Ebury-class, PID-scoped:
    tied to the carved libkeyutils.so copy) co-occurring with an SSH
    persistence signal (mostly host-scope: edr_hunt.py's authorized_keys/
    sshd_config checks target file paths, not a PID) -- the credential-
    harvesting backdoor paired with its own persistence mechanism. Checks
    both this PID's verdict and the host-scope verdict since either can
    carry the SSH-persistence half."""
    if cv.pid == HOST_SCOPE_PID:
        return None
    has_ebury = any(d.positive and 'Ebury' in d.rationale
                    for d in (cv.memory_verdict.dimensions if cv.memory_verdict else []))
    if not has_ebury:
        return None
    has_ssh_persist_here = _has(cv, 'M11_SSH_StructuralAnomaly', 'M9_Persistence')
    has_ssh_persist_host = host_cv is not None and _has(host_cv, 'M11_SSH_StructuralAnomaly', 'M9_Persistence')
    if not (has_ssh_persist_here or has_ssh_persist_host):
        return None
    evidence = [n for n in _dim_names(cv, positive=True) if 'M11_' in n or 'M9_' in n]
    if host_cv is not None:
        evidence += [n for n in _dim_names(host_cv, positive=True) if 'M11_' in n or 'M9_' in n]
    return TTPMatch(
        pattern='ssh-backdoor-with-persistence', pid=cv.pid, process=cv.process,
        mitre=['T1556', 'T1098.004'], confidence='high', evidence=evidence,
        description=(f'PID {cv.pid} ({cv.process}): keyutils/network capability-mismatch '
                     'backdoor (Ebury-class) co-occurs with an SSH persistence anomaly on the '
                     'same host -- credential interception paired with its own foothold mechanism.'),
    )


def _match_container_breakout_to_host(cv: CorrelationVerdict, chain: Optional[AttackChain]) -> Optional[TTPMatch]:
    """Namespace-escape/bind-mount runtime signal chained to host-scope
    persistence or kernel-rootkit findings -- the breakout led somewhere,
    not just a configuration exposure."""
    if not _has(cv, 'M8_NamespaceEscape_Runtime'):
        return None
    if chain is None:
        return None
    has_host_impact = any(e.stage in ('persistence', 'defense-evasion', 'privilege-escalation')
                          for e in chain.events if e.pid != cv.pid)
    if not has_host_impact:
        return None
    return TTPMatch(
        pattern='container-breakout-to-host', pid=cv.pid, process=cv.process,
        mitre=['T1611', 'T1610'], confidence='medium',
        evidence=[n for n in _dim_names(cv, positive=True) if 'M8_' in n],
        description=(f'PID {cv.pid} ({cv.process}): observed namespace/mount escape chained to '
                     'host-scope persistence or defense-evasion activity in the same timeline -- '
                     'the breakout was followed by host-level action, not just a config exposure.'),
    )


def _match_fileless_beacon(cv: CorrelationVerdict) -> Optional[TTPMatch]:
    """Deleted/memfd execution + injected anonymous-executable memory in the
    same process -- fileless implant staged and running, independent of
    whether a named C2 framework's config was recoverable."""
    if not _has(cv, 'M1_MemfdExec', 'M1_DeletedOrExec_WritablePath'):
        return None
    if not _has(cv, 'M3_Injected_AnonExec'):
        return None
    return TTPMatch(
        pattern='fileless-beacon', pid=cv.pid, process=cv.process,
        mitre=['T1055', 'T1620', 'T1070.004'], confidence='high',
        evidence=[n for n in _dim_names(cv, positive=True) if 'M1_' in n or 'M3_' in n],
        description=(f'PID {cv.pid} ({cv.process}): unlinked/memfd-backed execution combined '
                     'with anonymous executable memory in a non-JIT process -- fileless implant '
                     'staged and running in memory, independent of named-family identification.'),
    )


_MATCHERS_SIMPLE = [_match_fileless_beacon]
# Matchers that need the host-scope verdict alongside this PID's, because the
# two halves of the pattern live on different verdicts (a kernel module or a
# file-path-targeted check has no owning PID; see each matcher's docstring).
_MATCHERS_WITH_HOST = [_match_miner_rootkit, _match_bpfdoor_activation, _match_ssh_backdoor_persistence]
_MATCHERS_WITH_CHAIN = [_match_container_breakout_to_host]


def match_patterns(correlation_results: List[CorrelationVerdict],
                   chains: Optional[List[AttackChain]] = None) -> List[TTPMatch]:
    chain_by_pid: Dict[int, AttackChain] = {c.root_pid: c for c in (chains or [])}
    host_cv = next((cv for cv in correlation_results if cv.pid == HOST_SCOPE_PID), None)
    matches: List[TTPMatch] = []

    for cv in correlation_results:
        if not cv.memory_verdict or not cv.memory_verdict.dimensions:
            continue
        chain = chain_by_pid.get(cv.pid)

        for fn in _MATCHERS_SIMPLE:
            m = fn(cv)
            if m:
                matches.append(m)
        for fn in _MATCHERS_WITH_HOST:
            m = fn(cv, host_cv)
            if m:
                matches.append(m)
        for fn in _MATCHERS_WITH_CHAIN:
            m = fn(cv, chain)
            if m:
                matches.append(m)

    return matches
