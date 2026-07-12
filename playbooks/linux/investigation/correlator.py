"""Multi-source correlation layer (Linux) -- the QA pass across collectors.

Unlike the Windows engine (which has to reconcile several genuinely different
schemas -- mwcp hits, deep_sensor_ml EDR events, parsed Windows event log
entries -- into one scoring model), every Linux collector in this toolkit
already emits the SAME common schema by design:

    {Timestamp, Severity, Type, Target, Details, MITRE}

edr_hunt.py, analyze_memory_linux.py, journal_analysis.py, container_hunt.py,
remote_access_triage.py, and memory_enrich.py/mwcp_parsers/'s findings
all merge into Combined_Findings_*.json for exactly this reason. So the
Linux correlator's job is NOT translating incompatible shapes into a shared
weight model (that's what the Windows correlator's _score_mwcp/_score_edr/
_score_eventlog do) -- it's merging multiple already-compatible finding
lists, tagging which collector each finding came from for provenance, and
running the SAME tiered-evidence engine over the union. Cross-source
strength shows up naturally: a PID with an M3 injected-memory finding (from
analyze_memory_linux.py) AND an M19 remote-access finding (from
remote_access_triage.py) AND an M9 persistence finding (from journal_analysis.py)
already accumulates 3 independent module dimensions across 3 different
collectors -- exactly the "combination breaks the deception" principle the
Windows correlator's docstring describes, achieved here without a separate
weighting system.
"""
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .engine import investigate, _parse_pid_target, _assemble_verdict, _propagate_process_lineage
from .process_tree import load_from_adjudication
from .verdict import Verdict, VerdictLabel, Dimension, Tier, HOST_SCOPE_PID


@dataclass
class CrossSourceSignal:
    source: str       # 'memory', 'edr', 'journal', 'container', 'remote_access', 'c2_config'
    positive: bool
    weight: float
    description: str


@dataclass
class CorrelationVerdict:
    pid: int
    process: str
    label: VerdictLabel
    memory_verdict: Optional[Verdict]
    signals: List[CrossSourceSignal]
    positive_weight: float
    rationale: str
    all_evidence: Dict[str, List[dict]] = field(default_factory=dict)


# Any collector source not in this map is tagged 'memory' by default -- the
# vast majority of high-signal Types (injected memory, kernel rootkit, YARA)
# come from analyze_memory_linux.py regardless of which list the caller
# happened to pass it in under.
_TYPE_SOURCE_HINTS = {
    'Suspicious Cron Job': 'journal', 'Suspicious Service Execution': 'journal',
    'New Account Created': 'journal', 'Remote Root Logon': 'journal',
    'Unsigned Kernel Module': 'journal', 'Journal Log Truncation': 'journal',
    'Audit Logging Disabled': 'journal', 'Mandatory Access Control Disabled': 'journal',
    'Remote-Access Service': 'journal', 'SSH Brute Force': 'journal',
    'Package Manager Transaction': 'journal',
    'Container Host Namespace': 'container', 'Docker Socket Mount': 'container',
    'Privileged Container': 'container', 'Sensitive Host Mount': 'container',
    'Dangerous Container Capabilities': 'container', 'Pod Host Namespace': 'container',
    'Pod hostPath Mount': 'container', 'Privileged Pod Container': 'container',
    'Pod Privilege Escalation Allowed': 'container', 'Pod Dangerous Capabilities': 'container',
    'ClusterAdmin Binding': 'container',
    'Remote Access Tool': 'remote_access', 'Crypto Miner': 'remote_access',
    'Listening Service': 'remote_access', 'SSH Config Weakness': 'remote_access',
    'Process Thread Inventory (memory)': 'thread_inventory',
    'Traced Thread Detail (memory)': 'thread_inventory',
}


def _source_of(finding: dict) -> str:
    explicit = finding.get('Source', '')
    if explicit and explicit != 'Memory':
        return explicit.lower()
    ftype = finding.get('Type', '')
    if ftype.startswith(('C2 Config Recovered', 'BPFDoor', 'Botnet Config',
                         'SSH Backdoor Artifact', 'Cryptominer', 'Exfiltration Channel',
                         'Cloud Credential', 'Tor C2', 'C2 Endpoint')):
        return 'c2_config'
    return _TYPE_SOURCE_HINTS.get(ftype, 'memory')


def _package_integrity_dimension(entry: dict) -> Optional[Dimension]:
    """Pursue the lead adjudicate.py already ran the checks for, rather than
    leaving a "go verify this" note unresolved. adjudicate.py's own docstring
    names package ownership + integrity as THIS TOOLKIT'S TRUST ANCHOR (there
    is no Authenticode on Linux) and its adjudicate() function's first rule
    is unconditional: a package-owned binary that's been modified on disk is
    "Likely True Positive, High" regardless of finding type. A module like
    deleted_binary.py can only say "verify package ownership before closing"
    from the finding text alone -- it has no filesystem access. When
    Adjudication_*.json is available, this closes that lead definitively
    instead of leaving it as an instruction to the analyst.
    """
    owner = entry.get('PkgOwner')
    modified = entry.get('PkgModified')
    exists = entry.get('FileExists')
    trust = entry.get('PathTrust')
    path = entry.get('SubjectPath') or ''

    if owner and modified is True:
        return Dimension(
            name='M_PackageIntegrity_Tampered', positive=True, source_module=0,
            tier=Tier.DEFINITIVE,
            rationale=(f'Package-owned binary {path!r} (owner={owner}) was modified on disk after '
                       'install -- integrity check failed. This is adjudicate.py\'s own top-priority '
                       'rule (tampered packaged binary, regardless of finding type) and is as close '
                       'to unforgeable as this toolkit\'s trust model gets: a legitimate package '
                       'manager does not let installed files drift from their signed contents.')
        )
    if not owner and trust == 'Trusted-Location' and exists:
        return Dimension(
            name='M_PackageIntegrity_UnownedInTrustedPath', positive=True, source_module=0,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{path!r} sits in a trusted system directory but is owned by NO package -- '
                       'every legitimate file under /usr, /bin, /lib is normally package-managed; '
                       'an unowned file there is a planted binary wearing a trusted path, not '
                       'evidence the path itself vouches for it.')
        )
    if owner and modified is False and exists:
        return Dimension(
            name='M_PackageIntegrity_Confirmed', positive=False, source_module=0,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{path!r} is owned by package {owner!r} and verified unmodified on disk -- '
                       'this closes the "verify package ownership before treating as FP" lead that '
                       'a path-trust heuristic alone cannot resolve.')
        )
    return None


def _normalize_pkg_name(name: str) -> str:
    """Reduce a PkgOwner string to a bare package name so it compares equal to
    a journal_analysis.py package-event's name, regardless of which resolver
    produced it: dpkg -S gives 'name' already; rpm -qf gives a full NVRA
    ('name-version-release.arch'); pacman -Qo gives 'name version'."""
    name = (name or '').strip()
    if not name:
        return ''
    name = name.split()[0]                              # pacman: "name version" -> "name"
    stripped = re.sub(r'-[^-]+-[^-]+\.[^-.]+$', '', name)  # rpm NVRA -> name
    return stripped if stripped != name or '-' not in name else name


def _package_upgrade_window_dimension(owner: str, package_events: List[dict]) -> Optional[Dimension]:
    """Pursue deleted_binary.py's own "verify with journalctl/package-manager
    log for an upgrade window before closing as FP" lead with an actual
    matching transaction, rather than leaving it as an instruction to the
    analyst. Fires independently of _package_integrity_dimension: a deleted
    running binary's backing file no longer exists on disk, so pkg_modified()
    in adjudicate.py typically can't determine a modified/unmodified verdict
    at all -- this is the one signal that still closes the lead in exactly
    that gap.
    """
    target = _normalize_pkg_name(owner)
    if not target:
        return None
    for ev in package_events:
        if ev.get('Type') != 'Package Manager Transaction':
            continue
        pkg_m = re.match(r'package (\S+)', ev.get('Target', ''))
        if not pkg_m or pkg_m.group(1) != target:
            continue
        return Dimension(
            name='M_PackageIntegrity_UpgradeWindowConfirmed', positive=False, source_module=0,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'Package manager log confirms a real transaction for {target!r}: '
                       f'{ev.get("Details", "")} -- this closes the "verify with journalctl/'
                       'package-manager log for an upgrade window" lead with an actual matching '
                       'event, not a trusted-path assumption alone.')
        )
    return None


def correlate(memory_findings: List[dict],
             journal_findings: Optional[List[dict]] = None,
             container_findings: Optional[List[dict]] = None,
             remote_access_findings: Optional[List[dict]] = None,
             c2_config_findings: Optional[List[dict]] = None,
             adjudication_entries: Optional[List[dict]] = None) -> List[CorrelationVerdict]:
    """
    Merge every collector's findings (already common-schema) and run the
    tiered-evidence engine over the union. Returns one CorrelationVerdict per
    unique PID (plus the HOST_SCOPE_PID pseudo-PID for kernel/persistence/
    account findings with no owning process).

    adjudication_entries (Adjudication_*.json, when available) feeds each
    PID's already-computed package-ownership/integrity result back into the
    tiered verdict as a real dimension -- see _package_integrity_dimension()
    for why this is the single highest-value lead this engine can pursue
    automatically rather than leaving as an instruction to the analyst. The
    same adjudication data also carries ParentPid, which builds the process
    tree _propagate_process_lineage() needs for direct parent/child
    corroboration (engine.py's own Step 4 covers shared network
    infrastructure; lineage is the process-tree analog of that same lead).
    """
    all_findings: List[dict] = list(memory_findings or [])
    for extra in (journal_findings, container_findings, remote_access_findings, c2_config_findings):
        if extra:
            all_findings.extend(extra)

    verdicts = investigate(all_findings)

    # Pursue the package-integrity lead per PID, re-assembling the verdict
    # when adjudication data adds a new dimension (same pattern as the
    # Windows engine's Step 4 cross-PID handle-corroboration propagation).
    #
    # Most real-world Linux findings (SUID binaries, dangerous capabilities,
    # kernel module checks) are HOST-SCOPE -- edr_hunt.py targets a file path,
    # not a PID, so adjudicate.py's own enrich() leaves Pid=None for these
    # even though it still resolves PkgOwner/PkgModified/FileExists from the
    # SubjectPath. Skipping entries with no Pid would silently discard the
    # package-integrity lead for the majority case; route those into
    # HOST_SCOPE_PID instead of dropping them.
    if adjudication_entries:
        package_events = [f for f in (journal_findings or [])
                          if f.get('Type') == 'Package Manager Transaction']
        pkg_dims_by_pid: Dict[int, List[Dimension]] = defaultdict(list)
        for entry in adjudication_entries:
            pid_raw = entry.get('Pid')
            try:
                pid = int(pid_raw)
            except (TypeError, ValueError):
                pid = HOST_SCOPE_PID
            dim = _package_integrity_dimension(entry)
            if dim:
                pkg_dims_by_pid[pid].append(dim)
            # Independent of _package_integrity_dimension: fires even when the
            # backing file no longer exists (deleted running binary), the one
            # case where pkg_modified() usually can't return a verdict at all.
            window_dim = _package_upgrade_window_dimension(entry.get('PkgOwner'), package_events)
            if window_dim:
                pkg_dims_by_pid[pid].append(window_dim)

        if pkg_dims_by_pid:
            updated = []
            for v in verdicts:
                extra_dims = pkg_dims_by_pid.get(v.pid)
                if extra_dims:
                    v = _assemble_verdict(v.pid, v.process, v.dimensions + extra_dims, v.findings)
                updated.append(v)
            verdicts = updated

        # Direct parent/child lineage corroboration -- same adjudication data
        # already resolved ParentPid, so build the tree from it and pursue
        # the lead engine.py's own Step 4 network propagation can't reach
        # (see _propagate_process_lineage's docstring for the safeguards).
        tree = load_from_adjudication(adjudication_entries)
        verdicts = _propagate_process_lineage(verdicts, tree)

    results: List[CorrelationVerdict] = []
    for v in verdicts:
        signals = [
            CrossSourceSignal(
                source=_source_of(f), positive=True, weight=1.0,
                description=f'{f.get("Type", "")}: {f.get("Details", "")[:120]}'
            )
            for f in v.findings
        ]
        results.append(CorrelationVerdict(
            pid=v.pid, process=v.process, label=v.label, memory_verdict=v,
            signals=signals, positive_weight=float(v.positive_count),
            rationale=v.rationale,
            all_evidence={'memory': [f for f in all_findings
                                     if _parse_pid_target(f.get('Target', ''), f.get('Details', ''))[0] == v.pid]},
        ))
    return results
