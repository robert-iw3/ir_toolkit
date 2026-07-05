"""Investigation engine orchestrator.

Entry point: investigate(findings) -> List[Verdict]

Accepts the findings list from memory_forensic.py (Memory_Findings_*.json),
groups by PID, then for each PID:

  1. ML noise filter -- separates normal Windows system background noise from
     anomalous activity trying to blend in with system operations.
     If certainty-benign: NOISE_CLOSED verdict, no module investigation.

  2. Per-module investigation -- runs the appropriate investigation module
     for each finding type (dormant beacon, shellcode thread, ntdll hook, etc.)
     and collects Dimension objects (positive/negative).

  3. Verdict assembly (tiered evidence model -- see planning/CURRENT-STATE-AND-
     OPEN-ITEMS.md §4 design note for the full rationale):
     - Tier 0 (INVALID) dimensions excluded before scoring entirely (category error).
     - Any Tier 1 (DEFINITIVE) positive -> TRUE_POSITIVE immediately (single
       structurally-unforgeable fact settles it). Pure additive shortcut on top of
       the rule below -- never removes a case that used to reach TP.
     - Otherwise, 3+ Tier 1/2 positive dimensions -> TRUE_POSITIVE (Tier 3 positives
       never count toward this floor, regardless of how many exist).
     - 0 countable (Tier 1/2) positive dimensions AND no Tier 3 positives either
       -> FALSE_POSITIVE (with documented rationale).
     - Otherwise -> UNDETERMINED (more evidence needed; Tier-3-only positives are
       noted as "capability without demonstrated use", not closed either way).
"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .verdict import Verdict, VerdictLabel, Dimension, Tier, TP_DIMENSION_THRESHOLD
from .fp_closure import build_fp_closure, build_noise_closure
from .models.noise_filter import classify_noise
from .modules import (
    dormant_beacon,
    shellcode_thread,
    ntdll_hook,
    ekko_sleep,
    injected_memory,
    ppid_orphan,
    peb_decoy,
    clr_assembly,
    com_vtable,
    direct_syscall,
    handle_attribution,
)

# Map finding Type string -> module number for routing
_TYPE_TO_MODULE: Dict[str, int] = {
    'Dormant Beacon Candidate (Memory)':      13,
    'Shellcode Thread (Memory)':               5,
    'Manually-Mapped PE (Memory)':             5,
    'ntdll Syscall Stub Patched (Memory)':    12,
    'Thread-Pool / Ekko Pattern (Memory)':    14,
    'Injected Memory Region':                  3,
    'Injected Memory Cap Reached':             3,
    'Process Hollowing Indicator (Memory)':    3,
    'PPID Orphan (Memory)':                   17,
    'PEB CommandLine Pointer (Memory)':       15,
    'CLR Execute-Assembly (Memory)':          16,
    'COM VTable Hijacking (Memory)':          18,
    'YARA Hit (Memory)':                      19,
    'Direct Syscall Execution':               20,
    'Cross-Process Handle (Memory)':          23,
    'Cross-Process Thread Handle (Memory)':   23,
    'Hidden Process (Memory)':                99,  # handled inline
    'Suspicious Command Line (Memory)':       99,
    'External Network Connection':             4,  # context only
}

# NOTE: This engine detects STRUCTURAL and BEHAVIORAL anomalies in memory.
# It does NOT check for named malware families -- that is the job of the YARA
# and mwcp layers upstream. Here, a YARA hit matters because it fired in an
# ANONYMOUS EXECUTABLE REGION (structural indicator: code running outside any
# loaded module), not because of which rule or family name matched.
# An adversary blending into normal admin activity will NOT have a named-family
# signature. The engine must find them anyway via memory structure signals.


def _parse_pid_process(target: str) -> Tuple[int, str, str]:
    """Extract (pid, process_name, address) from 'PID 1234 (proc.exe) @ 0x...'"""
    m = re.match(r'PID\s+(\d+)\s+\(([^)]+)\)', target)
    if not m:
        return 0, target, ''
    pid  = int(m.group(1))
    proc = m.group(2)
    addr_m = re.search(r'@\s*(0x[0-9a-f]+)', target, re.IGNORECASE)
    return pid, proc, (addr_m.group(1) if addr_m else '')


def _group_by_pid(findings: List[dict]) -> Dict[int, List[dict]]:
    groups: Dict[int, List[dict]] = defaultdict(list)
    for f in findings:
        pid, _, _ = _parse_pid_process(f.get('Target', ''))
        if pid > 0:
            groups[pid].append(f)
    return groups


def _get_process_info(pid_findings: List[dict]) -> Tuple[str, str, str]:
    """Return (process_name, process_path, parent_name) from any finding for this PID."""
    for f in pid_findings:
        _, proc, _ = _parse_pid_process(f.get('Target', ''))
        if not proc:
            continue
        details = f.get('Details', '')
        path_m   = re.search(r'[Pp]ath=([^\s,;]+)|ImagePath=([^\s,;]+)', details)
        path     = (path_m.group(1) or path_m.group(2)) if path_m else ''
        parent_m = re.search(r'[Pp]arent=([^\s,;]+)|PPID.*\(([^)]+)\)', details)
        parent   = (parent_m.group(1) or (parent_m.group(2) if parent_m else '')) if parent_m else ''
        return proc, path, parent
    return '', '', ''


def _get_m13_details(pid_findings: List[dict]) -> str:
    for f in pid_findings:
        if 'Dormant Beacon' in f.get('Type', ''):
            return f.get('Details', '')
    return ''


def _has_network(pid_findings: List[dict]) -> bool:
    return any('Network Connection' in f.get('Type', '') or
               'ESTABLISHED' in f.get('Details', '')
               for f in pid_findings)


def _dedup_dimensions(dims: List[Dimension]) -> List[Dimension]:
    """Collapse identical dimensions into one, preserving the observation count.

    Repetition is not independence: many findings describing the same evidence
    (same dimension name, polarity, and rationale -- module rationales embed the
    region address, so distinct regions stay distinct) must count as ONE
    dimension toward the TP threshold, not one per finding.
    """
    merged: Dict[Tuple[str, bool, str], int] = {}
    first: Dict[Tuple[str, bool, str], Dimension] = {}
    order: List[Tuple[str, bool, str]] = []
    for d in dims:
        key = (d.name, d.positive, d.rationale)
        if key not in merged:
            merged[key] = 0
            first[key] = d
            order.append(key)
        merged[key] += 1
    out: List[Dimension] = []
    for key in order:
        d = first[key]
        n = merged[key]
        if n > 1:
            d = Dimension(
                name=d.name, positive=d.positive,
                rationale=f'{d.rationale} [observed in {n} findings]',
                source_module=d.source_module,
            )
        out.append(d)
    return out


def _investigate_pid(pid: int, pid_findings: List[dict],
                     all_findings: List[dict]) -> Verdict:
    process, path, parent = _get_process_info(pid_findings)

    # -------------------------------------------------------------------------
    # Step 1: ML noise filter
    # Goal: close out normal Windows system background (taskhostw work items,
    # COM infrastructure, audio buffers) WITHOUT wasting CPU on module logic.
    # A process blending in with system operations will NOT pass this filter.
    # -------------------------------------------------------------------------
    m13_details = _get_m13_details(pid_findings)
    is_noise, noise_score, noise_rationale = classify_noise(
        process, path, parent, m13_details
    )

    # Network activity disqualifies noise closure: a C2 beacon that is also
    # background noise is a contradiction -- if it has active external connections
    # it must be investigated regardless of byte-distribution profile.
    if is_noise and not _has_network(pid_findings):
        return build_noise_closure(pid, process, noise_rationale, pid_findings, noise_score)

    # -------------------------------------------------------------------------
    # Step 2: Per-module investigation
    # -------------------------------------------------------------------------
    all_dims: List[Dimension] = []
    m13_dims: List[Dimension] = []
    syscall_findings: List[dict] = []
    uncorroborated_injected: List[dict] = []
    handle_findings: List[dict] = []

    for finding in pid_findings:
        ftype   = finding.get('Type', '')
        mod_num = _TYPE_TO_MODULE.get(ftype, 0)

        if mod_num == 13:
            d = dormant_beacon.investigate(finding)
            m13_dims.extend(d)
            all_dims.extend(d)

        elif mod_num == 5:
            all_dims.extend(shellcode_thread.investigate(finding))

        elif mod_num == 12:
            all_dims.extend(ntdll_hook.investigate(finding))

        elif mod_num == 14:
            # Module 14 verdict depends on Module 13 signals -- pass m13_dims
            all_dims.extend(ekko_sleep.investigate(finding, m13_dims=m13_dims))

        elif mod_num == 3:
            d = injected_memory.investigate(finding, all_findings=all_findings)
            if d:
                all_dims.extend(d)
            else:
                # No per-region corroboration (MZ/thread/YARA) -- may still be
                # shared-section/high-user-space (already fully handled, empty
                # is correct) or a genuine uncorroborated anon-exec region.
                # Route true uncorroborated candidates to the per-PID aggregate
                # below rather than silently dropping them or double-counting.
                is_candidate, _ = injected_memory.is_uncorroborated(finding)
                if is_candidate:
                    uncorroborated_injected.append(finding)

        elif mod_num == 17:
            all_dims.extend(ppid_orphan.investigate(finding))

        elif mod_num == 15:
            all_dims.extend(peb_decoy.investigate(finding))

        elif mod_num == 16:
            all_dims.extend(clr_assembly.investigate(finding))

        elif mod_num == 18:
            all_dims.extend(com_vtable.investigate(finding))

        elif mod_num == 19:
            all_dims.extend(_investigate_yara(finding))

        elif mod_num == 20:
            # Aggregated per-PID below, not per-finding -- a JIT-heavy managed
            # host can produce dozens of syscall regions from one behavioral
            # pattern; scoring each independently fabricates dimension count.
            syscall_findings.append(finding)

        elif mod_num == 23:
            # Aggregated per-PID below, not per-finding -- a single holder can touch
            # dozens of distinct target PIDs (lsass.exe's session bookkeeping alone
            # is ~30 on a real host); scoring each target independently fabricates
            # dimension count the same way Module 20's per-region scoring did.
            handle_findings.append(finding)

        elif mod_num == 99:
            all_dims.extend(_investigate_misc(finding))

    if syscall_findings:
        all_dims.extend(direct_syscall.investigate_pid(syscall_findings, pid_findings))

    if handle_findings:
        all_dims.extend(handle_attribution.investigate_pid(handle_findings))

    if uncorroborated_injected:
        all_dims.extend(injected_memory.investigate_uncorroborated_pid(uncorroborated_injected))

    return _assemble_verdict(pid, process, all_dims, pid_findings)


def _assemble_verdict(pid: int, process: str, all_dims: List[Dimension],
                      pid_findings: List[dict]) -> Verdict:
    """Step 3: Verdict assembly (tiered evidence model). Factored out of
    _investigate_pid so Step 4 (cross-PID relationship propagation, see
    _propagate_handle_corroboration) can re-run assembly with an added dimension
    without duplicating the tiering rules."""
    all_dims = _dedup_dimensions(all_dims)
    # Tier 0 (INVALID): category error, not a benign-vs-malicious judgment -- excluded
    # before scoring entirely. No module emits Tier 0 yet (that filtering currently
    # happens at the data-extraction layer, e.g. memory_enrich.py's beyond-shadow-of-
    # doubt filters); this is forward-compatible plumbing for when one does.
    all_dims = [d for d in all_dims if d.tier != Tier.INVALID]
    pos_dims = [d for d in all_dims if d.positive]
    neg_dims = [d for d in all_dims if not d.positive]

    # Tier 1 (DEFINITIVE): a single structurally-unforgeable positive settles the
    # question immediately. Pure ADDITIVE shortcut on top of the threshold rule below
    # -- it can only turn a case that used to be UNDETERMINED (diluted into a dimension
    # count that never reached 3) into the TRUE_POSITIVE it should have been; it never
    # removes a verdict that already reached TP via the threshold rule. No module
    # tags Tier 1 yet either, so this has zero effect until one is migrated to it.
    tier1_pos = [d for d in pos_dims if d.tier == Tier.DEFINITIVE]
    if tier1_pos:
        rationale = (
            f'TRUE POSITIVE: PID {pid} ({process}) -- Tier 1 (DEFINITIVE) evidence: '
            f'a single structurally-unforgeable fact settles this.\n\n'
            + '\n'.join(f'  [TP-TIER1] M{d.source_module} {d.name}: {d.rationale}' for d in tier1_pos)
        )
        other_pos = [d for d in pos_dims if d not in tier1_pos]
        if other_pos:
            rationale += '\n\nOther positive dimensions:\n' + '\n'.join(
                f'  [TP] M{d.source_module} {d.name}: {d.rationale}' for d in other_pos)
        if neg_dims:
            rationale += '\n\nNegative dimensions (documented):\n' + '\n'.join(
                f'  [FP] M{d.source_module} {d.name}: {d.rationale}' for d in neg_dims)
        return Verdict(
            pid=pid, process=process, label=VerdictLabel.TRUE_POSITIVE,
            dimensions=all_dims, positive_count=len(pos_dims),
            negative_count=len(neg_dims), rationale=rationale,
            findings=pid_findings,
        )

    # Tier 3 (WEAK/STRUCTURAL): capability without demonstrated use can NEVER alone
    # reach TP, regardless of count -- excluded from the threshold-3 count below. No
    # module tags Tier 3 yet, so countable_pos == pos_dims until one is migrated.
    countable_pos = [d for d in pos_dims if d.tier != Tier.WEAK_STRUCTURAL]
    tier3_only_pos = [d for d in pos_dims if d.tier == Tier.WEAK_STRUCTURAL]
    pos_count = len(countable_pos)

    if pos_count >= TP_DIMENSION_THRESHOLD:
        unique_mods = len({d.source_module for d in countable_pos})
        rationale = (
            f'TRUE POSITIVE: PID {pid} ({process}) -- '
            f'{pos_count} independent positive dimension(s) across {unique_mods} module(s).\n\n'
            + '\n'.join(f'  [TP] M{d.source_module} {d.name}: {d.rationale}' for d in countable_pos)
        )
        if neg_dims:
            rationale += '\n\nNegative dimensions (documented):\n'
            rationale += '\n'.join(f'  [FP] M{d.source_module} {d.name}: {d.rationale}' for d in neg_dims)
        return Verdict(
            pid=pid, process=process, label=VerdictLabel.TRUE_POSITIVE,
            dimensions=all_dims, positive_count=len(pos_dims),
            negative_count=len(neg_dims), rationale=rationale,
            findings=pid_findings,
        )

    elif pos_count == 0 and not tier3_only_pos:
        return build_fp_closure(pid, process, all_dims, pid_findings)

    else:
        rationale = (
            f'UNDETERMINED: PID {pid} ({process}) -- '
            f'{pos_count} positive dimension(s), threshold={TP_DIMENSION_THRESHOLD}. '
            f'Insufficient for TP verdict; additional collection or correlation required.\n\n'
            + '\n'.join(
                f'  [{"TP" if d.positive else "FP"}] M{d.source_module} {d.name}: {d.rationale}'
                for d in all_dims
            )
        )
        if tier3_only_pos:
            rationale += (
                f'\n\n{len(tier3_only_pos)} Tier-3 (weak/structural) positive dimension(s) present -- '
                'capability without demonstrated use; cannot alone justify TP. Needs more Tier-2 '
                'evidence (enrichment, handle-walk, repeat capture) to progress.'
            )
        return Verdict(
            pid=pid, process=process, label=VerdictLabel.UNDETERMINED,
            dimensions=all_dims, positive_count=len(pos_dims),
            negative_count=len(neg_dims), rationale=rationale,
            findings=pid_findings,
        )


def _investigate_yara(finding: dict) -> List[Dimension]:
    """Classify a YARA hit purely by WHERE it fired, not WHICH rule.

    Structural classification:
      anon exec region -> elevated suspicion (code running outside loaded modules)
      file-backed      -> lower significance (may be rule FP on unmodified binary)

    This approach detects adversaries with NO named signature -- an unknown implant
    in anonymous memory still shows as anomalous code execution.
    """
    details      = finding.get('Details', '')
    is_file_back = 'file-backed' in details.lower()
    in_anon      = bool(re.search(r'anon|anonymous|private', details, re.IGNORECASE))
    rule_m       = re.search(r'\|\s*([A-Za-z0-9_]+)\s*\|', details)
    rule_name    = rule_m.group(1) if rule_m else 'unknown'
    hit_count_m  = re.search(r'(\d+)\s+match', details, re.IGNORECASE)
    hit_count    = int(hit_count_m.group(1)) if hit_count_m else 1

    if in_anon and not is_file_back:
        return [Dimension(
            name='Module19_YARA_AnonExec', positive=True, source_module=19,
            rationale=(f'YARA rule [{rule_name}] fired in ANONYMOUS executable region '
                       f'({hit_count} match(es)). Structural indicator: code is executing '
                       'outside any loaded module. Family identity irrelevant -- '
                       'adversaries without named signatures produce the same structural signal.')
        )]
    if is_file_back:
        return [Dimension(
            name='Module19_YARA_FileBacked', positive=False, source_module=19,
            rationale=(f'YARA rule [{rule_name}] fired in FILE-BACKED region -- '
                       'matched bytes are inside the loaded image, not anonymous code. '
                       'May be a rule FP on an unmodified binary. '
                       'Verify binary hash and Authenticode signer before closing.')
        )]
    return [Dimension(
        name='Module19_YARA_Unknown', positive=False, source_module=19,
        rationale=f'YARA hit [{rule_name}]: insufficient context (anon vs file-backed unknown)'
    )]


def _investigate_misc(finding: dict) -> List[Dimension]:
    ftype   = finding.get('Type', '')
    details = finding.get('Details', '')

    if 'Hidden Process' in ftype:
        return [Dimension(
            name='Module_HiddenProcess', positive=True, source_module=0,
            rationale=('DKOM/PEB-unlink artifact: process hidden from normal enumeration -- '
                       'definitive anti-forensic indicator; active rootkit or process injection')
        )]
    if 'Suspicious Command Line' in ftype:
        score_m = re.search(r'Score=(\d+)', details)
        score   = int(score_m.group(1)) if score_m else 0
        hits_m  = re.search(r'\[([^\]]+)\]', details)
        hits    = hits_m.group(1) if hits_m else ''
        return [Dimension(
            name='Module_SuspiciousCmdLine', positive=score >= 3, source_module=0,
            rationale=(f'Suspicious command line score={score} [{hits}] -- '
                       + ('high-confidence malicious command pattern' if score >= 3
                          else 'low-confidence; requires corroboration'))
        )]
    return []


_HANDLE_REL_RE = re.compile(r'^PID\s+(\d+)\s+\([^)]+\)\s*->\s*Target PID\s+(\d+)')


def _extract_handle_relationships(findings: List[dict]) -> Dict[int, set]:
    """{holder_pid: {target_pid, ...}} from Module 23's Cross-Process Handle/Thread
    Handle findings. Read directly from the raw findings (not from Dimension
    objects, which only carry aggregate counts) so this stays decoupled from
    handle_attribution.py's internal dimension shape."""
    rel: Dict[int, set] = {}
    for f in findings:
        if f.get('Type') not in ('Cross-Process Handle (Memory)', 'Cross-Process Thread Handle (Memory)'):
            continue
        m = _HANDLE_REL_RE.match(f.get('Target', ''))
        if not m:
            continue
        holder_pid, target_pid = int(m.group(1)), int(m.group(2))
        rel.setdefault(holder_pid, set()).add(target_pid)
    return rel


def _propagate_handle_corroboration(verdicts: List[Verdict], findings: List[dict]) -> List[Verdict]:
    """Step 4: cross-PID relationship propagation (single pass, not iterated to a
    fixed point -- bounded and simple to reason about; extend later if cascading
    turns out to matter). For every holder->target handle relationship (Module 23),
    if the target's OWN independently-computed verdict is TRUE_POSITIVE, that is
    new evidence for the holder: a structurally-unforgeable handle relationship
    into a process ALREADY confirmed compromised is exactly 'tracing a lead to see
    where it goes' rather than treating each PID's verdict as an island.

    Deliberately does NOT go the other direction (a clean-looking target does not
    exonerate the holder -- a capability finding into an innocent-looking process
    is still a capability finding; see detection-design memory Rule 4/4b and the
    'assume compromise, prove otherwise' directive)."""
    rel = _extract_handle_relationships(findings)
    if not rel:
        return verdicts

    verdict_by_pid = {v.pid: v for v in verdicts}
    out = []
    for v in verdicts:
        targets = rel.get(v.pid)
        if not targets:
            out.append(v)
            continue
        confirmed_targets = [t for t in sorted(targets)
                             if t in verdict_by_pid and verdict_by_pid[t].label == VerdictLabel.TRUE_POSITIVE]
        if not confirmed_targets:
            out.append(v)
            continue
        corroboration = Dimension(
            name='Module23_CrossPID_TargetCorroboration', positive=True, source_module=23,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'Holds a Module 23 cross-process handle into PID(s) '
                       f'{", ".join(str(t) for t in confirmed_targets)}, each independently confirmed '
                       'TRUE_POSITIVE on its own separate evidence -- tracing this structurally-'
                       'unforgeable relationship to an already-confirmed-compromised target is new '
                       'corroboration for this holder, not just an isolated capability claim.')
        )
        out.append(_assemble_verdict(v.pid, v.process, v.dimensions + [corroboration], v.findings))
    return out


def investigate(findings: List[dict]) -> List[Verdict]:
    """Accept findings from memory_forensic.py, return one Verdict per unique PID."""
    pid_groups = _group_by_pid(findings)
    verdicts = [
        _investigate_pid(pid, pid_findings, findings)
        for pid, pid_findings in sorted(pid_groups.items())
    ]
    return _propagate_handle_corroboration(verdicts, findings)
