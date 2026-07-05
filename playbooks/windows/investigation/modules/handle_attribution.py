"""Module 23 -- Cross-Process Handle & Thread-Creator Attribution investigation logic.

memory_forensic.py's Module 23 walks every process's handle table and correlates each
entry's va-object against every other process's EPROCESS/ETHREAD address -- a structurally
unforgeable fact (unlike a name or path, a handle-table entry cannot be spoofed the way a
cmdline or file path can). Severity is already tiered at collection time: Low for OS
session-management holders verified on their expected path (or the pathless 'System'
kernel pseudo-process), High for everything else -- including lsass.exe, which is
deliberately NOT special-cased as a holder (explicit design decision).

Scored PER HOLDER PID, not per handle -- a single holder can legitimately (or
maliciously) touch dozens of distinct target PIDs (lsass.exe's session/credential
bookkeeping touches ~30 processes on a real host); scoring each target separately would
fabricate dimension count the same way Module 20's per-region scoring did before its
investigate_pid fix (one behavioral pattern, not N independent pieces of evidence).

Tier assignment (planning/CURRENT-STATE-AND-OPEN-ITEMS.md §4 design note -- this module
is the design note's own worked example of Tier 1 evidence, and the first real migration
off the Tier 2 default):
  - PROCESS handle WITH PROCESS_CREATE_THREAD -> Tier 1 (DEFINITIVE). The full VM_WRITE+
    VM_OPERATION+CREATE_THREAD combination is the canonical OpenProcess() access mask for
    remote code injection (write payload, then start a thread to run it) with essentially
    no legitimate justification for a non-security-tool process to hold. VM_WRITE+
    VM_OPERATION WITHOUT CREATE_THREAD stays at the Tier 2 default -- writing into another
    process's memory alone has too many benign explanations (config/session data, IPC) to
    be "single item settles it." This is why lsass.exe's real VM_WRITE-into-~50-processes
    pattern (confirmed live, no CREATE_THREAD in the access mask) correctly stays
    UNDETERMINED rather than becoming an instant TRUE_POSITIVE. Split PER HANDLE, not
    aggregated with any() across the holder's whole target set -- confirmed live that a
    holder can have ~20 plain handles and exactly ONE with the full mask (svchost.exe with
    20 ordinary targets and a single CREATE_THREAD handle into winlogon.exe); any() would
    let that one handle promote the entire 20-target aggregate to Tier 1, the same volume-
    contamination bug class already fixed for Module 3/20 (here inverted: one strong fact
    inflating many weak ones, instead of many weak facts inflating a count). Each subset
    -- Module23_CrossProcessHandle_FullInjectionMask (Tier 1) and
    Module23_CrossProcessHandle_Holder (Tier 2, no CREATE_THREAD) -- is scoped to only the
    targets that actually justify it. NOTE: legitimate-looking process names (browser/
    service-host architecture) are NOT grounds to exclude or downgrade a genuine full-mask
    finding -- see detection-design memory Rule 4/4b; a real msedgewebview2.exe instance
    holding consistent ALL_ACCESS into several sibling processes on a live host correctly
    stays a Tier 1 TRUE_POSITIVE requiring analyst review, not an assumed-benign closure.
  - THREAD handle WITH shellcode-consistent start-address corroboration -> Tier 1. Two
    independent structurally-unforgeable facts converge (foreign handle possession AND a
    confirmed anon-exec execution target), the strongest case this module can produce.
  - THREAD handle WITHOUT that corroboration stays at the Tier 2 default -- a real
    capability (SET_CONTEXT/ALL_ACCESS into another process's thread) but not yet
    confirmed use, so it still needs independent corroboration before reaching TP.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier

_PROC_TYPE   = 'Cross-Process Handle (Memory)'
_THREAD_TYPE = 'Cross-Process Thread Handle (Memory)'


def _is_downgraded(finding: dict) -> bool:
    """Low severity here specifically means memory_forensic.py's OS-session-management
    downgrade fired (path-verified session subsystem, or the pathless 'System' kernel
    pseudo-process) -- Module 23 never emits any severity other than Low/High."""
    return finding.get('Severity') == 'Low'


def _distinct_targets(findings: List[dict]) -> int:
    targets = set()
    for f in findings:
        m = re.search(r'Target PID (\d+)', f.get('Target', ''))
        if m:
            targets.add(m.group(1))
    return len(targets)


def investigate_pid(handle_findings: List[dict]) -> List[Dimension]:
    """Aggregate every Cross-Process Handle/Thread Handle finding for one HOLDER pid
    into a small, fixed number of dimensions -- never one per target."""
    if not handle_findings:
        return []

    proc_findings   = [f for f in handle_findings if f.get('Type') == _PROC_TYPE]
    thread_findings = [f for f in handle_findings if f.get('Type') == _THREAD_TYPE]
    dims: List[Dimension] = []

    if proc_findings:
        elevated   = [f for f in proc_findings if not _is_downgraded(f)]
        downgraded = [f for f in proc_findings if _is_downgraded(f)]
        if elevated:
            # Split by whether EACH INDIVIDUAL handle carries CREATE_THREAD, rather than
            # aggregating "any() has it" across the whole set -- confirmed live on real
            # data that a holder can have ~20 plain VM_WRITE+VM_OPERATION handles (no
            # CREATE_THREAD) and exactly ONE with the full mask (e.g. svchost.exe with 20
            # ordinary targets and a single CREATE_THREAD handle into winlogon.exe). Using
            # any() would let that one handle promote the ENTIRE 20-target aggregate to
            # Tier 1 -- the same volume-contamination bug class already fixed for Module
            # 3/20, just inverted (one strong fact inflating many weak ones, instead of
            # many weak facts inflating a count). Each subset gets its own dimension,
            # correctly scoped to only the targets that actually justify its tier.
            full_mask = [f for f in elevated if 'PROCESS_CREATE_THREAD' in f.get('Details', '')]
            plain     = [f for f in elevated if f not in full_mask]
            if full_mask:
                n_full = _distinct_targets(full_mask)
                dims.append(Dimension(
                    name='Module23_CrossProcessHandle_FullInjectionMask', positive=True, source_module=23,
                    tier=Tier.DEFINITIVE,
                    rationale=(f'Holds a PROCESS handle with the full VM_WRITE+VM_OPERATION+'
                               f'CREATE_THREAD combination into {n_full} distinct process(es) -- '
                               'the canonical remote-injection access mask (write payload, then '
                               'start a thread to run it), essentially no legitimate justification '
                               'for a non-security-tool process. Tier 1 (DEFINITIVE): single item '
                               'settles it.')
                ))
            if plain:
                n_plain = _distinct_targets(plain)
                dims.append(Dimension(
                    name='Module23_CrossProcessHandle_Holder', positive=True, source_module=23,
                    rationale=(f'Holds a PROCESS handle with VM_WRITE+VM_OPERATION (no '
                               f'CREATE_THREAD) into {n_plain} distinct process(es) -- '
                               'structurally unforgeable cross-process write capability '
                               '(handle-table entry, not a name or path claim); needs '
                               'independent corroboration before reaching TP.')
                ))
        elif downgraded:
            dims.append(Dimension(
                name='Module23_CrossProcessHandle_OSSessionMgmt', positive=False, source_module=23,
                rationale=(f'{len(downgraded)} cross-process handle(s) held by a path-verified '
                           'OS session-management subsystem (or the pathless System pseudo-'
                           'process) -- structurally expected as a matter of OS architecture, '
                           'not injection.')
            ))

    if thread_findings:
        elevated   = [f for f in thread_findings if not _is_downgraded(f)]
        downgraded = [f for f in thread_findings if _is_downgraded(f)]
        if elevated:
            shellcode_backed = [f for f in elevated if 'shellcode-consistent' in f.get('Details', '')]
            if shellcode_backed:
                dims.append(Dimension(
                    name='Module23_CrossProcessThreadHandle_ShellcodeTarget', positive=True, source_module=23,
                    tier=Tier.DEFINITIVE,
                    rationale=(f'Holds a THREAD handle (SET_CONTEXT/ALL_ACCESS) into a thread '
                               'whose start address lands in an anonymous executable region in '
                               'the TARGET process -- the remote-thread-hijack primitive PLUS '
                               'independent corroboration that the target thread is executing '
                               'shellcode, not a legitimate module entry point. Two independent '
                               'structurally-unforgeable facts converge -- Tier 1 (DEFINITIVE).')
                ))
            else:
                n_targets = _distinct_targets(elevated)
                dims.append(Dimension(
                    name='Module23_CrossProcessThreadHandle_Holder', positive=True, source_module=23,
                    rationale=(f'Holds a THREAD handle (SET_CONTEXT/ALL_ACCESS) into '
                               f'{n_targets} thread(s) in other process(es) -- the remote-'
                               'thread-hijack/context-manipulation primitive (structurally '
                               'unforgeable handle-table fact).')
                ))
        elif downgraded:
            dims.append(Dimension(
                name='Module23_CrossProcessThreadHandle_OSSessionMgmt', positive=False, source_module=23,
                rationale=(f'{len(downgraded)} cross-process thread handle(s) held by a '
                           'path-verified OS session-management subsystem -- structurally '
                           'expected.')
            ))

    return dims
