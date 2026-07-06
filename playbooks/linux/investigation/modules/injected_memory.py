"""Module 3 -- injected/anonymous-executable memory (malfind-class).

Toolkit signals: Injected Memory (malfind), Implant-Backed Mapping (memory),
Anomalous Call Stack (memory), Injected Code (memory YARA).

From DETAILED-FOLLOW-ON-LINUX.md Section 4: an anon-exec region in a known
JIT runtime (node/java/python/browsers) is expected; the same region in any
other process is not. This module downgrades (never suppresses) the JIT
case and requires network/YARA/deleted-binary corroboration to promote it.

The JIT-runtime exemption trusts `comm`, which is attacker-controlled -- an
implant naming itself "python3" would otherwise get its one contributing
dimension suppressed for free. Real corroboration-seeking, not a name-match
shortcut: if the SAME PID also has a `Process Name Mismatch` finding (edr_hunt.py
has ALREADY independently compared `comm` against the actual backing
executable's basename), that is proof the "JIT runtime" identity is fake --
the exemption is void for that PID regardless of what `comm` says.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier
from ..models.linux_noise import JIT_RUNTIMES
from . import _shared

_MASQUERADE_DISPROOF_TYPES = {
    'Process Name Mismatch', 'Spoofed Process From Implant Dir (memory)',
    'Implant-Path Execution (memory)',
}


def investigate(finding: dict, pid_findings: List[dict] = None) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    target = finding.get('Target', '')
    dims: List[Dimension] = []

    comm = _shared.extract_comm(details) or ''
    proc_m = re.search(r'PID\s*:?\s*\d+\s*\(([^)]+)\)', target)
    proc = (proc_m.group(1) if proc_m else comm).lower().lstrip('./').split('/')[-1]

    masquerade_disproven = bool(pid_findings) and any(
        f.get('Type', '') in _MASQUERADE_DISPROOF_TYPES for f in pid_findings if f is not finding)
    is_jit = proc in JIT_RUNTIMES and not masquerade_disproven
    anon_exec_file_backed = 'file-backed' in details.lower()

    if anon_exec_file_backed:
        dims.append(Dimension(
            name='M3_Injected_FileBacked', positive=False, source_module=3,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: matched bytes are file-backed, not anonymous -- may be a rule '
                      'grazing a loaded library rather than injection.'
        ))
        return dims

    if proc in JIT_RUNTIMES and masquerade_disproven:
        dims.append(Dimension(
            name='M3_Injected_JITIdentityDisproven', positive=True, source_module=3,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: comm={proc!r} matches a JIT runtime name, but an independent '
                       'Process Name Mismatch / masquerade finding on this SAME PID already proves '
                       'the reported name does not match the actual backing executable -- the JIT '
                       'exemption does not apply; treat as non-JIT anon-exec.')
        ))
    elif is_jit:
        dims.append(Dimension(
            name='M3_Injected_JITRuntime', positive=False, source_module=3,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: owning process {proc!r} is a known JIT/interpreter runtime -- '
                       'anonymous executable pages are its normal operating mode, not injection '
                       'evidence by themselves.')
        ))
    else:
        dims.append(Dimension(
            name='M3_Injected_AnonExec', positive=True, source_module=3,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: executable+writable anonymous mapping with no backing file in '
                       f'a non-JIT process ({proc or "unknown"}) -- classic code-injection/'
                       f'shellcode-staging shape. {details[:160]}')
        ))

    # Corroboration: does this PID also show a reverse-shell/network/deleted-binary signal?
    if pid_findings:
        other_types = {f.get('Type', '') for f in pid_findings if f is not finding}
        if any('Reverse Shell' in t or 'External Connection' in t or 'Deleted' in t or 'memfd' in t
               for t in other_types):
            dims.append(Dimension(
                name='M3_Injected_Corroborated', positive=True, source_module=3,
                tier=Tier.STRONG_BEHAVIORAL,
                rationale='Anon-exec region co-occurs with a network/deleted-binary signal on the '
                          'same PID -- independent corroboration, not a JIT-runtime coincidence.'
            ))
    return dims
