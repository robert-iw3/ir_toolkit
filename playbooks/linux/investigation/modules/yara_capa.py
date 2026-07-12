"""Module 12 -- YARA / capa memory match classification.

Toolkit signals: YARA Memory Match, Injected Code (memory YARA), Memory
Capabilities (capa).

From DETAILED-FOLLOW-ON-LINUX.md's core philosophy and WORKFLOW-YARA.md: a
YARA hit matters because of WHERE it fired (anonymous executable region vs
file-backed), not which named rule/family matched -- mechanism-based, not
signature-based, mirroring the Windows engine's Module 19 exactly.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype == 'Memory Capabilities (capa)':
        return [Dimension(
            name='M12_Capa_Capabilities', positive=True, source_module=12,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:220]} -- capability identification only; corroborate '
                      'with a network/persistence/injection signal on the same PID/region.'
        )]

    # Real bug caught live: the 'in ANONYMOUS' alternative matched analyze_memory_linux.py's
    # own NON-executable phrasing too ("...matched in anonymous rw- memory..." legitimately
    # contains "in anonymous"), so every YARA hit in ordinary anonymous heap/data memory --
    # not just genuinely executable, unbacked memory -- got promoted to STRONG_BEHAVIORAL
    # "code executing outside any loaded module." On one live host this alone turned 19
    # coincidental rule-pack matches inside a large process's non-executable heap (rw-, no
    # x bit) into a false TRUE POSITIVE. The collector's ONLY phrasing for the genuine
    # anon+exec case is "ANONYMOUS EXECUTABLE" (analyze_memory_linux.py's analyze_yara());
    # anonymous non-exec memory is worded "anonymous {perms} memory" with no "EXECUTABLE"
    # anywhere in it, so requiring that exact word is both necessary and sufficient.
    in_anon_exec = ftype == 'Injected Code (memory YARA)' or bool(
        re.search(r'ANONYMOUS EXECUTABLE', details, re.IGNORECASE))
    is_file_backed = 'file-backed' in details.lower()
    breadth_shared = 'likely common/shared bytes' in details

    if in_anon_exec:
        return [Dimension(
            name='M12_YARA_AnonExec', positive=True, source_module=12, tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: rule fired in anonymous executable memory -- code executing '
                       f'outside any loaded module. Family identity irrelevant. {details[:180]}')
        )]

    if is_file_backed:
        return [Dimension(
            name='M12_YARA_FileBacked', positive=False, source_module=12, tier=Tier.WEAK_STRUCTURAL,
            rationale=(f'{ftype}: matched bytes are in a file-backed mapping -- verify the '
                       f'on-disk file\'s package ownership/hash before treating as TP. {details[:180]}')
        )]

    if breadth_shared:
        return [Dimension(
            name='M12_YARA_SharedBytes', positive=False, source_module=12, tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: rule matched many processes -- likely common/shared interpreter '
                      f'or library content, though a library-injection campaign is not ruled out. '
                      f'{details[:160]}'
        )]

    return [Dimension(
        name='M12_YARA_Unknown', positive=True, source_module=12, tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]} -- anon-vs-file-backed context unknown from this text.'
    )]
