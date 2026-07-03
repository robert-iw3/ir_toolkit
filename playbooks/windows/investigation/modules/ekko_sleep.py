"""Module 14 -- Thread-Pool / Ekko Correlation investigation logic.

Fires only when:
  - Module 13 High-severity beacon region present (shellcode-sized < 256 KB)
  - AND ntdll thread-pool threads currently running in same process

Module 14 verdict is DERIVED from Module 13 signals -- it never stands alone.
From investigation guide:
  "If Module 13 shows non-uniform / AdjAnonExec=False: deprioritize."
  "If Module 13 shows UNIFORM + AdjAnonExec=True: escalate."
"""
from __future__ import annotations
import re
from typing import List, Optional

from ..verdict import Dimension


def investigate(finding: dict,
                m13_dims: Optional[List[Dimension]] = None) -> List[Dimension]:
    """
    m13_dims: Dimension list from Module 13 investigation for this same PID.
    When provided, Module 14 applies its cross-module verdict rule.
    """
    dims: List[Dimension] = []
    details = finding.get('Details', '')

    m = re.search(r'(\d+)\s+ntdll.backed', details, re.IGNORECASE)
    thread_count = int(m.group(1)) if m else 0

    if m13_dims is not None:
        m13_pos = [d for d in m13_dims if d.positive and d.source_module == 13]
        m13_neg = [d for d in m13_dims if not d.positive and d.source_module == 13]

        if m13_neg and not m13_pos:
            # All Module 13 signals are benign: thread-pool workers are legitimate
            dims.append(Dimension(
                name='Module14_Deprioritized', positive=False, source_module=14,
                rationale=(f'Module 14 fired ({thread_count} ntdll thread-pool threads), '
                           'but all Module 13 signals are benign '
                           '(non-uniform CV, AdjAnonExec=False) -- '
                           'thread-pool workers are legitimate Windows Runtime/COM infrastructure. '
                           'Deprioritized per investigation guide: '
                           '"non-uniform / AdjAnonExec=False -> legitimate thread-pool workers."')
            ))
            return dims

        if m13_pos:
            # Module 13 has TP signals: Ekko pattern confirmed
            dims.append(Dimension(
                name='Module14_Ekko_Corroborated', positive=True, source_module=14,
                rationale=(f'Module 14: {thread_count} ntdll thread-pool threads co-present with '
                           'Module 13 TP signals (UNIFORM/AdjAnonExec=True). '
                           'Matches Ekko/Foliage sleep-obfuscation: '
                           'timer-pool callbacks decrypt and resume payload. Escalate.')
            ))
            return dims

    # No Module 13 context available -- flag for corroboration
    dims.append(Dimension(
        name='Module14_EkkoPattern_Pending', positive=True, source_module=14,
        rationale=(f'Module 14: {thread_count} ntdll thread-pool threads in process with '
                   'High-severity dormant beacon region. '
                   'Verdict requires Module 13 corroboration signals (CV%, AdjAnonExec). '
                   'Run dormant_beacon.investigate() for this PID first.')
    ))
    return dims
