"""Module 5 -- kernel rootkit signals (memory-only; host-scope, PID 0).

Toolkit signals: Hidden Kernel Module (memory/carved), IDT Hook (memory),
Netfilter Hook (memory), VFS fops Hook (memory), Kernel .text Inline Hook
(memory), Kernel Timer Hook (memory), Kernel Thread Hook (memory),
modprobe_path/uevent_helper/core_pattern Hijack (memory), Kernel-Thread Name
Masquerade (memory), Fake Kernel Thread, Suspicious Kernel Module, Kallsyms
Pseudo-Module (verify), Kernel Tainted By Unaccounted Module (verify),
Unnamed Carved Module (verify).

From DETAILED-FOLLOW-ON-LINUX.md Section 5: "Why memory, not live" -- a
rootkit that hides its LKM and hooks iterate_shared is invisible to lsmod/ps/
cat /proc/modules; those all traverse the structures it controls. Every
memory-sourced hook/hidden-module signal here is Tier 1 (DEFINITIVE): the
image is read out-of-band, so a hook resolving to no module, or a module
present in kernel structures but absent from /proc/modules, cannot be
produced by anything except rootkit tampering. Live-only '(verify)' signals
are corroborating hints (Tier 3) pending image analysis, per the guide.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier

_DEFINITIVE_MEMORY_TYPES = {
    'Hidden Kernel Module (memory)', 'Hidden Kernel Module (carved)',
    'IDT Hook (memory)', 'Netfilter Hook (memory)', 'VFS fops Hook (memory)',
    'Kernel .text Inline Hook (memory)', 'Kernel Timer Hook (memory)',
    'Kernel Thread Hook (memory)', 'modprobe_path Hijack (memory)',
    'uevent_helper Hijack (memory)', 'Kernel core_pattern Hijack (memory)',
    'Kernel-Thread Name Masquerade (memory)',
}
# Live-only heuristics: real, but the live host is not authoritative for
# kernel-structure tampering -- these are hints pointing at image analysis.
_VERIFY_ONLY_TYPES = {
    'Kallsyms Pseudo-Module (verify)', 'Kernel Tainted By Unaccounted Module (verify)',
    'Unnamed Carved Module (verify)',
}
# Live host findings without a "(memory)" qualifier that are still concrete
# (edr_hunt.py reads the actual sysctl/module values, not a derived hook state).
_LIVE_CONCRETE_TYPES = {
    'Fake Kernel Thread', 'Suspicious Kernel Module', 'Hidden Kernel Module',
    'uevent_helper Hijack', 'modprobe_path Hijack', 'Kernel core_pattern Hijack',
}


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype in _DEFINITIVE_MEMORY_TYPES:
        return [Dimension(
            name='M5_KernelRootkit_Memory', positive=True, source_module=5,
            tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: kernel-structure tampering observed out-of-band in the memory '
                       f'image -- a live host cannot fake or hide this from an offline analyzer. '
                       f'{details[:220]}')
        )]

    if ftype in _LIVE_CONCRETE_TYPES:
        return [Dimension(
            name='M5_KernelRootkit_LiveConcrete', positive=True, source_module=5,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]} (live-host read of an actual kernel-exposed '
                      'value; corroborate with a memory image if the finding needs to be TP-final).'
        )]

    if ftype in _VERIFY_ONLY_TYPES:
        return [Dimension(
            name='M5_KernelRootkit_VerifyOnly', positive=True, source_module=5,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=(f'{ftype}: hint only -- do not clear on the live host alone; pull a memory '
                       f'image and run the engine per DETAILED-FOLLOW-ON-LINUX.md Section 5. '
                       f'{details[:160]}')
        )]

    return [Dimension(
        name='M5_KernelRootkit_Other', positive=True, source_module=5,
        tier=Tier.STRONG_BEHAVIORAL,
        rationale=f'{ftype}: {details[:200]}'
    )]
