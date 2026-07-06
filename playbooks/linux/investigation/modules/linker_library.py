"""Module 13 -- linker/library hijack (LD_PRELOAD-class + GOT/PLT hooking).

Toolkit signals: Linker Hijack (memory), Linker Path in Implant Dir (memory),
Library Preload Hijack, Suspicious Loaded Library (memory), Process Preload
(memory), Process Preload, GOT/PLT Overwrite (memory), GOT Entry Relocation
(verify).

edr_hunt.py already distinguishes at collection time: LD_PRELOAD pointing at
a writable path is High ("Library Preload Hijack"); LD_PRELOAD merely SET
(pointing somewhere trusted) is Low ("Process Preload") -- this module keeps
that distinction rather than flattening it.

A GOT entry redirected to anonymous/unbacked memory (observed out-of-band in
a memory image, same as the kernel-hook signals in kernel_rootkit.py) has no
benign explanation -- RELRO/lazy-binding/legitimate hooking all resolve to a
real loaded module, never anonymous memory. Tier 1 (DEFINITIVE), matching
the other memory-sourced hook facts. "GOT Entry Relocation (verify)" is the
live-host, ambiguous counterpart (could be RELRO/lazy binding) -- stays weak.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier

_HIJACK_TYPES = {
    'Linker Hijack (memory)', 'Linker Path in Implant Dir (memory)', 'Library Preload Hijack',
}


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype == 'GOT/PLT Overwrite (memory)':
        return [Dimension(
            name='M13_LinkerLibrary_GOTOverwrite', positive=True, source_module=13,
            tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: {details[:220]} -- GOT entry redirected to anonymous/unbacked '
                       'memory, observed out-of-band in a memory image. No benign resolution '
                       '(RELRO, lazy binding, legitimate hooking) points at anonymous memory.')
        )]

    if ftype == 'GOT Entry Relocation (verify)':
        return [Dimension(
            name='M13_LinkerLibrary_GOTRelocation_Verify', positive=True, source_module=13,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:220]} -- ambiguous per the collector\'s own note '
                      '(could be RELRO, lazy binding, or a hook); needs the memory-sourced check.'
        )]

    if ftype in _HIJACK_TYPES:
        return [Dimension(
            name='M13_LinkerLibrary_Hijack', positive=True, source_module=13,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]} -- preload/linker path points at a writable '
                      'location; libc-hook/userland-rootkit shape.'
        )]

    if ftype == 'Suspicious Loaded Library (memory)':
        return [Dimension(
            name='M13_LinkerLibrary_SuspiciousLoad', positive=True, source_module=13,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:200]}'
        )]

    # Process Preload (Low, LD_PRELOAD set but path not flagged writable)
    return [Dimension(
        name='M13_LinkerLibrary_PreloadSet', positive=False, source_module=13,
        tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]} -- LD_PRELOAD is set but the collector did not flag '
                  'the target path as writable/suspicious; weak signal on its own.'
    )]
