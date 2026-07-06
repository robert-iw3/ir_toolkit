"""Module 1 -- deleted/memfd/writable-path execution.

Toolkit signals: Process Running Deleted Binary (memory), Deleted Running
Binary, Memory-Only Executable (memfd), Execution From Writable Path.

From DETAILED-FOLLOW-ON-LINUX.md Section 2: "(deleted)" alone is not
malicious -- long-running daemons across a package upgrade show it routinely.
The PATH (temp/writable dir vs package dir) and corroboration decide it.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier
from . import _shared


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    target = finding.get('Target', '')
    path = (_shared.extract_path(details)
            or _shared.first_group(r'unlinked from disk while running: (\S+)', details)
            or _shared.first_group(r'backing: (\S+)', details)
            or _shared.first_group(r'volatile path: (\S+)', details))
    if not path and target.startswith('/'):
        # High Entropy ELF (and similar file-scoped findings) put the path in
        # Target directly rather than embedding path=/exe= in Details.
        path = target.split()[0]
    verdict = _shared.path_verdict(path)
    dims: List[Dimension] = []

    if 'memfd' in ftype.lower():
        dims.append(Dimension(
            name='M1_MemfdExec', positive=True, source_module=1, tier=Tier.STRONG_BEHAVIORAL,
            rationale='Process executing from an anonymous memfd backing -- fileless execution '
                       'with no on-disk file to package-verify at all.'
        ))
        return dims

    if verdict == 'writable':
        dims.append(Dimension(
            name='M1_DeletedOrExec_WritablePath', positive=True, source_module=1,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: backing path {path!r} is in a world-writable/volatile '
                       'directory -- no legitimate package installs or upgrades a daemon there.')
        ))
    elif verdict == 'trusted':
        dims.append(Dimension(
            name='M1_DeletedBinary_PackagePath', positive=False, source_module=1,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=(f'{ftype}: backing path {path!r} is a normal package directory -- '
                       'consistent with a package upgrade/removal while the process kept '
                       'running. Verify with journalctl/package-manager log for an upgrade '
                       'window before closing as FP.')
        ))
    else:
        dims.append(Dimension(
            name='M1_DeletedOrExec_UnknownPath', positive=True, source_module=1,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=(f'{ftype}: path {path!r} could not be classified trusted/writable -- '
                       'insufficient to confirm alone.')
        ))

    return dims
