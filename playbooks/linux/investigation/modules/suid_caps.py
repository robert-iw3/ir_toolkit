"""Module 17 -- SUID/capability abuse.

Toolkit signals: Unexpected SUID Binary, Dangerous Capability (memory),
Dangerous File Capability, Privileged Task Binary Missing, Privileged Task
Non-Root Binary, Privileged Task World-Writable Binary.

edr_hunt.py's SUID_BASELINE already excludes the base-OS SUID set, so
anything reaching "Unexpected SUID Binary" is already off that baseline --
this module's job is deciding whether it's a package-shipped SUID tool
outside the hardcoded baseline (common: mount.cifs, vmware-tools variants)
versus a genuinely planted privesc binary, which the module cannot resolve
without a package-ownership check -- kept at WEAK_STRUCTURAL pending that.
Missing/non-root/world-writable privileged-task-binary findings are a
process-integrity break the collector already confirmed structurally.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier

_INTEGRITY_BREAK_TYPES = {
    'Privileged Task Binary Missing', 'Privileged Task Non-Root Binary',
    'Privileged Task World-Writable Binary',
}


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype in _INTEGRITY_BREAK_TYPES:
        return [Dimension(
            name='M17_SuidCaps_IntegrityBreak', positive=True, source_module=17,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]} -- a privileged (root-owned, elevated) task '
                      'whose backing binary is missing/non-root-owned/world-writable is a broken '
                      'trust boundary, not a benign misconfiguration.'
        )]

    if ftype in ('Dangerous Capability (memory)', 'Dangerous File Capability'):
        return [Dimension(
            name='M17_SuidCaps_DangerousCapability', positive=True, source_module=17,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- capability grant is a privesc primitive but '
                      'many legitimate tools (ping, some container runtimes) carry one; verify '
                      'the owning binary before escalating.'
        )]

    # Unexpected SUID Binary
    return [Dimension(
        name='M17_SuidCaps_UnexpectedSUID', positive=True, source_module=17,
        tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]} -- outside the base-OS SUID baseline; verify package '
                  'ownership (dpkg -S / rpm -qf) before treating as planted.'
    )]
