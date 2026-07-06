"""Module 11 -- SSH key & account hygiene.

Toolkit signals: Many SSH Authorized Keys, SSH Key Reused Across Accounts,
SSH authorized_keys is a Symlink, SSH Key File World/Group-Writable, SSH Key
File Owner Mismatch, root authorized_keys Recently Modified, SSH Config
Weakness, SSH Brute Force.

From DETAILED-FOLLOW-ON-LINUX.md Section 11: a symlinked authorized_keys or
a key reused across accounts is a strong operator-planted-access signal;
"Many SSH Authorized Keys" alone is the canonical FP on a bastion/CI host
(legitimately many operator keys) -- fingerprinting each key is what
actually resolves it, which this module cannot do from the finding text
alone, so it stays Tier 3 pending that check.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier

_STRUCTURAL_TP_TYPES = {
    'SSH authorized_keys is a Symlink', 'SSH Key Reused Across Accounts',
    'root authorized_keys Recently Modified', 'SSH Forced-Command Backdoor',
}
_WEAK_CONTEXT_TYPES = {'Many SSH Authorized Keys', 'SSH Config Weakness'}


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype in _STRUCTURAL_TP_TYPES:
        return [Dimension(
            name='M11_SSH_StructuralAnomaly', positive=True, source_module=11,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]} -- redirect/reuse/recent-modification pattern '
                      'with no benign single-admin explanation.'
        )]

    if ftype in ('SSH Key File World-Writable', 'SSH Key File Group-Writable', 'SSH Key File Owner Mismatch'):
        return [Dimension(
            name='M11_SSH_KeyPermissions', positive=True, source_module=11,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- privesc/persistence opportunity; confirm '
                      'whether a foreign key was already added before escalating.'
        )]

    if ftype == 'SSH Brute Force':
        return [Dimension(
            name='M11_SSH_BruteForce', positive=True, source_module=11,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- attempted access only; check auth log for '
                      'any resulting successful logon.'
        )]

    if ftype in _WEAK_CONTEXT_TYPES:
        return [Dimension(
            name='M11_SSH_WeakContext', positive=True, source_module=11,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- fingerprint each key/setting against the '
                      'roster before treating as anomalous (bastion/CI hosts legitimately vary here).'
        )]

    return [Dimension(
        name='M11_SSH_Other', positive=True, source_module=11,
        tier=Tier.WEAK_STRUCTURAL, rationale=f'{ftype}: {details[:200]}'
    )]
