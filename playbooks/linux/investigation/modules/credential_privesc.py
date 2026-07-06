"""Module 6 -- credential override / privilege-escalation residue.

Toolkit signals: Credential Override (memory), Unauthorized UID0 Account,
Empty Password Account, Unsigned Kernel Module.

From DETAILED-FOLLOW-ON-LINUX.md Section 6: cred != real_cred on a live task
is the residue of a kernel privesc (magic-signal "become root" a la
Diamorphine). A second uid-0 line in /etc/passwd, or an empty-password
account, has no benign explanation on a hardened host -- both are Tier 1.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype == 'Credential Override (memory)':
        return [Dimension(
            name='M6_CredentialOverride', positive=True, source_module=6, tier=Tier.DEFINITIVE,
            rationale=(f'{ftype}: task cred != real_cred -- credentials overwritten post-fork, the '
                       f'out-of-band-observed residue of a kernel privesc mechanism. {details[:200]}')
        )]

    if ftype in ('Unauthorized UID0 Account', 'Empty Password Account'):
        return [Dimension(
            name='M6_AccountIntegrity', positive=True, source_module=6, tier=Tier.DEFINITIVE,
            rationale=f'{ftype}: {details[:200]} -- backdoor superuser account / auth-bypass '
                      'condition with no benign explanation on an already-hardened host.'
        )]

    if ftype == 'Unsigned Kernel Module':
        return [Dimension(
            name='M6_UnsignedModule', positive=True, source_module=6, tier=Tier.WEAK_STRUCTURAL,
            rationale=f'{ftype}: {details[:200]} -- many legitimate out-of-tree drivers '
                      '(DKMS, proprietary GPU) are unsigned; needs corroboration.'
        )]

    return [Dimension(
        name='M6_CredentialPrivesc_Other', positive=True, source_module=6,
        tier=Tier.STRONG_BEHAVIORAL, rationale=f'{ftype}: {details[:200]}'
    )]
