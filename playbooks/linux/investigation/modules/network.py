"""Module 10 -- network connection triage.

Toolkit signals: External Connection (memory), External Connection From
Untrusted Binary, Network Listener From Untrusted Binary, External
Connection, Listening Service.

From DETAILED-FOLLOW-ON-LINUX.md Section 10: a connection owned by a normal
package daemon to a vendor endpoint is FP after confirming the binary path;
an established connection to a non-service port from an untrusted binary
(or a listener on an unexpected high port from one) is C2/backdoor-shaped.
"untrusted binary" is already determined upstream by edr_hunt.py's
_pid_exe_trust (deleted/memfd/writable-path) -- this module trusts that
label rather than re-deriving it, since it is itself Tier-1-adjacent
(a live host cannot fake its own /proc/pid/exe target).
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if 'Untrusted Binary' in ftype:
        return [Dimension(
            name='M10_Network_UntrustedBinary', positive=True, source_module=10,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:220]} -- network activity attributed to a deleted/'
                      'memfd/writable-path binary; provenance alone makes this C2/backdoor-shaped.'
        )]

    if ftype in ('External Connection (memory)', 'External Connection'):
        return [Dimension(
            name='M10_Network_ExternalConnection', positive=True, source_module=10,
            tier=Tier.WEAK_STRUCTURAL,
            rationale=(f'{ftype}: {details[:200]} -- external connection alone does not '
                       'distinguish C2 from legitimate update/telemetry traffic; needs binary '
                       'provenance or persistence corroboration.')
        )]

    # Listening Service: informational unless corroborated
    return [Dimension(
        name='M10_Network_Listener', positive=True, source_module=10,
        tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]}'
    )]
