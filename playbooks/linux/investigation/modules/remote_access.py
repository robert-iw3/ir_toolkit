"""Module 19 -- remote access tooling.

Toolkit signals: Remote Access Tool, Crypto Miner (remote_access_triage.py).

remote_access_triage.py already distinguishes a custom-relay/writable-path
RMM (unsanctioned) from a legitimate IT-managed one at the adjudication
layer; at the investigation-engine layer we don't have that same context
readily in Details, so this stays STRONG_BEHAVIORAL rather than DEFINITIVE
-- an RMM tool's mere presence is dual-use until relay/path is confirmed.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype == 'Crypto Miner':
        return [Dimension(
            name='M19_RemoteAccess_CryptoMiner', positive=True, source_module=19,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:200]} -- unauthorized compute/resource-hijacking process.'
        )]

    has_custom_relay = bool(re.search(r'relay=[\w.\-]+', details))
    return [Dimension(
        name='M19_RemoteAccess_Tool', positive=True, source_module=19,
        tier=Tier.STRONG_BEHAVIORAL if has_custom_relay else Tier.WEAK_STRUCTURAL,
        rationale=(f'{ftype}: {details[:200]}' +
                  (' -- custom relay endpoint, not the vendor default: unsanctioned use likely.'
                   if has_custom_relay else
                   ' -- RMM tool presence is dual-use; confirm whether IT-sanctioned before escalating.'))
    )]
