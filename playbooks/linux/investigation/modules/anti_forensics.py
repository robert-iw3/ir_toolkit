"""Module 15 -- anti-forensics / logging tamper (host-scope).

Toolkit signals: Audit Rules Cleared, Log File Truncated, Logging Service Not
Running, Journald Persistence Disabled, Shell History Disabled, Journal Log
Truncation, Audit Logging Disabled, Mandatory Access Control Disabled.

These are individually ambiguous (an admin can legitimately disable audit
during maintenance, or Docker/overlayfs images often ship without a
persistent journal) -- each stays Tier 3 alone, but co-occurrence with ANY
other module's positive dimension on the same host is a strong compound
signal (an intrusion covering its tracks), which the engine's cross-PID/
host-scope assembly already rewards via the 3-dimension threshold.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    return [Dimension(
        name='M15_AntiForensics', positive=True, source_module=15, tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]} -- individually explainable by routine maintenance '
                  'or minimal-image defaults; significant mainly in combination with other '
                  'findings on the same host.'
    )]
