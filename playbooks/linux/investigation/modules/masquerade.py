"""Module 14 -- process/file masquerade.

Toolkit signals: Process Name Mismatch, Spoofed Process From Implant Dir
(memory), Implant-Path Execution (memory), MagicByte Mismatch.

A comm/argv[0] that doesn't match the backing executable's basename, running
from an untrusted path, is argv[0]/PR_SET_NAME spoofing -- edr_hunt.py
already gates this on "untrusted path" before emitting it, so this module
treats the finding as pre-corroborated rather than re-deriving path trust.
"""
from __future__ import annotations
from typing import List

from ..verdict import Dimension, Tier


def investigate(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')

    if ftype == 'MagicByte Mismatch':
        return [Dimension(
            name='M14_Masquerade_MagicByte', positive=True, source_module=14,
            tier=Tier.STRONG_BEHAVIORAL,
            rationale=f'{ftype}: {details[:200]} -- file extension/reported type does not match '
                      'the actual file magic bytes.'
        )]

    return [Dimension(
        name='M14_Masquerade_NameOrPath', positive=True, source_module=14,
        tier=Tier.STRONG_BEHAVIORAL,
        rationale=f'{ftype}: {details[:220]} -- name/path spoofing already gated on an untrusted '
                  'backing path by the collector.'
    )]
