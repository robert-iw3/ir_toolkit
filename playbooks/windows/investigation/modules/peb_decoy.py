"""Module 15 -- PEB CommandLine Pointer (Argue / decoy) investigation logic.

From investigation guide:
  PEB.ProcessParameters.CommandLine differs from event log 4688 -> Argue technique
  Buffer pointer falls in anonymous exec region -> decoy stored with shellcode
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')

    has_mismatch  = bool(re.search(r'mismatch|differ|tamper|overwrite|decoy', details, re.IGNORECASE))
    ptr_in_anon   = bool(re.search(r'anonymous.*exec|anon.*exec|private.*exec', details, re.IGNORECASE))
    event_log_ref = bool(re.search(r'4688|event.log|spawn.*cmd|at.*creation', details, re.IGNORECASE))

    if has_mismatch or event_log_ref:
        dims.append(Dimension(
            name='Module15_CmdLineTampered', positive=True, source_module=15,
            rationale=('PEB.ProcessParameters.CommandLine differs from event log 4688 cmdline '
                       'recorded at process creation -- CobaltStrike Argue or equivalent '
                       'decoy-cmdline technique; process is concealing its actual arguments')
        ))

    if ptr_in_anon:
        dims.append(Dimension(
            name='Module15_PtrInAnonExec', positive=True, source_module=15,
            rationale=('CommandLine buffer pointer resolves to an anonymous executable region -- '
                       'decoy string co-located with shellcode storage; '
                       'strong cross-module TP indicator with Module 3/5/13')
        ))

    if not dims:
        dims.append(Dimension(
            name='Module15_PEB_Anomaly', positive=True, source_module=15,
            rationale=('Module 15: PEB CommandLine anomaly detected. '
                       'Verify against event log 4688 to confirm tampering before verdict.')
        ))

    return dims
