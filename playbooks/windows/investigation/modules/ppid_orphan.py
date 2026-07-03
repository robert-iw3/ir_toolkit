"""Module 17 -- PPID Orphan investigation logic.

From investigation guide:
  winlogon.exe, csrss.exe orphaned -> smss.exe exits early (expected)
  userinit.exe orphaned -> exits after explorer launch (expected)
  User-launched process (notepad, powershell) orphaned -> suspicious unless known-exit-early
  PID reuse mismatch -> definitive PPID spoofing
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension
from ..models.windows_noise import KNOWN_EXIT_EARLY_PARENTS, KNOWN_SYSTEM_PROCESSES


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')
    target  = finding.get('Target', '')

    proc_m = re.search(r'PID\s+\d+\s+\(([^)]+)\)', target)
    process = proc_m.group(1).lower() if proc_m else ''

    pid_reuse     = bool(re.search(r'PID.*reused|recycled|mismatch|spoofed', details, re.IGNORECASE))
    known_orphan  = any(ep in details.lower() for ep in KNOWN_EXIT_EARLY_PARENTS)
    is_system     = process in KNOWN_SYSTEM_PROCESSES
    orphan_reason = re.search(r'PPID.*\(([^)]+)\)', details)
    parent_named  = orphan_reason.group(1).lower() if orphan_reason else ''

    if pid_reuse:
        dims.append(Dimension(
            name='Module17_PID_Reuse', positive=True, source_module=17,
            rationale=('PID reuse/mismatch: parent PID exists in memory but process name '
                       'does not match event log 4688 at spawn time -- '
                       'PPID spoofing via CreateProcess PROC_THREAD_ATTRIBUTE_PARENT_PROCESS')
        ))
        return dims

    if known_orphan or (parent_named and parent_named in KNOWN_EXIT_EARLY_PARENTS):
        dims.append(Dimension(
            name='Module17_ExpectedOrphan', positive=False, source_module=17,
            rationale=(f'{process} orphaned -- parent is a known exit-early launcher '
                       f'(smss.exe/userinit.exe/msiexec.exe) that legitimately exits '
                       'before the memory snapshot. Expected behavior, not PPID spoofing.')
        ))
        return dims

    if is_system:
        dims.append(Dimension(
            name='Module17_SystemOrphan_Investigate', positive=False, source_module=17,
            rationale=(f'{process} is a system process with orphaned parent -- '
                       'cross-reference event log 4688 to verify actual parent name and PID at spawn. '
                       'If parent matches a known exit-early process: close. '
                       'If parent mismatch: escalate as PPID spoofing.')
        ))
    else:
        dims.append(Dimension(
            name='Module17_SuspiciousOrphan', positive=True, source_module=17,
            rationale=(f'{process} shows orphaned parent not in the known-exit-early list -- '
                       'suspicious; verify event log 4688 to confirm parent identity at spawn time. '
                       'PPID spoofing allows process to masquerade as a trusted system child.')
        ))

    return dims
