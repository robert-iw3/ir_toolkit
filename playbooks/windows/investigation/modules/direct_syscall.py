"""Module 20 -- Direct Syscall Execution (Hell's Gate / SysWhispers) investigation logic.

Raw `syscall` (0x0F 0x05) opcodes in a private executable region outside
ntdll.dll bypass usermode API hooking -- a well-known EDR-evasion technique
(Hell's Gate, SysWhispers, FreshyCalls, Halo's Gate). The same structural
signature also appears in legitimate managed-code hosts: .NET/CLR JIT-compiled
stubs (P/Invoke thunks, GC write barriers) routinely embed raw syscalls, in
the same regions the memory scanner already tags JIT-consistent via the
Injected Memory Region finding.

This is scored PER PROCESS, not per region. A JIT-heavy managed-code host can
show dozens of small syscall regions from ordinary CLR operation -- treating
each region as an independent dimension turns one behavioral pattern into
dozens of counted dimensions and blows through the TP threshold on volume
alone. Confirmed on live data: a single PowerShell 7 process produced 93
syscall-region findings; naive per-finding scoring pushed weight to 286 and
false-positived both PowerShell instances AND CrossDeviceService (a
legitimate Windows Nearby Sharing component), none of which involved evasion.

Corroboration, in priority order:
  1. This PID has ANY JIT-consistent Injected Memory Region finding -- managed-
     code hosts are common and expected background noise for this pattern.
     Not scored, regardless of how many syscall regions exist.
  2. No JIT-consistent evidence anywhere for this PID -- the process is not a
     known managed-code host, and a cluster of raw-syscall regions outside
     ntdll is exactly the Hell's Gate/SysWhispers shape. One dimension for the
     whole cluster, not one per region.
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension


def _parse_address(target: str) -> str:
    m = re.search(r'@\s*(0x[0-9a-f]+)', target, re.IGNORECASE)
    return m.group(1).lower() if m else ''


def _any_jit_consistent(pid_findings: List[dict]) -> bool:
    for f in pid_findings:
        if 'Injected Memory' not in f.get('Type', ''):
            continue
        if re.search(r'JIT.consistent', f.get('Details', ''), re.IGNORECASE):
            return True
    return False


def investigate_pid(syscall_findings: List[dict], pid_findings: List[dict]) -> List[Dimension]:
    """Aggregate every Direct Syscall Execution finding for one PID into a
    single dimension describing the pattern, not one dimension per region."""
    if not syscall_findings:
        return []

    region_count = len(syscall_findings)
    total_opcodes = 0
    for f in syscall_findings:
        m = re.search(r'(\d+)\s+raw syscall', f.get('Details', ''), re.IGNORECASE)
        if m:
            total_opcodes += int(m.group(1))

    if _any_jit_consistent(pid_findings):
        return [Dimension(
            name='Module20_Syscall_JIT_Host', positive=False, source_module=20,
            rationale=(f'{region_count} raw-syscall region(s) ({total_opcodes} opcodes total) '
                       'in a process with at least one JIT-consistent Injected Memory Region '
                       'finding -- .NET/CLR JIT stubs legitimately embed raw syscalls. '
                       'Not scored as EDR-evasion without independent corroboration.')
        )]

    return [Dimension(
        name='Module20_DirectSyscall_Cluster', positive=True, source_module=20,
        rationale=(f'{region_count} raw-syscall region(s) ({total_opcodes} opcodes total) '
                   'outside ntdll.dll, with no evidence this process is a JIT/managed-code '
                   "host -- Hell's Gate/SysWhispers-style EDR evasion pattern: direct "
                   'syscall invocation bypasses usermode API hooking.')
    )]
