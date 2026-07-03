"""Module 12 -- ntdll Syscall Stub Integrity investigation logic.

Key discriminator from investigation guide:
  Hook target inside loaded security DLL -> EDR hook (benign)
  Hook target in anonymous/private region -> malicious (SysWhispers/HellsGate)
  Selective hooked stubs (NtAllocateVirtualMemory etc.) -> attacker pattern
  Broad hook set -> EDR pattern
"""
from __future__ import annotations
import re
from typing import List

from ..verdict import Dimension

# Partial strings that identify known security product DLLs / directories
_EDR_SIGNATURES = (
    'amsi.dll', 'hvax64.dll', 'mpclient.dll', 'wscapi.dll',
    'crowdstrike', 'sentinelone', 'carbonblack', 'cylance',
    'mcafee', 'symantec', 'sophos', 'eset', 'bitdefender',
    'malwarebytes', 'heimdal', 'cybereason', 'darktrace',
    'tanium', 'palo alto', 'cortex', 'falcon',
)

_ATTACKER_STUBS = (
    'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx',
    'NtQueueApcThread', 'NtProtectVirtualMemory', 'NtUnmapViewOfSection',
)


def _target_is_edr(details: str) -> bool:
    d_lower = details.lower()
    return any(sig in d_lower for sig in _EDR_SIGNATURES)


def investigate(finding: dict) -> List[Dimension]:
    dims: List[Dimension] = []
    details = finding.get('Details', '')

    redirects_anon = bool(re.search(r'anonymous|private.*exec|anon.*exec', details, re.IGNORECASE))
    is_edr         = _target_is_edr(details)
    selective      = any(stub in details for stub in _ATTACKER_STUBS)
    broad_hook     = bool(re.search(r'broad|multiple.*stubs|all.*processes|consistent.*across', details, re.IGNORECASE))
    ssn_m          = re.search(r'SSN=0x([0-9a-f]+)', details, re.IGNORECASE)
    ssn            = ssn_m.group(1) if ssn_m else ''

    if is_edr:
        dims.append(Dimension(
            name='Module12_EDR_Hook', positive=False, source_module=12,
            rationale=(f'Hook target falls inside a known security DLL (EDR/AV vendor) -- '
                       'expected API monitoring hook, not malicious redirect')
        ))
    elif redirects_anon:
        dims.append(Dimension(
            name='Module12_MaliciousHook', positive=True, source_module=12,
            rationale=(f'Syscall stub JMP{(" SSN=" + ssn) if ssn else ""} redirects to '
                       'anonymous/private executable region -- definitive indicator of '
                       'malicious hook (SysWhispers/HellsGate/TartarusGate pattern)')
        ))

    if selective and not is_edr:
        dims.append(Dimension(
            name='Module12_SelectiveStubs', positive=True, source_module=12,
            rationale=('Hook targets specific memory-manipulation syscalls '
                       '(NtAllocateVirtualMemory/NtWriteVirtualMemory/NtCreateThreadEx) -- '
                       'attacker pattern: patch only the stubs needed for injection; '
                       'EDRs patch a much broader set including read-only APIs')
        ))

    if broad_hook and is_edr:
        dims.append(Dimension(
            name='Module12_BroadHook_EDR', positive=False, source_module=12,
            rationale=('Broad hook set consistent across all non-elevated processes -- '
                       'characteristic of EDR global API monitoring, not selective attacker patching')
        ))

    return dims
