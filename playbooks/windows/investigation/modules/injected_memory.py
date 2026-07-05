"""Module 3 -- Injected Memory Regions investigation logic.

From investigation guide:
  Shared section (same address multiple PIDs) -> classification gap, not injection
  High user space (0x7FFF...) -> almost always DLL/shared mapping
  YARA match in same address -> corroborated injection
  Module 5 thread start inside this VAD -> cross-module TP
  MZ at offset 0 -> manually-mapped PE

Per-region corroboration (MZ header, a shellcode thread inside this exact VAD, a
YARA hit in this exact region) stays scored per-finding: each is independent
evidence tied to a specific address. The UNCORROBORATED fallback -- a bare
"Executable private VAD, no backing file" with none of the above -- is scored
PER PID, not per region. Confirmed on live data: a process can legitimately hold
several small anonymous-exec regions from one underlying behavior (JIT
compilation, an internal scanning/emulation engine) with zero thread/YARA/MZ
evidence in any of them; scoring each region as an independent dimension crossed
the TP threshold on region COUNT alone for two unrelated processes on the same
host (MsMpEng.exe: 5 regions, PhoneExperienceHost.exe: 4 regions, both zero
other corroboration) -- the same "repetition is not independence" failure mode
already fixed for Module 20's direct-syscall clusters.
"""
from __future__ import annotations
import re
from typing import List, Tuple

from ..verdict import Dimension


def _parse_address(target: str) -> str:
    m = re.search(r'@\s*(0x[0-9a-f]+)', target, re.IGNORECASE)
    return m.group(1).lower() if m else ''


def _is_shared_section(addr: str, all_findings: List[dict]) -> bool:
    """Return True if addr appears in Module 3 findings for more than one PID."""
    if not addr:
        return False
    pids_at_addr = set()
    for f in all_findings:
        if 'Injected Memory' in f.get('Type', ''):
            m = re.search(r'PID\s+(\d+)', f.get('Target', ''))
            a = _parse_address(f.get('Target', ''))
            if m and a == addr:
                pids_at_addr.add(m.group(1))
    return len(pids_at_addr) > 1


def investigate(finding: dict, all_findings: List[dict] = None) -> List[Dimension]:
    """Per-finding corroboration check. Returns [] when the region has none of
    MZ/thread/YARA corroboration -- the caller (engine.py) collects those
    "uncorroborated" findings across the whole PID and scores them once via
    investigate_uncorroborated_pid(), not once per region.
    """
    dims: List[Dimension] = []
    details = finding.get('Details', '')
    target  = finding.get('Target', '')
    addr    = _parse_address(target)

    if all_findings and _is_shared_section(addr, all_findings):
        dims.append(Dimension(
            name='Module3_SharedSection', positive=False, source_module=3,
            rationale=(f'Address {addr} appears in Module 3 findings for multiple PIDs -- '
                       'system-wide shared section (DLL mapping or COM shared memory), '
                       'not genuine cross-process injection')
        ))
        return dims

    is_high_user = addr.startswith('0x7fff') or addr.startswith('0x7ffe')
    if is_high_user:
        dims.append(Dimension(
            name='Module3_HighUserSpace', positive=False, source_module=3,
            rationale=(f'Address {addr} is in very high user space (0x7FFF...) -- '
                       'almost always a DLL or shared-memory section, not injected shellcode')
        ))
        return dims

    # memory_forensic.py appends advisory/instructional text to JIT-consistent
    # regions -- "corroborate via YARA match or shellcode thread start in same
    # address range" -- telling the analyst what corroboration to LOOK for.
    # That sentence is not itself evidence: matching it as if a YARA hit or
    # shellcode thread had actually occurred fabricates cross-module
    # corroboration where none exists. Strip it before checking for real
    # assertions (confirmed on live data: 30/30 Injected Memory Region
    # findings from a JIT-consistent .NET host carried this exact suffix,
    # with zero actual Shellcode Thread findings for the same PID).
    evidence_text = re.split(r'corroborate via', details, flags=re.IGNORECASE)[0]

    has_mz    = bool(re.search(r'MZ.header|MZ at offset 0|manually.mapped', evidence_text, re.IGNORECASE))
    has_yara  = bool(re.search(r'yara|YARA|rule.*match|family.*match', evidence_text, re.IGNORECASE))
    has_m5    = bool(re.search(r'Module.5|shellcode.*thread|thread.*start.*inside', evidence_text, re.IGNORECASE))

    if has_mz:
        dims.append(Dimension(
            name='Module3_MZ_Header', positive=True, source_module=3,
            rationale=(f'MZ header at offset 0 of anonymous exec region @ {addr} -- '
                       'manually-mapped PE (Donut/reflective DLL injection)')
        ))

    if has_m5:
        dims.append(Dimension(
            name='Module3_Thread_Inside_Region', positive=True, source_module=3,
            rationale=(f'Module 5 shellcode thread start address inside this VAD @ {addr} -- '
                       'cross-module corroboration: active shellcode execution confirmed')
        ))

    if has_yara:
        dims.append(Dimension(
            name='Module3_YARA_Hit', positive=True, source_module=3,
            rationale=(f'YARA match in this anonymous exec region @ {addr} -- '
                       'rule corroborates injection')
        ))

    return dims


def is_uncorroborated(finding: dict) -> Tuple[bool, bool]:
    """Return (is_uncorroborated_candidate, is_jit) for a raw Injected Memory
    Region finding -- used by engine.py to decide whether this finding belongs
    in the per-PID aggregate pass. Excludes shared-section and high-user-space
    findings (those are already fully handled, non-aggregate cases).
    """
    details = finding.get('Details', '')
    target  = finding.get('Target', '')
    addr    = _parse_address(target)
    if addr.startswith('0x7fff') or addr.startswith('0x7ffe'):
        return False, False
    evidence_text = re.split(r'corroborate via', details, flags=re.IGNORECASE)[0]
    has_mz   = bool(re.search(r'MZ.header|MZ at offset 0|manually.mapped', evidence_text, re.IGNORECASE))
    has_yara = bool(re.search(r'yara|YARA|rule.*match|family.*match', evidence_text, re.IGNORECASE))
    has_m5   = bool(re.search(r'Module.5|shellcode.*thread|thread.*start.*inside', evidence_text, re.IGNORECASE))
    is_jit   = bool(re.search(r'JIT.consistent', evidence_text, re.IGNORECASE))
    return not (has_mz or has_yara or has_m5), is_jit


def investigate_uncorroborated_pid(uncorroborated_findings: List[dict]) -> List[Dimension]:
    """Aggregate every uncorroborated Injected Memory Region finding for one PID
    into a single dimension -- one behavioral fact ("this process holds N
    anonymous-exec regions with no other corroboration"), not N independent
    pieces of evidence toward a TP verdict.
    """
    if not uncorroborated_findings:
        return []

    addrs = [_parse_address(f.get('Target', '')) for f in uncorroborated_findings]
    addrs = [a for a in addrs if a]
    count = len(uncorroborated_findings)
    any_jit = any(is_uncorroborated(f)[1] for f in uncorroborated_findings)

    if any_jit:
        return [Dimension(
            name='Module3_JIT_Unconfirmed', positive=False, source_module=3,
            rationale=(f'{count} anonymous-exec region(s) ({", ".join(addrs[:5])}'
                       f'{"..." if len(addrs) > 5 else ""}), at least one flagged '
                       'JIT-consistent (known managed-code host), with no independent '
                       'corroboration in any of them -- no MZ header, no cross-module '
                       'YARA hit, no shellcode thread start. Expected JIT compilation '
                       'behavior; document, do not promote to TP without additional evidence.')
        )]

    return [Dimension(
        name='Module3_AnonExecRegion_Uncorroborated', positive=True, source_module=3,
        rationale=(f'{count} private anonymous executable VAD region(s) '
                   f'({", ".join(addrs[:5])}{"..." if len(addrs) > 5 else ""}) with unique '
                   'per-process addresses and no other corroboration (no MZ, no thread, '
                   'no YARA in any region) -- consistent with injected shellcode or '
                   'reflectively-loaded DLL, but requires further evidence '
                   '(cross-process handle attribution, capa/FLOSS on carved bytes, '
                   'protection-level check) before treating as confirmed.')
    )]
