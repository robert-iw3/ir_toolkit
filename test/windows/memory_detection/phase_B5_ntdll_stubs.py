#!/usr/bin/env python3
"""
Phase B5 -- TTP-008: ntdll syscall stub integrity (indirect / direct syscalls).

Detection: read ntdll.dll's .text in each process and find syscall stubs where
the expected mov-r10-rcx preamble (4C 8B D1) has been replaced with a JMP/INT3/CALL.
This is the fingerprint of EDR hook overwrites AND of indirect-syscall frameworks
(SysWhispers, HellsGate, TartarusGate) that patch the stub.

Clean stub:  4C 8B D1 B8 xx xx 00 00  0F 05  C3
             mov r10,rcx  mov eax,SSN  syscall  ret

Patched stub: E9 xx xx xx xx  B8 ...   (JMP before SSN load)

Standalone: python phase_B5_ntdll_stubs.py <image.aff4> <output_dir>
Unit test:  from phase_B5_ntdll_stubs import scan_ntdll_stubs, build_ntdll_corpus
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

_HOOK_OPCODES  = frozenset({0xE9, 0xEB, 0xFF, 0xCC, 0xE8})  # JMP/INT3/CALL variants
_CLEAN_PREFIX  = bytes([0x4C, 0x8B, 0xD1])                   # mov r10,rcx
_SYSCALL_BYTES = bytes([0x0F, 0x05])                          # syscall opcode
_MOV_EAX      = 0xB8                                          # mov eax,imm32


def find_patched_stubs(ntdll_bytes: bytes) -> list:
    """
    Scan a bytes buffer of ntdll .text for patched syscall stubs.

    Returns list of (offset, ssn, hook_byte) tuples.
    """
    results   = []
    limit     = len(ntdll_bytes) - 12
    j         = 0
    max_hits  = 10  # cap to avoid noise on partial reads

    while j < limit and len(results) < max_hits:
        # Find B8 (mov eax, imm32) followed by a valid SSN byte pattern.
        idx = ntdll_bytes.find(bytes([_MOV_EAX]), j, limit)
        if idx < 3:
            j = max(j + 1, idx + 1) if idx >= 0 else limit
            continue

        # High byte of SSN DWORD (offset +3 from B8) should be 0x00 or 0x01.
        if idx + 6 >= len(ntdll_bytes):
            break
        ssn_hi = ntdll_bytes[idx + 3]
        if ssn_hi not in (0x00, 0x01):
            j = idx + 1
            continue

        # Verify syscall opcode follows the 4-byte immediate.
        if ntdll_bytes[idx + 5: idx + 7] != _SYSCALL_BYTES:
            j = idx + 1
            continue

        # Check the 3 bytes before B8 for the expected clean prefix.
        prefix = ntdll_bytes[idx - 3: idx]
        if prefix == _CLEAN_PREFIX:
            j = idx + 7
            continue  # clean stub

        hook_byte = ntdll_bytes[idx - 3]
        if hook_byte not in _HOOK_OPCODES:
            j = idx + 7
            continue

        ssn = int.from_bytes(ntdll_bytes[idx + 1: idx + 3], 'little')
        results.append((idx - 3, ssn, hook_byte))
        j = idx + 7

    return results


def scan_ntdll_stubs(procs, add, log, _is_sys=None):
    """
    Scan ntdll.dll in each process for patched syscall stubs.

    Returns:
        int -- findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    for p in procs:
        if _sys(p):
            continue
        try:
            mods = p.module_list()
        except Exception:
            continue

        ntdll = next((m for m in mods if m.name.lower() == 'ntdll.dll'), None)
        if not ntdll:
            continue

        try:
            ntdll_bytes = p.memory.read(ntdll.base, min(0x40000, ntdll.image_size))
            if not ntdll_bytes:
                continue
        except Exception:
            continue

        patched = find_patched_stubs(ntdll_bytes)
        for offset, ssn, hook_byte in patched:
            add(
                'Critical',
                'ntdll Syscall Stub Patched (Memory)',
                f'PID {p.pid} ({p.name}) ntdll+{offset:#x}',
                f'Syscall stub SSN={ssn:#x} has hook opcode {hook_byte:#04x} instead of '
                f'expected mov r10,rcx (4C 8B D1). EDR user-mode hook or '
                f'indirect-syscall bypass (SysWhispers / HellsGate / TartarusGate).',
                'T1106 (Native API), T1562 (Impair Defenses), T1055',
            )
            n += 1

    log(f'  Patched ntdll stubs: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase B5: ntdll Stub Integrity (TTP-008) ===')
    scan_ntdll_stubs(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_B5_ntdll_stubs')
