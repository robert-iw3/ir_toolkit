"""
Phase 5 retrospective gap tests -- memory_forensic.py advanced evasion modules.
Source-text based (no vmmpyc import required).

Module 20 -- Direct syscall detection (T1055.004 / Hell's Gate / SysWhispers)
  Shellcode that bypasses user-mode hooks by issuing 'syscall' (0F 05) directly.
  Legitimate code in user space never emits raw syscall opcodes outside ntdll.

Module 21 -- Process ghosting detection (T1055.015)
  File-backed image VAD whose backing file no longer exists on disk.
  The loader maps a PE then the file is deleted before any snapshot.

Module 22 -- ETW-TI provider health check (T1562.006)
  Microsoft-Windows-Threat-Intelligence provider (GUID F4E1897C-...) is the kernel
  telemetry channel used by most EDRs. If absent or unregistered, sensors are blind.
"""
import re
import pathlib

SRC = pathlib.Path(__file__).parent.parent / 'playbooks' / 'windows' / 'threat_hunting' / 'memory_forensic.py'
src = SRC.read_text(encoding='utf-8')


# ---------------------------------------------------------------------------
# Module 20: Direct syscall detection
# ---------------------------------------------------------------------------

def test_module20_section_exists():
    """Module 20 must have a logged section header (=== 20.)."""
    assert re.search(r"=== 20\.", src), "Module 20 section header '=== 20.' not found"


def test_module20_uses_syscall_bytes_constant():
    """Module 20 must reference _SYSCALL_BYTES (0x0F 0x05) for opcode scanning."""
    # _SYSCALL_BYTES is already defined as bytes([0x0F, 0x05]) in the constants block.
    # Module 20 should search scanned regions for this opcode pattern.
    m20_start = src.find('=== 20.')
    assert m20_start != -1
    m20_end   = src.find('=== 21.', m20_start)
    if m20_end == -1: m20_end = len(src)
    block = src[m20_start:m20_end]
    assert '_SYSCALL_BYTES' in block, (
        "_SYSCALL_BYTES not referenced in Module 20 -- "
        "direct syscall detection must scan for the 0x0F 0x05 opcode"
    )


def test_module20_finding_type():
    """Module 20 must add a 'Direct Syscall Execution' (or similar) finding."""
    m20_start = src.find('=== 20.')
    assert m20_start != -1
    m20_end   = src.find('=== 21.', m20_start)
    if m20_end == -1: m20_end = len(src)
    block = src[m20_start:m20_end]
    assert re.search(r"'Direct Syscall", block) or re.search(r'"Direct Syscall', block), (
        "No 'Direct Syscall' finding type in Module 20"
    )


def test_module20_skips_ntdll():
    """Module 20 must NOT flag ntdll.dll itself (legitimate syscall stub source)."""
    m20_start = src.find('=== 20.')
    assert m20_start != -1
    m20_end   = src.find('=== 21.', m20_start)
    if m20_end == -1: m20_end = len(src)
    block = src[m20_start:m20_end]
    assert re.search(r'(?i)ntdll', block), (
        "Module 20 does not reference ntdll exclusion -- "
        "ntdll.dll legitimately contains syscall stubs and must be excluded"
    )


def test_module20_skips_jit_heavy_procs():
    """Module 20 must exclude JIT_HEAVY_PROCS (.NET CLR, V8, etc.).
    CLR JIT emits 'syscall' (0x0F 0x05) opcodes in compiled stubs -- 555 FP findings
    were produced from pwsh.exe and CrossDeviceService in the GOTEM smoke test."""
    m20_start = src.find('=== 20.')
    assert m20_start != -1
    m20_end   = src.find('=== 21.', m20_start)
    if m20_end == -1: m20_end = len(src)
    block = src[m20_start:m20_end]
    assert re.search(r'JIT_HEAVY_PROCS|is_jit|jit_host', block, re.IGNORECASE), (
        "Module 20 does not exclude JIT_HEAVY_PROCS -- "
        "CLR JIT legitimately emits syscall opcodes in its compiled code; "
        "without this exclusion all pwsh.exe / dotnet / CrossDeviceService regions fire"
    )


# ---------------------------------------------------------------------------
# Module 21: Process ghosting / deleted-file image VAD
# ---------------------------------------------------------------------------

def test_module21_section_exists():
    """Module 21 must have a logged section header (=== 21.)."""
    assert re.search(r"=== 21\.", src), "Module 21 section header '=== 21.' not found"


def test_module21_checks_backing_file_existence():
    """Module 21 must verify whether the VAD backing file exists on disk."""
    m21_start = src.find('=== 21.')
    assert m21_start != -1
    m21_end   = src.find('=== 22.', m21_start)
    if m21_end == -1: m21_end = len(src)
    block = src[m21_start:m21_end]
    # Should use os.path.exists, Path.exists, or similar filesystem check
    assert re.search(r'os\.path\.exists|Path.*exists|\.is_file\(\)', block), (
        "Module 21 does not check if backing file exists on disk -- "
        "process ghosting requires verifying the mapped file was deleted"
    )


def test_module21_only_checks_image_vads():
    """Module 21 must restrict the check to image-backed VADs (not anonymous regions)."""
    m21_start = src.find('=== 21.')
    assert m21_start != -1
    m21_end   = src.find('=== 22.', m21_start)
    if m21_end == -1: m21_end = len(src)
    block = src[m21_start:m21_end]
    assert re.search(r"'image'|\"image\"", block), (
        "Module 21 does not filter for 'image' VAD type -- "
        "must only check file-backed image regions, not anonymous allocations"
    )


def test_module21_finding_type():
    """Module 21 must add a 'Process Ghosting' finding."""
    m21_start = src.find('=== 21.')
    assert m21_start != -1
    m21_end   = src.find('=== 22.', m21_start)
    if m21_end == -1: m21_end = len(src)
    block = src[m21_start:m21_end]
    assert re.search(r"'Process Ghost|\"Process Ghost", block), (
        "No 'Process Ghosting' finding type in Module 21"
    )


# ---------------------------------------------------------------------------
# Module 22: ETW-TI provider health check
# ---------------------------------------------------------------------------

def test_module22_section_exists():
    """Module 22 must have a logged section header (=== 22.)."""
    assert re.search(r"=== 22\.", src), "Module 22 section header '=== 22.' not found"


def test_module22_references_etw_ti_guid():
    """Module 22 must reference the ETW-TI provider GUID (F4E1897C)."""
    m22_start = src.find('=== 22.')
    assert m22_start != -1
    block = src[m22_start: m22_start + 2000]
    assert re.search(r'(?i)F4E1897C', block), (
        "Module 22 does not reference the ETW-TI provider GUID F4E1897C-... -- "
        "must verify Microsoft-Windows-Threat-Intelligence is registered and active"
    )


def test_module22_graceful_degradation():
    """Module 22 must degrade gracefully when the ETW-TI API is unavailable."""
    m22_start = src.find('=== 22.')
    assert m22_start != -1
    block = src[m22_start: m22_start + 2000]
    # Should have a try/except or hasattr check so the module skips cleanly
    assert re.search(r'except|hasattr|getattr', block), (
        "Module 22 has no graceful degradation -- "
        "ETW-TI kernel API may not be available in all vmmpyc builds; must handle gracefully"
    )


def test_module22_finding_type():
    """Module 22 must add an 'ETW-TI' finding when the provider is absent."""
    m22_start = src.find('=== 22.')
    assert m22_start != -1
    block = src[m22_start: m22_start + 2000]
    assert re.search(r"'ETW|\"ETW", block), (
        "No 'ETW' finding type in Module 22"
    )
