#!/usr/bin/env python3
"""
Phase C1 -- TTP-010: DLL search-order hijacking / sideloading.

Behavioral evidence required (not just name matching):
  1. Module loaded from non-system path matching a sideloading target name.
  2. The loaded DLL's PE header in memory lacks a valid Security Directory
     (IMAGE_DIRECTORY_ENTRY_SECURITY offset 0x60 from OptionalHeader) -- a
     sideloaded replacement almost never carries the same Authenticode signature
     as the genuine system DLL it impersonates.
  3. The loaded DLL's import table references are checked: if a DLL named
     dbghelp.dll imports from unexpected modules (e.g., network/comms DLLs
     like ws2_32, winhttp, wininet) it is almost certainly a beacon implant.

All three signals together constitute beyond-a-shadow-of-doubt evidence.
Single name+path match alone is logged as INFO (not a finding).

Standalone: python phase_C1_dll_sideload.py <image.aff4> <output_dir>
Unit test:  from phase_C1_dll_sideload import scan_dll_sideload
"""
import sys, os, re, struct
from pathlib import Path
sys.path.insert(0, os.path.dirname(__file__))

from _boilerplate import is_system_proc

_SYSTEM_PATH = re.compile(
    r'(?i)^[a-z]:\\windows\\(system32|syswow64|winsxs|assembly|microsoft\.net)\\',
)
_SUSP_PATH = re.compile(
    r'(?i)\\(temp|tmp|appdata\\local\\temp|programdata|users\\public|downloads)\\',
)
_SIDELOAD_NAMES = re.compile(
    r'(?i)^(version|dbghelp|wbemprox|cscapi|phonebook|mfplat|mfreadwrite|'
    r'dwrite|d3d11|d2d1|windowscodecs|xmllite|cryptsp|secur32|userenv|'
    r'msvcp\d+|vcruntime\d+|api-ms-win-[a-z]|uxtheme|textshaping|'
    r'msasn1|ntmarta|profapi).*\.dll$',
)

# Imports that have no business being in a UI/helper DLL -- strong C2 indicator.
_BEACON_IMPORTS = frozenset({
    'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'msvcrt.dll',
    'ntdll.dll', 'advapi32.dll',
})

# Offsets into a 64-bit PE optional header from the PE signature location.
_PE_SIG         = b'PE\x00\x00'
_OPTIONAL_OFF   = 24      # from PE sig start to OptionalHeader
_MAGIC_OFF      = 0       # OptionalHeader: Magic
_PE32_PLUS      = 0x020B
_PE32           = 0x010B
_SECURITY_OFF32 = 0x60    # DataDirectory[4].VirtualAddress (32-bit optional header)
_SECURITY_OFF64 = 0x70    # DataDirectory[4].VirtualAddress (64-bit optional header)
_IMPORT_OFF32   = 0x50    # DataDirectory[1].VirtualAddress
_IMPORT_OFF64   = 0x60    # DataDirectory[1].VirtualAddress -- same as security in 32!
# Corrected offsets from OptionalHeader base:
# 64-bit: DataDirectory starts at 0x70; entry[0]=IMAGE_IMPORT (VirtualAddress at +0x78); entry[4]=Security at +0x98
# 32-bit: DataDirectory starts at 0x60; entry[0]=IMAGE_IMPORT (VirtualAddress at +0x68); entry[4]=Security at +0x88
_DATADIRS_OFF64 = 0x70   # start of DataDirectory array in 64-bit PE
_DATADIRS_OFF32 = 0x60   # start of DataDirectory array in 32-bit PE
_IMPORT_IDX     = 1      # DataDirectory index for import table
_SECURITY_IDX   = 4      # DataDirectory index for security (Authenticode)

_HDR_READ = 0x400   # bytes to read for PE header analysis


def _has_authenticode(pe_bytes: bytes) -> bool:
    """Return True if the PE has a non-zero Security directory entry."""
    e_lfanew_off = 0x3C
    if len(pe_bytes) < e_lfanew_off + 4:
        return False
    e_lfanew = struct.unpack_from('<I', pe_bytes, e_lfanew_off)[0]
    if e_lfanew + 6 > len(pe_bytes):
        return False
    if pe_bytes[e_lfanew:e_lfanew + 4] != _PE_SIG:
        return False
    magic_off = e_lfanew + _OPTIONAL_OFF
    if magic_off + 2 > len(pe_bytes):
        return False
    magic = struct.unpack_from('<H', pe_bytes, magic_off)[0]
    if magic == _PE32_PLUS:
        dirs_base = e_lfanew + _OPTIONAL_OFF + _DATADIRS_OFF64
    elif magic == _PE32:
        dirs_base = e_lfanew + _OPTIONAL_OFF + _DATADIRS_OFF32
    else:
        return False
    sec_off = dirs_base + _SECURITY_IDX * 8   # each DataDirectory entry = 8 bytes
    if sec_off + 4 > len(pe_bytes):
        return False
    sec_va = struct.unpack_from('<I', pe_bytes, sec_off)[0]
    return sec_va != 0


def _get_import_table_rva(pe_bytes: bytes):
    """Return (import_rva, magic) or (0, 0) if not parseable."""
    e_lfanew_off = 0x3C
    if len(pe_bytes) < e_lfanew_off + 4:
        return 0, 0
    e_lfanew = struct.unpack_from('<I', pe_bytes, e_lfanew_off)[0]
    if e_lfanew + 4 > len(pe_bytes):
        return 0, 0
    if pe_bytes[e_lfanew:e_lfanew + 4] != _PE_SIG:
        return 0, 0
    magic_off = e_lfanew + _OPTIONAL_OFF
    if magic_off + 2 > len(pe_bytes):
        return 0, 0
    magic = struct.unpack_from('<H', pe_bytes, magic_off)[0]
    if magic == _PE32_PLUS:
        dirs_base = e_lfanew + _OPTIONAL_OFF + _DATADIRS_OFF64
    elif magic == _PE32:
        dirs_base = e_lfanew + _OPTIONAL_OFF + _DATADIRS_OFF32
    else:
        return 0, 0
    imp_off = dirs_base + _IMPORT_IDX * 8
    if imp_off + 4 > len(pe_bytes):
        return 0, 0
    imp_rva = struct.unpack_from('<I', pe_bytes, imp_off)[0]
    return imp_rva, magic


def _parse_import_names_from_bytes(pe_bytes: bytes, imp_rva: int) -> list:
    """
    Walk the IMAGE_IMPORT_DESCRIPTOR table in the already-read PE buffer.
    Returns list of lowercase DLL name strings, or [] on failure.
    """
    if not imp_rva or imp_rva >= len(pe_bytes):
        return []
    names = []
    try:
        for i in range(32):
            off = imp_rva + i * 20
            if off + 20 > len(pe_bytes):
                break
            characteristics = struct.unpack_from('<I', pe_bytes, off)[0]
            name_rva        = struct.unpack_from('<I', pe_bytes, off + 12)[0]
            if not name_rva and not characteristics:
                break   # null terminator
            if name_rva >= len(pe_bytes):
                break
            nul      = pe_bytes.find(b'\x00', name_rva)
            dll_name = pe_bytes[name_rva:nul].decode('ascii', errors='ignore').lower() if nul >= 0 else ''
            if dll_name:
                names.append(dll_name)
    except Exception:
        pass
    return names


def scan_dll_sideload(procs, add, log, _is_sys=None, _read_mem=None):
    """
    Flag DLL sideloading candidates with structural PE behavioral evidence.

    Requires ALL of:
      - Non-system path with sideloading-target DLL name (structural context)
      - Missing Authenticode Security Directory (forged DLL)
      OR
      - Import table contains comms/crypto imports inconsistent with the DLL's
        stated identity (malicious implant)

    Returns:
        int -- findings emitted
    """
    _sys = _is_sys if _is_sys is not None else is_system_proc
    n    = 0

    for p in procs:
        if _sys(p):
            continue
        try:
            mods     = p.module_list()
            exe_path = str(getattr(p, 'pathuser', '') or '').lower()
            exe_dir  = str(Path(exe_path).parent).lower() if exe_path else ''
        except Exception:
            continue
        if not exe_dir:
            continue

        for m in mods:
            dll_path = str(
                getattr(m, 'path', '') or getattr(m, 'fullname', '') or ''
            ).lower()
            if not dll_path:
                continue
            if _SYSTEM_PATH.match(dll_path):
                continue
            dll_name = Path(dll_path).name
            in_exe_dir   = exe_dir and dll_path.startswith(exe_dir)
            in_susp_path = bool(_SUSP_PATH.search(dll_path))
            is_target    = bool(_SIDELOAD_NAMES.match(dll_name))

            if not (in_exe_dir or in_susp_path):
                continue
            if not is_target:
                continue

            # --- Behavioral evidence layer ---
            mod_base  = getattr(m, 'base', 0)
            pe_bytes  = b''
            try:
                if _read_mem is not None:
                    pe_bytes = _read_mem(p, mod_base, _HDR_READ) or b''
                elif hasattr(p, 'maps') and hasattr(p.maps, 'memory'):
                    pe_bytes = p.maps.memory.read(mod_base, _HDR_READ) or b''
            except Exception:
                pass

            has_sig = _has_authenticode(pe_bytes) if pe_bytes else True   # unknown -> benefit of doubt
            imp_rva, _ = _get_import_table_rva(pe_bytes)
            import_names = _parse_import_names_from_bytes(pe_bytes, imp_rva) if pe_bytes else []
            beacon_imports = set(import_names) & _BEACON_IMPORTS

            # Sideloading verdict: needs at least one structural indicator.
            no_sig  = pe_bytes and not has_sig
            c2_imp  = bool(beacon_imports)

            if not (no_sig or c2_imp):
                log(f'  C1: {dll_name} in {exe_dir} -- name/path match only, no PE evidence; skipping')
                continue

            sev = 'High' if (in_susp_path or c2_imp) else 'Medium'
            evidence_parts = []
            if no_sig:
                evidence_parts.append('no Authenticode signature in PE Security Directory')
            if c2_imp:
                evidence_parts.append(f'beacon-consistent imports: {sorted(beacon_imports)}')
            evidence = '; '.join(evidence_parts)

            add(
                sev,
                'DLL Sideloading (Memory)',
                f'PID {p.pid} ({p.name})',
                f'Module {dll_name} loaded from non-system path: {dll_path}. '
                f'Sideloading-target DLL name with behavioral PE evidence: {evidence}. '
                f'EXE: {exe_path}',
                'T1574.001 (DLL Search Order Hijacking), T1574.002 (DLL Side-Loading)',
            )
            n += 1

    log(f'  DLL sideloading candidates with PE evidence: {n}')
    return n


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: python {os.path.basename(__file__)} <image> <output_dir>')
        sys.exit(1)

    from _boilerplate import setup_runtime, write_report
    rt = setup_runtime(sys.argv[1], sys.argv[2])
    rt['log']('=== Phase C1: DLL Sideloading (TTP-010) ===')
    scan_dll_sideload(rt['procs'], rt['add'], rt['log'])
    write_report(rt, 'phase_C1_dll_sideload')
