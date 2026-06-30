"""
Unit tests -- Phases C1-C4: Additional coverage.

C1: DLL sideloading (requires PE behavioral evidence: no Authenticode / beacon imports)
C2: CLR assembly in non-managed host (requires BSJB CLI metadata magic in exec region)
C3: PPID spoofing
C4: COM VTable hijacking
"""
import os, sys, struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from conftest import MockProcess, MockModule

from phase_C1_dll_sideload  import scan_dll_sideload, _has_authenticode
from phase_C2_clr_assembly  import scan_clr_assembly, _find_bsjb
from phase_C3_ppid_spoof    import scan_ppid_spoof
from phase_C4_com_vtable     import scan_com_vtable


# ---------------------------------------------------------------------------
# PE builder helpers
# ---------------------------------------------------------------------------
def _build_pe64(has_authenticode: bool = False, import_dlls: list = None) -> bytes:
    """
    Build a minimal 64-bit PE header in memory suitable for behavioral tests.

    Layout:
      0x00  MZ header  (64 bytes, e_lfanew = 0x40)
      0x40  PE sig + COFF header (24 bytes)
      0x58  Optional header 64-bit (starts at e_lfanew + 24 = 0x58)
             Magic = 0x020B
             DataDirectory at 0x58 + 0x70 = 0xC8
               [0] Import:  (RVA, Size) at 0xC8
               [4] Security:(RVA, Size) at 0xC8 + 4*8 = 0xE8
      0x100 Import descriptor table (if requested)
      0x200 Import name table entries
    """
    buf = bytearray(0x400)
    # DOS header
    buf[0:2] = b'MZ'
    e_lfanew = 0x40
    struct.pack_into('<I', buf, 0x3C, e_lfanew)
    # PE signature
    buf[e_lfanew:e_lfanew + 4] = b'PE\x00\x00'
    # COFF header: Machine=AMD64, NumberOfSections=1
    struct.pack_into('<HH', buf, e_lfanew + 4, 0x8664, 1)
    # SizeOfOptionalHeader
    struct.pack_into('<H', buf, e_lfanew + 20, 0xF0)
    # Optional header
    opt_off = e_lfanew + 24
    struct.pack_into('<H', buf, opt_off, 0x020B)   # Magic = PE32+
    # DataDirectory base (NumberOfRvaAndSizes = 16 at opt+0x6C for PE32+)
    struct.pack_into('<I', buf, opt_off + 0x6C, 16)
    dirs_base = opt_off + 0x70

    # DataDirectory[4] = Security
    sec_off = dirs_base + 4 * 8
    if has_authenticode:
        struct.pack_into('<II', buf, sec_off, 0x0300, 0x1000)   # non-zero RVA

    # DataDirectory[1] = Import table
    imp_rva_off = dirs_base + 1 * 8
    imp_desc_rva = 0x100   # where descriptors live
    if import_dlls:
        struct.pack_into('<II', buf, imp_rva_off, imp_desc_rva, 20 * len(import_dlls))
        # Write IMAGE_IMPORT_DESCRIPTOR entries
        name_rva_base = 0x200
        for i, dll in enumerate(import_dlls):
            desc_off = imp_desc_rva + i * 20
            # Name RVA
            name_rva = name_rva_base + i * 64
            struct.pack_into('<I', buf, desc_off + 12, name_rva)
            struct.pack_into('<I', buf, desc_off + 0, 0xDEAD)   # non-zero characteristics
            # Write the name string
            enc = dll.encode('ascii') + b'\x00'
            buf[name_rva:name_rva + len(enc)] = enc
        # Null terminator descriptor
        null_off = imp_desc_rva + len(import_dlls) * 20
        buf[null_off:null_off + 20] = b'\x00' * 20

    return bytes(buf)


# ---------------------------------------------------------------------------
# C1: DLL sideloading (behavioral)
# ---------------------------------------------------------------------------
class TestDllSideload:

    def _make_mem_reader(self, pe_bytes: bytes, mod_base: int):
        """Return a _read_mem callable that returns pe_bytes for the given base."""
        def _read_mem(proc, addr, size):
            if addr == mod_base:
                return pe_bytes[:size]
            return b''
        return _read_mem

    def _make_proc(self, pid, name, exe_path, modules):
        return MockProcess(pid=pid, name=name, ppid=4,
                           pathuser=exe_path, modules=modules)

    def test_no_sig_known_name_fires_medium(self, findings, silent_log):
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False)
        # Use a path that is NOT in _SUSP_PATH (not temp/downloads/public)
        exe      = r'C:\Program Files\MyApp\app.exe'
        mod      = MockModule('version.dll', mod_base, 0x10000,
                              path=r'C:\Program Files\MyApp\version.dll')
        proc     = self._make_proc(8000, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 1
        assert result[0]['Severity'] == 'Medium'
        assert 'Sideloading' in result[0]['Type']

    def test_no_sig_temp_path_fires_high(self, findings, silent_log):
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False)
        exe      = r'C:\Users\bob\AppData\Local\Temp\app\app.exe'
        mod      = MockModule('dbghelp.dll', mod_base, 0x10000,
                              path=r'C:\Users\bob\AppData\Local\Temp\app\dbghelp.dll')
        proc     = self._make_proc(8001, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 1
        assert result[0]['Severity'] == 'High'

    def test_has_authenticode_no_finding(self, findings, silent_log):
        """DLL with valid Authenticode = not sideloaded (signature present)."""
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=True)
        exe      = r'C:\Program Files\MyApp\app.exe'
        mod      = MockModule('version.dll', mod_base, 0x10000,
                              path=r'C:\Program Files\MyApp\version.dll')
        proc     = self._make_proc(8002, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 0, 'DLL with Authenticode sig should not fire'

    def test_beacon_imports_fires_high(self, findings, silent_log):
        """dbghelp.dll importing ws2_32.dll = C2 beacon regardless of temp path."""
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False,
                               import_dlls=['ws2_32.dll', 'kernel32.dll'])
        # Use Program Files (not temp) so the HIGH comes from beacon imports, not path
        exe      = r'C:\Program Files\MyApp\app.exe'
        mod      = MockModule('dbghelp.dll', mod_base, 0x10000,
                              path=r'C:\Program Files\MyApp\dbghelp.dll')
        proc     = self._make_proc(8003, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 1
        assert 'ws2_32' in result[0]['Details']

    def test_system_dll_path_no_finding(self, findings, silent_log):
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False)
        exe      = r'C:\Program Files\MyApp\app.exe'
        mod      = MockModule('version.dll', mod_base, 0x10000,
                              path=r'C:\Windows\System32\version.dll')
        proc     = self._make_proc(8004, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 0

    def test_unknown_dll_name_not_flagged(self, findings, silent_log):
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False)
        exe      = r'C:\Program Files\MyApp\app.exe'
        mod      = MockModule('myapp_helper.dll', mod_base, 0x10000,
                              path=r'C:\Program Files\MyApp\myapp_helper.dll')
        proc     = self._make_proc(8005, 'app.exe', exe, [mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 0

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        mod_base = 0x10000000
        pe       = _build_pe64(has_authenticode=False)
        mod      = MockModule('version.dll', mod_base, 0x10000,
                              path=r'C:\Program Files\MyApp\version.dll')
        proc     = MockProcess(pid=4, name='System', ppid=0,
                               pathuser='', modules=[mod])
        n        = scan_dll_sideload([proc], add, silent_log,
                                     _read_mem=self._make_mem_reader(pe, mod_base))
        assert n == 0


class TestPeHelpers:
    """Direct unit tests for the PE parsing helpers."""

    def test_has_authenticode_true(self):
        pe = _build_pe64(has_authenticode=True)
        assert _has_authenticode(pe) is True

    def test_has_authenticode_false(self):
        pe = _build_pe64(has_authenticode=False)
        assert _has_authenticode(pe) is False

    def test_empty_bytes_returns_false(self):
        assert _has_authenticode(b'') is False

    def test_truncated_bytes_returns_false(self):
        assert _has_authenticode(b'MZ' + b'\x00' * 10) is False


# ---------------------------------------------------------------------------
# C2: CLR in non-managed host (BSJB behavioral evidence)
# ---------------------------------------------------------------------------
_BSJB = b'BSJB'


def _make_clr_proc(pid, name, clr_mods=None, exec_addr=0x20000000, no_bsjb=False):
    """Build a process with CLR DLLs loaded and BSJB magic in an exec VAD."""
    mods      = [MockModule(m, 0x7FF000000000 + i * 0x1000000, 0x500000)
                 for i, m in enumerate(clr_mods or ['clr.dll'])]
    if no_bsjb:
        bsjb_data = b'\x00' * 0x10000
    else:
        bsjb_data = b'\x00' * 0x100 + _BSJB + b'\x00' * (0x10000 - 0x104)
    vad = {'start': exec_addr, 'size': 0x10000, 'protection': 'EXECUTE_READ',
           'type': 'private', 'tag': ''}
    return MockProcess(pid=pid, name=name, ppid=4,
                       modules=mods, vads=[vad],
                       mem_regions={exec_addr: bsjb_data})


def _read_via_memory(proc, addr, size):
    return proc.maps.memory.read(addr, size)


class TestClrAssembly:

    def test_clr_with_bsjb_in_exec_fires_high(self, findings, silent_log):
        result, add = findings
        proc = _make_clr_proc(9000, 'notepad.exe')
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        assert n == 1
        assert result[0]['Severity'] == 'High'
        assert 'CLR' in result[0]['Type']
        assert 'BSJB' in result[0]['Details']

    def test_bsjb_alone_no_clr_dll_fires(self, findings, silent_log):
        """CLR was unloaded after exec-assembly -- BSJB still in memory."""
        result, add = findings
        exec_addr = 0x20000000
        bsjb_data = b'\x00' * 0x50 + _BSJB + b'\x00' * (0x10000 - 0x54)
        vad  = {'start': exec_addr, 'size': 0x10000, 'protection': 'EXECUTE_READ',
                'type': 'private', 'tag': ''}
        proc = MockProcess(pid=9001, name='calc.exe', ppid=4,
                           modules=[], vads=[vad],
                           mem_regions={exec_addr: bsjb_data})
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        assert n == 1
        assert 'none' in result[0]['Details'].lower() or 'unloaded' in result[0]['Details'].lower()

    def test_clr_dll_without_bsjb_no_finding(self, findings, silent_log):
        """CLR DLL present but no BSJB in exec memory = context only, not a finding."""
        result, add = findings
        proc = _make_clr_proc(9002, 'notepad.exe', no_bsjb=True)
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        assert n == 0, 'CLR DLL without BSJB magic = insufficient evidence'

    def test_powershell_suppressed(self, findings, silent_log):
        result, add = findings
        proc = _make_clr_proc(9003, 'powershell.exe')
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        assert n == 0

    def test_mscoree_plus_clr_suppressed(self, findings, silent_log):
        result, add = findings
        exec_addr = 0x20000000
        bsjb_data = _BSJB + b'\x00' * (0x10000 - 4)
        mods = [MockModule('mscoree.dll', 0x7FF600000000, 0x100000),
                MockModule('clr.dll',     0x7FF500000000, 0x500000)]
        vad  = {'start': exec_addr, 'size': 0x10000, 'protection': 'EXECUTE_READ',
                'type': 'private', 'tag': ''}
        proc = MockProcess(pid=9004, name='custom_managed.exe', ppid=4,
                           modules=mods, vads=[vad],
                           mem_regions={exec_addr: bsjb_data})
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        assert n == 0

    def test_bsjb_address_in_details(self, findings, silent_log):
        result, add = findings
        proc = _make_clr_proc(9005, 'explorer.exe', exec_addr=0x30000000)
        n    = scan_clr_assembly([proc], add, silent_log,
                                  _read_mem=_read_via_memory)
        # Formatted as 0x0000000030000000; check the non-zero part
        assert result and '30000000' in result[0]['Details'].lower()

    def test_find_bsjb_helper(self):
        assert _find_bsjb(b'\x00\x00BSJB\x00') is True
        assert _find_bsjb(b'\x00\x00\x00') is False
        assert _find_bsjb(b'') is False


# ---------------------------------------------------------------------------
# C3: PPID spoofing
# ---------------------------------------------------------------------------
class TestPpidSpoof:

    def test_parent_created_after_child_fires_high(self, findings, silent_log):
        result, add = findings
        child  = MockProcess(pid=10000, name='cmd.exe', ppid=10001, create_time=100)
        parent = MockProcess(pid=10001, name='explorer.exe', create_time=200)
        pid_map = {10001: parent}
        n, time_ok = scan_ppid_spoof([child], pid_map, add, silent_log)
        assert n == 1
        assert time_ok is True
        assert result[0]['Severity'] == 'High'
        assert 'PPID' in result[0]['Type']

    def test_parent_created_before_child_no_finding(self, findings, silent_log):
        result, add = findings
        child  = MockProcess(pid=10002, name='cmd.exe', ppid=10003, create_time=200)
        parent = MockProcess(pid=10003, name='explorer.exe', create_time=100)
        pid_map = {10003: parent}
        n, _ = scan_ppid_spoof([child], pid_map, add, silent_log)
        assert n == 0

    def test_orphaned_parent_fires_medium(self, findings, silent_log):
        result, add = findings
        child   = MockProcess(pid=10004, name='powershell.exe', ppid=9999)
        n, _ = scan_ppid_spoof([child], {}, add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Medium'
        assert 'Orphaned' in result[0]['Type'] or 'PPID' in result[0]['Type']

    def test_ppid_zero_not_flagged(self, findings, silent_log):
        result, add = findings
        child = MockProcess(pid=10005, name='smss.exe', ppid=0)
        n, _ = scan_ppid_spoof([child], {}, add, silent_log)
        assert n == 0, 'PPID=0 (Idle) is an expected orphan'

    def test_ppid_four_not_flagged(self, findings, silent_log):
        result, add = findings
        child = MockProcess(pid=10006, name='wininit.exe', ppid=4)
        n, _ = scan_ppid_spoof([child], {}, add, silent_log)
        assert n == 0, 'PPID=4 (System) is an expected orphan'

    def test_create_time_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        child  = MockProcess(pid=10007, name='cmd.exe', ppid=10008)
        parent = MockProcess(pid=10008, name='explorer.exe')
        pid_map = {10008: parent}
        n, time_ok = scan_ppid_spoof([child], pid_map, add, silent_log)
        assert time_ok is False

    def test_known_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        child  = MockProcess(pid=10009, name='smss.exe', ppid=10010, create_time=200)
        parent = MockProcess(pid=10010, name='notepad.exe', create_time=300)
        n, _ = scan_ppid_spoof([child], {10010: parent}, add, silent_log)
        assert n == 0, 'smss.exe is in PPID_SKIP'


# ---------------------------------------------------------------------------
# C4: COM VTable hijacking
# ---------------------------------------------------------------------------
class TestComVtable:

    def _anon_exec_vad(self, addr=0x10000000, size=0x1000):
        return {'start': addr, 'size': size, 'protection': 'EXECUTE_READ',
                'type': 'private', 'tag': ''}

    def _image_rw_vad(self, addr=0x400000, size=0x1000):
        return {'start': addr, 'size': size, 'protection': 'READWRITE',
                'type': 'image', 'tag': '\\Device\\test.dll'}

    def _ptr_bytes(self, val):
        return struct.pack('<Q', val)

    def test_pointer_into_anon_exec_fires_medium(self, findings, silent_log):
        result, add = findings
        anon_exec_addr = 0x10000000
        ptr_src_addr   = 0x400000
        anon_vad  = self._anon_exec_vad(addr=anon_exec_addr, size=0x1000)
        rw_vad    = self._image_rw_vad(addr=ptr_src_addr, size=0x1000)
        ptr_data  = self._ptr_bytes(anon_exec_addr + 0x100) * (0x1000 // 8)

        proc = MockProcess(pid=11000, name='app.exe', ppid=4,
                           vads=[anon_vad, rw_vad],
                           mem_regions={ptr_src_addr: ptr_data})
        n    = scan_com_vtable([proc], add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Medium'
        assert 'VTable' in result[0]['Type'] or 'COM' in result[0]['Type']

    def test_pointer_to_valid_addr_no_finding(self, findings, silent_log):
        result, add = findings
        anon_exec_addr = 0x10000000
        ptr_src_addr   = 0x400000
        anon_vad  = self._anon_exec_vad(addr=anon_exec_addr, size=0x1000)
        rw_vad    = self._image_rw_vad(addr=ptr_src_addr, size=0x1000)
        ptr_data  = self._ptr_bytes(0x7FF800001000) * (0x1000 // 8)

        proc = MockProcess(pid=11001, name='safe.exe', ppid=4,
                           vads=[anon_vad, rw_vad],
                           mem_regions={ptr_src_addr: ptr_data})
        n    = scan_com_vtable([proc], add, silent_log)
        assert n == 0

    def test_no_anon_exec_no_finding(self, findings, silent_log):
        result, add = findings
        rw_vad = self._image_rw_vad()
        proc   = MockProcess(pid=11002, name='test.exe', ppid=4, vads=[rw_vad])
        n      = scan_com_vtable([proc], add, silent_log)
        assert n == 0

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        proc = MockProcess(pid=4, name='System', ppid=0,
                           vads=[self._anon_exec_vad(), self._image_rw_vad()])
        n    = scan_com_vtable([proc], add, silent_log)
        assert n == 0

    def test_pointer_in_details(self, findings, silent_log):
        result, add = findings
        anon_exec_addr = 0x10000000
        ptr_src_addr   = 0x400000
        anon_vad  = self._anon_exec_vad(addr=anon_exec_addr, size=0x1000)
        rw_vad    = self._image_rw_vad(addr=ptr_src_addr, size=0x1000)
        ptr_data  = self._ptr_bytes(anon_exec_addr + 0x50) * (0x1000 // 8)

        proc = MockProcess(pid=11003, name='app.exe', ppid=4,
                           vads=[anon_vad, rw_vad],
                           mem_regions={ptr_src_addr: ptr_data})
        scan_com_vtable([proc], add, silent_log)
        assert result and '0x10000' in result[0]['Details'].lower()
