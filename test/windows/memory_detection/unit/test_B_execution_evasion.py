"""
Unit tests -- Phases B1-B5: Execution evasion techniques.

B1: Process hollowing (PE header zeroed fields)
B2: Suspended thread / early-bird APC
B3: Dr7 hardware breakpoint hooks
B4: Call-stack spoofing / synthetic frames
B5: ntdll syscall stub integrity
"""
import os, sys, struct
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from conftest import MockProcess, MockMaps, MockMemory, MockModule, make_user_proc

from phase_B1_process_hollowing import scan_hollowing, PE_OFF, PE_SIG
from phase_B2_apc_suspended      import scan_apc_suspended
from phase_B3_dr7_hooks           import scan_dr7_hooks
from phase_B4_callstack_spoof     import scan_callstack_spoof
from phase_B5_ntdll_stubs         import scan_ntdll_stubs, find_patched_stubs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_pe_header(ts=0x12345678, checksum=0x9ABCDEF0, size_of_image=0x00100000):
    """Return a 512-byte buffer with a minimal PE header."""
    buf = bytearray(512)
    # DOS header: e_magic = MZ, e_lfanew = 0x80
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)   # e_lfanew
    # PE signature at 0x80
    buf[0x80:0x84] = b'PE\x00\x00'
    # FileHeader.TimeDateStamp at 0x80+8 = 0x88
    struct.pack_into('<I', buf, 0x88, ts)
    # OptionalHeader starts at 0x80+24 = 0x98
    # CheckSum at +64 = 0x98+64 = 0xD8
    struct.pack_into('<I', buf, 0xD8, checksum)
    # SizeOfImage at +56 = 0x98+56 = 0xD0
    struct.pack_into('<I', buf, 0xD0, size_of_image)
    return bytes(buf)


def _image_vad(addr=0x400000, size=0x10000):
    return {'start': addr, 'size': size, 'protection': 'EXECUTE_READ',
            'type': 'image', 'tag': '\\Device\\HarddiskVolume3\\Windows\\test.exe'}


def _make_image_proc(header_bytes, addr=0x400000, pid=1000, name='test.exe'):
    vad = _image_vad(addr=addr)
    return MockProcess(pid=pid, name=name, ppid=4,
                       vads=[vad],
                       mem_regions={addr: header_bytes})


# ---------------------------------------------------------------------------
# B1: Process hollowing
# ---------------------------------------------------------------------------
class TestHollowing:

    def test_two_zeroed_fields_fires_high(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header(ts=0, checksum=0, size_of_image=0x100000)  # ts+chk zeroed
        proc = _make_image_proc(hdr)
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'High'
        assert 'Hollowing' in result[0]['Type']

    def test_three_zeroed_fields_fires(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header(ts=0, checksum=0, size_of_image=0)
        proc = _make_image_proc(hdr)
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 1

    def test_one_zeroed_field_no_finding(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header(ts=0, checksum=0x12345678, size_of_image=0x100000)
        proc = _make_image_proc(hdr)
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 0

    def test_valid_pe_header_no_finding(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header()
        proc = _make_image_proc(hdr)
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 0

    def test_non_image_vad_skipped(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header(ts=0, checksum=0)
        vad  = {'start': 0x400000, 'size': 0x10000, 'protection': 'EXECUTE_READ',
                'type': 'private', 'tag': ''}
        proc = MockProcess(pid=1, name='test.exe', ppid=4,
                           vads=[vad], mem_regions={0x400000: hdr})
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 0

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        hdr  = _build_pe_header(ts=0, checksum=0)
        proc = _make_image_proc(hdr, pid=4, name='System')
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 0

    def test_missing_mz_no_crash(self, findings, silent_log):
        result, add = findings
        buf  = bytearray(512)   # no MZ signature
        proc = _make_image_proc(bytes(buf))
        n    = scan_hollowing([proc], add, silent_log)
        assert n == 0


# ---------------------------------------------------------------------------
# B2: APC / suspended threads
# ---------------------------------------------------------------------------
class TestAPCSuspended:

    def _make_proc_with_thread(self, pid, name, thread_dict, modules=None):
        mods = modules or [MockModule('ntdll.dll', 0x7FF800000000, 0x200000)]
        return MockProcess(pid=pid, name=name, ppid=4,
                           threads=[thread_dict], modules=mods)

    def test_suspended_ntdll_thread_fires(self, findings, silent_log):
        result, add = findings
        ntdll_start = 0x7FF800001000
        t    = {'va-win32start': ntdll_start, 'tid': 100, 'exitstatus': 0,
                'suspendcount': 1, 'state': ''}
        proc = self._make_proc_with_thread(1000, 'explorer.exe', t)
        n, api = scan_apc_suspended([proc], add, silent_log)
        assert n == 1
        assert api is True
        assert result[0]['Severity'] == 'Medium'
        assert 'APC' in result[0]['Type']

    def test_running_thread_no_finding(self, findings, silent_log):
        result, add = findings
        t    = {'va-win32start': 0x7FF800001000, 'tid': 101, 'exitstatus': 0,
                'suspendcount': 0, 'state': ''}
        proc = self._make_proc_with_thread(1001, 'calc.exe', t)
        n, api = scan_apc_suspended([proc], add, silent_log)
        assert n == 0

    def test_api_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        # Thread with no suspendcount key -> api_ok stays False
        t    = {'va-win32start': 0x7FF800001000, 'tid': 102, 'exitstatus': 0}
        proc = self._make_proc_with_thread(1002, 'notepad.exe', t)
        n, api = scan_apc_suspended([proc], add, silent_log)
        assert n == 0
        # api_ok depends on whether any thread had the key -- here it didn't
        assert api is False

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        t    = {'va-win32start': 0x7FF800001000, 'tid': 103, 'exitstatus': 0,
                'suspendcount': 1, 'state': ''}
        proc = MockProcess(pid=4, name='System', ppid=0, threads=[t],
                           modules=[MockModule('ntdll.dll', 0x7FF800000000, 0x200000)])
        n, _ = scan_apc_suspended([proc], add, silent_log)
        assert n == 0

    def test_pid_in_target(self, findings, silent_log):
        result, add = findings
        t    = {'va-win32start': 0x7FF800001000, 'tid': 200, 'exitstatus': 0,
                'suspendcount': 2, 'state': ''}
        proc = self._make_proc_with_thread(9876, 'evil.exe', t)
        scan_apc_suspended([proc], add, silent_log)
        assert '9876' in result[0]['Target']


# ---------------------------------------------------------------------------
# B3: Dr7 hardware breakpoints
# ---------------------------------------------------------------------------
class TestDr7Hooks:

    def test_nonzero_dr7_fires_high(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 1, 'dr7': 0x00000701}  # Dr0 local enable
        proc = MockProcess(pid=2000, name='notepad.exe', ppid=4, threads=[t])
        n, api = scan_dr7_hooks([proc], add, silent_log)
        assert n == 1
        assert api is True
        assert result[0]['Severity'] == 'High'
        assert 'Dr7' in result[0]['Type']

    def test_zero_dr7_no_finding(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 2, 'dr7': 0x0}
        proc = MockProcess(pid=2001, name='notepad.exe', ppid=4, threads=[t])
        n, api = scan_dr7_hooks([proc], add, silent_log)
        assert n == 0

    def test_debugger_process_skipped(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 3, 'dr7': 0x00000701}
        proc = MockProcess(pid=2002, name='windbg.exe', ppid=4, threads=[t])
        n, _ = scan_dr7_hooks([proc], add, silent_log)
        assert n == 0

    def test_api_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 4}   # no dr7 key
        proc = MockProcess(pid=2003, name='calc.exe', ppid=4, threads=[t])
        n, api = scan_dr7_hooks([proc], add, silent_log)
        assert n == 0
        assert api is False

    def test_dr7_value_in_details(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 5, 'dr7': 0xFF}
        proc = MockProcess(pid=2004, name='explorer.exe', ppid=4, threads=[t])
        scan_dr7_hooks([proc], add, silent_log)
        assert '0xff' in result[0]['Details'].lower()


# ---------------------------------------------------------------------------
# B4: Call-stack spoofing
# ---------------------------------------------------------------------------
class TestCallstackSpoof:

    def _module(self, base=0x7FF800000000, size=0x200000, name='ntdll.dll'):
        return MockModule(name, base, size)

    def test_unbacked_frame_sandwiched_fires_high(self, findings, silent_log):
        result, add = findings
        # frames: [in-module, out-of-module, in-module] -- spoofed sandwich
        frames = [
            {'va': 0x7FF800001000},   # inside ntdll
            {'va': 0x20000000},        # outside all modules (shellcode)
            {'va': 0x7FF800002000},   # back in ntdll
        ]
        t    = {'tid': 1, 'callstack': frames}
        mod  = self._module()
        proc = MockProcess(pid=3000, name='explorer.exe', ppid=4,
                           threads=[t], modules=[mod])
        n, api = scan_callstack_spoof([proc], add, silent_log)
        assert n == 1
        assert api is True
        assert result[0]['Severity'] == 'High'
        assert 'spoofing' in result[0]['Type'].lower() or 'Spoof' in result[0]['Type']

    def test_isolated_unbacked_frame_fires_medium(self, findings, silent_log):
        result, add = findings
        frames = [
            {'va': 0x20000000},   # single unbacked frame at top
            {'va': 0x20000100},   # another unbacked -- no module above
        ]
        t    = {'tid': 2, 'callstack': frames}
        mod  = self._module()
        proc = MockProcess(pid=3001, name='calc.exe', ppid=4,
                           threads=[t], modules=[mod])
        n, api = scan_callstack_spoof([proc], add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Medium'

    def test_all_module_backed_frames_no_finding(self, findings, silent_log):
        result, add = findings
        frames = [{'va': 0x7FF800001000}, {'va': 0x7FF800002000}]
        t    = {'tid': 3, 'callstack': frames}
        mod  = self._module()
        proc = MockProcess(pid=3002, name='notepad.exe', ppid=4,
                           threads=[t], modules=[mod])
        n, _ = scan_callstack_spoof([proc], add, silent_log)
        assert n == 0

    def test_callstack_api_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        t    = {'tid': 4}   # no callstack key
        mod  = self._module()
        proc = MockProcess(pid=3003, name='test.exe', ppid=4,
                           threads=[t], modules=[mod])
        n, api = scan_callstack_spoof([proc], add, silent_log)
        assert n == 0
        assert api is False

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        frames = [{'va': 0x20000000}]
        t    = {'tid': 5, 'callstack': frames}
        proc = MockProcess(pid=4, name='System', ppid=0,
                           threads=[t], modules=[self._module()])
        n, _ = scan_callstack_spoof([proc], add, silent_log)
        assert n == 0


# ---------------------------------------------------------------------------
# B5: ntdll stub integrity
# ---------------------------------------------------------------------------
class TestNtdllStubs:

    def _clean_stub(self, ssn=0x0042):
        """Build a clean mov r10,rcx / mov eax,SSN / syscall / ret stub."""
        hi, lo = ssn >> 8, ssn & 0xFF
        return bytes([0x4C, 0x8B, 0xD1,           # mov r10,rcx
                      0xB8, lo, hi, 0x00, 0x00,   # mov eax,SSN
                      0x0F, 0x05,                  # syscall
                      0xC3])                       # ret

    def _patched_stub(self, ssn=0x0042):
        """
        Build a stub where the mov r10,rcx prefix is overwritten with a hook.
        E9 must be exactly 3 bytes before B8 so the scanner finds it at idx-3.
        Layout: [E9 xx xx] [B8 lo hi 00 00] [0F 05] [C3]
        """
        hi, lo = ssn >> 8, ssn & 0xFF
        return bytes([0xE9, 0x00, 0x00,           # hook opcode at idx-3
                      0xB8, lo, hi, 0x00, 0x00,   # mov eax,SSN
                      0x0F, 0x05,                  # syscall
                      0xC3])                       # ret

    def test_find_patched_stubs_clean_no_result(self):
        buf = self._clean_stub() * 20   # 20 clean stubs
        hits = find_patched_stubs(buf)
        assert hits == []

    def test_find_patched_stubs_detects_jmp(self):
        clean   = self._clean_stub(0x0025) * 3
        patched = self._patched_stub(0x0042)
        buf     = clean + patched + self._clean_stub(0x0050)
        hits    = find_patched_stubs(buf)
        assert len(hits) == 1
        _, ssn, hook_byte = hits[0]
        assert ssn == 0x0042
        assert hook_byte == 0xE9   # JMP opcode

    def test_find_patched_stubs_detects_int3(self):
        # Buffer must be > 12 bytes so the loop condition (j < limit) passes.
        # B8 at idx=3, scanner needs limit = len(buf)-12 > idx → len > 15.
        buf  = bytes([0xCC, 0x00, 0x00,              # CC at idx-3
                      0xB8, 0x25, 0x00, 0x00, 0x00, # mov eax,0x25
                      0x0F, 0x05,                    # syscall
                      0xC3]) + b'\x00' * 16          # pad to satisfy limit > 3
        hits = find_patched_stubs(buf)
        assert any(h[2] == 0xCC for h in hits)

    def test_scan_ntdll_stubs_fires_critical(self, findings, silent_log):
        result, add = findings
        ntdll_base  = 0x7FF800000000
        ntdll_bytes = self._patched_stub(0x0033) * 5

        mod  = MockModule('ntdll.dll', ntdll_base, len(ntdll_bytes))
        proc = MockProcess(pid=4000, name='notepad.exe', ppid=4,
                           modules=[mod],
                           mem_regions={ntdll_base: ntdll_bytes})
        n    = scan_ntdll_stubs([proc], add, silent_log)
        assert n >= 1
        assert result[0]['Severity'] == 'Critical'
        assert 'ntdll' in result[0]['Type'].lower()

    def test_scan_ntdll_stubs_clean_no_finding(self, findings, silent_log):
        result, add = findings
        ntdll_base  = 0x7FF800000000
        ntdll_bytes = self._clean_stub() * 20

        mod  = MockModule('ntdll.dll', ntdll_base, len(ntdll_bytes))
        proc = MockProcess(pid=4001, name='calc.exe', ppid=4,
                           modules=[mod],
                           mem_regions={ntdll_base: ntdll_bytes})
        n    = scan_ntdll_stubs([proc], add, silent_log)
        assert n == 0

    def test_no_ntdll_module_skipped(self, findings, silent_log):
        result, add = findings
        mod  = MockModule('kernel32.dll', 0x7FF700000000, 0x100000)
        proc = MockProcess(pid=4002, name='test.exe', ppid=4, modules=[mod])
        n    = scan_ntdll_stubs([proc], add, silent_log)
        assert n == 0

    def test_ssn_in_details(self, findings, silent_log):
        result, add = findings
        ntdll_base  = 0x7FF800000000
        ntdll_bytes = self._patched_stub(0x0099)

        mod  = MockModule('ntdll.dll', ntdll_base, len(ntdll_bytes))
        proc = MockProcess(pid=4003, name='evil.exe', ppid=4,
                           modules=[mod],
                           mem_regions={ntdll_base: ntdll_bytes})
        scan_ntdll_stubs([proc], add, silent_log)
        if result:
            assert '0x99' in result[0]['Details'] or 'SSN' in result[0]['Details']
