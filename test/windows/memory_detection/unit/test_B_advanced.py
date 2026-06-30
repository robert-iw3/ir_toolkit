"""
Unit tests -- Phases B6-B9: Advanced evasion techniques.

B6: Ekko/Foliage thread-pool correlation
B7: EPROCESS token theft
B8: Kernel callback / ETW-Ti / pool-tag carving
B9: PEB cmdline pointer integrity
"""
import os, sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from conftest import MockProcess, MockMaps, MockMemory, MockModule, MockToken, MockVmm

from phase_B6_ekko_correlation  import scan_ekko_correlation, _high_beacon_pids
from phase_B7_token_theft        import scan_token_theft, _SE_DEBUG, _SE_TCB
from phase_B8_kernel_integrity   import scan_callback_integrity, scan_etw_ti, scan_pool_connections
from phase_B9_peb_cmdline        import scan_peb_cmdline


# ---------------------------------------------------------------------------
# B6: Ekko correlation
# ---------------------------------------------------------------------------
class TestEkkoCorrelation:

    def _make_beacon_finding(self, pid, name):
        return {
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': f'PID {pid} ({name}) @ 0x10000000',
            'Severity': 'High',
        }

    def _proc_with_ntdll_threads(self, pid, name, n_threads=3):
        ntdll_lo = 0x7FF800000000
        ntdll_hi = ntdll_lo + 0x200000
        threads  = [
            {'va-win32start': ntdll_lo + 0x1000 + i * 0x100, 'tid': i, 'exitstatus': 0}
            for i in range(n_threads)
        ]
        mods = [MockModule('ntdll.dll', ntdll_lo, ntdll_hi - ntdll_lo)]
        return MockProcess(pid=pid, name=name, ppid=4, threads=threads, modules=mods)

    def test_beacon_pid_with_pool_threads_fires_high(self, findings, silent_log):
        result, add = findings
        prior = [self._make_beacon_finding(5000, 'evil.exe')]
        proc  = self._proc_with_ntdll_threads(5000, 'evil.exe', n_threads=3)
        n     = scan_ekko_correlation([proc], add, silent_log, prior_findings=prior)
        assert n == 1
        assert result[0]['Severity'] == 'High'
        assert 'Ekko' in result[0]['Type'] or 'Thread-Pool' in result[0]['Type']

    def test_beacon_pid_one_thread_no_finding(self, findings, silent_log):
        result, add = findings
        prior = [self._make_beacon_finding(5001, 'test.exe')]
        proc  = self._proc_with_ntdll_threads(5001, 'test.exe', n_threads=1)
        n     = scan_ekko_correlation([proc], add, silent_log, prior_findings=prior)
        assert n == 0

    def test_no_prior_findings_no_finding(self, findings, silent_log):
        result, add = findings
        proc = self._proc_with_ntdll_threads(5002, 'calc.exe', n_threads=5)
        n    = scan_ekko_correlation([proc], add, silent_log, prior_findings=[])
        assert n == 0

    def test_non_beacon_pid_skipped(self, findings, silent_log):
        result, add = findings
        prior = [self._make_beacon_finding(9999, 'other.exe')]
        proc  = self._proc_with_ntdll_threads(5003, 'safe.exe', n_threads=5)
        n     = scan_ekko_correlation([proc], add, silent_log, prior_findings=prior)
        assert n == 0

    def test_beacon_pids_extraction(self):
        priors = [
            {'Type': 'Dormant Beacon Candidate (Memory)', 'Severity': 'High',
             'Target': 'PID 1234 (evil.exe) @ 0x0'},
            {'Type': 'Dormant Beacon Candidate (Memory)', 'Severity': 'Medium',
             'Target': 'PID 9999 (data.exe) @ 0x0'},
            {'Type': 'Other Finding', 'Severity': 'High', 'Target': 'PID 5678 (safe.exe)'},
        ]
        pids = _high_beacon_pids(priors)
        assert 1234 in pids          # High beacon -> included
        assert 9999 not in pids      # Medium beacon -> excluded (too large for Ekko)
        assert 5678 not in pids      # Wrong type -> excluded

    def test_thread_count_in_details(self, findings, silent_log):
        result, add = findings
        prior = [self._make_beacon_finding(5004, 'x.exe')]
        proc  = self._proc_with_ntdll_threads(5004, 'x.exe', n_threads=4)
        scan_ekko_correlation([proc], add, silent_log, prior_findings=prior)
        assert result and '4' in result[0]['Details']


# ---------------------------------------------------------------------------
# B7: Token theft
# ---------------------------------------------------------------------------
class TestTokenTheft:

    def _proc_with_token(self, pid, name, ppid=4, parent_name='explorer.exe',
                          sid='S-1-5-1', integ=0x2000, pmask=0):
        tok  = MockToken(user_sid=sid, integrity_level=integ, privileges_enabled=pmask)
        proc = MockProcess(pid=pid, name=name, ppid=ppid, token=tok)
        parent = MockProcess(pid=ppid, name=parent_name)
        pid_map = {ppid: parent}
        return proc, pid_map

    def test_system_sid_non_system_parent_fires_critical(self, findings, silent_log):
        result, add = findings
        proc, pid_map = self._proc_with_token(
            6000, 'notepad.exe', ppid=1000, parent_name='explorer.exe',
            sid='S-1-5-18', integ=0x4000, pmask=_SE_DEBUG | _SE_TCB,
        )
        n, api = scan_token_theft([proc], pid_map, add, silent_log)
        assert n == 1
        assert api is True
        assert result[0]['Severity'] == 'Critical'
        assert 'Token Theft' in result[0]['Type']

    def test_both_privs_non_system_parent_fires(self, findings, silent_log):
        result, add = findings
        proc, pid_map = self._proc_with_token(
            6001, 'calc.exe', ppid=1000, parent_name='cmd.exe',
            sid='S-1-5-1', integ=0x2000, pmask=_SE_DEBUG | _SE_TCB,
        )
        n, _ = scan_token_theft([proc], pid_map, add, silent_log)
        assert n == 1

    def test_system_parent_suppresses(self, findings, silent_log):
        result, add = findings
        proc, pid_map = self._proc_with_token(
            6002, 'dllhost.exe', ppid=676, parent_name='services.exe',
            sid='S-1-5-18', integ=0x4000, pmask=_SE_DEBUG | _SE_TCB,
        )
        n, _ = scan_token_theft([proc], pid_map, add, silent_log)
        assert n == 0, 'services.exe parent is a SYSTEM lineage -- should suppress'

    def test_normal_user_token_no_finding(self, findings, silent_log):
        result, add = findings
        proc, pid_map = self._proc_with_token(
            6003, 'notepad.exe', sid='S-1-5-1', integ=0x2000, pmask=0,
        )
        n, _ = scan_token_theft([proc], pid_map, add, silent_log)
        assert n == 0

    def test_no_token_api_degrades(self, findings, silent_log):
        result, add = findings
        proc = MockProcess(pid=6004, name='test.exe', ppid=4)
        # proc.token is None by default
        pid_map = {}
        n, api = scan_token_theft([proc], pid_map, add, silent_log)
        assert n == 0
        assert api is False

    def test_legit_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        tok  = MockToken(user_sid='S-1-5-18', integrity_level=0x4000,
                         privileges_enabled=_SE_DEBUG | _SE_TCB)
        proc = MockProcess(pid=676, name='lsass.exe', ppid=4, token=tok)
        n, _ = scan_token_theft([proc], {4: MockProcess(4, 'System')}, add, silent_log)
        assert n == 0


# ---------------------------------------------------------------------------
# B8: Kernel integrity (callback + ETW-Ti + pool carving)
# ---------------------------------------------------------------------------
class TestKernelIntegrity:

    def test_null_callback_fires_critical(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm(kdriver=[{'base': 0xFFFFF80012345000, 'size': 0x10000}],
                      kernel_attrs={'notify_callbacks': [0]})
        n, api = scan_callback_integrity(vmm, add, silent_log)
        assert api is True
        assert n == 1
        assert result[0]['Severity'] == 'Critical'
        assert 'Stripped' in result[0]['Type']

    def test_out_of_module_callback_fires_critical(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm(
            kdriver=[{'base': 0xFFFFF80012345000, 'size': 0x10000, 'name': 'nt'}],
            kernel_attrs={'notify_callbacks': [0xDEADBEEFCAFEBABE]},
        )
        n, api = scan_callback_integrity(vmm, add, silent_log)
        assert n == 1
        assert 'Redirected' in result[0]['Type']

    def test_valid_callback_no_finding(self, findings, silent_log):
        result, add = findings
        drv_base = 0xFFFFF80012345000
        vmm = MockVmm(
            kdriver=[{'base': drv_base, 'size': 0x100000, 'name': 'nt'}],
            kernel_attrs={'notify_callbacks': [drv_base + 0x5000]},
        )
        n, api = scan_callback_integrity(vmm, add, silent_log)
        assert n == 0

    def test_callback_api_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm()   # no kernel callback attr
        n, api = scan_callback_integrity(vmm, add, silent_log)
        assert n == 0
        assert api is False

    def test_etw_ti_false_fires_critical(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm(kernel_attrs={'etw_ti_state': False})
        n, api = scan_etw_ti(vmm, add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Critical'
        assert 'ETW' in result[0]['Type']

    def test_etw_ti_true_no_finding(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm(kernel_attrs={'etw_ti_state': True})
        n, api = scan_etw_ti(vmm, add, silent_log)
        assert n == 0

    def test_etw_ti_api_unavailable_degrades(self, findings, silent_log):
        result, add = findings
        vmm = MockVmm()
        n, api = scan_etw_ti(vmm, add, silent_log)
        assert api is False

    def test_pool_hidden_conn_fires_critical(self, findings, silent_log):
        """A TCPT entry not in vmm.maps.net() should fire."""
        result, add = findings
        # OS table has one connection; pool carve has an ADDITIONAL hidden one.
        os_conn = {'dst-ip': '1.2.3.4', 'dst-port': 443,
                   'src-ip': '10.0.0.5', 'src-port': 50000,
                   'state': 'ESTABLISHED', 'pid': 100}
        hidden  = {'tag': 'TCPT', 'dst-ip': '5.6.7.8', 'dst-port': 4444,
                   'src-ip': '10.0.0.5', 'src-port': 50001}

        class FakeKernel:
            pool_connections = [hidden]

        class FakeVmm:
            kernel = FakeKernel()

            class maps:
                @staticmethod
                def net():
                    return [os_conn]

        n, api = scan_pool_connections(FakeVmm(), add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Critical'
        assert 'Hidden Network' in result[0]['Type']

    def test_pool_known_conn_not_flagged(self, findings, silent_log):
        result, add = findings
        conn = {'dst-ip': '1.2.3.4', 'dst-port': 443,
                'src-ip': '10.0.0.5', 'src-port': 50000}
        carved = [{'tag': 'TCPT', 'dst-ip': '1.2.3.4', 'dst-port': 443,
                   'src-ip': '10.0.0.5', 'src-port': 50000}]

        class FakeKernel:
            pool_connections = carved

        class FakeVmm:
            kernel = FakeKernel()

            class maps:
                @staticmethod
                def net():
                    return [conn]

        n, _ = scan_pool_connections(FakeVmm(), add, silent_log)
        assert n == 0


# ---------------------------------------------------------------------------
# B9: PEB cmdline pointer
# ---------------------------------------------------------------------------
class TestPebCmdline:

    def _make_proc_with_peb(self, pid, name, peb_addr, pp_ptr, cl_buf, vad_ranges):
        """
        Build a process whose PEB chain leads to a CommandLine.Buffer.

        peb_addr: int -- base address of the PEB in process memory
        pp_ptr:   int -- value at PEB+0x20 (ProcessParameters pointer)
        cl_buf:   int -- value at ProcessParameters+0x78 (Buffer pointer)
        vad_ranges: list of (start, size) tuples that ARE valid VAD entries
        """
        import struct as _s
        mem = bytearray(0x200)
        # Write ProcessParameters pointer at PEB+0x20
        _s.pack_into('<Q', mem, 0x20, pp_ptr)
        # Simulate ProcessParameters at offset (pp_ptr - peb_addr) in same buffer,
        # or use a separate region. For simplicity: pp_ptr == peb_addr + 0x100.
        pp_off = pp_ptr - peb_addr
        if 0 <= pp_off < len(mem) - 8:
            _s.pack_into('<Q', mem, pp_off + 0x70 + 0x08, cl_buf)

        vads = [{'start': s, 'size': sz, 'protection': 'READWRITE',
                 'type': 'private', 'tag': ''} for s, sz in vad_ranges]
        return MockProcess(
            pid=pid, name=name, ppid=4,
            peb=peb_addr,
            vads=vads,
            mem_regions={peb_addr: bytes(mem)},
        )

    def test_dangling_buffer_fires_high(self, findings, silent_log):
        result, add = findings
        peb    = 0x7FF6A0000000
        pp_ptr = peb + 0x100
        cl_buf = 0x99999999  # clearly outside any VAD
        vads   = [(0x1000, 0x1000)]  # VAD nowhere near cl_buf
        proc   = self._make_proc_with_peb(7000, 'test.exe', peb, pp_ptr, cl_buf, vads)
        n, api = scan_peb_cmdline([proc], add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'High'
        assert 'PEB' in result[0]['Type']

    def test_valid_buffer_in_vad_no_finding(self, findings, silent_log):
        result, add = findings
        peb    = 0x7FF6A0000000
        pp_ptr = peb + 0x100
        cl_buf = 0x20000000  # inside the VAD below
        vads   = [(0x1F000000, 0x2000000)]  # contains cl_buf
        proc   = self._make_proc_with_peb(7001, 'safe.exe', peb, pp_ptr, cl_buf, vads)
        n, _   = scan_peb_cmdline([proc], add, silent_log)
        assert n == 0

    def test_no_peb_attr_degrades(self, findings, silent_log):
        result, add = findings
        proc = MockProcess(pid=7002, name='nopeb.exe', ppid=4)
        # peb is None by default
        n, api = scan_peb_cmdline([proc], add, silent_log)
        assert n == 0
        assert api is False

    def test_system_proc_skipped(self, findings, silent_log):
        result, add = findings
        proc = MockProcess(pid=4, name='System', ppid=0, peb=0x7FF6A0000000)
        n, _ = scan_peb_cmdline([proc], add, silent_log)
        assert n == 0
