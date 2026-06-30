"""
Unit tests -- Phase A: Dormant beacon / W^X region detection (TTP-009/014).

Tests validate:
  - High-entropy private RW region fires at correct severity
  - Low-entropy region does not fire
  - EXECUTE-flagged regions are ignored (handled by section 3, not phase A)
  - Image-backed regions are ignored
  - Size out of bounds (too small, too large) does not fire
  - System processes are skipped
  - Finding count cap is respected (50 max)
"""
import os, sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from conftest import MockProcess, MockMaps, MockMemory, make_user_proc
from phase_A_dormant_beacon import scan_dormant_beacons

# ~7.9 bits/byte -- Cobalt Strike sleep-mask encrypted payload shape
RANDOM_BYTES = bytes(range(256)) * 32   # 8192 bytes, near-uniform distribution
LOW_ENT_BYTES = bytes([0x00] * 8192)    # flat zero -- entropy = 0


def _rw_vad(addr=0x10000000, size=32768, prot='READWRITE', typ='private', tag=''):
    return {'start': addr, 'size': size, 'protection': prot, 'type': typ, 'tag': tag}


def _make_proc(vad, mem_data=RANDOM_BYTES, pid=1000, name='notepad.exe'):
    return MockProcess(
        pid=pid, name=name, ppid=4,
        vads=[vad],
        mem_regions={vad['start']: mem_data},
    )


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------
class TestDormantBeaconCore:

    def test_high_entropy_rw_fires_high_for_small_region(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)           # 32 KB -- in High severity range
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 1
        assert len(result) == 1
        assert result[0]['Severity'] == 'High'
        assert 'Dormant Beacon Candidate' in result[0]['Type']

    def test_high_entropy_rw_fires_medium_for_large_region(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=512 * 1024)      # 512 KB -- above 256KB threshold -> Medium
        proc = _make_proc(vad, mem_data=RANDOM_BYTES * 64)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 1
        assert result[0]['Severity'] == 'Medium'

    def test_low_entropy_rw_no_finding(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad, mem_data=LOW_ENT_BYTES)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0
        assert len(result) == 0

    def test_details_contain_entropy_value_broken(self, findings, silent_log):
        pytest.skip('broken indexing -- correct version in TestDormantBeaconCoreFixed')


# Fix: use the fixture properly
class TestDormantBeaconCoreFixed:

    def test_details_contain_entropy_value(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad)
        scan_dormant_beacons([proc], add, silent_log)
        assert result, 'Expected at least one finding'
        assert 'entropy=' in result[0]['Details']

    def test_mitre_tag_present(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad)
        scan_dormant_beacons([proc], add, silent_log)
        assert 'T1027' in result[0]['MITRE']

    def test_pid_and_name_in_target(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad, pid=9999, name='explorer.exe')
        scan_dormant_beacons([proc], add, silent_log)
        assert '9999' in result[0]['Target']
        assert 'explorer.exe' in result[0]['Target']


# ---------------------------------------------------------------------------
# Filter: skip EXECUTE regions
# ---------------------------------------------------------------------------
class TestDormantBeaconFilters:

    def test_execute_rw_region_not_flagged(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(prot='EXECUTE_READWRITE')
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0, 'EXECUTE_READWRITE should be caught by section 3, not phase A'

    def test_image_backed_region_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(prot='READWRITE', typ='image')   # type='image' is vmmpyc convention
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_mapped_region_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(prot='READWRITE', typ='mapped')
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_too_small_region_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=512)             # below BEACON_MIN (4096)
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_too_large_region_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=4 * 1024 * 1024)   # above BEACON_MAX (2MB)
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_system_process_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        # PID 4 = System kernel process
        proc = MockProcess(pid=4, name='System', ppid=0, vads=[vad],
                           mem_regions={vad['start']: RANDOM_BYTES})
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_high_ent_proc_skipped(self, findings, silent_log):
        """MsMpEng and other known-FP processes are excluded from entropy scan."""
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = MockProcess(pid=9000, name='MsMpEng.exe', ppid=4, vads=[vad],
                           mem_regions={vad['start']: RANDOM_BYTES})
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0

    def test_readonly_region_skipped(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(prot='READONLY')
        proc = _make_proc(vad)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestDormantBeaconEdge:

    def test_empty_process_list(self, findings, silent_log):
        result, add = findings
        n = scan_dormant_beacons([], add, silent_log)
        assert n == 0

    def test_memory_read_failure_no_crash(self, findings, silent_log):
        """If memory.read raises, the scan should continue gracefully."""
        result, add = findings

        class BrokenMemory:
            def read(self, addr, size):
                raise OSError('read failed')

        vad  = _rw_vad(size=32768)
        proc = MockProcess(pid=2000, name='broken.exe', ppid=4, vads=[vad])
        proc.memory = BrokenMemory()
        n = scan_dormant_beacons([proc], add, silent_log)
        assert n == 0  # no crash, no finding

    def test_finding_cap_at_50(self, findings, silent_log):
        """Generator returns at most 50 findings even with 60 matching VADs."""
        result, add = findings
        vads = [_rw_vad(addr=0x10000000 + i * 0x10000, size=32768) for i in range(60)]
        mem  = {v['start']: RANDOM_BYTES for v in vads}
        proc = MockProcess(pid=3000, name='flood.exe', ppid=4, vads=vads, mem_regions=mem)
        n    = scan_dormant_beacons([proc], add, silent_log)
        assert n <= 50

    def test_multiple_processes_aggregate(self, findings, silent_log):
        result, add = findings
        vad  = _rw_vad(size=32768)
        p1   = _make_proc(vad, pid=1001, name='proc1.exe')
        p2   = _make_proc(vad, pid=1002, name='proc2.exe')
        n    = scan_dormant_beacons([p1, p2], add, silent_log)
        assert n == 2
        pids = {f['Target'].split()[1] for f in result}
        assert '1001' in pids
        assert '1002' in pids

    def test_byte_distrib_corroboration_in_details(self, findings, silent_log):
        """Finding details include CV%, ASCII%, MZ-remnant, AdjAnonExec, Head bytes."""
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad)
        scan_dormant_beacons([proc], add, silent_log)
        assert result, 'Expected a finding'
        d = result[0]['Details']
        assert 'CV=' in d
        assert 'ASCII=' in d
        assert 'MZ-remnant=' in d
        assert 'AdjAnonExec=' in d
        assert 'Head=' in d

    def test_adjacent_anon_exec_detected(self, findings, silent_log):
        """When a private EXECUTE region is adjacent to the beacon region, AdjAnonExec=True."""
        result, add = findings
        beacon_addr = 0x10000000
        exec_addr   = beacon_addr + 32768 + 4096  # within 64KB window
        beacon_vad = _rw_vad(addr=beacon_addr, size=32768, prot='READWRITE')
        exec_vad   = {'start': exec_addr, 'size': 4096,
                      'protection': 'EXECUTE_READ', 'type': 'private', 'tag': ''}
        proc = MockProcess(
            pid=8000, name='staged.exe', ppid=4,
            vads=[beacon_vad, exec_vad],
            mem_regions={beacon_addr: RANDOM_BYTES},
        )
        scan_dormant_beacons([proc], add, silent_log)
        assert result, 'Expected a finding'
        assert 'AdjAnonExec=True' in result[0]['Details']

    def test_no_adjacent_exec_no_flag(self, findings, silent_log):
        """Without nearby anon-exec region, AdjAnonExec=False in details."""
        result, add = findings
        vad  = _rw_vad(size=32768)
        proc = _make_proc(vad)
        scan_dormant_beacons([proc], add, silent_log)
        assert result, 'Expected a finding'
        assert 'AdjAnonExec=False' in result[0]['Details']
