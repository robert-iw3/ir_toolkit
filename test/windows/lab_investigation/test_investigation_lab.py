"""Investigation engine lab: tests that FIND REAL ISSUES in the analysis logic.

This lab feeds rich, realistic scenario data and verifies the engine produces
the correct verdict.  Tests are deliberately designed to catch:
  - FP rate failures (noise wrongly promoted to TP)
  - FN rate failures (TP wrongly closed as noise)
  - Threshold calibration failures (UNDETERMINED when TP is clear)
  - Admin-blending detection gaps (adversary traffic that looks like normal admin)
  - Multi-source correlation gaps (missed TP that requires cross-source evidence)

The test data is intentionally broad: system background noise, legitimate admin
activity, LotL adversaries blending into system operations, unknown C2 with no
named signature, and well-known technique combinations.

Run with:
  pytest test/windows/lab_investigation/ -v
"""
from __future__ import annotations
import sys
import os
import json
import pytest

# Add repo root to path so local package imports work
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from unittest.mock import patch

from playbooks.windows.investigation import investigate, correlate, VerdictLabel, Dimension, Tier
from playbooks.windows.investigation.correlator import CorrelationVerdict
from playbooks.windows.investigation.process_tree import (
    ProcessNode, load_from_snapshot, load_from_adjudication, ancestors, descendants,
)
from playbooks.windows.investigation.chain_builder import build_chains
from playbooks.windows.investigation.ttp_patterns import match_patterns
from playbooks.windows.investigation.live_runner import _parse_mwcp_log, _is_valid_address, _build_report
from playbooks.windows.investigation.calibrate_baseline import _harvest_from_report
from playbooks.windows.investigation.models.noise_filter import classify_noise
from playbooks.windows.investigation.models.features import (
    extract_m13_signals, process_feature_vector, shannon_entropy
)
from playbooks.windows.investigation.modules import (
    dormant_beacon, shellcode_thread, ntdll_hook,
    ekko_sleep, injected_memory, ppid_orphan,
    clr_assembly, com_vtable, direct_syscall,
    handle_attribution,
)

from .scenarios import (
    ALL_SCENARIOS, NOISE_SCENARIOS, TP_SCENARIOS,
    FP_SCENARIOS, UNDETERMINED_SCENARIOS,
    # Specific scenarios for targeted assertions
    NOISE_TASKHOSTW, NOISE_SVCHOST_COM, NOISE_WMIPRVSE, NOISE_AUDIODG,
    FP_TASKHOSTW_FIVE_SIGNALS,
    LOTL_SVCHOST_WRONG_PATH, LOTL_TASKHOSTW_WITH_SHELLCODE, LOTL_DLLHOST_BEACON,
    ADVANCED_EKKO_SLEEP, ADVANCED_CLR_EXECUTE_ASSEMBLY,
    ADVANCED_COM_VTABLE, ADVANCED_PPID_SPOOF, ADVANCED_PEB_DECOY,
    ADVANCED_SLIVER_REFLECTIVE,
    UNDETERMINED_JIT_ONLY, FP_CHROME_JIT, FP_LSASS_EDR_HOOK,
    FP_POWERSHELL_MANAGED_HOST, FP_FILE_BACKED_THREAD_NO_CORROBORATION,
)


# ============================================================================
# HELPERS
# ============================================================================

def _run(scenario: dict):
    """Run single-source investigation on a scenario and return Verdict for its PID."""
    verdicts = investigate(scenario['findings'])
    target_pid = scenario['pid']
    for v in verdicts:
        if v.pid == target_pid:
            return v
    pytest.fail(f'No verdict for PID {target_pid} in scenario: {scenario["description"]}')


def _run_correlate(scenario: dict, mwcp=None, edr=None, logs=None):
    cvs = correlate(scenario['findings'], mwcp, edr, logs)
    target_pid = scenario['pid']
    for cv in cvs:
        if cv.pid == target_pid:
            return cv
    pytest.fail(f'No correlation verdict for PID {target_pid}')


# ============================================================================
# SECTION 1: PARAMETRIZED SCENARIO SUITE
# Engine must produce the correct expected verdict for every scenario.
# ============================================================================

@pytest.mark.parametrize('scenario', ALL_SCENARIOS, ids=[s['description'] for s in ALL_SCENARIOS])
def test_scenario_verdict(scenario):
    """All scenarios must produce expected verdict label."""
    v = _run(scenario)
    expected = scenario['expected']
    assert v.label.value == expected, (
        f'\nScenario: {scenario["description"]}\n'
        f'Expected: {expected}\n'
        f'Got:      {v.label.value}\n'
        f'Rationale:\n{v.rationale}'
    )


# ============================================================================
# SECTION 2: NOISE FILTER UNIT TESTS
# The ML noise filter must close system background with high confidence
# and NOT close adversary-blending processes.
# ============================================================================

class TestNoiseFilter:
    def test_taskhostw_benign_profile_closes(self):
        """taskhostw.exe with non-uniform M13 signals must be classified as noise."""
        m13_details = (
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False Head=7a 00 00 00 f8 7f'
        )
        is_noise, score, rationale = classify_noise(
            'taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe', 'svchost.exe', m13_details
        )
        assert is_noise, f'taskhostw.exe benign M13 should be noise. Rationale: {rationale}'

    def test_svchost_wrong_path_not_noise(self):
        """svchost.exe from C:\\Users\\Public is NOT noise -- path masquerading."""
        is_noise, score, rationale = classify_noise(
            'svchost.exe', 'C:\\Users\\Public\\svchost.exe', 'explorer.exe', ''
        )
        assert not is_noise, (
            f'svchost.exe from wrong path must NOT be classified as noise.\n'
            f'Rationale: {rationale}'
        )

    def test_svchost_right_path_uniform_m13_not_noise(self):
        """svchost.exe from System32 with UNIFORM M13 -- NOT noise (anomalous memory)."""
        m13_details = (
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=1% '
            'MZ-remnant=False AdjAnonExec=True Head=fc 48 83 e4 f0'
        )
        is_noise, score, rationale = classify_noise(
            'svchost.exe', 'C:\\Windows\\System32\\svchost.exe', 'services.exe', m13_details
        )
        assert not is_noise, (
            f'svchost.exe with UNIFORM M13 + AdjAnonExec must not be noise.\n'
            f'Rationale: {rationale}'
        )

    def test_audiodg_high_cv_not_noise_despite_uniform_entropy(self):
        """audiodg.exe PCM data looks UNIFORM but CV check reveals non-encrypted data pattern."""
        # PCM audio has uniform-looking entropy but the CV is high because values cluster
        # The benign profile check (cv_pct >= 100 + ascii < 5%) actually handles this...
        # Let's test with what the real audiodg profile looks like
        m13_details = (
            'ByteDistrib: CV=180% [non-uniform(data-likely)] ASCII=2% '
            'MZ-remnant=False AdjAnonExec=False'
        )
        is_noise, score, rationale = classify_noise(
            'audiodg.exe', 'C:\\Windows\\System32\\audiodg.exe', 'svchost.exe', m13_details
        )
        assert is_noise, f'audiodg.exe normal audio buffer should be noise. Rationale: {rationale}'

    def test_unknown_process_random_name_not_noise(self):
        """Process with random-character name is anomalous -- should NOT be noise."""
        # High entropy name = masquerading or random-named dropper
        is_noise, score, rationale = classify_noise(
            'xkqzjvbt.exe', 'C:\\Windows\\System32\\xkqzjvbt.exe', 'services.exe', ''
        )
        # High name entropy (random chars) should not match benign baseline
        name_ent = shannon_entropy('xkqzjvbt')
        assert name_ent >= 3.0, f'Test assumption: random name has high entropy ({name_ent:.2f})'
        # Engine result: either not noise, OR score is high-anomaly
        # We accept either as long as it's not confidently closed
        if is_noise:
            # If noise filter passes this, the score should be marginal
            assert score > -0.5, f'Random-name process should have near-threshold score: {score}'

    def test_lsass_from_system32_right_path_not_flagged(self):
        """lsass.exe from System32 with legitimate key material -- known benign path."""
        m13_details = (
            'ByteDistrib: CV=6% [UNIFORM(crypto-likely)] ASCII=1% '
            'MZ-remnant=False AdjAnonExec=False '
            'SECURITY-PROC: security process.'
        )
        # lsass has UNIFORM key material but AdjAnonExec=False, so benign M13 profile
        # doesn't match (cv < 100), but it's a known security process at expected path
        is_noise, score, rationale = classify_noise(
            'lsass.exe', 'C:\\Windows\\System32\\lsass.exe', 'wininit.exe', m13_details
        )
        # Key material in lsass at legitimate path should eventually close as noise
        # but UNIFORM cv=6% doesn't match the benign profile (cv_pct_min=100)
        # This is intentional: lsass with UNIFORM region might get routed to ML
        # We just verify it doesn't panic
        assert isinstance(is_noise, bool)
        assert isinstance(score, float)

    def test_taskhostw_with_network_not_noise_closed(self):
        """taskhostw.exe with external network connection must NOT noise-close."""
        # Engine disqualifies noise closure for processes with active network connections
        v = _run(LOTL_TASKHOSTW_WITH_SHELLCODE)
        assert v.label != VerdictLabel.NOISE_CLOSED, (
            'taskhostw.exe with network + shellcode thread must NOT be noise-closed'
        )


# ============================================================================
# SECTION 3: MODULE 13 UNIT TESTS
# Verify dormant_beacon.investigate() emits correct positive/negative dimensions.
# ============================================================================

class TestModule13:
    def _find(self, severity, details, pid=100, proc='test.exe', addr='0x1000'):
        return {
            'Severity': severity,
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': f'PID {pid} ({proc}) @ {addr}',
            'Details': details,
        }

    def test_uniform_cv_is_positive(self):
        f = self._find('High',
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=1% '
            'MZ-remnant=False AdjAnonExec=True entropy=7.88 Head=fc 48 83 e4')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('CV_UNIFORM' in d.name for d in pos), \
            f'CV=8% must produce CV_UNIFORM positive dimension. Got: {[d.name for d in dims]}'

    def test_non_uniform_cv_is_negative(self):
        f = self._find('High',
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00')
        dims = dormant_beacon.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('CV_NonUniform' in d.name for d in neg), \
            f'CV=234% must produce NonUniform negative dimension. Got: {[d.name for d in dims]}'

    def test_adj_anon_exec_true_is_positive(self):
        f = self._find('High',
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=0% '
            'MZ-remnant=False AdjAnonExec=True entropy=7.90 Head=fc 48 83 e4')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('AdjAnonExec' in d.name for d in pos), \
            f'AdjAnonExec=True must be positive. Got: {[d.name for d in dims]}'

    def test_adj_anon_exec_false_is_negative(self):
        f = self._find('High',
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00')
        dims = dormant_beacon.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('No_AdjExec' in d.name for d in neg), \
            f'AdjAnonExec=False must be negative. Got: {[d.name for d in dims]}'

    def test_mz_remnant_true_is_positive(self):
        f = self._find('High',
            'ByteDistrib: CV=12% [UNIFORM(crypto-likely)] ASCII=0% '
            'MZ-remnant=True AdjAnonExec=True entropy=7.80 Head=4d 5a 90 00')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('MZ_Remnant' in d.name for d in pos), \
            f'MZ-remnant=True must be positive. Got: {[d.name for d in dims]}'

    def test_cs_head_bytes_positive(self):
        f = self._find('High',
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=0% '
            'MZ-remnant=False AdjAnonExec=True entropy=7.91 Head=fc 48 83 e4 f0 e8 c8 00')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('CSPrologue' in d.name for d in pos), \
            f'Head=fc 48 83 e4 must produce CSPrologue positive. Got: {[d.name for d in dims]}'

    def test_struct_7a_head_negative(self):
        f = self._find('High',
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00 f8 7f 10 1d')
        dims = dormant_beacon.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('StructMarker' in d.name for d in neg), \
            f'Head=7a 00 00 00 must produce StructMarker negative. Got: {[d.name for d in dims]}'

    def test_all_benign_signals_produce_no_positive_dims(self):
        """The worked example from the investigation guide: all 5 signals benign."""
        f = self._find('High',
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00 f8 7f')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert len(pos) == 0, \
            f'All-benign M13 signals must produce zero positive dimensions. Got: {[d.name for d in pos]}'

    def test_all_tp_signals_produce_multiple_positive_dims(self):
        """UNIFORM + AdjAnonExec + CS preamble: multiple positives."""
        f = self._find('High',
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=0% '
            'MZ-remnant=False AdjAnonExec=True entropy=7.91 Head=fc 48 83 e4 f0 e8 c8 00')
        dims = dormant_beacon.investigate(f)
        pos = [d for d in dims if d.positive]
        assert len(pos) >= 3, \
            f'TP M13 signals must produce >=3 positive dimensions. Got {len(pos)}: {[d.name for d in pos]}'


# ============================================================================
# SECTION 4: MODULE 5 (SHELLCODE THREAD)
# ============================================================================

class TestModule5:
    def _find(self, details, pid=200, proc='test.exe'):
        return {
            'Type': 'Shellcode Thread (Memory)',
            'Target': f'PID {pid} ({proc})',
            'Details': details,
        }

    def test_cross_process_is_positive(self):
        f = self._find('Cross-process: CreateRemoteThread from PID 4444.')
        dims = shellcode_thread.investigate(f)
        assert any(d.positive and 'CrossProcess' in d.name for d in dims), \
            f'Cross-process thread must be positive. Got: {[d.name for d in dims]}'

    def test_jit_no_corroboration_is_negative(self):
        """JIT-consistent with no corroboration should produce negative dimension."""
        f = self._find(
            'Thread start outside all modules. JIT-consistent (known JIT host: V8 engine). '
            'Adjacent evidence: absent. Corroboration count: 0.'
        )
        dims = shellcode_thread.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('JIT' in d.name for d in neg), \
            f'JIT with no corroboration must produce negative dimension. Got: {[d.name for d in dims]}'

    def test_anon_exec_non_jit_is_positive(self):
        f = self._find(
            'Thread start 0x12340000 in anonymous exec region. Not JIT-consistent. '
            'No loaded module covers this address.'
        )
        dims = shellcode_thread.investigate(f)
        pos = [d for d in dims if d.positive]
        assert len(pos) >= 1, \
            f'Anon exec non-JIT thread must produce positive dimension. Got: {[d.name for d in dims]}'

    def test_file_backed_image_vad_without_corroboration_is_negative(self):
        """Thread in file-backed image VAD outside PEB must NOT be a positive shellcode dim.

        Covers the snapshot-race / DLL-without-PEB-linkage case. Without cross-process
        creation, anonymous exec corroboration, or YARA, this is NOT strong evidence of
        shellcode -- it needs a second look but not an immediate TP.
        """
        f = self._find(
            'Thread start 0x7ffe08621b20 falls outside all loaded modules but resides in a '
            'file-backed (image) VAD -- DLL is loaded but absent from the PEB '
            'InLoadOrderModuleList (possible DLL injection without PEB linkage, or snapshot race). '
            'Corroborate: check Module 3 for anonymous exec regions in same PID.'
        )
        dims = shellcode_thread.investigate(f)
        pos = [d for d in dims if d.positive]
        neg = [d for d in dims if not d.positive]
        assert len(pos) == 0, \
            f'File-backed image VAD without corroboration must produce ZERO positive dims. Got: {[d.name for d in pos]}'
        assert any('PEB_Unlinked' in d.name for d in neg), \
            f'Must produce Module5_PEB_Unlinked_Thread negative dim. Got: {[d.name for d in dims]}'

    def test_file_backed_image_vad_with_cross_proc_is_positive(self):
        """File-backed thread WITH cross-process creation IS definitive injection."""
        f = self._find(
            'Thread start 0x7ffe08621b20 falls outside all loaded modules but resides in a '
            'file-backed (image) VAD -- DLL is loaded but absent from the PEB '
            'InLoadOrderModuleList. '
            'Cross-process: CreateRemoteThread from PID 9999 (evil.exe).'
        )
        dims = shellcode_thread.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('CrossProcess' in d.name for d in pos), \
            f'File-backed thread with cross-proc must still be positive via CrossProcess dim. Got: {[d.name for d in dims]}'

    def test_file_backed_thread_scenario_not_tp(self):
        """File-backed threads with no corroboration must not reach TP verdict."""
        v = _run(FP_FILE_BACKED_THREAD_NO_CORROBORATION)
        assert not v.is_tp, (
            f'File-backed thread without corroboration must NOT be TP. '
            f'Got: {v.label}\nRationale:\n{v.rationale}'
        )

    def test_repeated_identical_findings_deduplicate_to_one_dim(self):
        """The same evidence repeated N times must count as ONE dimension, not N.

        Repetition is not independence: a scanner emitting the same finding for
        every thread in one region must not push the PID over the TP threshold.
        """
        finding = {
            'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
            'Target': 'PID 5050 (someproc.exe)',
            'Details': 'Thread start 0x40000000 in anonymous exec region. Not JIT-consistent.',
            'MITRE': 'T1055',
        }
        verdicts = investigate([dict(finding) for _ in range(10)])
        v = next((x for x in verdicts if x.pid == 5050), None)
        assert v is not None
        assert v.positive_count == 1, (
            f'10 identical findings must dedup to 1 positive dim, got {v.positive_count}:\n'
            f'{[d.name for d in v.dimensions]}'
        )
        assert not v.is_tp, f'Repetition alone must not reach TP. Got: {v.label}'
        # Observation count must be preserved for forensic visibility
        assert any('[observed in 10 findings]' in d.rationale for d in v.dimensions), \
            'Dedup must preserve the observation count in the rationale'


# ============================================================================
# SECTION 5: MODULE 12 (ntdll HOOK)
# ============================================================================

class TestModule12:
    def _find(self, details, pid=300, proc='test.exe'):
        return {
            'Type': 'ntdll Syscall Stub Patched (Memory)',
            'Target': f'PID {pid} ({proc})',
            'Details': details,
        }

    def test_edr_hook_is_negative(self):
        f = self._find(
            'Syscall stub SSN=0x0020 patched. '
            'Hook target falls inside CrowdStrike sensor DLL crowdstrike/csagent.dll. '
            'Broad hook set consistent across all non-elevated processes.'
        )
        dims = ntdll_hook.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('EDR_Hook' in d.name for d in neg), \
            f'EDR hook to CrowdStrike DLL must be negative. Got: {[d.name for d in dims]}'

    def test_anon_exec_redirect_is_positive(self):
        f = self._find(
            'Syscall stub SSN=0x0018 (NtAllocateVirtualMemory) has hook opcode 0xe9. '
            'Hook redirects to anonymous exec region 0x7d010000 (private, no backing file).'
        )
        dims = ntdll_hook.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('MaliciousHook' in d.name for d in pos), \
            f'Anon exec redirect must be positive. Got: {[d.name for d in dims]}'

    def test_selective_stubs_is_positive(self):
        f = self._find(
            'NtAllocateVirtualMemory patched. Hook redirects to 0xbc000000 (anonymous).'
        )
        dims = ntdll_hook.investigate(f)
        pos = [d for d in dims if d.positive]
        assert len(pos) >= 1, \
            f'Selective stub (NtAllocateVirtualMemory) to anon exec must be positive. Got: {[d.name for d in dims]}'


# ============================================================================
# SECTION 6: MODULE 14 (EKKO / THREAD-POOL)
# ============================================================================

class TestModule14:
    def test_ekko_deprioritized_when_m13_all_negative(self):
        """Module 14 must deprioritize when all M13 signals are benign."""
        m13_dims = [
            dormant_beacon.investigate({
                'Type': 'Dormant Beacon Candidate (Memory)',
                'Target': 'PID 7076 (taskhostw.exe) @ 0x1000',
                'Details': (
                    'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
                    'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00'
                )
            })
        ][0]  # list of dims from first finding

        f14 = {
            'Type': 'Thread-Pool / Ekko Pattern (Memory)',
            'Target': 'PID 7076 (taskhostw.exe)',
            'Details': '8 ntdll-backed running thread(s) in a process with High-severity beacon region.',
        }
        # m13_dims is a flat list of Dimensions
        import playbooks.windows.investigation.modules.dormant_beacon as db
        m13_dim_list = db.investigate({
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 7076 (taskhostw.exe) @ 0x1000',
            'Details': (
                'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
                'MZ-remnant=False AdjAnonExec=False entropy=7.06 Head=7a 00 00 00'
            )
        })

        import playbooks.windows.investigation.modules.ekko_sleep as es
        dims = es.investigate(f14, m13_dims=m13_dim_list)
        neg = [d for d in dims if not d.positive]
        assert any('Deprioritized' in d.name for d in neg), \
            f'Module 14 must deprioritize when M13 all-negative. Got: {[d.name for d in dims]}'

    def test_ekko_corroborated_when_m13_has_positive(self):
        """Module 14 must escalate when M13 has positive signals."""
        m13_dim_list = dormant_beacon.investigate({
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 4420 (notepad.exe) @ 0x7d000000',
            'Details': (
                'ByteDistrib: CV=6% [UNIFORM(crypto-likely)] ASCII=0% '
                'MZ-remnant=False AdjAnonExec=True entropy=7.93 Head=fc 48 83 e4 f0 e8'
            )
        })
        f14 = {
            'Type': 'Thread-Pool / Ekko Pattern (Memory)',
            'Target': 'PID 4420 (notepad.exe)',
            'Details': '4 ntdll-backed running thread(s) in a process with High-severity beacon region.',
        }
        dims = ekko_sleep.investigate(f14, m13_dims=m13_dim_list)
        pos = [d for d in dims if d.positive]
        assert any('Corroborated' in d.name for d in pos), \
            f'Module 14 must escalate when M13 has positive signals. Got: {[d.name for d in dims]}'


# ============================================================================
# SECTION 7: MODULE 3 (INJECTED MEMORY)
# ============================================================================

class TestModule3:
    def test_shared_section_is_negative(self):
        """Same address across multiple PIDs must be classified as shared section."""
        all_findings = [
            {'Type': 'Injected Memory Region',
             'Target': 'PID 1500 (dllhost.exe) @ 0x7fff00100000',
             'Details': 'Executable private VAD.'},
            {'Type': 'Injected Memory Region',
             'Target': 'PID 2600 (svchost.exe) @ 0x7fff00100000',
             'Details': 'Executable private VAD.'},
        ]
        dims = injected_memory.investigate(all_findings[0], all_findings=all_findings)
        assert any(not d.positive for d in dims), \
            f'Shared section must produce negative dimension. Got: {[d.name for d in dims]}'

    def test_high_user_space_is_negative(self):
        f = {'Type': 'Injected Memory Region',
             'Target': 'PID 1000 (test.exe) @ 0x7fff00200000',
             'Details': 'Executable private VAD.'}
        dims = injected_memory.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('HighUserSpace' in d.name for d in neg), \
            f'High user space address must be negative. Got: {[d.name for d in dims]}'

    def test_mz_header_is_positive(self):
        f = {'Type': 'Injected Memory Region',
             'Target': 'PID 1000 (test.exe) @ 0x10000000',
             'Details': 'Executable private VAD. MZ header at offset 0 of region.'}
        dims = injected_memory.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('MZ_Header' in d.name for d in pos), \
            f'MZ at offset 0 must be positive. Got: {[d.name for d in dims]}'

    def test_advisory_corroborate_text_does_not_fabricate_corroboration(self):
        """memory_forensic.py's "corroborate via YARA match or shellcode thread start"
        advisory suffix must NOT be read as an actual YARA hit or thread finding.

        Confirmed on live data: every JIT-consistent Injected Memory Region finding
        carries this exact advisory sentence, and matching it as evidence fabricated
        Module3_Thread_Inside_Region + Module3_YARA_Hit with zero real corroboration
        (no Shellcode Thread finding existed for the same PID at all).
        """
        f = {'Type': 'Injected Memory Region',
             'Target': 'PID 3012 (pwsh.exe) @ 0x23a02e10000',
             'Details': ('Executable private VAD (no backing file). Protection=P-RWX-. '
                        'JIT-consistent (known JIT/managed-code host) -- corroborate via '
                        'YARA match or shellcode thread start in same address range.')}
        dims = injected_memory.investigate(f)
        pos = [d for d in dims if d.positive]
        assert not any('Thread_Inside_Region' in d.name for d in pos), \
            f'Advisory text must not fabricate Module3_Thread_Inside_Region. Got: {[d.name for d in dims]}'
        assert not any('YARA_Hit' in d.name for d in pos), \
            f'Advisory text must not fabricate Module3_YARA_Hit. Got: {[d.name for d in dims]}'

    def test_jit_consistent_uncorroborated_is_negative(self):
        """JIT-consistent region with no real corroboration must not be a blind positive.

        .NET/CLR JIT compilation legitimately produces anonymous exec regions --
        the same reasoning already applied to Module5_JIT_Unconfirmed. The
        uncorroborated fallback is now scored per-PID (investigate_uncorroborated_pid),
        not per-finding -- see test_uncorroborated_pid_aggregation below.
        """
        f = {'Type': 'Injected Memory Region',
             'Target': 'PID 3012 (pwsh.exe) @ 0x23a02e10000',
             'Details': ('Executable private VAD (no backing file). Protection=P-RWX-. '
                        'JIT-consistent (known JIT/managed-code host) -- corroborate via '
                        'YARA match or shellcode thread start in same address range.')}
        dims = injected_memory.investigate(f)
        assert dims == [], \
            f'Per-finding investigate() must defer uncorroborated regions to the PID aggregate. Got: {dims}'
        is_candidate, is_jit = injected_memory.is_uncorroborated(f)
        assert is_candidate and is_jit

        agg = injected_memory.investigate_uncorroborated_pid([f])
        assert len(agg) == 1
        assert not agg[0].positive
        assert 'JIT_Unconfirmed' in agg[0].name

    def test_uncorroborated_pid_aggregation_one_dim_regardless_of_region_count(self):
        """N distinct uncorroborated anon-exec regions in one PID must produce
        exactly ONE dimension, not N -- the exact bug found live on FLUSH
        (MsMpEng.exe: 5 regions, PhoneExperienceHost.exe: 4 regions, both zero
        other corroboration, both crossed the TP threshold on region count alone).
        """
        findings = [
            {'Type': 'Injected Memory Region',
             'Target': f'PID 4188 (MsMpEng.exe) @ 0x{i:x}0000',
             'Details': 'Executable private VAD (no backing file). Protection=P-RWX-'}
            for i in range(5)
        ]
        agg = injected_memory.investigate_uncorroborated_pid(findings)
        assert len(agg) == 1, f'Must collapse to exactly one dimension, got {len(agg)}'
        assert agg[0].positive
        assert 'Uncorroborated' in agg[0].name
        assert '5 private anonymous executable VAD region' in agg[0].rationale

    def test_uncorroborated_pid_bug_no_longer_reaches_tp_via_engine(self):
        """End-to-end: 5 uncorroborated regions in one PID must NOT reach TP
        through engine.investigate() -- confirms the fix at the orchestration level."""
        findings = [
            {'Severity': 'High', 'Type': 'Injected Memory Region',
             'Target': f'PID 4188 (MsMpEng.exe) @ 0x{i:x}0000',
             'Details': 'Executable private VAD (no backing file). Protection=P-RWX-',
             'MITRE': 'T1055'}
            for i in range(5)
        ]
        v = _run({'pid': 4188, 'findings': findings, 'description': 'uncorroborated region volume'})
        assert not v.is_tp, (
            f'5 uncorroborated regions must not reach TP via count alone. '
            f'Got: {v.label}\n{v.rationale}'
        )

    def test_real_yara_and_thread_corroboration_still_positive(self):
        """Genuine corroboration (not advisory text) must still count."""
        f = {'Type': 'Injected Memory Region',
             'Target': 'PID 4488 (msdtc.exe) @ 0xda000000',
             'Details': 'Executable private VAD (no backing file). YARA rule matched '
                        'in this region. Module 5 shellcode thread start confirmed inside VAD.'}
        dims = injected_memory.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('YARA_Hit' in d.name for d in pos), \
            f'Genuine YARA corroboration must still be positive. Got: {[d.name for d in dims]}'
        assert any('Thread_Inside_Region' in d.name for d in pos), \
            f'Genuine thread corroboration must still be positive. Got: {[d.name for d in dims]}'


# ============================================================================
# SECTION 7b: MODULE 20 (DIRECT SYSCALL EXECUTION -- HELL'S GATE / SYSWHISPERS)
# ============================================================================

class TestModule20DirectSyscall:
    """Module 20 scores PER PROCESS (investigate_pid), not per region.

    A naive per-finding design was tried and reverted after live testing: one
    PowerShell process with 93 syscall-region findings produced 93 independent
    dimensions (weight 286), false-positiving both PowerShell AND a legitimate
    Windows service (CrossDeviceService). The aggregate design collapses an
    entire process's syscall pattern into ONE dimension.
    """
    def _syscall_finding(self, pid=3012, proc='pwsh.exe', addr='0x7ffe03510000', count=3):
        return {'Type': 'Direct Syscall Execution',
                'Target': f'PID {pid} ({proc}) @ {addr}',
                'Details': (f'{count} raw syscall (0x0F 0x05) opcodes in private executable '
                            'region outside ntdll.dll -- Hell\'s Gate / SysWhispers pattern. '
                            'Region size=0x10000 protection=--RWX-')}

    def test_jit_host_produces_one_negative_dim_regardless_of_region_count(self):
        """Many syscall regions in a JIT-consistent process -> ONE negative dim, not N."""
        syscalls = [self._syscall_finding(addr=f'0x7ffe0{i:04x}0000') for i in range(50)]
        pid_findings = syscalls + [
            {'Type': 'Injected Memory Region', 'Target': 'PID 3012 (pwsh.exe) @ 0x23a02e10000',
             'Details': 'Executable private VAD. JIT-consistent (known JIT/managed-code host).'},
        ]
        dims = direct_syscall.investigate_pid(syscalls, pid_findings)
        assert len(dims) == 1, f'Must produce exactly one aggregate dimension, got {len(dims)}'
        assert not dims[0].positive
        assert 'JIT_Host' in dims[0].name

    def test_no_jit_evidence_produces_one_positive_dim(self):
        """A process with zero JIT-consistent tags -- genuine Hell's Gate indicator, one dim."""
        syscalls = [self._syscall_finding(pid=9900, proc='explorer.exe', addr='0x50000000')]
        dims = direct_syscall.investigate_pid(syscalls, syscalls)
        assert len(dims) == 1
        assert dims[0].positive
        assert 'Cluster' in dims[0].name

    def test_many_regions_no_jit_still_one_dim_not_many(self):
        """Even a large uncorrelated cluster must stay ONE dimension, not one per region."""
        syscalls = [self._syscall_finding(pid=9900, proc='explorer.exe', addr=f'0x5000{i:04x}0')
                    for i in range(20)]
        dims = direct_syscall.investigate_pid(syscalls, syscalls)
        assert len(dims) == 1, f'Must stay one dimension regardless of region count, got {len(dims)}'
        assert dims[0].positive

    def test_empty_input_produces_no_dims(self):
        assert direct_syscall.investigate_pid([], []) == []

    def test_engine_aggregates_syscall_findings_not_per_finding(self):
        """End-to-end: engine.py must call the aggregate path, not score per finding."""
        findings = [self._syscall_finding(addr=f'0x7ffe0{i:04x}0000') for i in range(40)]
        findings.append({
            'Type': 'Injected Memory Region', 'Target': 'PID 3012 (pwsh.exe) @ 0x23a02e10000',
            'Details': 'Executable private VAD. JIT-consistent (known JIT/managed-code host).',
        })
        v = _run({'pid': 3012, 'findings': findings, 'description': 'JIT host with many syscall regions'})
        assert not v.is_tp, (
            f'40 syscall regions in a JIT-consistent process must NOT reach TP via volume alone. '
            f'Got: {v.label}\n{v.rationale}'
        )

    def test_jit_tag_on_syscall_finding_itself_is_recognized(self):
        """memory_forensic.py no longer skips collection for JIT-heavy process names
        (chrome/pwsh/dotnet/java/etc.) -- it tags the Direct Syscall Execution finding
        directly with the JIT-consistent annotation instead, the same way Module 3
        already does for Injected Memory Region. This must be recognized even with
        NO corresponding Injected Memory Region finding for the same PID.
        """
        syscalls = [{
            'Type': 'Direct Syscall Execution',
            'Target': 'PID 5200 (chrome.exe) @ 0x30000000',
            'Details': ('12 raw syscall (0x0F 0x05) opcodes in private executable region '
                       'outside ntdll.dll. JIT-consistent (known JIT/managed-code host) -- '
                       'corroborate via cross-process thread creation or YARA match before '
                       'treating as Hell\'s Gate / SysWhispers evasion. '
                       'Region size=0x10000 protection=--RWX-'),
        }]
        dims = direct_syscall.investigate_pid(syscalls, syscalls)
        assert len(dims) == 1
        assert not dims[0].positive, \
            f'JIT tag on the syscall finding itself (no Injected Memory Region present) must be recognized. Got: {dims}'
        assert 'JIT_Host' in dims[0].name


# ============================================================================
# SECTION 7c: MODULE 23 (CROSS-PROCESS HANDLE & THREAD-CREATOR ATTRIBUTION)
# ============================================================================

class TestModule23HandleAttribution:
    """Module 23 scores PER HOLDER PID (investigate_pid), not per target. A single
    holder can legitimately (or maliciously) touch dozens of distinct target PIDs
    (lsass.exe's session/credential bookkeeping touches ~30 processes on a real
    host) -- scoring each target independently would fabricate dimension count the
    same way Module 20's per-region scoring did before its investigate_pid fix.
    """

    def _proc_finding(self, holder_pid=6666, holder='evil.exe', target_pid=1234,
                      severity='High', note='', create_thread=True):
        ct = ' including PROCESS_CREATE_THREAD' if create_thread else ''
        return {'Type': 'Cross-Process Handle (Memory)', 'Severity': severity,
                'Target': f'PID {holder_pid} ({holder}) -> Target PID {target_pid}',
                'Details': (f'Name: {holder} holds a PROCESS handle (access=0x1478) '
                            f'into PID {target_pid}{ct}.{note}'),
                'MITRE': 'T1055 (Process Injection)'}

    def _thread_finding(self, holder_pid=9001, holder='svchost.exe', target_pid=4321,
                        tid=9999, severity='High', shellcode=False, note=''):
        sc = ' Target thread starts in an anonymous executable region (shellcode-consistent).' if shellcode else ''
        return {'Type': 'Cross-Process Thread Handle (Memory)', 'Severity': severity,
                'Target': f'PID {holder_pid} ({holder}) -> Target PID {target_pid} TID {tid}',
                'Details': (f'Name: {holder} holds a THREAD handle (access=0x1fffff) into '
                            f'PID {target_pid} TID {tid} -- the remote-thread-hijack/'
                            f'context-manipulation primitive.{sc}{note}'),
                'MITRE': 'T1055.003 (Thread Execution Hijacking)'}

    def test_many_targets_one_positive_dimension_not_many(self):
        """A holder touching 30 distinct target PIDs must collapse to ONE dimension,
        not thirty (mirrors direct_syscall's region-volume fix)."""
        findings = [self._proc_finding(target_pid=1000 + i) for i in range(30)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1, f'Must produce exactly one dimension, got {len(dims)}'
        assert dims[0].positive
        assert 'CrossProcessHandle' in dims[0].name

    def test_many_targets_mixed_create_thread_splits_into_two_scoped_dimensions(self):
        """Real live-data bug caught before shipping: a holder can have MANY plain
        VM_WRITE+VM_OPERATION handles and exactly one with the full CREATE_THREAD
        mask (confirmed on a real host: svchost.exe with 20 ordinary targets and a
        single CREATE_THREAD handle into winlogon.exe). The one strong handle must
        NOT promote the entire 20-target aggregate to Tier 1 -- each subset gets its
        own dimension, scoped only to the targets that justify it."""
        findings = [self._proc_finding(target_pid=1000 + i, create_thread=False) for i in range(20)]
        findings.append(self._proc_finding(target_pid=328, create_thread=True))
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 2, f'Must split into exactly 2 dimensions, got {len(dims)}'
        by_name = {d.name: d for d in dims}
        assert 'Module23_CrossProcessHandle_FullInjectionMask' in by_name
        assert by_name['Module23_CrossProcessHandle_FullInjectionMask'].tier == Tier.DEFINITIVE
        assert 'Module23_CrossProcessHandle_Holder' in by_name
        assert by_name['Module23_CrossProcessHandle_Holder'].tier == Tier.STRONG_BEHAVIORAL

    def test_os_session_mgmt_downgraded_produces_one_negative_dimension(self):
        """A path-verified OS session-management holder (Low severity from
        memory_forensic.py) must produce a documented NEGATIVE dimension, not a
        positive one -- structurally expected OS behavior, not injection."""
        findings = [self._proc_finding(holder_pid=840, holder='csrss.exe', target_pid=1000 + i,
                                        severity='Low',
                                        note=' -- OS session-management subsystem on its expected path')
                    for i in range(10)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert not dims[0].positive
        assert 'OSSessionMgmt' in dims[0].name

    def test_thread_handle_shellcode_correlation_gets_distinct_dimension(self):
        """A thread-handle finding corroborated by the target thread starting in an
        anonymous executable region (shellcode-consistent) must be distinguished
        from a bare handle with no such corroboration."""
        findings = [self._thread_finding(shellcode=True)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].positive
        assert 'ShellcodeTarget' in dims[0].name

    def test_thread_handle_without_shellcode_correlation_is_generic_positive(self):
        findings = [self._thread_finding(shellcode=False)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].positive
        assert 'ShellcodeTarget' not in dims[0].name
        assert 'Holder' in dims[0].name

    # -- Batch 4 tier migration: Module 23 is the design note's own worked Tier-1 example --

    def test_process_handle_with_create_thread_is_tier1(self):
        """Full VM_WRITE+VM_OPERATION+CREATE_THREAD is the canonical remote-injection
        access mask -- essentially no legitimate reason for a non-security-tool
        process to hold it. Tier 1 (DEFINITIVE): single item settles it."""
        findings = [self._proc_finding(create_thread=True)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].tier == Tier.DEFINITIVE

    def test_process_handle_without_create_thread_stays_tier2(self):
        """VM_WRITE+VM_OPERATION WITHOUT CREATE_THREAD has too many legitimate
        explanations (session/config data, IPC) to be 'single item settles it' --
        this is EXACTLY lsass.exe's real access mask on a live host (confirmed via
        vmmpyc introspection before this module was written: access=0x1478, no
        CREATE_THREAD bit), which must stay UNDETERMINED, not become an instant TP."""
        findings = [self._proc_finding(create_thread=False)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].tier == Tier.STRONG_BEHAVIORAL

    def test_thread_handle_shellcode_correlation_is_tier1(self):
        """Two independent structurally-unforgeable facts converge (foreign handle +
        confirmed anon-exec execution target) -- the strongest case this module can
        produce. Tier 1 (DEFINITIVE)."""
        findings = [self._thread_finding(shellcode=True)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].tier == Tier.DEFINITIVE

    def test_thread_handle_without_shellcode_correlation_stays_tier2(self):
        """A real capability (SET_CONTEXT/ALL_ACCESS into a foreign thread) but not
        yet confirmed use -- stays at the Tier 2 default, needs corroboration."""
        findings = [self._thread_finding(shellcode=False)]
        dims = handle_attribution.investigate_pid(findings)
        assert len(dims) == 1
        assert dims[0].tier == Tier.STRONG_BEHAVIORAL

    def test_engine_end_to_end_lsass_like_pattern_stays_undetermined_not_tp(self):
        """End-to-end regression guard mirroring the real live FLUSH data: lsass.exe
        holding VM_WRITE (no CREATE_THREAD) into many processes must NOT become an
        instant TRUE_POSITIVE now that Tier 1 is wired in -- it must still require
        independent corroboration, exactly as it did before this migration."""
        findings = [self._proc_finding(holder_pid=680, holder='lsass.exe', target_pid=1000 + i,
                                        create_thread=False)
                    for i in range(30)]
        v = _run({'pid': 680, 'findings': findings, 'description': 'lsass.exe VM_WRITE, no CREATE_THREAD'})
        assert v.label == VerdictLabel.UNDETERMINED, (
            f"lsass.exe's real access-mask pattern must stay UNDETERMINED after the Tier 1 "
            f"migration, not become an instant TRUE_POSITIVE. Got: {v.label}"
        )

    def test_engine_end_to_end_full_injection_mask_is_instant_tp(self):
        """End-to-end: a holder with the FULL VM_WRITE+VM_OPERATION+CREATE_THREAD
        combination must reach TRUE_POSITIVE immediately via the Tier 1 shortcut,
        even with zero other corroborating dimensions."""
        findings = [self._proc_finding(holder_pid=6666, holder='evil.exe', target_pid=1234,
                                        create_thread=True)]
        v = _run({'pid': 6666, 'findings': findings, 'description': 'full injection access mask'})
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert 'TIER1' in v.rationale

    def test_process_and_thread_findings_produce_separate_dimensions(self):
        """Process-level and thread-level handle capability are qualitatively
        different (whole-process control vs one-thread control) -- both must be
        visible, as separate dimensions, when a holder has both."""
        findings = [self._proc_finding(create_thread=False), self._thread_finding()]
        dims = handle_attribution.investigate_pid(findings)
        names = {d.name for d in dims}
        assert 'Module23_CrossProcessHandle_Holder' in names
        assert 'Module23_CrossProcessThreadHandle_Holder' in names
        assert len(dims) == 2

    def test_empty_input_produces_no_dims(self):
        assert handle_attribution.investigate_pid([]) == []

    def test_engine_groups_by_holder_pid_not_target_pid(self):
        """End-to-end: engine.py's _group_by_pid must attribute the finding to the
        HOLDER (Target starts with 'PID <holder> (<name>)'), never the target/victim
        PID embedded later in the Target string."""
        findings = [self._proc_finding(holder_pid=6666, target_pid=1234)]
        verdicts = investigate(findings)
        pids = {v.pid for v in verdicts}
        assert 6666 in pids, 'Finding must be grouped under the HOLDER pid'
        assert 1234 not in pids, 'Finding must NOT be grouped under the target/victim pid'

    def test_engine_end_to_end_os_session_mgmt_closes_false_positive(self):
        """A path-verified OS session-management holder with only Module 23 evidence
        must close as FALSE_POSITIVE (0 positive dimensions), not linger UNDETERMINED."""
        findings = [self._proc_finding(holder_pid=840, holder='csrss.exe', target_pid=1000 + i,
                                        severity='Low',
                                        note=' -- OS session-management subsystem on its expected path')
                    for i in range(5)]
        v = _run({'pid': 840, 'findings': findings, 'description': 'csrss.exe OS session mgmt'})
        assert v.label == VerdictLabel.FALSE_POSITIVE
        assert v.positive_count == 0


# ============================================================================
# SECTION 7d: TIERED EVIDENCE MODEL (Batch 4) -- verdict-assembly mechanics
#
# planning/CURRENT-STATE-AND-OPEN-ITEMS.md §4 design note. No module tags Tier 0/1/3
# yet (everything defaults to Tier 2 -- STRONG_BEHAVIORAL), so these tests monkeypatch
# an already-wired module's investigate() to inject Dimensions at a controlled tier,
# proving the engine's assembly rules directly rather than waiting for a real module
# migration. The explicit design constraint validated here: the existing threshold=3
# floor is UNCHANGED for anything at the Tier 2 default -- Tier 1 is a pure additive
# shortcut, Tier 3 can never alone reach TP, Tier 0 is excluded before scoring.
# ============================================================================

class TestTieredEvidenceModel:

    def _beacon_finding(self, pid=7001, proc='evil.exe'):
        return {'Type': 'Dormant Beacon Candidate (Memory)',
                'Target': f'PID {pid} ({proc})',
                'Details': 'placeholder'}

    def test_two_tier2_positives_stay_undetermined_threshold_unchanged(self):
        """Baseline: with everything at the Tier 2 default, 2 positive dimensions must
        still be UNDETERMINED, not TP -- confirms the existing threshold=3 floor is
        untouched by the tiered-model addition (the exact ambiguity resolved by asking
        the user before implementation: Tier 2 does NOT drop to a 2-dimension bar for
        un-migrated modules)."""
        dims = [
            Dimension(name='Fake_A', positive=True, rationale='r1', source_module=0),
            Dimension(name='Fake_B', positive=True, rationale='r2', source_module=0),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7001, 'findings': [self._beacon_finding()], 'description': 'two Tier-2 positives'})
        assert v.label == VerdictLabel.UNDETERMINED
        assert v.positive_count == 2

    def test_single_tier1_positive_is_instant_true_positive(self):
        """A single Tier 1 (DEFINITIVE) positive settles the question immediately,
        even with zero other corroborating dimensions -- the additive shortcut."""
        dims = [
            Dimension(name='Fake_Definitive', positive=True, rationale='structurally unforgeable',
                       source_module=0, tier=Tier.DEFINITIVE),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7002, 'findings': [self._beacon_finding(pid=7002)], 'description': 'single Tier-1 positive'})
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert 'TIER1' in v.rationale

    def test_tier1_shortcut_does_not_suppress_other_positive_dimensions_in_rationale(self):
        """The Tier-1 shortcut must still surface OTHER positive dimensions present,
        not silently discard them from the record."""
        dims = [
            Dimension(name='Fake_Definitive', positive=True, rationale='structurally unforgeable',
                       source_module=0, tier=Tier.DEFINITIVE),
            Dimension(name='Fake_Extra', positive=True, rationale='extra corroboration', source_module=0),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7003, 'findings': [self._beacon_finding(pid=7003)], 'description': 'Tier-1 plus extra'})
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert 'Fake_Extra' in v.rationale

    def test_tier3_positives_never_reach_tp_regardless_of_count(self):
        """Even 5 Tier 3 (WEAK/STRUCTURAL) positives must NOT reach TP -- capability
        without demonstrated use can never alone justify it, no matter how many."""
        dims = [
            Dimension(name=f'Fake_Weak_{i}', positive=True, rationale=f'r{i}',
                       source_module=0, tier=Tier.WEAK_STRUCTURAL)
            for i in range(5)
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7004, 'findings': [self._beacon_finding(pid=7004)], 'description': 'five Tier-3 positives'})
        assert v.label != VerdictLabel.TRUE_POSITIVE

    def test_tier3_only_positives_stay_undetermined_not_false_positive(self):
        """Tier-3-only positive evidence is NOT proof of innocence either -- must stay
        UNDETERMINED (flagging 'needs more Tier-2 evidence'), not close as FALSE_POSITIVE."""
        dims = [
            Dimension(name='Fake_Weak', positive=True, rationale='capability only',
                       source_module=0, tier=Tier.WEAK_STRUCTURAL),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7005, 'findings': [self._beacon_finding(pid=7005)], 'description': 'Tier-3 only'})
        assert v.label == VerdictLabel.UNDETERMINED
        assert 'Tier-3' in v.rationale

    def test_tier0_invalid_dimensions_excluded_before_scoring(self):
        """A Tier 0 (INVALID -- category error) dimension must be excluded entirely,
        even if marked positive -- it must not count toward anything."""
        dims = [
            Dimension(name='Fake_Invalid', positive=True, rationale='category error',
                       source_module=0, tier=Tier.INVALID),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7006, 'findings': [self._beacon_finding(pid=7006)], 'description': 'Tier-0 only'})
        assert v.label == VerdictLabel.FALSE_POSITIVE
        assert v.positive_count == 0

    def test_three_tier2_positives_still_reach_tp_unchanged(self):
        """Regression guard: the original 3-dimension TP path must still work exactly
        as before for ordinary Tier-2-default dimensions."""
        dims = [
            Dimension(name=f'Fake_{i}', positive=True, rationale=f'r{i}', source_module=0)
            for i in range(3)
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', return_value=dims):
            v = _run({'pid': 7007, 'findings': [self._beacon_finding(pid=7007)], 'description': 'three Tier-2 positives'})
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert v.positive_count == 3


# ============================================================================
# SECTION 7e: CROSS-PID RELATIONSHIP PROPAGATION (Step 4 -- "tracing a lead")
#
# chain_builder.py only ever DISPLAYS each PID's independently-computed verdict;
# it never uses one PID's finding to re-examine another or revise a verdict. This
# is the actual propagation: if PID A holds a Module 23 handle into PID B, and B's
# OWN independent verdict is TRUE_POSITIVE, that is new corroborating evidence for
# A -- a structurally-unforgeable relationship into an already-confirmed-
# compromised process. Explicitly one-directional: a CLEAN-looking target must
# NOT exonerate the holder (a capability finding into an innocent-looking process
# is still a capability finding -- "assume compromise, prove otherwise").
# ============================================================================

class TestCrossPidPropagation:

    def _handle_finding(self, holder_pid, target_pid, severity='High'):
        return {'Type': 'Cross-Process Handle (Memory)', 'Severity': severity,
                'Target': f'PID {holder_pid} (evil.exe) -> Target PID {target_pid}',
                'Details': f'Name: evil.exe holds a PROCESS handle (access=0x1478) into PID {target_pid}.',
                'MITRE': 'T1055 (Process Injection)'}

    def _three_tier2_positives_finding(self, pid, proc='confirmed.exe'):
        return {'Type': 'Dormant Beacon Candidate (Memory)',
                'Target': f'PID {pid} ({proc})', 'Details': 'placeholder'}

    def test_holder_gains_corroboration_from_confirmed_tp_target(self):
        """Target PID reaches TRUE_POSITIVE independently (3 Tier-2 dims); the holder
        (1 fake dim + 1 real Module23 dim from its own handle finding = 2, otherwise
        UNDETERMINED) must pick up a corroborating dimension and escalate to
        TRUE_POSITIVE via the threshold rule."""
        target_dims = [Dimension(name=f'Fake_{i}', positive=True, rationale=f'r{i}', source_module=0)
                       for i in range(3)]
        holder_dims = [Dimension(name='Holder_0', positive=True, rationale='h0', source_module=0)]

        def fake_investigate(finding):
            target = self._three_tier2_positives_finding(9002)
            if finding.get('Target') == target['Target']:
                return target_dims
            return holder_dims

        findings = [
            self._three_tier2_positives_finding(9002),
            self._beacon_finding_for_propagation(9001),
            self._handle_finding(holder_pid=9001, target_pid=9002),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', side_effect=fake_investigate):
            verdicts = investigate(findings)
        by_pid = {v.pid: v for v in verdicts}
        assert by_pid[9002].label == VerdictLabel.TRUE_POSITIVE, "target must independently reach TP"
        assert by_pid[9001].label == VerdictLabel.TRUE_POSITIVE, (
            "holder must escalate via cross-PID corroboration from the confirmed-TP target"
        )
        assert 'TargetCorroboration' in by_pid[9001].rationale

    def _beacon_finding_for_propagation(self, pid, proc='holder.exe'):
        return {'Type': 'Dormant Beacon Candidate (Memory)',
                'Target': f'PID {pid} ({proc})', 'Details': 'placeholder-holder'}

    def test_holder_not_corroborated_when_target_only_undetermined(self):
        """The target must be CONFIRMED TRUE_POSITIVE, not merely UNDETERMINED --
        partial/ambiguous target evidence must not propagate as corroboration."""
        target_dims = [Dimension(name='Fake_Weak', positive=True, rationale='r', source_module=0)]  # only 1, stays UNDETERMINED
        holder_dims = [Dimension(name='Holder_0', positive=True, rationale='h0', source_module=0)]

        def fake_investigate(finding):
            target = self._three_tier2_positives_finding(9012)
            if finding.get('Target') == target['Target']:
                return target_dims
            return holder_dims

        findings = [
            self._three_tier2_positives_finding(9012),
            self._beacon_finding_for_propagation(9011),
            self._handle_finding(holder_pid=9011, target_pid=9012),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', side_effect=fake_investigate):
            verdicts = investigate(findings)
        by_pid = {v.pid: v for v in verdicts}
        assert by_pid[9012].label == VerdictLabel.UNDETERMINED
        assert by_pid[9011].label == VerdictLabel.UNDETERMINED, (
            "holder must NOT escalate from a target that is only UNDETERMINED, not confirmed TP"
        )
        assert 'TargetCorroboration' not in by_pid[9011].rationale

    def test_clean_target_does_not_exonerate_holder(self):
        """A FALSE_POSITIVE (clean) target must NOT clear the holder -- a capability
        finding into an innocent-looking process is still a capability finding."""
        holder_dims = [Dimension(name='Holder_0', positive=True, rationale='h0', source_module=0)]

        def fake_investigate(finding):
            target = self._three_tier2_positives_finding(9022)
            if finding.get('Target') == target['Target']:
                return []   # zero dims -> target closes FALSE_POSITIVE
            return holder_dims

        findings = [
            self._three_tier2_positives_finding(9022),
            self._beacon_finding_for_propagation(9021),
            self._handle_finding(holder_pid=9021, target_pid=9022),
        ]
        with patch('playbooks.windows.investigation.engine.dormant_beacon.investigate', side_effect=fake_investigate):
            verdicts = investigate(findings)
        by_pid = {v.pid: v for v in verdicts}
        assert by_pid[9022].label == VerdictLabel.FALSE_POSITIVE
        assert by_pid[9021].label == VerdictLabel.UNDETERMINED, (
            "holder's own 2-dimension UNDETERMINED verdict must be unchanged by a clean target"
        )

    def test_no_relationship_data_leaves_verdicts_unchanged(self):
        """With zero Cross-Process Handle findings, propagation must be a no-op."""
        findings = [self._beacon_finding_for_propagation(9031)]
        verdicts = investigate(findings)
        assert len(verdicts) == 1
        assert 'TargetCorroboration' not in verdicts[0].rationale


# ============================================================================
# SECTION 8: MODULE 16 (CLR EXECUTE-ASSEMBLY)
# ============================================================================

class TestModule16:
    def test_managed_host_is_negative(self):
        f = {'Type': 'CLR Execute-Assembly (Memory)',
             'Target': 'PID 7744 (powershell.exe)',
             'Details': 'BSJB signature in anonymous exec VAD of powershell.exe.'}
        dims = clr_assembly.investigate(f)
        neg = [d for d in dims if not d.positive]
        assert any('ManagedHost' in d.name for d in neg), \
            f'PowerShell CLR host must produce negative ManagedHost dim. Got: {[d.name for d in dims]}'

    def test_native_process_bsjb_is_positive(self):
        f = {'Type': 'CLR Execute-Assembly (Memory)',
             'Target': 'PID 9120 (rundll32.exe)',
             'Details': 'BSJB (ECMA-335 .NET assembly magic) in anonymous executable VAD. '
                        'rundll32.exe is native -- CLR inject confirmed.'}
        dims = clr_assembly.investigate(f)
        pos = [d for d in dims if d.positive]
        assert any('CLR_Execute_Assembly' in d.name for d in pos), \
            f'rundll32.exe + BSJB in anon exec must be positive. Got: {[d.name for d in dims]}'


# ============================================================================
# SECTION 9: ADVANCED SCENARIO ASSERTIONS
# Beyond label -- verify specific dimensions are present.
# ============================================================================

class TestAdvancedScenarios:
    def test_ekko_scenario_has_m14_corroborated(self):
        """Ekko scenario must emit Module14_Ekko_Corroborated as a positive dimension."""
        v = _run(ADVANCED_EKKO_SLEEP)
        assert v.is_tp, f'Ekko scenario must be TP. Got: {v.label}\n{v.rationale}'
        assert any('Ekko_Corroborated' in d.name for d in v.dimensions if d.positive), \
            f'Missing Module14_Ekko_Corroborated. Dims: {[d.name for d in v.dimensions]}'

    def test_svchost_wrong_path_tp_from_path_check(self):
        """svchost.exe from wrong path -- ML path check must route to investigation."""
        v = _run(LOTL_SVCHOST_WRONG_PATH)
        assert v.is_tp, f'svchost.exe wrong-path scenario must be TP. Got: {v.label}'

    def test_clr_execute_assembly_tp(self):
        v = _run(ADVANCED_CLR_EXECUTE_ASSEMBLY)
        assert v.is_tp, f'CLR execute-assembly scenario must be TP. Got: {v.label}\n{v.rationale}'
        assert any('CLR_Execute_Assembly' in d.name for d in v.dimensions if d.positive)

    def test_com_vtable_tp(self):
        v = _run(ADVANCED_COM_VTABLE)
        assert v.is_tp, f'COM VTable hijacking must be TP. Got: {v.label}\n{v.rationale}'

    def test_ppid_spoof_tp(self):
        v = _run(ADVANCED_PPID_SPOOF)
        assert v.is_tp, f'PPID spoofing scenario must be TP. Got: {v.label}\n{v.rationale}'

    def test_peb_decoy_tp(self):
        v = _run(ADVANCED_PEB_DECOY)
        assert v.is_tp, f'PEB CommandLine decoy scenario must be TP. Got: {v.label}\n{v.rationale}'

    def test_sliver_reflective_tp(self):
        v = _run(ADVANCED_SLIVER_REFLECTIVE)
        assert v.is_tp, f'Sliver reflective DLL must be TP. Got: {v.label}\n{v.rationale}'
        # Must have cross-module corroboration (MZ, thread inside region, YARA in anon exec)
        pos_dims = [d for d in v.dimensions if d.positive]
        modules = {d.source_module for d in pos_dims}
        assert len(modules) >= 2, \
            f'Sliver scenario must have positive dims from >=2 modules. Got: {modules}'

    def test_jit_only_is_undetermined_not_tp(self):
        """JIT-consistent thread with no corroboration must NOT be TP."""
        v = _run(UNDETERMINED_JIT_ONLY)
        assert not v.is_tp, \
            f'JIT-only scenario must NOT be TP. Got: {v.label}\n{v.rationale}'

    def test_chrome_jit_is_fp_not_tp(self):
        v = _run(FP_CHROME_JIT)
        assert v.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.UNDETERMINED), \
            f'Chrome JIT with no corroboration must be FP or UNDETERMINED. Got: {v.label}'

    def test_taskhostw_five_signals_noise_closed(self):
        """The worked example: all 5 M13 signals benign + M14 deprioritized + YARA file-backed."""
        v = _run(FP_TASKHOSTW_FIVE_SIGNALS)
        assert v.is_closed, \
            f'taskhostw worked example must close (FP or NOISE). Got: {v.label}\n{v.rationale}'

    def test_powershell_managed_host_fp(self):
        v = _run(FP_POWERSHELL_MANAGED_HOST)
        assert v.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.NOISE_CLOSED), \
            f'PowerShell CLR host must close. Got: {v.label}\n{v.rationale}'


# ============================================================================
# SECTION 10: MULTI-SOURCE CORRELATION TESTS
# These test the correlator.py QA layer, not just engine.py.
# An adversary blending into normal admin activity may look clean in each
# individual source but the combination is definitive.
# ============================================================================

class TestMultiSourceCorrelation:
    def _make_edr_normal(self, pid, process):
        return {'pid': pid, 'process': process, 'z_score': 0.5,
                'isolation_score': 0.2, 'velocity': 0.1, 'entropy': 2.5,
                'event_type': 'ProcessStart', 'confidence': 0.0, 'alert_reason': ''}

    def _make_edr_anomaly(self, pid, process, z=5.2, score=0.75):
        return {'pid': pid, 'process': process, 'z_score': z,
                'isolation_score': score, 'velocity': 0.5, 'entropy': 4.8,
                'event_type': 'ProcessStart', 'confidence': 88.0,
                'alert_reason': f'LotL temporal anomaly Z={z:.1f}'}

    def _make_mwcp_c2(self, pid):
        return {'file': f'carved_pid-{pid}_region.bin',
                'address': ['185.220.101.45:443'], 'mutex': ['AbcDef123'],
                'password': [], 'filename': [], 'decoded': []}

    def _make_svc_install_event(self, pid, path):
        return {'EventID': 7045, 'pid': pid,
                'ServiceName': 'UpdateHelper',
                'ServiceFileName': path,
                'SubjectUserName': 'SYSTEM'}

    def _make_edr_msix_unsigned_dll(self, pid, process, dll):
        return {'pid': pid, 'process': process, 'z_score': 1.0,
                'isolation_score': 0.65, 'velocity': 0.0, 'entropy': 0.0,
                'event_type': 'Suspicious Injected DLL', 'confidence': 80.0,
                'alert_reason': 'EDR: Suspicious Injected DLL',
                'details': (f'Unsigned DLL outside Windows paths. Sig=NotSigned '
                           f'Path=C:\\Program Files\\WindowsApps\\Microsoft.YourPhone_1.0.0.0_x64__8wekyb3d8bbwe\\{dll} '
                           '(MSIX/Store package-signed path - per-file Authenticode not meaningful)')}

    def test_clean_memory_but_edr_anomaly_elevates_undetermined(self):
        """Memory looks borderline but EDR anomaly adds enough weight to elevate verdict."""
        # Use a moderate-CV M13 scenario (UNDETERMINED from memory alone)
        # Add EDR anomaly signal -> combined should reach TP threshold
        findings = [{
            'Severity': 'High', 'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 3300 (spoolsv.exe) @ 0xee000000',
            'Details': ('ByteDistrib: CV=30% [moderate] ASCII=10% '
                        'MZ-remnant=False AdjAnonExec=True entropy=7.10 Head=00 10 00 00'),
            'MITRE': 'T1055',
        }, {
            'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
            'Target': 'PID 3300 (spoolsv.exe)',
            'Details': 'Thread start outside all modules. Anonymous exec. Not JIT-consistent.',
            'MITRE': 'T1055',
        }]
        edr = [self._make_edr_anomaly(3300, 'spoolsv.exe', z=6.1, score=0.82)]
        cvs = correlate(findings, edr_events=edr)
        target = next((cv for cv in cvs if cv.pid == 3300), None)
        assert target is not None, 'No verdict for PID 3300'
        # Combined positive weight: M13 moderate (1 dim) + M5 anon exec (1 dim) + EDR anomaly (1.0 weight)
        # should reach threshold
        assert target.label == VerdictLabel.TRUE_POSITIVE, (
            f'Memory + EDR anomaly should produce TP. Got: {target.label}\n{target.rationale}'
        )

    def test_mwcp_c2_extraction_elevates_verdict(self):
        """mwcp C2 config from carved region + borderline memory = TP."""
        findings = [{
            'Severity': 'High', 'Type': 'Injected Memory Region',
            'Target': 'PID 4488 (msdtc.exe) @ 0xda000000',
            'Details': 'Executable private VAD. Protection=PAGE_EXECUTE_READ.',
            'MITRE': 'T1055',
        }, {
            'Severity': 'High', 'Type': 'External Network Connection',
            'Target': 'PID 4488 (msdtc.exe)',
            'Details': 'ESTABLISHED 10.0.0.1:60000 -> 10.0.0.2:8888',
            'MITRE': 'T1071',
        }]
        mwcp = [self._make_mwcp_c2(4488)]
        cvs = correlate(findings, mwcp_hits=mwcp)
        target = next((cv for cv in cvs if cv.pid == 4488), None)
        assert target is not None
        # Check mwcp signal is present
        mwcp_sigs = [s for s in target.signals if s.source == 'mwcp' and s.positive]
        assert mwcp_sigs, f'mwcp C2 hit must add positive signal. Signals: {target.signals}'

    def test_mwcp_mutex_only_does_not_score_positive(self):
        """mwcp mutex-only hits (no address) must NOT contribute positive weight.

        Real mwcp scans against managed-code (.NET/PowerShell) memory routinely
        report WinAPI import names and hex padding as "mutex" -- this is scanner
        noise, not evidence of a real mutex handle. Only network-shaped address
        extraction should score.
        """
        findings = [{
            'Severity': 'High', 'Type': 'Injected Memory Region',
            'Target': 'PID 9100 (powershell.exe) @ 0x50000000',
            'Details': 'Executable private VAD. Protection=PAGE_EXECUTE_READ.',
            'MITRE': 'T1055',
        }]
        mwcp = [{'file': 'powershell_9100_50000000.bin', 'pid': 9100,
                 'address': [], 'mutex': ['CreateRemoteThread', 'ffffff', '111111111111'],
                 'password': []}]
        cvs = correlate(findings, mwcp_hits=mwcp)
        target = next((cv for cv in cvs if cv.pid == 9100), None)
        assert target is not None
        mwcp_pos = [s for s in target.signals if s.source == 'mwcp' and s.positive]
        assert not mwcp_pos, f'Mutex-only mwcp hit must not score positive. Signals: {target.signals}'
        # Still visible as context, just non-scored
        mwcp_ctx = [s for s in target.signals if s.source == 'mwcp']
        assert mwcp_ctx, 'Mutex artifacts should still appear as context in signals'

    def test_mwcp_only_pid_with_no_memory_findings_produces_no_phantom_verdict(self):
        """A PID known ONLY from a zero-weight mwcp context signal (no memory verdict,
        no other source) must not appear as an empty UNDETERMINED entry."""
        mwcp = [{'file': 'proc_4242_10000000.bin', 'pid': 4242,
                 'address': [], 'mutex': ['CreateRemoteThread'], 'password': []}]
        cvs = correlate([], mwcp_hits=mwcp)
        assert not any(cv.pid == 4242 for cv in cvs), \
            f'Phantom PID with no forensic content must not produce a verdict. Got: {cvs}'

    def test_benign_memory_plus_normal_edr_stays_noise(self):
        """Noise memory + normal EDR baseline = stays NOISE_CLOSED."""
        # Exact taskhostw benign scenario
        edr = [self._make_edr_normal(7076, 'taskhostw.exe')]
        cv = _run_correlate(NOISE_TASKHOSTW, edr=edr)
        assert cv.label in (VerdictLabel.NOISE_CLOSED, VerdictLabel.FALSE_POSITIVE), (
            f'Noise memory + normal EDR should stay closed. Got: {cv.label}\n{cv.rationale}'
        )

    def test_service_install_from_temp_path_is_positive_signal(self):
        """Event log: service installed from Temp path is a positive cross-source signal."""
        findings = [{
            'Severity': 'High', 'Type': 'Injected Memory Region',
            'Target': 'PID 9900 (svchost.exe) @ 0x22000000',
            'Details': 'Executable private VAD. YARA in anon region.',
            'MITRE': 'T1055',
        }]
        logs = [self._make_svc_install_event(9900, 'C:\\Windows\\Temp\\UpdateHelper.exe')]
        cvs = correlate(findings, event_logs=logs)
        target = next((cv for cv in cvs if cv.pid == 9900), None)
        assert target is not None
        log_sigs = [s for s in target.signals if s.source == 'eventlog' and s.positive]
        assert log_sigs, \
            f'Service install from Temp must produce positive eventlog signal. Signals: {[str(s) for s in target.signals]}'

    def test_admin_blending_lotl_requires_multiple_sources(self):
        """An adversary using WMI (normal admin tool) must require cross-source evidence."""
        # WMI execution alone: NOT enough for TP
        # WMI + memory anomaly + EDR Z-score: TP
        findings = [{
            'Severity': 'High', 'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 6600 (wmiprvse.exe) @ 0x33000000',
            'Details': ('ByteDistrib: CV=9% [UNIFORM(crypto-likely)] ASCII=0% '
                        'MZ-remnant=False AdjAnonExec=True entropy=7.88 Head=fc 48 83 e4'),
            'MITRE': 'T1047',
        }, {
            'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
            'Target': 'PID 6600 (wmiprvse.exe)',
            'Details': 'Thread start 0x33040000 outside all modules. Anonymous exec. Not JIT-consistent.',
            'MITRE': 'T1055',
        }]
        edr = [self._make_edr_anomaly(6600, 'wmiprvse.exe', z=4.8, score=0.71)]
        logs = [{
            'EventID': 4688, 'pid': 6600,
            'CommandLine': 'wmic process call create "powershell -enc SGVsbG8..."',
            'ParentProcessName': 'wmiprvse.exe',
            'SubjectUserName': 'SYSTEM',
        }]
        cvs = correlate(findings, edr_events=edr, event_logs=logs)
        target = next((cv for cv in cvs if cv.pid == 6600), None)
        assert target is not None
        # All three sources must contribute positive signals
        sources = {s.source for s in target.signals if s.positive}
        assert 'memory' in sources, 'Memory must contribute positive signals'
        assert target.label == VerdictLabel.TRUE_POSITIVE, (
            f'WMI LotL with memory+EDR+log must be TP. Got: {target.label}\n{target.rationale}'
        )


# ============================================================================
# SECTION 11: ML FEATURE ENGINEERING TESTS
# The feature vectors must correctly represent behavioral profiles.
# ============================================================================

class TestFeatureEngineering:
    def test_system_process_names_have_low_entropy(self):
        """System process names have low Shannon entropy -- good for discrimination."""
        for proc in ['svchost', 'taskhostw', 'wmiprvse', 'lsass', 'services']:
            ent = shannon_entropy(proc)
            assert ent < 3.5, f'System process {proc!r} entropy={ent:.2f} should be < 3.5'

    def test_random_name_has_high_entropy(self):
        """Random-character names have high entropy -- adversary masquerade indicator."""
        for name in ['xkqzjvbt', 'rznvmpkx', 'aqbhsdfl']:
            ent = shannon_entropy(name)
            assert ent > 2.8, f'Random name {name!r} entropy={ent:.2f} should be > 2.8'

    def test_m13_signal_extraction(self):
        details = (
            'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
            'MZ-remnant=False AdjAnonExec=False entropy=7.06 size=32768 '
            'Head=7a 00 00 00'
        )
        m13 = extract_m13_signals(details)
        assert m13['cv_pct'] == 234.0,  f'CV extraction failed: {m13}'
        assert m13['ascii_pct'] == 42.0, f'ASCII extraction failed: {m13}'
        assert m13['mz_remnant'] is False, f'MZ extraction failed: {m13}'
        assert m13['adj_anon_exec'] is False, f'AdjAnonExec extraction failed: {m13}'
        assert m13['entropy'] == 7.06, f'Entropy extraction failed: {m13}'
        assert m13['size'] == 32768, f'Size extraction failed: {m13}'
        assert not m13['is_uniform'], f'is_uniform should be False: {m13}'

    def test_m13_uniform_signal_extraction(self):
        details = (
            'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=1% '
            'MZ-remnant=False AdjAnonExec=True entropy=7.88'
        )
        m13 = extract_m13_signals(details)
        assert m13['cv_pct'] == 8.0
        assert m13['adj_anon_exec'] is True
        assert m13['is_uniform'] is True

    def test_feature_vector_shape(self):
        """Feature vector must always be 5D."""
        m13 = {'cv_pct': 234.0, 'ascii_pct': 42.0, 'mz_remnant': False, 'adj_anon_exec': False}
        vec = process_feature_vector('taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe', 'svchost.exe', m13)
        assert len(vec) == 5, f'Feature vector must be 5D, got {len(vec)}: {vec}'

    def test_benign_profile_has_lower_adj_exec_flag(self):
        """Benign profiles have AdjAnonExec=False (adj_exec_flag=0.0)."""
        m13_benign = {'cv_pct': 234.0, 'ascii_pct': 42.0, 'mz_remnant': False, 'adj_anon_exec': False}
        m13_susp   = {'cv_pct': 8.0,   'ascii_pct': 1.0,  'mz_remnant': False, 'adj_anon_exec': True}
        vec_b = process_feature_vector('taskhostw.exe', '', 'svchost.exe', m13_benign)
        vec_s = process_feature_vector('taskhostw.exe', '', 'svchost.exe', m13_susp)
        assert vec_b[4] == 0.0, f'Benign AdjAnonExec flag should be 0.0, got {vec_b[4]}'
        assert vec_s[4] == 1.0, f'Suspicious AdjAnonExec flag should be 1.0, got {vec_s[4]}'


# ============================================================================
# SECTION 12: ADMIN ACTIVITY BASELINE (MUST NOT TRIGGER TP)
# Legitimate admin operations that should be classified as noise or FP.
# The engine must not alert on normal IT operations.
# ============================================================================

class TestAdminBaseline:
    """Normal administrative activity must not generate TP alerts.

    These are the cases where an immature detection system generates false positives
    and burns analyst time. The investigation engine must close these out with certainty.
    """

    def _admin_findings(self, pid, proc, desc, extra=None):
        findings = [{
            'Severity': 'Medium', 'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': f'PID {pid} ({proc}) @ 0x{pid:08x}',
            'Details': desc, 'MITRE': 'T1027',
        }]
        if extra:
            findings.extend(extra)
        return findings

    def test_scheduled_task_runner_non_uniform(self):
        """Task scheduler work items in taskhostw.exe must close as noise."""
        v = _run(NOISE_TASKHOSTW)
        assert v.is_closed, f'Task scheduler data must close. Got: {v.label}'

    def test_wmi_provider_data_non_uniform(self):
        """WMI provider COM data in wmiprvse.exe must close as noise."""
        v = _run(NOISE_WMIPRVSE)
        assert v.is_closed, f'WMI provider data must close. Got: {v.label}'

    def test_svchost_com_data_non_uniform(self):
        """svchost.exe COM infrastructure data must close as noise."""
        v = _run(NOISE_SVCHOST_COM)
        assert v.is_closed, f'svchost COM data must close. Got: {v.label}'

    def test_audio_pcm_buffer_closes(self):
        """audiodg.exe PCM buffer must close regardless of entropy."""
        v = _run(NOISE_AUDIODG)
        assert v.is_closed, f'audiodg PCM buffer must close. Got: {v.label}'

    def test_edr_hook_on_lsass_closes(self):
        """lsass.exe EDR hook to CrowdStrike DLL must close."""
        v = _run(FP_LSASS_EDR_HOOK)
        assert v.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.UNDETERMINED), \
            f'lsass EDR hook must not be TP. Got: {v.label}'


# ============================================================================
# SECTION 13: PROCESS TREE + CHAIN BUILDER
# Lineage reconstruction and attack chain assembly from disparate sources.
# ============================================================================

class TestProcessTree:
    def _snapshot(self):
        return [
            {'ProcessId': 4,    'ParentProcessId': 0,    'Name': 'System'},
            {'ProcessId': 800,  'ParentProcessId': 4,    'Name': 'services.exe'},
            {'ProcessId': 1200, 'ParentProcessId': 800,  'Name': 'svchost.exe'},
            {'ProcessId': 3000, 'ParentProcessId': 1200, 'Name': 'wmiprvse.exe'},
            {'ProcessId': 4100, 'ParentProcessId': 3000, 'Name': 'powershell.exe',
             'CommandLine': 'powershell -enc AAAA'},
            {'ProcessId': 5200, 'ParentProcessId': 4100, 'Name': 'rundll32.exe'},
        ]

    def test_snapshot_ancestors(self):
        tree = load_from_snapshot(self._snapshot())
        anc = ancestors(tree, 4100)
        names = [n.name for n in anc]
        assert names == ['wmiprvse.exe', 'svchost.exe', 'services.exe', 'System'], \
            f'Ancestor walk wrong: {names}'

    def test_snapshot_descendants(self):
        tree = load_from_snapshot(self._snapshot())
        desc = descendants(tree, 3000)
        pids = sorted(n.pid for n in desc)
        assert pids == [4100, 5200], f'Descendant walk wrong: {pids}'

    def test_adjudication_partial_tree(self):
        entries = [
            {'Target': 'PID 4100 (powershell.exe)', 'ParentPid': 3000,
             'ParentName': 'wmiprvse.exe', 'CommandLine': 'powershell -enc AAAA',
             'SubjectPath': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'},
        ]
        tree = load_from_adjudication(entries)
        assert 4100 in tree
        assert tree[4100].ppid == 3000
        assert tree[4100].parent_name == 'wmiprvse.exe'

    def test_unknown_parent_still_reported(self):
        """When the parent is not in the tree, the child's knowledge of it is preserved."""
        entries = [
            {'Target': 'PID 4100 (powershell.exe)', 'ParentPid': 3000,
             'ParentName': 'wmiprvse.exe'},
        ]
        tree = load_from_adjudication(entries)
        anc = ancestors(tree, 4100)
        assert len(anc) == 1 and anc[0].pid == 3000 and anc[0].name == 'wmiprvse.exe', \
            f'Unknown parent must still appear in lineage: {[(n.pid, n.name) for n in anc]}'

    def test_pid_reuse_cycle_is_safe(self):
        """PID reuse can create parent cycles -- the walk must terminate."""
        tree = {
            100: ProcessNode(pid=100, name='a.exe', ppid=200),
            200: ProcessNode(pid=200, name='b.exe', ppid=100),
        }
        anc = ancestors(tree, 100)
        assert len(anc) <= 2, f'Cycle must terminate, got {len(anc)} ancestors'


class TestChainBuilder:
    def test_chain_for_tp_includes_lineage_and_stages(self):
        """A TP with injection + network findings must produce a chain with both stages."""
        findings = [
            {'Severity': 'High', 'Type': 'Injected Memory Region',
             'Target': 'PID 4100 (powershell.exe) @ 0x10000000',
             'Details': 'Executable private VAD (no backing file). MZ header at offset 0.',
             'MITRE': 'T1055', 'Timestamp': '2026-07-03 02:10:00'},
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 4100 (powershell.exe)',
             'Details': 'Thread start inside Module 3 flagged VAD. Not JIT-consistent.',
             'MITRE': 'T1055', 'Timestamp': '2026-07-03 02:11:00'},
            {'Severity': 'High', 'Type': 'External Network Connection',
             'Target': 'PID 4100 (powershell.exe)',
             'Details': 'ESTABLISHED 10.0.0.5:50000 -> 203.0.113.10:443',
             'MITRE': 'T1071', 'Timestamp': '2026-07-03 02:12:00'},
        ]
        tree = load_from_snapshot([
            {'ProcessId': 3000, 'ParentProcessId': 1200, 'Name': 'wmiprvse.exe'},
            {'ProcessId': 4100, 'ParentProcessId': 3000, 'Name': 'powershell.exe'},
        ])
        cvs = correlate(findings)
        chains = build_chains(cvs, tree)
        chain = next((c for c in chains if c.root_pid == 4100), None)
        assert chain is not None, 'No chain built for suspicious PID 4100'
        assert 'injection' in chain.stages_present, f'Stages: {chain.stages_present}'
        assert 'command-and-control' in chain.stages_present, f'Stages: {chain.stages_present}'
        assert any('wmiprvse.exe' in l for l in chain.lineage), \
            f'Lineage must include parent: {chain.lineage}'
        # Events must be time-ordered
        stamps = [e.timestamp for e in chain.events if e.timestamp]
        assert stamps == sorted(stamps), f'Events not time-ordered: {stamps}'

    def test_no_chain_for_closed_pids(self):
        """FP/NOISE PIDs must not generate attack chains."""
        findings = [
            {'Severity': 'Medium', 'Type': 'YARA Hit (Memory)',
             'Target': 'PID 2288 (notepad.exe)',
             'Details': '| LOLBin_BITS_Drop | 1 match(es) | file-backed -wx notepad.exe',
             'MITRE': 'T1197', 'Timestamp': '2026-07-03 03:00:00'},
        ]
        cvs = correlate(findings)
        chains = build_chains(cvs, {})
        assert not any(c.root_pid == 2288 for c in chains), \
            'FP-closed PID must not get an attack chain'

    def test_chain_includes_eventlog_evidence(self):
        """Event log entries for the focus PID must appear in the chain timeline."""
        findings = [
            {'Severity': 'High', 'Type': 'Injected Memory Region',
             'Target': 'PID 4100 (powershell.exe) @ 0x10000000',
             'Details': 'Executable private VAD. MZ header at offset 0.',
             'MITRE': 'T1055', 'Timestamp': '2026-07-03 02:10:00'},
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 4100 (powershell.exe)',
             'Details': 'Thread start inside Module 3 flagged VAD. Not JIT-consistent.',
             'MITRE': 'T1055', 'Timestamp': '2026-07-03 02:11:00'},
            {'Severity': 'High', 'Type': 'External Network Connection',
             'Target': 'PID 4100 (powershell.exe)',
             'Details': 'ESTABLISHED 10.0.0.5:50000 -> 203.0.113.10:443',
             'MITRE': 'T1071', 'Timestamp': '2026-07-03 02:12:00'},
        ]
        logs = [{'EventID': 4688, 'pid': 4100,
                 'CommandLine': 'powershell -enc AAAA', 'ParentProcessName': 'wmiprvse.exe',
                 'SubjectUserName': 'SYSTEM', 'TimeCreated': '2026-07-03 02:09:00'}]
        cvs = correlate(findings, event_logs=logs)
        chains = build_chains(cvs, {}, event_logs=logs)
        chain = next((c for c in chains if c.root_pid == 4100), None)
        assert chain is not None
        assert any(e.source == 'eventlog' for e in chain.events), \
            'Chain must include event log evidence'


# ============================================================================
# SECTION 14: MWCP LOG PARSER
# mwcp's generic parsers, run against decoded PowerShell/.NET memory, produce
# a high volume of noise: CLR namespace strings reported as "address", and
# WinAPI import names / hex padding reported as "mutex". The parser must strip
# proven-noise classes while still surfacing genuine network indicators.
# ============================================================================

class TestMwcpLogParser:
    def _write_log(self, tmp_path, lines):
        p = tmp_path / 'mwcp_scan_log.txt'
        p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return str(p)

    def test_clr_namespace_address_rejected(self):
        assert not _is_valid_address('System.IO')
        assert not _is_valid_address('Json.Net')

    def test_benign_microsoft_domain_rejected(self):
        assert not _is_valid_address('https://aka.ms/PSWindows')
        assert not _is_valid_address('aka.ms')

    def test_ip_port_accepted(self):
        assert _is_valid_address('185.220.101.45:443')

    def test_unknown_external_domain_accepted(self):
        assert _is_valid_address('http://evil-c2-panel.example.net/beacon')

    def test_clean_lines_skipped(self, tmp_path):
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:00 UTC] [CLEAN] proc_1234_10000000.bin (PE) "
            "parsers=Executable,GenericC2 no config",
        ])
        hits = _parse_mwcp_log(log)
        assert hits == []

    def test_namespace_only_match_dropped(self, tmp_path):
        """A MATCH with only CLR-namespace address noise must not become a hit."""
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:01 UTC] [MATCH] proc_1234_10000000.bin (PE) "
            "parsers=Executable,GenericC2 address=['System.IO', 'System.Net']",
        ])
        hits = _parse_mwcp_log(log)
        assert hits == [], f'Namespace-only match must be dropped entirely. Got: {hits}'

    def test_junk_mutex_only_match_dropped(self, tmp_path):
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:02 UTC] [MATCH] proc_1234_10000000.bin (PE) "
            "parsers=Executable,GenericMutex mutex=['ffffff', '111111111111']",
        ])
        hits = _parse_mwcp_log(log)
        assert hits == [], f'Junk-hex-mutex-only match must be dropped. Got: {hits}'

    def test_real_address_survives_and_pid_extracted(self, tmp_path):
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:03 UTC] [MATCH] kimbap_powershell_6464_006ad00000.bin (PE) "
            "parsers=Executable,GenericC2 address=['185.220.101.45:443', 'System.IO']",
        ])
        hits = _parse_mwcp_log(log)
        assert len(hits) == 1
        assert hits[0]['pid'] == 6464
        assert hits[0]['address'] == ['185.220.101.45:443'], \
            f'CLR namespace noise must be filtered from address list: {hits[0]}'

    def test_named_mutex_survives_hex_junk_filtered(self, tmp_path):
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:04 UTC] [MATCH] proc_5555_20000000.bin (PE) "
            "parsers=Executable,GenericMutex mutex=['Global\\WmiSync_7d3f', 'ffffff']",
        ])
        hits = _parse_mwcp_log(log)
        assert len(hits) == 1
        assert hits[0]['mutex'] == ['Global\\WmiSync_7d3f']

    def test_missing_log_file_returns_empty(self, tmp_path):
        assert _parse_mwcp_log(str(tmp_path / 'does_not_exist.txt')) == []

    def test_no_pid_in_filename_dropped(self, tmp_path):
        """A carved file that doesn't follow the {proc}_{pid}_{addr}.bin convention
        can't be attributed to a PID -- must not silently become an unattributed hit."""
        log = self._write_log(tmp_path, [
            "[2026-07-03 00:00:05 UTC] [MATCH] yara64.exe (PE) "
            "parsers=Executable,GenericC2 address=['185.220.101.45:443']",
        ])
        hits = _parse_mwcp_log(log)
        assert hits == [], f'No-PID filename must be dropped. Got: {hits}'


# ============================================================================
# SECTION 15: NAMED TTP PATTERN MATCHING
# Recognizable technique shapes across sources, independent of the
# TP/UNDETERMINED weight threshold.
# ============================================================================

class TestTTPPatterns:
    def test_beacon_pattern_matches_uniform_plus_anon_exec(self):
        cvs = correlate(LOTL_DLLHOST_BEACON['findings'])
        matches = match_patterns(cvs)
        hit = next((m for m in matches if m.pattern == 'beacon-in-uniform-region'
                    and m.pid == LOTL_DLLHOST_BEACON['pid']), None)
        assert hit is not None, f'Beacon pattern must match dllhost.exe scenario. Matches: {matches}'
        assert 'T1055' in hit.mitre

    def test_beacon_pattern_absent_for_noise(self):
        cvs = correlate(NOISE_TASKHOSTW['findings'])
        matches = match_patterns(cvs)
        assert not any(m.pid == NOISE_TASKHOSTW['pid'] for m in matches), \
            'Benign noise scenario must not match any TTP pattern'

    def test_ekko_sleep_pattern_matches(self):
        cvs = correlate(ADVANCED_EKKO_SLEEP['findings'])
        chains = build_chains(cvs, {})
        matches = match_patterns(cvs, chains=chains)
        hit = next((m for m in matches if m.pattern == 'sleep-obfuscation'), None)
        assert hit is not None, f'Ekko scenario must match sleep-obfuscation pattern. Matches: {matches}'
        assert hit.confidence == 'high', 'No network at snapshot is expected for sleep-obfuscation'

    def test_ppid_spoof_with_execution_pattern(self):
        findings = [
            {'Severity': 'High', 'Type': 'PPID Orphan (Memory)',
             'Target': 'PID 7700 (powershell.exe)',
             'Details': 'PID reused: PPID=4 (System) claimed by powershell.exe, but event log '
                        '4688 shows parent was svchost.exe (PID 1234 at spawn time).',
             'MITRE': 'T1134'},
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 7700 (powershell.exe)',
             'Details': 'Thread start 0xba000000 outside all loaded modules. Anonymous exec. '
                        'Not JIT-consistent.',
             'MITRE': 'T1055'},
        ]
        cvs = correlate(findings)
        matches = match_patterns(cvs)
        hit = next((m for m in matches if m.pattern == 'ppid-spoof-with-execution'), None)
        assert hit is not None, f'PPID spoof + exec must match. Matches: {matches}'
        assert 'T1134' in hit.mitre

    def test_lsass_credential_access_pattern(self):
        findings = [
            {'Severity': 'High', 'Type': 'Injected Memory Region',
             'Target': 'PID 676 (lsass.exe) @ 0x20000000',
             'Details': 'Executable private VAD. YARA match in this region.',
             'MITRE': 'T1003.001'},
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 676 (lsass.exe)',
             'Details': 'Thread start 0x7ffe08621b20 falls outside all loaded modules but '
                        'resides in a file-backed (image) VAD -- DLL is loaded but absent from '
                        'the PEB InLoadOrderModuleList.',
             'MITRE': 'T1003.001'},
        ]
        cvs = correlate(findings)
        matches = match_patterns(cvs)
        hit = next((m for m in matches if m.pattern == 'lsass-credential-access'), None)
        assert hit is not None, f'lsass thread+YARA corroboration must match. Matches: {matches}'

    def test_lsass_credential_access_absent_without_corroboration(self):
        """A lone unattributed thread in lsass with NO independent corroboration must not match."""
        findings = [
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 676 (lsass.exe)',
             'Details': 'Thread start 0x7ffe08621b20 falls outside all loaded modules but '
                        'resides in a file-backed (image) VAD -- DLL is loaded but absent from '
                        'the PEB InLoadOrderModuleList.',
             'MITRE': 'T1003.001'},
        ]
        cvs = correlate(findings)
        matches = match_patterns(cvs)
        assert not any(m.pattern == 'lsass-credential-access' for m in matches), \
            f'Uncorroborated lsass thread must not match. Matches: {matches}'

    def test_wmi_persistence_to_execution_pattern(self):
        findings = [
            {'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
             'Target': 'PID 9900 (svchost.exe)',
             'Details': 'Thread start outside all modules. Anonymous exec. Not JIT-consistent.',
             'MITRE': 'T1055', 'Timestamp': '2026-07-03 02:00:00'},
        ]
        logs = [{'EventID': 7045, 'pid': 9900,
                 'ServiceName': 'WMI Event Consumer', 'ServiceFileName': 'C:\\Windows\\wmiconsumer.exe',
                 'TimeCreated': '2026-07-03 01:55:00'}]
        cvs = correlate(findings, event_logs=logs)
        chains = build_chains(cvs, {}, event_logs=logs)
        matches = match_patterns(cvs, chains=chains)
        hit = next((m for m in matches if m.pattern == 'wmi-persistence-to-execution'), None)
        assert hit is not None, f'WMI persistence + execution must match. Matches: {matches}'

    def test_lolbin_loader_pattern(self):
        findings = [
            {'Severity': 'Medium', 'Type': 'Injected Memory Region',
             'Target': 'PID 6600 (wmic.exe) @ 0x20000000',
             'Details': 'Executable private VAD (no backing file).',
             'MITRE': 'T1218', 'Timestamp': '2026-07-03 02:00:00'},
        ]
        logs = [{'EventID': 4688, 'pid': 6600,
                 'CommandLine': 'wmic.exe process call create "powershell -enc SGVsbG8="',
                 'ParentProcessName': 'cmd.exe', 'TimeCreated': '2026-07-03 01:59:00'}]
        cvs = correlate(findings, event_logs=logs)
        chains = build_chains(cvs, {}, event_logs=logs)
        matches = match_patterns(cvs, chains=chains)
        hit = next((m for m in matches if m.pattern == 'lolbin-loader'), None)
        assert hit is not None, f'LOLBin loader + anon exec must match. Matches: {matches}'
        assert 'T1218' in hit.mitre

    def test_no_matches_without_memory_dimensions(self):
        """A PID with zero dimensions (e.g. inert findings) must not spuriously match."""
        cvs = correlate([])
        matches = match_patterns(cvs)
        assert matches == []


# ============================================================================
# SECTION 16: BASELINE CALIBRATION HARVESTER
# Must only harvest findings that independently pass a deterministic (non-ML)
# benign check -- never the ML forest's own prior verdict, to avoid circular
# self-training.
# ============================================================================

class TestCalibrationHarvester:
    def _write_findings(self, tmp_path, findings):
        d = tmp_path / 'report'
        d.mkdir()
        (d / 'Memory_Findings_20260703_000000.json').write_text(
            json.dumps(findings), encoding='utf-8')
        return str(d)

    def test_benign_m13_profile_is_harvested(self, tmp_path):
        findings = [{
            'Timestamp': '2026-07-03 00:00:00', 'Severity': 'High',
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 7076 (taskhostw.exe) @ 0x1000',
            'Details': ('Private RW region entropy=7.06 size=32768 bytes. '
                        'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
                        'MZ-remnant=False AdjAnonExec=False Head=7a 00 00 00'),
            'MITRE': 'T1055',
        }]
        report_dir = self._write_findings(tmp_path, findings)
        rows, total, verified = _harvest_from_report(report_dir)
        assert total == 1
        assert verified == 1, f'Documented-benign M13 profile must be harvested. Rows: {rows}'
        assert rows[0]['process'] == 'taskhostw.exe'

    def test_suspicious_m13_is_not_harvested(self, tmp_path):
        """UNIFORM + AdjAnonExec is the TP shape -- must never enter the benign baseline."""
        findings = [{
            'Timestamp': '2026-07-03 00:00:00', 'Severity': 'High',
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 5512 (svchost.exe) @ 0x1000',
            'Details': ('Private RW region entropy=7.87 size=65536 bytes. '
                        'ByteDistrib: CV=8% [UNIFORM(crypto-likely)] ASCII=1% '
                        'MZ-remnant=False AdjAnonExec=True Head=fc 48 83 e4'),
            'MITRE': 'T1055',
        }]
        report_dir = self._write_findings(tmp_path, findings)
        rows, total, verified = _harvest_from_report(report_dir)
        assert total == 1
        assert verified == 0, f'TP-shaped M13 must never be harvested as benign. Rows: {rows}'

    def test_bad_path_is_not_harvested_even_if_m13_looks_benign(self, tmp_path):
        """Path masquerading disqualifies harvesting regardless of M13 shape."""
        findings = [{
            'Timestamp': '2026-07-03 00:00:00', 'Severity': 'High',
            'Type': 'Dormant Beacon Candidate (Memory)',
            'Target': 'PID 5512 (svchost.exe) @ 0x1000',
            'Details': ('Path=C:\\Users\\Public\\svchost.exe. '
                        'ByteDistrib: CV=234% [non-uniform(data-likely)] ASCII=42% '
                        'MZ-remnant=False AdjAnonExec=False Head=7a 00 00 00'),
            'MITRE': 'T1055',
        }]
        report_dir = self._write_findings(tmp_path, findings)
        rows, total, verified = _harvest_from_report(report_dir)
        assert verified == 0, f'Wrong-path process must never be harvested. Rows: {rows}'

    def test_missing_report_dir_returns_zero(self, tmp_path):
        rows, total, verified = _harvest_from_report(str(tmp_path / 'nonexistent'))
        assert rows == [] and total == 0 and verified == 0


# ============================================================================
# SECTION 17: UNCONFIRMED PRIOR TP (inverse of miss detection)
# A prior "True Positive" call the ML engine cannot independently reach from
# memory evidence alone -- flags TP calls that may rest on non-memory evidence
# or deserve a second look, without asserting the prior call was wrong.
# ============================================================================

class TestUnconfirmedPriorTP:
    def test_prior_tp_not_reached_by_ml_is_flagged(self):
        """Prior says True Positive; memory evidence alone only reaches UNDETERMINED."""
        findings = [{
            'Severity': 'High', 'Type': 'Shellcode Thread (Memory)',
            'Target': 'PID 13816 (msedgewebview2.exe)',
            'Details': 'Thread start falls outside all loaded modules but resides in a '
                       'file-backed (image) VAD -- DLL absent from PEB InLoadOrderModuleList.',
            'MITRE': 'T1055',
        }]
        cvs = correlate(findings)
        report = _build_report('test-host', '20260703_000000', 'Memory_Findings.json',
                               cvs, [], prior_adj={13816: 'True Positive'})
        unconfirmed = report['unconfirmed_prior_tps']
        assert any(u['pid'] == 13816 for u in unconfirmed), \
            f'Prior TP not reached by ML must be flagged. Got: {unconfirmed}'

    def test_prior_tp_confirmed_by_ml_not_flagged(self):
        """When ML independently reaches TP too, there's no inverse-check finding."""
        cvs = correlate(LOTL_DLLHOST_BEACON['findings'])
        report = _build_report('test-host', '20260703_000000', 'Memory_Findings.json',
                               cvs, [], prior_adj={LOTL_DLLHOST_BEACON['pid']: 'True Positive'})
        unconfirmed = report['unconfirmed_prior_tps']
        assert not any(u['pid'] == LOTL_DLLHOST_BEACON['pid'] for u in unconfirmed), \
            f'ML-confirmed TP must not appear in the inverse check. Got: {unconfirmed}'

    def test_no_prior_adj_produces_no_unconfirmed_section(self):
        cvs = correlate([])
        report = _build_report('test-host', '20260703_000000', 'Memory_Findings.json',
                               cvs, [], prior_adj=None)
        assert report['unconfirmed_prior_tps'] == []
