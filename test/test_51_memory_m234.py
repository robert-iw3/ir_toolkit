"""Memory analyzers for the M2/M3/M4 advanced-TTP gaps: io_uring, namespaces/container
escape, kernel timers, .text inline hooks, VFS fops hooks, credential override, eBPF C2
correlation, and re-enabled GOT/PLT. Pure functions over synthetic vol-plugin rows; each
technique's signature is flagged and clean input stays silent (FP guard).
"""
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as am  # noqa: E402


# ── G1 io_uring ─────────────────────────────────────────────────────────────────
def test_io_uring_implant_high_legit_info():
    f = am.analyze_io_uring([
        {"PID": 10, "Comm": "impl", "Path": "/dev/shm/x", "Rings": 1},
        {"PID": 11, "Comm": "nginx", "Path": "/usr/sbin/nginx", "Rings": 2}])
    by = {x["Severity"] for x in f}
    assert any(x["Severity"] == "High" and "10" in x["Target"] for x in f)
    assert any(x["Severity"] == "Info" and "11" in x["Target"] for x in f)  # surfaced, not blinded
    assert "High" in by and "Info" in by


# ── G9 namespaces / container escape ────────────────────────────────────────────
def test_namespace_escape_flagged():
    f = am.analyze_namespaces([
        {"PID": 1, "Comm": "systemd", "MntNs": "4026531840", "PidNs": "4026531836", "NetNs": "4026531992"},
        {"PID": 900, "Comm": "app", "MntNs": "4026532111", "PidNs": "4026531836", "NetNs": "4026532222"}])
    assert f and f[0]["Type"] == "Namespace Escape (memory)" and "T1611" in f[0]["MITRE"]
    assert "pid" in f[0]["Details"]


def test_fully_contained_or_host_process_not_flagged():
    f = am.analyze_namespaces([
        {"PID": 1, "Comm": "systemd", "MntNs": "4026531840", "PidNs": "4026531836", "NetNs": "4026531992"},
        {"PID": 2, "Comm": "host", "MntNs": "4026531840", "PidNs": "4026531836", "NetNs": "4026531992"},
        {"PID": 3, "Comm": "ctr", "MntNs": "4026532111", "PidNs": "4026532112", "NetNs": "4026532113"}])
    assert f == []


# ── G8 kernel timers ────────────────────────────────────────────────────────────
def test_kernel_timer_unbacked_handler_high():
    f = am.analyze_kernel_timers([{"Symbol": "", "Module": "", "Address": "0xffffc0001234"}])
    assert f and f[0]["Type"] == "Kernel Timer Hook (memory)" and "T1053" in f[0]["MITRE"]


def test_kernel_timer_backed_handler_silent():
    assert am.analyze_kernel_timers([{"Symbol": "delayed_work_timer_fn", "Module": "kernel"}]) == []


# ── G7 .text inline hooks ───────────────────────────────────────────────────────
def test_text_inline_hook_flagged():
    f = am.analyze_text_hooks([{"Symbol": "__x64_sys_getdents64", "Prologue": "e9 ab cd",
                                "Hooked": True}])
    assert f and f[0]["Type"] == "Kernel .text Inline Hook (memory)"


def test_text_clean_prologue_silent():
    assert am.analyze_text_hooks([{"Symbol": "__x64_sys_read", "Hooked": False}]) == []


# ── G3 VFS fops hooks ───────────────────────────────────────────────────────────
def test_fops_hook_unattributed_high():
    f = am.analyze_fops_hooks([{"Object": "proc_root", "Op": "iterate_shared",
                                "Handler": "0xffffc0", "Module": ""}])
    assert f and f[0]["Type"] == "VFS fops Hook (memory)" and "T1014" in f[0]["MITRE"]


def test_fops_backed_by_module_silent():
    assert am.analyze_fops_hooks([{"Object": "/", "Op": "lookup", "Module": "ext4"}]) == []


# ── G12 credential override ─────────────────────────────────────────────────────
def test_cred_override_flagged():
    f = am.analyze_task_creds([{"PID": 31337, "Comm": "sh", "UID": 1000, "EUID": 0,
                                "CredMatchesReal": False}])
    assert f and f[0]["Type"] == "Credential Override (memory)" and "T1068" in f[0]["MITRE"]


def test_cred_consistent_silent():
    assert am.analyze_task_creds([{"PID": 1, "UID": 0, "EUID": 0, "CredMatchesReal": True}]) == []


# ── G5 eBPF C2 correlation ──────────────────────────────────────────────────────
def test_ebpf_netfilter_c2_correlation():
    f = am.correlate_ebpf_c2(
        [{"Type": "xdp", "Name": "magic_recv"}],
        [{"Is Hooked": "True", "Name": "nf_hook"}])
    assert f and f[0]["Type"] == "eBPF Network C2 Correlated (memory)" and "T1205.002" in f[0]["MITRE"]


def test_ebpf_without_netfilter_no_correlation():
    assert am.correlate_ebpf_c2([{"Type": "xdp", "Name": "x"}], []) == []
    assert am.correlate_ebpf_c2([], [{"Is Hooked": "True"}]) == []


# ── G4 GOT/PLT (re-enabled) ─────────────────────────────────────────────────────
def test_got_overwrite_to_anon_is_critical():
    f = am.analyze_got_plt([{"PID": 5, "Process": "sshd", "Function": "getpwnam",
                             "Backed_By": "anon", "Actual_Addr": "0x7f00", "Library": "libc"}])
    assert f and f[0]["Severity"] == "Critical" and "T1574.001" in f[0]["MITRE"]


def test_dispatch_wires_new_analyzers():
    findings = am.analyze({
        "linux_ir.io_uring.IoUring": [{"PID": 1, "Comm": "x", "Path": "/tmp/x", "Rings": 1}],
        "linux_ir.task_creds.TaskCreds": [{"PID": 2, "CredMatchesReal": False, "UID": 1000, "EUID": 0}],
        "linux.ebpf.EBPF": [{"Type": "xdp", "Name": "m"}],
        "linux.malware.netfilter.Netfilter": [{"Is Hooked": "True"}]})
    types = {f["Type"] for f in findings}
    assert "io_uring Anti-EDR I/O (memory)" in types
    assert "Credential Override (memory)" in types
    assert "eBPF Network C2 Correlated (memory)" in types
