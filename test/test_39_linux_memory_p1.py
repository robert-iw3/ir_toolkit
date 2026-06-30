"""Tests for LTTP-001 (analyze_ebpf), LTTP-002 (analyze_got_plt), LTTP-003 (analyze_ptrace).

All functions accept lists of row-dicts (Volatility plugin JSON output) and return
lists of finding dicts - pure functions with no I/O.
"""
import sys
from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as m  # noqa: E402


def types(findings):
    return {f["Type"] for f in findings}


def sevs(findings):
    return {f["Severity"] for f in findings}


# ---------------------------------------------------------------------------
# LTTP-001: analyze_ebpf
# ---------------------------------------------------------------------------

def test_ebpf_base_coverage_medium():
    """All eBPF programs should produce at least a Medium finding (no signal dropped)."""
    rows = [{"Type": "lsm", "Name": "policy_checker", "Tag": "abc123", "PID": 10, "Process": "agent"}]
    f = m.analyze_ebpf(rows)
    assert len(f) > 0
    assert any(f_["Severity"] in ("Medium", "High", "Critical") for f_ in f)


def test_ebpf_kprobe_getdents_escalates_to_high():
    """kprobe attached to getdents64 is a process-hiding indicator - must be High."""
    rows = [{"Type": "kprobe", "Name": "hook_getdents64", "Tag": "deadbeef", "PID": 1, "Process": "rootkit"}]
    f = m.analyze_ebpf(rows)
    assert len(f) > 0
    high_or_above = [x for x in f if x["Severity"] in ("High", "Critical")]
    assert len(high_or_above) > 0, f"Expected High or Critical, got: {[x['Severity'] for x in f]}"


def test_ebpf_tracepoint_network_filter_high():
    """tracepoint on tcp-related hook is a network-hiding indicator - must be High."""
    rows = [{"Type": "tracepoint", "Name": "tcp_filter_hide", "Tag": "cafebabe", "PID": 2, "Process": "evader"}]
    f = m.analyze_ebpf(rows)
    high_or_above = [x for x in f if x["Severity"] in ("High", "Critical")]
    assert len(high_or_above) > 0


def test_ebpf_socket_filter_type_is_high():
    """socket_filter type is always a network hook - must be escalated to High."""
    rows = [{"Type": "socket_filter", "Name": "legit_name", "Tag": "11111", "PID": 3, "Process": "svc"}]
    f = m.analyze_ebpf(rows)
    high = [x for x in f if x["Severity"] in ("High", "Critical")]
    assert len(high) > 0


def test_ebpf_xdp_escalates():
    """XDP programs are network hooks - must be High."""
    rows = [{"Type": "xdp", "Name": "xdp_prog", "Tag": "xyz", "PID": 4, "Process": "net"}]
    f = m.analyze_ebpf(rows)
    high = [x for x in f if x["Severity"] in ("High", "Critical")]
    assert len(high) > 0


def test_ebpf_empty_rows_returns_empty():
    assert m.analyze_ebpf([]) == []
    assert m.analyze_ebpf(None) == []


def test_ebpf_multiple_programs_all_flagged():
    """Multiple eBPF programs should all produce findings."""
    rows = [
        {"Type": "kprobe",        "Name": "hide_proc",   "Tag": "1", "PID": 10, "Process": "bad"},
        {"Type": "socket_filter",  "Name": "filter_net",  "Tag": "2", "PID": 11, "Process": "bad"},
        {"Type": "lsm",           "Name": "lsm_hook",    "Tag": "3", "PID": 12, "Process": "agent"},
    ]
    f = m.analyze_ebpf(rows)
    assert len(f) >= 3


def test_ebpf_mitre_tag_present():
    """eBPF findings must include a MITRE tag."""
    rows = [{"Type": "kprobe", "Name": "x", "Tag": "y", "PID": 1, "Process": "p"}]
    f = m.analyze_ebpf(rows)
    assert all("MITRE" in x or "Mitre" in x or "mitre" in x.get("MITRE","") or x.get("MITRE") for x in f), \
        f"Missing MITRE in finding: {f}"


# ---------------------------------------------------------------------------
# LTTP-002: analyze_got_plt
# ---------------------------------------------------------------------------

def test_got_plt_anon_backed_is_critical():
    """GOT entry pointing to anonymous memory is a clear hook indicator - Critical."""
    rows = [{
        "PID": 100, "Process": "sshd",
        "Library": "libpam.so", "Function": "pam_authenticate",
        "Expected_Addr": "0x7f0000000000", "Actual_Addr": "0x7fff00001234",
        "Backed_By": "anon"
    }]
    f = m.analyze_got_plt(rows)
    assert len(f) > 0
    crits = [x for x in f if x["Severity"] == "Critical"]
    assert len(crits) > 0, f"Expected Critical but got: {[x['Severity'] for x in f]}"
    assert "GOT/PLT Overwrite" in crits[0]["Type"]


def test_got_plt_anonymous_variants_all_critical():
    """'anonymous', '(anon)', '[anon]', '' - all should map to Critical."""
    for backed in ("anonymous", "[anon]", "(anon)", "", "none"):
        rows = [{"PID": 1, "Process": "p", "Library": "lib.so", "Function": "f",
                 "Expected_Addr": "0x1", "Actual_Addr": "0x2", "Backed_By": backed}]
        f = m.analyze_got_plt(rows)
        assert any(x["Severity"] == "Critical" for x in f), \
            f"Backed_By='{backed}' did not produce Critical"


def test_got_plt_legit_backed_is_medium():
    """GOT entry pointing to a legit but unexpected lib produces Medium (verify)."""
    rows = [{
        "PID": 100, "Process": "nginx",
        "Library": "libssl.so", "Function": "SSL_read",
        "Expected_Addr": "0x7f0000000000", "Actual_Addr": "0x7f1234560000",
        "Backed_By": "/lib/x86_64-linux-gnu/libcustom.so"
    }]
    f = m.analyze_got_plt(rows)
    assert len(f) > 0
    assert any(x["Severity"] == "Medium" for x in f)


def test_got_plt_empty_rows_returns_empty():
    assert m.analyze_got_plt([]) == []
    assert m.analyze_got_plt(None) == []


def test_got_plt_mitre_reference():
    """Findings must reference the MITRE technique for GOT overwrite."""
    rows = [{"PID": 1, "Process": "sshd", "Library": "libc.so", "Function": "write",
             "Expected_Addr": "0x1", "Actual_Addr": "0x2", "Backed_By": "anon"}]
    f = m.analyze_got_plt(rows)
    assert len(f) > 0
    assert any("T1574" in str(x.get("MITRE", "")) for x in f)


def test_got_plt_target_includes_pid_and_process():
    """Finding Target must identify the affected process."""
    rows = [{"PID": 4242, "Process": "sshd", "Library": "libpam.so", "Function": "auth",
             "Expected_Addr": "0x0", "Actual_Addr": "0x1", "Backed_By": "anon"}]
    f = m.analyze_got_plt(rows)
    assert len(f) > 0
    assert "4242" in f[0]["Target"] or "sshd" in f[0]["Target"]


# ---------------------------------------------------------------------------
# LTTP-003: analyze_ptrace
# ---------------------------------------------------------------------------

def test_ptrace_active_attachment_flagged_medium():
    """Any active ptrace attachment should produce at least a Medium finding."""
    rows = [{"PID": 500, "Process": "bash", "Tracer PID": 600, "Tracer": "gdb",
             "Thread IP": None, "Backed": None}]
    f = m.analyze_ptrace(rows)
    assert len(f) > 0
    assert any(x["Severity"] in ("Medium", "High", "Critical") for x in f)


def test_ptrace_ip_in_anon_region_escalates_to_high():
    """Thread IP in anonymous/injected memory during ptrace must escalate to High."""
    rows = [{
        "PID": 501, "Process": "cron", "Tracer PID": 601, "Tracer": "injector",
        "Thread IP": "0x7f1234567890",
        "Backed": "anon"
    }]
    f = m.analyze_ptrace(rows)
    high = [x for x in f if x["Severity"] in ("High", "Critical")]
    assert len(high) > 0, f"Expected High or Critical for anon IP, got: {[x['Severity'] for x in f]}"


def test_ptrace_thread_ip_anon_variants():
    """Anonymous memory variants for Backed field all should escalate."""
    for backed in ("anon", "anonymous", "[anon]", "(anon)"):
        rows = [{"PID": 1, "Process": "p", "Tracer PID": 2, "Tracer": "t",
                 "Thread IP": "0x1234", "Backed": backed}]
        f = m.analyze_ptrace(rows)
        high = [x for x in f if x["Severity"] in ("High", "Critical")]
        assert len(high) > 0, f"Backed='{backed}' did not produce High/Critical"


def test_ptrace_no_ip_info_stays_medium():
    """When Thread IP field is absent/None, finding stays Medium (no escalation)."""
    rows = [{"PID": 502, "Process": "bash", "Tracer PID": 602, "Tracer": "strace"}]
    f = m.analyze_ptrace(rows)
    assert len(f) > 0
    # Should have at least the base Medium; should NOT have a High for missing IP
    high = [x for x in f if x["Severity"] in ("High", "Critical") and "IP" in x.get("Type", "")]
    assert len(high) == 0


def test_ptrace_empty_rows_returns_empty():
    assert m.analyze_ptrace([]) == []
    assert m.analyze_ptrace(None) == []


def test_ptrace_mitre_reference():
    """Ptrace findings must reference T1055 or T1055.008."""
    rows = [{"PID": 1, "Process": "x", "Tracer PID": 2, "Tracer": "y"}]
    f = m.analyze_ptrace(rows)
    assert len(f) > 0
    assert any("T1055" in str(x.get("MITRE", "")) for x in f)
