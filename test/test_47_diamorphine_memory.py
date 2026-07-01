"""Diamorphine (LKM rootkit) detection by the memory engine.

The userland hunt (edr_hunt.py) is largely blind to a kernel rootkit that unlinks itself
from every module list - that is the memory pass's job. Diamorphine's on-image signatures:
  * syscall-table hooks on sys_kill / sys_getdents(64)   (privesc magic + file/proc hiding)
  * the module carved from kernel memory but absent from the module list
  * a process in the PID hashtable but hidden from pslist (its `kill -31` process hiding)
  * a tampered credential structure (its `kill -64` "become root" magic)

Each is an independent T1014 signal, so the engine catches Diamorphine several ways over -
proving why "capture and analyze memory" is non-optional against kernel rootkits.
"""
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as am  # noqa: E402


def _diamorphine_plugin_rows():
    return {
        # Diamorphine overwrites sys_call_table entries -> handlers no longer resolve to a module.
        "linux.malware.check_syscall.Check_syscall": [
            {"Index": "__x64_sys_kill", "Symbol": "UNKNOWN"},
            {"Index": "__x64_sys_getdents64", "Symbol": "UNKNOWN"}],
        # Unlinked from the module list but recovered by carving kernel memory.
        "linux.hidden_modules.Hidden_modules": [
            {"Name": "diamorphine", "Address": "0xffffffffc0a20000"}],
        # Its process-hiding (kill -31): present in the hashtable, gone from pslist.
        "linux.pslist.PsList": [
            {"PID": 1, "COMM": "systemd"}, {"PID": 900, "COMM": "sshd"}],
        "linux.pidhashtable.PIDHashTable": [
            {"PID": 1, "COMM": "systemd"}, {"PID": 900, "COMM": "sshd"},
            {"PID": 31337, "COMM": "backdoor"}],
        # Its privesc magic (kill -64): a credential structure tampered to uid 0.
        "linux.check_creds.Check_creds": [
            {"PID": 31337, "Comment": "credentials shared/escalated to uid 0"}],
    }


def test_diamorphine_caught_by_multiple_signals():
    findings = am.analyze(_diamorphine_plugin_rows())
    types = {f["Type"] for f in findings}

    assert "Syscall Table Hook" in types
    assert any(f["Type"] == "Hidden Kernel Module (carved)" and "diamorphine" in f["Target"]
               for f in findings)
    assert any(f["Type"] == "Hidden Process (memory)" and "31337" in f["Target"]
               for f in findings)
    assert "Shared Credential Structure (memory)" in types

    # at least three independent rootkit (T1014) signals -> defense in depth
    t1014 = {f["Type"] for f in findings if "T1014" in f.get("MITRE", "")}
    assert len(t1014) >= 3, f"expected multiple independent rootkit signals, got {t1014}"


def test_syscall_hook_is_high_severity_rootkit():
    hooks = am.analyze_check_syscall(
        _diamorphine_plugin_rows()["linux.malware.check_syscall.Check_syscall"])
    assert hooks and all(f["Severity"] == "High" and "T1014" in f["MITRE"] for f in hooks)


def test_clean_syscall_table_is_silent():
    # every entry attributes to a known module/symbol -> no hook finding
    clean = am.analyze_check_syscall([
        {"Index": "__x64_sys_read", "Symbol": "__x64_sys_read"},
        {"Index": "__x64_sys_write", "Symbol": "__x64_sys_write"}])
    assert clean == []


def test_hidden_module_requires_a_name():
    # a named carve is a real rootkit signal; an address-only carve is a 'verify' artifact
    named = am.analyze_hidden_modules([{"Name": "diamorphine", "Address": "0xc0a20000"}])
    assert named and named[0]["Severity"] == "High"
    unnamed = am.analyze_hidden_modules([{"Name": "", "Address": "0xc0a20000"}])
    assert unnamed and unnamed[0]["Severity"] == "Medium"
