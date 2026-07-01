"""analyze_kernel_globals - the memory-image counterpart of the live usermodehelper check.
Consumes rows from the toolkit's custom linux_ir.kernel_globals vol3 plugin
({"Global","Value"}) and flags core_pattern / modprobe_path / uevent_helper hijacks.
Distro-agnostic legitimate values must stay silent.
"""
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import analyze_memory_linux as am  # noqa: E402


def _rows(**kw):
    # matches the plugin's TreeGrid columns ("Name", "Value")
    return [{"Name": k, "Value": v} for k, v in kw.items()]


CLEAN = dict(modprobe_path="/sbin/modprobe",
             core_pattern="|/usr/lib/systemd/systemd-coredump %P",
             poweroff_cmd="/sbin/poweroff", uevent_helper="")


def test_clean_globals_silent():
    assert am.analyze_kernel_globals(_rows(**CLEAN)) == []


def test_distro_variants_silent():
    # RHEL/Fedora ABRT + usr-merged modprobe are legitimate on other distros
    assert am.analyze_kernel_globals(_rows(
        modprobe_path="/usr/bin/modprobe",
        core_pattern="|/usr/libexec/abrt-hook-ccpp %P %u",
        uevent_helper="")) == []


def test_core_pattern_hijack_flagged():
    f = am.analyze_kernel_globals(_rows(**{**CLEAN, "core_pattern": "|/tmp/.x/collect %P"}))
    assert any(x["Type"] == "Kernel core_pattern Hijack (memory)" and x["Severity"] == "High"
               and "T1611" in x["MITRE"] for x in f)


def test_modprobe_hijack_flagged():
    f = am.analyze_kernel_globals(_rows(**{**CLEAN, "modprobe_path": "/dev/shm/loader"}))
    assert any(x["Type"] == "modprobe_path Hijack (memory)" and "T1547.006" in x["MITRE"]
               for x in f)


def test_uevent_helper_flagged():
    f = am.analyze_kernel_globals(_rows(**{**CLEAN, "uevent_helper": "/tmp/pwn"}))
    assert any(x["Type"] == "uevent_helper Hijack (memory)" for x in f)


def test_analyze_dispatch_wires_kernel_globals():
    findings = am.analyze({
        "linux_ir.kernel_globals.KernelGlobals": _rows(**{**CLEAN, "modprobe_path": "/tmp/x"})})
    assert any(x["Type"] == "modprobe_path Hijack (memory)" for x in findings)
