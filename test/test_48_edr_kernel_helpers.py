"""check_kernel_helper_paths - usermodehelper path hijack (core_pattern / modprobe_path /
uevent_helper). Repointing a root-run kernel helper at an attacker binary is a classic
privesc / container-escape / persistence primitive (e.g. CVE-2022-0492 via core_pattern).
"""
import sys
from unittest.mock import patch

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402


def _run(values):
    h.FINDINGS.clear()
    with patch.object(h, "read_file", side_effect=lambda p, *a, **k: values.get(p)):
        h.check_kernel_helper_paths()
    return h.FINDINGS


CLEAN = {
    "/proc/sys/kernel/core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u %g",
    "/proc/sys/kernel/modprobe": "/sbin/modprobe",
    "/sys/kernel/uevent_helper": "",
    "/proc/sys/kernel/hotplug": "",
}


def test_clean_host_is_silent():
    assert _run(CLEAN) == []
    # a plain 'core' pattern (no pipe) is also fine
    assert _run({**CLEAN, "/proc/sys/kernel/core_pattern": "core"}) == []


def test_core_pattern_pipe_to_implant_is_critical():
    f = _run({**CLEAN, "/proc/sys/kernel/core_pattern": "|/tmp/.x/collect %P"})
    hit = [x for x in f if x["Type"] == "Kernel core_pattern Hijack"]
    assert hit and hit[0]["Severity"] == "Critical" and "T1611" in hit[0]["MITRE"]


def test_core_pattern_pipe_to_nonstandard_is_high():
    f = _run({**CLEAN, "/proc/sys/kernel/core_pattern": "|/opt/evil/handler %P"})
    hit = [x for x in f if x["Type"] == "Kernel core_pattern Hijack"]
    assert hit and hit[0]["Severity"] == "High"


def test_modprobe_hijack_flagged():
    f = _run({**CLEAN, "/proc/sys/kernel/modprobe": "/tmp/rootkit_loader"})
    hit = [x for x in f if x["Type"] == "modprobe_path Hijack"]
    assert hit and hit[0]["Severity"] == "Critical" and "T1547.006" in hit[0]["MITRE"]


def test_uevent_helper_set_is_flagged():
    f = _run({**CLEAN, "/sys/kernel/uevent_helper": "/tmp/pwn"})
    assert any(x["Type"] == "uevent_helper Hijack" for x in f)


def test_apport_coredump_handler_not_flagged():
    f = _run({**CLEAN,
              "/proc/sys/kernel/core_pattern": "|/usr/share/apport/apport %p %s %c"})
    assert not [x for x in f if x["Type"] == "Kernel core_pattern Hijack"]


def test_distro_variants_not_flagged():
    # RHEL/Fedora ABRT handler + usr-merged modprobe path must both be treated as legitimate
    f = _run({**CLEAN,
              "/proc/sys/kernel/core_pattern": "|/usr/libexec/abrt-hook-ccpp %P %u %g %s %t %e",
              "/proc/sys/kernel/modprobe": "/usr/bin/modprobe"})
    assert f == []
