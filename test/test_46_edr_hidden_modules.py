"""check_hidden_modules hardening - a Diamorphine-class LKM rootkit unlinks from BOTH
/proc/modules and /sys/module, defeating the naive sysfs-vs-procfs diff. The hardened
check adds two more independent views: /proc/kallsyms symbol ownership, and sticky kernel
taint that no visible module accounts for.
"""
import sys
from unittest.mock import patch

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402


def _run(files, sys_modules):
    """Drive check_hidden_modules with a fake /proc + /sys/module layout.
    files: dict path -> contents (read_file). sys_modules: dict modname -> taint string."""
    h.FINDINGS.clear()

    def rf(path, *a, **k):
        if path.startswith("/sys/module/") and path.endswith("/taint"):
            return sys_modules.get(path.split("/")[3], "")
        return files.get(path)

    with patch.object(h, "read_file", side_effect=rf), \
         patch("os.listdir", return_value=list(sys_modules)), \
         patch("os.path.isdir", return_value=True), \
         patch("os.path.exists", return_value=True):
        h.check_hidden_modules()
    return h.FINDINGS


def test_kallsyms_only_module_is_flagged():
    # module owns symbols in kallsyms but is absent from /proc/modules and /sys/module
    findings = _run({
        "/proc/modules": "ext4 100 0 - Live 0x0\n",
        "/proc/kallsyms": "0000000000000000 t evil_hook\t[diamorphine]\n"
                          "0000000000000000 t ext4_something\t[ext4]\n",
        "/proc/sys/kernel/tainted": "0",
    }, {"ext4": ""})
    hits = [f for f in findings if f["Type"] == "Hidden Kernel Module"]
    assert any(f["Target"] == "diamorphine" for f in hits)


def test_kallsyms_pseudo_modules_downgraded_not_suppressed():
    # [bpf] (JITed programs) and [ftrace] (trampolines) are synthetic kallsyms tags, not
    # loadable modules - so NOT flagged as a hidden module, but surfaced at Info rather than
    # suppressed (a rootkit could try to masquerade under one of these names).
    findings = _run({
        "/proc/modules": "ext4 100 0 - Live 0x0\n",
        "/proc/kallsyms": "0000000000000000 t bpf_prog_abc\t[bpf]\n"
                          "0000000000000000 t ftrace_tramp\t[ftrace]\n",
        "/proc/sys/kernel/tainted": "0",
    }, {"ext4": ""})
    assert not [f for f in findings if f["Type"] == "Hidden Kernel Module"]
    info = [f for f in findings if f["Type"] == "Kallsyms Pseudo-Module (verify)"]
    assert len(info) == 2 and all(f["Severity"] == "Info" for f in info)


def test_sysfs_hidden_module_still_flagged():
    findings = _run({
        "/proc/modules": "ext4 100 0 - Live 0x0\n",
        "/proc/kallsyms": "",
        "/proc/sys/kernel/tainted": "0",
    }, {"ext4": "", "sneaky": ""})       # sneaky in sysfs, not in /proc/modules
    assert any(f["Type"] == "Hidden Kernel Module" and f["Target"] == "sneaky"
               for f in findings)


def test_unexplained_taint_is_flagged():
    # kernel tainted E (unsigned module, bit 13 = 8192) but no visible module carries E
    findings = _run({
        "/proc/modules": "ext4 100 0 - Live 0x0\n",
        "/proc/kallsyms": "",
        "/proc/sys/kernel/tainted": "8192",
    }, {"ext4": ""})
    taint = [f for f in findings if f["Type"] == "Kernel Tainted By Unaccounted Module (verify)"]
    assert taint and "E" in taint[0]["Target"]
    assert "T1014" in taint[0]["MITRE"]


def test_explained_taint_no_false_positive():
    # kernel tainted O (out-of-tree, 4096); the visible nvidia module carries O -> explained.
    # This mirrors the real validated host (nvidia -> taint O, no finding).
    findings = _run({
        "/proc/modules": "nvidia 100 0 - Live 0x0\next4 100 0 - Live 0x0\n",
        "/proc/kallsyms": "",
        "/proc/sys/kernel/tainted": "4096",
    }, {"nvidia": "O", "ext4": ""})
    assert not [f for f in findings if "Tainted" in f["Type"]]


def test_clean_host_is_silent():
    findings = _run({
        "/proc/modules": "ext4 100 0 - Live 0x0\nxfs 90 0 - Live 0x0\n",
        "/proc/kallsyms": "0000000000000000 t ext4_x\t[ext4]\n",
        "/proc/sys/kernel/tainted": "0",
    }, {"ext4": "", "xfs": ""})
    assert findings == []
