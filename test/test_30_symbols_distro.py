"""Cross-distro kernel-symbol (ISF) acquisition — Build-LinuxSymbols.sh.

Volatility-3-Linux needs a kernel-exact ISF (a generic vmlinux.h won't do). This validates
the distro-aware acquisition plan (debian/rhel/suse/arch) + the universal debuginfod path,
using an injected os-release (IR_OS_RELEASE) and PLAN mode (IR_SYMBOLS_PLAN) so no package
manager actually runs.
"""
import os
import subprocess

from conftest import ROOT

SCRIPT = os.path.join(ROOT, "playbooks", "linux", "threat_hunting", "Build-LinuxSymbols.sh")


def _osrel(tmp_path, **kv):
    p = tmp_path / "os-release"
    p.write_text("".join(f'{k}="{v}"\n' for k, v in kv.items()))
    return str(p)


def _run(osrel, *args, build_id=None):
    env = {**os.environ, "IR_OS_RELEASE": osrel, "IR_SYMBOLS_PLAN": "1"}
    cmd = ["bash", SCRIPT, "--kernel", "9.9.9-fake", "--fetch-symbols", *args]
    if build_id:
        cmd += ["--build-id", build_id]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)


def test_debian_branch(tmp_path):
    r = _run(_osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing"))
    assert "family=debian" in r.stderr
    assert "PLAN[debian]" in r.stderr and "linux-image-9.9.9-fake-dbgsym" in r.stderr
    assert r.returncode == 3            # acquisition only planned -> no vmlinux -> exit 3


def test_rhel_branch(tmp_path):
    r = _run(_osrel(tmp_path, ID="fedora", ID_LIKE="rhel"))
    assert "family=rhel" in r.stderr
    assert "PLAN[rhel]" in r.stderr and "debuginfo-install kernel-9.9.9-fake" in r.stderr


def test_suse_branch(tmp_path):
    r = _run(_osrel(tmp_path, ID="opensuse-leap", ID_LIKE="suse opensuse"))
    assert "family=suse" in r.stderr and "PLAN[suse]" in r.stderr
    assert "kernel-default-debuginfo" in r.stderr


def test_arch_uses_debuginfod_only(tmp_path):
    r = _run(_osrel(tmp_path, ID="arch"))
    assert "family=arch" in r.stderr
    assert "debuginfod.archlinux.org" in r.stderr      # arch guidance points at debuginfod


def test_debuginfod_plan_with_explicit_build_id(tmp_path):
    r = _run(_osrel(tmp_path, ID="arch"), build_id="abcdef0123456789")
    assert "PLAN[debuginfod]" in r.stderr and "abcdef0123456789" in r.stderr


def test_unknown_distro_exits_with_guidance(tmp_path):
    r = _run(_osrel(tmp_path, ID="weirdos"))
    assert "family=unknown" in r.stderr
    assert r.returncode == 3 and "--vmlinux" in r.stderr


def test_btf_note_when_present():
    # On a host with /sys/kernel/btf/vmlinux, the builder must say it can't use BTF.
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return
    env = {**os.environ, "IR_SYMBOLS_PLAN": "1"}
    r = subprocess.run(["bash", SCRIPT, "--kernel", "9.9.9-fake"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert "unusable by dwarf2json" in r.stderr
