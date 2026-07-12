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


# ---------------------------------------------------------------------------
# Rootless Debian/Ubuntu path (apt-get download + dpkg-deb -x, no sudo) + error
# surfacing. Real bug caught live: apt-get's output was fully redirected to
# /dev/null, so a failed fetch (network unreachable, package not found, ...) gave
# zero diagnostic trail -- just a generic "failed" with no way to tell why.
# ---------------------------------------------------------------------------
def _fake_bin(tmp_path, name, script):
    d = tmp_path / "fakebin"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(f"#!/usr/bin/env bash\n{script}\n")
    p.chmod(0o755)
    return str(d)


def test_debian_rootless_index_failure_is_surfaced_not_swallowed(tmp_path):
    """A failing 'apt-get ... update' must show its actual error output, not just
    a bare 'failed'."""
    fakebin = _fake_bin(tmp_path, "apt-get",
        'if [[ "$*" == *update* ]]; then echo "DISTINCTIVE_NETWORK_ERROR: could not resolve ddebs.ubuntu.com" >&2; exit 1; fi\n'
        'exit 1\n')
    _fake_bin(tmp_path, "dpkg-deb", "exit 0")  # present, so the rootless path is attempted
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}",
          "IR_OS_RELEASE": _osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing")}
    r = subprocess.run(["bash", SCRIPT, "--kernel", "9.9.9-fake", "--fetch-symbols"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert "DISTINCTIVE_NETWORK_ERROR" in r.stderr
    assert "trying rootless download" in r.stderr


def test_debian_rootless_extraction_failure_is_surfaced(tmp_path):
    """apt-get update/download succeed (fake), but dpkg-deb -x fails -- that error
    must also be surfaced, not swallowed, and the download must still leave a
    package file for it to have something to extract."""
    fakebin = _fake_bin(tmp_path, "apt-get",
        'if [[ "$*" == *download* ]]; then touch "linux-image-9.9.9-fake-dbgsym_1_amd64.ddeb"; fi\n'
        'exit 0\n')
    _fake_bin(tmp_path, "dpkg-deb",
             'echo "DISTINCTIVE_EXTRACT_ERROR: corrupt archive" >&2; exit 1')
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}",
          "IR_OS_RELEASE": _osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing")}
    r = subprocess.run(["bash", SCRIPT, "--kernel", "9.9.9-fake", "--fetch-symbols"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert "DISTINCTIVE_EXTRACT_ERROR" in r.stderr


# ---------------------------------------------------------------------------
# --allow-closest-symbols: when the EXACT requested kernel's dbgsym package isn't
# published, opt-in to using the closest AVAILABLE point-release in the same series
# instead of failing outright. Must never mislabel the result as an exact match --
# the ISF gets named after the version ACTUALLY used, with a loud warning, so the
# false-rootkit-findings bug class (stale/mismatched symbols silently reused) fixed
# elsewhere in this script can't reappear through this new path.
# ---------------------------------------------------------------------------
def _fake_apt_with_index(tmp_path, exact_pkg, series_pkgs, fail_pkgs=()):
    """A fake apt-get that serves a Packages index (for the closest-match grep to
    search) on 'update', and fails only on names listed in fail_pkgs on 'download'."""
    fail_list = " ".join(f'"{p}"' for p in fail_pkgs) if fail_pkgs else f'"{exact_pkg}"'
    pkgs_block = "\n".join(f"Package: {p}" for p in series_pkgs)
    script = f'''
lists_dir=""
for a in "$@"; do
    case "$a" in Dir::State::lists=*) lists_dir="${{a#Dir::State::lists=}}" ;; esac
done
if [[ "$*" == *update* ]]; then
    mkdir -p "$lists_dir"
    cat > "${{lists_dir}}/fake_Packages" <<'PKGSEOF'
{pkgs_block}
PKGSEOF
    exit 0
fi
if [[ "$*" == *download* ]]; then
    pkg="${{@: -1}}"
    for f in {fail_list}; do
        if [[ "$pkg" == "$f" ]]; then
            echo "E: Unable to locate package ${{pkg}}" >&2
            exit 100
        fi
    done
    touch "${{pkg}}_1_amd64.ddeb"
    exit 0
fi
exit 0
'''
    return _fake_bin(tmp_path, "apt-get", script)


def _fake_dpkg_deb_writing_vmlinux(tmp_path, vmlinux_name):
    return _fake_bin(tmp_path, "dpkg-deb", f'mkdir -p "$3"; touch "$3/{vmlinux_name}"; exit 0')


def test_allow_closest_symbols_finds_and_uses_closest_available(tmp_path):
    requested = "9.9.9-9-fake"
    exact_pkg = f"linux-image-{requested}-dbgsym"
    series_pkgs = ["linux-image-9.9.9-3-fake-dbgsym", "linux-image-9.9.9-7-fake-dbgsym"]
    fakebin = _fake_apt_with_index(tmp_path, exact_pkg, series_pkgs, fail_pkgs=(exact_pkg,))
    _fake_dpkg_deb_writing_vmlinux(tmp_path, "vmlinux-9.9.9-7-fake")
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}",
          "IR_OS_RELEASE": _osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing")}
    r = subprocess.run(
        ["bash", SCRIPT, "--kernel", requested, "--fetch-symbols", "--allow-closest-symbols"],
        capture_output=True, text=True, env=env, timeout=30)
    assert "using CLOSEST" in r.stderr and "available instead: 9.9.9-7-fake" in r.stderr
    assert "vmlinux-9.9.9-7-fake" in r.stderr           # the SUBSTITUTE vmlinux, not the requested one
    assert "using CLOSEST-AVAILABLE kernel 9.9.9-7-fake in place of requested 9.9.9-9-fake" in r.stderr
    assert "ISF written as 9.9.9-7-fake.json, NOT 9.9.9-9-fake.json" in r.stderr
    assert r.returncode != 3   # got past "no vmlinux acquired" -- acquisition succeeded


def test_closest_symbols_not_used_without_the_flag(tmp_path):
    """Same archive state as above, but --allow-closest-symbols is NOT passed --
    must behave exactly like the pre-existing 'not published' case (no silent
    substitution just because a candidate happens to exist)."""
    requested = "9.9.9-9-fake"
    exact_pkg = f"linux-image-{requested}-dbgsym"
    series_pkgs = ["linux-image-9.9.9-3-fake-dbgsym", "linux-image-9.9.9-7-fake-dbgsym"]
    fakebin = _fake_apt_with_index(tmp_path, exact_pkg, series_pkgs, fail_pkgs=(exact_pkg,))
    _fake_dpkg_deb_writing_vmlinux(tmp_path, "vmlinux-9.9.9-7-fake")
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}",
          "IR_OS_RELEASE": _osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing")}
    r = subprocess.run(["bash", SCRIPT, "--kernel", requested, "--fetch-symbols"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert "using CLOSEST" not in r.stderr
    assert "not published in this distro's archive yet" in r.stderr


def test_allow_closest_symbols_no_candidate_in_series_either(tmp_path):
    """The archive has an index, but nothing in the same kernel series -- must say
    so plainly instead of silently falling through."""
    requested = "9.9.9-9-fake"
    exact_pkg = f"linux-image-{requested}-dbgsym"
    unrelated_pkgs = ["linux-image-5.15.0-3-generic-dbgsym"]
    fakebin = _fake_apt_with_index(tmp_path, exact_pkg, unrelated_pkgs, fail_pkgs=(exact_pkg,))
    _fake_bin(tmp_path, "dpkg-deb", "exit 0")
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}",
          "IR_OS_RELEASE": _osrel(tmp_path, ID="ubuntu", ID_LIKE="debian", VERSION_CODENAME="questing")}
    r = subprocess.run(
        ["bash", SCRIPT, "--kernel", requested, "--fetch-symbols", "--allow-closest-symbols"],
        capture_output=True, text=True, env=env, timeout=30)
    assert "no --allow-closest-symbols candidate found" in r.stderr


def test_btf_note_when_present():
    # On a host with /sys/kernel/btf/vmlinux, the builder must say it can't use BTF.
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return
    env = {**os.environ, "IR_SYMBOLS_PLAN": "1"}
    r = subprocess.run(["bash", SCRIPT, "--kernel", "9.9.9-fake"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert "unusable by dwarf2json" in r.stderr
