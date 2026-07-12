"""Single-run Linux memory-analysis orchestrator (Analyze-Memory-Linux.sh).

Validates arg handling, the INVALID_-image guard, the dry-run plan, and that the
teardown trap fires — without standing up a real venv/Volatility (that's the live step).
"""
import os
import subprocess

from conftest import ROOT

SCRIPT = os.path.join(ROOT, "playbooks", "linux", "threat_hunting", "Analyze-Memory-Linux.sh")


def _run(args):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=30)


def test_dry_run_prints_plan_and_teardown(tmp_path):
    img = tmp_path / "memory_host.raw"
    img.write_bytes(b"\0" * 16)
    r = _run(["--image", str(img), "--host-folder", str(tmp_path), "--yara",
              "--adjudicate", "--dry-run"])
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "DRY RUN" in out
    assert "venv" in out and "volatility3" in out          # step 1
    assert "Build-LinuxSymbols.sh" in out                  # step 2
    assert "analyze_memory_linux.py" in out and "--yara" in out  # step 3
    assert "Combined_Findings" in out                      # step 4 (adjudicate)
    assert "torn down" in out                               # teardown trap fired
    assert "Memory_Findings_" in out                       # emitted output path


def test_refuses_invalid_image(tmp_path):
    bad = tmp_path / "INVALID_memory_host.raw"
    bad.write_bytes(b"x")
    r = _run(["--image", str(bad)])
    assert r.returncode == 2 and "INVALID_" in r.stderr


def test_missing_image(tmp_path):
    r = _run(["--image", str(tmp_path / "nope.raw")])
    assert r.returncode == 2 and "not found" in r.stderr


def test_requires_image():
    r = _run([])
    assert r.returncode == 2 and "--image required" in r.stderr


# ---------------------------------------------------------------------------
# _resolve_staged_symbols() -- kernel-version match check. Real bug caught live:
# this used to accept ANY staged ISF regardless of kernel version (a box patched
# since symbols were last staged silently got analyzed with the WRONG kernel's
# symbol table), producing dozens of false rootkit-shaped findings (check_syscall/
# check_afinfo/hidden-process) with no error -- struct-layout plugins (pslist/
# malfind) mostly still worked since layouts are stable across point releases, so
# nothing about the run looked obviously broken.
# ---------------------------------------------------------------------------
def _resolve(staged_dir, kernel):
    # Source only the function definition by extracting it, not the whole script
    # (the whole script requires --image etc. and would exit early).
    r = subprocess.run(
        ["bash", "-c",
         f'source <(sed -n "/^_resolve_staged_symbols()/,/^}}/p" "{SCRIPT}") && '
         f'_resolve_staged_symbols "{staged_dir}" "{kernel}"'],
        capture_output=True, text=True, timeout=10)
    lines = r.stdout.splitlines()
    return (lines[0] if len(lines) > 0 else ""), (lines[1] if len(lines) > 1 else "")


def test_resolve_staged_symbols_exact_match(tmp_path):
    staged = tmp_path / "symbols"
    (staged / "linux").mkdir(parents=True)
    (staged / "linux" / "6.17.0-40-generic.json").write_text("{}")
    symbols, stale = _resolve(str(staged), "6.17.0-40-generic")
    assert symbols == str(staged)
    assert stale == ""


def test_resolve_staged_symbols_version_mismatch_ignored(tmp_path):
    staged = tmp_path / "symbols"
    (staged / "linux").mkdir(parents=True)
    (staged / "linux" / "6.17.0-35-generic.json").write_text("{}")
    symbols, stale = _resolve(str(staged), "6.17.0-40-generic")
    assert symbols == ""                    # the mismatched ISF must NOT be used
    assert stale == "6.17.0-35-generic.json"  # but its presence is reported


def test_resolve_staged_symbols_nothing_staged(tmp_path):
    staged = tmp_path / "symbols"
    symbols, stale = _resolve(str(staged), "6.17.0-40-generic")
    assert symbols == "" and stale == ""


# ---------------------------------------------------------------------------
# --kernel default warning + --identify-kernel. Real gap found live: in real IR
# work the analyst machine and the compromised host are essentially always
# different systems (you never fetch/build anything ON a system under
# investigation), so --kernel's default (this machine's own `uname -r`) is very
# often wrong for a real target image -- confirmed live: it silently analyzed a
# fresh capture with the wrong kernel's symbols with no error at all.
# ---------------------------------------------------------------------------
def test_warns_when_kernel_not_explicit(tmp_path):
    img = tmp_path / "memory_host.raw"
    img.write_bytes(b"\0" * 16)
    r = _run(["--image", str(img), "--host-folder", str(tmp_path), "--dry-run"])
    assert "kernel not given" in r.stdout.lower() or "kernel not given" in r.stderr.lower()


def test_no_warning_when_kernel_explicit(tmp_path):
    img = tmp_path / "memory_host.raw"
    img.write_bytes(b"\0" * 16)
    r = _run(["--image", str(img), "--host-folder", str(tmp_path), "--kernel", "5.4.0-fake", "--dry-run"])
    assert "kernel not given" not in r.stdout.lower() and "kernel not given" not in r.stderr.lower()


# ---------------------------------------------------------------------------
# _sort_banners_by_offset() -- banners.Banners' offsets are hex strings; a plain
# `sort` is lexicographic, not numeric, and gets the wrong order once offsets have
# different digit counts. Real live data (a captured image with a stale cached
# kernel-version string alongside the genuine running kernel's banner) confirmed
# the running kernel's banner sits at the LOWEST offset -- the heuristic this
# function's ordering exists to support.
# ---------------------------------------------------------------------------
def _sort_banners(rows):
    r = subprocess.run(
        ["bash", "-c",
         f'source <(sed -n "/^_sort_banners_by_offset()/,/^}}/p" "{SCRIPT}") && _sort_banners_by_offset'],
        input="\n".join(rows) + "\n", capture_output=True, text=True, timeout=10)
    return r.stdout.splitlines()


def test_sort_banners_orders_numerically_not_lexicographically(tmp_path):
    rows = [
        "0x5e62fcebe\tLinux version 6.17.0-35-generic (stale, higher offset)",
        "0x4d96000e0\tLinux version 6.17.0-40-generic (genuine, lowest offset)",
        "0x5c86bbbbc\tLinux version 2.2.5-15smp (unrelated garbage match)",
    ]
    out = _sort_banners(rows)
    assert out[0].startswith("0x4d96000e0")     # lowest offset first
    assert out[-1].startswith("0x5e62fcebe")    # highest offset last


def test_sort_banners_handles_different_digit_counts(tmp_path):
    """The bug a naive lexicographic sort would hit: '0x999' vs '0x1000' -- fewer
    hex digits does not mean a smaller numeric value in general."""
    rows = ["0x100000\tsecond", "0x99\tfirst"]
    out = _sort_banners(rows)
    assert out[0].startswith("0x99\t")
    assert out[1].startswith("0x100000\t")
