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
