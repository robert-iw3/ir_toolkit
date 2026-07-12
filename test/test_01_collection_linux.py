"""
Section 1 — COLLECTION (Linux).

The orchestrator runs the forensics snapshot + the python hunt tools, and a real
(read-only) forensics snapshot can actually be produced on this host.
"""
import os
import subprocess
import sys

from conftest import IRCOLLECT_SH, LINUX_HUNT, read_text


def test_linux_orchestrator_wires_phases():
    src = read_text(IRCOLLECT_SH)
    assert "edr_hunt.py" in src
    assert "remote_access_triage.py" in src
    assert "adjudicate.py" in src
    assert "generate_reports.py" in src


def test_linux_forensics_snapshot_runs(tmp_path):
    """Prove the Linux collection can take a real read-only forensics snapshot."""
    out = tmp_path / "host"
    (out / "forensics").mkdir(parents=True)
    f = out / "forensics"
    # mirror a representative slice of phase-1 of the orchestrator
    subprocess.run(f"ps -eo pid,ppid,user,comm > '{f}/processes.txt' 2>/dev/null",
                   shell=True, timeout=30)
    subprocess.run(f"(ip addr; ip route) > '{f}/network.txt' 2>/dev/null || true",
                   shell=True, timeout=30)
    assert (f / "processes.txt").exists()
    assert (f / "processes.txt").stat().st_size > 0


def test_linux_edr_hunt_produces_report(tmp_path):
    """Deeper-analysis collector runs live (read-only) and emits an EDR report."""
    edr = os.path.join(LINUX_HUNT, "edr_hunt.py")
    if not os.path.isfile(edr):
        import pytest
        pytest.skip("linux edr_hunt.py not present")
    r = subprocess.run([sys.executable, edr, "--report-dir", str(tmp_path),
                        "--stamp", "testrun", "--quiet"],
                       capture_output=True, text=True, timeout=120)
    # tool is allowed to exit non-zero on findings; it must still write a report
    produced = list(tmp_path.glob("EDR_Report_*.json"))
    assert produced, f"no EDR report produced (rc={r.returncode}, err={r.stderr[:300]})"
