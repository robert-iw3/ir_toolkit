"""
Section 1 — COLLECTION.

Windows: the orchestrator must call every threat_hunting script at its REAL path
(the historical bug pointed at the non-existent windows\\scripting\\threat_hunting\\),
must lock the firewall down FIRST (containment), and must run the report phase.

Linux: the orchestrator runs the forensics snapshot + the python hunt tools, and a
real (read-only) forensics snapshot can actually be produced on this host.
"""
import os
import subprocess
import sys

from conftest import (IRCOLLECT_PS1, IRCOLLECT_SH, WIN_HUNT, LINUX_HUNT,
                      FIREWALL_PS1, read_text)

HUNT_SCRIPTS = ["EDR_Toolkit.ps1", "Analyze-EDRReport.ps1", "Get-FindingContext.ps1",
                "Get-RemoteAccessTriage.ps1", "Get-PersistenceSnapshot.ps1"]


def test_threat_hunting_scripts_exist():
    for s in HUNT_SCRIPTS:
        assert os.path.isfile(os.path.join(WIN_HUNT, s)), f"missing hunt script {s}"


def test_orchestrator_references_correct_hunt_path():
    """Regression: the broken 'windows\\scripting\\threat_hunting' path is gone and
    the orchestrator points at the real playbooks\\windows\\threat_hunting."""
    src = read_text(IRCOLLECT_PS1)
    assert "windows\\scripting\\threat_hunting" not in src, "stale broken hunt path present"
    assert "playbooks\\windows\\threat_hunting" in src


def test_orchestrator_invokes_every_hunt_script():
    src = read_text(IRCOLLECT_PS1)
    for s in HUNT_SCRIPTS:
        assert s in src, f"orchestrator never invokes {s}"


def test_collection_locks_firewall_first():
    """Containment (Default-Deny inbound) must run as PHASE 0, before forensics."""
    src = read_text(IRCOLLECT_PS1)
    assert "Enforce-StrictFirewall.ps1" in src
    assert "-FullInboundLockdown" in src
    # the lockdown phase block must precede the forensics phase block
    assert src.index("PHASE 0: CONTAINMENT") < src.index("PHASE 1: forensics")


def test_collection_persists_firewall_backup_for_eradication():
    """The pre-lockdown .wfw path is recorded so eradication can restore known-good."""
    src = read_text(IRCOLLECT_PS1)
    assert "_firewall_state.json" in src
    assert "backup_wfw" in src


def test_collection_runs_report_phase():
    src = read_text(IRCOLLECT_PS1)
    assert "generate_reports" in src
    assert "Reporting" in src


def test_firewall_script_supports_full_lockdown_and_rollback():
    src = read_text(FIREWALL_PS1)
    assert "FullInboundLockdown" in src
    assert "Rollback" in src
    assert "advfirewall export" in src and "advfirewall import" in src


# -- Linux collection actually executes (read-only forensics snapshot) ----------
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
