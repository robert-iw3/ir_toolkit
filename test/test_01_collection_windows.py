"""
Section 1 — COLLECTION (Windows).

The orchestrator must call every threat_hunting script at its REAL path (the
historical bug pointed at the non-existent windows\\scripting\\threat_hunting\\),
must lock the firewall down FIRST (containment), and must run the report phase.
"""
import os

from conftest import IRCOLLECT_PS1, WIN_HUNT, FIREWALL_PS1, read_text

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
