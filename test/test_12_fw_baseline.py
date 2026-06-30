"""P0-1 - containment baseline is first-write-wins (double-run cannot corrupt known-good)."""
import os
import subprocess

from conftest import PLAYBOOKS, IRCOLLECT_PS1, FIREWALL_PS1, read_text

FW_LIB = os.path.join(PLAYBOOKS, "lib", "fw_baseline.sh")


def _record(marker, candidate):
    script = f'source "$1"; ir_baseline_record "$2" "$3"'
    r = subprocess.run(["bash", "-c", script, "_", FW_LIB, str(marker), candidate],
                       capture_output=True, text=True, timeout=30)
    return r.stdout


def test_first_write_records_candidate(tmp_path):
    marker = tmp_path / "baseline.txt"
    out = _record(marker, "/backups/FW_State_first.wfw")
    assert out == "/backups/FW_State_first.wfw"
    assert marker.read_text() == "/backups/FW_State_first.wfw"


def test_second_run_reuses_original_baseline(tmp_path):
    """A re-run must NOT overwrite the recorded known-good with the locked-down state."""
    marker = tmp_path / "baseline.txt"
    _record(marker, "/backups/FW_State_first.wfw")           # run 1: pre-incident state
    out = _record(marker, "/backups/FW_State_LOCKED.wfw")    # run 2: already isolated
    assert out == "/backups/FW_State_first.wfw"              # original wins
    assert marker.read_text() == "/backups/FW_State_first.wfw"


def test_enforce_script_guards_baseline():
    """Enforce-StrictFirewall reuses an existing baseline instead of re-exporting."""
    src = read_text(FIREWALL_PS1)
    assert "baseline.txt" in src
    assert "REUSING known-good" in src or "not re-exporting" in src.lower()


def test_orchestrator_reads_baseline_marker_not_newest():
    """The orchestrator records the baseline pointer, not the newest .wfw."""
    src = read_text(IRCOLLECT_PS1)
    assert "baseline.txt" in src
    # the buggy 'newest FW_State_*.wfw' selection must be gone from the lockdown phase
    assert "FIRST-WRITE-WINS" in src.upper() or "first-write-wins" in src
