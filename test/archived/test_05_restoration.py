"""Section 5 - restoration: sha256-verified rollback of quarantined files; firewall un-isolation wiring."""
import os

import workflow_sim as sim
from conftest import RESTORE_PS1, RESTORE_SH, read_text


def test_restore_round_trip(tmp_path):
    """Quarantine then restore returns the file to its original path."""
    victim = tmp_path / "dir" / "evil.exe"
    victim.parent.mkdir()
    victim.write_bytes(b"payload-bytes")
    journal = tmp_path / "rollback.jsonl"

    sim.quarantine(str(victim), str(tmp_path / "Q"), str(journal))
    assert not victim.exists()

    restored, skipped = sim.restore(str(journal))
    assert str(victim) in restored
    assert victim.exists()
    assert victim.read_bytes() == b"payload-bytes"
    assert skipped == []


def test_restore_refuses_tampered_bytes(tmp_path):
    """A quarantined file whose bytes changed must NOT be restored."""
    victim = tmp_path / "evil.exe"
    victim.write_bytes(b"original")
    journal = tmp_path / "rollback.jsonl"
    entry = sim.quarantine(str(victim), str(tmp_path / "Q"), str(journal))

    with open(entry["dest"], "wb") as fh:          # tamper after quarantine
        fh.write(b"swapped-malicious")

    restored, skipped = sim.restore(str(journal))
    assert restored == []
    assert str(victim) in skipped
    assert not victim.exists()                     # left in quarantine, not restored


# -- Restoration scripts wire the same sha256-verified contract -----------------
def test_windows_restore_script_verifies_hash():
    src = read_text(RESTORE_PS1)
    assert "Get-FileHash" in src
    assert "sha256" in src.lower()
    assert "advfirewall import" in src             # un-isolate via firewall backup
    assert "rollback" in src.lower()


def test_linux_restore_script_verifies_hash():
    src = read_text(RESTORE_SH)
    assert "sha256" in src.lower()
    assert "iptables-restore" in src               # un-isolate via iptables backup
    assert "rollback" in src.lower()
