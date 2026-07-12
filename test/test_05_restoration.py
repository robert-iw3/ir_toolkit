"""Section 5 - restoration: sha256-verified rollback of quarantined files (platform-agnostic
simulation logic; see test_05_restoration_windows.py / test_05_restoration_linux.py for the
per-platform script wiring)."""
import workflow_sim as sim


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
