"""Section 5 - restoration (Linux): the sha256-verified rollback contract, un-isolation via
iptables backup."""
from conftest import RESTORE_SH, read_text


def test_linux_restore_script_verifies_hash():
    src = read_text(RESTORE_SH)
    assert "sha256" in src.lower()
    assert "iptables-restore" in src               # un-isolate via iptables backup
    assert "rollback" in src.lower()
