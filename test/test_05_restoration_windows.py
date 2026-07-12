"""Section 5 - restoration (Windows): the sha256-verified rollback contract, un-isolation via
firewall backup."""
from conftest import RESTORE_PS1, read_text


def test_windows_restore_script_verifies_hash():
    src = read_text(RESTORE_PS1)
    assert "Get-FileHash" in src
    assert "sha256" in src.lower()
    assert "advfirewall import" in src             # un-isolate via firewall backup
    assert "rollback" in src.lower()
