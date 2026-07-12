"""P0 #1 - credential/session revocation: Windows-native eradication + orchestrator wiring."""
import os

from conftest import REPORTING, IRCOLLECT_PS1, ERADICATE_PS1, read_text


def test_windows_orchestrator_emits_principals():
    win = read_text(IRCOLLECT_PS1)
    assert "-PrincipalsOnly" in win                          # Windows native, no python
    assert "extract_principals.py" not in win


def test_windows_eradication_revokes_credentials_natively():
    src = read_text(ERADICATE_PS1)
    assert "Principals.json" in src
    assert "Disable-LocalUser" in src
    assert "klist purge" in src
    assert "disable_account" in src                          # journaled (reversible)
    assert "$env:USERNAME" in src                            # never disable the responder


def test_windows_collection_no_python_dependency():
    """Windows orchestrator + native generator must not invoke python or .py scripts."""
    orch = read_text(IRCOLLECT_PS1)
    assert ".py" not in orch                            # orchestrator references no python scripts
    for src in (orch, read_text(os.path.join(REPORTING, "generate_reports.ps1"))):
        assert "Get-Command python" not in src          # no python executable lookup
        assert "python.exe" not in src
        assert "-File" not in src or ".py" not in src.split("-File", 1)[-1][:40]  # no -File *.py invocation
