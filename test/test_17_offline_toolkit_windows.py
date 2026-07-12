"""Third-party tooling is accounted for in the Windows offline-toolkit builder."""
import os

from conftest import ROOT, IRCOLLECT_PS1, read_text

BUILD_PS1 = os.path.join(ROOT, "Build-OfflineToolkit.ps1")


def test_windows_builder_accounts_for_its_tools():
    src = read_text(BUILD_PS1)
    for tool in ("Autoruns", "WinPmem", "LOLDrivers", "Sigcheck"):
        assert tool in src, f"Windows builder does not account for {tool}"


def test_memory_capture_wired_windows():
    src = read_text(IRCOLLECT_PS1)
    assert "-CaptureMemory" in src       # Windows (winpmem)
    assert "tools\\winpmem.exe" in src
