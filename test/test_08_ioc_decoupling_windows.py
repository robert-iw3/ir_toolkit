"""P0-2 - IOC emission belongs to the analysis stage, not reporting (Windows orchestrator)."""
from conftest import IRCOLLECT_PS1, read_text


def test_windows_orchestrator_emits_iocs_before_reporting():
    """The Windows collection orchestrator runs the IOC analysis phase ahead of reporting."""
    win = read_text(IRCOLLECT_PS1)
    assert "-IocsOnly" in win
    assert win.index("IOCs (analysis hand-off)") < win.index("Reporting (Incident_Report")
