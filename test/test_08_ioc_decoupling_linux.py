"""P0-2 - IOC emission belongs to the analysis stage, not reporting (Linux orchestrator)."""
from conftest import IRCOLLECT_SH, read_text


def test_linux_orchestrator_emits_iocs_before_reporting():
    """The Linux collection orchestrator runs the IOC analysis phase ahead of reporting."""
    lin = read_text(IRCOLLECT_SH)
    assert "build_iocs.py" in lin
    assert lin.index("build_iocs.py") < lin.index("generate_reports.py")
