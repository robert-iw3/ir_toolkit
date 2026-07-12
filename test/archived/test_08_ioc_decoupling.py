"""P0-2 - IOC emission belongs to the analysis stage, not reporting."""
import json
import os

import generate_reports as gr
from conftest import REPORTING, IRCOLLECT_PS1, IRCOLLECT_SH, read_text, run_py


def test_emit_iocs_standalone(windows_collection):
    """emit_iocs writes IOCs.json without any report being generated."""
    path = gr.emit_iocs(windows_collection, "WIN")
    assert os.path.basename(path) == "IOCs.json"
    files = os.listdir(windows_collection)
    assert "IOCs.json" in files
    assert "Incident_Report.md" not in files      # reports NOT generated
    assert "Attack_Graph.md" not in files
    iocs = json.load(open(path))
    assert iocs["c2_endpoints"][0]["host"] == "relay.example-c2.test"


def test_build_iocs_cli(windows_collection):
    cli = os.path.join(REPORTING, "build_iocs.py")
    r = run_py(cli, "--host-folder", windows_collection, "--incident-id", "WIN")
    assert r.returncode == 0, r.stderr
    assert os.path.isfile(os.path.join(windows_collection, "IOCs.json"))


def test_iocs_match_full_report(windows_collection):
    """Standalone IOCs and the report's IOCs are byte-identical (no drift)."""
    gr.emit_iocs(windows_collection, "WIN")
    standalone = json.load(open(os.path.join(windows_collection, "IOCs.json")))
    gr.generate(windows_collection, incident_id="WIN")     # overwrites via same path
    from_report = json.load(open(os.path.join(windows_collection, "IOCs.json")))
    assert standalone["c2_endpoints"] == from_report["c2_endpoints"]
    assert standalone["file_hashes_sha256"] == from_report["file_hashes_sha256"]


def test_orchestrators_emit_iocs_before_reporting():
    """All collection orchestrators run the IOC analysis phase ahead of reporting."""
    lin = read_text(IRCOLLECT_SH)
    assert "build_iocs.py" in lin
    assert lin.index("build_iocs.py") < lin.index("generate_reports.py")
    win = read_text(IRCOLLECT_PS1)
    assert "-IocsOnly" in win
    assert win.index("IOCs (analysis hand-off)") < win.index("Reporting (Incident_Report")
