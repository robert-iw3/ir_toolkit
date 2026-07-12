"""P0-2 - IOC emission belongs to the analysis stage, not reporting.

Platform-agnostic: generate_reports.py's IOC-emission logic runs against a mock collection
folder (windows_collection is just a synthetic fixture, not real Windows tooling). See
test_08_ioc_decoupling_windows.py / _linux.py for the per-platform orchestrator wiring check.
"""
import json
import os

import generate_reports as gr
from conftest import REPORTING, run_py


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
