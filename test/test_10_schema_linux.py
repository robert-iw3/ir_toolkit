"""P1-5 - Linux synthetic + live adjudication output conforms to the canonical schema."""
import json
import os
import subprocess
import sys

import pytest

from conftest import REPORTING, LINUX_HUNT, newest

sys.path.insert(0, REPORTING)
import finding_schema as fs   # noqa: E402


def test_linux_synthetic_conforms(linux_collection):
    adj = newest(linux_collection, "Adjudication_*.json")
    assert fs.validate_file(adj) == []


def test_linux_live_adjudication_conforms(tmp_path):
    """Real Linux adjudicator output also satisfies the canonical schema."""
    edr = os.path.join(LINUX_HUNT, "edr_hunt.py")
    adj = os.path.join(LINUX_HUNT, "adjudicate.py")
    if not (os.path.isfile(edr) and os.path.isfile(adj)):
        pytest.skip("linux scripts not present")
    subprocess.run([sys.executable, edr, "--report-dir", str(tmp_path), "--stamp", "s", "--quiet"], timeout=120)
    edr_json = tmp_path / "EDR_Report_s.json"
    findings = json.loads(edr_json.read_text()) if edr_json.exists() else []
    combined = tmp_path / "Combined_Findings_s.json"
    combined.write_text(json.dumps(findings))
    if not findings:
        pytest.skip("no live findings to adjudicate")
    subprocess.run([sys.executable, adj, "--host-folder", str(tmp_path),
                    "--report", str(combined), "--stamp", "s"], timeout=180)
    produced = newest(str(tmp_path), "Adjudication_*.json")
    assert fs.validate_file(produced) == []
