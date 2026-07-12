"""P1-5 - Cloud adjudicator output conforms to the canonical schema."""
import json
import os
import subprocess
import sys

from conftest import REPORTING, CLOUD_DIR

sys.path.insert(0, REPORTING)
import finding_schema as fs   # noqa: E402


def test_cloud_adjudicator_output_conforms(tmp_path):
    adj = os.path.join(CLOUD_DIR, "adjudicate_cloud.py")
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "guardduty_findings.json").write_text(json.dumps(
        {"Findings": [{"Title": "T", "Severity": 8, "Description": "d"}]}))
    out = tmp_path / "Combined.json"
    subprocess.run([sys.executable, adj, "--forensics-dir", str(fz), "--out", str(out),
                    "--provider", "aws", "--c2-ips", "1.2.3.4"], timeout=60, check=True)
    assert fs.validate_file(str(out)) == []
