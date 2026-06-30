"""P1-5 - every platform's adjudicated findings conform to the canonical schema."""
import json
import os
import subprocess
import sys

import pytest

from conftest import REPORTING, CLOUD_DIR, LINUX_HUNT, newest

sys.path.insert(0, REPORTING)
import finding_schema as fs   # noqa: E402


def test_verdict_ladder_is_canonical():
    assert fs.VERDICTS[0] == "False Positive"
    assert fs.VERDICTS[-1] == "True Positive"
    assert fs.VERDICT_RANK["Likely True Positive"] > fs.VERDICT_RANK["Indeterminate"]


def test_validator_flags_missing_fields():
    errs = fs.validate([{"Target": "x"}])           # no Type, no Verdict
    assert any("Type" in e for e in errs)
    assert any("Verdict" in e for e in errs)


def test_validator_flags_bad_verdict():
    errs = fs.validate([{"Type": "t", "Target": "x", "Verdict": "Maybe"}])
    assert any("not in the canonical ladder" in e for e in errs)


def test_windows_synthetic_conforms(windows_collection):
    adj = newest(windows_collection, "Adjudication_*.json")
    assert fs.validate_file(adj) == []


def test_linux_synthetic_conforms(linux_collection):
    adj = newest(linux_collection, "Adjudication_*.json")
    assert fs.validate_file(adj) == []


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
