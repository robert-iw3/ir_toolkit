"""Section 2 - adjudication: every finding gets a verdict; signed RATs are not cleared on signature."""
import json
import os
import subprocess
import sys
from collections import Counter

from conftest import LINUX_HUNT, load_json_bom, newest

TP_CLASS = ("True Positive", "Likely True Positive")


def test_synthetic_windows_funnel(windows_collection):
    data = load_json_bom(newest(windows_collection, "Adjudication_*.json"))
    funnel = Counter(x["Verdict"] for x in data)
    assert funnel["False Positive"] == 4
    assert funnel["Likely False Positive"] == 2
    assert funnel["Indeterminate"] == 1
    assert funnel["Likely True Positive"] == 3


def test_signed_rat_still_true_positive(windows_collection):
    """A validly-signed remote-access tool must still reach true-positive class."""
    data = load_json_bom(newest(windows_collection, "Adjudication_*.json"))
    rat = [x for x in data if x["Type"] == "Remote Access Tool"][0]
    assert rat["SigStatus"] == "Valid"
    assert rat["Verdict"] in TP_CLASS


def test_every_finding_has_a_verdict(windows_collection):
    data = load_json_bom(newest(windows_collection, "Adjudication_*.json"))
    for f in data:
        assert f.get("Verdict") and f.get("Confidence")


def test_linux_adjudication_runs_live(tmp_path):
    """adjudicate.py runs on freshly-merged live hunt output and verdicts every finding."""
    scripts = [os.path.join(LINUX_HUNT, s) for s in
               ("edr_hunt.py", "remote_access_triage.py", "adjudicate.py")]
    if not all(os.path.isfile(s) for s in scripts):
        import pytest
        pytest.skip("linux hunt/adjudicate scripts not present")
    edr, ra, adj = scripts

    subprocess.run([sys.executable, edr, "--report-dir", str(tmp_path), "--stamp", "t", "--quiet"], timeout=120)
    subprocess.run([sys.executable, ra, "--report-dir", str(tmp_path), "--stamp", "t", "--quiet"], timeout=120)
    merged = []
    for p in (tmp_path / "EDR_Report_t.json", tmp_path / "RemoteAccess_Findings_t.json"):
        if p.exists():
            merged += json.loads(p.read_text())
    combined = tmp_path / "Combined_Findings_t.json"
    combined.write_text(json.dumps(merged))
    if not merged:
        import pytest
        pytest.skip("no findings on this host to adjudicate")

    subprocess.run([sys.executable, adj, "--host-folder", str(tmp_path),
                    "--report", str(combined), "--stamp", "t"], timeout=180)
    produced = newest(str(tmp_path), "Adjudication_*.json")
    assert produced
    for f in load_json_bom(produced):
        assert f.get("Verdict")
