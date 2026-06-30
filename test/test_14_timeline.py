"""P3 - automated event timeline distinguishing activity time from detection time."""
import json
import os

import generate_reports as gr


def test_timeline_orders_events_and_labels_kind(tmp_path):
    folder = tmp_path / "host"
    folder.mkdir()
    findings = [
        {"Type": "Hidden Process", "Target": "PID: 2", "Verdict": "Likely True Positive",
         "StartTime": "6/16/2026 1:59:31 PM"},                 # activity time
        {"Type": "Remote Access Tool", "Target": "ScreenConnect", "Verdict": "True Positive",
         "Timestamp": "2026-06-18 12:54:20"},                  # detection time only
    ]
    (folder / "Adjudication_1.json").write_text(json.dumps(findings))
    res = gr.generate(str(folder), incident_id="T")
    assert os.path.isfile(res["timeline"])
    tl = open(res["timeline"], encoding="utf-8").read()
    assert "Event Timeline" in tl
    assert "activity" in tl and "detection" in tl
    # earliest event (2026-06-16 activity) must appear before the 2026-06-18 detection row
    assert tl.index("2026-06-16") < tl.index("2026-06-18")


def test_timeline_handles_no_timestamps(windows_collection):
    """Synthetic windows adjudication has no times -> timeline flags the gap, no crash."""
    res = gr.generate(windows_collection, incident_id="WIN")
    tl = open(res["timeline"], encoding="utf-8").read()
    assert "could not be built" in tl


def test_timeline_built_for_timestamped_findings(linux_collection):
    """The linux fixture carries Timestamp fields -> a real timeline table is produced."""
    res = gr.generate(linux_collection, incident_id="LIN")
    tl = open(res["timeline"], encoding="utf-8").read()
    assert "| Time | Kind | Type | Target | Verdict |" in tl
