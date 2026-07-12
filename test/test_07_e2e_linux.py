"""Section 7 - end-to-end (Linux): full lifecycle (collection -> analysis -> report ->
eradication -> restoration)."""
import json
import os
import subprocess
import sys

import pytest

import generate_reports as gr
import workflow_sim as sim
from conftest import LINUX_HUNT, newest, load_json_bom


def test_linux_full_lifecycle(tmp_path):
    """Real Linux pipeline: hunt -> merge -> adjudicate -> report -> eradicate -> restore."""
    scripts = {n: os.path.join(LINUX_HUNT, n) for n in
               ("edr_hunt.py", "remote_access_triage.py", "adjudicate.py")}
    if not all(os.path.isfile(s) for s in scripts.values()):
        pytest.skip("linux hunt/adjudicate scripts not present")

    out = tmp_path / "host"
    out.mkdir()

    # 1. COLLECTION / deeper analysis - run the live read-only hunters.
    subprocess.run([sys.executable, scripts["edr_hunt.py"], "--report-dir", str(out),
                    "--stamp", "e2e", "--quiet"], timeout=120)
    subprocess.run([sys.executable, scripts["remote_access_triage.py"], "--report-dir",
                    str(out), "--stamp", "e2e", "--quiet"], timeout=120)
    assert (out / "EDR_Report_e2e.json").exists()
    assert (out / "RemoteAccess_Findings_e2e.json").exists()

    # Merge live findings + one controllable malicious finding so the chain always
    # has something actionable to eradicate and restore.
    victim = out / "payload"
    victim.write_bytes(b"e2e-malware")
    merged = []
    for p in (out / "EDR_Report_e2e.json", out / "RemoteAccess_Findings_e2e.json"):
        merged += json.loads(p.read_text())
    merged.append({"Type": "Hidden Process", "Target": "PID: 424242",
                   "Details": "synthetic e2e finding", "MITRE": "T1014",
                   "SubjectPath": str(victim)})
    combined = out / "Combined_Findings_e2e.json"
    combined.write_text(json.dumps(merged))

    # 2. ANALYSIS - adjudicate.
    subprocess.run([sys.executable, scripts["adjudicate.py"], "--host-folder", str(out),
                    "--report", str(combined), "--stamp", "e2e"], timeout=180)
    adj = newest(str(out), "Adjudication_*.json")
    assert adj, "adjudication did not run"
    assert all(f.get("Verdict") for f in load_json_bom(adj))

    # 3. REPORTING.
    res = gr.generate(str(out), incident_id="LIN_E2E")
    for key in ("incident_report", "attack_graph", "retrospective", "iocs"):
        assert os.path.isfile(res[key])

    # 4. ERADICATION - quarantine the malicious file with a rollback journal.
    journal = out / "rollback.jsonl"
    sim.quarantine(str(victim), str(out / "Quarantine"), str(journal))
    assert not victim.exists()

    # 5. RESTORATION - sha256-verified rollback.
    restored, skipped = sim.restore(str(journal))
    assert str(victim) in restored
    assert victim.exists() and victim.read_bytes() == b"e2e-malware"
