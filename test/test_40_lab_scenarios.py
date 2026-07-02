"""Cloud-IR lab: drive the REAL collection->adjudication->reporting workflow against a
scenario-seeded mock environment (no provider calls, no charges) and prove each attack is
detected, adjudicated on the right ATT&CK technique/verdict, and mapped on the coverage grid.

Each scenario in test/lab/scenarios/*.json defines the telemetry an attack would leave and an
`expect` block. Adding a scenario file automatically adds a validated case here - this is the
regression harness for refining detection logic before touching a real environment.
"""
import glob
import json
import os
import subprocess

import pytest

from conftest import IRCOLLECT_CLOUD_SH

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab")
MOCK_ENV = os.path.join(LAB, "mock_env")
SCENARIOS = sorted(glob.glob(os.path.join(LAB, "scenarios", "*.json")))

VERDICT_RANK = {"False Positive": 0, "Likely False Positive": 1, "Indeterminate": 2,
                "Likely True Positive": 3, "True Positive": 4}


def _ids(path):
    return os.path.splitext(os.path.basename(path))[0]


@pytest.mark.parametrize("scenario_path", SCENARIOS, ids=[_ids(p) for p in SCENARIOS])
def test_lab_scenario_is_detected_and_adjudicated(scenario_path, tmp_path):
    scn = json.load(open(scenario_path, encoding="utf-8"))
    provider = scn["provider"]
    coll = scn.get("collect", {})
    expect = scn["expect"]

    env = dict(os.environ)
    env["PATH"] = MOCK_ENV + os.pathsep + env.get("PATH", "")
    env["IR_LAB_SCENARIO"] = scenario_path
    env["IR_MOCK_LOG"] = str(tmp_path / "calls.log")
    # provider context the collectors expect (values are irrelevant to the mock)
    env.update({"IR_AZURE_SUBSCRIPTION": "lab-sub", "IR_AZURE_RESOURCE_GROUP": "lab-rg",
                "IR_GCP_PROJECT": "lab-proj", "IR_AWS_REGION": "us-east-1",
                "IR_S3_DATAEVENT_LOG_GROUP": "ir-s3-dataevents"})

    out_root = tmp_path / "proj"
    out_root.mkdir()
    cmd = ["bash", IRCOLLECT_CLOUD_SH, "--provider", provider,
           "--target", coll.get("target", "10.0.0.5"),
           "--incident-id", scn["name"], "--output-root", str(out_root)]
    if coll.get("c2_ips"):
        cmd += ["--c2-ips", coll["c2_ips"]]
    if coll.get("c2_domains"):
        cmd += ["--c2-domains", coll["c2_domains"]]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr

    host = next(out_root.glob(f"{provider}-*"))
    findings = json.loads(next(host.glob("Combined_Findings_*.json")).read_text())

    # clean-tenant scenario: benign baseline only, must produce NO true-positive-class finding
    if expect.get("no_true_positive"):
        tp = [(f["Type"], f["Target"]) for f in findings
              if VERDICT_RANK.get(f.get("Verdict"), 0) >= 3]
        assert not tp, f"{scn['name']}: clean-tenant baseline produced true-positive-class: {tp}"
        return

    # 1. every expected finding TYPE was produced
    types_seen = {f["Type"] for f in findings}
    for t in expect.get("types", []):
        assert t in types_seen, f"{scn['name']}: missing finding type {t!r} (saw {types_seen})"

    # 2. at least one expected ATT&CK technique appears
    mitre_blob = " ".join(f.get("MITRE", "") for f in findings)
    if expect.get("mitre_any"):
        assert any(m in mitre_blob for m in expect["mitre_any"]), \
            f"{scn['name']}: none of {expect['mitre_any']} in findings"

    # 3. the adjudicated severity reaches the expected floor
    floor = VERDICT_RANK[expect["min_verdict"]]
    assert max((VERDICT_RANK.get(f.get("Verdict"), 0) for f in findings), default=0) >= floor, \
        f"{scn['name']}: no finding reached {expect['min_verdict']}"

    # 4. the full pipeline ran - report + coverage grid mark the expected tactics
    assert (host / "Incident_Report.md").exists()
    coverage = next(host.glob("Attack_Coverage_*.md")).read_text()
    for tactic in expect.get("tactics", []):
        assert f"| {tactic} | ✅" in coverage, \
            f"{scn['name']}: tactic {tactic!r} not marked covered in the ATT&CK grid"


def test_lab_has_scenarios_for_every_provider():
    provs = {json.load(open(p, encoding="utf-8"))["provider"] for p in SCENARIOS}
    assert {"aws", "azure", "gcp"} <= provs, f"lab missing provider coverage: {provs}"


# Every finding TYPE the cloud workflow can emit from attack telemetry. The lab must
# exercise each - if a new detection type is added, add a covering scenario (or extend one).
_DETECTION_CATALOG = {
    "Cloud Control-Plane Activity", "Cloud Detection", "Cloud Exposure", "Cloud IAM Posture",
    "Cloud OAuth Consent Grant", "Cloud Inbox Forwarding Rule", "Cloud Identity Audit",
    "Cloud Identity Risk", "Cloud Sign-In", "Cloud Network Flow to C2", "Cloud C2 Beacon",
    "Cloud Data Exfiltration"}


def _collect_scenario(scenario_path, workdir):
    scn = json.load(open(scenario_path, encoding="utf-8"))
    provider = scn["provider"]
    coll = scn.get("collect", {})
    env = dict(os.environ)
    env["PATH"] = MOCK_ENV + os.pathsep + env.get("PATH", "")
    env["IR_LAB_SCENARIO"] = scenario_path
    env.update({"IR_AZURE_SUBSCRIPTION": "lab-sub", "IR_AZURE_RESOURCE_GROUP": "lab-rg",
                "IR_GCP_PROJECT": "lab-proj", "IR_AWS_REGION": "us-east-1",
                "IR_S3_DATAEVENT_LOG_GROUP": "ir-s3-dataevents"})
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = ["bash", IRCOLLECT_CLOUD_SH, "--provider", provider,
           "--target", coll.get("target", "10.0.0.5"),
           "--incident-id", scn["name"], "--output-root", str(workdir)]
    if coll.get("c2_ips"):
        cmd += ["--c2-ips", coll["c2_ips"]]
    if coll.get("c2_domains"):
        cmd += ["--c2-domains", coll["c2_domains"]]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr
    host = next(workdir.glob(f"{provider}-*"))
    return json.loads(next(host.glob("Combined_Findings_*.json")).read_text())


def test_lab_scenarios_cover_all_detection_types(tmp_path):
    produced = set()
    for i, sp in enumerate(SCENARIOS):
        produced |= {f["Type"] for f in _collect_scenario(sp, tmp_path / f"s{i}")}
    missing = _DETECTION_CATALOG - produced
    assert not missing, f"detection types with NO covering lab scenario: {sorted(missing)}"
