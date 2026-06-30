"""Blast-radius / principal-reachability mapping - given a compromised principal and the
collected telemetry, enumerate what it could touch (GCP roles held, CloudTrail actions
observed, adjudicated findings attributable to it). Feeds the report's "what could they
reach" section and prioritises containment.
"""
import json
import os
import subprocess
import sys

from conftest import CLOUD_DIR

sys.path.insert(0, CLOUD_DIR)
import principal_reachability as pr   # noqa: E402

REACH = os.path.join(CLOUD_DIR, "principal_reachability.py")


def _ct(records):
    return {"Events": [{"CloudTrailEvent": json.dumps(r)} for r in records]}


def test_gcp_roles_held_and_privileged_flagged(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "gcp_iam_policy.json").write_text(json.dumps({"bindings": [
        {"role": "roles/owner", "members": ["serviceAccount:svc@p.iam"]},
        {"role": "roles/storage.objectViewer", "members": ["serviceAccount:svc@p.iam"]},
        {"role": "roles/viewer", "members": ["user:other@corp.test"]}]}))
    rows = pr.blast_radius(str(fz), ["svc@p.iam"])
    assert rows[0]["roles_held"] == ["roles/owner", "roles/storage.objectViewer"]
    assert rows[0]["privileged_roles"] == ["roles/owner"]


def test_aws_observed_actions(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "cloudtrail_events.json").write_text(json.dumps(_ct([
        {"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
         "userIdentity": {"userName": "attacker"}},
        {"eventName": "GetObject", "eventSource": "s3.amazonaws.com",
         "userIdentity": {"userName": "attacker"}},
        {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
         "userIdentity": {"userName": "someone-else"}}])))
    rows = pr.blast_radius(str(fz), ["attacker"])
    actions = rows[0]["observed_actions"]
    assert "iam:CreateAccessKey" in actions and "s3:GetObject" in actions
    assert "s3:ListBuckets" not in actions     # belongs to a different principal


def test_related_findings_and_max_verdict(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    findings = [
        {"Type": "Cloud Control-Plane Activity", "Target": "CreateAccessKey:attacker",
         "Details": "by attacker", "Verdict": "Likely True Positive"},
        {"Type": "Cloud Detection", "Target": "other", "Details": "x", "Verdict": "Indeterminate"}]
    rows = pr.blast_radius(str(fz), ["attacker"], findings)
    assert rows[0]["related_finding_count"] == 1
    assert rows[0]["max_related_verdict"] == "Likely True Positive"


def test_empty_principal_skipped(tmp_path):
    rows = pr.blast_radius(str(tmp_path), ["", "  "])
    assert rows == []


def test_reachability_markdown_renders():
    rows = [{"principal": "svc@p.iam", "roles_held": ["roles/owner"],
             "privileged_roles": ["roles/owner"], "observed_actions": ["iam:CreateAccessKey"],
             "related_finding_count": 2, "max_related_verdict": "True Positive"}]
    md = pr.reachability_markdown(rows)
    assert "Blast Radius" in md and "svc@p.iam" in md and "roles/owner" in md
    assert pr.reachability_markdown([]).strip().endswith("map._")


def test_cli_writes_blast_radius_artifacts(tmp_path):
    host = tmp_path / "gcp-vm"
    fz = host / "cloud_forensics"
    fz.mkdir(parents=True)
    (fz / "gcp_iam_policy.json").write_text(json.dumps({"bindings": [
        {"role": "roles/editor", "members": ["serviceAccount:svc@p.iam"]}]}))
    (host / "Principals.json").write_text(json.dumps({"principals": [
        {"name": "svc@p.iam", "type": "cloud-identity", "auto_revoke": True}]}))
    (host / "Combined_Findings_20260101_000000.json").write_text(json.dumps([
        {"Type": "Cloud Identity Risk", "Target": "svc@p.iam", "Details": "risky",
         "Verdict": "Likely True Positive"}]))
    r = subprocess.run([sys.executable, REACH, "--host-folder", str(host), "--quiet"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    md = list(host.glob("Blast_Radius_*.md"))
    js = list(host.glob("Blast_Radius_*.json"))
    assert md and js
    data = json.loads(js[0].read_text())
    assert data[0]["principal"] == "svc@p.iam"
    assert "roles/editor" in data[0]["roles_held"]
    assert data[0]["related_finding_count"] == 1
