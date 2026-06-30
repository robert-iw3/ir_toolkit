"""IAM identity posture - the state the investigation lands in (no-MFA console users,
stale/long-lived keys, a root key, public IAM bindings, external-reachable resources).
Bounds the blast radius and surfaces standing persistence. Pure-function normalizers in
cloud_iam.py, mapped to ATT&CK + the shared verdict ladder.
"""
import base64
import json
import os
import subprocess
import sys

from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env

sys.path.insert(0, CLOUD_DIR)
import cloud_iam as ci            # noqa: E402
import adjudicate_cloud as ac     # noqa: E402

TP_CLASS = ("True Positive", "Likely True Positive")


def _credreport(csv_text):
    return {"Content": base64.b64encode(csv_text.encode()).decode(), "ReportFormat": "text/csv"}


# ── AWS credential report ───────────────────────────────────────────────────────
def test_root_active_key_and_no_mfa_are_tp():
    csv = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_2_active,access_key_2_last_rotated\n"
           "<root_account>,arn:aws:iam::1:root,true,false,true,2021-01-01T00:00:00+00:00,false,N/A")
    out = ci.normalize_iam_credential_report(_credreport(csv))
    details = " ".join(f["Details"] for f in out)
    assert "active access key" in details and "MFA disabled" in details
    assert all(f["Verdict"] in TP_CLASS for f in out)
    assert all(f["Type"] == "Cloud IAM Posture" for f in out)


def test_console_user_without_mfa_is_indeterminate():
    csv = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_2_active,access_key_2_last_rotated\n"
           "alice,arn:aws:iam::1:user/alice,true,false,false,N/A,false,N/A")
    out = ci.normalize_iam_credential_report(_credreport(csv))
    assert len(out) == 1 and out[0]["Verdict"] == "Indeterminate"
    assert "without MFA" in out[0]["Details"] and "T1078.004" in out[0]["MITRE"]


def test_stale_active_key_flagged():
    csv = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_2_active,access_key_2_last_rotated\n"
           "svc,arn:aws:iam::1:user/svc,false,true,true,2020-01-01T00:00:00+00:00,false,N/A")
    out = ci.normalize_iam_credential_report(_credreport(csv))
    assert out and any("days old" in f["Details"] for f in out)
    assert out[0]["Verdict"] == "Indeterminate"


def test_clean_user_yields_nothing():
    from datetime import datetime, timezone
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    csv = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_2_active,access_key_2_last_rotated\n"
           f"ok,arn:aws:iam::1:user/ok,true,true,true,{recent},false,N/A")
    assert ci.normalize_iam_credential_report(_credreport(csv)) == []


def test_credreport_empty_or_missing_safe():
    assert ci.normalize_iam_credential_report(None) == []
    assert ci.normalize_iam_credential_report({}) == []


# ── AWS Access Analyzer ─────────────────────────────────────────────────────────
def test_access_analyzer_public_is_tp():
    out = ci.normalize_access_analyzer({"findings": [
        {"resource": "arn:aws:s3:::loot", "status": "ACTIVE", "isPublic": True}]})
    assert out and out[0]["Verdict"] in TP_CLASS and out[0]["Type"] == "Cloud Exposure"


def test_access_analyzer_external_nonpublic_indeterminate():
    out = ci.normalize_access_analyzer({"findings": [
        {"resource": "arn:aws:s3:::shared", "status": "ACTIVE", "isPublic": False,
         "principal": "999988887777"}]})
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_access_analyzer_resolved_ignored():
    out = ci.normalize_access_analyzer({"findings": [
        {"resource": "x", "status": "RESOLVED", "isPublic": True}]})
    assert out == []


# ── GCP IAM policy + SA keys ────────────────────────────────────────────────────
def test_gcp_public_binding_is_tp():
    out = ci.normalize_gcp_iam_policy({"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
        {"role": "roles/viewer", "members": ["user:a@corp.test"]}]})
    assert len(out) == 1 and out[0]["Verdict"] in TP_CLASS
    assert "allUsers" in out[0]["Details"]


def test_gcp_user_managed_sa_key_flagged():
    out = ci.normalize_gcp_sa_keys({"keys": [
        {"serviceAccount": "svc@p.iam", "name": "k1", "keyType": "USER_MANAGED",
         "validAfterTime": "2021-01-01T00:00:00Z"},
        {"serviceAccount": "svc@p.iam", "name": "k2", "keyType": "SYSTEM_MANAGED"}]})
    assert len(out) == 1 and out[0]["Verdict"] == "Indeterminate"
    assert "T1098.001" in out[0]["MITRE"] and "days old" in out[0]["Details"]


# ── Wiring + collection ─────────────────────────────────────────────────────────
def test_adjudicate_wires_aws_iam_posture(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    csv = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_2_active,access_key_2_last_rotated\n"
           "<root_account>,arn:aws:iam::1:root,true,false,true,2021-01-01T00:00:00+00:00,false,N/A")
    (fz / "aws_iam_credential_report.json").write_text(json.dumps(_credreport(csv)))
    findings = ac.adjudicate(str(fz), "aws", "", "")
    assert any(f["Type"] == "Cloud IAM Posture" and f["Verdict"] in TP_CLASS for f in findings)


def test_collection_emits_iam_posture_findings(tmp_path):
    """End-to-end: the AWS collector pulls the credential report and it is adjudicated."""
    env = cloud_env(incident="iam-e2e", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", "iam-e2e", "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"
    assert (host / "cloud_forensics" / "aws_iam_credential_report.json").exists()
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    assert any(f["Type"] == "Cloud IAM Posture" for f in combined)
