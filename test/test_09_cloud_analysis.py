"""P0-3 - cloud telemetry is normalized and run through the verdict ladder."""
import json
import os
import subprocess
import sys

import pytest

from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env

ADJ = os.path.join(CLOUD_DIR, "adjudicate_cloud.py")
sys.path.insert(0, CLOUD_DIR)
import adjudicate_cloud as ac   # noqa: E402

TP_CLASS = ("True Positive", "Likely True Positive")


def test_guardduty_severity_drives_verdict():
    out = ac.normalize_guardduty({"Findings": [
        {"Title": "HighThing", "Severity": 8, "Description": "x"},
        {"Title": "LowThing", "Severity": 1, "Description": "y"}]})
    by_target = {f["Target"]: f["Verdict"] for f in out}
    assert by_target["HighThing"] in TP_CLASS
    assert by_target["LowThing"] == "Indeterminate"


def test_scc_high_is_true_positive_class():
    out = ac.normalize_scc([{"finding": {"category": "MALWARE_C2", "severity": "HIGH"}}])
    assert out[0]["Verdict"] in TP_CLASS
    assert out[0]["Type"] == "Cloud Detection"


def test_azure_risky_user_high():
    out = ac.normalize_azure_risky({"value": [
        {"userPrincipalName": "a@b.test", "riskLevel": "high"},
        {"userPrincipalName": "c@d.test", "riskLevel": "low"}]})
    by = {f["Target"]: f["Verdict"] for f in out}
    assert by["a@b.test"] in TP_CLASS
    assert by["c@d.test"] == "Indeterminate"


def test_operator_c2_is_true_positive():
    out = ac.c2_findings("1.2.3.4", "evil.test")
    assert all(f["Verdict"] == "True Positive" for f in out)
    assert {f["Target"] for f in out} == {"1.2.3.4", "evil.test"}


def test_cli_writes_adjudicated_findings(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "guardduty_findings.json").write_text(json.dumps(
        {"Findings": [{"Title": "T", "Severity": 9, "Description": "d"}]}))
    out = tmp_path / "Combined.json"
    r = subprocess.run([sys.executable, ADJ, "--forensics-dir", str(fz), "--out", str(out),
                        "--provider", "aws", "--c2-ips", "9.9.9.9"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text())
    assert any(f["Verdict"] in TP_CLASS for f in data)
    assert all("Verdict" in f and "MITRE" in f for f in data)


# ── SaaS / identity normalizers (Entra/M365: OAuth grants, inbox rules, audit) ──
def test_oauth_grant_mail_scope_tenant_wide_is_tp():
    out = ac.normalize_oauth_grants({"value": [
        {"clientId": "app-evil", "consentType": "AllPrincipals",
         "scope": "User.Read Mail.Read Mail.Send offline_access"}]})
    assert out and out[0]["Verdict"] in TP_CLASS
    assert out[0]["Type"] == "Cloud OAuth Consent Grant"
    assert "T1528" in out[0]["MITRE"]
    assert "Mail.Read" in out[0]["Details"]


def test_oauth_grant_benign_scope_ignored():
    out = ac.normalize_oauth_grants({"value": [
        {"clientId": "app-ok", "consentType": "Principal", "scope": "User.Read openid"}]})
    assert out == []


def test_oauth_grant_user_consent_nonmail_is_indeterminate():
    out = ac.normalize_oauth_grants({"value": [
        {"clientId": "app-x", "consentType": "Principal", "scope": "Files.ReadWrite.All"}]})
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_inbox_rule_external_forward_is_tp():
    out = ac.normalize_inbox_rules({"value": [
        {"displayName": "fwd", "actions": {
            "forwardTo": [{"emailAddress": {"address": "exfil@evil.test"}}]}}]},
        internal_domains=["corp.test"])
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1114.003" in out[0]["MITRE"] and "external" in out[0]["Details"]


def test_inbox_rule_internal_only_is_indeterminate():
    out = ac.normalize_inbox_rules({"value": [
        {"displayName": "team", "actions": {
            "forwardTo": [{"emailAddress": {"address": "boss@corp.test"}}]}}]},
        internal_domains=["corp.test"])
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_inbox_rule_delete_after_forward_is_tp():
    out = ac.normalize_inbox_rules({"value": [
        {"displayName": "hide", "actions": {
            "forwardTo": [{"emailAddress": {"address": "boss@corp.test"}}],
            "delete": True}}]}, internal_domains=["corp.test"])
    assert out and out[0]["Verdict"] in TP_CLASS and "hides message" in out[0]["Details"]


def test_inbox_rule_no_forward_ignored():
    out = ac.normalize_inbox_rules({"value": [
        {"displayName": "label", "actions": {"moveToFolder": "AAA"}}]})
    assert out == []


def test_directory_audit_sp_credential_is_tp():
    out = ac.normalize_directory_audit({"value": [
        {"activityDisplayName": "Add service principal credentials",
         "initiatedBy": {"user": {"userPrincipalName": "adm@corp.test"}}}]})
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1098.001" in out[0]["MITRE"] and "adm@corp.test" in out[0]["Details"]


def test_directory_audit_benign_ignored():
    out = ac.normalize_directory_audit({"value": [
        {"activityDisplayName": "Update user", "initiatedBy": {}}]})
    assert out == []


def test_saas_findings_conform_to_schema():
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(CLOUD_DIR), "reporting"))
    import finding_schema
    findings = (
        ac.normalize_oauth_grants({"value": [
            {"clientId": "c", "consentType": "AllPrincipals", "scope": "Mail.ReadWrite"}]})
        + ac.normalize_inbox_rules({"value": [
            {"displayName": "r", "actions": {
                "forwardTo": [{"emailAddress": {"address": "x@evil.test"}}]}}]})
        + ac.normalize_directory_audit({"value": [
            {"activityDisplayName": "Consent to application", "initiatedBy": {}}]}))
    assert finding_schema.validate(findings, adjudicated=True) == []


def test_azure_provider_picks_up_saas_files(tmp_path):
    """adjudicate() wires the new azure SaaS files into the combined output."""
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "azure_risky_users.json").write_text(json.dumps({"value": []}))
    (fz / "azure_oauth_grants.json").write_text(json.dumps({"value": [
        {"clientId": "evil", "consentType": "AllPrincipals", "scope": "Mail.Read"}]}))
    (fz / "azure_inbox_rules.json").write_text(json.dumps({"value": [
        {"displayName": "fwd", "actions": {
            "forwardTo": [{"emailAddress": {"address": "x@evil.test"}}]}}]}))
    (fz / "azure_directory_audit.json").write_text(json.dumps({"value": [
        {"activityDisplayName": "Add service principal credentials", "initiatedBy": {}}]}))
    findings = ac.adjudicate(str(fz), "azure", "", "")
    types_seen = {f["Type"] for f in findings}
    assert {"Cloud OAuth Consent Grant", "Cloud Inbox Forwarding Rule",
            "Cloud Identity Audit"} <= types_seen


def test_cloud_collection_adjudicates_real_telemetry(tmp_path):
    """End-to-end: orchestrator adjudicates the mock GuardDuty detection, not just IOCs."""
    env = cloud_env(incident="aws-adj", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", "aws-adj", "--output-root", str(out_root)],   # NO --c2-ips
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    # the GuardDuty SSH-brute-force detection (severity 8) was adjudicated TP-class
    assert any(f["Verdict"] in TP_CLASS and "GuardDuty" in f["Details"] for f in combined)
    assert list(host.glob("Adjudication_*.json")), "no adjudication artifact emitted"
