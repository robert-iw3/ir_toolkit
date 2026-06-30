"""Control-plane behavioral analysis - the raw provider audit logs (AWS CloudTrail,
GCP Cloud Audit, Azure Activity) are adjudicated into findings, not just collected.

Each adversary API call is a pure-function detection mapped to ATT&CK + the shared
verdict ladder; benign calls produce nothing or stay Indeterminate.
"""
import json
import os
import subprocess
import sys

from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env

sys.path.insert(0, CLOUD_DIR)
import adjudicate_cloud as ac   # noqa: E402

TP_CLASS = ("True Positive", "Likely True Positive")
FORENSICS = os.path.join(CLOUD_DIR, "00_collect_forensics.sh")


def _ct(records):
    """Wrap raw CloudTrail records the way lookup-events returns them."""
    return {"Events": [{"CloudTrailEvent": json.dumps(r)} for r in records]}


# ── AWS CloudTrail ──────────────────────────────────────────────────────────────
def test_cloudtrail_stop_logging_is_defense_evasion_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "StopLogging", "userIdentity": {"userName": "attacker"},
         "sourceIPAddress": "203.0.113.9"}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1562.008" in out[0]["MITRE"]
    assert out[0]["Type"] == "Cloud Control-Plane Activity"


def test_cloudtrail_delete_flow_logs_and_detector_tp():
    for ev in ("DeleteFlowLogs", "DeleteDetector", "DeleteTrail"):
        out = ac.normalize_cloudtrail(_ct([{"eventName": ev, "userIdentity": {}}]))
        assert out and out[0]["Verdict"] in TP_CLASS, ev
        assert "T1562" in out[0]["MITRE"], ev


def test_cloudtrail_root_usage_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "RunInstances", "userIdentity": {"type": "Root"},
         "sourceIPAddress": "198.51.100.7"}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1078.004" in out[0]["MITRE"] and "root" in out[0]["Target"]


def test_cloudtrail_console_login_without_mfa_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "ConsoleLogin", "userIdentity": {"userName": "bob"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": "No"}}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "WITHOUT MFA" in out[0]["Details"]


def test_cloudtrail_console_login_with_mfa_ignored():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "ConsoleLogin", "userIdentity": {"userName": "bob"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": "Yes"}}]))
    assert out == []


def test_cloudtrail_create_access_key_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "CreateAccessKey", "userIdentity": {"userName": "svc"},
         "requestParameters": {"userName": "victim"}}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1098.001" in out[0]["MITRE"] and "victim" in out[0]["Target"]


def test_cloudtrail_attach_admin_policy_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "AttachUserPolicy", "userIdentity": {"userName": "svc"},
         "requestParameters": {"userName": "victim",
                               "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "admin policy" in out[0]["Details"]


def test_cloudtrail_attach_nonadmin_policy_is_indeterminate():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "AttachUserPolicy", "userIdentity": {"userName": "svc"},
         "requestParameters": {"userName": "victim",
                               "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}]))
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_cloudtrail_failed_call_ignored():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "AttachUserPolicy", "errorCode": "AccessDenied",
         "userIdentity": {"userName": "svc"}, "requestParameters": {"userName": "v"}}]))
    assert out == []


def test_cloudtrail_snapshot_shared_externally_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "ModifySnapshotAttribute", "userIdentity": {"userName": "x"},
         "requestParameters": {"createVolumePermission": {
             "add": {"items": [{"userId": "999988887777"}]}}}}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1537" in out[0]["MITRE"] and "external account" in out[0]["Details"]


def test_cloudtrail_ami_shared_public_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "ModifyImageAttribute", "userIdentity": {"userName": "x"},
         "requestParameters": {"launchPermission": {"add": {"items": [{"group": "all"}]}}}}]))
    assert out and out[0]["Verdict"] in TP_CLASS and "publicly" in out[0]["Details"]


def test_cloudtrail_public_bucket_policy_is_tp():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "PutBucketPolicy", "userIdentity": {"userName": "x"},
         "requestParameters": {"bucketName": "loot",
                               "bucketPolicy": {"Statement": [{"Principal": "*",
                                                               "Effect": "Allow"}]}}}]))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert out[0]["Type"] == "Cloud Exposure" and out[0]["Target"] == "loot"


def test_cloudtrail_sg_open_admin_port_is_tp_world_only_indeterminate():
    admin = ac.normalize_cloudtrail(_ct([
        {"eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {"userName": "x"},
         "requestParameters": {"ipPermissions": {"items": [
             {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
              "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}}]))
    assert admin and admin[0]["Verdict"] in TP_CLASS and "admin port" in admin[0]["Details"]

    web = ac.normalize_cloudtrail(_ct([
        {"eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {"userName": "x"},
         "requestParameters": {"ipPermissions": {"items": [
             {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
              "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}}]))
    assert web and web[0]["Verdict"] == "Indeterminate"


def test_cloudtrail_benign_describe_ignored():
    out = ac.normalize_cloudtrail(_ct([
        {"eventName": "DescribeInstances", "userIdentity": {"userName": "ops"}},
        {"eventName": "GetCallerIdentity", "userIdentity": {"userName": "ops"}}]))
    assert out == []


def test_cloudtrail_handles_lookup_events_and_raw_list():
    raw = [{"eventName": "StopLogging", "userIdentity": {}}]
    assert ac.normalize_cloudtrail(raw)            # raw record list
    assert ac.normalize_cloudtrail({"Records": raw})   # {"Records":[...]}
    assert ac.normalize_cloudtrail(None) == []     # missing file
    assert ac.normalize_cloudtrail({}) == []


# ── GCP Cloud Audit ─────────────────────────────────────────────────────────────
def _gcp(method, principal="attacker@evil.test", extra=None):
    e = {"protoPayload": {"methodName": method,
                          "authenticationInfo": {"principalEmail": principal},
                          "resourceName": "projects/p/x"}}
    if extra:
        e["protoPayload"].update(extra)
    return [e]


def test_gcp_service_account_key_creation_is_tp():
    out = ac.normalize_gcp_audit(_gcp("google.iam.admin.v1.CreateServiceAccountKey"))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert "T1098.001" in out[0]["MITRE"]


def test_gcp_sink_deletion_is_defense_evasion_tp():
    out = ac.normalize_gcp_audit(_gcp("google.logging.v2.ConfigServiceV2.DeleteSink"))
    assert out and out[0]["Verdict"] in TP_CLASS and "T1562.008" in out[0]["MITRE"]


def test_gcp_public_iam_binding_is_exposure_tp():
    out = ac.normalize_gcp_audit(_gcp("google.iam.v1.IAMPolicy.SetIamPolicy", extra={
        "request": {"policy": {"bindings": [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}}))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert out[0]["Type"] == "Cloud Exposure" and "allUsers" in out[0]["Details"]


def test_gcp_private_iam_binding_ignored():
    out = ac.normalize_gcp_audit(_gcp("google.iam.v1.IAMPolicy.SetIamPolicy", extra={
        "request": {"policy": {"bindings": [
            {"role": "roles/viewer", "members": ["user:alice@corp.test"]}]}}}))
    assert out == []


def test_gcp_world_open_firewall_is_exposure():
    out = ac.normalize_gcp_audit(_gcp("v1.compute.firewalls.insert", extra={
        "request": {"sourceRanges": ["0.0.0.0/0"]}}))
    assert out and out[0]["Type"] == "Cloud Exposure"
    assert "T1562.007" in out[0]["MITRE"]


def test_gcp_benign_get_ignored():
    out = ac.normalize_gcp_audit(_gcp("google.iam.admin.v1.GetServiceAccount"))
    assert out == []


# ── Azure Activity ──────────────────────────────────────────────────────────────
def _az(op, caller="attacker@evil.test", status="Succeeded", extra=None):
    e = {"operationName": {"value": op}, "caller": caller,
         "status": {"value": status}, "resourceId": "/subscriptions/s/x"}
    if extra:
        e.update(extra)
    return [e]


def test_azure_diagnostic_settings_delete_is_tp():
    out = ac.normalize_azure_activity(_az("Microsoft.Insights/diagnosticSettings/delete"))
    assert out and out[0]["Verdict"] in TP_CLASS and "T1562.008" in out[0]["MITRE"]


def test_azure_nsg_world_open_is_tp():
    out = ac.normalize_azure_activity(_az(
        "Microsoft.Network/networkSecurityGroups/securityRules/write",
        extra={"properties": {"requestbody": json.dumps({
            "properties": {"access": "Allow", "direction": "Inbound",
                           "sourceAddressPrefix": "0.0.0.0/0"}})}}))
    assert out and out[0]["Verdict"] in TP_CLASS
    assert out[0]["Type"] == "Cloud Exposure"


def test_azure_role_assignment_is_indeterminate():
    out = ac.normalize_azure_activity(_az("Microsoft.Authorization/roleAssignments/write"))
    assert out and out[0]["Verdict"] == "Indeterminate" and "T1098.003" in out[0]["MITRE"]


def test_azure_run_command_is_indeterminate():
    out = ac.normalize_azure_activity(_az(
        "Microsoft.Compute/virtualMachines/runCommand/action"))
    assert out and out[0]["Verdict"] == "Indeterminate" and "T1059" in out[0]["MITRE"]


def test_azure_non_succeeded_status_ignored():
    out = ac.normalize_azure_activity(_az(
        "Microsoft.Insights/diagnosticSettings/delete", status="Started"))
    assert out == []


def test_azure_benign_operation_ignored():
    out = ac.normalize_azure_activity(_az("Microsoft.Compute/virtualMachines/read"))
    assert out == []


# ── Schema conformance + adjudicate() wiring ────────────────────────────────────
def test_controlplane_findings_conform_to_schema():
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(CLOUD_DIR), "reporting"))
    import finding_schema
    findings = (
        ac.normalize_cloudtrail(_ct([{"eventName": "StopLogging", "userIdentity": {}}]))
        + ac.normalize_gcp_audit(_gcp("google.iam.admin.v1.CreateServiceAccountKey"))
        + ac.normalize_azure_activity(_az("Microsoft.Insights/diagnosticSettings/delete")))
    assert finding_schema.validate(findings, adjudicated=True) == []


def test_adjudicate_wires_cloudtrail(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "cloudtrail_events.json").write_text(json.dumps(
        _ct([{"eventName": "StopLogging", "userIdentity": {"userName": "evil"}}])))
    findings = ac.adjudicate(str(fz), "aws", "", "")
    assert any(f["Type"] == "Cloud Control-Plane Activity"
               and "T1562.008" in f["MITRE"] for f in findings)


def test_adjudicate_wires_gcp_audit(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "gcp_audit_log.json").write_text(json.dumps(
        _gcp("google.iam.admin.v1.CreateServiceAccountKey")))
    findings = ac.adjudicate(str(fz), "gcp", "", "")
    assert any("T1098.001" in f["MITRE"] for f in findings)


def test_adjudicate_wires_azure_activity(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "azure_activity_log.json").write_text(json.dumps(
        _az("Microsoft.Insights/diagnosticSettings/delete")))
    (fz / "azure_risky_users.json").write_text(json.dumps({"value": []}))
    findings = ac.adjudicate(str(fz), "azure", "", "")
    assert any("T1562.008" in f["MITRE"] for f in findings)


# ── Entra sign-in logs ──────────────────────────────────────────────────────────
def test_signin_legacy_auth_success_is_tp():
    out = ac.normalize_signins({"value": [
        {"userPrincipalName": "u@corp.test", "ipAddress": "203.0.113.9",
         "clientAppUsed": "IMAP4", "status": {"errorCode": 0},
         "location": {"countryOrRegion": "RU"}}]})
    assert any(f["Verdict"] in TP_CLASS and "legacy-auth" in f["Details"] for f in out)
    assert all(f["Type"] == "Cloud Sign-In" for f in out)


def test_signin_modern_auth_success_ignored():
    out = ac.normalize_signins({"value": [
        {"userPrincipalName": "u@corp.test", "ipAddress": "1.2.3.4",
         "clientAppUsed": "Browser", "status": {"errorCode": 0},
         "location": {"countryOrRegion": "US"}}]})
    assert out == []


def test_signin_atypical_travel_is_indeterminate():
    out = ac.normalize_signins({"value": [
        {"userPrincipalName": "u@corp.test", "clientAppUsed": "Browser",
         "status": {"errorCode": 0}, "location": {"countryOrRegion": "US"}},
        {"userPrincipalName": "u@corp.test", "clientAppUsed": "Browser",
         "status": {"errorCode": 0}, "location": {"countryOrRegion": "CN"}}]})
    travel = [f for f in out if "multiple countries" in f["Details"]]
    assert travel and travel[0]["Verdict"] == "Indeterminate"


def test_signin_failed_then_success_same_ip_is_tp():
    out = ac.normalize_signins({"value": [
        {"userPrincipalName": "u@corp.test", "ipAddress": "203.0.113.9",
         "clientAppUsed": "Browser", "status": {"errorCode": 50126}},
        {"userPrincipalName": "u@corp.test", "ipAddress": "203.0.113.9",
         "clientAppUsed": "Browser", "status": {"errorCode": 0}}]})
    spray = [f for f in out if "brute force" in f["Details"]]
    assert spray and spray[0]["Verdict"] in TP_CLASS and "T1110" in spray[0]["MITRE"]


def test_adjudicate_wires_signins(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "azure_risky_users.json").write_text(json.dumps({"value": []}))
    (fz / "azure_signin_logs.json").write_text(json.dumps({"value": [
        {"userPrincipalName": "v@corp.test", "clientAppUsed": "POP3",
         "status": {"errorCode": 0}, "ipAddress": "203.0.113.9"}]}))
    findings = ac.adjudicate(str(fz), "azure", "", "")
    assert any(f["Type"] == "Cloud Sign-In" for f in findings)


# ── ATT&CK Cloud coverage map ───────────────────────────────────────────────────
def test_attack_coverage_marks_tactics_from_findings():
    findings = (
        ac.normalize_cloudtrail(_ct([{"eventName": "StopLogging", "userIdentity": {}}]))     # Defense Evasion
        + ac.normalize_cloudtrail(_ct([{"eventName": "CreateAccessKey",                        # Persistence/PrivEsc
                                         "userIdentity": {"userName": "x"},
                                         "requestParameters": {"userName": "v"}}]))
        + ac.c2_findings("1.2.3.4", ""))                                                       # (T1071 not in map)
    rows = {r["tactic"]: r for r in ac.attack_coverage(findings)}
    assert rows["Defense Evasion"]["covered"] and "T1562.008" in rows["Defense Evasion"]["techniques"]
    assert rows["Persistence"]["covered"]
    assert not rows["Impact"]["covered"]            # nothing in the findings hits Impact


def test_coverage_markdown_renders_table():
    md = ac.coverage_markdown(ac.attack_coverage(
        ac.normalize_cloudtrail(_ct([{"eventName": "StopLogging", "userIdentity": {}}]))))
    assert "Cloud ATT&CK Coverage" in md and "Defense Evasion" in md
    assert "✅" in md and "⬜" in md


def test_cli_writes_coverage_artifact(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "cloudtrail_events.json").write_text(json.dumps(
        _ct([{"eventName": "StopLogging", "userIdentity": {"userName": "e"}}])))
    out = tmp_path / "Combined.json"
    cov = tmp_path / "Coverage.md"
    import subprocess as sp
    r = sp.run([sys.executable, os.path.join(CLOUD_DIR, "adjudicate_cloud.py"),
                "--forensics-dir", str(fz), "--out", str(out), "--provider", "aws",
                "--coverage-out", str(cov), "--quiet"],
               capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert cov.exists() and "Defense Evasion" in cov.read_text()


# ── Multi-region sweep ──────────────────────────────────────────────────────────
def test_all_regions_sweeps_each_region(tmp_path):
    env = cloud_env(provider="aws", incident="mr-test", mock_log=tmp_path / "calls.log")
    env["IR_ALL_REGIONS"] = "1"
    r = subprocess.run(["bash", FORENSICS], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls.log").read_text()
    assert "describe-regions" in calls
    # CloudTrail pulled from both regions the mock advertises
    assert "--region us-east-1" in calls and "--region us-west-2" in calls


# ── Logging-enablement preflight ────────────────────────────────────────────────
def test_logging_status_disabled_source_is_finding():
    out = ac.normalize_logging_status({"provider": "aws", "sources": [
        {"name": "CloudTrail", "enabled": False, "detail": "no trail"},
        {"name": "GuardDuty", "enabled": True, "detail": "det-1"}]})
    assert len(out) == 1
    assert out[0]["Type"] == "Cloud Logging Disabled" and out[0]["Target"] == "CloudTrail"
    assert "T1562.008" in out[0]["MITRE"] and out[0]["Verdict"] == "Indeterminate"


def test_logging_status_all_enabled_is_clean():
    assert ac.normalize_logging_status({"sources": [
        {"name": "CloudTrail", "enabled": True}]}) == []
    assert ac.normalize_logging_status(None) == []


# ── Collection: configurable window, preflight artifact, paginated CloudTrail ────
def test_forensics_honors_configurable_window(tmp_path):
    """An explicit window is used verbatim in the CloudTrail/CloudWatch calls."""
    log = tmp_path / "calls.log"
    env = cloud_env(provider="aws", incident="win-test", mock_log=log)
    env.update({"IR_WINDOW_START": "2026-01-01T00:00:00Z",
                "IR_WINDOW_END": "2026-01-02T00:00:00Z"})
    r = subprocess.run(["bash", FORENSICS], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    calls = log.read_text()
    assert "2026-01-01T00:00:00Z" in calls and "2026-01-02T00:00:00Z" in calls
    # the narrow 3-event-name filter is gone (full management-event capture)
    assert "AttributeValue=StopInstances" not in calls


def test_forensics_writes_logging_status(tmp_path):
    env = cloud_env(provider="aws", incident="ls-test", mock_log=tmp_path / "c.log")
    subprocess.run(["bash", FORENSICS], env=env, capture_output=True, text=True, timeout=120)
    with open("/tmp/ir/ls-test/logging_status.json") as fh:
        status = json.load(fh)
    names = {s["name"] for s in status["sources"]}
    assert {"CloudTrail", "GuardDuty", "VPCFlowLogs"} <= names


def test_cloud_findings_feed_reporting_like_hosts(tmp_path):
    """Cloud adjudications must populate the SAME report artifacts the Linux/Windows
    workflows produce - Incident_Report (verdict table), Attack_Graph (ATT&CK kill chain),
    IOCs, and the coverage map - not just sit in Combined_Findings."""
    env = cloud_env(incident="rep-e2e", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", "rep-e2e", "--c2-ips", "45.66.77.88", "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"

    report = (host / "Incident_Report.md").read_text()
    # a behavioral (control-plane) finding and its verdict reached the report body
    assert "Cloud Control-Plane Activity" in report and "StopLogging" in report
    assert "True Positive" in report

    graph = (host / "Attack_Graph.md").read_text()
    # adjudicated findings are placed on the ATT&CK kill chain in the graph
    assert "Defense Evasion" in graph and "T1562.008" in graph
    assert "Command and Control" in graph                    # C2 IOC node

    iocs = json.loads((host / "IOCs.json").read_text())
    assert "45.66.77.88" in {e["host"] for e in iocs.get("c2_endpoints", [])}

    coverage = list(host.glob("Attack_Coverage_*.md"))
    assert coverage and "Defense Evasion" in coverage[0].read_text()


def test_collection_adjudicates_cloudtrail_end_to_end(tmp_path):
    """Orchestrator: a CloudTrail StopLogging event becomes a defense-evasion finding."""
    env = cloud_env(incident="ct-e2e", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", "ct-e2e", "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    assert any(f["Type"] == "Cloud Control-Plane Activity"
               and "T1562.008" in f["MITRE"] for f in combined), \
        "CloudTrail StopLogging was not adjudicated as defense evasion"
