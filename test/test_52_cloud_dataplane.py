"""C6 data-plane / SaaS exfil detectors (cloud_dataplane.py).

Verifies the tiering discipline: automation bulk-reads are Indeterminate (verify), while human
bulk-reads, cross-account object copies, and mailbox exports are Likely True Positive - and that
below-threshold/benign activity produces NO finding (the false-positive guard).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "playbooks", "cloud"))

from cloud_dataplane import (normalize_s3_data_events, normalize_gcp_data_access,
                             normalize_m365_audit, _GET_MED, _GET_HIGH)


def _s3_reads(actor, ptype, n, bucket="data", ip="203.0.113.9"):
    return {"Events": [{"CloudTrailEvent": (
        '{"eventName":"GetObject","sourceIPAddress":"%s",'
        '"userIdentity":{"type":"%s","userName":"%s"},'
        '"requestParameters":{"bucketName":"%s"}}' % (ip, ptype, actor, bucket))}
        for _ in range(n)]}


# ---- AWS S3 ---------------------------------------------------------------------
def test_s3_human_bulk_read_is_likely_tp():
    f = normalize_s3_data_events(_s3_reads("alice", "IAMUser", _GET_HIGH))
    assert f and f[0]["Verdict"] == "Likely True Positive"
    assert "T1530" in f[0]["MITRE"] and f[0]["Type"] == "Cloud Data Exfiltration"


def test_s3_service_moderate_read_is_indeterminate():
    # An assumed role reading a moderate volume from a single bucket = routine -> verify only.
    f = normalize_s3_data_events(_s3_reads("etl-role", "AssumedRole", _GET_MED + 5))
    assert f and f[0]["Verdict"] == "Indeterminate"


def test_s3_below_threshold_is_silent():
    assert normalize_s3_data_events(_s3_reads("etl-role", "AssumedRole", _GET_MED - 1)) == []


def test_s3_cross_account_copy_is_likely_tp():
    data = {"Events": [{"CloudTrailEvent": (
        '{"eventName":"CopyObject","sourceIPAddress":"203.0.113.9",'
        '"userIdentity":{"type":"IAMUser","userName":"mallory"},'
        '"requestParameters":{"bucketName":"attacker-bkt","copySource":"victim/secret"}}')}]}
    f = normalize_s3_data_events(data)
    assert f and f[0]["Verdict"] == "Likely True Positive" and "T1537" in f[0]["MITRE"]


def test_s3_service_wide_bucket_spread_escalates():
    # Same service identity but reading across many buckets is itself anomalous -> Likely TP.
    evs = []
    for b in range(6):
        evs += _s3_reads("etl-role", "AssumedRole", 10, bucket=f"b{b}")["Events"]
    f = normalize_s3_data_events({"Events": evs})
    assert f and f[0]["Verdict"] == "Likely True Positive"


# ---- GCP GCS -------------------------------------------------------------------
def _gcs_reads(actor, n, bucket="projects/_/buckets/data"):
    return {"entries": [{"protoPayload": {
        "methodName": "storage.objects.get",
        "authenticationInfo": {"principalEmail": actor},
        "resourceName": f"{bucket}/objects/f{i}"}} for i in range(n)]}


def test_gcs_human_bulk_read_is_likely_tp():
    f = normalize_gcp_data_access(_gcs_reads("dev@corp.test", _GET_HIGH))
    assert f and f[0]["Verdict"] == "Likely True Positive" and "T1530" in f[0]["MITRE"]


def test_gcs_service_account_moderate_read_is_indeterminate():
    f = normalize_gcp_data_access(_gcs_reads("etl@proj.iam.gserviceaccount.com", _GET_MED + 5))
    assert f and f[0]["Verdict"] == "Indeterminate"


def test_gcs_below_threshold_silent():
    assert normalize_gcp_data_access(_gcs_reads("dev@corp.test", _GET_MED - 1)) == []


# ---- M365 SaaS -----------------------------------------------------------------
def test_m365_mailbox_export_is_likely_tp():
    data = {"value": [{"Operation": "New-MailboxExportRequest", "UserId": "vip@corp.test"}]}
    f = normalize_m365_audit(data)
    assert f and f[0]["Verdict"] == "Likely True Positive" and "T1114" in f[0]["MITRE"]


def test_m365_bulk_download_tiers_by_volume():
    data = {"value": [{"Operation": "FileDownloaded", "UserId": "u@corp.test"}
                      for _ in range(_GET_HIGH)]}
    f = normalize_m365_audit(data)
    assert f and f[0]["Verdict"] == "Likely True Positive"
    assert "T1213" in f[0]["MITRE"] or "T1567" in f[0]["MITRE"]


def test_m365_light_download_silent():
    data = {"value": [{"Operation": "FileDownloaded", "UserId": "u@corp.test"}
                      for _ in range(_GET_MED - 1)]}
    assert normalize_m365_audit(data) == []


# ---- benign guards -------------------------------------------------------------
def test_empty_inputs_produce_nothing():
    assert normalize_s3_data_events(None) == []
    assert normalize_gcp_data_access({}) == []
    assert normalize_m365_audit([]) == []
