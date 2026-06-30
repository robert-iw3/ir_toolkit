"""Posture / exposure snapshot - the point-in-time attack surface (security groups, NSGs,
firewall rules open to the internet; public storage buckets) that explains how the breach
was reachable. Normalizers in cloud_posture.py, mapped to ATT&CK + the shared ladder.
"""
import json
import os
import subprocess
import sys

from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env

sys.path.insert(0, CLOUD_DIR)
import cloud_posture as cp        # noqa: E402
import adjudicate_cloud as ac     # noqa: E402

TP_CLASS = ("True Positive", "Likely True Positive")


# ── AWS security groups ─────────────────────────────────────────────────────────
def test_sg_world_open_admin_port_is_tp():
    out = cp.normalize_security_groups({"SecurityGroups": [
        {"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
    assert out and out[0]["Verdict"] in TP_CLASS and out[0]["Type"] == "Cloud Exposure"
    assert "admin port" in out[0]["Details"]


def test_sg_world_open_web_port_is_indeterminate():
    out = cp.normalize_security_groups({"SecurityGroups": [
        {"GroupId": "sg-2", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_sg_internal_only_ignored():
    out = cp.normalize_security_groups({"SecurityGroups": [
        {"GroupId": "sg-3", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]})
    assert out == []


def test_sg_all_ports_world_open_is_tp():
    out = cp.normalize_security_groups({"SecurityGroups": [
        {"GroupId": "sg-4", "IpPermissions": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]})
    assert out and out[0]["Verdict"] in TP_CLASS


# ── Azure NSG ───────────────────────────────────────────────────────────────────
def test_nsg_inbound_internet_admin_is_tp():
    out = cp.normalize_nsg_rules([
        {"name": "nsg1", "securityRules": [
            {"name": "rdp", "direction": "Inbound", "access": "Allow",
             "sourceAddressPrefix": "Internet", "destinationPortRange": "3389"}]}])
    assert out and out[0]["Verdict"] in TP_CLASS and out[0]["Type"] == "Cloud Exposure"


def test_nsg_inbound_internet_web_is_indeterminate():
    out = cp.normalize_nsg_rules([
        {"name": "nsg2", "securityRules": [
            {"name": "web", "direction": "Inbound", "access": "Allow",
             "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "443"}]}])
    assert out and out[0]["Verdict"] == "Indeterminate"


def test_nsg_outbound_or_deny_ignored():
    out = cp.normalize_nsg_rules([
        {"name": "nsg3", "securityRules": [
            {"name": "out", "direction": "Outbound", "access": "Allow",
             "sourceAddressPrefix": "*", "destinationPortRange": "*"},
            {"name": "deny", "direction": "Inbound", "access": "Deny",
             "sourceAddressPrefix": "*", "destinationPortRange": "22"}]}])
    assert out == []


# ── GCP firewall ────────────────────────────────────────────────────────────────
def test_gcp_firewall_world_open_admin_is_tp():
    out = cp.normalize_gcp_firewall([
        {"name": "fw1", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}])
    assert out and out[0]["Verdict"] in TP_CLASS


def test_gcp_firewall_internal_ignored():
    out = cp.normalize_gcp_firewall([
        {"name": "fw2", "direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}])
    assert out == []


def test_gcp_firewall_egress_ignored():
    out = cp.normalize_gcp_firewall([
        {"name": "fw3", "direction": "EGRESS", "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "all"}]}])
    assert out == []


# ── Public buckets ──────────────────────────────────────────────────────────────
def test_public_bucket_is_tp():
    out = cp.normalize_public_buckets({"buckets": [
        {"name": "loot", "public": True}, {"name": "ok", "public": False}]})
    assert len(out) == 1 and out[0]["Verdict"] in TP_CLASS
    assert out[0]["Target"] == "loot" and "T1530" in out[0]["MITRE"]


def test_posture_empty_safe():
    assert cp.normalize_security_groups(None) == []
    assert cp.normalize_nsg_rules(None) == []
    assert cp.normalize_gcp_firewall(None) == []
    assert cp.normalize_public_buckets(None) == []


# ── Wiring + collection ─────────────────────────────────────────────────────────
def test_adjudicate_wires_posture(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "security_groups.json").write_text(json.dumps({"SecurityGroups": [
        {"GroupId": "sg-x", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}))
    (fz / "aws_public_buckets.json").write_text(json.dumps({"buckets": [{"name": "loot", "public": True}]}))
    findings = ac.adjudicate(str(fz), "aws", "", "")
    types = [f for f in findings if f["Type"] == "Cloud Exposure"]
    assert any("admin port" in f["Details"] for f in types)
    assert any(f["Target"] == "loot" for f in types)


def test_collection_emits_exposure_findings(tmp_path):
    env = cloud_env(incident="posture-e2e", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", "posture-e2e", "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"
    assert (host / "cloud_forensics" / "aws_public_buckets.json").exists()
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    exposures = [f for f in combined if f["Type"] == "Cloud Exposure"]
    assert any("Security group" in f["Details"] for f in exposures)   # world-open SG
    assert any(f["Target"] == "loot-bucket" for f in exposures)        # public bucket
