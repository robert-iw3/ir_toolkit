"""Secure IR evidence storage (Terraform) for AWS / Azure / GCP.

Collections can be large; these modules provision a locked-down WORM bucket/container to
hold them off-host. Posture is verified STATICALLY here (runs anywhere, no Terraform binary
needed). When `terraform` is installed (CI / responder machine), each module is additionally
`terraform validate`-d — the diff/lint check the AWS/Azure/GCP modules share.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

from conftest import ROOT, IRCOLLECT_CLOUD_SH, cloud_env

TF = os.path.join(ROOT, "terraform")


def _main(provider):
    with open(os.path.join(TF, provider, "main.tf"), encoding="utf-8") as fh:
        return fh.read()


def _files(provider):
    return set(os.listdir(os.path.join(TF, provider)))


def _assign(text, key, val):
    """True if HCL `key = val` appears, ignoring fmt alignment whitespace."""
    return re.search(rf"\b{re.escape(key)}\s*=\s*{re.escape(val)}(?!\w)", text) is not None


# ── module structure ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_module_has_standard_files(provider):
    assert {"main.tf", "variables.tf"} <= _files(provider)


# ── AWS lockdown posture ─────────────────────────────────────────────────────
def test_aws_locked_down():
    m = _main("aws")
    assert _assign(m, "object_lock_enabled", "true")            # WORM-capable bucket
    assert "aws_s3_bucket_object_lock_configuration" in m        # default retention
    assert "aws_s3_bucket_public_access_block" in m
    for sw in ("block_public_acls", "block_public_policy",
               "ignore_public_acls", "restrict_public_buckets"):
        assert _assign(m, sw, "true"), sw
    assert "aws_s3_bucket_versioning" in m and _assign(m, "status", '"Enabled"')
    assert "aws_s3_bucket_server_side_encryption_configuration" in m
    assert "aws:SecureTransport" in m                            # deny non-TLS
    assert _assign(m, "force_destroy", "false")


# ── Azure lockdown posture ───────────────────────────────────────────────────
def test_azure_locked_down():
    m = _main("azure")
    assert _assign(m, "min_tls_version", '"TLS1_2"')
    assert _assign(m, "https_traffic_only_enabled", "true")
    assert _assign(m, "allow_nested_items_to_be_public", "false")
    assert _assign(m, "public_network_access_enabled", "false")
    assert _assign(m, "versioning_enabled", "true")
    assert "azurerm_storage_container_immutability_policy" in m  # WORM
    assert _assign(m, "container_access_type", '"private"')
    assert _assign(m, "default_action", '"Deny"')


# ── GCP lockdown posture ─────────────────────────────────────────────────────
def test_gcp_locked_down():
    m = _main("gcp")
    assert _assign(m, "uniform_bucket_level_access", "true")
    assert _assign(m, "public_access_prevention", '"enforced"')
    assert "versioning {" in m and _assign(m, "enabled", "true")
    assert "retention_policy {" in m and _assign(m, "is_locked", "true")
    assert _assign(m, "force_destroy", "false")


# ── terraform validate (only when the binary is present) ─────────────────────
@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_terraform_validate(provider):
    tf = shutil.which("terraform") or shutil.which("tofu")
    if not tf:
        pytest.skip("terraform/tofu not installed — static posture checks cover this env")
    d = os.path.join(TF, provider)
    init = subprocess.run([tf, "-chdir=" + d, "init", "-backend=false", "-input=false"],
                          capture_output=True, text=True)
    assert init.returncode == 0, init.stderr
    val = subprocess.run([tf, "-chdir=" + d, "validate"], capture_output=True, text=True)
    assert val.returncode == 0, val.stderr


# ── collector wires upload to the locked-down bucket ─────────────────────────
def test_cloud_collection_uploads_to_evidence_bucket(tmp_path):
    incident = f"aws-evid-{tmp_path.name}"
    env = cloud_env(provider="aws", target="10.0.0.5", incident=incident,
                    mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", incident, "--evidence-bucket", "my-ir-evidence",
         "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr or r.stdout
    calls = (tmp_path / "calls.log").read_text()
    assert "s3 cp --recursive" in calls
    assert "s3://my-ir-evidence/aws-10_0_0_5/" in calls


def test_no_upload_without_evidence_bucket(tmp_path):
    incident = f"aws-noev-{tmp_path.name}"
    env = cloud_env(provider="aws", target="10.0.0.5", incident=incident,
                    mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
         "--incident-id", incident, "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=120)
    assert "s3 cp" not in (tmp_path / "calls.log").read_text()
