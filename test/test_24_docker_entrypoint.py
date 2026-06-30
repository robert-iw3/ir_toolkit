"""Ephemeral cloud-IR container: entrypoint config translation + Dockerfile posture.

The container runs the cloud collection and ships evidence to locked-down storage, leaving
no trace on the host. These tests validate the templated-config -> collector-args mapping
(via the entrypoint's IR_DRY_RUN seam) and that the image is built safely. No image build
needed for the unit tests; a real `podman build` is the integration check (see README).
"""
import os
import subprocess

import pytest

from conftest import ROOT

ENTRYPOINT = os.path.join(ROOT, "docker", "entrypoint.sh")
DOCKERFILE = os.path.join(ROOT, "docker", "Dockerfile")
TEMPLATE = os.path.join(ROOT, "docker", "ir-cloud.env.template")


def _dry_run(env_extra):
    env = dict(os.environ, IR_DRY_RUN="1", IR_TOOLKIT_DIR=ROOT, **env_extra)
    r = subprocess.run(["bash", ENTRYPOINT], env=env, capture_output=True, text=True)
    return r


def test_entrypoint_builds_basic_args():
    r = _dry_run({"IR_PROVIDER": "aws", "IR_TARGET": "10.0.0.5", "IR_REGION": "us-west-2"})
    assert r.returncode == 0, r.stderr
    assert "--provider aws" in r.stdout
    assert "--target 10.0.0.5" in r.stdout
    assert "--region us-west-2" in r.stdout
    assert "Invoke-IRCollection-Cloud.sh" in r.stdout


def test_entrypoint_maps_all_action_flags():
    r = _dry_run({
        "IR_PROVIDER": "gcp", "IR_TARGET": "vm1", "IR_CONTAIN": "1",
        "IR_SNAPSHOT_DISKS": "1", "IR_EVIDENCE_BUCKET": "ir-eviden",
        "IR_PROVISION_EVIDENCE": "1", "IR_C2_IPS": "45.66.77.88",
        "IR_EVIDENCE_RETENTION_DAYS": "30"})
    out = r.stdout
    assert "--contain" in out and "--snapshot-disks" in out
    assert "--evidence-bucket ir-eviden" in out and "--provision-evidence" in out
    assert "--c2-ips 45.66.77.88" in out
    assert "--evidence-retention-days 30" in out


def test_entrypoint_omits_unset_optionals():
    r = _dry_run({"IR_PROVIDER": "aws", "IR_TARGET": "10.0.0.5"})
    assert "--contain" not in r.stdout
    assert "--evidence-bucket" not in r.stdout
    assert "--c2-ips" not in r.stdout


def test_entrypoint_requires_provider_and_target():
    r = _dry_run({"IR_PROVIDER": "aws"})          # no IR_TARGET
    assert r.returncode != 0
    assert "IR_TARGET" in (r.stderr + r.stdout)


# ── config template ──────────────────────────────────────────────────────────
def test_template_documents_all_knobs():
    txt = open(TEMPLATE, encoding="utf-8").read()
    for key in ("IR_PROVIDER", "IR_TARGET", "IR_EVIDENCE_BUCKET",
                "IR_PROVISION_EVIDENCE", "IR_SNAPSHOT_DISKS", "IR_WIPE_WORKDIR",
                "GOOGLE_APPLICATION_CREDENTIALS"):
        assert key in txt


def test_template_bakes_no_real_secrets():
    txt = open(TEMPLATE, encoding="utf-8").read()
    # credential lines must be commented placeholders, never real values
    for line in txt.splitlines():
        if line.startswith(("AWS_SECRET", "AZURE_CLIENT_SECRET")):
            assert False, f"uncommented secret in template: {line}"


# ── Dockerfile posture ───────────────────────────────────────────────────────
def test_dockerfile_has_all_tooling_and_entrypoint():
    df = open(DOCKERFILE, encoding="utf-8").read()
    assert "FROM alpine:" in df                       # pinned via ARG ALPINE_VERSION
    assert "aws-cli" in df and "azure-cli" in df
    assert "gcloud" in df and "terraform" in df.lower()
    assert "entrypoint.sh" in df
    assert "--tmpfs" in df or "VOLUME" in df          # ephemeral scratch documented/declared


def test_dockerfile_bakes_no_secrets():
    df = open(DOCKERFILE, encoding="utf-8").read().lower()
    for bad in ("aws_secret_access_key", "azure_client_secret", "api_key="):
        assert bad not in df


# ── real image build (opt-in: slow, ~10 min, pulls cloud SDKs) ───────────────
def test_podman_build_smoke():
    import shutil
    builder = shutil.which("podman") or shutil.which("docker")
    if not builder or not os.environ.get("IR_RUN_IMAGE_BUILD"):
        pytest.skip("set IR_RUN_IMAGE_BUILD=1 to run the full image build (~10 min)")
    r = subprocess.run([builder, "build", "-t", "ir-cloud:test",
                        "-f", DOCKERFILE, ROOT],
                       capture_output=True, text=True, timeout=1800)
    assert r.returncode == 0, (r.stderr or r.stdout)[-3000:]
