"""Dockerized terraform/OpenTofu validation lab for the IR evidence-storage modules.

The host here has no terraform/tofu binary, so the modules are lint/diff-checked inside a
throwaway container (test/tf_validate/). These tests verify the lab is wired correctly
(runs anywhere) and, when a container runtime is present and IR_RUN_TF_VALIDATE=1, build the
image and assert every module validates with `tofu validate`.
"""
import os
import shutil
import subprocess

import pytest

from conftest import ROOT

LAB = os.path.join(ROOT, "test", "tf_validate")
DOCKERFILE = os.path.join(LAB, "Dockerfile")
RUNNER = os.path.join(LAB, "validate.sh")


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


# ── static wiring (no container needed) ──────────────────────────────────────
def test_lab_files_present():
    assert os.path.isfile(DOCKERFILE) and os.path.isfile(RUNNER)
    assert os.access(RUNNER, os.X_OK), "validate.sh must be executable"


def test_dockerfile_installs_tofu_and_copies_modules():
    df = _read(DOCKERFILE)
    assert "opentofu" in df.lower() and "TOFU_VERSION" in df
    assert "COPY terraform/" in df                    # modules under validation
    assert "validate.sh" in df


def test_runner_validates_every_provider_module():
    sh = _read(RUNNER)
    assert "for p in aws azure gcp" in sh
    assert "init -backend=false" in sh and "validate" in sh
    # init must not require real state/credentials
    assert "-backend=false" in sh


def test_dockerignore_reincludes_lab_for_build_context():
    di = _read(os.path.join(ROOT, ".dockerignore"))
    assert "!test/tf_validate" in di, \
        "the tf-validate runner must be re-included so its Dockerfile can COPY it"


# ── real build + validate (opt-in) ───────────────────────────────────────────
def test_modules_validate_in_container():
    builder = shutil.which("podman") or shutil.which("docker")
    if not builder or not os.environ.get("IR_RUN_TF_VALIDATE"):
        pytest.skip("set IR_RUN_TF_VALIDATE=1 (and have podman/docker) to build+validate")
    b = subprocess.run([builder, "build", "-t", "ir-tf-validate", "-f", DOCKERFILE, ROOT],
                       capture_output=True, text=True, timeout=600)
    assert b.returncode == 0, (b.stderr or b.stdout)[-3000:]
    r = subprocess.run([builder, "run", "--rm", "ir-tf-validate"],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (r.stderr or r.stdout)[-3000:]
    assert "ALL MODULES VALID" in r.stdout
    for p in ("aws", "azure", "gcp"):
        assert f"OK {p}" in r.stdout
