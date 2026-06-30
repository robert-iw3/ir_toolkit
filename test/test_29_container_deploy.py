"""Deployability of the cloud-IR workflow in its container.

The image is built `COPY . /opt/ir-toolkit` with a .dockerignore that keeps ONLY the
cloud workflow. These tests prove (1) the build context actually contains every cloud
file the workflow needs - including the modular collect/*.sh and cloud_*.py split-outs -
and excludes host/Windows material; and (2) the deployed entrypoint runs the whole
modular pipeline (entrypoint -> collector -> collect/<provider> -> adjudicator -> reports)
to completion against the mock CLIs, the same way it will inside the container.
"""
import fnmatch
import os
import subprocess

import pytest

from conftest import ROOT, MOCKS

ENTRYPOINT = os.path.join(ROOT, "docker", "entrypoint.sh")
DOCKERIGNORE = os.path.join(ROOT, ".dockerignore")

# Cloud-workflow files that MUST survive .dockerignore (relative to the build context).
# The modular split-outs are listed explicitly so a future move that breaks packaging fails.
KEEP = [
    "Invoke-IRCollection-Cloud.sh", "Invoke-Eradication-Cloud.sh", "WORKFLOW-CLOUD.md",
    "docker/entrypoint.sh", "docker/Dockerfile",
    "playbooks/cloud/00_collect_forensics.sh", "playbooks/cloud/01_contain_identity.sh",
    "playbooks/cloud/collect/lib.sh", "playbooks/cloud/collect/aws.sh",
    "playbooks/cloud/collect/azure.sh", "playbooks/cloud/collect/gcp.sh",
    "playbooks/cloud/adjudicate_cloud.py", "playbooks/cloud/cloud_findings.py",
    "playbooks/cloud/cloud_detectors.py", "playbooks/cloud/cloud_controlplane.py",
    "playbooks/cloud/cloud_identity.py", "playbooks/cloud/cloud_coverage.py",
    "playbooks/reporting/generate_reports.py",
]
# Host/Windows material that MUST be excluded from the cloud image.
DROP = [
    "Invoke-IRCollection.ps1", "Invoke-IRCollection-Linux.sh",
    "playbooks/windows/Invoke-WindowsPlaybooks.ps1", "playbooks/linux/06_restore.sh",
    "test/test_06_cloud.py", "planning/CLOUD-IR-Gap-Analysis-and-Roadmap.md",
    "WORKFLOW-WINDOWS.md", "playbooks/cloud/__pycache__/adjudicate_cloud.cpython-312.pyc",
]


def _patterns():
    out = []
    for line in open(DOCKERIGNORE, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _match(rel, pat):
    """Approximate Docker's .dockerignore matching for the patterns this repo uses."""
    pat = pat.rstrip("/")
    if pat.startswith("**/"):
        tail = pat[3:]
        if "/" not in tail:
            return any(fnmatch.fnmatch(seg, tail) for seg in rel.split("/"))
        return fnmatch.fnmatch(rel, tail) or fnmatch.fnmatch(rel, pat)
    if rel == pat or rel.startswith(pat + "/"):     # exact or directory prefix
        return True
    if "/" not in pat:                              # top-level glob; '*' does not cross '/'
        return "/" not in rel and fnmatch.fnmatch(rel, pat)
    return fnmatch.fnmatch(rel, pat)


def _ignored(rel, patterns):
    # Docker semantics: last matching pattern wins; '!' re-includes (negates).
    ignored = False
    for p in patterns:
        neg = p.startswith("!")
        pat = p[1:] if neg else p
        if _match(rel, pat):
            ignored = not neg
    return ignored


def test_dockerignore_keeps_entire_cloud_workflow():
    patterns = _patterns()
    for rel in KEEP:
        assert os.path.exists(os.path.join(ROOT, rel)), f"missing on disk: {rel}"
        assert not _ignored(rel, patterns), f".dockerignore would drop required file: {rel}"


def test_dockerignore_excludes_host_material():
    patterns = _patterns()
    for rel in DROP:
        assert _ignored(rel, patterns), f".dockerignore should exclude host file: {rel}"


def test_modular_files_are_self_contained_imports():
    """The adjudicator's modules import each other by sibling name, so they resolve
    when the directory is copied into the image (no package install, no PYTHONPATH)."""
    cloud = os.path.join(ROOT, "playbooks", "cloud")
    r = subprocess.run(
        ["python3", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); "
         "import adjudicate_cloud, cloud_controlplane, cloud_identity, cloud_detectors, "
         "cloud_coverage, cloud_findings; "
         "print(bool(adjudicate_cloud.adjudicate and cloud_coverage.attack_coverage))", cloud],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "True" in r.stdout


def test_entrypoint_runs_deployed_workflow_end_to_end(tmp_path):
    """Run the container entrypoint for real (IR_DRY_RUN unset) against the mock CLIs,
    with IR_TOOLKIT_DIR pointed at the repo - exactly how the image invokes it. Proves the
    deployed entrypoint -> collector -> modular collect/ -> modular adjudicator -> reports
    chain produces a collection."""
    work = tmp_path / "work"
    env = dict(os.environ)
    env["PATH"] = MOCKS + os.pathsep + env.get("PATH", "")
    env.update({"IR_TOOLKIT_DIR": ROOT, "IR_PROVIDER": "aws", "IR_TARGET": "10.0.0.5",
                "IR_INCIDENT_ID": "ctr-deploy", "IR_WORKDIR": str(work),
                "IR_AWS_REGION": "us-east-1"})
    env.pop("IR_DRY_RUN", None)
    r = subprocess.run(["bash", ENTRYPOINT], env=env, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    host = work / "aws-10_0_0_5"
    assert host.is_dir(), "deployed workflow produced no per-host collection folder"
    import glob
    import json
    combined = glob.glob(str(host / "Combined_Findings_*.json"))
    assert combined, "deployed adjudicator wrote no findings"
    findings = json.load(open(combined[0]))
    # the modular control-plane analyzer ran inside the deployed pipeline
    assert any(f["Type"] == "Cloud Control-Plane Activity" for f in findings)
    assert (host / "cloud_forensics" / "logging_status.json").exists()  # collect/lib preflight ran
    assert glob.glob(str(host / "Attack_Coverage_*.md"))               # coverage map emitted


def test_container_image_runs_entrypoint(tmp_path):
    """Opt-in: build the real image and run its entrypoint (dry-run) to prove the
    deployed bits resolve inside the container, not just in the repo checkout."""
    import shutil
    builder = shutil.which("podman") or shutil.which("docker")
    if not builder or not os.environ.get("IR_RUN_IMAGE_BUILD"):
        pytest.skip("set IR_RUN_IMAGE_BUILD=1 to build+run the image (~10 min)")
    b = subprocess.run([builder, "build", "-t", "ir-cloud:test", "-f",
                        os.path.join(ROOT, "docker", "Dockerfile"), ROOT],
                       capture_output=True, text=True, timeout=1800)
    assert b.returncode == 0, (b.stderr or b.stdout)[-3000:]
    run = subprocess.run([builder, "run", "--rm", "-e", "IR_DRY_RUN=1", "-e", "IR_PROVIDER=aws",
                          "-e", "IR_TARGET=10.0.0.5", "ir-cloud:test"],
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr
    assert "Invoke-IRCollection-Cloud.sh" in run.stdout and "--provider aws" in run.stdout
