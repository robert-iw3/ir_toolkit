"""Section 6 - cloud: playbooks simulated against mock aws/az/gcloud; orchestrators run end-to-end."""
import json
import os
import subprocess

import pytest

from conftest import (CLOUD_DIR, IRCOLLECT_CLOUD_SH, ERADICATE_CLOUD_SH,
                      MOCKS, cloud_env)

PLAYBOOKS = ["00_collect_forensics.sh", "01_contain_host.sh", "02_eradicate_process.sh",
             "03_eradicate_persistence.sh", "04_block_c2.sh", "05_restore_host.sh"]


def _run(cmd, env, cwd=None, timeout=120):
    return subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=cwd, timeout=timeout)


def test_mock_clis_executable():
    for cli in ("aws", "az", "gcloud"):
        p = os.path.join(MOCKS, cli)
        assert os.access(p, os.X_OK), f"mock {cli} not executable"


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_forensics_playbook_runs_per_provider(provider, tmp_path):
    """Each provider's forensics path completes and emits a phase-status line."""
    log = tmp_path / "calls.log"
    env = cloud_env(provider=provider, incident=f"fz-{provider}", mock_log=log)
    env.update({"IR_AZURE_SUBSCRIPTION": "sub", "IR_AZURE_RESOURCE_GROUP": "rg",
                "IR_GCP_PROJECT": "proj"})
    r = _run(["bash", os.path.join(CLOUD_DIR, "00_collect_forensics.sh")], env)
    assert r.returncode == 0, r.stderr
    assert f'"provider":"{provider}"' in r.stdout
    assert '"status":"success"' in r.stdout
    assert os.path.isfile(f"/tmp/ir/fz-{provider}/forensics.log")


def test_aws_containment_isolates(tmp_path):
    env = cloud_env(incident="ct-aws", mock_log=tmp_path / "c.log")
    r = _run(["bash", os.path.join(CLOUD_DIR, "01_contain_host.sh")], env)
    assert r.returncode == 0, r.stderr
    assert '"phase":"containment"' in r.stdout
    assert '"status":"failed"' not in r.stdout
    # the mock AWS CLI was actually exercised
    calls = (tmp_path / "c.log").read_text()
    assert "ec2 describe-instances" in calls


@pytest.mark.parametrize("script", PLAYBOOKS)
def test_every_cloud_playbook_runs_without_failure(script, tmp_path):
    """No cloud playbook crashes against the mock environment."""
    env = cloud_env(incident="all-aws", mock_log=tmp_path / "c.log",
                    IR_C2_IPS="45.66.77.88", IR_MALICIOUS_PROCESSES="evil-user")
    r = _run(["bash", os.path.join(CLOUD_DIR, script)], env)
    assert r.returncode == 0, f"{script}: {r.stderr}"
    assert '"status":"failed"' not in r.stdout, f"{script} reported failure: {r.stdout}"


def test_cloud_collection_orchestrator_end_to_end(tmp_path):
    """Invoke-IRCollection-Cloud.sh: forensics -> findings -> reports -> manifest."""
    env = cloud_env(incident="aws-e2e", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = _run(["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
              "--incident-id", "aws-e2e", "--c2-ips", "45.66.77.88,203.0.113.9",
              "--c2-domains", "evil.test", "--output-root", str(out_root)], env)
    assert r.returncode == 0, r.stderr
    host = out_root / "aws-10_0_0_5"
    for name in ("Incident_Report.md", "Attack_Graph.md", "Retrospective.md", "IOCs.json"):
        assert (host / name).exists(), f"missing {name}"
    iocs = json.load(open(host / "IOCs.json"))
    hosts = {e["host"] for e in iocs["c2_endpoints"]}
    assert {"45.66.77.88", "203.0.113.9", "evil.test"} <= hosts
    assert list(host.glob("_manifest_*.json"))


def test_cloud_eradication_dry_run_and_apply(tmp_path):
    """Eradication reads known-bad C2 from IOCs.json; dry-run changes nothing."""
    host = tmp_path / "aws-10_0_0_5"
    host.mkdir()
    (host / "IOCs.json").write_text(json.dumps({
        "c2_endpoints": [{"host": "45.66.77.88", "port": 443, "sanctioned": False}]}))
    env = cloud_env(incident="aws-erad", mock_log=tmp_path / "c.log")

    dry = _run(["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                "--host-folder", str(host)], env)
    assert dry.returncode == 0, dry.stderr
    assert "DRY-RUN" in dry.stdout
    assert "45.66.77.88" in dry.stdout              # known-bad sourced from IOCs.json
    assert "[run]" not in dry.stdout                # nothing executed

    appl = _run(["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                 "--host-folder", str(host), "--apply", "--restore"], env)
    assert appl.returncode == 0, appl.stderr
    assert "[run] 04_block_c2.sh" in appl.stdout
    assert "Restoration" in appl.stdout
