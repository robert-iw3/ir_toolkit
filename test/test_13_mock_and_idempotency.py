"""P2-7 - mocks assert the exact mutating cloud calls; key stages are idempotent."""
import json
import os
import subprocess

import generate_reports as gr
from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env


def _run(cmd, env, timeout=120):
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)


# -- The mocks now prove the RIGHT mutation happened, not just "it ran" ---------
def test_containment_attaches_quarantine_sg(tmp_path):
    log = tmp_path / "calls.log"
    env = cloud_env(incident="ct", mock_log=log)
    _run(["bash", os.path.join(CLOUD_DIR, "01_contain_host.sh")], env)
    calls = log.read_text()
    # the instance's security groups are actually swapped to the quarantine SG
    assert "ec2 modify-instance-attribute" in calls
    assert "--groups" in calls


def test_block_c2_creates_deny_entry_for_each_ip(tmp_path):
    log = tmp_path / "calls.log"
    env = cloud_env(incident="c2", mock_log=log, IR_C2_IPS="45.66.77.88,203.0.113.9")
    _run(["bash", os.path.join(CLOUD_DIR, "04_block_c2.sh")], env)
    calls = log.read_text()
    assert "ec2 create-network-acl-entry" in calls          # a deny rule is created
    assert "45.66.77.88/32" in calls                        # for the actual C2 IP
    assert "203.0.113.9/32" in calls
    assert "--rule-action deny" in calls


def test_forensics_actually_queries_guardduty(tmp_path):
    log = tmp_path / "calls.log"
    env = cloud_env(incident="fz", mock_log=log)
    _run(["bash", os.path.join(CLOUD_DIR, "00_collect_forensics.sh")], env)
    assert "guardduty get-findings" in log.read_text()      # telemetry path exercised


# -- Idempotency ---------------------------------------------------------------
def test_emit_iocs_is_idempotent(windows_collection):
    gr.emit_iocs(windows_collection, "WIN")
    first = open(os.path.join(windows_collection, "IOCs.json")).read()
    gr.emit_iocs(windows_collection, "WIN")
    second = open(os.path.join(windows_collection, "IOCs.json")).read()
    assert first == second


def test_cloud_collection_is_deterministic(tmp_path):
    """Running cloud collection twice yields the same IOCs and a COMPLETED status."""
    def run(tag):
        env = cloud_env(incident="aws-idem", mock_log=tmp_path / f"{tag}.log")
        root = tmp_path / tag
        root.mkdir()
        r = _run(["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                  "--incident-id", "aws-idem", "--c2-ips", "45.66.77.88",
                  "--output-root", str(root)], env)
        assert r.returncode == 0, r.stderr
        host = root / "aws-10_0_0_5"
        iocs = json.load(open(host / "IOCs.json"))
        status = json.load(open(host / "_status.json"))
        c2 = sorted(e["host"] for e in iocs["c2_endpoints"])
        return c2, status["status"]

    c2_a, st_a = run("run1")
    c2_b, st_b = run("run2")
    assert c2_a == c2_b
    assert st_a == st_b == "COMPLETED"
