"""Cloud VPC/NSG flow-log collection + C2-confirmation normalizer.

Closes the Collection gap: network egress evidence for cloud C2 was not collected.
The normalizer upgrades an operator-supplied C2 IOC from "asserted" to "observed on
the wire" when the IP appears in collected flow logs (format-agnostic across AWS VPC
Flow Logs / Azure NSG flow logs / GCP VPC flow logs).
"""
import json
import os
import subprocess
import sys

from conftest import CLOUD_DIR, IRCOLLECT_CLOUD_SH, cloud_env

sys.path.insert(0, CLOUD_DIR)
import adjudicate_cloud as ac          # noqa: E402

C2 = "45.66.77.88"


# ── normalizer (pure) ────────────────────────────────────────────────────────
def test_flow_match_confirms_c2():
    text = '... 10.0.0.5 45.66.77.88 49152 443 6 ACCEPT OK ...'
    out = ac.normalize_flow_logs(text, C2)
    assert out and out[0]["Verdict"] == "True Positive"
    assert out[0]["Type"] == "Cloud Network Flow to C2" and out[0]["Target"] == C2
    assert "T1071" in out[0]["MITRE"]


def test_flow_no_match_is_silent():
    assert ac.normalize_flow_logs("10.0.0.5 8.8.8.8 443 ACCEPT", C2) == []


def test_flow_multiple_c2_ips():
    text = "1.1.1.1 ... 2.2.2.2"
    out = ac.normalize_flow_logs(text, "1.1.1.1,2.2.2.2,3.3.3.3")
    assert {f["Target"] for f in out} == {"1.1.1.1", "2.2.2.2"}


def test_flow_empty_text_is_silent():
    assert ac.normalize_flow_logs("", C2) == []
    assert ac.normalize_flow_logs(None, C2) == []


def test_adjudicate_wires_flow_logs(tmp_path):
    fz = tmp_path / "fz"
    fz.mkdir()
    (fz / "aws_vpc_flow_logs.json").write_text(
        json.dumps({"events": [{"message": f"2 acct eni 10.0.0.5 {C2} 49152 443 6 ACCEPT OK"}]}))
    findings = ac.adjudicate(str(fz), "aws", C2, "")
    assert any(f["Type"] == "Cloud Network Flow to C2" and f["Target"] == C2
               for f in findings)


# ── collection integration (mock CLIs) ───────────────────────────────────────
def _collect(tmp_path, provider, target):
    incident = f"{provider}-flow-{tmp_path.name}"
    env = cloud_env(provider=provider, target=target, incident=incident,
                    mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", provider, "--target", target,
         "--incident-id", incident, "--c2-ips", C2, "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr or r.stdout
    label = f"{provider}-" + "".join(c if c.isalnum() else "_" for c in target)
    return out_root / label


def test_aws_collects_flow_logs_and_confirms_c2(tmp_path):
    host = _collect(tmp_path, "aws", "10.0.0.5")
    assert (host / "cloud_forensics" / "aws_vpc_flow_logs.json").exists()
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    assert any(f["Type"] == "Cloud Network Flow to C2" and f["Target"] == C2
               for f in combined)


def test_gcp_collects_flow_logs_and_confirms_c2(tmp_path):
    host = _collect(tmp_path, "gcp", "vm1")
    assert (host / "cloud_forensics" / "gcp_vpc_flow_logs.json").exists()
    combined = json.loads(list(host.glob("Combined_Findings_*.json"))[0].read_text())
    assert any(f["Type"] == "Cloud Network Flow to C2" and f["Target"] == C2
               for f in combined)
