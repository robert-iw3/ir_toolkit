"""P1-6 - every orchestrator emits a uniform _status.json for SOAR gating (Cloud, live-executed)."""
import json

from conftest import IRCOLLECT_CLOUD_SH, cloud_env

REQUIRED_KEYS = {"incident_id", "hostname", "platform", "status", "tp_count", "phases"}
VALID_STATUS = {"COMPLETED", "PARTIAL", "FAILED"}


def test_cloud_orchestrator_writes_status(tmp_path):
    import subprocess
    env = cloud_env(incident="aws-st", mock_log=tmp_path / "c.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    subprocess.run(["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                    "--incident-id", "aws-st", "--output-root", str(out_root)],
                   env=env, capture_output=True, text=True, timeout=120, check=True)
    status = json.loads((out_root / "aws-10_0_0_5" / "_status.json").read_text())
    assert REQUIRED_KEYS <= set(status)
    assert status["platform"] == "cloud"
    assert status["status"] in VALID_STATUS
