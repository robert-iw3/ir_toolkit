"""P0 #1 - credential/session revocation: Cloud IAM eradication + orchestrator wiring."""
import json
import subprocess

from conftest import IRCOLLECT_CLOUD_SH, ERADICATE_CLOUD_SH, read_text, cloud_env


def test_cloud_orchestrator_emits_principals():
    assert "extract_principals.py" in read_text(IRCOLLECT_CLOUD_SH)


def test_cloud_eradication_revokes_iam_principals(tmp_path):
    host = tmp_path / "aws-10_0_0_5"
    host.mkdir()
    (host / "Principals.json").write_text(json.dumps({"principals": [
        {"name": "rogue-iam-user", "type": "iam", "auto_revoke": True},
        {"name": "system", "type": "iam", "auto_revoke": False},
    ]}))
    env = cloud_env(incident="aws-cred", mock_log=tmp_path / "c.log")
    r = subprocess.run(["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                        "--host-folder", str(host)], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "rogue-iam-user" in r.stdout          # implicated IAM principal flows to eradication
    assert "system" not in r.stdout.split("IAM revoke:")[1].split("\n")[0]  # protected excluded
