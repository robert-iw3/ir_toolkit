"""P0 #1 - credential/session revocation: Linux revocation playbook + orchestrator wiring."""
import json
import subprocess

from conftest import PLAYBOOKS, IRCOLLECT_SH, read_text
import os

REVOKE_SH = os.path.join(PLAYBOOKS, "linux", "07_revoke_credentials.sh")


def test_linux_plan_lists_targets_skips_protected(tmp_path):
    princ = tmp_path / "Principals.json"
    princ.write_text(json.dumps({"principals": [
        {"name": "attacker", "type": "local", "auto_revoke": True},
        {"name": "root", "type": "local", "auto_revoke": False},
    ]}))
    r = subprocess.run(["bash", REVOKE_SH, "--principals", str(princ)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "PLAN: passwd -l attacker" in r.stdout
    assert "root" not in r.stdout.replace("rollback", "")  # root never planned
    assert "[i] PLAN only" in r.stdout                      # nothing applied


def test_linux_orchestrator_emits_principals():
    assert "extract_principals.py" in read_text(IRCOLLECT_SH)
