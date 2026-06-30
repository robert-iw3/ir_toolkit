"""Identity-first containment - disable the implicated principal and revoke its live
sessions (deactivating a key does not kill issued tokens), journaled so restore can
reverse it. Dry-run by default; the eradication orchestrator runs it before anything else.
"""
import json
import os
import subprocess

from conftest import CLOUD_DIR, ERADICATE_CLOUD_SH, cloud_env

CONTAIN_ID = os.path.join(CLOUD_DIR, "01_contain_identity.sh")
RESTORE = os.path.join(CLOUD_DIR, "05_restore_host.sh")


def _run(cmd, env, timeout=120):
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)


def _journal(incident):
    return f"/tmp/ir/{incident}/persistence_rollback.jsonl"


def test_identity_containment_dry_run_changes_nothing(tmp_path):
    env = cloud_env(incident="id-dry", mock_log=tmp_path / "c.log",
                    IR_CONTAIN_PRINCIPALS="attacker-user")
    r = _run(["bash", CONTAIN_ID], env)
    assert r.returncode == 0, r.stderr
    assert "[DRY-RUN]" in open("/tmp/ir/id-dry/identity_containment.log").read()
    # dry-run journals nothing
    assert not os.path.exists(_journal("id-dry"))
    calls = (tmp_path / "c.log").read_text()
    assert "iam put-user-policy" not in calls   # no mutation


def test_identity_containment_no_principals_skips(tmp_path):
    env = cloud_env(incident="id-none", mock_log=tmp_path / "c.log")
    env.pop("IR_MALICIOUS_PROCESSES", None)
    r = _run(["bash", CONTAIN_ID], env)
    assert r.returncode == 0
    assert '"status":"skipped"' in r.stdout and "no_principals" in r.stdout


def test_identity_containment_apply_revokes_and_journals(tmp_path):
    env = cloud_env(incident="id-apply", mock_log=tmp_path / "c.log",
                    IR_CONTAIN_PRINCIPALS="attacker-user", IR_DRY_RUN="0")
    r = _run(["bash", CONTAIN_ID], env)
    assert r.returncode == 0, r.stderr
    assert '"status":"success"' in r.stdout
    calls = (tmp_path / "c.log").read_text()
    # deny-all + session revocation both issued against the IAM principal
    assert "iam attach-user-policy" in calls
    assert "iam put-user-policy" in calls and "IRRevokeOlderSessions" in calls
    # journal records reversible actions for restore
    journal = open(_journal("id-apply")).read()
    assert "iam_user_deny" in journal and "iam_revoke_sessions" in journal


def test_restore_reverses_identity_containment(tmp_path):
    incident = "id-rev"
    os.makedirs(f"/tmp/ir/{incident}", exist_ok=True)
    with open(_journal(incident), "w") as fh:
        fh.write(json.dumps({"action": "iam_user_deny", "user": "attacker-user",
                             "policy_arn": "arn:aws:iam::aws:policy/AWSDenyAll"}) + "\n")
        fh.write(json.dumps({"action": "iam_revoke_sessions", "entity_type": "user",
                             "entity": "attacker-user"}) + "\n")
        fh.write(json.dumps({"action": "gcp_sa_disable", "sa": "svc@p.iam"}) + "\n")
    env = cloud_env(incident=incident, mock_log=tmp_path / "c.log", IR_DRY_RUN="0")
    r = _run(["bash", RESTORE], env)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "c.log").read_text()
    assert "iam detach-user-policy" in calls              # deny-all reversed
    assert "iam delete-user-policy" in calls              # session-revoke policy removed
    assert "service-accounts enable" in calls             # SA re-enabled


def test_eradication_runs_identity_containment_first(tmp_path):
    host = tmp_path / "aws-10_0_0_5"
    host.mkdir()
    (host / "Principals.json").write_text(json.dumps({"principals": [
        {"name": "attacker-user", "type": "iam", "auto_revoke": True}]}))
    env = cloud_env(incident="id-erad", mock_log=tmp_path / "c.log")
    r = _run(["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
              "--host-folder", str(host)], env)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "01_contain_identity.sh" in out
    # identity containment is sequenced before process eradication
    assert out.index("01_contain_identity.sh") < out.index("02_eradicate_process.sh")
