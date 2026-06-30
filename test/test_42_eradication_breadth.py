"""Eradication breadth - the persistence-removal and C2-blocking mechanisms the playbooks
advertise are actually implemented (closing the prior doc-vs-code drift), dry-run-first and
journaled so 05_restore can reverse them.

Resource targets are passed as prefixed IR_MALICIOUS_PATHS tokens (function:/rule:/logicapp:/
runbook:/app:/scheduler:/binding:). DNS-based C2 is blocked at the cloud DNS layer.
"""
import json
import os
import subprocess

from conftest import CLOUD_DIR, cloud_env

ERAD = os.path.join(CLOUD_DIR, "03_eradicate_persistence.sh")
BLOCK = os.path.join(CLOUD_DIR, "04_block_c2.sh")
RESTORE = os.path.join(CLOUD_DIR, "05_restore_host.sh")


def _run(script, env):
    return subprocess.run(["bash", script], env=env, capture_output=True, text=True, timeout=120)


def _journal(incident):
    return f"/tmp/ir/{incident}/persistence_rollback.jsonl"


# ── 03: resource-based persistence removal (apply mode) ──────────────────────────
def test_aws_eventbridge_rule_removed_and_journaled(tmp_path):
    env = cloud_env(provider="aws", incident="er-aws", mock_log=tmp_path / "c.log",
                    IR_MALICIOUS_PATHS="rule:evil-sched,function:evil-fn", IR_DRY_RUN="0")
    r = _run(ERAD, env)
    assert r.returncode == 0 and '"status":"success"' in r.stdout
    calls = (tmp_path / "c.log").read_text()
    assert "events delete-rule" in calls and "lambda delete-function" in calls
    journal = open(_journal("er-aws")).read()
    assert "eventbridge_delete" in journal and "lambda_delete" in journal


def test_azure_logicapp_runbook_app_removed(tmp_path):
    env = cloud_env(provider="azure", incident="er-az", mock_log=tmp_path / "c.log",
                    IR_MALICIOUS_PATHS="logicapp:/subs/x/wf,runbook:acct/evil,app:app-123",
                    IR_AZURE_RESOURCE_GROUP="rg", IR_DRY_RUN="0")
    r = _run(ERAD, env)
    assert r.returncode == 0 and '"status":"success"' in r.stdout
    calls = (tmp_path / "c.log").read_text()
    assert "resource update" in calls and "state=Disabled" in calls
    assert "automation runbook delete" in calls
    journal = open(_journal("er-az")).read()
    assert "azure_logicapp_disable" in journal and "azure_runbook_delete" in journal
    assert "azure_sp_disable" in journal             # app:<id> disables its SP


def test_gcp_function_scheduler_binding_removed(tmp_path):
    env = cloud_env(provider="gcp", incident="er-gcp", mock_log=tmp_path / "c.log",
                    IR_MALICIOUS_PATHS="function:evil-fn,scheduler:evil-job,binding:user:bad@x=roles/owner",
                    IR_GCP_PROJECT="proj", IR_DRY_RUN="0")
    r = _run(ERAD, env)
    assert r.returncode == 0 and '"status":"success"' in r.stdout
    calls = (tmp_path / "c.log").read_text()
    assert "functions delete" in calls and "scheduler jobs delete" in calls
    assert "remove-iam-policy-binding" in calls
    journal = open(_journal("er-gcp")).read()
    for a in ("gcp_function_delete", "gcp_scheduler_delete", "gcp_binding_remove"):
        assert a in journal


def test_persistence_removal_dry_run_is_safe(tmp_path):
    env = cloud_env(provider="aws", incident="er-dry", mock_log=tmp_path / "c.log",
                    IR_MALICIOUS_PATHS="rule:evil-sched")    # IR_DRY_RUN defaults to 1
    r = _run(ERAD, env)
    assert r.returncode == 0
    log = tmp_path / "c.log"
    calls = log.read_text() if log.exists() else ""   # may be absent: nothing was invoked
    assert "events delete-rule" not in calls          # nothing mutated
    assert not os.path.exists(_journal("er-dry"))


# ── 04: DNS-based C2 blocking ───────────────────────────────────────────────────
def test_aws_dns_firewall_blocks_domains(tmp_path):
    env = cloud_env(provider="aws", incident="c2-aws", mock_log=tmp_path / "c.log",
                    IR_C2_IPS="45.66.77.88", IR_C2_DOMAINS="evil.test,bad.example",
                    IR_DRY_RUN="0")
    r = _run(BLOCK, env)
    assert r.returncode == 0 and '"status":"failed"' not in r.stdout
    calls = (tmp_path / "c.log").read_text()
    assert "route53resolver create-firewall-domain-list" in calls
    assert "route53resolver create-firewall-rule" in calls


def test_gcp_dns_response_policy_blocks_domains(tmp_path):
    env = cloud_env(provider="gcp", incident="c2-gcp", mock_log=tmp_path / "c.log",
                    IR_C2_IPS="45.66.77.88", IR_C2_DOMAINS="evil.test",
                    IR_GCP_PROJECT="proj", IR_DRY_RUN="0")
    r = _run(BLOCK, env)
    assert r.returncode == 0
    calls = (tmp_path / "c.log").read_text()
    assert "dns response-policies create" in calls
    assert "dns response-policies rules create" in calls


def test_dns_block_dry_run_is_safe(tmp_path):
    env = cloud_env(provider="aws", incident="c2-dry", mock_log=tmp_path / "c.log",
                    IR_C2_DOMAINS="evil.test")               # IR_DRY_RUN defaults to 1
    _run(BLOCK, env)
    calls = (tmp_path / "c.log").read_text()
    assert "route53resolver create-firewall-domain-list" not in calls


# ── 05: restore reverses the new reversible actions ─────────────────────────────
def test_restore_reverses_new_actions(tmp_path):
    incident = "er-rev"
    os.makedirs(f"/tmp/ir/{incident}", exist_ok=True)
    with open(_journal(incident), "w") as fh:
        for e in (
            {"action": "azure_logicapp_disable", "id": "/subs/x/wf"},
            {"action": "gcp_binding_remove", "member": "user:bad@x", "role": "roles/owner"},
            {"action": "eventbridge_delete", "rule": "evil-sched", "backup": "/tmp/eb.json"},
            {"action": "gcp_function_delete", "function": "evil-fn", "backup": "/tmp/fn.json"},
        ):
            fh.write(json.dumps(e) + "\n")
    env = cloud_env(provider="aws", incident=incident, mock_log=tmp_path / "c.log",
                    IR_GCP_PROJECT="proj", IR_DRY_RUN="0")
    r = _run(RESTORE, env)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "c.log").read_text()
    assert "state=Enabled" in calls                  # logic app re-enabled
    assert "add-iam-policy-binding" in calls          # gcp binding re-added
    restore_log = open(f"/tmp/ir/{incident}/restore.log").read()
    assert "MANUAL: EventBridge rule evil-sched" in restore_log
    assert "MANUAL: Cloud Function evil-fn" in restore_log
