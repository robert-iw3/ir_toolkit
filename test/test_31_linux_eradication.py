"""Linux eradication revisions (2026-06-21 review) — safety hardening.

Covers: command-injection resistance in the orchestrator's indicator extraction (no `eval` of
attacker-influenceable finding content), the protected-process choke point, the adjudication-gated
hidden-PID sweep, the module dry-run guard, and the chmod-action reversibility in restore.
"""
import json
import os
import subprocess

from conftest import ROOT

ERAD = os.path.join(ROOT, "Invoke-Eradication-Linux.sh")
PROC = os.path.join(ROOT, "playbooks", "linux", "02_eradicate_process.sh")
RESTORE = os.path.join(ROOT, "playbooks", "linux", "06_restore.sh")


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def test_orchestrator_does_not_eval_finding_content():
    src = read(ERAD)
    assert "eval " not in src                       # the injection vector is gone
    assert "read -r PIDS" in src                     # values read as literal data lines


def test_orchestrator_no_shell_injection(tmp_path):
    """A TP finding whose persistence path carries shell metacharacters must NOT execute."""
    host = tmp_path / "host"
    host.mkdir()
    sentinel = tmp_path / "PWNED"
    adj = [{"Verdict": "True Positive", "Type": "Cron Persistence",
            "SubjectPath": f'/tmp/x";touch {sentinel};"'}]
    (host / "Adjudication_20260101_000000.json").write_text(json.dumps(adj))

    r = subprocess.run(["bash", ERAD, "--host-folder", str(host)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert not sentinel.exists()                      # injection did NOT run
    assert "DRY-RUN" in r.stdout                       # default is dry-run (no --apply)
    # the path is still captured as an inert data token in the report
    rep = next(host.glob("Eradication_*.json"))
    assert "/tmp/x" in rep.read_text()


def test_protected_process_choke_point_in_kill_tree():
    src = read(PROC)
    kt = src[src.index("kill_tree()"):src.index("IFS=',' read -ra PID_LIST")]
    assert "is_protected" in kt                       # guard enforced inside kill_tree (all paths)
    assert "refused_protected_pid" in kt


def test_hidden_pid_sweep_is_adjudication_gated():
    src = read(PROC)
    assert "FLAGGED for analyst (not auto-killed)" in src     # unattributed hidden PID not killed
    assert "RACE GUARD" in src                                # exit-race mitigation present


def test_module_dry_run_default_safe():
    src = read(PROC)
    assert 'DRY_RUN="${IR_DRY_RUN:-1}"' in src        # safe by default when invoked directly
    assert "[DRY-RUN] would kill PID" in src


def test_chmod_action_is_reversible():
    proc = read(PROC)
    assert "chmod" in proc and "orig_mode" in proc     # chmod000 fallback journals original mode
    assert 'action":"chmod' in proc.replace("\\", "")  # the journal entry tags the action
    restore = read(RESTORE)
    assert '"chmod"' in restore and "orig_mode" in restore   # restore reverses it by mode


# ── Cloud eradication revisions (2026-06-21 review) ──────────────────────────
CLOUD_ERAD = os.path.join(ROOT, "Invoke-Eradication-Cloud.sh")
CLOUD_PROC = os.path.join(ROOT, "playbooks", "cloud", "02_eradicate_process.sh")
CLOUD_PERSIST = os.path.join(ROOT, "playbooks", "cloud", "03_eradicate_persistence.sh")


def test_cloud_orchestrator_passes_dry_run_flag():
    src = read(CLOUD_ERAD)
    assert "IR_DRY_RUN=0 bash" in src                  # modules only mutate under --apply


def test_cloud_modules_dry_run_default_safe():
    for f in (CLOUD_PROC, CLOUD_PERSIST):
        src = read(f)
        assert 'DRY_RUN="${IR_DRY_RUN:-1}"' in src      # safe by default standalone
        assert "[DRY-RUN] would" in src


def test_cloud_persistence_journals_and_backs_up_lambda():
    src = read(CLOUD_PERSIST)
    # irreversible Lambda delete is backed up first + journaled
    assert "aws lambda get-function" in src
    assert src.index("get-function") < src.index("delete-function")   # backup BEFORE delete
    # reversible IAM revocations are journaled for rollback
    assert "persistence_rollback.jsonl" in src
    for action in ("iam_key_deactivate", "iam_role_deny", "azure_sp_disable"):
        assert action in src


# ── Follow-ups: containment ordering + IAM-revocation rollback ───────────────
CLOUD_RESTORE = os.path.join(ROOT, "playbooks", "cloud", "05_restore_host.sh")
C2 = os.path.join(ROOT, "playbooks", "linux", "04_block_c2.sh")


def test_linux_blocks_c2_before_killing_processes():
    src = read(ERAD)
    assert src.index('"C2 blocking"') < src.index('"Process eradication"')   # cut C2 first
    assert "--isolate" in src and "01_contain_host.sh" in src                 # optional full isolation


def test_c2_block_backs_up_firewall_for_restore():
    src = read(C2)
    assert "iptables-pre-${INCIDENT_ID}.rules" in src    # same path 06_restore.sh reads
    assert "iptables-save" in src


def test_cloud_restore_reverses_iam_revocations():
    src = read(CLOUD_RESTORE)
    assert "reverse_iam_revocations" in src
    assert "--status Active" in src                       # reactivate key
    assert "detach-role-policy" in src                    # remove deny-all
    assert "accountEnabled=true" in src                   # re-enable SP
    assert "persistence_rollback.jsonl" in src
