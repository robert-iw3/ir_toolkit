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


# ── Precise per-thread suspension (IR_TARGET_TIDS) ───────────────────────────
# A "PID" is a thread group, not one task -- killing the whole process when
# only one thread is compromised (e.g. ptrace-injected) is unnecessary
# instability for a protected/highly-threaded process. Signals can't isolate
# one thread (a fatal signal's default action is process-wide regardless of
# which thread receives it), so kill_thread() suspends the target thread via
# ptrace (suspend_thread.py) instead of signaling it.

def test_kill_thread_delegates_to_suspend_thread_helper():
    """kill_thread() must call suspend_thread.py (ptrace-based), not send a
    signal -- tgkill/kill on a bare TID cannot isolate one thread, since a
    fatal signal's default action always tears down the whole process."""
    src = read(PROC)
    assert "SUSPEND_HELPER" in src and "suspend_thread.py" in src
    kt = src[src.index("kill_thread()"):src.index("# -- Kill by PID")]
    assert "SUSPEND_HELPER" in kt


def test_target_tids_env_var_defaults_empty_no_behavior_change():
    """IR_TARGET_TIDS must default to empty so every existing invocation
    (no env var set) takes the exact same whole-process path as before."""
    src = read(PROC)
    assert 'TARGET_TIDS="${IR_TARGET_TIDS:-}"' in src


def test_force_whole_process_kill_override_exists():
    src = read(PROC)
    assert 'FORCE_WHOLE_PROCESS="${IR_FORCE_WHOLE_PROCESS_KILL:-0}"' in src
    kt = src[src.index("kill_tree()"):]
    assert 'FORCE_WHOLE_PROCESS' in kt


def test_thread_inventory_journaled_unconditionally_in_kill_tree():
    """Every kill_tree() invocation must record the full TID set at kill time,
    regardless of whether the precise-thread path is taken -- forensic
    completeness even when the whole process ends up being killed."""
    src = read(PROC)
    kt = src[src.index("kill_tree()"):src.index("Precise-thread path")]
    assert 'action\\":\\"thread_inventory' in kt
    assert "list_tids" in kt


def test_precise_path_fires_for_protected_process_with_target_tids(tmp_path):
    """A genuine multi-threaded process, with IR_TARGET_TIDS naming one of
    its real threads, must take the precise-thread path (not the
    whole-process path) when that PID's thread count crosses the instability
    threshold. Dry-run only -- no live ptrace attach in the test suite."""
    script = f"""
import threading, time
def worker():
    time.sleep(30)
for _ in range(4):
    threading.Thread(target=worker, daemon=True).start()
time.sleep(30)
"""
    proc = subprocess.Popen(["python3", "-c", script])
    try:
        import time as _time
        _time.sleep(0.5)
        tids = os.listdir(f"/proc/{proc.pid}/task")
        other_tid = next(t for t in tids if t != str(proc.pid))

        env = dict(os.environ, IR_INCIDENT_ID="test-precise-thread",
                  IR_DRY_RUN="1", IR_MALICIOUS_PIDS=str(proc.pid),
                  IR_TARGET_TIDS=f"{proc.pid}:{other_tid}",
                  IR_MULTI_THREAD_THRESHOLD="2")
        r = subprocess.run(["bash", PROC], capture_output=True, text=True,
                           timeout=30, env=env)
        assert f"would suspend TID {other_tid} of PID {proc.pid} only" in r.stdout
        assert f"would kill PID {proc.pid}" not in r.stdout
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_default_path_unchanged_without_target_tids(tmp_path):
    """Regression: with IR_TARGET_TIDS unset, behavior must be identical to
    before this feature existed -- whole-process kill, no thread-precise
    branching at all."""
    proc = subprocess.Popen(["python3", "-c", "import time; time.sleep(30)"])
    try:
        env = dict(os.environ, IR_INCIDENT_ID="test-default-path",
                  IR_DRY_RUN="1", IR_MALICIOUS_PIDS=str(proc.pid))
        r = subprocess.run(["bash", PROC], capture_output=True, text=True,
                           timeout=30, env=env)
        assert f"would kill PID {proc.pid}" in r.stdout
        assert "would suspend TID" not in r.stdout
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_restore_reverses_suspend_thread_by_killing_tracer(tmp_path, monkeypatch):
    """06_restore.sh must reverse a suspend_thread journal entry by SIGTERM-ing
    the recorded tracer_pid -- suspend_thread.py's daemon only holds a thread
    stopped while it is alive, so terminating it is what resumes the thread."""
    tracer = subprocess.Popen(["python3", "-c", "import time; time.sleep(30)"])
    try:
        rollback_dir = tmp_path / "rollback"
        rollback_dir.mkdir()
        (rollback_dir / "test-restore-thread.jsonl").write_text(
            json.dumps({"action": "suspend_thread", "pid": 4242,
                        "tid": 4243, "tracer_pid": tracer.pid}) + "\n"
        )
        env = dict(os.environ, IR_INCIDENT_ID="test-restore-thread")
        monkeypatch_src = read(RESTORE).replace(
            '/var/ir/rollback/${INCIDENT_ID}.jsonl', f'{rollback_dir}/${{INCIDENT_ID}}.jsonl'
        )
        patched = tmp_path / "06_restore_patched.sh"
        patched.write_text(monkeypatch_src)
        r = subprocess.run(["bash", str(patched)], capture_output=True, text=True,
                           timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        tracer.wait(timeout=5)
        assert tracer.returncode is not None       # SIGTERM delivered, process exited
        assert "resumed TID 4243 of PID 4242" in r.stdout
    finally:
        if tracer.poll() is None:
            tracer.kill()
            tracer.wait(timeout=5)


def test_restore_skips_suspend_thread_when_tracer_already_gone(tmp_path):
    """If the tracer daemon already exited (thread already resumed, or the
    daemon crashed), restore must skip it -- not error -- since there is
    nothing left to reverse."""
    src = read(RESTORE)
    assert '"/proc/${tracer_pid}"' in src
    assert "tracer_gone" in src


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
