"""suspend_thread.py -- ptrace-based single-thread suspension.

Signal delivery cannot isolate one thread of a process: a fatal signal's
default action is process-wide regardless of which thread receives it.
These tests exercise the actual PTRACE_SEIZE/PTRACE_INTERRUPT/PTRACE_DETACH
mechanism against a real forked child process, not a mock.

The fork+ptrace test runs in a standalone `python3` subprocess rather than
inside the pytest process itself: forking a process with pytest's own
internal state (plugins, threads) is unreliable, and ptrace additionally
requires the tracer to be a direct ancestor of the target (Yama
ptrace_scope=1, the common default) unless running as root -- both are
satisfied by giving the subprocess its own child to fork and trace.
"""
import json
import os
import subprocess
import sys

from conftest import ROOT

_HELPER_DIR = os.path.join(ROOT, "playbooks", "linux", "threat_hunting")

_DRIVER = f"""
import ctypes, json, os, signal, sys, threading, time
sys.path.insert(0, {_HELPER_DIR!r})
import suspend_thread as st

pid = os.fork()
if pid == 0:
    def worker():
        time.sleep(20)
    for _ in range(5):
        threading.Thread(target=worker, daemon=True).start()
    time.sleep(20)
    os._exit(0)

tids = None
for _ in range(50):
    cand = sorted(os.listdir(f"/proc/{{pid}}/task"), key=int)
    if len(cand) > 5:
        tids = cand
        break
    time.sleep(0.1)
if tids is None:
    print(json.dumps({{"error": "child threads did not start in time"}}))
    os.kill(pid, signal.SIGKILL)
    sys.exit(1)

target_tid = int(tids[-1])
libc = st._libc()
ok, reason = st._seize_and_interrupt(libc, pid, target_tid)

result = {{"ok": ok, "reason": reason, "pid": pid, "target_tid": target_tid, "tids": tids}}
if ok:
    result["target_state_after_seize"] = st._thread_state(pid, target_tid)
    result["sibling_states"] = {{t: st._thread_state(pid, int(t)) for t in tids if int(t) != target_tid}}
    result["process_alive_after_seize"] = os.path.isdir(f"/proc/{{pid}}")

    ret = libc.ptrace(st._PTRACE_DETACH, target_tid, 0, 0)
    time.sleep(0.3)
    result["detach_ret"] = ret
    result["target_state_after_detach"] = st._thread_state(pid, target_tid)

print(json.dumps(result))
# This test process is both the real fork() parent of pid and (until DETACH,
# above) its ptrace tracer -- a dual relationship a production tracer never
# has. A pending ptrace-stop notification left unconsumed by that dual role
# blocks the final waitpid() below indefinitely, even after DETACH and even
# though the target has already been sent SIGKILL. Draining any pending
# notification first avoids the deadlock.
try:
    os.waitpid(-1, os.WNOHANG)
except ChildProcessError:
    pass
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
"""


def _run_driver():
    r = subprocess.run([sys.executable, "-c", _DRIVER], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"driver failed: {r.stderr}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_seize_and_interrupt_suspends_only_target_thread():
    result = _run_driver()
    assert result["ok"], result["reason"]
    assert result["target_state_after_seize"] == "t"
    assert all(state == "S" for state in result["sibling_states"].values())
    assert result["process_alive_after_seize"]


def test_detach_resumes_the_suspended_thread():
    result = _run_driver()
    assert result["ok"], result["reason"]
    assert result["detach_ret"] == 0
    assert result["target_state_after_detach"] == "S"


def test_seize_fails_cleanly_on_nonexistent_tid():
    driver = f"""
import sys
sys.path.insert(0, {_HELPER_DIR!r})
import suspend_thread as st
libc = st._libc()
ok, reason = st._seize_and_interrupt(libc, 999999, 999999)
print(ok, reason)
"""
    r = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0
    assert r.stdout.startswith("False")
