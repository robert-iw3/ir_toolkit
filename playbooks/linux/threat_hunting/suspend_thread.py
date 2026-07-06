#!/usr/bin/env python3
"""
suspend_thread.py - persistently suspend ONE thread of a running process via
ptrace, without killing the process or any of its other threads.

Signal delivery cannot do this: a fatal signal's default action (SIGKILL,
unhandled SIGTERM) is process-wide regardless of which thread receives it
(`man 7 signal`), so tgkill(2) targeted at one TID still tears down the
whole thread group.

The mechanism used here instead: PTRACE_SEIZE + PTRACE_INTERRUPT on a
specific TID puts only that thread into a tracing-stop state; sibling
threads keep running. This suspension holds only as long as the tracer
process stays alive -- the kernel auto-detaches (resuming the thread) the
moment the tracer exits, even without an explicit PTRACE_DETACH. This script
is therefore a persistent daemon, not a one-shot helper.

That lifecycle doubles as the rollback mechanism: 06_restore.sh reverses a
suspension by killing this daemon's PID (recorded in the rollback journal),
and the kernel's auto-detach-on-exit resumes the thread.

Usage:
    suspend_thread.py --tgid 1234 --tid 1240 [--incident-id ID]
    Prints one JSON line to stdout on success:
      {"status": "suspended", "daemon_pid": <pid>, "tgid": 1234, "tid": 1240}
    then detaches from the controlling terminal and holds the suspension
    until it receives SIGTERM (clean PTRACE_DETACH) or the target exits.
    On failure, prints {"status": "failed", "reason": "..."} and exits 1
    without detaching -- the caller must not journal a PID that was never
    started, since there would be nothing to roll back.
"""
import argparse
import ctypes
import json
import os
import signal
import sys
import time

_PTRACE_SEIZE = 0x4206
_PTRACE_INTERRUPT = 0x4207
_PTRACE_DETACH = 17
_POLL_INTERVAL_S = 5


def _libc():
    return ctypes.CDLL("libc.so.6", use_errno=True)


def _thread_state(tgid, tid):
    try:
        with open(f"/proc/{tgid}/task/{tid}/status") as f:
            for ln in f:
                if ln.startswith("State:"):
                    return ln.split(":", 1)[1].strip().split()[0]
    except (FileNotFoundError, OSError):
        return None
    return None


def _seize_and_interrupt(libc, tgid, tid):
    ret = libc.ptrace(_PTRACE_SEIZE, tid, 0, 0)
    if ret != 0:
        return False, f"PTRACE_SEIZE failed (errno={ctypes.get_errno()})"
    ret = libc.ptrace(_PTRACE_INTERRUPT, tid, 0, 0)
    if ret != 0:
        return False, f"PTRACE_INTERRUPT failed (errno={ctypes.get_errno()})"
    # Give the kernel a moment to actually land the stop, then verify --
    # never report success without confirming the real /proc state.
    for _ in range(20):
        time.sleep(0.05)
        state = _thread_state(tgid, tid)
        if state == "t":
            return True, None
    return False, f"target did not reach tracing-stop state (last seen: {_thread_state(tgid, tid)!r})"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tgid", type=int, required=True)
    ap.add_argument("--tid", type=int, required=True)
    ap.add_argument("--incident-id", default="UNKNOWN")
    args = ap.parse_args()

    if not os.path.isdir(f"/proc/{args.tgid}/task/{args.tid}"):
        print(json.dumps({"status": "failed", "reason": "target tgid/tid not found"}))
        return 1

    libc = _libc()
    ok, reason = _seize_and_interrupt(libc, args.tgid, args.tid)
    if not ok:
        print(json.dumps({"status": "failed", "reason": reason}))
        return 1

    # Confirmed suspended. Report success with THIS process's own PID -- the
    # rollback journal records exactly this PID to kill later, so it must
    # stay valid. Deliberately does NOT double-fork (the traditional daemonize
    # pattern): a double-fork's second child gets a PID the caller never sees,
    # which would make the rollback journal's PID entry point at nothing.
    # A single setsid() still detaches from the controlling terminal/session
    # (so the caller's shell exiting doesn't SIGHUP this process) while
    # keeping the reported PID authoritative.
    print(json.dumps({"status": "suspended", "daemon_pid": os.getpid(),
                      "tgid": args.tgid, "tid": args.tid}))
    sys.stdout.flush()

    os.setsid()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        try:
            os.dup2(devnull, fd)
        except OSError:
            pass

    def _on_term(_signum, _frame):
        libc.ptrace(_PTRACE_DETACH, args.tid, 0, 0)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)

    while True:
        time.sleep(_POLL_INTERVAL_S)
        if not os.path.isdir(f"/proc/{args.tgid}"):
            # Target process is gone entirely -- nothing left to hold.
            break


if __name__ == "__main__":
    sys.exit(main())
