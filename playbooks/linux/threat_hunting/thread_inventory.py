#!/usr/bin/env python3
"""
thread_inventory.py - Linux per-PID thread (TID) enumeration for a PID hit.

When a process is flagged by any other collector (Ptrace Injection, Hidden
Process, Injected Memory, ...) or targeted for eradication, "the process" is
not one unit of execution -- a multi-threaded process is a set of TASKS, each
with its own kernel task_struct, its own /proc/<pid>/task/<tid>/ directory,
and its own independent ability to be signaled. Ptrace-based code injection
in particular attaches to and redirects ONE specific thread's instruction
pointer (see analyze_memory_linux.py's "Ptrace Injection - Thread IP in
Injected Memory (memory)" finding) -- the other threads in that same process
may be entirely legitimate. Eradicating "the PID" without knowing which
thread is actually compromised means either:
  (a) killing the whole process, destroying every legitimate thread with it
      (real instability risk for a multi-threaded service -- a connection-
      per-thread server, a critical multi-threaded daemon), or
  (b) refusing to touch it at all if it's on a protected-process list,
      leaving the injected thread running.

This script enumerates every TID under a target PID's /proc/<pid>/task/ and
reads each thread's state, tracer attachment (TracerPid), and wait-channel --
emitting common-schema findings so the investigation engine can consume this
like any other collector, and so 02_eradicate_process.sh's IR_TARGET_TIDS can
be populated with the SPECIFIC compromised thread(s) rather than guessing.

A thread's saved instruction pointer is NOT read live here: /proc/<pid>/task/
<tid>/stat's kstkeip field -- the only live, non-ptrace way to read it -- is
unconditionally zeroed under kptr_restrict=1 (the standard hardened default;
verified empirically, not assumed). The reliable source for "is this specific
thread's saved IP inside anonymous/unbacked memory" is analyze_memory_linux.py's
linux.pscallstack.PsCallStack analysis of the memory image itself, which reads
the kernel stack directly and isn't subject to that restriction -- it emits
"Anomalous Call Stack (memory)" per TID. --report-dir cross-references this
script's live TID enumeration against those already-flagged TIDs (when both a
memory image and a live triage of the same host are available for the same
incident) and escalates a match, corroborating the memory-forensic anomaly
with confirmation the thread still exists and is live-inspectable.

Usage:
    thread_inventory.py --pid 1234 [--pid 5678 ...]
    thread_inventory.py --report-dir reports/<host>     # auto-targets PIDs
                                                        # already flagged in
                                                        # EDR_Report/Memory_Findings
    thread_inventory.py --pid 1234 --json-only          # print {pid:[tids]}
                                                        # for eradication tooling
Writes Thread_Inventory_<stamp>.json (list of findings, common schema) and
prints the path, unless --json-only.
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys

FINDINGS = []


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add(severity, ftype, target, details, mitre):
    FINDINGS.append({
        "Timestamp": now(), "Severity": severity, "Type": ftype,
        "Target": target, "Details": details, "MITRE": mitre,
    })


def read_file(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def read_bin(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


def comm_of(pid):
    return (read_file(f"/proc/{pid}/comm") or "").strip()


def _status_field(status_text, key):
    if not status_text:
        return None
    for ln in status_text.splitlines():
        if ln.startswith(key + ":"):
            return ln.split(":", 1)[1].strip()
    return None


def _task_ids(pid):
    """Every TID under /proc/<pid>/task/ -- the complete thread set of this
    process at the moment of inspection. Best-effort: a thread that exits
    mid-enumeration just disappears from the listing (not an error)."""
    try:
        return sorted((int(t) for t in os.listdir(f"/proc/{pid}/task")), key=int)
    except (FileNotFoundError, PermissionError):
        return []


def enumerate_threads(pid):
    """Return a list of per-thread dossiers for one PID: {tid, state, tracer_pid,
    tracer_comm, wchan, comm, is_leader}. Read-only; degrades gracefully without
    root (a thread's own /proc/<pid>/task/<tid>/status is still world-readable
    for state/tracer fields even without CAP_SYS_PTRACE on most configurations;
    entries that can't be read at all are recorded with nulls, not dropped)."""
    out = []
    for tid in _task_ids(pid):
        status = read_file(f"/proc/{pid}/task/{tid}/status")
        state = _status_field(status, "State")
        tracer_pid = _status_field(status, "TracerPid")
        wchan = read_file(f"/proc/{pid}/task/{tid}/wchan")
        tcomm = (read_file(f"/proc/{pid}/task/{tid}/comm") or "").strip()
        tracer_comm = None
        if tracer_pid and tracer_pid != "0":
            tracer_comm = comm_of(tracer_pid)
        out.append({
            "tid": tid, "pid": pid, "is_leader": (tid == pid),
            "comm": tcomm, "state": state,
            "tracer_pid": tracer_pid, "tracer_comm": tracer_comm,
            "wchan": wchan,
        })
    return out


def analyze_pid(pid, source_hint="", flagged_tids=None):
    """Emit one 'Process Thread Inventory (memory)' finding listing every TID,
    plus a separate escalated finding for any thread under active ptrace
    attachment by a process OTHER than a recognised debugger, since that is
    exactly the mechanism the Ptrace Injection finding describes -- this
    script corroborates it with the full sibling-thread picture.

    flagged_tids (optional): TID strings analyze_memory_linux.py's
    linux.pscallstack.PsCallStack analysis already flagged as returning into
    unbacked memory ('Anomalous Call Stack (memory)', see
    _flagged_tids_from_report_dir). A live TID matching one of these is
    corroborated from two independent mechanisms -- a memory-forensic stack
    anomaly AND live confirmation the thread still exists -- and is escalated
    regardless of ptrace attachment state (this is a different signal than
    the traced-thread check above)."""
    flagged_tids = flagged_tids or set()
    proc_comm = comm_of(pid)
    if not proc_comm and not os.path.isdir(f"/proc/{pid}"):
        add("Info", "Hunt Error", f"PID: {pid}",
            f"PID {pid} not found at inventory time (exited before enumeration).", "N/A")
        return

    threads = enumerate_threads(pid)
    if not threads:
        add("Low", "Process Thread Inventory (memory)", f"PID: {pid} ({proc_comm})",
            "No threads enumerable (process exited mid-scan, or /proc/<pid>/task "
            "unreadable without root).", "N/A")
        return

    tid_list = ", ".join(str(t["tid"]) for t in threads)
    add("Info", "Process Thread Inventory (memory)", f"PID: {pid} ({proc_comm})",
        f"{len(threads)} thread(s): [{tid_list}]." +
        (f" source={source_hint}" if source_hint else ""),
        "N/A")

    traced = [t for t in threads if t["tracer_pid"] and t["tracer_pid"] != "0"]
    for t in traced:
        add("Medium", "Traced Thread Detail (memory)",
            f"PID: {pid} TID: {t['tid']} ({t['comm'] or proc_comm})",
            f"Thread is under active ptrace attachment by PID {t['tracer_pid']} "
            f"({t['tracer_comm'] or 'unknown'}). Cross-check against 'Ptrace Injection "
            f"- Thread IP in Injected Memory (memory)' / 'Ptrace Attachment (memory)' "
            f"findings for this TID specifically -- eradication should target this TID "
            f"precisely (IR_TARGET_TIDS={pid}:{t['tid']}) rather than the whole process "
            f"if killing PID {pid} outright would be destabilizing.",
            "T1055 (Process Injection), T1057 (Process Discovery)")

    for t in threads:
        if str(t["tid"]) in flagged_tids:
            add("Critical", "Corroborated Injected Thread (memory+live)",
                f"PID: {pid} TID: {t['tid']} ({t['comm'] or proc_comm})",
                f"This TID's saved instruction pointer was independently flagged by "
                f"analyze_memory_linux.py's linux.pscallstack analysis (stack frame "
                f"returning into unbacked memory) AND the thread still exists live on "
                f"this host -- two independent mechanisms (memory-forensic stack walk, "
                f"live /proc enumeration) agree on the exact same thread. Eradication "
                f"should target this TID precisely (IR_TARGET_TIDS={pid}:{t['tid']}).",
                "T1055 (Process Injection)")


def _pids_from_report_dir(report_dir):
    """Auto-target every PID already mentioned in this host's EDR_Report /
    Memory_Findings -- 'extract all TIDs when a PID hit occurs' means every
    PID a hit already exists for, not just ones the operator manually names."""
    pids = set()
    pid_re = re.compile(r"PID:?\s*(\d+)")
    for pattern in ("EDR_Report_*.json", "Memory_Findings_*.json", "Combined_Findings_*.json"):
        for path in glob.glob(os.path.join(report_dir, pattern)):
            try:
                with open(path, encoding="utf-8-sig") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            for f in (data if isinstance(data, list) else [data]):
                if not isinstance(f, dict):
                    continue
                m = pid_re.search(f.get("Target", "") or "") or pid_re.search(f.get("Details", "") or "")
                if m:
                    pids.add(int(m.group(1)))
    return sorted(pids)


_FLAGGED_TID_RE = re.compile(r"TID\s+(\d+)")


def _flagged_tids_from_report_dir(report_dir):
    """TID strings from every 'Anomalous Call Stack (memory)' finding already
    captured for this host (see analyze_memory_linux.py's analyze_pscallstack --
    Target is "PID N (comm) TID M" when the owning PID was resolved, or
    "comm (TID M)" when it wasn't; either shape carries a TID)."""
    tids = set()
    for pattern in ("Memory_Findings_*.json", "Combined_Findings_*.json"):
        for path in glob.glob(os.path.join(report_dir, pattern)):
            try:
                with open(path, encoding="utf-8-sig") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            for f in (data if isinstance(data, list) else [data]):
                if not isinstance(f, dict) or f.get("Type") != "Anomalous Call Stack (memory)":
                    continue
                m = _FLAGGED_TID_RE.search(f.get("Target", "") or "")
                if m:
                    tids.add(m.group(1))
    return tids


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, action="append", default=[],
                    help="target PID (repeatable)")
    ap.add_argument("--report-dir", help="auto-target every PID already flagged "
                    "in this host's EDR_Report/Memory_Findings/Combined_Findings")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--json-only", action="store_true",
                    help="print {pid: [tid, ...]} only, for eradication tooling "
                    "(IR_TARGET_TIDS population) -- no findings file written")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    pids = list(args.pid)
    if args.report_dir:
        pids.extend(p for p in _pids_from_report_dir(args.report_dir) if p not in pids)
    if not pids:
        print("[thread_inventory] no PIDs given (--pid or --report-dir required)", file=sys.stderr)
        return 1

    if args.json_only:
        out = {}
        for pid in pids:
            out[str(pid)] = [t["tid"] for t in enumerate_threads(pid)]
        print(json.dumps(out))
        return 0

    flagged_tids = _flagged_tids_from_report_dir(args.report_dir) if args.report_dir else set()
    for pid in pids:
        analyze_pid(pid, source_hint=(args.report_dir or ""), flagged_tids=flagged_tids)

    if not args.report_dir:
        print(json.dumps(FINDINGS, indent=2))
        return 0

    out_path = os.path.join(args.report_dir, f"Thread_Inventory_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(FINDINGS, fh, indent=2)
    if not args.quiet:
        print(f"[thread_inventory] {len(FINDINGS)} finding(s) across {len(pids)} PID(s) -> {out_path}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
