"""thread_inventory.py -- per-PID thread (TID) enumeration and cross-referencing
against analyze_memory_linux.py's memory-forensic 'Anomalous Call Stack (memory)'
findings.

A thread's saved instruction pointer cannot be read live via /proc (kstkeip is
zeroed under kptr_restrict=1, the standard hardened default -- verified
empirically, not assumed). The reliable source for "is this thread's IP inside
unbacked memory" is the memory image itself (analyze_memory_linux.py's
linux.pscallstack analysis); these tests cover thread_inventory.py's live TID
enumeration and its cross-reference against that already-flagged data.
"""
import json
import subprocess
import sys
import time

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import thread_inventory as ti  # noqa: E402


def types(findings):
    return {f["Type"] for f in findings}


def test_enumerate_threads_real_multithreaded_process():
    driver = ("import threading, time\n"
             "def worker():\n"
             "    time.sleep(15)\n"
             "for _ in range(3):\n"
             "    threading.Thread(target=worker, daemon=True).start()\n"
             "time.sleep(15)\n")
    proc = subprocess.Popen([sys.executable, "-c", driver])
    try:
        time.sleep(0.3)
        threads = ti.enumerate_threads(proc.pid)
        assert len(threads) >= 4                      # main + 3 workers
        assert any(t["is_leader"] for t in threads)
        assert all(t["pid"] == proc.pid for t in threads)
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_analyze_pid_emits_inventory_finding():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        time.sleep(0.2)
        ti.FINDINGS.clear()
        ti.analyze_pid(proc.pid)
        assert "Process Thread Inventory (memory)" in types(ti.FINDINGS)
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_analyze_pid_missing_process_is_hunt_error():
    ti.FINDINGS.clear()
    ti.analyze_pid(999999999)
    assert ti.FINDINGS and ti.FINDINGS[0]["Type"] == "Hunt Error"


def test_flagged_tid_match_escalates_to_corroborated_injected_thread(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        time.sleep(0.2)
        ti.FINDINGS.clear()
        ti.analyze_pid(proc.pid, flagged_tids={str(proc.pid)})
        found = [f for f in ti.FINDINGS
                if f["Type"] == "Corroborated Injected Thread (memory+live)"]
        assert found
        assert found[0]["Severity"] == "Critical"
        assert f"IR_TARGET_TIDS={proc.pid}:{proc.pid}" in found[0]["Details"]
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_no_flagged_tids_does_not_escalate():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        time.sleep(0.2)
        ti.FINDINGS.clear()
        ti.analyze_pid(proc.pid)
        assert "Corroborated Injected Thread (memory+live)" not in types(ti.FINDINGS)
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_flagged_tids_from_report_dir_parses_both_target_shapes(tmp_path):
    findings = [
        {"Type": "Anomalous Call Stack (memory)", "Target": "PID 1234 (nginx) TID 1240",
         "Details": "stack anomaly", "Severity": "Medium", "MITRE": "T1055"},
        {"Type": "Anomalous Call Stack (memory)", "Target": "worker (TID 5678)",
         "Details": "stack anomaly, owning PID unresolved", "Severity": "Medium", "MITRE": "T1055"},
        {"Type": "Process Thread Inventory (memory)", "Target": "PID: 1 (init)",
         "Details": "not relevant", "Severity": "Info", "MITRE": "N/A"},
    ]
    (tmp_path / "Memory_Findings_20260706_000000.json").write_text(json.dumps(findings))
    tids = ti._flagged_tids_from_report_dir(str(tmp_path))
    assert tids == {"1240", "5678"}


def test_flagged_tids_from_report_dir_empty_when_no_matches(tmp_path):
    (tmp_path / "Memory_Findings_20260706_000000.json").write_text(json.dumps([
        {"Type": "Hidden Process (memory)", "Target": "PID 1 (init)",
         "Details": "x", "Severity": "High", "MITRE": "T1014"},
    ]))
    assert ti._flagged_tids_from_report_dir(str(tmp_path)) == set()
