"""Per-process Linux YARA worker (linux_yara_worker.py + linux_yara helpers).

The proven, ATTRIBUTED engine: Volatility vmayarascan driven one process at a time, with the same
robustness the Windows worker has — per-PID attribution, a resumable rolling JSONL, crash isolation
(skip the in-flight PID on resume), and a per-process canary self-test. These tests cover that
LOGIC (no memory image needed); the actual scan is exercised by the live run.
"""
import json
import os
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import linux_yara as ly                 # noqa: E402
import linux_yara_worker as lw          # noqa: E402


def _jsonl(*recs):
    return [json.dumps(r) for r in recs]


def test_parse_worker_jsonl_attributes_per_pid():
    lines = _jsonl(
        {"t": "start", "pid": "100", "name": "sshd"},
        {"t": "result", "pid": "100", "name": "sshd", "canary": True, "timed_out": False,
         "hits": [["Linux_Trojan_Gafgyt", 2]]},
        {"t": "start", "pid": "200", "name": "nginx"},
        {"t": "result", "pid": "200", "name": "nginx", "canary": True, "timed_out": False,
         "hits": []},
        {"t": "done", "scanned": 2})
    s = ly.parse_worker_jsonl(lines)
    assert s["done"] is True and s["canary_hits"] == 2          # both procs proved scanned
    rows = ly.worker_rows_to_yara_rows(s["finished"])
    # the hit is attributed to PID 100 (sshd), NOT a bare offset
    assert {"Rule": "Linux_Trojan_Gafgyt", "PID": "100", "Process": "sshd"} in rows
    assert len(rows) == 1                                        # nginx had no hits


def test_enriched_hits_carry_vma_context():
    # the targeted/enriched worker records WHERE each rule matched — the FP/TP disambiguator
    lines = _jsonl(
        {"t": "start", "pid": "4671", "name": "firefox-bin"},
        {"t": "result", "pid": "4671", "name": "firefox-bin", "canary": True, "timed_out": False,
         "hits": [{"rule": "ELF_Mirai", "perms": "r-x", "region": "file",
                   "path": "/usr/lib/firefox/libxul.so", "strings": ["$elf_magic"], "n": 1}]},
        {"t": "done"})
    s = ly.parse_worker_jsonl(lines)
    rows = ly.worker_rows_to_yara_rows(s["finished"])
    r = rows[0]
    assert r["Rule"] == "ELF_Mirai" and r["PID"] == "4671"
    # context preserved: file-backed r-x mapping of a library + only the generic ELF-magic string ->
    # the analyst can see this is the rule grazing a loaded .so, not injected code
    assert r["Region"] == "file" and r["Perms"] == "r-x"
    assert r["Path"].endswith("libxul.so") and r["Strings"] == ["$elf_magic"]


def test_carve_region_writes_bin_and_metadata(tmp_path):
    # a carved injected region must land on disk as raw bytes + a JSON sidecar carrying the base
    # address (for correct Binary Ninja addressing) + attribution
    data = b"\x90\x90\x48\x31\xc0" + b"\x00" * 100      # fake shellcode-ish bytes
    out = lw.carve_region(str(tmp_path), "mem.raw", 1337, "evil/proc", 0x7f0010,
                          data, "rwx", "anon", "", ["Linux_Trojan_X"])
    assert out and out.endswith(".bin") and os.path.isfile(out)
    assert open(out, "rb").read() == data                # exact bytes, inert on disk
    meta = json.load(open(out[:-4] + ".json"))
    assert meta["pid"] == "1337" and meta["base_address"] == hex(0x7f0010)
    assert meta["region"] == "anon" and meta["perms"] == "rwx"
    assert meta["matched_rules"] == ["Linux_Trojan_X"] and meta["size"] == len(data)
    assert "x86_64" in meta["arch_hint"]
    assert meta["injected"] is True and "INJECTED" in meta["note"]   # anon+exec -> injected TP


def test_carve_file_backed_is_not_labelled_injected(tmp_path):
    # a file-backed hit (carve-any triage) must NOT be mislabelled as injected
    out = lw.carve_region(str(tmp_path), "m.raw", 99, "nvidia-powerd", 0x400000,
                          b"\x7fELF" + b"\x00" * 64, "r--", "file", "/usr/bin/nvidia-powerd", ["R"])
    meta = json.load(open(out[:-4] + ".json"))
    assert meta["injected"] is False and "INJECTED" not in meta["note"]
    assert "/usr/bin/nvidia-powerd" in meta["note"]      # points at the file to verify


def test_carve_region_skips_oversize(tmp_path):
    # guard: never dump a region bigger than the cap (avoids accidental multi-GB carves)
    assert lw.carve_region(str(tmp_path), "m", 1, "p", 0, b"\x00" * (lw.CARVE_MAX + 1),
                           "rwx", "anon", "", ["R"]) is None


def test_crashing_pid_isolates_in_flight():
    lines = _jsonl(
        {"t": "start", "pid": "100"}, {"t": "result", "pid": "100", "hits": []},
        {"t": "start", "pid": "200"})                            # 200 started, never finished -> crasher
    s = ly.parse_worker_jsonl(lines)
    assert ly.crashing_pid(s["started_pids"], s["finished_pids"]) == "200"
    assert ly.crashing_pid({"1"}, {"1"}) is None                # all accounted for


def test_resume_skips_finished_and_crasher(tmp_path):
    p = tmp_path / "_yara_pp.jsonl"
    p.write_text("\n".join(_jsonl(
        {"t": "start", "pid": "100"}, {"t": "result", "pid": "100", "hits": []},
        {"t": "start", "pid": "200"})) + "\n")                   # 100 done, 200 crashed mid-scan
    skip = lw._done_pids(str(p))
    assert "100" in skip and "200" in skip                      # both skipped on resume (no infinite crash loop)


def test_timeout_is_recorded_not_silent():
    lines = _jsonl(
        {"t": "start", "pid": "9"},
        {"t": "result", "pid": "9", "name": "huge", "canary": False, "timed_out": True, "hits": []})
    s = ly.parse_worker_jsonl(lines)
    assert s["timeouts"] == ["9"]                                # a per-process timeout is surfaced
    # a process that timed out without the canary firing is NOT trustworthy-clean
    assert ly.yara_trust_verdict(0, s["canary_hits"])["trusted"] is False
