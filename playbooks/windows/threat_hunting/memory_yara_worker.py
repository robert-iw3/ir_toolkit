#!/usr/bin/env python3
"""Isolated YARA memory-scan worker.

Scans process memory with a precompiled .yac and streams JSONL results. Runs as a
subprocess of memory_forensic.py so a native MemProcFS segfault on a pathological
process (e.g. dwm.exe, whose GPU mappings crash the scanner) cannot kill the whole
analysis. On crash the parent restarts us with the offending PIDs in the skip list,
so we resume past them. The compiled ruleset includes the DOS-stub canary, so each
result records whether the engine actually inspected memory.

argv: <image> <yac> <results_jsonl> <skip_csv> <mpc_dir> <timeout_sec>
"""
import sys, os, glob, json, threading

CANARY = "IRToolkit_Canary_DOSStub"
KERNEL = {"system", "secure system", "registry", "memory compression",
          "interrupts", "idle", "mssmbios", "memcompression"}


def main():
    image, yac, results_path, skip_csv, mpc_dir, timeout_s = sys.argv[1:7]
    timeout_s = int(timeout_s)
    skip = {int(x) for x in skip_csv.split(",") if x.strip()}

    os.add_dll_directory(mpc_dir)
    sys.path.insert(0, mpc_dir)
    for z in glob.glob(os.path.join(mpc_dir, "python", "python3*.zip")):
        sys.path.insert(0, z)
    import vmmpyc

    out = open(results_path, "a", encoding="utf-8")
    def emit(rec):
        out.write(json.dumps(rec) + "\n")
        out.flush()
        os.fsync(out.fileno())          # survive a segfault on the very next call

    vmm = vmmpyc.Vmm(["-device", image, "-disable-symbolserver", "-disable-python"])

    def is_sys(p):
        return p.name.lower() in KERNEL or p.pid <= 8

    scannable = [p for p in vmm.process_list() if not is_sys(p) and p.pid not in skip]

    for p in scannable:
        emit({"t": "start", "pid": p.pid})         # written BEFORE the risky scan
        res = {}
        try:
            y = p.search_yara(yac)
            timer = threading.Timer(timeout_s, y.abort)
            timer.start()
            try:
                hits = y.result()
            finally:
                timer.cancel()
            for h in (hits or []):
                rn = str(h.get("id", ""))
                res[rn] = res.get(rn, 0) + sum(len(v) for v in h.get("matches", {}).values())
        except Exception as e:
            emit({"t": "result", "pid": p.pid, "name": p.name, "canary": False,
                  "hits": [], "error": str(e)})
            continue
        emit({"t": "result", "pid": p.pid, "name": p.name,
              "canary": CANARY in res,
              "hits": [[k, v] for k, v in res.items() if k != CANARY]})

    emit({"t": "done"})
    out.close()


if __name__ == "__main__":
    main()
