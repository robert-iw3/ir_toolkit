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

    def _addr_context(addr, vads, mods):
        """VAD perms/type + backing module path for a match address. region='file' when
        the address is backed by a loaded module or an Image/Mapped VAD; else 'anon'
        (Private/unbacked - where injected/reflective code lives)."""
        prot, vtype, path = "", "", ""
        for v in vads:
            try:
                if int(v["start"]) <= addr < int(v["end"]):
                    prot, vtype = v.get("protection", ""), str(v.get("type", "")).strip()
                    break
            except Exception:
                continue
        for m in mods:
            try:
                if m.base <= addr < m.base + m.image_size:
                    path = m.fullname or m.name or ""
                    break
            except Exception:
                continue
        region = "file" if (path or "image" in vtype.lower() or "mapped" in vtype.lower()) else "anon"
        return region, prot, path

    for p in scannable:
        emit({"t": "start", "pid": p.pid})         # written BEFORE the risky scan
        try:
            y = p.search_yara(yac)
            timer = threading.Timer(timeout_s, y.abort)
            timer.start()
            try:
                hits = y.result()
            finally:
                timer.cancel()
            try:
                vads = p.maps.vad()
            except Exception:
                vads = []
            try:
                mods = p.module_list()
            except Exception:
                mods = []
            canary = False
            agg = {}   # (rule, region, perms, base(path)) -> {rule,region,perms,path,strings,n}
            for h in (hits or []):
                rn = str(h.get("id", ""))
                matches = h.get("matches", {}) or {}
                if rn == CANARY:
                    canary = True
                    continue
                addr = next((vlist[0] for vlist in matches.values() if vlist), None)
                region, prot, path = _addr_context(addr, vads, mods) if addr is not None else ("", "", "")
                key = (rn, region, prot, os.path.basename(path))
                ent = agg.setdefault(key, {"rule": rn, "region": region, "perms": "",
                                           "path": path, "strings": set(), "n": 0,
                                           "_prot": prot})
                ent["n"] += sum(len(v) for v in matches.values())
                ent["strings"].update(matches.keys())
            hits_out = [{"rule": e["rule"], "region": e["region"], "perms": e["_prot"],
                         "path": e["path"], "strings": sorted(e["strings"]), "n": e["n"]}
                        for e in agg.values()]
        except Exception as e:
            emit({"t": "result", "pid": p.pid, "name": p.name, "canary": False,
                  "hits": [], "error": str(e)})
            continue
        emit({"t": "result", "pid": p.pid, "name": p.name, "canary": canary, "hits": hits_out})

    emit({"t": "done"})
    out.close()


if __name__ == "__main__":
    main()
