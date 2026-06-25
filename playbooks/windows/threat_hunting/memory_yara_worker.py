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
import sys, os, re, glob, json, threading

CANARY = "IRToolkit_Canary_DOSStub"
KERNEL = {"system", "secure system", "registry", "memory compression",
          "interrupts", "idle", "mssmbios", "memcompression"}
CARVE_MAX = 64 * 1024 * 1024             # only carve regions up to 64MB (injected code is small;
                                         # guards against dumping a giant region by accident)


def _safe(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(s))[:48] if s else "x"


def carve_region(carve_dir, image, pid, name, base, data, perms, region, vad_type, path, rules,
                 arch="x86_64"):
    """A YARA hit in a Private + executable VAD is injected/unbacked code (the Windows analogue of
    Linux anon+exec) - the strongest true-positive signal. Carve that region to <carve_dir>/ (raw
    bytes + a JSON sidecar with base address + arch hint + attribution) so it can be loaded into
    Binary Ninja for deeper RE. Returns the .bin path or None. Reversible/inert: just bytes on disk,
    never executed. Mirrors the Linux linux_yara_worker.carve_region sidecar schema."""
    if not data or len(data) > CARVE_MAX:
        return None
    try:
        os.makedirs(carve_dir, exist_ok=True)
        stem = f"pid{pid}_{_safe(name)}_0x{base:x}"
        binp = os.path.join(carve_dir, stem + ".bin")
        with open(binp, "wb") as fh:
            fh.write(data)
        injected = region == "anon" and "x" in (perms or "").lower()
        if injected:
            note = ("INJECTED Private+exec VAD (no on-disk backing) - strong true-positive; treat as "
                    "live malware, analyse only in the isolated Binary Ninja container.")
        elif region == "file":
            note = (f"File-backed {perms} region of {path or '?'} - a YARA hit here is often a rule "
                    f"grazing a loaded binary/library; verify that file's hash/package before "
                    f"treating it as malicious. Analyse only in the isolated container.")
        else:
            note = (f"{region or 'unknown'} {perms} region carried a YARA hit. Analyse only in the "
                    f"isolated Binary Ninja container.")
        meta = {
            "carved_from": os.path.basename(str(image)), "pid": str(pid), "process": name,
            "base_address": hex(base),              # load at this base in Binary Ninja for true addrs
            "size": len(data), "perms": perms, "region": region, "backing_path": path,
            "injected": injected, "matched_rules": sorted(set(rules)),
            "arch_hint": arch,                      # confirm in the loader (wow64 -> x86)
            "load_as": "Raw (Mapped) - set platform/arch, base = base_address, then re-analyze",
            "note": note,
            "protection": perms, "vad_type": vad_type,   # Windows context (PAGE_*/Private|Image|Mapped)
        }
        with open(os.path.join(carve_dir, stem + ".json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        return binp
    except OSError:
        return None


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

    carve_dir = os.environ.get("IR_CARVE_DIR") or None       # set by Analyze-Memory.ps1 -Carve
    carve_any = os.environ.get("IR_CARVE_ANY") == "1"        # triage: carve ANY hit's region

    def _addr_context(addr, vads, mods):
        """VAD perms/type + backing module path for a match address. region='file' when
        the address is backed by a loaded module or an Image/Mapped VAD; else 'anon'
        (Private/unbacked - where injected/reflective code lives). Also returns the VAD
        start/end so the carve can read the whole region."""
        prot, vtype, path, vstart, vend = "", "", "", None, None
        for v in vads:
            try:
                if int(v["start"]) <= addr < int(v["end"]):
                    prot, vtype = v.get("protection", ""), str(v.get("type", "")).strip()
                    vstart, vend = int(v["start"]), int(v["end"])
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
        return region, prot, path, vstart, vend, vtype

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
            carve_t = {}   # vstart -> {vend,region,prot,path,vtype,rules} regions to carve for this PID
            for h in (hits or []):
                rn = str(h.get("id", ""))
                matches = h.get("matches", {}) or {}
                if rn == CANARY:
                    canary = True
                    continue
                addr = next((vlist[0] for vlist in matches.values() if vlist), None)
                if addr is not None:
                    region, prot, path, vstart, vend, vtype = _addr_context(addr, vads, mods)
                else:
                    region, prot, path, vstart, vend, vtype = "", "", "", None, None, ""
                key = (rn, region, prot, os.path.basename(path))
                ent = agg.setdefault(key, {"rule": rn, "region": region, "perms": "",
                                           "path": path, "strings": set(), "n": 0,
                                           "_prot": prot})
                ent["n"] += sum(len(v) for v in matches.values())
                ent["strings"].update(matches.keys())
                # carve bookkeeping: Private+exec (injected) by default; IR_CARVE_ANY adds file-backed
                if carve_dir and vstart is not None:
                    injected_here = region == "anon" and "x" in (prot or "").lower()
                    if injected_here or carve_any:
                        ct = carve_t.setdefault(vstart, {"vend": vend, "region": region, "prot": prot,
                                                         "path": path, "vtype": vtype, "rules": set()})
                        ct["rules"].add(rn)
            hits_out = [{"rule": e["rule"], "region": e["region"], "perms": e["_prot"],
                         "path": e["path"], "strings": sorted(e["strings"]), "n": e["n"]}
                        for e in agg.values()]
            # CARVE the qualifying regions to tools\binja\data\<id>\ for offline Binary Ninja RE.
            # raw bytes + JSON sidecar, never executed. One file per region (deduped by base address).
            carved = []
            if carve_dir and carve_t:
                try:
                    arch = "x86" if getattr(p, "wow64", False) else "x86_64"
                except Exception:
                    arch = "x86_64"
                for vstart, t in carve_t.items():
                    size = min((t["vend"] or vstart) - vstart, CARVE_MAX)
                    if size <= 0:
                        continue
                    try:
                        data = p.memory.read(vstart, size)
                    except Exception:
                        data = b""
                    if not data:
                        continue
                    cp = carve_region(carve_dir, image, p.pid, p.name, vstart, data, t["prot"],
                                      t["region"], t["vtype"], t["path"], t["rules"], arch)
                    if cp:
                        carved.append(os.path.basename(cp))
        except Exception as e:
            emit({"t": "result", "pid": p.pid, "name": p.name, "canary": False,
                  "hits": [], "error": str(e)})
            continue
        rec = {"t": "result", "pid": p.pid, "name": p.name, "canary": canary, "hits": hits_out}
        if carved:
            rec["carved"] = carved
        emit(rec)

    emit({"t": "done"})
    out.close()


if __name__ == "__main__":
    main()
