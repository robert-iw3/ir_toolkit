#!/usr/bin/env python3
"""Per-process Linux memory YARA scan - Volatility 3 driven IN-PROCESS (init once, loop tasks).

  • per-PID attribution            (each hit carries task.tgid + comm)
  • PER-PROCESS TIMEOUT            (a slow/huge process aborts between VMAs; the scan keeps going)
  • ROLLING, RESUMABLE JSONL       ({"t":"start","pid"} → {"t":"result",...}); a crash/stop leaves a
                                    record so a re-run skips finished + the in-flight (crasher) PID
  • per-process ELF canary         (the canary in the compiled ruleset must fire for a process that
                                    has mapped memory - proves the engine actually read it)

Usage:
  linux_yara_worker.py <image> <compiled.yarc> <results.jsonl> <symbols_dir|->
                       <per_proc_timeout_s> [pids_csv]
Progress to stderr; the authoritative, resumable output is the JSONL.
"""
import json
import os
import re
import sys
import time

CANARY_RULE_NAME = "IRToolkit_Canary_ELF"
SANITY_VMA = 256 * 1024 * 1024           # skip individual VMAs > 256MB (giant file-backed mappings -
                                         # libs/fonts/heap; malware lives in small anon RWX regions)
PROC_BYTE_BUDGET = 768 * 1024 * 1024     # cap total bytes scanned per process so a multi-GB IDE/
                                         # browser process is bounded (the full-coverage path is the
                                         # native engine; vol is the ATTRIBUTED path). 0 = unlimited.
CARVE_MAX = 64 * 1024 * 1024             # only carve regions up to 64MB (injected code is small;
                                         # guards against dumping a giant region by accident)


def _safe(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(s))[:48] if s else "x"


def carve_region(carve_dir, image, pid, name, vm_start, data, perms, region, path, rules):
    """A YARA hit in ANONYMOUS EXECUTABLE memory is injected/unbacked code — the strongest
    true-positive signal. Carve that region to <carve_dir>/ (raw bytes + a JSON sidecar with the
    base address + arch hint + attribution) so it can be loaded into Binary Ninja for deeper RE.
    Returns the .bin path or None. Reversible/inert: just bytes on disk, never executed."""
    import json as _json
    if not data or len(data) > CARVE_MAX:
        return None
    try:
        os.makedirs(carve_dir, exist_ok=True)
        stem = f"pid{pid}_{_safe(name)}_0x{vm_start:x}"
        binp = os.path.join(carve_dir, stem + ".bin")
        with open(binp, "wb") as fh:
            fh.write(data)
        injected = region == "anon" and "x" in (perms or "")
        if injected:
            note = ("INJECTED anon+exec region (no on-disk backing) — strong true-positive; treat as "
                    "live malware, analyse only in the isolated Binary Ninja container.")
        elif region == "file":
            note = (f"File-backed {perms} region of {path or '?'} — a YARA hit here is often a rule "
                    f"grazing a loaded binary/library; verify that file's hash/package before "
                    f"treating it as malicious. Analyse only in the isolated container.")
        else:
            note = (f"{region or 'unknown'} {perms} region carried a YARA hit. Analyse only in the "
                    f"isolated Binary Ninja container.")
        meta = {
            "carved_from": os.path.basename(str(image)), "pid": str(pid), "process": name,
            "base_address": hex(vm_start),          # load at this base in Binary Ninja for true addrs
            "size": len(data), "perms": perms, "region": region, "backing_path": path,
            "injected": injected, "matched_rules": sorted(set(rules)),
            "arch_hint": "x86_64",                  # Linux Intel64 images; confirm in the loader
            "load_as": "Raw (Mapped) — set platform/arch, base = base_address, then re-analyze",
            "note": note,
        }
        with open(os.path.join(carve_dir, stem + ".json"), "w", encoding="utf-8") as fh:
            _json.dump(meta, fh, indent=2)
        return binp
    except OSError:
        return None


def build_context(image, symbols):
    """Construct the Volatility context + kernel module ONCE (the expensive ~130s step)."""
    import io
    import volatility3
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, interfaces, plugins
    import volatility3.plugins
    import volatility3.symbols
    from volatility3.plugins.linux import pslist

    def _quiet_progress(_pct=None, _desc=None):       # avoid flooding the rolling log during init
        return None

    # Minimal in-memory file handler - construct_plugin requires an open_method class, but pslist
    # never dumps a file so it is never actually instantiated.
    class _NullFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
        def __init__(self, preferred_filename):
            io.BytesIO.__init__(self)
            interfaces.plugins.FileHandlerInterface.__init__(self, preferred_filename)

        def writable(self):
            return True

    framework.require_interface_version(2, 0, 0)
    if symbols and symbols != "-":
        volatility3.symbols.__path__.append(os.path.abspath(symbols))
    ctx = contexts.Context()
    framework.import_files(volatility3.plugins, True)
    ctx.config["automagic.LayerStacker.single_location"] = "file://" + os.path.abspath(image)
    automagics = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    constructed = plugins.construct_plugin(ctx, automagics, pslist.PsList, "plugins",
                                           _quiet_progress, _NullFileHandler)
    return ctx, constructed.config["kernel"], pslist.PsList


def _task_name(task):
    try:
        from volatility3.framework.objects import utility
        return utility.array_to_string(task.comm)
    except Exception:
        return ""


def _matched_string_ids(match):
    """The yara STRING identifiers that actually fired (e.g. '$elf_magic' vs '$c2_url') - the single
    best FP/TP tell: a rule that only matched a generic anchor (ELF magic) is noise; one that matched
    a specific C2/behaviour string is real."""
    out = set()
    try:
        for s in match.strings:
            ident = getattr(s, "identifier", None)
            if ident is None and isinstance(s, (list, tuple)) and len(s) >= 2:
                ident = s[1]
            if ident:
                out.add(ident if isinstance(ident, str) else ident.decode("utf-8", "ignore"))
    except Exception:
        pass
    return out


def _vma_context(ctx, task, vma):
    """(perms, region, path) for the VMA a match landed in - the disambiguator. region is 'anon'
    (no backing file → injected/JIT/heap) or 'file' (mapped from disk → likely benign lib/binary)."""
    try:
        perms = vma.get_protection()
    except Exception:
        perms = "?"
    path, region = "", "anon"
    try:
        from volatility3.framework.symbols.linux import LinuxUtilities
        p = LinuxUtilities.path_for_file(ctx, task, vma.vm_file)
        if p:
            path, region = p, "file"
    except Exception:
        pass
    return perms, region, path


def _scan_task(ctx, task, rules, ptimeout, byte_budget=PROC_BYTE_BUDGET, carve_dir=None, image=""):
    """Scan one task's VMAs. Bounded by BOTH a wall-clock timeout (between VMAs) and a per-process
    byte budget (so a multi-GB process can't dominate). Each hit is enriched with the matching VMA's
    permissions + anon/file-backed + path + matched-string ids (the context that disambiguates an
    injected-code hit from a rule grazing a loaded library). When carve_dir is set, a hit in an
    ANONYMOUS EXECUTABLE region (injected code, the TP signal) is CARVED to disk for RE in Binary
    Ninja. Returns (hits[{rule,perms,region,path,strings,n}], canary_bool, capped_bool, had_mem)."""
    proc_layer_name = task.add_process_layer()
    if not proc_layer_name:
        return [], False, False, False            # kernel thread / no address space
    proc_layer = ctx.layers[proc_layer_name]
    agg, canary, capped, had_mem, scanned_bytes = {}, False, False, False, 0
    t0 = time.time()
    mm = task.mm
    if not mm:
        return [], False, False, False
    for vma in mm.get_vma_iter():
        if time.time() - t0 > ptimeout:
            capped = True
            break
        if byte_budget and scanned_bytes >= byte_budget:
            capped = True
            break
        size = int(vma.vm_end - vma.vm_start)
        if size <= 0 or size > SANITY_VMA:
            continue
        try:
            data = proc_layer.read(vma.vm_start, size, pad=True)
        except Exception:
            continue
        had_mem = True
        scanned_bytes += size
        try:
            matches = rules.match(data=data)
        except Exception:
            continue
        if not matches:
            continue
        perms, region, path = _vma_context(ctx, task, vma)
        real = []
        for m in matches:
            if m.rule == CANARY_RULE_NAME:
                canary = True
                continue
            real.append(m.rule)
            key = (m.rule, perms, region, os.path.basename(path))
            ent = agg.setdefault(key, {"rule": m.rule, "perms": perms, "region": region,
                                       "path": path, "strings": set(), "n": 0})
            ent["n"] += 1
            ent["strings"] |= _matched_string_ids(m)
        # CARVE: a real rule hitting anonymous EXECUTABLE memory == injected/unbacked code (TP).
        # IR_CARVE_ANY=1 relaxes this to carve ANY hit's region (test/triage of file-backed hits too).
        carve_this = region == "anon" and "x" in (perms or "")
        if os.environ.get("IR_CARVE_ANY") == "1":
            carve_this = True
        if carve_dir and real and carve_this:
            try:
                tgid = int(task.tgid)
            except Exception:
                tgid = 0
            p = carve_region(carve_dir, image, tgid, _task_name(task), int(vma.vm_start),
                             data, perms, region, path, real)
            if p:
                sys.stderr.write(f"[mem]   CARVED injected region -> {p}\n")
                sys.stderr.flush()
    hits = [{**v, "strings": sorted(v["strings"])} for v in agg.values()]
    return hits, canary, capped, had_mem


def _done_pids(jsonl):
    """PIDs already finished + the in-flight crasher (skip on resume)."""
    started, finished = set(), set()
    if os.path.isfile(jsonl):
        with open(jsonl, encoding="utf-8") as fh:
            for ln in fh:
                try:
                    rec = json.loads(ln)
                except Exception:
                    continue
                if rec.get("t") == "start":
                    started.add(str(rec.get("pid")))
                elif rec.get("t") == "result":
                    finished.add(str(rec.get("pid")))
    return finished | (started - finished)


def main():
    if len(sys.argv) < 6:
        sys.stderr.write(__doc__)
        return 2
    image, yarc, jsonl, symbols, ptimeout = sys.argv[1:6]
    ptimeout = int(ptimeout)
    want_pids = {p.strip() for p in sys.argv[6].split(",")} if len(sys.argv) > 6 else None
    carve_dir = os.environ.get("IR_CARVE_DIR") or None    # set by the analyzer's --carve

    import yara
    rules = yara.load(yarc)
    sys.stderr.write("[mem]   building Volatility context (one-time image init) …\n")
    sys.stderr.flush()
    t_init = time.time()
    ctx, kernel, PsList = build_context(image, symbols)
    sys.stderr.write(f"[mem]   context ready in {int(time.time() - t_init)}s; scanning processes …\n")
    sys.stderr.flush()

    skip = _done_pids(jsonl)
    fh = open(jsonl, "a", buffering=1, encoding="utf-8")
    scanned = 0
    for task in PsList.list_tasks(context=ctx, vmlinux_module_name=kernel):
        pid = str(int(task.tgid))
        if pid in skip or (want_pids is not None and pid not in want_pids):
            continue
        name = _task_name(task)
        fh.write(json.dumps({"t": "start", "pid": pid, "name": name, "ts": time.time()}) + "\n")
        fh.flush()
        hits, canary, capped, had_mem = _scan_task(ctx, task, rules, ptimeout,
                                                   carve_dir=carve_dir, image=image)
        fh.write(json.dumps({"t": "result", "pid": pid, "name": name, "canary": canary,
                             "timed_out": capped, "had_mem": had_mem, "hits": hits,
                             "ts": time.time()}) + "\n")
        fh.flush()
        scanned += 1
        if hits or capped:
            tag = "CAPPED " if capped else ""
            desc = " ".join(f"{h['rule']}[{h['region']}/{h['perms']}]" for h in hits)
            sys.stderr.write(f"[mem]   YARA pid {pid} ({name}): {tag}{desc}\n")
            sys.stderr.flush()
    fh.write(json.dumps({"t": "done", "scanned": scanned, "ts": time.time()}) + "\n")
    fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
