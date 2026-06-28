"""YARA trust/verify helpers for the Windows memory scan.

Factored out of memory_forensic.py (which imports vmmpyc at module load) so the
rule-handling logic is importable and unit-testable without a memory image.
"""
import os
import re
import glob
import tempfile
import subprocess

# Rule-name prefixes that generate high false-positive volume in a memory context.
_NOISE_RE = re.compile(
    r"(?i)^(generic_|test_|debug_|example_|placeholder|with_|pua_|riskware_|grayware_)")

# Rule-name keywords that warrant Critical (vs the default High) severity.
_HIGH_SIGNAL = ("cobalt", "beacon", "meterpreter", "mimikatz", "shellcode",
                "inject", "empire")

# Self-test canary: the MS-DOS stub string is present in every loaded PE image,
# so this rule MUST match in any process that has a module mapped. If it never
# fires across a real scan, the YARA engine is not inspecting memory.
CANARY_RULE_NAME = "IRToolkit_Canary_DOSStub"


def collect_rule_files(rules_dir):
    """Return sorted .yar/.yara paths under rules_dir ([] if it does not exist)."""
    if not os.path.isdir(rules_dir):
        return []
    paths = []
    for ext in ("*.yar", "*.yara"):
        paths.extend(glob.glob(os.path.join(rules_dir, "**", ext), recursive=True))
    return sorted(paths)


# Rule files tagged for a non-Windows OS - excluded before compiling a Windows scan.
_NON_WIN_RE = re.compile(r"(?i)(?:^|[\\/_])(linux|macos|osx|android|freebsd|unix|ios)(?:[\\/_.]|$)")


def is_noise_rule(name):
    """True if a rule name matches a known high-FP noise prefix."""
    return bool(_NOISE_RE.match(name or ""))


def is_windows_rule(path):
    """True unless the rule name/path is tagged for a non-Windows OS."""
    return not _NON_WIN_RE.search(path or "")


def filter_windows_rules(rule_files):
    """Keep Windows + platform-generic rules; drop Linux/macOS/etc."""
    return [f for f in rule_files if is_windows_rule(f)]


# Rule sets that are file-scan oriented and noise/unstable against process MEMORY.
# abuse.ch rules match PE structure (MZ header, imports, TLS callbacks, packed/encrypted
# markers) that is present in EVERY loaded DLL, so in a memory scan they bury real
# detections and crash the native scanner. Excluded from memory; still available to the
# file scan + offline staging.
_MEM_EXCLUDE_RE = re.compile(r"(?i)(?:^|[\\/])abusech(?:[\\/]|$)")


def exclude_memory_noise(rule_files):
    """Drop file-oriented rule sets (abuse.ch) that are noise/unstable in a memory scan."""
    return [f for f in rule_files if not _MEM_EXCLUDE_RE.search(f or "")]


def severity_for_rule(rule_name):
    """Critical for high-signal rule names, otherwise High."""
    low = (rule_name or "").lower()
    return "Critical" if any(k in low for k in _HIGH_SIGNAL) else "High"


def canary_rule_source():
    """YARA source for the DOS-stub self-test canary."""
    return (
        "rule %s {\n"
        '    meta:\n'
        '        author = "IR_Toolkit"\n'
        '        description = "self-test canary; matches the MS-DOS stub in every PE"\n'
        "    strings:\n"
        '        $dos = "This program cannot be run in DOS mode"\n'
        "    condition:\n"
        "        $dos\n"
        "}\n" % CANARY_RULE_NAME
    )


def _default_externals(external_vars):
    if external_vars is not None:
        return external_vars
    return {"filename": "", "filepath": "", "extension": "",
            "filetype": "", "owner": ""}


def _run_yarac(files, yarac_exe, out_path, external_vars):
    """Compile files -> out_path; return True if yarac64 exits 0.

    No namespace prefixes: yarac's `namespace:file` syntax collides with the
    Windows drive-letter colon. yarac follows `include` directives, so a single
    combined-include file compiles the whole set.
    """
    args = [yarac_exe]
    for k, v in (external_vars or {}).items():
        args += ["-d", "%s=%s" % (k, v)]
    args.extend(files)
    args.append(out_path)                     # yarac: [src...] DEST
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return r.returncode == 0
    except Exception:
        return False


def _compile_batch(files, yarac_exe, external_vars):
    """Validate a batch: compile to a throwaway .yac; return True on exit 0."""
    out = tempfile.NamedTemporaryFile(suffix=".yac", delete=False)
    out.close()
    try:
        return _run_yarac(files, yarac_exe, out.name, external_vars)
    finally:
        try:
            os.unlink(out.name)
        except OSError:
            pass


def _write_combined_include(rule_files, work_dir):
    """Write a combined-include .yar referencing each rule by absolute path."""
    fd, path = tempfile.mkstemp(suffix="_combined.yar", dir=work_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for r in rule_files:
            f.write('include "%s"\n' % os.path.abspath(r))
    return path


_RULE_NAME_RE = re.compile(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)")


def _rule_names(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return _RULE_NAME_RE.findall(fh.read())
    except Exception:
        return []


def dedupe_rule_files(rule_files):
    """Drop files that would re-introduce an already-seen rule identifier (a single
    compiled .yac can't contain two rules of the same name). Returns (kept, dropped).
    Keeps the first occurrence; a file with no parseable rule names is always kept."""
    seen, kept, dropped = set(), [], []
    for f in rule_files:
        names = _rule_names(f)
        if names and any(n in seen for n in names):
            dropped.append(f)
            continue
        seen.update(names)
        kept.append(f)
    return kept, dropped


def compile_ruleset(rule_files, yarac_exe, out_path, external_vars=None):
    """Compile rule_files into ONE compiled .yac at out_path.

    This is what MemProcFS search_yara needs: a single compiled ruleset (passing
    a list of source paths makes it treat each path as inline source -> nothing
    compiles -> silent zero matches). Returns (yac_path|None, n_compiled, n_failed).
    On a combined-compile failure, isolates the good rules and retries with them.
    """
    external_vars = _default_externals(external_vars)
    if not rule_files:
        return None, 0, 0
    # A single .yac cannot hold two rules with the same identifier; vendor feeds
    # (e.g. abusech shipping copies of neo23x0 rules) cause duplicates that fail the
    # whole compile. Drop files that re-introduce an already-seen rule name.
    rule_files, _dupe_dropped = dedupe_rule_files(rule_files)
    work = os.path.dirname(os.path.abspath(out_path)) or "."
    combined = _write_combined_include(rule_files, work)
    try:
        if _run_yarac([combined], yarac_exe, out_path, external_vars):
            return out_path, len(rule_files), len(_dupe_dropped)
    finally:
        try:
            os.unlink(combined)
        except OSError:
            pass
    # Fallback: drop the rules that fail to compile, retry with the good set.
    # Third return value is always total-excluded = dedup-dropped + compile-failed,
    # consistent with the success-path convention (len(_dupe_dropped)).
    good, failed = validate_rule_files(rule_files, yarac_exe, external_vars)
    _total_excl = len(_dupe_dropped) + len(failed)
    if not good:
        return None, 0, _total_excl
    combined2 = _write_combined_include(good, work)
    try:
        if _run_yarac([combined2], yarac_exe, out_path, external_vars):
            return out_path, len(good), _total_excl
        return None, 0, len(_dupe_dropped) + len(rule_files)
    finally:
        try:
            os.unlink(combined2)
        except OSError:
            pass


def validate_rule_files(rule_files, yarac_exe, external_vars=None, chunk_size=128):
    """Split rule_files into (good, failed) by compiling with yarac64.

    Fast path: compile in chunks; a clean chunk passes all its files. Only a
    failing chunk is bisected to per-file to isolate the offender. external_vars
    declares the filename/filepath/etc. externals some rule sets reference.
    """
    if external_vars is None:
        external_vars = {"filename": "", "filepath": "", "extension": "",
                         "filetype": "", "owner": ""}
    good, failed = [], []
    for i in range(0, len(rule_files), chunk_size):
        chunk = rule_files[i:i + chunk_size]
        if _compile_batch(chunk, yarac_exe, external_vars):
            good.extend(chunk)
        else:
            for f in chunk:                   # isolate the bad file(s)
                if _compile_batch([f], yarac_exe, external_vars):
                    good.append(f)
                else:
                    failed.append(f)
    return good, failed


def normalize_perms(protection):
    """Protection string -> short rwx form. Handles both the PAGE_* keyword form
    (PAGE_EXECUTE_READWRITE -> 'rwx') and the MemProcFS VAD char form ('p-rw--' -> 'rw-')."""
    p = (protection or "")
    pu = p.upper()
    if "PAGE_" in pu or "EXECUTE" in pu or "READONLY" in pu or "READWRITE" in pu:
        r = "r" if ("READ" in pu or "WRITE" in pu or "EXECUTE" in pu) else "-"
        w = "w" if "WRITE" in pu else "-"   # READWRITE / WRITECOPY
        x = "x" if "EXECUTE" in pu else "-"
        return r + w + x
    pl = p.lower()                          # char-flag form, e.g. 'p-rwx-' / '---wxc'
    return ("r" if "r" in pl else "-") + ("w" if "w" in pl else "-") + ("x" if "x" in pl else "-")


def vad_region(vad_type, path):
    """'file' if the region is backed by a disk file (Image/Mapped or any path), else 'anon'
    (Private/unbacked - where injected/reflective code lives)."""
    if path:
        return "file"
    t = (vad_type or "").lower()
    return "file" if ("image" in t or "mapped" in t) else "anon"


def classify_yara_hit(region, perms, base_severity="High"):
    """Escalate an anonymous EXECUTABLE hit (injected/unbacked code) to Critical. Never downgrade -
    a file-backed hit could still be a trojanised/reflectively-loaded DLL, so it keeps its severity."""
    if region == "anon" and "x" in (perms or ""):
        return "Critical"
    return base_severity


def hit_context_note(region, perms, path):
    """One-line disambiguation note for a YARA hit, mirroring the Linux report context."""
    if region == "anon" and "x" in (perms or ""):
        return "anon-exec region (%s) -- injected/unbacked code" % perms
    if region == "file":
        import os as _os
        return "file-backed %s %s -- verify signature/hash" % (perms, _os.path.basename(path) or "?")
    return "%s %s" % (region, perms)


def parse_worker_jsonl(lines):
    """Parse JSONL emitted by memory_yara_worker into a resumable summary.

    Records: {"t":"start","pid"} before each scan, {"t":"result","pid","name",
    "canary","hits":[[rule,count]...]} after, {"t":"done"} at clean finish.
    """
    import json as _json
    canary_hits = 0
    finished = []
    started, fin = set(), set()
    done = False
    for ln in lines:
        ln = (ln or "").strip()
        if not ln:
            continue
        try:
            rec = _json.loads(ln)
        except Exception:
            continue
        t = rec.get("t")
        if t == "start":
            started.add(rec.get("pid"))
        elif t == "result":
            pid = rec.get("pid")
            fin.add(pid)
            if rec.get("canary"):
                canary_hits += 1
            # hits are enriched dicts {rule, region, perms, path, strings, n}
            finished.append((pid, rec.get("name", ""), list(rec.get("hits", []))))
        elif t == "done":
            done = True
    return {"canary_hits": canary_hits, "finished": finished,
            "started_pids": started, "finished_pids": fin, "done": done}


def crashing_pid(started_pids, finished_pids):
    """The pid that started scanning but never produced a result (the crasher)."""
    pending = set(started_pids) - set(finished_pids)
    return next(iter(pending)) if pending else None


def yara_trust_verdict(procs_scanned, canary_hits, scan_errors):
    """Decide whether the YARA run can be trusted.

    Untrusted only when real processes were scanned yet the canary (present in
    every PE) never matched -- that means the engine did not inspect memory.
    """
    trusted = True
    if procs_scanned > 0 and canary_hits == 0:
        trusted = False
        message = ("YARA self-test FAILED: canary never matched across %d process(es) "
                   "-- engine is not inspecting memory; YARA results are unreliable."
                   % procs_scanned)
    elif procs_scanned == 0:
        message = "YARA: no processes scanned."
    else:
        message = ("YARA self-test OK: canary matched in %d/%d process(es)."
                   % (canary_hits, procs_scanned))
    return {"trusted": trusted, "canary_hits": canary_hits,
            "procs_scanned": procs_scanned, "scan_errors": scan_errors,
            "message": message}
