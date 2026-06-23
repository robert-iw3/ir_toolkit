"""YARA rule compilation for the Linux memory scan (Volatility 3 vmayarascan / yarascan)."""
import glob
import json
import os
import re
import sys
import tempfile

# Externals that file-scan rule packs reference; declared empty for a memory scan so they compile.
LINUX_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}

# High-FP rule-name prefixes in a memory context.
_NOISE_RE = re.compile(
    r"(?i)^(generic_|test_|debug_|example_|placeholder|with_|pua_|riskware_|grayware_)")
# Linux-applicability is decided by RULE CONTENT, not filename. The staged packs are ~10k rules,
# the vast majority Windows/PE malware that can never match a Linux ELF image — scanning them all
# is the "goes forever" problem. We keep only rules that can plausibly fire on Linux memory.
#
#   DROP: imports a Windows/macOS executable-format module (pe/dotnet/macho) — format-bound; OR
#         the rule body is Windows-API/registry/path bound AND shows no Linux/cross-platform signal.
#   KEEP: imports elf; OR shows a Linux/ELF/ProcFS/shell/script/webshell signal; OR is generic
#         (no platform-specific strings at all — cross-platform families, packers, hacktools).
_NONLINUX_IMPORT_RE = re.compile(r'^\s*import\s+"(?:pe|dotnet|macho)"', re.MULTILINE)
# Unsupported / problematic module imports stripped before compile (à la malhunt).
_STRIP_IMPORT_RE = re.compile(r'^\s*import\s+"(?:cuckoo|androguard|magic)"\s*$', re.MULTILINE)
_LINUX_RE = re.compile(
    r'(?i)(\x7fELF|7f\s?45\s?4c\s?46|import\s+"elf"|/proc/|/etc/(?:passwd|shadow|cron|init)|'
    r'/usr/(?:bin|lib|sbin)|/bin/(?:ba|da|z)?sh|/dev/(?:tcp|udp|shm)|\bld\.so|\bld-linux|'
    r'\.so(?:\.\d)?\b|\bELF\b|\blinux\b|\bunix\b|\besxi\b|\bexecve\b|\bsetuid\b|\bptrace\b|'
    r'/tmp/|/var/(?:tmp|www|spool)|systemd|crontab|\bbashrc\b|authorized_keys|ld\.so\.preload|'
    r'/sys/kernel|\bmodprobe\b|\binsmod\b|<\?php|\bwebshell\b|\beval\(|base64_decode|\bmirai\b|'
    r'\bxmrig\b|\bglibc\b|GLIBC_)')
_WINDOWS_RE = re.compile(
    r'(?i)(kernel32|ntdll|advapi32|user32\.dll|ws2_32|wininet|shell32|ole32|gdi32|crypt32|'
    r'\bHK(?:EY|LM|CU)_?|\\\\Windows\\\\|System32|SysWOW64|\\\\Device\\\\|RtlMoveMemory|'
    r'VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress|'
    r'\.dll"|regsvr32|rundll32|powershell|cmd\.exe|mshta|wscript|cscript|\bC:\\\\|amsi|'
    r'\\\\registry|CurrentVersion\\\\Run|\.NET|mscoree|clr\.dll|appdata\\\\roaming)')
_HIGH_SIGNAL = ("cobalt", "beacon", "meterpreter", "mimikatz", "shellcode", "inject",
                "empire", "rootkit", "implant", "webshell")

# Self-test canary: the 4-byte ELF magic is at the start of every mapped ELF (exe + every .so),
# so this MUST match if the engine is actually inspecting memory.
CANARY_RULE_NAME = "IRToolkit_Canary_ELF"


def collect_rule_files(rules_dir):
    """Sorted .yar/.yara paths under rules_dir ([] if missing)."""
    if not os.path.isdir(rules_dir):
        return []
    paths = []
    for ext in ("*.yar", "*.yara"):
        paths.extend(glob.glob(os.path.join(rules_dir, "**", ext), recursive=True))
    return sorted(paths)


def classify_rule(path):
    """'linux' | 'windows' | 'generic' for a rule FILE, by content. Drives curation: we scan only
    'linux' + 'generic' rules on a Linux image (Windows/PE rules are the bulk and never match ELF
    memory — scanning them is the performance killer)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return "windows"
    if _NONLINUX_IMPORT_RE.search(content):       # pe/dotnet/macho bound -> Windows/macOS
        return "windows"
    has_linux = bool(_LINUX_RE.search(content))
    has_windows = bool(_WINDOWS_RE.search(content))
    if has_linux:
        return "linux"                            # explicit Linux/ELF/script signal -> keep
    if has_windows:
        return "windows"                          # Windows-API/registry bound, no Linux -> drop
    return "generic"                              # no platform-specific signal -> cross-platform


def select_rules(files, include_generic=False):
    """Curate the scan set. Default (include_generic=False) keeps only rules with an explicit
    Linux/ELF/ProcFS/shell/script signal — targeted + low-noise + fast, like the Windows ~500-rule
    set. include_generic=True also keeps platform-generic rules (broader coverage, but the generic
    bucket holds broad Windows byte-pattern rules that match millions of times in a full-image scan
    and slow it dramatically). Windows/macOS-bound rules are always dropped."""
    keep = ("linux", "generic") if include_generic else ("linux",)
    return [f for f in files if classify_rule(f) in keep]


def is_linux_rule(path):
    """True if the rule applies to a Linux memory scan (Linux-specific or platform-generic)."""
    return classify_rule(path) in ("linux", "generic")


def filter_linux_rules(files):
    """Linux-applicable rules incl. generic (back-compat). For the scan set use select_rules()."""
    return [f for f in files if is_linux_rule(f)]


def is_noise_rule(name):
    return bool(_NOISE_RE.match(name or ""))


def severity_for_rule(name):
    low = (name or "").lower()
    return "Critical" if any(k in low for k in _HIGH_SIGNAL) else "High"


def canary_rule_source():
    return ("rule %s {\n"
            "  strings:\n"
            "    $elf = { 7f 45 4c 46 }\n"
            "  condition:\n"
            "    $elf\n"
            "}\n" % CANARY_RULE_NAME)


def _compile_files(files, externals, extra_source="", work_dir=None):
    """Compile rule files with externals declared, each in its OWN namespace so duplicate rule
    names across packs (signature-base, abuse.ch, …) don't collide, and `include` directives stay
    self-contained. Returns a yara.Rules object; raises yara.Error on a genuine compile failure."""
    import yara
    work = work_dir or tempfile.gettempdir()
    filepaths = {f"ns{i}": os.path.abspath(f) for i, f in enumerate(files)}
    canary_tmp = None
    if extra_source:
        fd, canary_tmp = tempfile.mkstemp(suffix="_canary.yar", dir=work)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(extra_source)
        filepaths["ns_canary"] = canary_tmp
    try:
        return yara.compile(filepaths=filepaths, externals=externals)
    finally:
        if canary_tmp:
            try:
                os.unlink(canary_tmp)
            except OSError:
                pass


def validate_rule_files(files, externals, chunk_size=128):
    """Split files into (good, failed) by compiling in chunks; bisect a failing chunk to per-file."""
    import yara
    good, failed = [], []
    for i in range(0, len(files), chunk_size):
        chunk = files[i:i + chunk_size]
        try:
            _compile_files(chunk, externals)
            good.extend(chunk)
        except yara.Error:
            for f in chunk:
                try:
                    _compile_files([f], externals)
                    good.append(f)
                except yara.Error:
                    failed.append(f)
    return good, failed


def compile_ruleset(rules_dir, out_path, externals=None, add_canary=True, include_generic=False):
    """Compile the curated Linux rule set under rules_dir into ONE COMPILED file at out_path
    (loadable via --yara-compiled-file or yara.load). Returns (out_path|None, n_compiled, n_failed).
    Default scans Linux-specific rules only; include_generic broadens it. On a combined-compile
    failure, isolates the rules that won't compile and retries with the good set."""
    externals = LINUX_EXTERNALS if externals is None else externals
    files = select_rules(collect_rule_files(rules_dir), include_generic=include_generic)
    if not files:
        return None, 0, 0
    import yara                              # imported only once there's something to compile
    canary = canary_rule_source() if add_canary else ""
    work = os.path.dirname(os.path.abspath(out_path)) or "."
    try:
        rules = _compile_files(files, externals, canary, work)
        rules.save(out_path)
        return out_path, len(files), 0
    except yara.Error:
        pass
    good, failed = validate_rule_files(files, externals)
    if not good:
        return None, 0, len(failed)
    rules = _compile_files(good, externals, canary, work)
    rules.save(out_path)
    return out_path, len(good), len(failed)


def scan_image(yarc_path, image_path, timeout=3600, max_snippet=80, results_jsonl=None, log=True):
    """NATIVE-engine scan: yara-python mmaps the raw/LiME image and scans it with the C engine in a
    single Aho-Corasick pass — full physical coverage (kernel + unmapped + free-page remnants), at
    ~hundreds of MB/s, regardless of rule count. This is what makes it fast where Volatility's
    per-page Python `vmayarascan` is not.

    ROLLING LOG (parity with the Windows worker): as each rule matches DURING the scan, the hit is
    APPENDED (flushed) to results_jsonl and printed live — so you can `tail -f` the matches and the
    record survives a crash/timeout. Returns (rows, timed_out): one dict per matched rule
    [{Rule, Offset, Value(hex snippet)}]; the callback fires once per matching rule."""
    import yara
    import json as _json
    import time as _time
    rules = yara.load(yarc_path)
    rows = []
    fh = None
    if results_jsonl:
        fh = open(results_jsonl, "a", buffering=1, encoding="utf-8")   # line-buffered
        fh.write(_json.dumps({"t": "start", "image": os.path.basename(str(image_path)),
                              "ts": _time.time()}) + "\n")

    def _emit(rec):
        if fh:
            fh.write(_json.dumps(rec) + "\n")
            fh.flush()
        if log and rec.get("rule") != CANARY_RULE_NAME:
            sys.stderr.write(f"[mem]   YARA HIT: {rec['rule']} @ {rec['offset']}\n")
            sys.stderr.flush()

    def _cb(d):
        if d.get("matches"):
            off, snippet = 0, ""
            try:
                sm = d.get("strings") or []
                if sm:
                    inst = getattr(sm[0], "instances", None)
                    if inst is not None:                       # yara-python >= 4.3
                        off = inst[0].offset
                        snippet = bytes(inst[0].matched_data)[:max_snippet].hex()
                    else:                                       # older tuple API
                        off, _, data = sm[0]
                        snippet = bytes(data)[:max_snippet].hex()
            except Exception:
                pass
            rule = d.get("rule", "")
            rows.append({"Rule": rule, "Offset": hex(off), "Value": snippet})
            _emit({"t": "match", "rule": rule, "offset": hex(off), "hex": snippet,
                   "ts": _time.time()})
        return yara.CALLBACK_CONTINUE

    try:
        rules.match(filepath=image_path, timeout=timeout, callback=_cb,
                    which_callbacks=yara.CALLBACK_MATCHES)
        timed_out = False
    except yara.TimeoutError:
        timed_out = True
    if fh:
        n = sum(1 for r in rows if r["Rule"] != CANARY_RULE_NAME)
        fh.write(_json.dumps({"t": "done", "matches": n, "timed_out": timed_out,
                              "ts": _time.time()}) + "\n")
        fh.close()
    return rows, timed_out


def parse_worker_jsonl(lines):
    """Parse the per-process worker's JSONL (parity with the Windows memory_yara worker) into a
    resumable summary. Records: {"t":"start","pid"} before a process scan, {"t":"result","pid",
    "name","canary","timed_out","hits":[[rule,count]...]} after, {"t":"done"} at clean finish."""
    canary_hits, finished = 0, []
    started, fin, done, timeouts = set(), set(), False, []
    for ln in lines:
        ln = (ln or "").strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except Exception:
            continue
        t = rec.get("t")
        if t == "start":
            started.add(str(rec.get("pid")))
        elif t == "result":
            pid = str(rec.get("pid"))
            fin.add(pid)
            if rec.get("canary"):
                canary_hits += 1
            if rec.get("timed_out"):
                timeouts.append(pid)
            # hits are enriched dicts {rule,perms,region,path,strings,n}; tolerate legacy [rule,count]
            finished.append((pid, rec.get("name", ""), rec.get("hits", [])))
        elif t == "done":
            done = True
    return {"canary_hits": canary_hits, "finished": finished, "started_pids": started,
            "finished_pids": fin, "timeouts": timeouts, "done": done}


def crashing_pid(started_pids, finished_pids):
    """The pid that started scanning but never produced a result (the crasher) — so a resumed run
    can skip it. Mirrors the Windows worker's crash-isolation."""
    pending = set(started_pids) - set(finished_pids)
    return next(iter(pending)) if pending else None


def worker_rows_to_yara_rows(finished):
    """Convert parsed per-process results into the rows analyze_yara() consumes — preserving PER-PID
    attribution AND the enrichment context (VMA perms, anon/file region, backing path, matched yara
    string ids) that disambiguates injected code from a rule grazing a loaded library."""
    rows = []
    for pid, name, hits in finished:
        for h in hits:
            if isinstance(h, dict):
                rows.append({"Rule": h.get("rule"), "PID": pid, "Process": name,
                             "Perms": h.get("perms", ""), "Region": h.get("region", ""),
                             "Path": h.get("path", ""), "Strings": h.get("strings", [])})
            else:                                    # legacy [rule, count]
                rule = h[0] if isinstance(h, (list, tuple)) else h
                rows.append({"Rule": rule, "PID": pid, "Process": name})
    return rows


def yara_trust_verdict(total_matches, canary_matches):
    """Untrusted when the scan returned matches-capable output but the canary (in every ELF) never
    fired — that means the engine did not actually inspect memory (compile/load failure)."""
    if canary_matches > 0:
        return {"trusted": True,
                "message": "YARA self-test OK: ELF canary matched (%d) — engine inspected memory."
                           % canary_matches}
    return {"trusted": False,
            "message": "YARA self-test FAILED: ELF canary never matched — rules did not compile/"
                       "load and memory was NOT scanned; YARA results are unreliable."}
