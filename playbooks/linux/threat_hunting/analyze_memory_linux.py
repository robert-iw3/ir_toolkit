#!/usr/bin/env python3
"""
analyze_memory_linux.py — offline Linux memory analysis (Volatility 3) -> findings.

Run this on your ANALYST machine after copying the avml `.raw`/`.lime` image off
the target. Runs a set of Volatility 3 Linux plugins and emits ONLY concerning
findings in the common schema (so they merge into Combined_Findings and re-adjudicate):

    {Timestamp, Severity, Type, Target, Details, MITRE}

Prerequisites (analyst machine):
  vol (Volatility 3)   pip install volatility3   (or stage tools/vol)
  Linux symbols (ISF)  UNLIKE Windows, Linux needs a symbol table matching the target
                       kernel banner. Generate with dwarf2json from the target's
                       vmlinux/System.map, or drop a matching ISF in the symbol dir.
                       Point at it with --symbols. `linux.pslist` failing with "no
                       suitable symbols" means the ISF doesn't match the kernel.

Plugins run (concerning output only):
  linux.pslist + linux.pidhashtable  - hidden processes (in the hashtable, not pslist)
  linux.malfind                      - injected/anonymous executable memory
  linux.psaux                        - suspicious process command lines
  linux.bash                         - recovered shell history (attacker commands)
  linux.sockstat                     - external network connections (C2)
  linux.check_syscall                - hooked syscall table entries (rootkit)
  linux.check_modules                - kernel modules hidden from the module list (rootkit)
  linux.tty_check                    - hooked tty operations (keylogger/rootkit)

Output: Memory_Findings_<stamp>.json in --output-dir (default: image folder).
Integrate: add Memory_Findings_*.json to Combined_Findings and re-run adjudicate.py.

Usage:
  analyze_memory_linux.py --image mem.raw [--output-dir DIR] [--vol vol] [--symbols DIR]
                          [--offline-dir DIR] [--skip-plugins a,b] [--quiet]
  --offline-dir reads pre-saved `<plugin>.json` (vol -r json) instead of running vol —
  for air-gapped re-analysis and testing.
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys

REVSHELL_RE = re.compile(
    r"(bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|socat\b|sh\s+-i\b|"
    r"python[0-9.]*\s+-c\s+['\"]?import\s+socket|mkfifo\b.*\bnc\b)", re.IGNORECASE)
IMPLANT_RE = re.compile(r"(?:^|[\s=\"'(,:])(/tmp/|/var/tmp/|/dev/shm/)")
# A token that is an EXECUTABLE living in a world-writable implant dir: the dir must be
# followed by a real filename char (so a bare `/tmp/` *argument*, e.g. firefox crashhelper's
# scratch dir, is NOT treated as an implant exec).
IMPLANT_EXEC_RE = re.compile(r"^(?:/tmp/|/var/tmp/|/dev/shm/)[^\s/]")
# argv[0] is an interpreter -> the implant is the script it runs (argv[1]).
INTERPRETER_RE = re.compile(r"(?:^|/)(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|node|php)$")
OFFENSIVE_RE = re.compile(
    r"\b(mimikatz|cobalt|meterpreter|empire|bloodhound|linpeas|pspy|chisel|"
    r"nps|frp|ligolo|reverse_tcp|msfvenom|/dev/tcp)\b", re.IGNORECASE)

PLUGINS = ("linux.pslist.PsList", "linux.pidhashtable.PIDHashTable",
           "linux.malfind.Malfind", "linux.psaux.PsAux", "linux.bash.Bash",
           "linux.sockstat.Sockstat", "linux.check_syscall.Check_syscall",
           "linux.check_modules.Check_modules", "linux.tty_check.tty_check")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _finding(severity, ftype, target, details, mitre):
    return {"Timestamp": now(), "Severity": severity, "Type": ftype,
            "Target": target, "Details": details, "MITRE": mitre}


def _get(row, *names, default=""):
    """Case-insensitive column fetch (Volatility JSON column names vary by version)."""
    if not isinstance(row, dict):
        return default
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return default


def _is_external(ip):
    try:
        a = ipaddress.ip_address(str(ip))
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_unspecified or a.is_reserved)
    except ValueError:
        return False


# -- per-plugin analyzers (pure: rows -> findings) ----------------------------
def analyze_processes(pslist_rows, pidhash_rows):
    """Hidden process = present in the PID hashtable but not in pslist (DKOM/unlink)."""
    pslist_pids = {str(_get(r, "PID")) for r in pslist_rows or [] if isinstance(r, dict)}
    out = []
    for r in pidhash_rows or []:
        pid = str(_get(r, "PID"))
        if pid and pid not in pslist_pids:
            out.append(_finding("High", "Hidden Process (memory)",
                                f"PID {pid} ({_get(r, 'COMM', 'Process')})",
                                "Process in the PID hashtable but missing from pslist — "
                                "DKOM/unlink rootkit hiding.",
                                "T1014 (Rootkit), T1055 (Process Injection)"))
    return out


def analyze_malfind(rows):
    out = []
    for r in rows or []:
        prot = str(_get(r, "Protection", "Prot"))
        pid = _get(r, "PID")
        proc = _get(r, "Process", "COMM", "Task")
        start = _get(r, "Start", "Start VPN", "Vaddr")
        out.append(_finding("High", "Injected Memory (malfind)",
                            f"PID {pid} ({proc}) @ {start}",
                            f"Executable+writable anonymous mapping (prot={prot}) with no "
                            f"backing file — injected code/shellcode.",
                            "T1055 (Process Injection)"))
    return out


def _implant_exec(args):
    """True when the program being executed lives in a world-writable implant dir — i.e. the
    executable (argv[0]) is there, OR an interpreter (argv[0]) is running a script (argv[1])
    from there. An implant dir appearing only as a *data argument* (e.g. firefox crashhelper
    '/usr/lib/firefox/crashhelper … /tmp/ …') is NOT a match — that was a false positive."""
    toks = args.split()
    if not toks:
        return False
    if IMPLANT_EXEC_RE.match(toks[0]):
        return True
    if INTERPRETER_RE.search(toks[0]) and len(toks) > 1 and IMPLANT_EXEC_RE.match(toks[1]):
        return True
    return False


def analyze_cmdlines(rows):
    out = []
    for r in rows or []:
        args = str(_get(r, "ARGS", "Args", "COMM"))
        pid = _get(r, "PID")
        if REVSHELL_RE.search(args):
            out.append(_finding("High", "Reverse Shell (memory)", f"PID {pid}",
                                f"Reverse-shell command line in memory: {args[:300]}",
                                "T1059.004 (Unix Shell), T1071"))
        elif OFFENSIVE_RE.search(args):
            out.append(_finding("High", "Offensive Tooling (memory)", f"PID {pid}",
                                f"Known offensive tool in command line: {args[:300]}",
                                "T1059, T1105"))
        elif _implant_exec(args):
            out.append(_finding("Medium", "Implant-Path Execution (memory)", f"PID {pid}",
                                f"Process executing from an implant dir: {args[:300]}",
                                "T1059.004 (Unix Shell)"))
    return out


def analyze_bash(rows):
    out = []
    for r in rows or []:
        cmd = str(_get(r, "Command", "CommandLine"))
        pid = _get(r, "PID")
        if REVSHELL_RE.search(cmd) or OFFENSIVE_RE.search(cmd) or IMPLANT_RE.search(cmd) \
           or re.search(r"\b(curl|wget)\b[^|;&]*[|;&]+\s*(?:[\w/]*sh|bash|python)", cmd, re.I):
            out.append(_finding("High", "Suspicious Shell History (memory)",
                                f"PID {pid} @ {_get(r, 'CommandTime', 'Time')}",
                                f"Recovered shell history: {cmd[:300]}",
                                "T1059.004 (Unix Shell)"))
    return out


def analyze_sockstat(rows):
    out = []
    for r in rows or []:
        dst = _get(r, "Destination Addr", "DestinationAddr", "Dest IP", "RemoteAddr")
        dport = _get(r, "Destination Port", "DestinationPort", "Dest Port")
        state = str(_get(r, "State"))
        proc = _get(r, "Process", "COMM")
        if dst and _is_external(dst) and state.upper() in ("ESTABLISHED", "SYN_SENT", ""):
            out.append(_finding("Medium", "External Connection (memory)",
                                f"{dst}:{dport}",
                                f"Process '{proc}' had an external connection to {dst}:{dport} "
                                f"(state={state or 'n/a'}) at capture — possible C2.",
                                "T1071 (Application Layer Protocol)"))
    return out


def _analyze_hooks(rows, ftype, what):
    out = []
    for r in rows or []:
        sym = str(_get(r, "Symbol", "Module", "Name", "Handler Symbol")).strip().upper()
        # vol flags a hook when the handler can't be attributed to a known module/symbol
        if sym in ("", "UNKNOWN", "HOOKED") or "UNKNOWN" in sym or "HOOKED" in sym:
            target = _get(r, "Index", "Name", "Address", "Table Address") or "entry"
            out.append(_finding("High", ftype, str(target),
                                f"{what} points to an unattributed handler "
                                f"(sym={sym or 'UNKNOWN'}) — kernel hook / rootkit.",
                                "T1014 (Rootkit)"))
    return out


def analyze_check_syscall(rows):
    return _analyze_hooks(rows, "Syscall Table Hook", "Syscall table entry")


def analyze_check_modules(rows):
    out = []
    for r in rows or []:
        name = str(_get(r, "Name", "Module") or "").strip()
        # check_modules emits unnamed/empty rows on modern kernels (sysfs-vs-list deltas that
        # aren't real modules). A genuinely rootkit-hidden module still carries a name, so an
        # empty name is plugin noise — skip it rather than cry "rootkit" on every empty row.
        if not name or name in ("-", "0x0"):
            continue
        out.append(_finding("High", "Hidden Kernel Module (memory)", name,
                            f"Module '{name}' present in kernel structures but hidden from "
                            f"the module list — possible rootkit.",
                            "T1014 (Rootkit), T1547.006 (Kernel Modules)"))
    return out


def analyze_tty(rows):
    return _analyze_hooks(rows, "TTY Hook", "TTY operations pointer")


# YARA rule names that fire on benign/common content — suppress to keep signal high.
YARA_NOISE = re.compile(r"(base64|url|email|ipv4|domain|hex_|generic_|test_|eicar)",
                        re.IGNORECASE)


def analyze_yara(rows):
    """vol3 yarascan.YaraScan output -> findings. A rule hit in memory is a strong signal
    (malware family / tool signature). Attribute to the owning process when present."""
    out = []
    for r in rows or []:
        rule = str(_get(r, "Rule", "Rule Name", "rule"))
        if not rule or YARA_NOISE.search(rule):
            continue
        pid = _get(r, "PID", "Pid")
        proc = _get(r, "Process", "COMM", "Task", "Component", "Owner")
        offset = _get(r, "Offset", "Address")
        where = f"PID {pid} ({proc})" if pid else (str(proc) if proc else f"@ {offset}")
        out.append(_finding("High", "YARA Memory Match", f"{rule} :: {where}",
                            f"YARA rule '{rule}' matched in memory ({where}, offset={offset}) "
                            f"— malware/tool signature.",
                            "T1055 (Process Injection), T1027 (Obfuscated Files)"))
    return out


def analyze(plugin_rows):
    """plugin_rows: {plugin_name: [row, ...]} -> findings. Pure."""
    g = plugin_rows
    return (
        analyze_processes(g.get("linux.pslist.PsList"), g.get("linux.pidhashtable.PIDHashTable"))
        + analyze_malfind(g.get("linux.malfind.Malfind"))
        + analyze_cmdlines(g.get("linux.psaux.PsAux"))
        + analyze_bash(g.get("linux.bash.Bash"))
        + analyze_sockstat(g.get("linux.sockstat.Sockstat"))
        + analyze_check_syscall(g.get("linux.check_syscall.Check_syscall"))
        + analyze_check_modules(g.get("linux.check_modules.Check_modules"))
        + analyze_tty(g.get("linux.tty_check.tty_check"))
        + analyze_yara(g.get("yarascan.YaraScan"))
    )


# -- volatility runner --------------------------------------------------------
def _vol_exe(explicit=None):
    if explicit:
        return explicit
    for c in ("vol", "vol.py", "volatility3"):
        if shutil.which(c):
            return c
    staged = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "vol")
    return staged if os.path.isfile(staged) else None


def run_plugin(vol, image, plugin, symbols=None, extra=None, timeout=900):
    cmd = [vol, "-q", "-r", "json", "-f", image]
    if symbols:
        cmd += ["-s", symbols]
    cmd.append(plugin)
    cmd += extra or []
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return json.loads(cp.stdout) if cp.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def collect(image, vol=None, symbols=None, offline_dir=None, skip=(), yara_file=None):
    rows = {}
    plugins = list(PLUGINS)
    if yara_file or offline_dir:
        plugins.append("yarascan.YaraScan")   # YARA only when rules are supplied (it's slow)
    for plugin in plugins:
        if plugin in skip:
            continue
        if offline_dir:
            path = os.path.join(offline_dir, plugin + ".json")
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    rows[plugin] = json.load(fh)
            except (OSError, ValueError):
                rows[plugin] = []
        elif plugin == "yarascan.YaraScan":
            rows[plugin] = run_plugin(vol, image, plugin, symbols,
                                      extra=["--yara-file", yara_file])
        else:
            rows[plugin] = run_plugin(vol, image, plugin, symbols)
    return rows


def decompress_if_needed(image, quiet=False):
    """avml --compress output (snappy LiME) isn't readable by Volatility directly. If the
    image is compressed, convert it to plain LiME with avml-convert. Returns the usable path."""
    if not image or not re.search(r"\.(lime\.)?compressed$", image, re.IGNORECASE):
        return image
    staged = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "avml-convert")
    conv = shutil.which("avml-convert") or (staged if os.access(staged, os.X_OK) else None)
    if not conv:
        raise RuntimeError("compressed image needs 'avml-convert' to decompress "
                           "(stage it: Build-OfflineToolkit-Linux.sh --include-memory) — not found")
    out = re.sub(r"\.(lime\.)?compressed$", ".lime", image, flags=re.IGNORECASE)
    if not quiet:
        print(f"[mem] decompressing {os.path.basename(image)} -> {os.path.basename(out)}",
              file=sys.stderr)
    subprocess.run([conv, image, out], check=True, capture_output=True, timeout=1800)
    return out


def resolve_yara(yara_file, yara_dir, use_staged):
    """Return a single YARA rules file for vol3 --yara-file. --yara-file wins; else build a
    combined include file from a rules dir (or the staged tools/yara_rules with --yara)."""
    if yara_file:
        return yara_file
    rules_dir = yara_dir
    if not rules_dir and use_staged:
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "yara_rules")
    if not rules_dir or not os.path.isdir(rules_dir):
        return None
    import glob as _glob
    import tempfile
    files = sorted(_glob.glob(os.path.join(rules_dir, "**", "*.yar"), recursive=True)
                   + _glob.glob(os.path.join(rules_dir, "**", "*.yara"), recursive=True))
    if not files:
        return None
    fd, combined = tempfile.mkstemp(suffix="_combined.yar")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for f in files:
            fh.write(f'include "{os.path.abspath(f)}"\n')
    return combined


def main():
    ap = argparse.ArgumentParser(description="Offline Linux memory analysis (Volatility 3)")
    ap.add_argument("--image")
    ap.add_argument("--output-dir")
    ap.add_argument("--vol")
    ap.add_argument("--symbols")
    ap.add_argument("--offline-dir", help="read pre-saved <plugin>.json instead of running vol")
    ap.add_argument("--skip-plugins", default="")
    ap.add_argument("--yara", action="store_true",
                    help="YARA-scan memory with the staged tools/yara_rules")
    ap.add_argument("--yara-file", help="single YARA rules file (or compiled) for vol yarascan")
    ap.add_argument("--yara-rules-dir", help="dir of .yar rules (combined into one include file)")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not args.image and not args.offline_dir:
        ap.error("--image (or --offline-dir) required")
    if args.image and os.path.basename(args.image).startswith("INVALID_"):
        print("[mem] refusing to analyze a truncated INVALID_ image", file=sys.stderr)
        return 1

    out_dir = args.output_dir or (os.path.dirname(os.path.abspath(args.image))
                                  if args.image else ".")
    vol, image, yara_file = None, args.image, None
    if not args.offline_dir:
        vol = _vol_exe(args.vol)
        if not vol:
            print("[mem] Volatility 3 not found (pip install volatility3 or --vol PATH)",
                  file=sys.stderr)
            return 1
        try:
            image = decompress_if_needed(args.image, args.quiet)
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            print(f"[mem] {e}", file=sys.stderr)
            return 1
        yara_file = resolve_yara(args.yara_file, args.yara_rules_dir, args.yara)
        if (args.yara or args.yara_file or args.yara_rules_dir) and not yara_file:
            print("[mem] YARA requested but no rules found (--yara-file / --yara-rules-dir / "
                  "staged tools/yara_rules).", file=sys.stderr)

    skip = {p.strip() for p in args.skip_plugins.split(",") if p.strip()}
    rows = collect(image, vol, args.symbols, args.offline_dir, skip, yara_file=yara_file)
    findings = analyze(rows)

    out_path = os.path.join(out_dir, f"Memory_Findings_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    if not args.quiet:
        from collections import Counter
        print(f"[mem] {len(findings)} finding(s) "
              f"{dict(Counter(f['Severity'] for f in findings))} -> {out_path}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
