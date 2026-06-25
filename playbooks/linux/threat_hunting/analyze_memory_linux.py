#!/usr/bin/env python3
"""
analyze_memory_linux.py - offline Linux memory analysis (Volatility 3) -> findings.

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
  --offline-dir reads pre-saved `<plugin>.json` (vol -r json) instead of running vol -
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

# Living-off-the-Land: native/trusted binaries abused for attacker objectives (GTFOBins-style).
# Each rule is a (finding-type, severity, ATT&CK, regex). Kept tight to stay high-signal; matches
# still adjudicate as Indeterminate on benign admin activity (surfaced with context, not cleared).
LOTL_RULES = [
    ("Encoded Execution (memory)", "High", "T1140 (Deobfuscate), T1059",
     re.compile(r"(?:base64\s+(?:-d|--decode|-D)|xxd\s+-r\s+-p|openssl\s+enc\s+-d)\b[^|]*\|\s*"
                r"(?:/usr/bin/|/bin/)?(?:ba|da|z|c|k)?sh\b|\|\s*base64\s+-d\s*\|", re.I)),
    ("Download Cradle (memory)", "High", "T1105 (Ingress Tool Transfer), T1059",
     re.compile(r"\b(?:curl|wget|fetch)\b[^|;&]*[|]\s*"
                r"(?:/usr/bin/|/bin/)?(?:(?:ba|da|z)?sh|python[0-9.]*|perl|ruby|php)\b", re.I)),
    ("Shell Escape / GTFOBins (memory)", "High", "T1059, T1548 (Abuse Elevation)",
     re.compile(r"\bfind\b[^\n]*-exec\s+(?:/bin/)?(?:ba|da|z)?sh\b|"
                r"\b(?:vi|vim|view)\b[^\n]*\s-c\s*['\"]?:?!|"
                r"\bawk\b[^\n]*BEGIN\s*\{\s*system|"
                r"\b(?:perl|ruby|python[0-9.]*)\b\s+-e[^\n]*\b(?:exec|system|pty)\b|"
                r"\btar\b[^\n]*--checkpoint-action=exec|\bnmap\b[^\n]*--interactive", re.I)),
    ("Privilege Escalation (memory)", "Medium", "T1548 (Abuse Elevation Control)",
     re.compile(r"\bpkexec\b|\bsudo\s+(?:-u\s+\S+\s+)?(?:/bin/)?(?:ba|da|z)?sh\b|"
                r"\bsudo\s+su\b|\bdoas\s+\S", re.I)),
    ("Defense Evasion / Anti-Forensics (memory)", "High", "T1070, T1562 (Impair Defenses)",
     re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|\bsetenforce\s+0\b|"
                r"\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+"
                r"(?:firewalld|auditd|apparmor|ufw)\b|\biptables\s+-F\b|\bufw\s+disable\b|"
                r"\bchattr\s+[+-]i\b|\b(?:shred|truncate)\b[^\n]*/var/log|"
                r"\brm\b\s+(?:-[rf]+\s+)*/var/log", re.I)),
    ("Credential Access (memory)", "High", "T1003 (OS Credential Dumping), T1552",
     re.compile(r"/etc/(?:shadow|gshadow)\b|\bgcore\b|\bstrings\s+/proc/\d+/mem\b|"
                r"/proc/\d+/environ\b|\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)\b|"
                r"\bmimipenguin\b|\bunshadow\b", re.I)),
    ("Persistence (memory)", "Medium", "T1053/T1543/T1546/T1547",
     re.compile(r"\bcrontab\s+-|\bat\s+(?:now|-f)\b|>>?\s*\S*(?:\.bashrc|\.bash_profile|"
                r"\.profile)\b|\bauthorized_keys\b|/etc/ld\.so\.preload\b|"
                r"/etc/systemd/system/\S+\.service|\brc\.local\b", re.I)),
    ("Tunneling / C2 (memory)", "High", "T1572 (Protocol Tunneling), T1090",
     # `ssh␠…-R/-L/-D` (port-forward/SOCKS) but NOT ssh-agent/ssh-add/ssh-keygen (hyphen, no space)
     re.compile(r"(?:^|/|\s)ssh\s+(?:[^\n]*\s)?-[RLD]\b|\bngrok\b|\biodine\b|\bdnscat|"
                r"\bsocat\b[^\n]*(?:TCP|EXEC|OPENSSL)|\bnc\b\s+-l", re.I)),
    ("Exfiltration / Staging (memory)", "Medium", "T1041, T1048 (Exfil)",
     re.compile(r"\b(?:curl|wget)\b[^\n]*(?:--upload-file|\s-T\s)|\bscp\b\s+\S+\s+\S+@|"
                r"\brsync\b[^\n]*\S+@\S+:|\bnc\b\s+\S+\s+\d+\s*<", re.I)),
]


def _lotl(text):
    """Yield (type, severity, mitre) for each LOTL technique present in a command string."""
    return [(t, s, m) for (t, s, m, rx) in LOTL_RULES if rx.search(text)]

PLUGINS = ("linux.pslist.PsList", "linux.pidhashtable.PIDHashTable",
           "linux.malfind.Malfind", "linux.psaux.PsAux", "linux.bash.Bash",
           "linux.sockstat.Sockstat", "linux.check_syscall.Check_syscall",
           "linux.check_modules.Check_modules", "linux.tty_check.tty_check",
           "linux.envars.Envars", "linux.ptrace.Ptrace",
           "linux.hidden_modules.Hidden_modules",
           "linux.check_afinfo.Check_afinfo", "linux.check_idt.Check_idt",
           "linux.check_creds.Check_creds", "linux.netfilter.Netfilter",
           "linux.keyboard_notifiers.Keyboard_notifiers", "linux.kthreads.Kthreads",
           "linux.ebpf.EBPF",
           "linux.capabilities.Capabilities", "linux.mountinfo.MountInfo",
           "linux.library_list.LibraryList")

# Heavy per-VMA / per-thread plugins (big output, slow on large images) - opt-in with --deep.
OPTIONAL_PLUGINS = ("linux.proc.Maps", "linux.pscallstack.PsCallStack")

# YARA scan scope (perf vs coverage): process = per-PID VMAs (faster, attributable, skips free
# physical pages); full = exhaustive physical layer (kernel + unlinked + free-page remnants, slow).
YARA_SCOPE_PLUGIN = {"process": "linux.vmayarascan.VmaYaraScan", "full": "yarascan.YaraScan"}
YARA_PLUGINS = tuple(YARA_SCOPE_PLUGIN.values())


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
                                "Process in the PID hashtable but missing from pslist - "
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
                            f"backing file - injected code/shellcode.",
                            "T1055 (Process Injection)"))
    return out


def _implant_exec(args):
    """True when the program being executed lives in a world-writable implant dir - i.e. the
    executable (argv[0]) is there, OR an interpreter (argv[0]) is running a script (argv[1])
    from there. An implant dir appearing only as a *data argument* (e.g. firefox crashhelper
    '/usr/lib/firefox/crashhelper … /tmp/ …') is NOT a match - that was a false positive."""
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
        # Living-off-the-Land techniques are ADDITIVE (a process can be offensive AND a cradle).
        for ftype, sev, mitre in _lotl(args):
            out.append(_finding(sev, ftype, f"PID {pid}",
                                f"Living-off-the-Land technique in command line: {args[:300]}",
                                mitre))
    return out


def analyze_bash(rows):
    out = []
    for r in rows or []:
        cmd = str(_get(r, "Command", "CommandLine"))
        pid = _get(r, "PID")
        lotl = _lotl(cmd)
        if REVSHELL_RE.search(cmd) or OFFENSIVE_RE.search(cmd) or IMPLANT_RE.search(cmd) or lotl:
            tech = ", ".join(t for t, _s, _m in lotl) or "reverse-shell/offensive/implant"
            out.append(_finding("High", "Suspicious Shell History (memory)",
                                f"PID {pid} @ {_get(r, 'CommandTime', 'Time')}",
                                f"Recovered shell history [{tech}]: {cmd[:300]}",
                                "T1059.004 (Unix Shell)"))
    return out


def _pid_comm_map(pslist_rows):
    """PID(str) -> process name, from pslist. sockstat output often lacks the comm, so we join
    it back in for reputation ranking + attribution."""
    m = {}
    for r in pslist_rows or []:
        pid = str(_get(r, "PID", "Pid"))
        comm = _get(r, "COMM", "Comm", "Process", "Name")
        if pid:
            m[pid] = comm
    return m


def analyze_sockstat(rows, proc_map=None):
    proc_map = proc_map or {}
    out = []
    for r in rows or []:
        dst = _get(r, "Destination Addr", "DestinationAddr", "Dest IP", "RemoteAddr")
        dport = _get(r, "Destination Port", "DestinationPort", "Dest Port")
        state = str(_get(r, "State"))
        pid = _get(r, "PID", "Pid", "Tid")
        # sockstat frequently has no comm column - join the pslist PID->name for ATTRIBUTION
        # only. Severity is NOT adjusted by process reputation: a browser/daemon beaconing is a
        # real C2 vector (injection), so name-based downgrade would be a blindspot.
        proc = _get(r, "Process", "COMM") or proc_map.get(str(pid), "")
        if dst and _is_external(dst) and state.upper() in ("ESTABLISHED", "SYN_SENT", ""):
            out.append(_finding("Medium", "External Connection (memory)",
                                f"{dst}:{dport}",
                                f"PID {pid} ('{proc}') had an external connection to "
                                f"{dst}:{dport} (state={state or 'n/a'}) at capture - possible C2.",
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
                                f"(sym={sym or 'UNKNOWN'}) - kernel hook / rootkit.",
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
        # empty name is plugin noise - skip it rather than cry "rootkit" on every empty row.
        if not name or name in ("-", "0x0"):
            continue
        out.append(_finding("High", "Hidden Kernel Module (memory)", name,
                            f"Module '{name}' present in kernel structures but hidden from "
                            f"the module list - possible rootkit.",
                            "T1014 (Rootkit), T1547.006 (Kernel Modules)"))
    return out


def analyze_tty(rows):
    return _analyze_hooks(rows, "TTY Hook", "TTY operations pointer")


# -- Userland rootkit / injection / stealth --------------------------
def analyze_envars(rows):
    """linux.envars -> dynamic-linker hijack (LD_PRELOAD/LD_AUDIT = userland rootkit)."""
    out = []
    for r in rows or []:
        key = str(_get(r, "KEY", "Key", "Variable")).strip().upper()
        val = str(_get(r, "VALUE", "Value"))
        pid, comm = _get(r, "PID", "Pid"), _get(r, "COMM", "Process", "Comm")
        if key in ("LD_PRELOAD", "LD_AUDIT"):
            out.append(_finding("High", "Linker Hijack (memory)", f"PID {pid} ({comm})",
                                f"{key}={val[:200]} - dynamic-linker injection (userland rootkit / "
                                f"library injection).", "T1574.006 (Dynamic Linker Hijacking)"))
        elif key == "LD_LIBRARY_PATH" and IMPLANT_RE.search(val):
            out.append(_finding("Medium", "Linker Path in Implant Dir (memory)",
                                f"PID {pid} ({comm})",
                                f"LD_LIBRARY_PATH includes a world-writable dir: {val[:200]}",
                                "T1574.006 (Dynamic Linker Hijacking)"))
    return out


# NOTE: a vol3 `linux.lsof` analyzer was removed after live validation - its FD column is a plain
# integer (no txt/mem class), so it cannot isolate the EXECUTABLE from the thousands of benign
# open memfd/deleted data FDs (`memfd:libffi`, gvfs metadata, …). Flagging them all is pure noise.
# Fileless / injected execution is covered precisely by `malfind` (anon executable memory) and, in
# --deep, by `proc.Maps` (memfd-backed *executable* mapping). No detection capability was lost.


def analyze_ptrace(rows):
    """linux.ptrace -> active ptrace attachment (injection / credential theft / anti-debug)."""
    out = []
    for r in rows or []:
        tracer = str(_get(r, "Tracer TID", "TracerTID", "Tracer")).strip()
        pid, comm = _get(r, "PID", "Pid"), _get(r, "Process", "COMM", "Comm")
        if tracer and tracer not in ("", "0", "-", "N/A", "None"):
            out.append(_finding("Medium", "Ptrace Attachment (memory)", f"PID {pid} ({comm})",
                                f"Process is being ptrace'd by TID {tracer} - code injection / "
                                f"credential theft / anti-debug.",
                                "T1055.008 (Ptrace Injection), T1622 (Debugger Evasion)"))
    return out


def analyze_hidden_modules(rows):
    """linux.hidden_modules -> kernel modules found by carving but absent from the module list.
    A NAMED carved module is a strong rootkit signal (High). An UNNAMED, address-only carve is
    most often the carver hitting a non-module structure - surface it (no blindspot) but at Medium
    'verify', since a real hidden module almost always retains its name field."""
    out = []
    for r in rows or []:
        name = str(_get(r, "Name", "Module Name", "Module") or "").strip()
        addr = _get(r, "Address", "Offset", "Base")
        if name and name not in ("-", "0x0"):
            out.append(_finding("High", "Hidden Kernel Module (carved)", name,
                                f"Module '{name}' (addr {addr}) recovered by carving but missing "
                                f"from the module list - rootkit hiding.",
                                "T1014 (Rootkit), T1547.006 (Kernel Modules)"))
        elif addr:
            out.append(_finding("Medium", "Unnamed Carved Module (verify)", f"@{addr}",
                                f"Address-only module struct (@{addr}) carved but unnamed - likely "
                                f"a carving artifact; verify it is not a name-stripped hidden module.",
                                "T1014 (Rootkit)"))
    return out


# NOTE: a derived "kernel-thread masquerade" check (bracketed argv[0] with extra tokens) was
# removed after live validation - normal kthread names with spaces/dashes (`[kworker/u16:3-events]`)
# tripped it. Without the (absent) process_spoofing plugin there is no reliable comm-vs-exe source,
# so this heuristic was net false-positive. Re-add if a real exe/comm cross-source becomes available.


# -- Kernel-rootkit integrity suite ----------------------------------
def _row_brief(r):
    if not isinstance(r, dict):
        return str(r)[:200]
    return ", ".join(f"{k}={v}" for k, v in list(r.items())[:6]
                     if v not in ("", None))[:240]


def _analyze_anomaly_rows(rows, ftype, mitre, severity="High"):
    """These integrity plugins emit a row only when something is OFF (hooked/unexpected), so
    each returned row is a finding. (Output columns vary by build - summarize the row.)"""
    return [_finding(severity, ftype, (_row_brief(r)[:70] or "(kernel)"),
                     f"{ftype}: {_row_brief(r)}", mitre) for r in (rows or [])]


def analyze_check_afinfo(rows):
    return _analyze_anomaly_rows(rows, "Network Proto-Handler Hook (memory)",
                                 "T1014 (Rootkit)")


def analyze_check_creds(rows):
    return _analyze_anomaly_rows(rows, "Shared Credential Structure (memory)",
                                 "T1068 (Privilege Escalation), T1014")


def analyze_netfilter(rows):
    """linux.netfilter lists ALL hooks (conntrack/defrag/docker are legitimate). Flag only the
    ones vol3 itself marks `Is Hooked = True` (handler outside expected netfilter code)."""
    out = []
    for r in rows or []:
        hooked = str(_get(r, "Is Hooked", "IsHooked", "Hooked")).strip().lower()
        if hooked in ("true", "1", "yes"):
            out.append(_finding("High", "Netfilter Hook (memory)", _row_brief(r)[:70] or "(kernel)",
                                f"Netfilter hook flagged hooked: {_row_brief(r)}",
                                "T1205 (Traffic Signaling), T1014 (Rootkit)"))
    return out


def analyze_keyboard_notifiers(rows):
    return _analyze_anomaly_rows(rows, "Keyboard Notifier Hook (keylogger)",
                                 "T1056.001 (Keylogging)")


def analyze_check_idt(rows):
    """IDT can list all entries; flag only the ones whose handler is unresolved/hooked."""
    out = []
    for r in rows or []:
        sym = str(_get(r, "Symbol", "Name", "Module")).strip().upper()
        idx = _get(r, "Index", "Idx", "Entry")
        if sym in ("", "UNKNOWN", "-", "HOOKED"):
            out.append(_finding("High", "IDT Hook (memory)", f"IDT[{idx}]",
                                f"Interrupt-descriptor {idx} handler unresolved/hooked "
                                f"(symbol='{sym}') - kernel rootkit.", "T1014 (Rootkit)"))
    return out


def analyze_kthreads(rows):
    """linux.kthreads -> kernel thread whose handler is backed by NO module (and unresolved).
    A handler inside a real module (dm_crypt, nvidia, …) is legitimate - only a handler that
    belongs to no module AND resolves to no symbol points at injected/unbacked code."""
    out = []
    for r in rows or []:
        sym = str(_get(r, "Symbol")).strip().upper()
        module = str(_get(r, "Module")).strip().lower()
        name = _get(r, "Thread Name", "Name", "Comm")
        tid = _get(r, "TID", "Tid")
        no_module = module in ("", "-", "none", "unknown")
        if sym in ("", "UNKNOWN", "-") and no_module:
            out.append(_finding("High", "Kernel Thread Hook (memory)", f"{name} (TID {tid})",
                                f"Kernel thread '{name}' handler resolves to no module and no "
                                f"symbol - unbacked/injected code (possible kthread hijack).",
                                "T1014 (Rootkit)"))
    return out


def analyze_ebpf(rows):
    """linux.ebpf -> loaded eBPF programs. Flag ALL of them (Medium/Indeterminate): every program
    type can be abused (kprobe/tracepoint/xdp for hooking, socket-filter/cgroup for traffic
    control), so filtering by type would tune out real vectors. The analyst confirms expected vs
    not - modern rootkits/C2 (bpfdoor, TripleCross, ebpfkit) live here."""
    out = []
    for r in rows or []:
        typ = str(_get(r, "Type")).strip().lower()
        name, tag = _get(r, "Name"), _get(r, "Tag")
        out.append(_finding("Medium", "eBPF Program (memory)", f"{name} [{typ}]",
                            f"Loaded eBPF program name='{name}' type='{typ}' tag='{tag}' - eBPF "
                            f"backs modern rootkits/C2; confirm it is expected.",
                            "T1014 (Rootkit), T1205 (Traffic Signaling)"))
    return out


# -- Phase 3: privilege / escape / loaded-code surface ------------------------
DANGEROUS_CAPS = ("sys_admin", "sys_module", "sys_ptrace", "sys_rawio", "dac_override",
                  "dac_read_search", "bpf", "net_admin", "net_raw", "sys_boot")
POWERFUL_CAPS = ("sys_module", "bpf", "sys_ptrace", "sys_rawio")


def analyze_capabilities(rows):
    """linux.capabilities -> dangerous capabilities held by a NON-root process. Root (euid 0)
    holds caps by definition, so that carries no signal; a non-root process granted sys_admin/
    sys_module/ptrace/dac_override/bpf/… is the privilege-escalation / container-escape indicator."""
    out = []
    for r in rows or []:
        eff = str(_get(r, "cap_effective", "Effective", "cap_eff")).lower()
        euid = str(_get(r, "EUID", "Euid")).strip()
        name, pid = _get(r, "Name", "Comm"), _get(r, "Pid", "PID")
        if euid in ("0", "", "-"):
            continue                       # root has all caps - not an attack indicator
        hits = [c for c in DANGEROUS_CAPS if c in eff]
        if hits:
            out.append(_finding("Medium", "Dangerous Capability (memory)", f"{name} (PID {pid})",
                                f"Non-root process (euid={euid}) holds dangerous capabilities "
                                f"({', '.join(hits)}) - privilege-escalation / container-escape "
                                f"surface.", "T1548 (Abuse Elevation Control)"))
    return out


def analyze_mountinfo(rows):
    """linux.mountinfo -> bind-mounts shadowing a system path (file hiding). NOTE: tmpfs on /tmp,
    /dev/shm, /run, /run/user/* is the NORMAL system layout, so tmpfs location is not flagged -
    only a bind mount placed over a sensitive system path is anomalous."""
    out = []
    for r in rows or []:
        mp = str(_get(r, "MOUNT_POINT", "PATH", "Mount Point"))
        opts = str(_get(r, "MNT_OPTS", "MOUNT_OPTIONS", "SB_OPTIONS")).lower()
        src = str(_get(r, "MOUNT_SRC", "DEVNAME", "Source"))
        if re.match(r"/(?:etc|bin|sbin|usr|boot|proc|root)(?:/|$)", mp) and "bind" in opts:
            out.append(_finding("High", "Bind Mount Over System Path (memory)", mp,
                                f"bind mount over {mp} (src={src}) - file shadowing / hiding.",
                                "T1564.001 (Hidden Files and Directories)"))
    return out


def analyze_library_list(rows):
    """linux.library_list -> shared libraries loaded from memfd / deleted / implant dirs."""
    out = []
    for r in rows or []:
        path = str(_get(r, "Path", "Name"))
        pid = _get(r, "Pid", "PID")
        low = path.lower()
        if "memfd:" in low or "(deleted)" in low or IMPLANT_EXEC_RE.match(path):
            out.append(_finding("High", "Suspicious Loaded Library (memory)", f"PID {pid}",
                                f"Library loaded from an anomalous location: {path[:200]} "
                                f"(memfd/deleted/implant dir) - library injection.",
                                "T1574 (Hijack Execution Flow), T1620"))
    return out


def analyze_maps(rows):
    """linux.proc.Maps (optional, heavy) -> executable mappings backed by memfd/implant dirs."""
    out = []
    for r in rows or []:
        fp = str(_get(r, "File Path", "Path", "File")).strip()
        flags = str(_get(r, "Flags", "Protection", "Perms")).lower()
        pid, proc = _get(r, "PID"), _get(r, "Process", "COMM")
        if "x" in flags and fp and ("memfd:" in fp.lower() or IMPLANT_EXEC_RE.match(fp)):
            out.append(_finding("High", "Implant-Backed Mapping (memory)", f"PID {pid} ({proc})",
                                f"Executable mapping backed by {fp[:160]} (memfd/implant dir).",
                                "T1620 (Reflective Code Loading)"))
    return out


def analyze_pscallstack(rows):
    """linux.pscallstack (optional, heavy) -> stack frames returning into anonymous/unbacked
    memory (no module/symbol) - a hallmark of injected/shellcode execution."""
    out = []
    for r in rows or []:
        mod = str(_get(r, "Module")).strip()
        name = str(_get(r, "Name", "Symbol")).strip()
        tid, comm = _get(r, "TID", "Tid"), _get(r, "Comm", "Process")
        if mod in ("", "-", "UNKNOWN") and name in ("", "-", "UNKNOWN"):
            out.append(_finding("Medium", "Anomalous Call Stack (memory)", f"{comm} (TID {tid})",
                                f"Stack frame returns into unbacked memory (no module/symbol) "
                                f"@ {_get(r, 'Address', 'Value')} - possible injected execution.",
                                "T1055 (Process Injection)"))
    return out


# YARA rule names that fire on benign/common content - suppress to keep signal high.
YARA_NOISE = re.compile(r"(base64|url|email|ipv4|domain|hex_|generic_|test_|eicar)",
                        re.IGNORECASE)


CANARY_RULE = "IRToolkit_Canary_ELF"   # self-test rule (see linux_yara.py); never a real threat


def _canary_hits(rows):
    return sum(1 for r in (rows or [])
               if str(_get(r, "Rule", "Rule Name", "rule")) == CANARY_RULE)


_YARA_HIGH_SIGNAL = ("cobalt", "beacon", "meterpreter", "mimikatz", "shellcode", "inject",
                     "empire", "rootkit", "implant", "webshell", "ransom", "backdoor")


def analyze_yara(rows):
    """YARA hits (native scan OR per-process vol worker) -> findings. A rule hit in memory is a
    strong signal (malware family / tool signature). The self-test canary + known-noise rules are
    excluded. Native rows carry {Rule, Offset, Value(hex)}; the per-process worker adds PID/Process
    plus ENRICHMENT - {Perms, Region(anon|file), Path, Strings} - the FP/TP disambiguator.

    Context only ESCALATES or ANNOTATES, never downgrades (no blindspots): a hit in anonymous
    EXECUTABLE memory is injected/unbacked code -> Critical; a file-backed hit keeps its severity but
    is annotated with the backing path (could still be a trojanised binary) so the adjudicator/analyst
    decides; a rule that matched many processes is flagged as likely-shared-bytes (could also be a
    library-injection campaign) - all surfaced, nothing cleared here."""
    out = []
    # breadth: how many distinct PIDs each rule hit (a rule across many procs == common/shared bytes,
    # OR an LD_PRELOAD-style injection - annotate, don't clear).
    rule_pids = {}
    for r in rows or []:
        rule = str(_get(r, "Rule", "Rule Name", "rule"))
        pid = _get(r, "PID", "Pid")
        if rule and pid:
            rule_pids.setdefault(rule, set()).add(str(pid))
    for r in rows or []:
        rule = str(_get(r, "Rule", "Rule Name", "rule"))
        if not rule or rule == CANARY_RULE or YARA_NOISE.search(rule):
            continue
        pid = _get(r, "PID", "Pid")
        proc = _get(r, "Process", "COMM", "Task", "Component", "Owner")
        offset = _get(r, "Offset", "Address")
        snippet = _get(r, "Value", "Data", "Match")          # hex snippet (native engine)
        perms = str(_get(r, "Perms") or "")
        region = str(_get(r, "Region") or "")                # 'anon' | 'file' | ''
        path = str(_get(r, "Path") or "")
        strings = _get(r, "Strings") or []
        where = f"PID {pid} ({proc})" if pid else (str(proc) if proc else f"offset {offset}")
        anon_exec = region == "anon" and "x" in perms
        sev = "Critical" if (anon_exec or any(k in rule.lower() for k in _YARA_HIGH_SIGNAL)) else "High"
        ftype = "Injected Code (memory YARA)" if anon_exec else "YARA Memory Match"
        # context clause
        if anon_exec:
            loc = f"in ANONYMOUS EXECUTABLE memory ({perms}) - injected/unbacked code"
        elif region == "file":
            loc = (f"in file-backed {perms} mapping {path or '?'} - verify that on-disk file's "
                   f"hash/package ownership (a rule grazing a loaded binary/library is often benign, "
                   f"but a trojanised binary is not)")
        elif region == "anon":
            loc = f"in anonymous {perms} memory"
        else:
            loc = f"({where}, offset={offset})"
        details = f"YARA rule '{rule}' matched {loc}."
        if strings:
            details += f" Matched strings: {', '.join(str(s) for s in strings[:12])}."
        breadth = len(rule_pids.get(rule, ()))
        if breadth >= 3:
            details += (f" NOTE: this rule matched {breadth} processes - likely common/shared bytes "
                        f"(e.g. interpreter/library content), but rule out a library-injection campaign.")
        if snippet:
            details += f" Bytes(hex): {str(snippet)[:96]}"
        out.append(_finding(sev, ftype, f"{rule} :: {where}", details,
                            "T1055 (Process Injection), T1027 (Obfuscated Files)"))
    return out


# -- (A) cross-plugin correlation + (B) priority ranking ----------------------
# Inherently-suspicious, PID-bearing signals. A single one of these is already notable; when one
# co-occurs with ANY other signal on the same PID it is a high-confidence compromise pattern.
STRONG_TYPES = frozenset({
    "Hidden Process (memory)", "Reverse Shell (memory)", "Offensive Tooling (memory)",
    "Implant-Path Execution (memory)", "YARA Memory Match",
    # high-signal living-off-the-land techniques (a single one + any other signal = compromise)
    "Encoded Execution (memory)", "Download Cradle (memory)",
    "Shell Escape / GTFOBins (memory)", "Defense Evasion / Anti-Forensics (memory)",
    "Credential Access (memory)", "Tunneling / C2 (memory)",
    "Linker Hijack (memory)", "Suspicious Loaded Library (memory)",
    "Implant-Backed Mapping (memory)",
})
_PID_RE = re.compile(r"\bPID (\d+)")
_PROC_RE = re.compile(r"\bPID \d+ \(([^)]+)\)")


def _pid_of(f):
    m = _PID_RE.search(f.get("Target", "") + " " + f.get("Details", ""))
    return m.group(1) if m else None


def correlate(findings):
    """(A) Join findings by PID and raise confidence where signals CONVERGE. To avoid false
    escalation on benign JIT+network processes (a browser legitimately has anon-exec memory AND
    external connections), require ≥1 inherently-strong signal PLUS ≥1 other distinct signal on
    the same PID. Only ELEVATES (emits a new High finding) - never suppresses, so no blindspot."""
    by_pid = {}
    for f in findings:
        pid = _pid_of(f)
        if pid:
            by_pid.setdefault(pid, []).append(f)
    out = []
    for pid, group in by_pid.items():
        types = {f["Type"] for f in group}
        strong = types & STRONG_TYPES
        if strong and len(types) >= 2:
            pm = next((_PROC_RE.search(f["Target"]) for f in group if _PROC_RE.search(f["Target"])), None)
            proc = pm.group(1) if pm else ""
            out.append(_finding(
                "High", "Correlated Memory Threat",
                f"PID {pid}" + (f" ({proc})" if proc else ""),
                f"{len(types)} independent memory signals converge on PID {pid}: "
                f"{', '.join(sorted(types))}. A high-signal indicator "
                f"({', '.join(sorted(strong))}) co-occurring with other anomalies is a "
                f"high-confidence compromise pattern - prioritize for analyst review.",
                "T1055 (Process Injection), T1059, T1071"))
    return out


def dedup(findings):
    """Collapse identical findings - e.g. a process with many sockets to the same IP yields one
    'External Connection' fact, not N. Keyed on content (Timestamp excluded). First-seen order."""
    seen, out = set(), []
    for f in findings:
        k = (f.get("Type"), f.get("Target"), f.get("Details"), f.get("Severity"), f.get("MITRE"))
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def prioritize(findings):
    """(B) Stable-order findings by investigative priority so the few high-value items float to
    the top of a wide-net flood: correlated threats first, then by severity, then strong signals.
    Pure ordering - nothing is dropped."""
    sev = {"Critical": -1, "High": 0, "Medium": 1, "Low": 2}
    return sorted(findings, key=lambda f: (
        0 if f["Type"] == "Correlated Memory Threat" else 1,
        sev.get(f["Severity"], 3),
        0 if f["Type"] in STRONG_TYPES else 1,
    ))


def analyze(plugin_rows):
    """plugin_rows: {plugin_name: [row, ...]} -> findings. Pure."""
    g = plugin_rows
    base = (
        analyze_processes(g.get("linux.pslist.PsList"), g.get("linux.pidhashtable.PIDHashTable"))
        + analyze_malfind(g.get("linux.malfind.Malfind"))
        + analyze_cmdlines(g.get("linux.psaux.PsAux"))
        + analyze_bash(g.get("linux.bash.Bash"))
        + analyze_sockstat(g.get("linux.sockstat.Sockstat"),
                           _pid_comm_map(g.get("linux.pslist.PsList")))
        + analyze_check_syscall(g.get("linux.check_syscall.Check_syscall"))
        + analyze_check_modules(g.get("linux.check_modules.Check_modules"))
        + analyze_tty(g.get("linux.tty_check.tty_check"))
        + analyze_envars(g.get("linux.envars.Envars"))
        + analyze_ptrace(g.get("linux.ptrace.Ptrace"))
        + analyze_hidden_modules(g.get("linux.hidden_modules.Hidden_modules"))
        + analyze_check_afinfo(g.get("linux.check_afinfo.Check_afinfo"))
        + analyze_check_idt(g.get("linux.check_idt.Check_idt"))
        + analyze_check_creds(g.get("linux.check_creds.Check_creds"))
        + analyze_netfilter(g.get("linux.netfilter.Netfilter"))
        + analyze_keyboard_notifiers(g.get("linux.keyboard_notifiers.Keyboard_notifiers"))
        + analyze_kthreads(g.get("linux.kthreads.Kthreads"))
        + analyze_ebpf(g.get("linux.ebpf.EBPF"))
        + analyze_capabilities(g.get("linux.capabilities.Capabilities"))
        + analyze_mountinfo(g.get("linux.mountinfo.MountInfo"))
        + analyze_library_list(g.get("linux.library_list.LibraryList"))
        + analyze_maps(g.get("linux.proc.Maps"))                        # optional (--deep)
        + analyze_pscallstack(g.get("linux.pscallstack.PsCallStack"))   # optional (--deep)
        + analyze_yara([row for k in YARA_PLUGINS for row in (g.get(k) or [])])
    )
    deduped = dedup(base)
    return prioritize(deduped + correlate(deduped))


# -- volatility runner --------------------------------------------------------
def _vol_exe(explicit=None):
    if explicit:
        return explicit
    for c in ("vol", "vol.py", "volatility3"):
        if shutil.which(c):
            return c
    staged = os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "vol")
    return staged if os.path.isfile(staged) else None


def run_plugin(vol, image, plugin, symbols=None, extra=None, timeout=900, progress=False):
    # `-q` suppresses Volatility's progress feedback - keep it for the fast plugins, but DROP it for
    # the long YARA scan so vol's native progress streams (plus a heartbeat) instead of looking hung.
    cmd = [vol, "-r", "json", "-f", image]
    if not progress:
        cmd.insert(1, "-q")
    if symbols:
        cmd += ["-s", symbols]
    cmd.append(plugin)
    cmd += extra or []
    try:
        if progress:
            return _run_with_progress(cmd, timeout)
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return json.loads(cp.stdout) if cp.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def _run_with_progress(cmd, timeout):
    """Run a long plugin with a rolling log: vol's own progress streams to stderr (we leave it
    attached) and a heartbeat prints elapsed time every 30 s, so a multi-minute YARA scan visibly
    progresses instead of appearing stuck. stdout (the JSON) is still captured + parsed."""
    import threading
    import time
    print("[mem]   YARA scan started - vol progress streams below; heartbeat every 30s …",
          file=sys.stderr, flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)   # stderr inherits -> live
    start, stop = time.time(), threading.Event()

    def _beat():
        while not stop.wait(30):
            print(f"[mem]   … YARA still scanning ({int(time.time() - start)}s elapsed)",
                  file=sys.stderr, flush=True)

    th = threading.Thread(target=_beat, daemon=True)
    th.start()
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out = ""
    finally:
        stop.set()
    print(f"[mem]   YARA scan finished ({int(time.time() - start)}s elapsed).",
          file=sys.stderr, flush=True)
    try:
        return json.loads(out) if out and out.strip() else []
    except ValueError:
        return []


def collect(image, vol=None, symbols=None, offline_dir=None, skip=(), yara_extra=None,
            yara_plugin="yarascan.YaraScan", yara_timeout=7200, deep=False):
    """yara_extra: the vol args selecting the ruleset, e.g. ["--yara-compiled-file", "x.yarc"]
    (preferred - pre-compiled with externals so it actually loads) or ["--yara-file", src]."""
    rows = {}
    plugins = list(PLUGINS)
    if deep or offline_dir:
        plugins += list(OPTIONAL_PLUGINS)      # heavy per-VMA/per-thread plugins (opt-in / offline)
    if offline_dir:
        plugins += list(YARA_PLUGINS)          # read whichever yara JSON was pre-saved
    elif yara_extra:
        plugins.append(yara_plugin)            # YARA only when rules are supplied (it's slow)
    total = len(plugins)
    for i, plugin in enumerate(plugins, 1):
        if plugin in skip:
            continue
        if not offline_dir:                        # rolling per-plugin log so nothing looks hung
            print(f"[mem]   [{i}/{total}] {plugin}", file=sys.stderr, flush=True)
        if offline_dir:
            path = os.path.join(offline_dir, plugin + ".json")
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    rows[plugin] = json.load(fh)
            except (OSError, ValueError):
                rows[plugin] = []
        elif plugin in YARA_PLUGINS:
            # YARA is the long pole - its own (larger) timeout + a rolling progress log so the
            # multi-minute scan doesn't look hung after "compiled N rules".
            rows[plugin] = run_plugin(vol, image, plugin, symbols,
                                      extra=yara_extra, timeout=yara_timeout, progress=True)
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
                           "(stage it: Build-OfflineToolkit-Linux.sh --include-memory) - not found")
    out = re.sub(r"\.(lime\.)?compressed$", ".lime", image, flags=re.IGNORECASE)
    if not quiet:
        print(f"[mem] decompressing {os.path.basename(image)} -> {os.path.basename(out)}",
              file=sys.stderr)
    subprocess.run([conv, image, out], check=True, capture_output=True, timeout=1800)
    return out


def _write_yara_results(out_dir, stamp, engine, image, rules_n, rules_failed, duration,
                        timed_out, canary_hits, yara_rows):
    """Dedicated YARA scan-results file (parity with the Windows `_yara_results_<stamp>.jsonl`).
    Captures the scan provenance + every rule match with offset/attribution/snippet, so YARA output
    is auditable independently of the merged Memory_Findings."""
    matches = []
    for r in yara_rows or []:
        rule = str(_get(r, "Rule", "Rule Name", "rule"))
        if not rule or rule == CANARY_RULE:
            continue
        region = str(_get(r, "Region") or "")
        perms = str(_get(r, "Perms") or "")
        matches.append({
            "rule": rule,
            "offset": _get(r, "Offset", "Address"),
            "pid": _get(r, "PID", "Pid"),
            "process": _get(r, "Process", "COMM", "Task"),
            "region": region,                                # anon | file (the FP/TP disambiguator)
            "perms": perms,                                  # e.g. rwx / r-x / r--
            "path": _get(r, "Path"),                         # backing file when region == file
            "strings": _get(r, "Strings") or [],             # which yara strings actually fired
            "matched_hex": _get(r, "Value", "Data"),
            "severity": ("Critical" if (region == "anon" and "x" in perms)
                         or any(k in rule.lower() for k in _YARA_HIGH_SIGNAL) else "High"),
        })
    doc = {
        "stamp": stamp, "engine": engine, "image": os.path.basename(str(image)),
        "rules_compiled": rules_n, "rules_failed": rules_failed,
        "duration_seconds": duration, "timed_out": timed_out,
        "canary_matched": canary_hits > 0,
        "trusted": canary_hits > 0 and not timed_out,
        "match_count": len(matches), "matches": matches,
    }
    path = os.path.join(out_dir, f"_yara_results_{stamp}.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        print(f"[mem]   YARA results -> {os.path.basename(path)} "
              f"({len(matches)} match(es), trusted={doc['trusted']})", file=sys.stderr, flush=True)
    except OSError:
        pass
    return path


def compile_yara_ruleset(yara_file, yara_dir, use_staged, out_dir, stamp, quiet=False,
                         include_generic=False):
    """Compile the requested YARA rules to a single COMPILED .yarc (Linux-curated by content +
    externals declared). Used by BOTH engines - the native scanner loads it directly, and the vol
    fallback passes it via --yara-compiled-file. Returns the .yarc path or None.

    Why compile ourselves: vol's --yara-file compiles raw source with no externals → a single
    undefined identifier fails the whole set → 0 matches (a silent false 'clean')."""
    if yara_file and yara_file.endswith((".yarc", ".yc", ".compiled")):
        return yara_file, 0, 0                 # analyst supplied an already-compiled ruleset
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import linux_yara
    except ImportError:                        # yara-python not available
        return None, 0, 0
    out = os.path.join(out_dir, f"_yara_compiled_{stamp}.yarc")
    if yara_file:                              # analyst source file: compile just it (its own dir)
        import tempfile
        import shutil as _sh
        d = tempfile.mkdtemp()
        _sh.copy(yara_file, d)
        compiled, n, failed = linux_yara.compile_ruleset(d, out, include_generic=include_generic)
    else:
        rules_dir = yara_dir
        if not rules_dir and use_staged:
            rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                     "tools", "yara_rules")
        if not rules_dir or not os.path.isdir(rules_dir):
            return None, 0, 0
        compiled, n, failed = linux_yara.compile_ruleset(rules_dir, out, include_generic=include_generic)
    if not compiled:
        return None, 0, 0
    if not quiet:
        print(f"[mem] compiled {n} Linux-applicable YARA rule file(s) ({failed} skipped) "
              f"-> {os.path.basename(out)}", file=sys.stderr)
    return compiled, n, failed


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
    ap.add_argument("--yara-engine", choices=["native", "vol"], default="native",
                    help="native (DEFAULT) = yara-python over the whole image: fast triage, FULL "
                         "physical coverage (kernel+free pages), but NO per-PID attribution "
                         "(~25min/25GB). vol = per-process worker via Volatility library: PER-PID "
                         "ATTRIBUTION + per-process timeout + rolling resumable JSONL, scans mapped "
                         "process memory only (~80min on a desktop w/ browsers, resumable).")
    ap.add_argument("--yara-broad", action="store_true",
                    help="also scan platform-generic rules (broader, but slower - generic Windows "
                         "byte-pattern rules match heavily in a full-image scan). Default: Linux-only.")
    ap.add_argument("--yara-proc-timeout", type=int, default=180,
                    help="per-process scan timeout in seconds (vol engine + native two-phase "
                         "follow-up); a slow/huge process aborts and the scan continues. Default 180.")
    ap.add_argument("--no-yara-followup", dest="yara_followup", action="store_false",
                    help="native engine: do NOT auto-run the per-process enrichment after triage "
                         "finds matches (default: follow up to attribute + add VMA context).")
    ap.add_argument("--yara-scope", choices=["process", "full"], default="full",
                    help="vol engine only: process = vmayarascan (per-PID); full = yarascan")
    ap.add_argument("--yara-timeout", type=int, default=7200,
                    help="seconds for the YARA scan (default 7200; the scan is the long pole)")
    ap.add_argument("--deep", action="store_true",
                    help="also run heavy per-VMA/per-thread plugins (proc.Maps, pscallstack)")
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
    vol, image = None, args.image
    yara_extra, yarc, yara_n, yara_failed = None, None, 0, 0
    yara_requested = bool(args.yara or args.yara_file or args.yara_rules_dir)
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
        if yara_requested:
            yarc, yara_n, yara_failed = compile_yara_ruleset(
                args.yara_file, args.yara_rules_dir, args.yara, out_dir, args.stamp, args.quiet,
                include_generic=args.yara_broad)
            if not yarc:
                print("[mem] YARA requested but no rules compiled (need yara-python + rules in "
                      "--yara-rules-dir / staged tools/yara_rules).", file=sys.stderr)
            # Both engines run POST-collect: native scans the whole image (scan_image), vol drives the
            # per-process worker. Neither uses collect()'s in-line yara plugin (yara_extra stays None).

    skip = {p.strip() for p in args.skip_plugins.split(",") if p.strip()}
    rows = collect(image, vol, args.symbols, args.offline_dir, skip, yara_extra=yara_extra,
                   yara_plugin=YARA_SCOPE_PLUGIN[args.yara_scope], yara_timeout=args.yara_timeout,
                   deep=args.deep)

    # YARA scan runs POST-collect so its rows feed the same analyze() pipeline:
    #   native (default) = yara-python over the whole image (fast, full physical coverage, no PID)
    #   vol              = per-process worker via Volatility vmayarascan (PER-PID ATTRIBUTION,
    #                      per-process timeout, ROLLING RESUMABLE JSONL) - the proven attributed path
    yara_dur, canary_override = 0, None
    if yarc and not args.offline_dir:
        import linux_yara
        import time as _t
        worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "linux_yara_worker.py")
        jsonl = os.path.join(out_dir, f"_yara_results_{args.stamp}.jsonl")
        if args.yara_engine == "native":
            print("[mem]   YARA native triage (engine=yara-python, full image) …", file=sys.stderr,
                  flush=True)
            _s = _t.time()
            yrows, timed_out = linux_yara.scan_image(yarc, image, timeout=args.yara_timeout,
                                                     results_jsonl=jsonl)
            yara_dur = int(_t.time() - _s)
            print(f"[mem]   YARA native triage finished ({yara_dur}s, {len(yrows)} rule-match(es)).",
                  file=sys.stderr, flush=True)
            rows["yarascan.YaraScan"] = yrows
            if timed_out:
                rows["_yara_timed_out"] = True
            # TWO-PHASE: the fast triage tells us WHICH signatures are present (no PID). If any fired,
            # follow up IMMEDIATELY with the per-process worker to ATTRIBUTE them to a PID and ENRICH
            # each with VMA context (anon/file region, perms, backing path, matched strings) - the
            # detail that separates injected code from a rule grazing a loaded library. Skipped on a
            # clean host (0 triage matches), so the common case stays fast.
            matched = {str(_get(r, "Rule", "rule")) for r in yrows
                       if str(_get(r, "Rule", "rule")) not in ("", CANARY_RULE)}
            if matched and args.yara_followup and vol:
                print(f"[mem]   triage matched {len(matched)} rule(s); running per-process "
                      f"enrichment (attribute + context) - rolling log: {jsonl}",
                      file=sys.stderr, flush=True)
                jl = os.path.join(out_dir, f"_yara_followup_{args.stamp}.jsonl")
                _s2 = _t.time()
                subprocess.run([sys.executable, worker, image, yarc, jl,
                                args.symbols or "-", str(args.yara_proc_timeout)], check=False)
                yara_dur += int(_t.time() - _s2)
                try:
                    with open(jl, encoding="utf-8") as fh:
                        parsed = linux_yara.parse_worker_jsonl(fh.readlines())
                    enriched = linux_yara.worker_rows_to_yara_rows(parsed["finished"])
                    if enriched:                       # prefer attributed+enriched over offset-only
                        rows["yarascan.YaraScan"] = enriched
                        canary_override = parsed["canary_hits"]
                        print(f"[mem]   enrichment attributed {len(enriched)} match(es) across "
                              f"{len(parsed['finished'])} proc(s).", file=sys.stderr, flush=True)
                except OSError:
                    pass
        else:                                       # vol: per-process worker (attributed, resumable)
            print("[mem]   YARA per-process scan (engine=vol vmayarascan, per-PID attribution) - "
                  f"rolling log: {jsonl}", file=sys.stderr, flush=True)
            _s = _t.time()
            subprocess.run([sys.executable, worker, image, yarc, jsonl,
                            args.symbols or "-", str(args.yara_proc_timeout)], check=False)
            yara_dur = int(_t.time() - _s)
            with open(jsonl, encoding="utf-8") as fh:
                parsed = linux_yara.parse_worker_jsonl(fh.readlines())
            yrows = linux_yara.worker_rows_to_yara_rows(parsed["finished"])
            rows["yarascan.YaraScan"] = yrows
            canary_override = parsed["canary_hits"]   # per-process canary (not the native ELF row)
            print(f"[mem]   YARA per-process scan finished ({yara_dur}s, "
                  f"{len(parsed['finished'])} proc(s), {len(yrows)} attributed match(es), "
                  f"{len(parsed['timeouts'])} per-proc timeout(s)).", file=sys.stderr, flush=True)

    findings = analyze(rows)

    # YARA trust self-test + dedicated results file (parity with the Windows _yara_results JSON).
    if yarc and not args.offline_dir:
        yrows = [r for k in YARA_PLUGINS for r in (rows.get(k) or [])]
        # native: canary is an ELF-match row; vol: per-process canary count from the worker JSONL
        canary = canary_override if canary_override is not None else _canary_hits(yrows)
        timed_out = bool(rows.get("_yara_timed_out"))
        if canary == 0 or timed_out:
            why = "timed out" if timed_out else "the ELF self-test canary never matched"
            findings.insert(0, _finding(
                "High", "YARA Self-Test FAILED", "engine did not inspect memory",
                f"YARA scan unreliable ({why}) - '0 YARA matches' is NOT a clean result. "
                f"Raise --yara-timeout, check yara-python, or try --yara-engine vol.", "N/A"))
        _write_yara_results(out_dir, args.stamp, args.yara_engine, image, yara_n, yara_failed,
                            yara_dur, timed_out, canary, yrows)

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
