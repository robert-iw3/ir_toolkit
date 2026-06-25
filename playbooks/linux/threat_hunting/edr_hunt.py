#!/usr/bin/env python3
"""
edr_hunt.py - Linux fileless / evasion hunt engine.

Inspects /proc, the loaded-module list, persistence locations and writable paths
and emits structured findings in the common schema:

    {Timestamp, Severity, Type, Target, Details, MITRE}

so findings from every collection phase merge into one set the adjudicator can
consume. Read-only and degrades gracefully without root (best-effort; unreadable
items are skipped, never fatal).

Usage:
    edr_hunt.py [--report-dir DIR] [--stamp YYYYmmdd_HHMMSS] [--quiet]
Writes EDR_Report_<stamp>.json (list of findings) and prints the path.
"""
import argparse
import datetime
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

FINDINGS = []
# Executable/volatile locations an implant typically drops into.
WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run")
# SUID binaries shipped by the base OS - anything SUID outside this set is noteworthy.
SUID_BASELINE = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
    "pkexec", "fusermount", "fusermount3", "ping", "ping6", "mount.nfs",
    "ntfs-3g", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "snap-confine", "unix_chkpwd", "Xorg.wrap", "vmware-user-suid-wrapper",
}


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add(severity, ftype, target, details, mitre):
    FINDINGS.append({
        "Timestamp": now(),
        "Severity": severity,
        "Type": ftype,
        "Target": target,
        "Details": details,
        "MITRE": mitre,
    })


def read_file(path, binary=False, limit=None):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read(limit) if limit else fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit) if limit else fh.read()
    except Exception:
        return None


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ""


def proc_pids():
    return [d for d in os.listdir("/proc") if d.isdigit()]


def cmdline(pid):
    raw = read_file(f"/proc/{pid}/cmdline", binary=True)
    if not raw:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def exe_of(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return None


def comm(pid):
    return (read_file(f"/proc/{pid}/comm") or "").strip()


# --- Check 1: hidden processes (rootkit getdents hooking) ---------------------
def is_thread_group_leader(pid):
    """True only for a real process (Tgid == Pid). Individual threads share the
    leader's Tgid but have their own /proc/<tid>, so this excludes them - without
    it, every thread (gmain/gdbus/pool-spawner...) looks like a 'hidden process'."""
    status = read_file(f"/proc/{pid}/status")
    if not status:
        return False
    tgid = pid_field = None
    for ln in status.splitlines():
        if ln.startswith("Tgid:"):
            tgid = ln.split()[1]
        elif ln.startswith("Pid:"):
            pid_field = ln.split()[1]
        if tgid and pid_field:
            break
    return tgid is not None and tgid == pid_field == str(pid)


def check_hidden_processes():
    """A PID whose /proc/<pid> is independently accessible but does NOT appear in
    os.listdir('/proc') indicates a userland/LKM rootkit hiding directory entries.
    Only thread-group leaders count (threads are statable but unlisted by design)."""
    try:
        listed = set(proc_pids())
        pid_max = int((read_file("/proc/sys/kernel/pid_max") or "65536").strip())
        for pid in range(1, min(pid_max, 4194304) + 1):
            sp = str(pid)
            if sp in listed:
                continue
            # Hidden from listdir but the task dir still resolves → candidate.
            if read_file(f"/proc/{pid}/maps") is None:
                continue
            if not is_thread_group_leader(pid):
                continue  # a thread (TID), not a hidden process
            # Confirm against a FRESH listing: a process that merely spawned after
            # the initial snapshot now shows up (race); a rootkit-hidden one stays
            # alive-but-unlisted. This removes transient-process false positives.
            if sp in set(proc_pids()):
                continue
            if read_file(f"/proc/{pid}/maps") is None:
                continue  # exited between checks → was transient, not hidden
            add("High", "Hidden Process", f"PID: {pid}",
                f"Visible via /proc/{pid} but hidden from directory listing. "
                f"comm={comm(sp) or 'unknown'} cmd={cmdline(sp)[:120]}",
                "T1014 (Rootkit)")
    except Exception as e:
        add("Info", "Hunt Error", "check_hidden_processes", str(e), "-")


# --- Check 2: deleted-but-running executables ---------------------------------
def check_deleted_running():
    for pid in proc_pids():
        try:
            link = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            continue
        if link.endswith(" (deleted)"):
            add("Medium", "Deleted Running Binary", f"PID: {pid}",
                f"Executable removed from disk while still running: {link}. "
                f"comm={comm(pid)} cmd={cmdline(pid)[:120]}",
                "T1070.004 (File Deletion)")


# --- Check 3: anonymous executable memory (injected code) --------------------
def check_anon_exec_maps():
    pat = re.compile(r"^[0-9a-f]+-[0-9a-f]+ r.xp 0+ 00:00 0 *$")
    for pid in proc_pids():
        maps = read_file(f"/proc/{pid}/maps")
        if not maps:
            continue
        hits = [ln for ln in maps.splitlines() if pat.match(ln)]
        if hits:
            ex = exe_of(pid) or "unknown"
            add("Medium", "Anonymous Exec Memory", f"PID: {pid}",
                f"{len(hits)} executable mapping(s) with no backing file (possible "
                f"injected code/JIT). exe={ex} comm={comm(pid)}",
                "T1055 (Process Injection)")


# --- Check 4: LD_PRELOAD / ld.so.preload hijack ------------------------------
def check_preload():
    pre = read_file("/etc/ld.so.preload")
    if pre and pre.strip():
        add("High", "Library Preload Hijack", "/etc/ld.so.preload",
            f"Global preload set (libc hook / userland rootkit): {pre.strip()[:200]}",
            "T1574.006 (LD_PRELOAD)")
    for pid in proc_pids():
        env = read_file(f"/proc/{pid}/environ", binary=True)
        if not env:
            continue
        for tok in env.split(b"\x00"):
            if not (tok.startswith(b"LD_PRELOAD=") and tok.split(b"=", 1)[1].strip()):
                continue
            val = tok.split(b"=", 1)[1].decode("utf-8", "replace")
            # A preload pointing into a writable/volatile location is the real tell;
            # bare library names (sandbox/accessibility/snap shims) are routine.
            if any(d in val for d in WRITABLE_DIRS) or "/home/" in val:
                add("High", "Library Preload Hijack", f"PID: {pid}",
                    f"LD_PRELOAD references a writable path: {val[:160]} comm={comm(pid)}",
                    "T1574.006 (LD_PRELOAD)")
            else:
                add("Low", "Process Preload", f"PID: {pid}",
                    f"LD_PRELOAD set: {val[:160]} comm={comm(pid)}", "T1574.006 (LD_PRELOAD)")
            break


# --- Check 5: kernel modules with no backing file (in-memory LKM rootkit) -----
def check_kernel_modules():
    mods = read_file("/proc/modules")
    if not mods:
        return
    for line in mods.splitlines():
        name = line.split()[0] if line.split() else None
        if not name:
            continue
        path = run(["modinfo", "-n", name]).strip()
        if not path:
            add("High", "Suspicious Kernel Module", name,
                "Loaded module has no resolvable file on disk (in-memory LKM rootkit indicator).",
                "T1014 (Rootkit)")
        elif not path.startswith(f"/lib/modules/{os.uname().release}") and not path.startswith("/usr/lib/modules/"):
            add("Medium", "Suspicious Kernel Module", name,
                f"Module loaded from non-standard path: {path}", "T1547.006 (Kernel Module)")


# --- Check 6: executables running from writable/volatile dirs ------------------
def check_writable_exec():
    for pid in proc_pids():
        ex = exe_of(pid)
        if not ex:
            continue
        clean = ex[:-10] if ex.endswith(" (deleted)") else ex
        if any(clean.startswith(d + "/") for d in WRITABLE_DIRS):
            add("High", "Execution From Writable Path", f"PID: {pid}",
                f"Running binary under world-writable/volatile path: {clean}. "
                f"comm={comm(pid)} cmd={cmdline(pid)[:120]}",
                "T1036 (Masquerading)")


# --- Check 7: SUID/SGID binaries outside the base-OS baseline -----------------
# Container/image layer roots hold their own copies of base-OS SUID binaries;
# they are not host persistence and would otherwise flood the results.
CONTAINER_PATHS = ("/overlay/", "/containers/storage/", "/var/lib/docker/",
                   "/var/lib/containerd/", "/snap/", "/.local/share/containers/")


def check_suid():
    out = run(["find", "/", "-xdev", "-perm", "/6000", "-type", "f"])
    for path in filter(None, (l.strip() for l in out.splitlines())):
        if os.path.basename(path) in SUID_BASELINE:
            continue
        if any(seg in path for seg in CONTAINER_PATHS):
            continue
        sev = "High" if any(path.startswith(d) for d in (*WRITABLE_DIRS, "/home")) else "Low"
        add(sev, "Unexpected SUID Binary", path,
            "SUID/SGID binary outside the base-OS baseline.", "T1548.001 (SetUID)")


# --- Check 8: persistence in cron / systemd referencing writable paths --------
# Matches download-and-execute / reverse-shell payloads, not benign uses of the
# same tools (e.g. `nc -U` unix sockets, `base64 -d > keyfile`).
SUSPICIOUS_CMD = re.compile(
    r"(/dev/tcp/\d|"                                       # reverse shell
    r"\bnc\b\s+[^|]*-\w*e|\bncat\b\s+[^|]*-\w*e|"          # nc/ncat -e
    r"\bnc\b\s+\d{1,3}(\.\d{1,3}){3}|"                     # nc to a raw IP
    r"\bsocat\b.*EXEC|bash\s+-i|python[0-9.]*\s+-c.*pty\.spawn|"
    r"(curl|wget)\s+[^|]*\|\s*(ba)?sh\b|"                  # fetch | sh
    r"(curl|wget)\s+[^|]*-o\s*/(tmp|dev/shm|var/tmp)/|"    # fetch into writable
    r"base64\s+-d[^>]*\|\s*(ba)?sh\b|"                     # base64 -d | sh
    r"\b(/tmp|/dev/shm|/var/tmp)/\S+)", re.I)              # exec from writable dir


def check_persistence():
    cron_files = []
    for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
              "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs"):
        try:
            for root, _, files in os.walk(d):
                cron_files += [os.path.join(root, f) for f in files]
        except Exception:
            pass
    if os.path.isfile("/etc/crontab"):
        cron_files.append("/etc/crontab")
    for cf in cron_files:
        body = read_file(cf) or ""
        for ln in body.splitlines():
            if ln.strip() and not ln.lstrip().startswith("#") and SUSPICIOUS_CMD.search(ln):
                add("Medium", "Cron Persistence", cf,
                    f"Cron entry with suspicious payload: {ln.strip()[:160]}",
                    "T1053.003 (Cron)")
    # systemd unit ExecStart pointing at writable/suspicious payloads
    for d in ("/etc/systemd/system", "/usr/local/lib/systemd/system", "/run/systemd/system"):
        try:
            for root, _, files in os.walk(d):
                for f in files:
                    if not (f.endswith(".service") or f.endswith(".timer")):
                        continue
                    p = os.path.join(root, f)
                    body = read_file(p) or ""
                    for ln in body.splitlines():
                        if ln.strip().startswith("ExecStart") and SUSPICIOUS_CMD.search(ln):
                            add("Medium", "Systemd Persistence", p,
                                f"Unit ExecStart with suspicious payload: {ln.strip()[:160]}",
                                "T1543.002 (Systemd Service)")
        except Exception:
            pass


# --- Check 9: high-entropy ELF in writable dirs (packed/encrypted implant) -----
def shannon(data):
    if not data:
        return 0.0
    c = Counter(data)
    t = len(data)
    return -sum((v / t) * math.log2(v / t) for v in c.values())


def check_entropy():
    for d in WRITABLE_DIRS + ("/home", "/root", "/opt", "/var/www"):
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            depth = root[len(d):].count(os.sep)
            if depth > 4:
                continue
            for f in files:
                p = os.path.join(root, f)
                try:
                    if not os.access(p, os.X_OK) or os.path.islink(p):
                        continue
                    size = os.path.getsize(p)
                    if size < 64 or size > 50 * 1024 * 1024:
                        continue
                    head = read_file(p, binary=True, limit=4)
                    if head != b"\x7fELF":
                        continue
                    ent = shannon(read_file(p, binary=True, limit=65536))
                    if ent > 7.2:
                        add("Medium", "High Entropy ELF", p,
                            f"Shannon entropy {ent:.2f} (packed/encrypted likely), size={size}.",
                            "T1027.002 (Packing)")
                except Exception:
                    continue


# --- Check 10: rogue accounts (extra UID-0, empty passwords) [beginner] -------
def check_accounts():
    passwd = read_file("/etc/passwd") or ""
    for ln in passwd.splitlines():
        parts = ln.split(":")
        if len(parts) < 7:
            continue
        user, uid = parts[0], parts[2]
        if uid == "0" and user != "root":
            add("High", "Unauthorized UID0 Account", user,
                f"Non-root account with UID 0 (privilege backdoor): {ln}", "T1136 (Create Account)")
    shadow = read_file("/etc/shadow")  # needs root; skipped silently otherwise
    if shadow:
        for ln in shadow.splitlines():
            parts = ln.split(":")
            if len(parts) > 1 and parts[1] == "" and parts[0] not in ("sync",):
                add("High", "Empty Password Account", parts[0],
                    "Account has an empty password hash (passwordless login).", "T1078 (Valid Accounts)")


# --- Check 11: shell-init backdoors (.bashrc/.profile, profile.d) [beginner] ---
def check_shell_init():
    targets = []
    for base in ["/root"] + [os.path.join("/home", d) for d in (os.listdir("/home") if os.path.isdir("/home") else [])]:
        for f in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login"):
            targets.append(os.path.join(base, f))
    targets += ["/etc/bash.bashrc", "/etc/profile"]
    for d in ("/etc/profile.d",):
        try:
            targets += [os.path.join(d, f) for f in os.listdir(d)]
        except Exception:
            pass
    for t in targets:
        body = read_file(t)
        if not body:
            continue
        for ln in body.splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and SUSPICIOUS_CMD.search(s):
                add("Medium", "Shell Init Backdoor", t,
                    f"Shell init contains suspicious command: {s[:160]}", "T1546.004 (Shell Init)")


# --- Check 12: webshells in common web roots [beginner/intermediate] ----------
WEBSHELL = re.compile(
    r"(eval\s*\(\s*\$_(POST|GET|REQUEST)|system\s*\(\s*\$_|passthru\s*\(|"
    r"shell_exec\s*\(|base64_decode\s*\(\s*\$_|assert\s*\(\s*\$_|`\s*\$_)", re.I)


def check_webshells():
    for root_dir in ("/var/www", "/srv/www", "/usr/share/nginx", "/opt/lampp/htdocs"):
        if not os.path.isdir(root_dir):
            continue
        for root, _, files in os.walk(root_dir):
            for f in files:
                if not f.lower().endswith((".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx")):
                    continue
                p = os.path.join(root, f)
                body = read_file(p)
                if body and WEBSHELL.search(body):
                    add("High", "Webshell", p,
                        "Web file contains dynamic-eval-of-request-data webshell pattern.",
                        "T1505.003 (Web Shell)")


# --- Check 13: memory-only execution via memfd_create [intermediate/advanced] --
def check_memfd():
    for pid in proc_pids():
        ex = exe_of(pid)
        if ex and ("memfd:" in ex or ex.startswith("/dev/shm/")):
            add("High", "Memory-Only Executable (memfd)", f"PID: {pid}",
                f"Process executing from anonymous/memfd backing: {ex}. "
                f"comm={comm(pid)} cmd={cmdline(pid)[:120]}",
                "T1620 (Reflective Loading)")


# --- Check 14: hidden kernel modules (/sys/module vs /proc/modules) [advanced] -
def check_hidden_modules():
    proc_mods = set()
    mods = read_file("/proc/modules") or ""
    for ln in mods.splitlines():
        if ln.split():
            proc_mods.add(ln.split()[0])
    try:
        sys_mods = {m for m in os.listdir("/sys/module")
                    if os.path.isdir(f"/sys/module/{m}") and
                    os.path.exists(f"/sys/module/{m}/initstate")}
    except Exception:
        return
    # modules present in sysfs (loaded) but absent from /proc/modules = hidden by rootkit
    for m in sys_mods - proc_mods:
        add("High", "Hidden Kernel Module", m,
            "Module visible in /sys/module but hidden from /proc/modules (LKM rootkit).",
            "T1014 (Rootkit)")


# --- Check 15: capability-endowed binaries outside baseline [intermediate] -----
def check_capabilities():
    if not shutil.which("getcap"):
        return
    out = run(["getcap", "-r", "/usr", "/opt", "/home", "/tmp", "/var"])
    for ln in out.splitlines():
        if not ln.strip():
            continue
        path = ln.split()[0]
        caps = ln.lower()
        if any(c in caps for c in ("cap_setuid", "cap_sys_admin", "cap_sys_ptrace",
                                   "cap_dac_override", "cap_sys_module")):
            sev = "High" if any(path.startswith(d) for d in (*WRITABLE_DIRS, "/home")) else "Medium"
            add(sev, "Dangerous File Capability", path,
                f"Binary granted powerful capability: {ln.strip()[:160]}", "T1548 (Privilege Escalation)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    checks = [
        check_hidden_processes, check_deleted_running, check_anon_exec_maps,
        check_preload, check_kernel_modules, check_writable_exec,
        check_suid, check_persistence, check_entropy,
        check_accounts, check_shell_init, check_webshells, check_memfd,
        check_hidden_modules, check_capabilities,
    ]
    for ch in checks:
        try:
            ch()
        except Exception as e:
            add("Info", "Hunt Error", ch.__name__, str(e), "-")

    os.makedirs(args.report_dir, exist_ok=True)
    out = os.path.join(args.report_dir, f"EDR_Report_{args.stamp}.json")
    with open(out, "w") as fh:
        json.dump(FINDINGS, fh, indent=2)
    if not args.quiet:
        sev = Counter(f["Severity"] for f in FINDINGS)
        print(f"[edr_hunt] {len(FINDINGS)} finding(s) "
              f"({', '.join(f'{k}:{v}' for k, v in sev.items()) or 'none'}) -> {out}")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
