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
# World-writable staging dirs only. /run and /var/run are root-owned tmpfs that
# legitimate services (udev, alsa, gpu) reference constantly, so they are excluded
# here to avoid flooding the persistence/integrity checks with false positives.
IMPLANT_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
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
# JIT runtimes legitimately map anonymous executable pages (V8/SpiderMonkey,
# Mono/.NET, the JVM, CPython's ctypes/cffi trampolines). On a desktop these
# dominate the results, so a known JIT process is only reported when the signal
# is corroborated by an untrusted binary - injection into a renamed dropper still
# shows, but gnome-shell doing its job does not.
JIT_RUNTIMES = {
    "gnome-shell", "gjs", "mono", "mono-sgen", "dotnet", "node", "java",
    "firefox", "thunderbird", "chrome", "chromium", "code", "Web Content",
    "Isolated Web Co", "WebExtensions",
}


def check_anon_exec_maps():
    pat = re.compile(r"^[0-9a-f]+-[0-9a-f]+ r.xp 0+ 00:00 0 *$")
    for pid in proc_pids():
        maps = read_file(f"/proc/{pid}/maps")
        if not maps:
            continue
        hits = [ln for ln in maps.splitlines() if pat.match(ln)]
        if not hits:
            continue
        cm = comm(pid)
        untrusted = _pid_exe_trust(pid)
        if cm in JIT_RUNTIMES and not untrusted:
            continue  # expected JIT behaviour from a trusted binary
        ex = exe_of(pid) or "unknown"
        sev = "High" if untrusted else "Medium"
        add(sev, "Anonymous Exec Memory", f"PID: {pid}",
            f"{len(hits)} executable mapping(s) with no backing file (possible "
            f"injected code/JIT). exe={ex} comm={cm}"
            + (f" [untrusted: {untrusted}]" if untrusted else ""),
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


# --- Check 12: SSH authorized_keys audit --------------------------------------
# A planted key's *comment* ("kali@kali") is attacker-controlled and trivially
# scrubbed, so it is worthless as a signal. These checks key off properties an
# attacker cannot remove while retaining access: who can write the file, who owns
# it, a forced command embedded in the key, the same key reused across accounts,
# and an sshd_config that redirects key lookups to a non-standard location.
SSH_KEY_RE = re.compile(
    r"((?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[\w-]+|sk-[\w@.-]+))\s+([A-Za-z0-9+/]{40,}={0,3})")
# A forced command that hands back a shell / fetches+runs / lives in a writable
# dir is a backdoor. Benign forced commands (git-shell, rrsync, borg serve,
# internal-sftp) are left alone to keep the signal clean.
SSH_CMD_BACKDOOR = re.compile(
    r"(/dev/tcp/|\b(ba|z|k)?sh\b\s*(-i|$)|/bin/(ba|z|k)?sh\b|pty\.spawn|"
    r"(curl|wget)\b[^|]*\|\s*\w*sh\b|nc\b[^|]*-\w*e\b|/tmp/|/dev/shm/|/var/tmp/)", re.I)


def _interactive_users():
    """(user, uid, home) for accounts that can actually log in via SSH."""
    out = []
    for line in (read_file("/etc/passwd") or "").splitlines():
        p = line.split(":")
        if len(p) < 7:
            continue
        user, uid, home, shell = p[0], p[2], p[5], p[6]
        if not home or not home.startswith("/"):
            continue
        if shell in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/sync", ""):
            continue
        try:
            out.append((user, int(uid), home))
        except ValueError:
            continue
    return out


def _ssh_authorized_keys_files():
    """Non-default AuthorizedKeysFile locations declared in sshd_config -
    attackers redirect key lookups to a writable/global path they control."""
    cfg = read_file("/etc/ssh/sshd_config") or ""
    for ln in cfg.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or not s.lower().startswith("authorizedkeysfile"):
            continue
        for tok in s.split()[1:]:
            if tok.startswith("/"):  # absolute path = outside per-user ~/.ssh
                sev = "High" if tok.startswith(IMPLANT_DIRS) else "Medium"
                add(sev, "Non-standard AuthorizedKeysFile", "/etc/ssh/sshd_config",
                    f"sshd reads authorized keys from an absolute path '{tok}' (not per-user "
                    f"~/.ssh) - verify it is not attacker-controlled.",
                    "T1098.004 (SSH Authorized Keys)")


def check_authorized_keys():
    _ssh_authorized_keys_files()
    blob_to_users = {}  # public key blob -> set(users) for cross-account reuse
    for user, uid, home in _interactive_users():
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        body = read_file(ak_path)
        if not body:
            continue

        # File hygiene: writability and ownership (StrictModes-relevant, hard to fake).
        if os.path.islink(ak_path):
            add("High", "SSH authorized_keys is a Symlink", ak_path,
                f"'{user}' authorized_keys is a symlink - may redirect to an attacker file.",
                "T1098.004 (SSH Authorized Keys)")
        try:
            st = os.stat(ak_path)
            if st.st_mode & 0o002:
                add("Critical", "SSH Key File World-Writable", ak_path,
                    f"'{user}' authorized_keys is world-writable (mode {oct(st.st_mode)[-3:]}) - "
                    f"any user can append a key.", "T1098.004 (SSH Authorized Keys)")
            elif st.st_mode & 0o020:
                add("High", "SSH Key File Group-Writable", ak_path,
                    f"'{user}' authorized_keys is group-writable (mode {oct(st.st_mode)[-3:]}).",
                    "T1098.004 (SSH Authorized Keys)")
            if st.st_uid != uid:
                add("High", "SSH Key File Owner Mismatch", ak_path,
                    f"authorized_keys for '{user}' (uid {uid}) is owned by uid {st.st_uid} - "
                    f"written by a different account.", "T1098.004 (SSH Authorized Keys)")
            age_days = (datetime.datetime.now().timestamp() - st.st_mtime) / 86400
            if age_days < 7 and user == "root":
                add("Medium", "root authorized_keys Recently Modified", ak_path,
                    f"root's authorized_keys changed {age_days:.1f} days ago - verify the key add.",
                    "T1098.004 (SSH Authorized Keys)")
        except Exception:
            pass

        keys = [ln.strip() for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        for k in keys:
            m = SSH_KEY_RE.search(k)
            if not m:
                continue
            options = k[:m.start()].strip()  # everything before the key type = options
            blob_to_users.setdefault(m.group(2), set()).add(user)
            cmd_m = re.search(r'command="((?:[^"\\]|\\.)*)"', options)
            if cmd_m and SSH_CMD_BACKDOOR.search(cmd_m.group(1)):
                add("High", "SSH Forced-Command Backdoor", ak_path,
                    f"'{user}' key pins a forced command that yields a shell / runs from a "
                    f"writable path: command=\"{cmd_m.group(1)[:120]}\".",
                    "T1098.004 (SSH Authorized Keys), T1059.004 (Unix Shell)")

        if len(keys) > 5:
            add("Medium", "Many SSH Authorized Keys", ak_path,
                f"'{user}' has {len(keys)} authorized keys - verify all are expected.",
                "T1098.004 (SSH Authorized Keys)")

    # Same public key authorized on multiple accounts = shared backdoor / lateral movement.
    for blob, users in blob_to_users.items():
        if len(users) >= 2:
            add("High", "SSH Key Reused Across Accounts", ", ".join(sorted(users)),
                f"One public key (...{blob[-16:]}) is authorized for {len(users)} accounts "
                f"({', '.join(sorted(users))}) - shared backdoor / lateral movement.",
                "T1098.004 (SSH Authorized Keys), T1021.004 (SSH)")


# --- Check 13: PAM module tampering [LEDR-002] --------------------------------
def check_pam_modules():
    """PAM module tampering - unauthorized modules in /etc/pam.d/."""
    pam_dir = "/etc/pam.d"
    if not os.path.isdir(pam_dir):
        return
    # Trusted module directory prefixes (distro-installed)
    trusted_prefixes = (
        "/lib/security/", "/lib/x86_64-linux-gnu/security/",
        "/lib/aarch64-linux-gnu/security/", "/lib64/security/",
        "/usr/lib/security/", "/usr/lib/x86_64-linux-gnu/security/",
        "/usr/lib/aarch64-linux-gnu/security/", "/usr/lib64/security/",
        "/usr/lib/pam/",
    )
    for fname in os.listdir(pam_dir):
        fpath = os.path.join(pam_dir, fname)
        body = read_file(fpath) or ""
        for ln in body.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            # PAM rule format: <type> <control> <module-path> [args]
            tokens = s.split()
            if len(tokens) < 3:
                continue
            module_path = tokens[2]
            # Skip @include and built-in references
            if module_path.startswith("@") or "/" not in module_path:
                continue
            # Absolute path to a module outside trusted dirs
            if module_path.startswith("/"):
                trusted = any(module_path.startswith(p) for p in trusted_prefixes)
                if not trusted:
                    sev = "Critical" if any(
                        module_path.startswith(d) for d in ("/tmp", "/dev/shm", "/var/tmp", "/run/shm")) else "High"
                    add(sev, "PAM Module Tampering", fpath,
                        f"PAM config references module outside trusted paths: {module_path} "
                        f"(rule: {s[:160]})",
                        "T1556.003 (Pluggable Authentication Modules)")
                    continue
                # Trusted path - check if the file exists and is recently modified
                try:
                    mtime = os.path.getmtime(module_path)
                    age_days = (datetime.datetime.now().timestamp() - mtime) / 86400
                    if age_days < 30:
                        add("Medium", "Recently Modified PAM Module (verify)", module_path,
                            f"PAM module modified {age_days:.1f} days ago - verify it is expected. "
                            f"Config: {fpath}, rule: {s[:120]}",
                            "T1556.003 (Pluggable Authentication Modules)")
                except Exception:
                    pass


# --- Check 14: webshells in common web roots [beginner/intermediate] ----------
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


# --- Check 16: network connection audit ---------------------------------------
# Static parse of /proc/net/{tcp,tcp6,udp,udp6} + inode->pid attribution from
# /proc/<pid>/fd. No external tooling (ss/netstat may be tampered or absent).
TRUSTED_REMOTE_PORTS = frozenset({
    80, 443, 8080, 8443, 53, 123, 22, 21, 25, 587, 465, 993, 995, 110, 143, 389, 636,
})
EXPECTED_LISTEN_PORTS = frozenset({
    22, 25, 53, 80, 110, 143, 443, 465, 587, 631, 993, 995, 3306, 5432, 6379, 11211,
})
C2_LISTEN_HINT_PORTS = frozenset({4444, 1234, 8888, 9999, 31337, 6666, 7777, 1337, 12345})
# Processes that legitimately hold many outbound connections / odd ports.
TRUSTED_NET_PROCS = frozenset({
    "sshd", "systemd", "systemd-resolve", "systemd-resol", "chronyd", "ntpd",
    "NetworkManager", "dhclient", "dhcpcd", "snapd", "packagekitd", "containerd",
    "dockerd", "kubelet", "chrome", "firefox", "thunderbird", "code", "spotify",
    "slack", "teams", "discord", "curl", "wget", "apt", "apt-get", "dnf", "yum",
})


def _hex_to_ip(hex_addr):
    """/proc/net hex address -> dotted/colon IP. IPv4 is little-endian per-4-bytes."""
    h = hex_addr.upper()
    try:
        if len(h) == 8:                       # IPv4
            b = bytes.fromhex(h)
            return ".".join(str(x) for x in reversed(b))
        if len(h) == 32:                      # IPv6 (4 little-endian 32-bit words)
            words = [h[i:i + 8] for i in range(0, 32, 8)]
            raw = b"".join(bytes(reversed(bytes.fromhex(w))) for w in words)
            import socket
            return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return None
    return None


def _is_private_ip(ip):
    if not ip:
        return True
    if ":" in ip:  # IPv6: treat loopback/link-local/ULA as private
        return ip in ("::1", "::") or ip.lower().startswith(("fe80", "fc", "fd", "::ffff:127", "::ffff:10.", "::ffff:192.168", "::ffff:172."))
    try:
        o = [int(x) for x in ip.split(".")]
    except Exception:
        return True
    if o[0] in (10, 127, 0):
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    if o[0] >= 224:  # multicast / reserved
        return True
    return False


def _socket_inode_map():
    """Map socket inode -> (pid, comm) by walking /proc/<pid>/fd symlinks."""
    m = {}
    for pid in proc_pids():
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except Exception:
            continue
        for fd in fds:
            try:
                tgt = os.readlink(os.path.join(fd_dir, fd))
            except Exception:
                continue
            if tgt.startswith("socket:["):
                inode = tgt[8:-1]
                m.setdefault(inode, (pid, comm(pid)))
    return m


def _parse_proc_net(path):
    """Yield (local_ip, local_port, rem_ip, rem_port, state_hex, inode)."""
    body = read_file(path)
    if not body:
        return
    for ln in body.splitlines()[1:]:
        f = ln.split()
        if len(f) < 10:
            continue
        try:
            la, lp = f[1].split(":")
            ra, rp = f[2].split(":")
            yield (_hex_to_ip(la), int(lp, 16), _hex_to_ip(ra), int(rp, 16), f[3], f[9])
        except Exception:
            continue


def check_network():
    inode_map = _socket_inode_map()
    for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
        for lip, lport, rip, rport, st, inode in _parse_proc_net(path):
            pid, cm = inode_map.get(inode, (None, ""))
            who = f"PID: {pid} ({cm})" if pid else f"socket inode {inode}"
            untrusted = _pid_exe_trust(pid) if pid else None

            if st == "01" and not _is_private_ip(rip):
                # Behavioral first: an external connection from a deleted/memfd/
                # writable-path binary is C2 regardless of port - a beacon over 443
                # defeats any port allow-list, but the binary's provenance does not.
                if untrusted:
                    add("High", "External Connection From Untrusted Binary", who,
                        f"ESTABLISHED {proto} to {rip}:{rport} from a process whose "
                        f"{untrusted}. comm={cm} cmd={cmdline(pid)[:100] if pid else 'n/a'}",
                        "T1071 (Application Layer Protocol), T1059 (Command and Control)")
                    continue
                # Port heuristic second (weaker, supplementary).
                if cm and cm in TRUSTED_NET_PROCS:
                    continue
                if rport in TRUSTED_REMOTE_PORTS:
                    continue
                sev = "High" if rport in C2_LISTEN_HINT_PORTS else "Medium"
                add(sev, "Suspicious Outbound Connection", who,
                    f"ESTABLISHED {proto} to {rip}:{rport} (public IP, non-standard port). "
                    f"comm={cm} cmd={cmdline(pid)[:100] if pid else 'n/a'}",
                    "T1071 (Application Layer Protocol), T1095 (Non-Standard Port)")

            elif st == "0A":
                bound_external = lip not in ("127.0.0.1", "::1", None)
                # Behavioral: a listener backed by an untrusted binary is a backdoor
                # listener whatever the port (including high/ephemeral).
                if untrusted and (bound_external or lport in C2_LISTEN_HINT_PORTS):
                    add("High", "Network Listener From Untrusted Binary", who,
                        f"Listening {proto} on {lip}:{lport} from a process whose "
                        f"{untrusted}. comm={cm} cmd={cmdline(pid)[:100] if pid else 'n/a'}",
                        "T1071 (Application Layer Protocol), T1205 (Traffic Signaling)")
                    continue
                if lport in EXPECTED_LISTEN_PORTS or lport >= 32768:
                    continue
                if not bound_external and lport not in C2_LISTEN_HINT_PORTS:
                    continue  # loopback-only on a high port is usually benign IPC
                sev = "High" if (lport in C2_LISTEN_HINT_PORTS or lport < 1024) else "Medium"
                add(sev, "Unexpected Network Listener", who,
                    f"Listening {proto} on {lip}:{lport} (not an expected service). "
                    f"comm={cm} cmd={cmdline(pid)[:100] if pid else 'n/a'}",
                    "T1071 (Application Layer Protocol)")


# --- Check 17: ELF magic / extension mismatch ---------------------------------
# A real ELF carrying a benign-looking extension in a writable dir = staged implant.
_DECEPTIVE_EXTS = (".txt", ".log", ".dat", ".jpg", ".jpeg", ".png", ".gif", ".pdf",
                   ".doc", ".docx", ".xls", ".csv", ".conf", ".cfg", ".json", ".xml",
                   ".html", ".css", ".md", ".bak", ".old", ".tmp", ".cache")


def check_magic_mismatch():
    for d in WRITABLE_DIRS + ("/home", "/root", "/opt", "/var/www", "/srv"):
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            if root[len(d):].count(os.sep) > 4:
                continue
            for f in files:
                low = f.lower()
                if not low.endswith(_DECEPTIVE_EXTS):
                    continue
                p = os.path.join(root, f)
                try:
                    if os.path.islink(p) or os.path.getsize(p) < 4:
                        continue
                    head = read_file(p, binary=True, limit=4)
                except Exception:
                    continue
                if not head:
                    continue
                if head == b"\x7fELF":
                    add("High", "MagicByte Mismatch", p,
                        f"File has '{os.path.splitext(f)[1]}' extension but ELF magic bytes "
                        f"(executable masquerading as a data file).",
                        "T1036.008 (Masquerade File Type), T1027 (Obfuscation)")
                elif head[:2] == b"#!" and low.endswith((".jpg", ".png", ".gif", ".pdf", ".doc", ".xls")):
                    add("Medium", "MagicByte Mismatch", p,
                        f"File has image/doc extension but a script shebang '#!' header.",
                        "T1036.008 (Masquerade File Type)")


# --- Check 18: logging / telemetry tampering ----------------------------------
def check_log_tampering():
    # 18a. Core audit/logging services disabled or dead.
    for unit in ("auditd", "rsyslog", "systemd-journald"):
        state = run(["systemctl", "is-enabled", unit]).strip()
        active = run(["systemctl", "is-active", unit]).strip()
        if state in ("disabled", "masked"):
            sev = "High" if unit in ("auditd", "systemd-journald") else "Medium"
            add(sev, "Logging Service Disabled", unit,
                f"{unit} is '{state}' - audit/telemetry coverage gap.",
                "T1562.001 (Impair Defenses), T1562.006 (Indicator Blocking)")
        elif active and active not in ("active", "") and unit != "auditd":
            add("Medium", "Logging Service Not Running", unit,
                f"{unit} is '{active}'.", "T1562.001 (Impair Defenses)")
    # 18b. journald persistence disabled (Storage=none/volatile loses logs on reboot).
    jconf = read_file("/etc/systemd/journald.conf") or ""
    for ln in jconf.splitlines():
        s = ln.strip()
        if s.lower().startswith("storage=") and s.split("=", 1)[1].strip().lower() in ("none", "volatile"):
            add("Medium", "Journald Persistence Disabled", "/etc/systemd/journald.conf",
                f"journald {s} - logs are not retained across reboot.",
                "T1562.001 (Impair Defenses)")
    # 18c. auditd ruleset empty (-D / no rules = blind auditing).
    if shutil.which("auditctl"):
        rules = run(["auditctl", "-l"]).strip()
        if rules and "No rules" in rules:
            add("Medium", "Audit Rules Cleared", "auditctl -l",
                "auditd is running with no active rules - no syscall/file auditing.",
                "T1562.001 (Impair Defenses)")
    # 18d. shell history neutered (HISTFILE=/dev/null, HISTSIZE=0, unset).
    hist_pat = re.compile(r"(?i)\b(HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0|HISTFILESIZE\s*=\s*0|"
                          r"unset\s+HIST(FILE|SIZE)|set\s+\+o\s+history|export\s+HISTFILE\s*=\s*$)")
    for base in ["/root"] + [os.path.join("/home", d) for d in (os.listdir("/home") if os.path.isdir("/home") else [])]:
        for rc in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
            body = read_file(os.path.join(base, rc))
            if body and hist_pat.search(body):
                add("Medium", "Shell History Disabled", os.path.join(base, rc),
                    "Shell rc neutralises command history (anti-forensics).",
                    "T1070.003 (Clear Command History)")
    # 18e. truncated auth/audit logs (size 0 on a running system = suspicious wipe).
    # btmp is excluded: it only records FAILED logins and is routinely empty on a
    # healthy host, so a zero-byte btmp is the normal case, not a wipe indicator.
    for lf in ("/var/log/auth.log", "/var/log/secure", "/var/log/wtmp",
               "/var/log/audit/audit.log", "/var/log/syslog"):
        try:
            if os.path.isfile(lf) and os.path.getsize(lf) == 0:
                add("Medium", "Log File Truncated", lf,
                    "Security/audit log exists but is zero bytes (possible log wipe).",
                    "T1070.002 (Clear Linux Logs)")
        except Exception:
            pass


# --- Check 19: privileged-task binary integrity -------------------------------
# Root-run cron/systemd unit whose target binary is missing, world-writable, or
# owned by a non-root user = trivially hijackable persistence.
def _audit_exec_target(binpath, source, mitre):
    in_writable = binpath.startswith(IMPLANT_DIRS)
    try:
        st = os.stat(binpath)
    except FileNotFoundError:
        # Missing from a standard system path = an uninstalled optional unit
        # (quotaon, brltty, ...) - routine noise. Only a binary staged in a
        # world-writable dir that is absent *now* is dropped-at-runtime persistence.
        if in_writable:
            add("High", "Privileged Task Binary Missing", source,
                f"Root-context binary staged under a world-writable path is absent now: "
                f"{binpath} (dropped-at-runtime persistence).", mitre)
        return
    except Exception:
        return
    mode = st.st_mode
    if mode & 0o002:
        add("Critical", "Privileged Task World-Writable Binary", source,
            f"Root-context binary {binpath} is world-writable (mode {oct(mode)[-3:]}) "
            f"- any user can hijack it.", mitre)
    elif st.st_uid != 0:
        add("High", "Privileged Task Non-Root Binary", source,
            f"Root-context binary {binpath} is owned by uid {st.st_uid} (non-root) "
            f"- owner can modify what root executes.", mitre)


def check_privileged_task_integrity():
    import shlex
    # systemd units running as root (no User= override) -> audit ExecStart target.
    for d in ("/etc/systemd/system", "/usr/local/lib/systemd/system",
              "/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"):
        try:
            entries = os.walk(d)
        except Exception:
            continue
        for root, _, files in entries:
            for fn in files:
                if not fn.endswith(".service"):
                    continue
                p = os.path.join(root, fn)
                body = read_file(p) or ""
                if re.search(r"(?im)^\s*User\s*=\s*(?!root\b)\S+", body):
                    continue  # runs as a non-root user - lower value, skip
                for ln in body.splitlines():
                    m = re.match(r"\s*ExecStart\s*=\s*[-@+!]*\s*(\S+)", ln)
                    if not m:
                        continue
                    binpath = m.group(1)
                    if binpath.startswith("/") and not binpath.startswith(("/bin/sh", "/usr/bin/env")):
                        _audit_exec_target(binpath, p, "T1543.002 (Systemd Service)")
    # System crontab / cron.d entries (run as root) -> audit the invoked binary.
    cron_files = ["/etc/crontab"]
    try:
        cron_files += [os.path.join("/etc/cron.d", f) for f in os.listdir("/etc/cron.d")]
    except Exception:
        pass
    for cf in cron_files:
        body = read_file(cf) or ""
        for ln in body.splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            toks = s.split()
            # /etc/crontab & cron.d: min hr dom mon dow user cmd...
            if len(toks) >= 7 and toks[5] in ("root",):
                try:
                    cand = shlex.split(s)[6]
                except Exception:
                    continue
                if cand.startswith("/"):
                    _audit_exec_target(cand, cf, "T1053.003 (Cron)")


# --- Check 20: extended persistence locations ---------------------------------
def check_persistence_extended():
    # 20a. rc.local / init scripts with suspicious payloads.
    for p in ("/etc/rc.local", "/etc/rc.d/rc.local"):
        body = read_file(p)
        if body:
            for ln in body.splitlines():
                s = ln.strip()
                if s and not s.startswith("#") and SUSPICIOUS_CMD.search(s):
                    add("High", "rc.local Persistence", p,
                        f"rc.local runs suspicious command at boot: {s[:160]}",
                        "T1037.004 (RC Scripts)")
    # 20b. udev rules invoking external programs (RUN+= to a writable path).
    for d in ("/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"):
        try:
            rules = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".rules")]
        except Exception:
            continue
        for rf in rules:
            body = read_file(rf) or ""
            for ln in body.splitlines():
                m = re.search(r'RUN\s*[+]?=\s*"([^"]+)"', ln)
                if m and (any(x in m.group(1) for x in IMPLANT_DIRS) or
                          SUSPICIOUS_CMD.search(m.group(1))):
                    add("High", "udev Rule Persistence", rf,
                        f"udev rule executes from a writable/suspicious path: {m.group(1)[:160]}",
                        "T1547.010 (udev Rules)")
    # 20c. XDG autostart entries pointing at writable/suspicious binaries.
    autostart_dirs = ["/etc/xdg/autostart"]
    for base in [os.path.join("/home", d) for d in (os.listdir("/home") if os.path.isdir("/home") else [])] + ["/root"]:
        autostart_dirs.append(os.path.join(base, ".config", "autostart"))
    for d in autostart_dirs:
        try:
            desktops = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".desktop")]
        except Exception:
            continue
        for df in desktops:
            body = read_file(df) or ""
            for ln in body.splitlines():
                if ln.strip().startswith("Exec="):
                    cmd = ln.split("=", 1)[1]
                    if any(x in cmd for x in IMPLANT_DIRS) or SUSPICIOUS_CMD.search(cmd):
                        add("High", "Autostart Persistence", df,
                            f"Desktop autostart runs from a writable/suspicious path: {cmd[:160]}",
                            "T1547.013 (XDG Autostart)")
    # 20d. at-jobs queued (often used for one-shot delayed execution).
    for d in ("/var/spool/cron/atjobs", "/var/spool/at"):
        try:
            jobs = os.listdir(d)
        except Exception:
            continue
        if jobs:
            add("Low", "Scheduled at-job Present", d,
                f"{len(jobs)} queued at-job(s) - verify (one-shot delayed execution).",
                "T1053.002 (At)")


# --- Check 21: GTFOBins-style live process abuse ------------------------------
# Running processes whose argv matches download-and-exec / reverse-shell / an
# interpreter spawning an interactive shell - the Linux LOLBin equivalent.
_GTFO_PAT = re.compile(
    r"(/dev/tcp/\d|/dev/udp/\d|"                                   # bash net redirection
    r"\bnc\b[^|]*-\w*e\b|\bncat\b[^|]*-\w*e\b|"                    # nc/ncat -e
    r"\bsocat\b[^|]*EXEC|"                                         # socat EXEC
    r"python[0-9.]*\s+-c[^|]*(pty\.spawn|socket|subprocess)|"      # python rev shell
    r"perl\s+-e[^|]*socket|ruby\s+-e[^|]*TCPSocket|"               # perl/ruby rev shell
    r"php\s+-r[^|]*fsockopen|"                                     # php rev shell
    r"(curl|wget)\s+[^|]*\|\s*(ba|z|d|a)?sh\b|"                    # fetch | sh
    r"\b(base64|xxd|openssl\s+enc)\b[^|]*\|\s*(ba)?sh\b)", re.I)   # decode | sh


def check_gtfobins_exec():
    for pid in proc_pids():
        cmd = cmdline(pid)
        if not cmd or pid in (str(os.getpid()),):
            continue
        if _GTFO_PAT.search(cmd):
            add("High", "Suspicious Process Execution", f"PID: {pid}",
                f"Live process argv matches download-and-exec / reverse-shell pattern: "
                f"{cmd[:180]} comm={comm(pid)}",
                "T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer)")


# --- Check 22: credential-access artifacts ------------------------------------
def check_cred_access():
    # 22a. world-readable shadow file.
    try:
        mode = oct(os.stat("/etc/shadow").st_mode)[-3:]
        if mode[2] not in ("0",):
            add("High", "Shadow File World-Readable", "/etc/shadow",
                f"/etc/shadow is world-readable (mode {mode}) - offline hash cracking exposure.",
                "T1003.008 (/etc/passwd and /etc/shadow)")
    except Exception:
        pass
    # 22b. copies of credential stores staged in writable dirs.
    cred_name = re.compile(r"(?i)(shadow|passwd|gshadow|sssd|krb5|\.kdbx|secrets|"
                           r"id_rsa|id_ed25519|\.pem|wallet|\.gnupg|aws.*credentials)")
    core_pat = re.compile(r"(?i)(^core(\.\d+)?$|\.core$|core\.\d+)")
    for d in WRITABLE_DIRS:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            if root[len(d):].count(os.sep) > 3:
                continue
            for f in files:
                p = os.path.join(root, f)
                if cred_name.search(f) and not os.path.islink(p):
                    add("High", "Staged Credential Artifact", p,
                        f"Credential-store-like file in a writable/volatile dir: {f}",
                        "T1003 (OS Credential Dumping)")
                elif core_pat.match(f):
                    # core dump of a credential-bearing process is a known dumping path.
                    add("Medium", "Process Core Dump", p,
                        "Core dump in a writable dir - may contain in-memory secrets "
                        "(e.g. crafted crash of an auth process).",
                        "T1003.007 (Proc Filesystem)")


# =============================================================================
# Behavioral / structural correlation checks.
#
# These do not pattern-match payload strings (trivially renamed). They key off
# relationships and state that the malicious behavior cannot avoid: where a
# process's binary lives, who its ancestors are, whether the name it presents
# matches its real executable, and which sensitive handles it holds open.
# =============================================================================

def _pid_exe_trust(pid):
    """Return a reason string if a PID's backing binary is untrustworthy
    (deleted, memfd/anonymous, or under a world-writable dir), else None."""
    raw = exe_of(pid)
    if not raw:
        return None
    if "memfd:" in raw:
        return "anonymous memfd backing (fileless)"
    if raw.endswith(" (deleted)"):
        return "binary deleted from disk while running"
    if raw.startswith(IMPLANT_DIRS):
        return f"binary under a world-writable path ({raw})"
    return None


def _proc_table():
    """pid -> {ppid, comm, exe, deleted, cmd}. One pass over /proc."""
    tbl = {}
    for pid in proc_pids():
        ppid = None
        st = read_file(f"/proc/{pid}/stat")
        if st:
            # comm sits in parens and may itself contain ') ' - split after the LAST ')'.
            rp = st.rfind(")")
            tail = st[rp + 2:].split() if rp != -1 else []
            if len(tail) >= 2:
                ppid = tail[1]  # tail[0]=state, tail[1]=ppid
        raw = exe_of(pid)
        deleted = bool(raw and raw.endswith(" (deleted)"))
        clean = raw[:-10] if deleted else raw
        tbl[pid] = {"ppid": ppid, "comm": comm(pid), "exe": clean,
                    "deleted": deleted, "cmd": cmdline(pid)}
    return tbl


def _pids_with_external_conn():
    """Set of pids owning an ESTABLISHED socket to a public IP."""
    inode_map = _socket_inode_map()
    pids = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for _lip, _lp, rip, _rp, stt, inode in _parse_proc_net(path):
            if stt == "01" and not _is_private_ip(rip):
                pid = inode_map.get(inode, (None, ""))[0]
                if pid:
                    pids.add(pid)
    return pids


_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash"}
_NET_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet", "nc.openbsd", "nc.traditional"}
_INTERPRETERS = ("python", "perl", "ruby", "php", "lua", "tclsh", "node")
_NET_DAEMONS = {
    "nginx", "apache2", "httpd", "php-fpm", "lighttpd", "caddy", "node", "java",
    "mysqld", "mariadbd", "postgres", "redis-server", "memcached", "mongod",
    "tomcat", "gunicorn", "uwsgi", "vsftpd", "proftpd", "smbd", "dovecot",
    "master", "exim4", "sendmail", "named", "jenkins",
}


# --- Behavioral: service daemon spawned an interactive shell / network tool ----
def check_process_ancestry():
    """A shell / netcat / interpreter whose ancestry runs back to a network-facing
    daemon is the structural signature of web/service RCE or a reverse shell -
    independent of any command string. A corroborating factor (untrusted binary,
    a live external socket, or a raw network tool) is required to suppress the
    benign 'service legitimately calls a helper script' case."""
    tbl = _proc_table()
    ext_pids = _pids_with_external_conn()
    for pid, info in tbl.items():
        c = (info["comm"] or "").lower()
        shellish = c in _SHELLS or c in _NET_TOOLS or any(c.startswith(i) for i in _INTERPRETERS)
        if not shellish:
            continue
        anc, daemon, depth = info["ppid"], None, 0
        while anc and anc in tbl and depth < 8:
            ac = (tbl[anc]["comm"] or "").lower()
            if ac in _NET_DAEMONS:
                daemon = (anc, tbl[anc]["comm"])
                break
            anc, depth = tbl[anc]["ppid"], depth + 1
        if not daemon:
            continue
        factors = []
        if info["deleted"] or (info["exe"] and info["exe"].startswith(IMPLANT_DIRS)):
            factors.append("untrusted binary")
        if pid in ext_pids:
            factors.append("live external socket")
        if c in _NET_TOOLS:
            factors.append(f"raw network tool ({c})")
        if not factors:
            continue
        add("High", "Service-Spawned Shell", f"PID: {pid} ({info['comm']})",
            f"{info['comm']} descends from network daemon {daemon[1]} (PID {daemon[0]}) "
            f"[{', '.join(factors)}] - service RCE / reverse shell. cmd={info['cmd'][:120]}",
            "T1059.004 (Unix Shell), T1505.003 (Web Shell)")


# --- Behavioral: process name does not match its real executable ---------------
def check_masquerade():
    """Real kernel threads have no exe link; a process presenting a bracketed
    '[kworker]'-style name while owning a userland binary is name-spoofing to
    hide. A comm that disagrees with its exe basename only matters when the exe
    sits in an untrusted (writable/deleted) path - otherwise it is just an
    interpreter/symlink and noise."""
    for pid in proc_pids():
        cm = comm(pid)
        raw = exe_of(pid)
        if cm.startswith("[") and cm.endswith("]"):
            if raw:  # kernel threads cannot have an exe - this one does
                add("High", "Fake Kernel Thread", f"PID: {pid}",
                    f"Process presents kernel-thread name '{cm}' but has a userland binary "
                    f"{raw} - masquerade to evade process review. cmd={cmdline(pid)[:120]}",
                    "T1036.004 (Masquerade Task or Service), T1014 (Rootkit)")
            continue
        if not raw:
            continue
        clean = raw[:-10] if raw.endswith(" (deleted)") else raw
        base = os.path.basename(clean)
        untrusted = raw.endswith(" (deleted)") or clean.startswith(IMPLANT_DIRS)
        if cm and base and untrusted and not (base.startswith(cm[:15]) or cm[:15] in base):
            add("Medium", "Process Name Mismatch", f"PID: {pid}",
                f"Reported name '{cm}' does not match executable '{base}' running from an "
                f"untrusted path ({clean}) - argv[0]/PR_SET_NAME spoofing.",
                "T1036 (Masquerading)")


# --- Behavioral: open handle to a credential store or raw memory ---------------
_TRUSTED_CRED_EXES = (
    "/usr/sbin/sshd", "/usr/bin/sudo", "/usr/bin/su", "/bin/su", "/usr/bin/login",
    "/bin/login", "/usr/sbin/unix_chkpwd", "/usr/sbin/cron", "/usr/sbin/crond",
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/sbin/vipw", "/usr/sbin/nscd",
    "/usr/sbin/sssd", "/usr/libexec/", "/usr/lib/systemd/", "/lib/systemd/",
    "/usr/sbin/dovecot", "/usr/lib/dovecot/", "/usr/bin/systemd",
)


def check_credential_access():
    """A process holding an open descriptor to /etc/shadow, raw kernel/physical
    memory (/proc/kcore, /dev/mem), or another task's /proc/<pid>/mem - while not
    being a known authentication component - is actively touching secrets. This
    catches credential dumpers regardless of how they are named or packed."""
    self_pid = str(os.getpid())
    other_mem = re.compile(r"^/proc/(\d+)/mem$")
    for pid in proc_pids():
        if pid == self_pid:
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except Exception:
            continue
        raw = exe_of(pid) or ""
        clean = raw[:-10] if raw.endswith(" (deleted)") else raw
        if any(clean.startswith(t) for t in _TRUSTED_CRED_EXES):
            continue
        for fd in fds:
            try:
                tgt = os.readlink(f"/proc/{pid}/fd/{fd}")
            except Exception:
                continue
            hit = None
            if tgt in ("/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"):
                hit = tgt
            elif tgt.startswith(("/dev/mem", "/dev/kmem", "/proc/kcore")):
                hit = tgt
            else:
                mm = other_mem.match(tgt)
                if mm and mm.group(1) != pid:
                    hit = tgt
            if hit:
                add("High", "Credential/Memory Access", f"PID: {pid} ({comm(pid)})",
                    f"Holds an open handle to {hit} but is not a known auth component "
                    f"(exe={clean or 'unknown'}) - credential dumping / memory scraping. "
                    f"cmd={cmdline(pid)[:100]}",
                    "T1003 (OS Credential Dumping), T1003.008 (/etc/shadow)")
                break


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
        check_accounts, check_shell_init, check_authorized_keys, check_pam_modules,
        check_webshells, check_memfd,
        check_hidden_modules, check_capabilities,
        check_network, check_magic_mismatch, check_log_tampering,
        check_privileged_task_integrity, check_persistence_extended,
        check_gtfobins_exec, check_cred_access,
        check_process_ancestry, check_masquerade, check_credential_access,
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
