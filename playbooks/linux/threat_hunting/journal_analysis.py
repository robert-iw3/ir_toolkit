#!/usr/bin/env python3
"""
journal_analysis.py - Linux systemd-journal / syslog -> findings engine.

The Linux analog of the Windows Invoke-EventLogAnalysis.ps1. The forensics phase
collects the journal raw; nothing turned it into adjudicable findings. This reads a
`journalctl -o json` export (one JSON object per line) and emits findings in the
common schema so they merge into Combined_Findings_<stamp>.json:

    {Timestamp, Severity, Type, Target, Details, MITRE}

Closes the collection gaps the retrospective flagged on the Linux side:
  Credential Access   - SSH brute force (repeated "Failed password")
  Lateral Movement    - remote root logon, accepted-after-brute-force
  Privilege Escalation- sudo auth failures / NOT-in-sudoers / shell via sudo
  Persistence         - new account/group, service or cron in a writable path
  Defense Evasion     - journal vacuum, auditd stop, SELinux/AppArmor disabled,
                        out-of-tree/unsigned kernel module
  Execution           - reverse-shell one-liners in the journal text

Also collects package-manager transactions (dpkg/apt, pacman, rpm) as
"Package Manager Transaction" findings. These are not suspicious on their own
(Info severity, never scored as a detection) -- they exist so the
investigation engine can check whether a "deleted running binary" or
"modified package file" finding coincides with a real install/upgrade/remove
event for that exact package, closing deleted_binary.py's "verify with
journalctl/package-manager log for an upgrade window" lead with an actual
matching transaction instead of a trusted-path assumption alone.

Read-only. Degrades gracefully: unparseable lines are skipped, never fatal.

Usage:
    journal_analysis.py [--report-dir DIR] [--stamp YYYYmmdd_HHMMSS]
                        [--input FILE] [--live] [--window-seconds N]
                        [--brute-threshold N] [--quiet]

  --input FILE   read journald JSON from FILE (one object per line). Default:
                 <report-dir>/forensics/journal.json if present.
  --live         run `journalctl -o json --no-pager` and analyze its output.
Writes Journal_Findings_<stamp>.json (list of findings) and prints the path.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

# ── tunables (overridable on the CLI) ────────────────────────────────────────
DEFAULT_WINDOW_SECONDS = 120      # brute-force time window
DEFAULT_BRUTE_THRESHOLD = 5       # failed SSH logons per source in the window
MAX_FINDINGS = 500                # safety cap so a noisy journal can't explode output

# Pure implant dirs: legitimate services/cron almost never execute from here, so ANY
# reference is worth surfacing.
IMPLANT_RE = re.compile(r"(?:^|[\s=\"'(,:])(/tmp/|/var/tmp/|/dev/shm/)")
# Runtime dirs (/run, /var/run) DO hold legitimate state (/run/user/<uid>, /run/systemd,
# /run/lock). Do NOT blanket-match them - that floods on benign systemd units. Flag only
# when an attacker payload is implied: a hidden file, or a script/binary under the runtime
# dir. This keeps /run/var-run as a real detection surface (attackers use tmpfs) WITHOUT
# the noise - no blindspot, just precision.
RUNTIME_RE = re.compile(
    r"(?:/run/|/var/run/)\S*?(?:/\.[\w.-]+|\.(?:sh|bash|py|pl|rb|elf|bin|so|ko|out))\b")
# Download-to-interpreter cradle: curl/wget/fetch piped or chained into a shell/interpreter
# (the classic `curl http://x | bash` payload pull). Bare curl/wget is NOT matched here -
# that's a C2-beacon question for network analysis, not a cron-text signal.
DOWNLOAD_CRADLE_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n|;&]*[|;&]+\s*(?:[\w/]*sh|bash|python[0-9.]*|perl|ruby|php)\b",
    re.IGNORECASE)


def suspicious_path(text):
    """True if text references a likely implant payload location."""
    return bool(IMPLANT_RE.search(text) or RUNTIME_RE.search(text))
# Reverse-shell / dual-use one-liners.
REVSHELL_RE = re.compile(
    r"(bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|socat\b|"
    r"python[0-9.]*\s+-c\s+['\"]?import\s+socket|sh\s+-i\b|mkfifo\b.*\bnc\b)",
    re.IGNORECASE)
# RMM / remote-access service names.
RMM_RE = re.compile(
    r"(teamviewer|anydesk|screenconnect|connectwise|splashtop|ngrok|rustdesk|"
    r"meshagent|atera|datto|gotoassist|remoteutilities|tailscale)", re.IGNORECASE)
IPV4_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── record normalization ─────────────────────────────────────────────────────
def _ts(rec):
    """journald __REALTIME_TIMESTAMP is microseconds since epoch (string)."""
    raw = rec.get("__REALTIME_TIMESTAMP")
    try:
        return int(raw) / 1_000_000.0
    except (TypeError, ValueError):
        return None


def _ts_human(rec):
    t = _ts(rec)
    if t is None:
        return rec.get("__REALTIME_TIMESTAMP") or now()
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")


def _ident(rec):
    return (rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "").lower()


def _msg(rec):
    m = rec.get("MESSAGE")
    if isinstance(m, list):          # journald can encode binary MESSAGE as int list
        try:
            m = bytes(m).decode("utf-8", "replace")
        except Exception:
            m = str(m)
    return m or ""


def parse_journal_text(text):
    """Parse `journalctl -o json` output (one JSON object per line) -> [dict]."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except (ValueError, json.JSONDecodeError):
            continue
    return records


# ── detection core (pure: records -> findings) ───────────────────────────────
def analyze(records, window_seconds=DEFAULT_WINDOW_SECONDS,
            brute_threshold=DEFAULT_BRUTE_THRESHOLD):
    """Return a list of finding dicts. Pure function - unit-testable in isolation."""
    findings = []

    def add(severity, ftype, target, details, mitre):
        if len(findings) < MAX_FINDINGS:
            findings.append({
                "Timestamp": now(),
                "Severity": severity,
                "Type": ftype,
                "Target": target,
                "Details": details,
                "MITRE": mitre,
            })

    ssh_fail = []           # (timestamp, src_ip, raw_msg) for brute-force windowing
    ssh_accept_root = []    # successful root logons
    kmod_events = {}        # module-key -> {"count", "first_when", "msg"} (deduped)

    for rec in records:
        ident = _ident(rec)
        msg = _msg(rec)
        when = _ts_human(rec)
        t = _ts(rec)

        # ── SSH credential access / remote logon ─────────────────────────────
        if "sshd" in ident:
            if "Failed password" in msg or "Failed publickey" in msg or \
               "Invalid user" in msg or "authentication failure" in msg:
                ip = IPV4_RE.search(msg)
                ssh_fail.append((t, ip.group(1) if ip else "unknown", msg))
            m = re.search(r"Accepted (?:password|publickey|keyboard-interactive\S*) "
                          r"for (\S+)", msg)
            if m:
                user = m.group(1)
                ip = IPV4_RE.search(msg)
                src = ip.group(1) if ip else "unknown"
                if user == "root":
                    ssh_accept_root.append((t, src))
                    add("High", "Remote Root Logon",
                        f"sshd @ {when}",
                        f"Successful SSH logon as root from {src}: {msg.strip()}",
                        "T1021.004 (Remote Services: SSH), T1078.003 (Valid Accounts: Local)")

        # ── sudo privilege escalation ────────────────────────────────────────
        if "sudo" in ident:
            if "authentication failure" in msg or "incorrect password attempt" in msg:
                add("Medium", "Sudo Authentication Failure",
                    f"sudo @ {when}", msg.strip(),
                    "T1548.003 (Abuse Elevation Control: Sudo)")
            elif "NOT in sudoers" in msg or "user NOT in" in msg:
                add("High", "Unauthorized Sudo Attempt",
                    f"sudo @ {when}", msg.strip(),
                    "T1548.003 (Abuse Elevation Control: Sudo)")
            else:
                cmd = re.search(r"COMMAND=(.+)$", msg)
                if cmd and (suspicious_path(cmd.group(1)) or
                            re.search(r"/(?:ba)?sh\b|python|perl|nc\b|ncat\b",
                                      cmd.group(1))):
                    add("High", "Suspicious Sudo Command",
                        f"sudo @ {when}",
                        f"sudo invoked an interpreter/shell or writable-path binary: "
                        f"{cmd.group(1).strip()}",
                        "T1548.003 (Abuse Elevation Control: Sudo), T1059.004 (Unix Shell)")

        # ── new account / group (persistence) ────────────────────────────────
        if ident in ("useradd", "groupadd", "usermod") or \
           any(k in msg for k in ("new user:", "new group:", "new account")):
            if "new user" in msg or "new group" in msg or "new account" in msg or \
               ident in ("useradd", "groupadd"):
                add("High", "New Account Created",
                    f"{ident or 'accounts'} @ {when}", msg.strip(),
                    "T1136.001 (Create Account: Local Account)")

        # ── systemd service in a writable path or RMM (persistence) ──────────
        if "systemd" in ident and ("Started" in msg or "Starting" in msg or
                                    "Installed" in msg):
            if suspicious_path(msg):
                add("High", "Suspicious Service Execution",
                    f"systemd @ {when}",
                    f"systemd started a unit referencing a writable path: {msg.strip()}",
                    "T1543.002 (Create or Modify System Process: systemd Service)")
            elif RMM_RE.search(msg):
                add("Medium", "Remote-Access Service",
                    f"systemd @ {when}",
                    f"systemd started a remote-access/RMM service: {msg.strip()}",
                    "T1219 (Remote Access Software)")

        # ── cron job from a writable path / network one-liner (persistence) ──
        if ident in ("cron", "crond", "cronie") or "cron" in ident:
            # Real cron-persistence techniques: payload in an implant dir, a download
            # cradle (curl|bash), or a reverse-shell one-liner. Bare curl/wget is left to
            # network/C2 analysis so legitimate cron jobs don't flood the report.
            if suspicious_path(msg) or DOWNLOAD_CRADLE_RE.search(msg) or \
               REVSHELL_RE.search(msg):
                add("High", "Suspicious Cron Job",
                    f"cron @ {when}", msg.strip(),
                    "T1053.003 (Scheduled Task/Job: Cron)")

        # ── reverse-shell / dual-use execution anywhere in the journal ───────
        if REVSHELL_RE.search(msg):
            add("High", "Reverse Shell Indicator",
                f"{ident or 'journal'} @ {when}",
                f"Reverse-shell / network one-liner in journal: {msg.strip()}",
                "T1059.004 (Unix Shell), T1071 (Application Layer Protocol)")

        # ── defense evasion: log / audit / MAC tampering ─────────────────────
        if ("journal" in ident and ("vacuum" in msg.lower())) or "--vacuum" in msg:
            add("High", "Journal Log Truncation",
                f"{ident or 'journald'} @ {when}",
                f"systemd journal vacuumed/truncated: {msg.strip()}",
                "T1070.002 (Indicator Removal: Clear Linux System Logs)")
        if "audit" in ident or "auditd" in ident:
            if "audit daemon is exiting" in msg or re.search(r"audit.*enabled=0", msg):
                add("High", "Audit Logging Disabled",
                    f"{ident} @ {when}", msg.strip(),
                    "T1562.001 (Impair Defenses: Disable or Modify Tools)")
        # Explicit MAC-disable events. NOTE: "unconfined" is intentionally NOT matched -
        # `profile="unconfined"` appears in routine AppArmor audit records (100s/host) and
        # is not a disable event. "apparmor ... disabled/unloaded" IS a real tamper signal.
        if re.search(r"SELinux:\s*Disabled", msg) or "enforcing=0" in msg or \
           "setenforce 0" in msg or "apparmor=0" in msg or \
           re.search(r"apparmor.*(?:disabled by boot|module is unloaded)", msg, re.I):
            add("High", "Mandatory Access Control Disabled",
                f"{ident or 'kernel'} @ {when}",
                f"SELinux/AppArmor enforcement disabled: {msg.strip()}",
                "T1562.001 (Impair Defenses: Disable or Modify Tools)")

        # ── rootkit / unsigned kernel module (persistence / evasion) ─────────
        # Deduped per module below: a driver re-loaded every boot must not produce
        # N identical findings (observed: nvidia x12 on a workstation).
        if "kernel" in ident:
            if "module verification failed" in msg or "loading out-of-tree module" in msg \
               or (re.search(r"taint", msg, re.IGNORECASE) and "module" in msg.lower()):
                lead = re.match(r"([\w-]+):", msg)
                key = lead.group(1) if lead else msg.strip()[:80]
                ev = kmod_events.setdefault(
                    key, {"count": 0, "first_when": when, "msg": msg.strip()})
                ev["count"] += 1

    # ── SSH brute force: threshold per source IP within the window ───────────
    by_ip = {}
    for t, ip, msg in ssh_fail:
        by_ip.setdefault(ip, []).append(t)
    for ip, times in by_ip.items():
        known = sorted(x for x in times if x is not None)
        # If timestamps are present, require threshold within a sliding window;
        # otherwise fall back to a raw count (export may lack __REALTIME_TIMESTAMP).
        burst = False
        if len(known) >= brute_threshold:
            for i in range(len(known) - brute_threshold + 1):
                if known[i + brute_threshold - 1] - known[i] <= window_seconds:
                    burst = True
                    break
        elif not known and len(times) >= brute_threshold:
            burst = True
        if burst or (not known and len(times) >= brute_threshold):
            sev = "High"
            # Escalate if a successful root logon followed the burst from same IP.
            if any(src == ip for _, src in ssh_accept_root):
                sev = "Critical"
            add(sev, "SSH Brute Force",
                f"sshd source {ip}",
                f"{len(times)} failed SSH logons from {ip}"
                f"{' followed by a successful root logon' if sev == 'Critical' else ''} "
                f"(threshold {brute_threshold}/{window_seconds}s).",
                "T1110 (Brute Force)")

    # ── unsigned / out-of-tree kernel modules: one finding per unique module ─
    for key, ev in kmod_events.items():
        suffix = f" (x{ev['count']} loads)" if ev["count"] > 1 else ""
        add("Medium", "Unsigned Kernel Module",
            f"kernel module {key}",
            f"{ev['msg']}{suffix}",
            "T1547.006 (Boot or Logon Autostart: Kernel Modules), T1014 (Rootkit)")

    return findings


# ── package-manager transaction collection ──────────────────────────────────
# dpkg.log format: "TIMESTAMP ACTION pkg:arch old_ver [new_ver]"
_DPKG_LOG_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'(?P<action>install|upgrade|remove|purge) '
    r'(?P<pkg>[^:\s]+)(?::\S+)? (?P<ver1>\S+)(?: (?P<ver2>\S+))?$')
# pacman.log format: "[2026-07-06T10:15:23+0000] [ALPM] upgraded openssl (1.1.1k-1 -> 1.1.1l-1)"
_PACMAN_LOG_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\] \[ALPM\] '
    r'(?P<action>installed|upgraded|removed|reinstalled) (?P<pkg>\S+) \((?P<ver>[^)]+)\)$')
DEFAULT_DPKG_LOG = "/var/log/dpkg.log"
DEFAULT_PACMAN_LOG = "/var/log/pacman.log"


def _normalize_pkg_name(name):
    """Strip a dpkg :arch suffix or a trailing version token so a package
    name from any source (log line, PkgOwner resolution) compares equal."""
    return (name or "").split(":", 1)[0].split()[0] if name else ""


def parse_dpkg_log(text):
    """dpkg.log install/upgrade/remove/purge lines -> [{ts, epoch, action, pkg, version}]."""
    out = []
    for line in (text or "").splitlines():
        m = _DPKG_LOG_RE.match(line.strip())
        if not m:
            continue
        try:
            epoch = datetime.datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            continue
        version = m.group("ver2") or m.group("ver1")
        out.append({"ts": m.group("ts"), "epoch": epoch, "action": m.group("action"),
                    "pkg": _normalize_pkg_name(m.group("pkg")), "version": version})
    return out


def parse_pacman_log(text):
    """pacman.log installed/upgraded/removed/reinstalled lines -> same shape as parse_dpkg_log."""
    out = []
    for line in (text or "").splitlines():
        m = _PACMAN_LOG_RE.match(line.strip())
        if not m:
            continue
        # pacman's ISO-8601 timestamp: "2026-07-06T10:15:23+0000" (colon-less offset).
        raw_ts = m.group("ts")
        try:
            epoch = datetime.datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except ValueError:
            continue
        out.append({"ts": raw_ts, "epoch": epoch, "action": m.group("action"),
                    "pkg": _normalize_pkg_name(m.group("pkg")), "version": m.group("ver")})
    return out


def rpm_installed_events(runner=None):
    """Every currently-installed RPM's last install/upgrade time, via the RPM
    database itself rather than a log file (RHEL/Fedora/SUSE rotate/omit
    dnf.log far more aggressively than dpkg/pacman keep their own logs, but
    the database's installtime survives as long as the package is installed).
    Returns the same shape as parse_dpkg_log. Best-effort: absent rpm binary
    or any query failure -> empty list, never fatal."""
    run = runner or (lambda cmd: subprocess.run(
        cmd, capture_output=True, text=True, timeout=60, check=False))
    out = []
    try:
        cp = run(["rpm", "-qa", "--qf", "%{name}\t%{installtime}\t%{version}-%{release}\n"])
    except (OSError, subprocess.SubprocessError):
        return out
    if not cp or cp.returncode != 0:
        return out
    for line in (cp.stdout or "").splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 3:
            continue
        name, raw_epoch, version = parts
        try:
            epoch = float(raw_epoch)
        except ValueError:
            continue
        out.append({"ts": datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S"),
                    "epoch": epoch, "action": "install_or_upgrade",
                    "pkg": _normalize_pkg_name(name), "version": version})
    return out


def collect_package_events(dpkg_log=DEFAULT_DPKG_LOG, pacman_log=DEFAULT_PACMAN_LOG,
                           since_days=30, use_rpm=True, runner=None):
    """Read every available package manager's transaction history and return
    common-schema findings (Type='Package Manager Transaction', Info
    severity -- context for the investigation engine, never a detection on
    its own). Missing logs / absent package managers are silently skipped,
    matching this module's read-only, never-fatal contract."""
    events = []
    if os.path.isfile(dpkg_log):
        try:
            with open(dpkg_log, "r", encoding="utf-8", errors="replace") as fh:
                events.extend(parse_dpkg_log(fh.read()))
        except OSError:
            pass
    if os.path.isfile(pacman_log):
        try:
            with open(pacman_log, "r", encoding="utf-8", errors="replace") as fh:
                events.extend(parse_pacman_log(fh.read()))
        except OSError:
            pass
    if use_rpm:
        events.extend(rpm_installed_events(runner=runner))

    cutoff = datetime.datetime.now().timestamp() - since_days * 86400
    events = [e for e in events if e["epoch"] >= cutoff]

    out = []
    for e in events[:MAX_FINDINGS]:
        out.append({
            "Timestamp": now(), "Severity": "Info", "Type": "Package Manager Transaction",
            "Target": f"package {e['pkg']}",
            "Details": f"{e['action']} {e['pkg']} {e['version']} at {e['ts']}",
            "MITRE": "N/A",
        })
    return out


# ── input acquisition ────────────────────────────────────────────────────────
def read_input(args):
    """Return raw journald JSON text from --input, default forensics file, or --live."""
    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as e:
            print(f"[journal] cannot read --input {args.input}: {e}", file=sys.stderr)
            return ""
    default = os.path.join(args.report_dir, "forensics", "journal.json")
    if not args.live and os.path.isfile(default):
        with open(default, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    # Live capture (best effort; absent/permission-denied -> empty, never fatal).
    # BOUNDED: the full journal can be gigabytes and time out. Constrain by time
    # window (--since) and a hard line cap (-n) so the dump stays fast and finite,
    # mirroring how the Windows analyzer reads bounded event CSVs.
    try:
        cp = subprocess.run(
            ["journalctl", "-o", "json", "--no-pager",
             "--since", args.since, "-n", str(args.max_lines)],
            capture_output=True, text=True, timeout=180, check=False)
        return cp.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[journal] journalctl unavailable: {e}", file=sys.stderr)
        return ""


def main():
    ap = argparse.ArgumentParser(description="Linux journal -> findings")
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp",
                    default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--input", help="journald JSON export (one object per line)")
    ap.add_argument("--live", action="store_true",
                    help="run journalctl -o json instead of reading a file")
    ap.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    ap.add_argument("--brute-threshold", type=int, default=DEFAULT_BRUTE_THRESHOLD)
    ap.add_argument("--since", default="7 days ago",
                    help="live capture lookback window (journalctl --since). "
                         "Bounds the dump so it can't hang on a huge journal.")
    ap.add_argument("--max-lines", type=int, default=200000,
                    help="live capture hard line cap (journalctl -n).")
    ap.add_argument("--no-pkg-events", action="store_true",
                    help="skip package-manager transaction collection")
    ap.add_argument("--pkg-since-days", type=int, default=30,
                    help="package-manager transaction lookback window in days")
    ap.add_argument("--dpkg-log", default=DEFAULT_DPKG_LOG)
    ap.add_argument("--pacman-log", default=DEFAULT_PACMAN_LOG)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    text = read_input(args)
    records = parse_journal_text(text)
    findings = analyze(records, window_seconds=args.window_seconds,
                       brute_threshold=args.brute_threshold)
    if not args.no_pkg_events:
        findings.extend(collect_package_events(
            dpkg_log=args.dpkg_log, pacman_log=args.pacman_log,
            since_days=args.pkg_since_days))

    out_path = os.path.join(args.report_dir, f"Journal_Findings_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    if not args.quiet:
        from collections import Counter
        sev = Counter(f["Severity"] for f in findings)
        print(f"[journal] {len(records)} record(s) -> {len(findings)} finding(s) "
              f"{dict(sev)}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
