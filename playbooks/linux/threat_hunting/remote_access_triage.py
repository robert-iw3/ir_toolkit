#!/usr/bin/env python3
"""
remote_access_triage.py — Linux remote-access / RMM / reverse-shell triage.

Read-only. Emits findings in the common schema
{Timestamp, Severity, Type, Target, Details, MITRE}.

Covers the realistic Linux remote-access vectors:
  - RMM / remote-control agents (AnyDesk, TeamViewer, RustDesk, MeshAgent, NetSupport,
    Splashtop, DWAgent, ScreenConnect/ConnectWise, VNC, ngrok tunnels)
  - Reverse / bind shells (bash -i, /dev/tcp, nc -e, socat EXEC, python pty.spawn)
  - SSH backdoors (authorized_keys additions, risky sshd_config, active sessions)

Usage: remote_access_triage.py [--report-dir DIR] [--stamp STAMP] [--quiet]
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from collections import Counter

FINDINGS = []

# name -> (regex over process name/cmdline/path, default listening port hint)
RMM_CATALOG = {
    "AnyDesk":          (re.compile(r"\banydesk\b", re.I), "7070"),
    "TeamViewer":       (re.compile(r"\bteamviewer", re.I), "5938"),
    "RustDesk":         (re.compile(r"\brustdesk\b", re.I), "21115-21119"),
    "MeshAgent":        (re.compile(r"\bmeshagent\b", re.I), "-"),
    "NetSupport":       (re.compile(r"\bnetsupport|\bpcicl32|\bclient32\b", re.I), "-"),
    "Splashtop":        (re.compile(r"\bsplashtop|\bSRServer\b", re.I), "-"),
    "DWAgent":          (re.compile(r"\bdwagent\b", re.I), "-"),
    "ScreenConnect":    (re.compile(r"screenconnect|connectwise", re.I), "-"),
    "GoToAssist":       (re.compile(r"\bgotoassist|\bg2a\b", re.I), "-"),
    "LogMeIn":          (re.compile(r"\blogmein\b", re.I), "-"),
    "Atera":            (re.compile(r"\bateraagent|\bsyncro\b", re.I), "-"),
    "VNC":              (re.compile(r"\b(x11vnc|tigervnc|tightvnc|vncserver|Xvnc)\b", re.I), "5900"),
    "ngrok":            (re.compile(r"\bngrok\b", re.I), "-"),
}

# Reverse/bind-shell command patterns (apply to a full command line).
SHELL_PATTERNS = [
    (re.compile(r"/dev/tcp/\d", re.I), "bash /dev/tcp reverse shell"),
    (re.compile(r"\bnc\b.*\s-e\b|\bncat\b.*\s-e\b", re.I), "netcat -e shell"),
    (re.compile(r"\bsocat\b.*EXEC", re.I), "socat EXEC shell"),
    (re.compile(r"bash\s+-i\b.*(>&|>/dev/tcp)", re.I), "interactive bash redirect"),
    (re.compile(r"python[0-9.]*\s+-c.*pty\.spawn", re.I), "python pty.spawn shell"),
    (re.compile(r"perl\s+-e.*Socket", re.I), "perl socket shell"),
    (re.compile(r"\bmkfifo\b.*\|.*\bnc\b", re.I), "mkfifo+nc backdoor"),
]

WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add(sev, ftype, target, details, mitre):
    FINDINGS.append({"Timestamp": now(), "Severity": sev, "Type": ftype,
                     "Target": target, "Details": details, "MITRE": mitre})


def read_file(path, binary=False):
    try:
        if binary:
            with open(path, "rb") as fh:
                return fh.read()
        with open(path, "r", errors="replace") as fh:
            return fh.read()
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
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip() if raw else ""


def exe_of(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return None


# --- RMM / remote-control agents ---------------------------------------------
def check_rmm():
    for pid in proc_pids():
        cmd = cmdline(pid)
        ex = exe_of(pid) or ""
        hay = f"{ex} {cmd}"
        if not hay.strip():
            continue
        for tool, (rx, port) in RMM_CATALOG.items():
            if rx.search(hay):
                # Custom relay (non-vendor host) is the high-signal tell — generalize the
                # ScreenConnect h=<relay> trick: surface any host=/server=/--relay token.
                relay = ""
                m = re.search(r"(?:h=|host=|--server[= ]|server=|relay[= ])([\w.\-]+)", cmd, re.I)
                if m:
                    relay = f" relay={m.group(1)}"
                add("High", "Remote Access Tool", f"{tool} (PID {pid})",
                    f"RMM/remote-control agent running. exe={ex or 'unknown'} "
                    f"port_hint={port}{relay} cmd={cmd[:160]}",
                    "T1219 (Remote Access Software)")
                break


# --- reverse / bind shells ----------------------------------------------------
def check_shells():
    for pid in proc_pids():
        cmd = cmdline(pid)
        if not cmd:
            continue
        for rx, label in SHELL_PATTERNS:
            if rx.search(cmd):
                add("High", "Reverse Shell", f"PID: {pid}",
                    f"{label}: {cmd[:180]}", "T1059.004 (Unix Shell)")
                break


# --- SSH backdoors ------------------------------------------------------------
def check_ssh():
    # authorized_keys across root + all homes
    roots = ["/root"] + [os.path.join("/home", d) for d in (os.listdir("/home") if os.path.isdir("/home") else [])]
    for base in roots:
        ak = os.path.join(base, ".ssh", "authorized_keys")
        body = read_file(ak)
        if not body:
            continue
        keys = [l for l in body.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        for k in keys:
            sev = "Medium"
            note = ""
            # forced-command / restrictive options are benign; bare keys with odd comments less so
            if "command=" not in k and len(keys) > 0:
                note = " (no forced-command)"
            add(sev, "SSH Authorized Key", ak,
                f"authorized_keys entry{note}: ...{k.strip()[-80:]}", "T1098.004 (SSH Keys)")
    # sshd_config risky directives
    cfg = read_file("/etc/ssh/sshd_config")
    if cfg:
        for ln in cfg.splitlines():
            s = ln.strip()
            if re.match(r"(?i)PermitRootLogin\s+(yes|prohibit-password)", s):
                add("Medium", "SSH Config Weakness", "/etc/ssh/sshd_config",
                    f"{s}", "T1098 (Account Manipulation)")
            if re.match(r"(?i)(AllowTcpForwarding\s+yes|PermitTunnel\s+yes)", s):
                add("Low", "SSH Config Weakness", "/etc/ssh/sshd_config",
                    f"Tunneling enabled: {s}", "T1572 (Protocol Tunneling)")


# --- listening services on uncommon ports bound to all interfaces -------------
COMMON_PORTS = {22, 53, 80, 443, 631, 5353, 25, 587, 993, 143, 110, 3306, 5432, 6379, 111}


def check_listeners():
    out = run(["ss", "-tlpnH"]) or run(["ss", "-tlpn"])
    for ln in out.splitlines():
        m = re.search(r"\b(?:0\.0\.0\.0|\*|\[::\]):(\d+)\b", ln)
        if not m:
            continue
        port = int(m.group(1))
        if port in COMMON_PORTS or port > 49152:  # skip well-known + ephemeral
            continue
        proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', ln)
        who = f"{proc.group(1)} pid={proc.group(2)}" if proc else "unknown"
        add("Low", "Listening Service", f"port {port}",
            f"Service listening on all interfaces, uncommon port. proc={who}",
            "T1571 (Non-Standard Port)")


# --- crypto miners (process names + mining-pool command lines) ----------------
MINER_RE = re.compile(
    r"\b(xmrig|minerd|cpuminer|ccminer|cgminer|bfgminer|ethminer|nbminer|"
    r"phoenixminer|t-rex|lolminer|nanominer|kdevtmpfsi|kinsing)\b", re.I)
POOL_RE = re.compile(r"(stratum\+tcp://|--pool\b|--donate-level|pool\.|xmr\.|miningpool)", re.I)


def check_miners():
    for pid in proc_pids():
        cmd = cmdline(pid)
        ex = exe_of(pid) or ""
        hay = f"{ex} {cmd}"
        if MINER_RE.search(hay) or POOL_RE.search(cmd):
            add("High", "Crypto Miner", f"PID: {pid}",
                f"Cryptominer/mining-pool indicators. exe={ex or 'unknown'} cmd={cmd[:160]}",
                "T1496 (Resource Hijacking)")


# --- outbound C2: established connections to public IPs on uncommon ports ------
def _is_private(ip):
    return (ip.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fe80", "fc", "fd"))
            or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip) or ip in ("0.0.0.0", "*"))


def check_egress():
    out = run(["ss", "-tpnH", "state", "established"]) or run(["ss", "-tpn"])
    seen = set()
    for ln in out.splitlines():
        m = re.search(r"\s(\S+):(\d+)\s+users:\(\(\"([^\"]+)\",pid=(\d+)", ln)
        if not m:
            # fall back to peer address without process attribution
            m2 = re.search(r"\s(\d+\.\d+\.\d+\.\d+):(\d+)\s*$", ln)
            if not m2:
                continue
            peer, port = m2.group(1), int(m2.group(2))
            proc = "unknown"
        else:
            peer, port, proc = m.group(1), int(m.group(2)), f"{m.group(3)} pid={m.group(4)}"
        peer = peer.strip("[]")
        if _is_private(peer) or port in COMMON_PORTS:
            continue
        key = (peer, port)
        if key in seen:
            continue
        seen.add(key)
        add("Medium", "External Connection", f"{peer}:{port}",
            f"Established outbound connection to public host on uncommon port. proc={proc}",
            "T1071 (C2 / Application Layer Protocol)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    for ch in (check_rmm, check_shells, check_ssh, check_listeners, check_miners, check_egress):
        try:
            ch()
        except Exception as e:
            add("Info", "Triage Error", ch.__name__, str(e), "-")

    os.makedirs(args.report_dir, exist_ok=True)
    out = os.path.join(args.report_dir, f"RemoteAccess_Findings_{args.stamp}.json")
    with open(out, "w") as fh:
        json.dump(FINDINGS, fh, indent=2)
    if not args.quiet:
        sev = Counter(f["Severity"] for f in FINDINGS)
        print(f"[remote_access] {len(FINDINGS)} finding(s) "
              f"({', '.join(f'{k}:{v}' for k, v in sev.items()) or 'none'}) -> {out}")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
