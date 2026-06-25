#!/usr/bin/env python3
"""
adjudicate.py - Linux finding adjudication + evidence acquisition.

Consumes Combined_Findings_<stamp>.json, enriches every finding with on-host
context, assigns a Verdict + Confidence, and acquires Evidence/ bundles for
true-positive-class findings.

The trust anchor is **package ownership + integrity**: a binary owned by a distro
package (dpkg/rpm) and verified unmodified, living in a trusted system path, is
treated as trusted. Unowned binaries, modified packaged files, and binaries in
writable locations lose that trust and are weighted toward true-positive.

Verdict ladder:
    False Positive < Likely False Positive < Indeterminate < Likely True Positive

Usage: adjudicate.py --host-folder DIR --report COMBINED.json [--stamp STAMP]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

TRUSTED_PATHS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/",
                 "/lib/", "/usr/libexec/", "/lib64/", "/usr/lib64/")
WRITABLE_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/home/")
VERDICT_RANK = {"False Positive": 0, "Likely False Positive": 1,
                "Indeterminate": 2, "Likely True Positive": 3, "True Positive": 4}


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception:
        return None


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def read(path, binary=False):
    try:
        with (open(path, "rb") if binary else open(path, "r", errors="replace")) as fh:
            return fh.read()
    except Exception:
        return None


def proc_field(pid, key):
    st = read(f"/proc/{pid}/status")
    if not st:
        return None
    for ln in st.splitlines():
        if ln.startswith(key + ":"):
            return ln.split(":", 1)[1].strip()
    return None


# --- package ownership / integrity: the trust anchor (distro-agnostic) --------
# Probes whichever package manager is present: dpkg (Debian/Ubuntu), rpm
# (RHEL/Fedora/SUSE), pacman (Arch), apk (Alpine).
def pkg_owner(path):
    if not path or not os.path.exists(path):
        return None
    if shutil.which("dpkg"):
        r = run(["dpkg", "-S", path])
        if r and r.returncode == 0 and ":" in r.stdout:
            return r.stdout.split(":", 1)[0].strip()
    if shutil.which("rpm"):
        r = run(["rpm", "-qf", path])
        if r and r.returncode == 0 and "not owned" not in r.stdout:
            return r.stdout.strip()
    if shutil.which("pacman"):
        r = run(["pacman", "-Qo", path])
        if r and r.returncode == 0 and "owned by" in r.stdout:
            return r.stdout.strip().split("owned by", 1)[1].strip()
    if shutil.which("apk"):
        r = run(["apk", "info", "--who-owns", path])
        if r and r.returncode == 0 and "owned by" in r.stdout:
            return r.stdout.strip().split("owned by", 1)[1].strip()
    return None


def pkg_modified(path, owner):
    """True if the package manager reports the on-disk file was altered."""
    if not owner:
        return None
    if shutil.which("debsums"):
        r = run(["debsums", "-s", path])
        if r is not None:
            return bool(r.stdout.strip() or r.returncode != 0)
    if shutil.which("rpm"):
        r = run(["rpm", "-Vf", path])
        if r is not None and r.stdout.strip():
            # a '5' in the verify flags means the file's checksum differs
            return any(re.match(r"^\S*5", ln) for ln in r.stdout.splitlines())
    if shutil.which("pacman"):
        r = run(["pacman", "-Qkk", path])
        if r is not None and r.stdout.strip():
            return "FAILED" in r.stdout or "modification" in r.stdout.lower()
    return None


def path_trust(path):
    if not path:
        return "Unknown"
    if any(path.startswith(p) for p in WRITABLE_PATHS):
        return "Writable-Location"
    if any(path.startswith(p) for p in TRUSTED_PATHS):
        return "Trusted-Location"
    return "Other"


# --- subject resolution -------------------------------------------------------
PID_RE = re.compile(r"(?:PID:?\s*|pid[ =]|\(PID\s*)(\d+)", re.I)


def resolve_subject(finding):
    """Return (subject_path, pid) for a finding from its Target/Details."""
    target = finding.get("Target", "") or ""
    details = finding.get("Details", "") or ""
    pid = None
    m = PID_RE.search(target) or PID_RE.search(details)
    if m:
        pid = m.group(1)
    # explicit filesystem path in Target?
    if target.startswith("/") and os.path.lexists(target.split()[0]):
        return target.split()[0], pid
    if pid:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            return (exe[:-10] if exe.endswith(" (deleted)") else exe), pid
        except Exception:
            return None, pid
    # path mentioned in details (e.g. "...path: /tmp/x")
    m2 = re.search(r"(/[\w./\-]+)", target) or re.search(r"exe=(/[\w./\-]+)", details)
    if m2:
        cand = m2.group(1)
        if os.path.lexists(cand):
            return cand, pid
    return None, pid


def enrich(finding):
    path, pid = resolve_subject(finding)
    e = dict(finding)
    e["SubjectPath"] = path
    e["Pid"] = pid
    e["FileExists"] = bool(path and os.path.exists(path))
    e["PathTrust"] = path_trust(path)
    owner = pkg_owner(path) if e["FileExists"] else None
    e["PkgOwner"] = owner
    e["PkgModified"] = pkg_modified(path, owner) if owner else None
    e["SHA256"] = sha256(path) if e["FileExists"] else None
    if pid and os.path.isdir(f"/proc/{pid}"):
        raw = read(f"/proc/{pid}/cmdline", binary=True)
        e["CommandLine"] = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip() if raw else None
        uid_line = proc_field(pid, "Uid")
        e["Owner"] = uid_line.split()[0] if uid_line else None
        ppid = proc_field(pid, "PPid")
        e["ParentPid"] = ppid
        e["ParentName"] = (read(f"/proc/{ppid}/comm") or "").strip() if ppid else None
    return e


# --- verdict logic ------------------------------------------------------------
# Base disposition per finding type, then adjusted by path trust + pkg ownership.
ALWAYS_TP = {"Reverse Shell", "Suspicious Kernel Module", "Library Preload Hijack",
             "Webshell", "Unauthorized UID0 Account", "Empty Password Account",
             "Hidden Kernel Module", "Memory-Only Executable (memfd)", "Crypto Miner"}
HUMAN_REVIEW = {"SSH Authorized Key", "SSH Config Weakness", "Listening Service",
                "Anonymous Exec Memory", "Deleted Running Binary", "Process Preload",
                "External Connection"}


def adjudicate(e):
    ftype = e.get("Type", "")
    trust = e.get("PathTrust")
    owned = bool(e.get("PkgOwner"))
    modified = e.get("PkgModified")
    writable = trust == "Writable-Location"

    # Tampered packaged binary is a strong signal regardless of type.
    if owned and modified:
        return "Likely True Positive", "High", "Package-owned binary modified on disk (integrity fail)."

    if ftype in ALWAYS_TP:
        return "Likely True Positive", "High", f"{ftype} is high-fidelity on Linux."

    if ftype == "Remote Access Tool":
        relay = re.search(r"relay=([\w.\-]+)", e.get("Details", "") or "")
        if relay or writable:
            return "Likely True Positive", "High", "RMM with custom relay / untrusted path (unsanctioned)."
        return "Indeterminate", "Medium", "RMM present; confirm whether IT-sanctioned."

    if ftype == "Hidden Process":
        if owned and trust == "Trusted-Location" and not modified:
            return "Likely False Positive", "Medium", "Hidden-from-listing but packaged & unmodified (likely scan race/daemon)."
        return "Likely True Positive", "High", "Hidden process not backed by a trusted package."

    if ftype in ("Execution From Writable Path", "High Entropy ELF",
                 "Unexpected SUID Binary", "Dangerous File Capability"):
        if writable and not owned:
            return "Likely True Positive", "High" if ftype != "High Entropy ELF" else "Medium", "Unowned binary in writable path."
        if owned and not modified:
            return "Likely False Positive", "Medium", "Packaged & unmodified."
        return "Indeterminate", "Medium", "Needs context."

    if ftype in ("Cron Persistence", "Systemd Persistence", "Shell Init Backdoor"):
        return "Likely True Positive", "Medium", "Persistence with suspicious payload."

    if ftype in HUMAN_REVIEW:
        return "Indeterminate", "Low", "Requires analyst confirmation."

    if ftype in ("Hunt Error", "Triage Error"):
        return "Indeterminate", "Low", "Collector error, not a detection."

    return "Indeterminate", "Low", "Unclassified finding type."


# --- evidence bundles ---------------------------------------------------------
def acquire_evidence(e, idx, evidence_root):
    safe_type = re.sub(r"\W+", "_", e.get("Type", "finding"))
    name = f"{idx:03d}_{safe_type}"
    bdir = os.path.join(evidence_root, name)
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, "evidence.json"), "w") as fh:
        json.dump(e, fh, indent=2)
    path = e.get("SubjectPath")
    if path and os.path.isfile(path):
        try:
            shutil.copy2(path, os.path.join(bdir, "subject_" + os.path.basename(path)))
        except Exception:
            pass
    pid = e.get("Pid")
    if pid and os.path.isdir(f"/proc/{pid}"):
        for art in ("maps", "status", "cmdline"):
            data = read(f"/proc/{pid}/{art}", binary=True)
            if data:
                with open(os.path.join(bdir, f"pid_{pid}_{art}.txt"), "wb") as fh:
                    fh.write(data)
    return name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-folder", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--min-verdict", default="Likely True Positive",
                    help="acquire evidence for findings at or above this verdict")
    args = ap.parse_args()

    raw = read(args.report)
    if raw is None:
        print(f"[adjudicate] cannot read {args.report}", file=sys.stderr)
        return 1
    # tolerate a UTF-8 BOM on the merged input
    findings = json.loads(raw.lstrip("﻿"))
    if isinstance(findings, dict):
        findings = [findings]

    evidence_root = os.path.join(args.host_folder, "Evidence")
    min_rank = VERDICT_RANK.get(args.min_verdict, 3)
    results = []
    idx = 0
    for f in findings:
        e = enrich(f)
        verdict, conf, rationale = adjudicate(e)
        e["Verdict"] = verdict
        e["Confidence"] = conf
        e["Rationale"] = rationale
        if VERDICT_RANK.get(verdict, 0) >= min_rank:
            idx += 1
            e["EvidenceBundle"] = acquire_evidence(e, idx, evidence_root)
        results.append(e)

    out_json = os.path.join(args.host_folder, f"Adjudication_{args.stamp}.json")
    with open(out_json, "w") as fh:
        json.dump(results, fh, indent=2)

    counts = Counter(r["Verdict"] for r in results)
    out_md = os.path.join(args.host_folder, f"Adjudication_{args.stamp}.md")
    with open(out_md, "w") as fh:
        fh.write(f"# Adjudication summary ({args.stamp})\n\n")
        fh.write(f"Total findings: **{len(results)}**\n\n| Verdict | Count |\n|---|---:|\n")
        for v in sorted(counts, key=lambda k: -VERDICT_RANK.get(k, 0)):
            fh.write(f"| {v} | {counts[v]} |\n")
        tps = [r for r in results if VERDICT_RANK.get(r["Verdict"], 0) >= 3]
        if tps:
            fh.write("\n## True-positive-class\n\n| Type | Target | Conf | Subject | Pkg |\n|---|---|---|---|---|\n")
            for r in tps:
                fh.write(f"| {r['Type']} | {r['Target']} | {r['Confidence']} | "
                         f"{r.get('SubjectPath') or '-'} | {r.get('PkgOwner') or 'UNOWNED'} |\n")

    print(f"[adjudicate] {len(results)} finding(s): "
          f"{', '.join(f'{k}={v}' for k, v in counts.most_common())}")
    print(f"[adjudicate] evidence bundles: {idx} -> {evidence_root}")
    print(out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
