#!/usr/bin/env python3
"""
extract_principals.py — identify the accounts/identities an incident implicates.

Emitted in the ANALYSIS stage (like IOCs.json) so eradication can revoke
credentials/sessions for the right principals without re-deriving them. A confirmed
hands-on intrusion means the accounts used on the host must be assumed exposed; this
turns the manual "rotate credentials" note into a machine-readable target list.

A principal is auto-revocable unless it is a built-in/system account or the
responder — those are flagged for review, never auto-disabled.

Output Principals.json:
    {incident_id, hostname, generated_utc,
     principals:[{name, domain, type, source, auto_revoke, reason}]}
  type: local | domain | iam | service_account | ssh | cloud-identity

Usage: extract_principals.py --host-folder DIR [--incident-id ID]
"""
import argparse
import os
import re
import sys

import generate_reports as gr

# Built-in accounts that must never be auto-disabled (host would be bricked / is noise).
PROTECTED = {
    "system", "local service", "network service", "administrator", "guest",
    "defaultaccount", "wdagutilityaccount", "trustedinstaller", "root", "daemon",
    "bin", "sys", "nobody", "sshd", "_apt", "messagebus", "syslog",
}
TP_CLASS = ("True Positive", "Likely True Positive")


def _split_owner(owner):
    """'DOMAIN\\user' or 'user@domain' -> (domain, user)."""
    owner = owner.strip()
    if "\\" in owner:
        d, u = owner.split("\\", 1)
        return d.strip(), u.strip()
    if "@" in owner:
        u, d = owner.split("@", 1)
        return d.strip(), u.strip()
    return "", owner


def _classify(raw, domain, user, finding_type, host):
    ft = (finding_type or "").lower()
    is_cloud = bool(re.search(r"cloud|identity|iam", ft))
    if "@" in str(raw) and "." in str(raw).split("@")[-1]:
        return "cloud-identity", str(raw).strip(), ""     # full UPN/email
    if is_cloud:
        return "iam", user, ""
    if domain and domain.lower() == host.lower():
        return "local", user, domain                       # DOMAIN == hostname -> local
    if domain and domain.upper() not in ("NT AUTHORITY", "BUILTIN", ".", "WORKGROUP"):
        return "domain", user, domain
    return "local", user, domain


def extract(findings, host=""):
    """Return a de-duplicated list of implicated-principal dicts from TP findings."""
    seen, principals = {}, []
    for f in findings:
        if gr.get(f, "Verdict") not in TP_CLASS:
            continue
        ftype = gr.get(f, "Type")
        candidates = []
        for fld in ("Owner", "User", "UserName", "Account", "Principal"):
            v = gr.get(f, fld)
            if v:
                candidates.append(v)
        if re.search(r"(?i)identity|iam|account|cloud detection", ftype) and gr.get(f, "Target"):
            candidates.append(gr.get(f, "Target"))

        for raw in candidates:
            domain, user = _split_owner(str(raw))
            if not user or user.lower() in ("", "-"):
                continue
            ptype, name, dom = _classify(raw, domain, user, ftype, host)
            key = (dom.lower(), name.lower())
            if key in seen:
                continue
            protected = name.lower() in PROTECTED
            principals.append({
                "name": name, "domain": dom, "type": ptype,
                "source": ftype,
                "auto_revoke": (not protected),
                "reason": "built-in/system account — review only" if protected
                          else "implicated by a true-positive finding",
            })
            seen[key] = True
    return principals


def emit(host_folder, incident_id=None):
    if not os.path.isdir(host_folder):
        raise SystemExit(f"host folder not found: {host_folder}")
    _, host, findings = gr.load_model(host_folder)
    import datetime
    import json
    data = {
        "incident_id": incident_id or host,
        "hostname": host,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "principals": extract(findings, host),
    }
    path = os.path.join(host_folder, "Principals.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path, data


def main(argv=None):
    p = argparse.ArgumentParser(description="Emit Principals.json (analysis stage).")
    p.add_argument("--host-folder", required=True)
    p.add_argument("--incident-id", default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    path, data = emit(args.host_folder, args.incident_id)
    if not args.quiet:
        auto = sum(1 for x in data["principals"] if x["auto_revoke"])
        print(f"[+] {path}  ({len(data['principals'])} principal(s), {auto} auto-revocable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
