#!/usr/bin/env python3
"""
principal_reachability.py - blast-radius mapping for a compromised cloud principal.

Containment answers "how do we stop them"; this answers "what could they touch". Given
the implicated principals (from Principals.json or --principals) and the collected
telemetry, it assembles, per principal:

  * roles_held       - GCP IAM roles bound to the principal (privileged ones flagged)
  * observed_actions - the API calls the principal actually made (from CloudTrail)
  * related_findings - adjudicated findings attributable to the principal, with the
                       strongest verdict among them

This feeds the report's "what could they reach" section and prioritises which principals
to contain first. Pure functions (blast_radius / reachability_markdown) are unit-tested;
the CLI writes Blast_Radius_<stamp>.{json,md} into the host folder.
"""
import argparse
import glob
import json
import os
import sys
import time

from cloud_findings import VERDICT_RANK, read_json
from cloud_controlplane import _ct_events, _get

PRIVILEGED_ROLE_MARKERS = ("owner", "editor", "admin", "iam.securityadmin",
                           "iam.serviceaccountadmin", "resourcemanager")


def _gcp_roles_for(policy, principal):
    """Roles a principal holds in a GCP get-iam-policy document (member match)."""
    roles = []
    bindings = (policy or {}).get("bindings", []) if isinstance(policy, dict) else []
    for b in bindings if isinstance(bindings, list) else []:
        if not isinstance(b, dict):
            continue
        members = b.get("members", []) or []
        if any(principal == m or principal in m for m in members):
            roles.append(b.get("role", "unknown-role"))
    return sorted(set(roles))


def _aws_actions_for(cloudtrail, principal):
    """The eventSource:eventName pairs a principal invoked, from CloudTrail records."""
    actions = set()
    for rec in _ct_events(cloudtrail):
        uid = _get(rec, "userIdentity") or {}
        actor = ""
        if isinstance(uid, dict):
            actor = str(uid.get("userName") or uid.get("arn") or uid.get("principalId") or "")
        if actor and principal in actor:
            src = str(_get(rec, "eventSource") or "").split(".")[0]
            name = _get(rec, "eventName") or ""
            if name:
                actions.add(f"{src}:{name}" if src else name)
    return sorted(actions)


def blast_radius(forensics_dir, principals, findings=None):
    """Assemble the reachability rows for each principal. Pure over its inputs."""
    policy = read_json(os.path.join(forensics_dir, "gcp_iam_policy.json"))
    cloudtrail = read_json(os.path.join(forensics_dir, "cloudtrail_events.json"))
    findings = findings or []
    rank_to_verdict = {v: k for k, v in VERDICT_RANK.items()}
    rows = []
    for p in principals:
        p = (p or "").strip()
        if not p:
            continue
        roles = _gcp_roles_for(policy, p)
        privileged = [r for r in roles
                      if any(m in r.lower() for m in PRIVILEGED_ROLE_MARKERS)]
        actions = _aws_actions_for(cloudtrail, p)
        related = [f for f in findings
                   if p in (str(f.get("Target", "")) + " " + str(f.get("Details", "")))]
        top = max((VERDICT_RANK.get(f.get("Verdict"), 0) for f in related), default=None)
        rows.append({
            "principal": p,
            "roles_held": roles,
            "privileged_roles": privileged,
            "observed_actions": actions,
            "related_finding_count": len(related),
            "max_related_verdict": rank_to_verdict.get(top) if top is not None else None,
        })
    return rows


def reachability_markdown(rows):
    out = ["# Cloud Blast Radius (principal reachability)", ""]
    if not rows:
        out.append("_No implicated principals to map._\n")
        return "\n".join(out)
    out += ["| Principal | Roles held | Privileged | Observed actions | Related findings (max verdict) |",
            "|---|---|---|---|---|"]
    for r in rows:
        out.append(
            f"| `{r['principal']}` | {', '.join(r['roles_held']) or '-'} "
            f"| {', '.join(r['privileged_roles']) or '-'} "
            f"| {len(r['observed_actions'])} ({', '.join(r['observed_actions'][:6]) or '-'}) "
            f"| {r['related_finding_count']} ({r['max_related_verdict'] or '-'}) |")
    return "\n".join(out) + "\n"


def _principals_from_file(host_folder):
    data = read_json(os.path.join(host_folder, "Principals.json"))
    return [p.get("name") for p in (data or {}).get("principals", [])
            if isinstance(p, dict) and p.get("name")]


def _latest_findings(host_folder):
    hits = sorted(glob.glob(os.path.join(host_folder, "Combined_Findings_*.json")),
                  key=os.path.getmtime, reverse=True)
    return read_json(hits[0]) if hits else []


def main(argv=None):
    p = argparse.ArgumentParser(description="Map the blast radius of compromised principals.")
    p.add_argument("--host-folder", required=True)
    p.add_argument("--principals", default="", help="comma-separated; default reads Principals.json")
    p.add_argument("--incident-id", default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    principals = [x for x in args.principals.split(",") if x.strip()] \
        or _principals_from_file(args.host_folder)
    forensics_dir = os.path.join(args.host_folder, "cloud_forensics")
    if not os.path.isdir(forensics_dir):
        forensics_dir = args.host_folder
    rows = blast_radius(forensics_dir, principals, _latest_findings(args.host_folder) or [])

    stamp = time.strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(args.host_folder, f"Blast_Radius_{stamp}.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    with open(os.path.join(args.host_folder, f"Blast_Radius_{stamp}.md"), "w", encoding="utf-8") as fh:
        fh.write(reachability_markdown(rows))
    if not args.quiet:
        print(f"[+] blast radius mapped for {len(rows)} principal(s) -> Blast_Radius_{stamp}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
