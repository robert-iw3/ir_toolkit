#!/usr/bin/env python3
"""
adjudicate_cloud.py — cloud finding normalization + adjudication.

Closes the cloud "no real analysis" gap: parses the provider telemetry that
00_collect_forensics.sh wrote (AWS GuardDuty, Azure Activity/risky-users, GCP SCC)
plus any operator-supplied C2 IOCs, normalizes everything into the common finding
schema, and assigns a Verdict on the same ladder the Linux/Windows adjudicators use.

Trust model (cloud): provider-native detections (GuardDuty/SCC) with HIGH/CRITICAL
severity are true-positive class; operator-supplied C2 is true-positive class;
informational/low provider findings are indeterminate; everything else is a likely
false positive.

Usage: adjudicate_cloud.py --forensics-dir DIR --out COMBINED.json
                           [--c2-ips a,b] [--c2-domains x,y] [--provider aws]
"""
import argparse
import json
import os
import sys

VERDICT_RANK = {"False Positive": 0, "Likely False Positive": 1,
                "Indeterminate": 2, "Likely True Positive": 3, "True Positive": 4}
HIGH_SEV = {"HIGH", "CRITICAL", "SEV_HIGH", "8", "9", "10"}

# OAuth/Graph delegated scopes that grant mailbox/file/tenant reach — the payload of
# an illicit-consent-grant attack. Lower-cased for comparison.
HIGH_RISK_OAUTH_SCOPES = {
    "mail.read", "mail.readwrite", "mail.send", "mail.read.shared", "mail.readwrite.shared",
    "mailboxsettings.readwrite", "files.read.all", "files.readwrite.all",
    "sites.read.all", "sites.readwrite.all", "full_access_as_user",
    "directory.read.all", "directory.readwrite.all", "application.readwrite.all",
    "user.read.all", "group.readwrite.all", "exchange.manageasapp",
}
# Entra directory-audit operations that are persistence / privilege / defense-evasion
# moves rather than routine admin. activityDisplayName is matched case-insensitively.
SUSPICIOUS_DIRECTORY_AUDIT = {
    "add service principal credentials": ("T1098.001 (Account Manipulation: Additional Cloud Credentials)", "High"),
    "update application – certificates and secrets management": ("T1098.001 (Account Manipulation: Additional Cloud Credentials)", "High"),
    "update application - certificates and secrets management": ("T1098.001 (Account Manipulation: Additional Cloud Credentials)", "High"),
    "consent to application": ("T1528 (Steal Application Access Token)", "High"),
    "add app role assignment to service principal": ("T1098.003 (Additional Cloud Roles)", "High"),
    "add member to role": ("T1098.003 (Account Manipulation: Additional Cloud Roles)", "High"),
    "add eligible member to role": ("T1098.003 (Account Manipulation: Additional Cloud Roles)", "Medium"),
    "disable strong authentication": ("T1556.006 (Modify Authentication Process: MFA)", "High"),
    "update conditional access policy": ("T1556 (Modify Authentication Process)", "Medium"),
    "add unverified domain": ("T1484.002 (Domain Trust Modification)", "High"),
    "set domain authentication": ("T1484.002 (Domain Trust Modification)", "High"),
}


def _read(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def _sev_is_high(value):
    return str(value).upper() in HIGH_SEV or (str(value).replace(".", "").isdigit()
                                              and float(value) >= 7.0)


def _finding(ftype, target, details, mitre, verdict, confidence, severity="High"):
    return {"Type": ftype, "Target": target, "Details": details, "MITRE": mitre,
            "Severity": severity, "Verdict": verdict, "Confidence": confidence,
            "Source": "cloud"}


def normalize_guardduty(data):
    """AWS GuardDuty get-findings output -> common findings."""
    out = []
    findings = (data or {}).get("Findings", []) if isinstance(data, dict) else (data or [])
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict):
            continue
        title = f.get("Title") or f.get("Type") or "GuardDuty finding"
        sev = f.get("Severity", 0)
        verdict = "Likely True Positive" if _sev_is_high(sev) else "Indeterminate"
        out.append(_finding("Cloud Detection", title,
                            f"GuardDuty: {f.get('Description', title)}",
                            "T1078 (Valid Accounts)", verdict,
                            "High" if _sev_is_high(sev) else "Low"))
    return out


def normalize_scc(data):
    """GCP Security Command Center findings -> common findings."""
    out = []
    for item in data if isinstance(data, list) else []:
        f = item.get("finding", item) if isinstance(item, dict) else {}
        cat = f.get("category", "SCC finding")
        sev = f.get("severity", "")
        verdict = "Likely True Positive" if _sev_is_high(sev) else "Indeterminate"
        out.append(_finding("Cloud Detection", cat, f"SCC: {cat} (severity={sev})",
                            "T1078 (Valid Accounts)", verdict,
                            "High" if _sev_is_high(sev) else "Low"))
    return out


def normalize_azure_risky(data):
    """Azure Identity Protection risky users -> common findings."""
    out = []
    users = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    for u in users if isinstance(users, list) else []:
        if not isinstance(u, dict):
            continue
        level = u.get("riskLevel", "")
        verdict = "Likely True Positive" if str(level).lower() == "high" else "Indeterminate"
        out.append(_finding("Cloud Identity Risk",
                            u.get("userPrincipalName", "unknown-user"),
                            f"Entra risky user (riskLevel={level})",
                            "T1078 (Valid Accounts)", verdict,
                            "High" if verdict.startswith("Likely True") else "Low"))
    return out


def normalize_oauth_grants(data, internal_domains=None):
    """Graph oauth2PermissionGrants -> findings (illicit consent grant, T1528).

    A delegated grant carrying mailbox/file/tenant scopes is the mechanism attackers
    use to read mail or exfiltrate without a password. Tenant-wide (AllPrincipals)
    consent to such scopes is the strongest signal.
    """
    out = []
    grants = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    for g in grants if isinstance(grants, list) else []:
        if not isinstance(g, dict):
            continue
        scopes = [s for s in str(g.get("scope", "")).replace(",", " ").split() if s]
        risky = sorted({s for s in scopes if s.lower() in HIGH_RISK_OAUTH_SCOPES})
        if not risky:
            continue
        tenant_wide = str(g.get("consentType", "")).lower() == "allprincipals"
        client = g.get("clientId") or g.get("clientDisplayName") or "unknown-client"
        verdict = "Likely True Positive" if (tenant_wide or any(
            s.startswith("mail.") or s == "full_access_as_user" for s in risky)) \
            else "Indeterminate"
        out.append(_finding(
            "Cloud OAuth Consent Grant", client,
            f"OAuth grant ({'tenant-wide' if tenant_wide else 'user'}) with high-risk "
            f"scopes: {', '.join(risky)}",
            "T1528 (Steal Application Access Token), T1550.001 (Application Access Token)",
            verdict, "High" if verdict.startswith("Likely True") else "Low"))
    return out


def normalize_inbox_rules(data, internal_domains=None):
    """Graph mailbox messageRules -> findings (BEC forwarding/redirect, T1114.003).

    External auto-forward/redirect is a top business-email-compromise indicator;
    rules that also delete/move the message hide the exfiltration.
    """
    internal = {d.lower().lstrip("@") for d in (internal_domains or [])}

    def _addrs(action_val):
        res = []
        for r in action_val if isinstance(action_val, list) else []:
            ea = (r or {}).get("emailAddress", {}) if isinstance(r, dict) else {}
            if ea.get("address"):
                res.append(ea["address"])
        return res

    out = []
    rules = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    for ru in rules if isinstance(rules, list) else []:
        if not isinstance(ru, dict):
            continue
        actions = ru.get("actions", {}) if isinstance(ru.get("actions"), dict) else {}
        targets = _addrs(actions.get("forwardTo")) + _addrs(actions.get("redirectTo")) \
            + _addrs(actions.get("forwardAsAttachmentTo"))
        if not targets:
            continue
        ext = [a for a in targets if "@" in a and a.split("@")[-1].lower() not in internal]
        hides = bool(actions.get("delete") or actions.get("markAsRead")
                     or actions.get("moveToFolder"))
        # External target, or a hiding action, makes it true-positive class.
        if ext or hides:
            verdict, conf = "Likely True Positive", "High"
        else:
            verdict, conf = "Indeterminate", "Low"
        scope = "external" if ext else "internal"
        out.append(_finding(
            "Cloud Inbox Forwarding Rule",
            ru.get("displayName") or "(unnamed rule)",
            f"Mailbox rule auto-forwards/redirects to {scope} address(es): "
            f"{', '.join(targets)}{' + hides message' if hides else ''}",
            "T1114.003 (Email Collection: Email Forwarding Rule)",
            verdict, conf))
    return out


def normalize_directory_audit(data):
    """Graph auditLogs/directoryAudits -> findings (identity persistence / evasion)."""
    out = []
    events = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        name = str(ev.get("activityDisplayName", "")).strip().lower()
        hit = SUSPICIOUS_DIRECTORY_AUDIT.get(name)
        if not hit:
            continue
        mitre, sev = hit
        actor = "unknown"
        ip = ev.get("initiatedBy", {})
        if isinstance(ip, dict):
            u = ip.get("user", {}) or ip.get("app", {}) or {}
            actor = u.get("userPrincipalName") or u.get("displayName") or actor
        verdict = "Likely True Positive" if sev == "High" else "Indeterminate"
        out.append(_finding(
            "Cloud Identity Audit", ev.get("activityDisplayName", name),
            f"Entra directory audit: '{ev.get('activityDisplayName', name)}' by {actor}",
            mitre, verdict, "High" if sev == "High" else "Low", severity=sev))
    return out


def normalize_flow_logs(flow_text, c2_ips):
    """VPC/NSG/firewall flow-log evidence that a known C2 IP actually appeared in traffic.

    Format-agnostic: a C2 IP is the same string in AWS VPC Flow Logs, Azure NSG flow
    logs, and GCP VPC flow logs, so a substring match confirms communication regardless
    of provider schema. This upgrades an operator-supplied IOC from "asserted" to
    "observed on the wire."
    """
    out = []
    text = flow_text or ""
    for ip in [x.strip() for x in (c2_ips or "").split(",") if x.strip()]:
        if ip and ip in text:
            out.append(_finding(
                "Cloud Network Flow to C2", ip,
                f"Known C2 IP {ip} observed in collected VPC/NSG flow logs — confirms "
                f"network communication (not just an asserted indicator).",
                "T1071 (Application Layer Protocol)", "True Positive", "High"))
    return out


def c2_findings(c2_ips, c2_domains):
    out = []
    for ip in [x.strip() for x in (c2_ips or "").split(",") if x.strip()]:
        out.append(_finding("Cloud C2 Beacon", ip, f"Operator-supplied C2 endpoint {ip}",
                            "T1071 (Application Layer Protocol)", "True Positive", "High"))
    for d in [x.strip() for x in (c2_domains or "").split(",") if x.strip()]:
        out.append(_finding("Cloud C2 Beacon", d, f"Operator-supplied C2 domain {d}",
                            "T1071 (Application Layer Protocol)", "True Positive", "High"))
    return out


def adjudicate(forensics_dir, provider, c2_ips, c2_domains):
    findings = []
    if provider == "aws":
        findings += normalize_guardduty(_read(os.path.join(forensics_dir, "guardduty_findings.json")))
    elif provider == "gcp":
        findings += normalize_scc(_read(os.path.join(forensics_dir, "gcp_scc_findings.json")))
    elif provider == "azure":
        findings += normalize_azure_risky(_read(os.path.join(forensics_dir, "azure_risky_users.json")))
        findings += normalize_oauth_grants(_read(os.path.join(forensics_dir, "azure_oauth_grants.json")))
        findings += normalize_inbox_rules(_read(os.path.join(forensics_dir, "azure_inbox_rules.json")))
        findings += normalize_directory_audit(_read(os.path.join(forensics_dir, "azure_directory_audit.json")))
    # Flow-log C2 confirmation (provider-specific file, format-agnostic IP match).
    flow_file = {"aws": "aws_vpc_flow_logs.json", "azure": "azure_flow_logs.json",
                 "gcp": "gcp_vpc_flow_logs.json"}.get(provider)
    if flow_file:
        findings += normalize_flow_logs(_read_text(os.path.join(forensics_dir, flow_file)), c2_ips)
    findings += c2_findings(c2_ips, c2_domains)
    return findings


def main(argv=None):
    p = argparse.ArgumentParser(description="Normalize + adjudicate cloud telemetry.")
    p.add_argument("--forensics-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--provider", default="aws")
    p.add_argument("--c2-ips", default="")
    p.add_argument("--c2-domains", default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    findings = adjudicate(args.forensics_dir, args.provider, args.c2_ips, args.c2_domains)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    if not args.quiet:
        tp = sum(1 for f in findings if VERDICT_RANK[f["Verdict"]] >= 3)
        print(f"[+] {len(findings)} cloud finding(s), {tp} true-positive-class -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
