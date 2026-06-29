#!/usr/bin/env python3
"""
cloud_identity.py - Entra / M365 identity-attack analysis: illicit OAuth consent
grants, business-email-compromise inbox rules, and the high-impact Entra directory
audit events. Identity is the cloud perimeter; these are the persistence + collection
moves that survive a password reset.
"""
from cloud_findings import finding

# OAuth/Graph delegated scopes that grant mailbox/file/tenant reach - the payload of
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
    "update application - certificates and secrets management": ("T1098.001 (Account Manipulation: Additional Cloud Credentials)", "High"),
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
        out.append(finding(
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
        out.append(finding(
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
        out.append(finding(
            "Cloud Identity Audit", ev.get("activityDisplayName", name),
            f"Entra directory audit: '{ev.get('activityDisplayName', name)}' by {actor}",
            mitre, verdict, "High" if sev == "High" else "Low", severity=sev))
    return out
