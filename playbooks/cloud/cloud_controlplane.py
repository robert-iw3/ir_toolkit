#!/usr/bin/env python3
"""
cloud_controlplane.py - behavioral analysis of the raw provider audit logs (AWS
CloudTrail, GCP Cloud Audit, Azure Activity, Entra sign-ins). This is where the
attacker's actual API-level TTPs live - IAM privilege escalation, defense evasion,
public exposure, account-takeover sign-ins - as opposed to the provider-native
detectors in cloud_detectors.py. Each rule maps an event to an ATT&CK technique and a
verdict on the shared ladder.
"""
import json

from cloud_findings import finding

# AWS CloudTrail: IAM privilege-escalation / account-manipulation API calls.
AWS_IAM_PRIVESC = {
    "CreateAccessKey":         "T1098.001 (Account Manipulation: Additional Cloud Credentials)",
    "CreateLoginProfile":      "T1098 (Account Manipulation)",
    "UpdateLoginProfile":      "T1098 (Account Manipulation)",
    "AttachUserPolicy":        "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "AttachRolePolicy":        "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "AttachGroupPolicy":       "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "PutUserPolicy":           "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "PutRolePolicy":           "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "PutGroupPolicy":          "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "AddUserToGroup":          "T1098 (Account Manipulation)",
    "CreatePolicyVersion":     "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "SetDefaultPolicyVersion": "T1098.003 (Account Manipulation: Additional Cloud Roles)",
    "UpdateAssumeRolePolicy":  "T1098 (Account Manipulation)",
    "CreateUser":              "T1136.003 (Create Account: Cloud Account)",
    "CreateServiceLinkedRole": "T1098 (Account Manipulation)",
}
# Event names that are themselves the attack payload (no target/admin check needed).
AWS_PRIVESC_INHERENTLY_BAD = {"CreateAccessKey", "CreateLoginProfile", "CreateUser"}
# AWS CloudTrail: cloud-log / detector tampering (highest-signal defense evasion).
AWS_DEFENSE_EVASION = {
    "StopLogging":                 "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "DeleteTrail":                 "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "UpdateTrail":                 "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "PutEventSelectors":           "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "DeleteFlowLogs":              "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "DeleteDetector":              "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "DisassociateMembers":         "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
    "StopConfigurationRecorder":   "T1562.001 (Impair Defenses: Disable or Modify Tools)",
    "DeleteConfigurationRecorder": "T1562.001 (Impair Defenses: Disable or Modify Tools)",
}

# GCP Cloud Audit methodName substrings -> (description, ATT&CK, verdict, severity).
GCP_AUDIT_RULES = [
    ("CreateServiceAccountKey", "user-managed service-account key created (credential persistence)",
     "T1098.001 (Account Manipulation: Additional Cloud Credentials)", "Likely True Positive", "High"),
    ("DeleteSink", "Cloud Logging sink deleted (cloud-log tampering)",
     "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)", "Likely True Positive", "High"),
    ("ConfigServiceV2.DeleteBucket", "Cloud Logging bucket deleted (cloud-log tampering)",
     "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)", "Likely True Positive", "High"),
    ("CreateServiceAccount", "service account created",
     "T1136.003 (Create Account: Cloud Account)", "Indeterminate", "Low"),
    ("compute.instances.setMetadata", "instance metadata/startup-script modified (persistence/execution)",
     "T1059 (Command and Scripting Interpreter)", "Indeterminate", "Low"),
    ("CreateFunction", "Cloud Function created (serverless persistence/execution)",
     "T1648 (Serverless Execution)", "Indeterminate", "Low"),
]

# Entra sign-in clientAppUsed values that are legacy/basic auth - these bypass MFA and
# Conditional Access, so a *successful* one is a strong account-takeover signal.
LEGACY_AUTH_CLIENTS = {
    "other clients", "imap4", "imap", "pop3", "pop", "smtp", "authenticated smtp", "mapi",
    "exchange activesync", "exchange web services", "autodiscover", "offline address book",
    "exchange online powershell", "reporting web services",
}

# Azure Activity operationName (lower-cased) -> (description, ATT&CK, verdict, severity).
AZURE_ACTIVITY_RULES = {
    "microsoft.insights/diagnosticsettings/delete":
        ("diagnostic settings deleted (cloud-log tampering)",
         "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)", "Likely True Positive", "High"),
    "microsoft.compute/virtualmachines/runcommand/action":
        ("VM Run Command executed (remote execution)",
         "T1059 (Command and Scripting Interpreter)", "Indeterminate", "Low"),
    "microsoft.compute/virtualmachines/extensions/write":
        ("VM extension written (Custom Script Extension = remote execution/persistence)",
         "T1059 (Command and Scripting Interpreter)", "Indeterminate", "Low"),
    "microsoft.authorization/roleassignments/write":
        ("role assignment created (privilege grant)",
         "T1098.003 (Account Manipulation: Additional Cloud Roles)", "Indeterminate", "Low"),
}


def _ct_events(data):
    """Yield parsed CloudTrail event records from either lookup-events output
    ({"Events":[{"CloudTrailEvent":"<json string>", ...}]}) or a raw record list."""
    if isinstance(data, dict):
        events = data.get("Events") or data.get("Records") or []
    elif isinstance(data, list):
        events = data
    else:
        events = []
    for e in events if isinstance(events, list) else []:
        if not isinstance(e, dict):
            continue
        cte = e.get("CloudTrailEvent")
        if isinstance(cte, str):
            try:
                yield json.loads(cte)
                continue
            except Exception:
                pass
        yield e


def _get(rec, *names):
    """Case-insensitive field fetch across CloudTrail's mixed casing."""
    if not isinstance(rec, dict):
        return None
    for n in names:
        if n in rec:
            return rec[n]
    low = {k.lower(): v for k, v in rec.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return None


def _sg_opens_admin_port(params):
    """True if an AuthorizeSecurityGroupIngress request opens SSH (22) or RDP (3389),
    including ranges that span them and the all-ports (-1 / 0-65535) case."""
    if not isinstance(params, dict):
        return False
    perms = (params.get("ipPermissions") or {})
    items = perms.get("items") if isinstance(perms, dict) else perms
    for perm in items if isinstance(items, list) else []:
        if not isinstance(perm, dict):
            continue
        proto = str(perm.get("ipProtocol", ""))
        frm, to = perm.get("fromPort"), perm.get("toPort")
        if proto in ("-1", "all") or frm is None or to is None:
            return True   # all protocols/ports exposed
        try:
            lo, hi = int(frm), int(to)
        except (TypeError, ValueError):
            continue
        if lo <= 22 <= hi or lo <= 3389 <= hi:
            return True
    return False


def normalize_cloudtrail(data):
    """AWS CloudTrail management events -> findings (IAM privesc, root use, console
    login without MFA, cloud-log tampering, snapshot/AMI sharing, public exposure)."""
    out = []
    for rec in _ct_events(data):
        name = _get(rec, "eventName") or ""
        if not name:
            continue
        src_ip = _get(rec, "sourceIPAddress") or "?"
        uid = _get(rec, "userIdentity") or {}
        actor = "unknown"
        if isinstance(uid, dict):
            actor = (uid.get("userName") or uid.get("arn") or uid.get("principalId")
                     or _get(rec, "Username") or "unknown")
        err = _get(rec, "errorCode")
        params = _get(rec, "requestParameters") or {}
        # Whitespace-free so substring checks ("group":"all" etc.) are spacing-agnostic.
        params_blob = json.dumps(params, separators=(",", ":")).lower() if params else ""

        # Cloud-log / detector tampering - fire even on partial success (highest signal).
        if name in AWS_DEFENSE_EVASION and not err:
            out.append(finding(
                "Cloud Control-Plane Activity", name,
                f"CloudTrail: {name} by {actor} from {src_ip} - disabling cloud logging/detection",
                AWS_DEFENSE_EVASION[name], "Likely True Positive", "High"))
            continue

        # Root-account API usage (root should never be used for day-to-day actions).
        if isinstance(uid, dict) and str(uid.get("type", "")).lower() == "root" and not err \
                and name not in ("ConsoleLogin",):
            out.append(finding(
                "Cloud Control-Plane Activity", f"root:{name}",
                f"CloudTrail: root-account action {name} from {src_ip}",
                "T1078.004 (Valid Accounts: Cloud Accounts)", "Likely True Positive", "High"))
            continue

        # Console login without MFA (successful interactive logon, no second factor).
        if name == "ConsoleLogin":
            aed = _get(rec, "additionalEventData") or {}
            resp = _get(rec, "responseElements") or {}
            success = str((resp or {}).get("ConsoleLogin", "")).lower() == "success"
            mfa = str((aed or {}).get("MFAUsed", "")).lower()
            is_root = isinstance(uid, dict) and str(uid.get("type", "")).lower() == "root"
            if success and mfa == "no":
                out.append(finding(
                    "Cloud Control-Plane Activity", actor,
                    f"CloudTrail: console login WITHOUT MFA by {actor} from {src_ip}"
                    f"{' (ROOT)' if is_root else ''}",
                    "T1078.004 (Valid Accounts: Cloud Accounts)", "Likely True Positive", "High"))
            continue

        if err:   # remaining rules consider only successful API calls
            continue

        # IAM privilege escalation / account manipulation.
        if name in AWS_IAM_PRIVESC:
            tgt = actor
            if isinstance(params, dict):
                tgt = params.get("userName") or params.get("roleName") \
                    or params.get("groupName") or actor
            admin = "admin" in params_blob or "administratoraccess" in params_blob
            inherently = name in AWS_PRIVESC_INHERENTLY_BAD
            verdict = "Likely True Positive" if (admin or inherently) else "Indeterminate"
            out.append(finding(
                "Cloud Control-Plane Activity", f"{name}:{tgt}",
                f"CloudTrail: {name} by {actor} from {src_ip} targeting {tgt}"
                f"{' (admin policy)' if admin else ''}",
                AWS_IAM_PRIVESC[name], verdict,
                "High" if verdict.startswith("Likely") else "Low"))
            continue

        # Snapshot / AMI shared outside the account (data staging for exfiltration).
        if name in ("ModifySnapshotAttribute", "ModifyImageAttribute"):
            public = '"group":"all"' in params_blob or '"groups":["all"]' in params_blob
            external = '"userid"' in params_blob
            if public or external:
                where = "publicly" if public else "to an external account"
                out.append(finding(
                    "Cloud Control-Plane Activity", name,
                    f"CloudTrail: {name} by {actor} shares a snapshot/AMI {where} "
                    f"(data staging for exfiltration)",
                    "T1537 (Transfer Data to Cloud Account)", "Likely True Positive", "High"))
            continue

        # Bucket policy / ACL opened to the public.
        if name in ("PutBucketPolicy", "PutBucketAcl"):
            if "allusers" in params_blob or '"principal":"*"' in params_blob \
                    or '"aws":"*"' in params_blob:
                bucket = params.get("bucketName") if isinstance(params, dict) else None
                out.append(finding(
                    "Cloud Exposure", bucket or name,
                    f"CloudTrail: {name} by {actor} grants public access to S3 bucket "
                    f"{bucket or '(unknown)'}",
                    "T1530 (Data from Cloud Storage)", "Likely True Positive", "High"))
            continue

        # Security-group ingress opened to the internet.
        if name == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in params_blob:
            admin_port = _sg_opens_admin_port(params)
            verdict = "Likely True Positive" if admin_port else "Indeterminate"
            out.append(finding(
                "Cloud Exposure", name,
                f"CloudTrail: {name} by {actor} opens a security group to 0.0.0.0/0"
                f"{' on an admin port (SSH/RDP)' if admin_port else ''}",
                "T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)", verdict,
                "High" if admin_port else "Low"))
            continue
    return out


def normalize_gcp_audit(data):
    """GCP Cloud Audit Logs -> findings (SA-key creation, public IAM bindings,
    log-sink tampering, world-open firewall, startup-script/metadata persistence)."""
    out = []
    entries = data if isinstance(data, list) else (data or {}).get("entries", []) \
        if isinstance(data, dict) else []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        proto = entry.get("protoPayload", entry) if isinstance(entry, dict) else {}
        method = str((proto or {}).get("methodName", "")) if isinstance(proto, dict) else ""
        if not method:
            continue
        auth = (proto or {}).get("authenticationInfo", {}) if isinstance(proto, dict) else {}
        actor = (auth or {}).get("principalEmail", "unknown") if isinstance(auth, dict) else "unknown"
        resource = (proto or {}).get("resourceName", "") if isinstance(proto, dict) else ""
        blob = json.dumps(entry).lower()

        # IAM policy set to a public/all-principals member, or to an external party.
        if method.endswith("SetIamPolicy") or method.endswith("setIamPolicy"):
            if "allusers" in blob or "allauthenticatedusers" in blob:
                out.append(finding(
                    "Cloud Exposure", resource or "iam-policy",
                    f"GCP: {actor} set an IAM policy granting access to allUsers/"
                    f"allAuthenticatedUsers on {resource or 'a resource'} (public exposure)",
                    "T1530 (Data from Cloud Storage)", "Likely True Positive", "High"))
            continue

        for needle, desc, mitre, verdict, sev in GCP_AUDIT_RULES:
            if needle.lower() in method.lower():
                out.append(finding(
                    "Cloud Control-Plane Activity", method.rsplit(".", 1)[-1],
                    f"GCP: {actor} - {desc} ({method})",
                    mitre, verdict, "High" if verdict.startswith("Likely") else "Low",
                    severity=sev))
                break
        else:
            # Firewall rule inserted allowing ingress from anywhere.
            if "firewalls.insert" in method.lower() and "0.0.0.0/0" in blob:
                out.append(finding(
                    "Cloud Exposure", method.rsplit(".", 1)[-1],
                    f"GCP: {actor} created a firewall rule allowing 0.0.0.0/0 ({method})",
                    "T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)",
                    "Indeterminate", "Low"))
    return out


def normalize_azure_activity(data):
    """Azure Activity Log -> findings (diagnostic-settings deletion, NSG rule opened to
    the internet, role assignment, Run Command / extension execution)."""
    out = []
    events = data if isinstance(data, list) else (data or {}).get("value", []) \
        if isinstance(data, dict) else []
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        op = ev.get("operationName", {})
        op_name = (op.get("value") if isinstance(op, dict) else op) or ""
        op_name = str(op_name).lower()
        if not op_name:
            continue
        status = ev.get("status", {})
        status_val = str((status.get("value") if isinstance(status, dict) else status) or "")
        # Activity log emits Started/Accepted/Succeeded/Failed per operation; only the
        # successful terminal state is a confirmed action (and avoids per-op duplicates).
        if status_val and status_val.lower() not in ("succeeded", "success"):
            continue
        actor = ev.get("caller") or "unknown"
        blob = json.dumps(ev).lower()

        # NSG security rule written allowing inbound from the internet.
        if op_name == "microsoft.network/networksecuritygroups/securityrules/write":
            world = "0.0.0.0/0" in blob or '"*"' in blob or "internet" in blob
            inbound_allow = "inbound" in blob and "allow" in blob
            if world and inbound_allow:
                out.append(finding(
                    "Cloud Exposure", ev.get("resourceId", op_name),
                    f"Azure: {actor} wrote an NSG rule allowing inbound from the internet",
                    "T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)",
                    "Likely True Positive", "High"))
            continue

        rule = AZURE_ACTIVITY_RULES.get(op_name)
        if rule:
            desc, mitre, verdict, sev = rule
            out.append(finding(
                "Cloud Control-Plane Activity", ev.get("resourceId", op_name),
                f"Azure: {actor} - {desc}",
                mitre, verdict, "High" if verdict.startswith("Likely") else "Low",
                severity=sev))
    return out


def normalize_signins(data):
    """Entra sign-in logs -> findings (legacy-auth that bypasses MFA, atypical travel,
    failed-then-successful sign-ins indicating a successful password spray/brute force)."""
    out = []
    records = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    if not isinstance(records, list):
        return out
    succ_countries = {}   # user -> {country}
    succ_ips = {}         # user -> {ip}
    fail_ips = {}         # user -> {ip}
    for r in records:
        if not isinstance(r, dict):
            continue
        user = r.get("userPrincipalName") or r.get("userDisplayName") or "unknown-user"
        ip = r.get("ipAddress") or "?"
        status = r.get("status", {}) if isinstance(r.get("status"), dict) else {}
        success = str(status.get("errorCode", 0)) in ("0", "")
        client = str(r.get("clientAppUsed", "")).strip().lower()
        loc = r.get("location", {}) if isinstance(r.get("location"), dict) else {}
        country = str(loc.get("countryOrRegion", "")).strip()

        if success and client in LEGACY_AUTH_CLIENTS:
            out.append(finding(
                "Cloud Sign-In", user,
                f"Successful legacy-auth sign-in ({r.get('clientAppUsed')}) by {user} from {ip} "
                f"- bypasses MFA / Conditional Access",
                "T1078.004 (Valid Accounts: Cloud Accounts)", "Likely True Positive", "High"))
        if success:
            if country:
                succ_countries.setdefault(user, set()).add(country)
            succ_ips.setdefault(user, set()).add(ip)
        else:
            fail_ips.setdefault(user, set()).add(ip)

    for user, countries in succ_countries.items():
        if len(countries) > 1:
            out.append(finding(
                "Cloud Sign-In", user,
                f"Successful sign-ins from multiple countries ({', '.join(sorted(countries))}) "
                f"for {user} - atypical travel (verify against VPN/legitimate travel)",
                "T1078 (Valid Accounts)", "Indeterminate", "Low"))
    for user, fips in fail_ips.items():
        overlap = fips & succ_ips.get(user, set())
        if overlap:
            out.append(finding(
                "Cloud Sign-In", user,
                f"Failed sign-ins followed by a success from the same IP(s) "
                f"{', '.join(sorted(overlap))} for {user} - brute force / spray then access",
                "T1110 (Brute Force)", "Likely True Positive", "High"))
    return out
