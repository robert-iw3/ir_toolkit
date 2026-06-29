#!/usr/bin/env python3
"""
cloud_iam.py - point-in-time AWS/GCP IAM posture analysis. Where cloud_controlplane.py
adjudicates IAM *events* (the attacker minting a key), this reads the *state* the
investigation lands in: console users without MFA, stale/long-lived access keys, a root
key, externally-reachable resources, public IAM bindings, and user-managed service-account
keys. These bound the blast radius and surface the persistence an attacker may already
have left behind.
"""
import base64
import csv
import datetime
import io

from cloud_findings import finding

STALE_KEY_DAYS = 90


def _age_days(iso):
    """Days between an ISO-8601 timestamp and now (UTC); None if unparseable/NA."""
    if not iso or str(iso).upper() in ("N/A", "NO_INFORMATION", "NOT_SUPPORTED", ""):
        return None
    try:
        s = str(iso).replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return (datetime.datetime.now(datetime.timezone.utc) - dt).days
    except Exception:
        return None


def normalize_iam_credential_report(data):
    """AWS IAM credential report (get-credential-report, base64 CSV) -> posture findings:
    root account with an active key, console users without MFA, stale active access keys."""
    out = []
    content = (data or {}).get("Content") if isinstance(data, dict) else None
    if not content:
        return out
    try:
        text = base64.b64decode(content).decode("utf-8", "replace")
        rows = list(csv.DictReader(io.StringIO(text)))
    except Exception:
        return out
    for row in rows:
        user = row.get("user", "")
        is_root = user == "<root_account>"
        mfa = str(row.get("mfa_active", "")).lower() == "true"
        pw_enabled = str(row.get("password_enabled", "")).lower() == "true"

        if is_root:
            if str(row.get("access_key_1_active", "")).lower() == "true" \
                    or str(row.get("access_key_2_active", "")).lower() == "true":
                out.append(finding(
                    "Cloud IAM Posture", "<root_account>",
                    "Root account has an active access key - root keys should not exist; "
                    "high-value standing credential.",
                    "T1078.004 (Valid Accounts: Cloud Accounts)", "Likely True Positive", "High"))
            if not mfa:
                out.append(finding(
                    "Cloud IAM Posture", "<root_account>",
                    "Root account has MFA disabled.",
                    "T1078.004 (Valid Accounts: Cloud Accounts)", "Likely True Positive", "High"))
            continue

        if pw_enabled and not mfa:
            out.append(finding(
                "Cloud IAM Posture", user,
                f"IAM user '{user}' has console access without MFA - weak standing credential.",
                "T1078.004 (Valid Accounts: Cloud Accounts)", "Indeterminate", "Medium",
                severity="Medium"))

        for n in ("1", "2"):
            if str(row.get(f"access_key_{n}_active", "")).lower() != "true":
                continue
            age = _age_days(row.get(f"access_key_{n}_last_rotated"))
            if age is not None and age > STALE_KEY_DAYS:
                out.append(finding(
                    "Cloud IAM Posture", f"{user}:key{n}",
                    f"IAM user '{user}' access key {n} is active and {age} days old "
                    f"(>{STALE_KEY_DAYS}d without rotation).",
                    "T1078.004 (Valid Accounts: Cloud Accounts)", "Indeterminate", "Low"))
    return out


def normalize_access_analyzer(data):
    """AWS IAM Access Analyzer findings -> external-exposure findings."""
    out = []
    findings = (data or {}).get("findings", []) if isinstance(data, dict) else (data or [])
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict) or str(f.get("status", "ACTIVE")).upper() != "ACTIVE":
            continue
        res = f.get("resource") or f.get("resourceType") or "resource"
        is_public = bool(f.get("isPublic"))
        verdict = "Likely True Positive" if is_public else "Indeterminate"
        out.append(finding(
            "Cloud Exposure", res,
            f"Access Analyzer: {res} is reachable by an external principal "
            f"{f.get('principal', '')}{' (PUBLIC)' if is_public else ''}".strip(),
            "T1530 (Data from Cloud Storage)", verdict,
            "High" if is_public else "Low", severity="High" if is_public else "Medium"))
    return out


def normalize_gcp_iam_policy(data):
    """GCP project IAM policy (get-iam-policy) -> public-binding exposure findings."""
    out = []
    bindings = (data or {}).get("bindings", []) if isinstance(data, dict) else []
    for b in bindings if isinstance(bindings, list) else []:
        if not isinstance(b, dict):
            continue
        role = b.get("role", "unknown-role")
        public = [m for m in b.get("members", [])
                  if m in ("allUsers", "allAuthenticatedUsers")]
        if public:
            out.append(finding(
                "Cloud Exposure", role,
                f"GCP IAM binding grants {role} to {', '.join(public)} (public access).",
                "T1530 (Data from Cloud Storage)", "Likely True Positive", "High"))
    return out


def normalize_gcp_sa_keys(data):
    """GCP service-account key inventory -> user-managed-key persistence-risk findings.

    User-managed SA keys are long-lived credentials that survive most cleanup; flag each,
    noting age for the older ones.
    """
    out = []
    keys = (data or {}).get("keys", []) if isinstance(data, dict) else (data or [])
    for k in keys if isinstance(keys, list) else []:
        if not isinstance(k, dict) or str(k.get("keyType", "")).upper() != "USER_MANAGED":
            continue
        sa = k.get("serviceAccount") or k.get("name", "service-account")
        age = _age_days(k.get("validAfterTime"))
        age_txt = f" ({age} days old)" if age is not None else ""
        out.append(finding(
            "Cloud IAM Posture", sa,
            f"User-managed service-account key on {sa}{age_txt} - long-lived credential / "
            f"persistence risk; prefer short-lived workload identity.",
            "T1098.001 (Account Manipulation: Additional Cloud Credentials)",
            "Indeterminate", "Low"))
    return out
