#!/usr/bin/env python3
"""
cloud_detectors.py - the provider-native detectors and operator/indicator findings:
GuardDuty, Security Command Center, Entra risky users, logging-enablement gaps,
flow-log C2 confirmation, and operator-supplied C2. These are the "told to us"
signals, as opposed to the behavioral analysis in cloud_controlplane.py.
"""
from cloud_findings import finding, sev_is_high


def normalize_guardduty(data):
    """AWS GuardDuty get-findings output -> common findings."""
    out = []
    findings = (data or {}).get("Findings", []) if isinstance(data, dict) else (data or [])
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict):
            continue
        title = f.get("Title") or f.get("Type") or "GuardDuty finding"
        sev = f.get("Severity", 0)
        verdict = "Likely True Positive" if sev_is_high(sev) else "Indeterminate"
        out.append(finding("Cloud Detection", title,
                           f"GuardDuty: {f.get('Description', title)}",
                           "T1078 (Valid Accounts)", verdict,
                           "High" if sev_is_high(sev) else "Low"))
    return out


def normalize_scc(data):
    """GCP Security Command Center findings -> common findings. Accepts a raw list or a
    {"findings":[...]} wrapper (the multi-project collector merges per-project arrays)."""
    out = []
    items = data if isinstance(data, list) else (data or {}).get("findings", []) \
        if isinstance(data, dict) else []
    for item in items if isinstance(items, list) else []:
        f = item.get("finding", item) if isinstance(item, dict) else {}
        cat = f.get("category", "SCC finding")
        sev = f.get("severity", "")
        verdict = "Likely True Positive" if sev_is_high(sev) else "Indeterminate"
        out.append(finding("Cloud Detection", cat, f"SCC: {cat} (severity={sev})",
                           "T1078 (Valid Accounts)", verdict,
                           "High" if sev_is_high(sev) else "Low"))
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
        out.append(finding("Cloud Identity Risk",
                           u.get("userPrincipalName", "unknown-user"),
                           f"Entra risky user (riskLevel={level})",
                           "T1078 (Valid Accounts)", verdict,
                           "High" if verdict.startswith("Likely True") else "Low"))
    return out


def normalize_defender_alerts(data):
    """Microsoft Defender for Cloud alerts -> common findings. Azure's provider-native
    detector, the counterpart of AWS GuardDuty / GCP Security Command Center. Active
    High/Critical alerts are true-positive class; lower severities are Indeterminate."""
    out = []
    alerts = data if isinstance(data, list) else (data or {}).get("value", []) \
        if isinstance(data, dict) else []
    for a in alerts if isinstance(alerts, list) else []:
        if not isinstance(a, dict):
            continue
        if str(a.get("status", "Active")).lower() in ("dismissed", "resolved"):
            continue
        name = a.get("alertDisplayName") or a.get("alertType") or "Defender alert"
        sev = a.get("severity", "")
        entity = a.get("compromisedEntity") or a.get("resourceIdentifiers") or ""
        verdict = "Likely True Positive" if sev_is_high(sev) else "Indeterminate"
        out.append(finding(
            "Cloud Detection", name,
            f"Microsoft Defender for Cloud: {a.get('description', name)} "
            f"(severity={sev}, entity={entity})",
            "T1078 (Valid Accounts)", verdict,
            "High" if sev_is_high(sev) else "Low"))
    return out


def normalize_logging_status(data):
    """logging_status.json -> a visibility-gap finding for every disabled log source.

    If a control-plane log source is off, the collection has a blind spot and an
    adversary may have disabled it to evade detection (T1562.008). Indeterminate by
    itself (it may simply never have been configured), but it bounds what the rest of
    the investigation can possibly see and warrants analyst follow-up."""
    out = []
    sources = (data or {}).get("sources", []) if isinstance(data, dict) else []
    provider = (data or {}).get("provider", "cloud") if isinstance(data, dict) else "cloud"
    for s in sources if isinstance(sources, list) else []:
        if not isinstance(s, dict) or s.get("enabled") is not False:
            continue
        name = s.get("name", "log source")
        out.append(finding(
            "Cloud Logging Disabled", name,
            f"{provider} log source '{name}' is not enabled ({s.get('detail', 'no detail')}) "
            f"- evidence gap; verify it was not disabled to evade detection.",
            "T1562.008 (Impair Defenses: Disable or Modify Cloud Logs)",
            "Indeterminate", "Medium", severity="Medium"))
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
            out.append(finding(
                "Cloud Network Flow to C2", ip,
                f"Known C2 IP {ip} observed in collected VPC/NSG flow logs - confirms "
                f"network communication (not just an asserted indicator).",
                "T1071 (Application Layer Protocol)", "True Positive", "High"))
    return out


def c2_findings(c2_ips, c2_domains):
    out = []
    for ip in [x.strip() for x in (c2_ips or "").split(",") if x.strip()]:
        out.append(finding("Cloud C2 Beacon", ip, f"Operator-supplied C2 endpoint {ip}",
                           "T1071 (Application Layer Protocol)", "True Positive", "High"))
    for d in [x.strip() for x in (c2_domains or "").split(",") if x.strip()]:
        out.append(finding("Cloud C2 Beacon", d, f"Operator-supplied C2 domain {d}",
                           "T1071 (Application Layer Protocol)", "True Positive", "High"))
    return out
