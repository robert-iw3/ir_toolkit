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


def _read(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


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
