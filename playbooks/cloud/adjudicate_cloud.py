#!/usr/bin/env python3
"""
adjudicate_cloud.py - cloud finding normalization + adjudication (CLI entry point).

Closes the cloud "no real analysis" gap: parses the provider telemetry that
00_collect_forensics.sh wrote and assigns a Verdict on the same ladder the
Linux/Windows adjudicators use. The analysis itself lives in focused modules so no
single file is a monolith:

    cloud_findings.py      shared schema/helpers (verdict ladder, finding ctor, readers)
    cloud_detectors.py     provider-native detectors + indicators (GuardDuty/SCC/risky,
                           logging gaps, flow-log C2, operator C2)
    cloud_controlplane.py  behavioral analysis of raw audit logs (CloudTrail / GCP audit
                           / Azure activity / Entra sign-ins)
    cloud_identity.py      Entra/M365 identity (OAuth grants, inbox rules, directory audit)
    cloud_coverage.py      ATT&CK Cloud coverage map

This file wires them together (adjudicate()) and is the CLI. Public names are re-exported
below so callers/tests can keep importing them from `adjudicate_cloud`.

Trust model (cloud): provider-native detections (GuardDuty/SCC) at HIGH/CRITICAL severity
and cloud-log/detector tampering and operator-supplied C2 are true-positive class; identity
privesc and public exposure are likely-true-positive when unambiguous, else Indeterminate.

Usage: adjudicate_cloud.py --forensics-dir DIR --out COMBINED.json
                           [--c2-ips a,b] [--c2-domains x,y] [--provider aws]
                           [--coverage-out COVERAGE.md]
"""
import argparse
import json
import os
import sys

from cloud_findings import VERDICT_RANK, read_json, read_text
from cloud_detectors import (normalize_guardduty, normalize_scc, normalize_azure_risky,
                             normalize_defender_alerts, normalize_logging_status,
                             normalize_flow_logs, c2_findings)
from cloud_identity import (normalize_oauth_grants, normalize_inbox_rules,
                            normalize_directory_audit)
from cloud_controlplane import (normalize_cloudtrail, normalize_gcp_audit,
                                normalize_azure_activity, normalize_signins)
from cloud_iam import (normalize_iam_credential_report, normalize_access_analyzer,
                       normalize_gcp_iam_policy, normalize_gcp_sa_keys)
from cloud_posture import (normalize_security_groups, normalize_nsg_rules,
                          normalize_gcp_firewall, normalize_public_buckets,
                          normalize_public_snapshots, normalize_public_amis, normalize_imds)
from cloud_dataplane import (normalize_s3_data_events, normalize_gcp_data_access,
                            normalize_m365_audit)
from cloud_coverage import attack_coverage, coverage_markdown


def adjudicate(forensics_dir, provider, c2_ips, c2_domains):
    findings = []
    if provider == "aws":
        findings += normalize_guardduty(read_json(os.path.join(forensics_dir, "guardduty_findings.json")))
        findings += normalize_cloudtrail(read_json(os.path.join(forensics_dir, "cloudtrail_events.json")))
        findings += normalize_iam_credential_report(read_json(os.path.join(forensics_dir, "aws_iam_credential_report.json")))
        findings += normalize_access_analyzer(read_json(os.path.join(forensics_dir, "aws_access_analyzer.json")))
        findings += normalize_security_groups(read_json(os.path.join(forensics_dir, "security_groups.json")))
        findings += normalize_public_buckets(read_json(os.path.join(forensics_dir, "aws_public_buckets.json")))
        findings += normalize_public_snapshots(read_json(os.path.join(forensics_dir, "aws_public_snapshots.json")))
        findings += normalize_public_amis(read_json(os.path.join(forensics_dir, "aws_public_amis.json")))
        findings += normalize_imds(read_json(os.path.join(forensics_dir, "aws_imds.json")))
        # Data-plane exfil: S3 object-level events (bulk read / cross-account copy).
        findings += normalize_s3_data_events(read_json(os.path.join(forensics_dir, "aws_s3_data_events.json")))
    elif provider == "gcp":
        findings += normalize_scc(read_json(os.path.join(forensics_dir, "gcp_scc_findings.json")))
        findings += normalize_gcp_audit(read_json(os.path.join(forensics_dir, "gcp_audit_log.json")))
        # Data-plane exfil: GCS object reads live in the same data-access audit stream.
        findings += normalize_gcp_data_access(read_json(os.path.join(forensics_dir, "gcp_audit_log.json")))
        findings += normalize_gcp_iam_policy(read_json(os.path.join(forensics_dir, "gcp_iam_policy.json")))
        findings += normalize_gcp_sa_keys(read_json(os.path.join(forensics_dir, "gcp_sa_keys.json")))
        findings += normalize_gcp_firewall(read_json(os.path.join(forensics_dir, "gcp_firewall_rules.json")))
    elif provider == "azure":
        findings += normalize_azure_risky(read_json(os.path.join(forensics_dir, "azure_risky_users.json")))
        findings += normalize_defender_alerts(read_json(os.path.join(forensics_dir, "azure_defender_alerts.json")))
        findings += normalize_oauth_grants(read_json(os.path.join(forensics_dir, "azure_oauth_grants.json")))
        findings += normalize_inbox_rules(read_json(os.path.join(forensics_dir, "azure_inbox_rules.json")))
        findings += normalize_directory_audit(read_json(os.path.join(forensics_dir, "azure_directory_audit.json")))
        findings += normalize_azure_activity(read_json(os.path.join(forensics_dir, "azure_activity_log.json")))
        findings += normalize_signins(read_json(os.path.join(forensics_dir, "azure_signin_logs.json")))
        findings += normalize_nsg_rules(read_json(os.path.join(forensics_dir, "azure_nsg_rules.json")))
        # Data-plane / SaaS exfil: M365 unified audit (mass download + mailbox export).
        findings += normalize_m365_audit(read_json(os.path.join(forensics_dir, "azure_m365_audit.json")))
    # Logging-enablement preflight: disabled sources become visibility-gap findings.
    findings += normalize_logging_status(read_json(os.path.join(forensics_dir, "logging_status.json")))
    # Flow-log C2 confirmation (provider-specific file, format-agnostic IP match).
    flow_file = {"aws": "aws_vpc_flow_logs.json", "azure": "azure_flow_logs.json",
                 "gcp": "gcp_vpc_flow_logs.json"}.get(provider)
    if flow_file:
        findings += normalize_flow_logs(read_text(os.path.join(forensics_dir, flow_file)), c2_ips)
    findings += c2_findings(c2_ips, c2_domains)
    return findings


def main(argv=None):
    p = argparse.ArgumentParser(description="Normalize + adjudicate cloud telemetry.")
    p.add_argument("--forensics-dir", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--provider", default="aws")
    p.add_argument("--c2-ips", default="")
    p.add_argument("--c2-domains", default="")
    p.add_argument("--coverage-out", default="")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    findings = adjudicate(args.forensics_dir, args.provider, args.c2_ips, args.c2_domains)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    if args.coverage_out:
        with open(args.coverage_out, "w", encoding="utf-8") as fh:
            fh.write(coverage_markdown(attack_coverage(findings)))
    if not args.quiet:
        tp = sum(1 for f in findings if VERDICT_RANK[f["Verdict"]] >= 3)
        print(f"[+] {len(findings)} cloud finding(s), {tp} true-positive-class -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
