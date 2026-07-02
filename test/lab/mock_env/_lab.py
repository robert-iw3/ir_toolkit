#!/usr/bin/env python3
"""
_lab.py - the engine behind the lab's scenario-driven mock cloud CLIs.

The `aws`, `az`, and `gcloud` shims in this directory all defer here. Unlike the simple
recording mocks in test/mocks/ (one canned answer per query), this serves telemetry from
an *attack scenario* selected by $IR_LAB_SCENARIO, so the same collector code path exercises
a realistic, per-attack environment without ever calling a real provider (no charges).

A scenario is JSON (see test/lab/scenarios/*.json). Each query the collectors make is
answered from the scenario's provider block; anything unspecified gets a safe empty default
so the happy path still completes.
"""
import base64
import json
import os
import sys

PROVIDER_KEY = {"aws": "aws", "az": "azure", "gcloud": "gcp"}


def _scenario():
    path = os.environ.get("IR_LAB_SCENARIO")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def _baseline():
    """Benign baseline telemetry merged into every scenario (real-tenant noise)."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "baseline.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _merge(base, scen):
    """Merge scenario telemetry over the benign baseline: lists are concatenated (baseline
    first, then attack), nested dict lists (e.g. {"value":[...]}) likewise, scalars override."""
    out = dict(base)
    for k, v in (scen or {}).items():
        b = out.get(k)
        if isinstance(v, list) and isinstance(b, list):
            out[k] = b + v
        elif isinstance(v, dict) and isinstance(b, dict):
            merged = dict(b)
            for kk, vv in v.items():
                if isinstance(vv, list) and isinstance(merged.get(kk), list):
                    merged[kk] = merged[kk] + vv
                else:
                    merged[kk] = vv
            out[k] = merged
        else:
            out[k] = v
    return out


def _provider_data(prog):
    """Baseline + scenario telemetry for the CLI's provider."""
    scn = _scenario()
    pkey = PROVIDER_KEY.get(prog, prog)
    return _merge(_baseline().get(pkey, {}), scn.get(pkey, {}))


def _emit(s):
    if not s.endswith("\n"):
        s += "\n"
    sys.stdout.write(s)


def _is_text(line):
    return ("--output text" in line or "--output tsv" in line
            or "--format=value" in line or "--format 'value" in line
            or "--format='value" in line)


def _arg(line, flag):
    """Value token following a flag on the command line (e.g. --bucket NAME)."""
    toks = line.split()
    return toks[toks.index(flag) + 1] if flag in toks and toks.index(flag) + 1 < len(toks) else ""


# ── AWS ─────────────────────────────────────────────────────────────────────────
def _aws(line, data, text):
    ct = data.get("cloudtrail", [])
    if "cloudtrail describe-trails" in line:
        return "ir-trail" if text else json.dumps({"trailList": [{"Name": "ir-trail"}]})
    if "iam generate-credential-report" in line:
        return "{}"
    if "iam get-credential-report" in line:
        csv = data.get("credential_report_csv", "")
        if not csv:
            return "{}"
        return json.dumps({"Content": base64.b64encode(csv.encode()).decode(),
                           "ReportFormat": "text/csv"})
    if "accessanalyzer list-analyzers" in line:
        return ("arn:aws:access-analyzer:::analyzer/a" if data.get("access_analyzer") else "None") \
            if text else json.dumps({"analyzers": [{"arn": "arn:aws:access-analyzer:::analyzer/a"}]})
    if "accessanalyzer list-findings" in line:
        return json.dumps(data.get("access_analyzer", {"findings": []}))
    if "guardduty list-detectors" in line:
        return "det-lab0001" if text else json.dumps({"DetectorIds": ["det-lab0001"]})
    if "guardduty list-findings" in line:
        return "f1" if text else json.dumps({"FindingIds": ["f1"]})
    if "guardduty get-findings" in line:
        return json.dumps(data.get("guardduty", {"Findings": []}))
    if "ec2 describe-regions" in line:
        regions = data.get("regions", ["us-east-1"])
        return "\t".join(regions) if text else json.dumps(
            {"Regions": [{"RegionName": r} for r in regions]})
    if "cloudtrail lookup-events" in line:
        events = [{"EventName": r.get("eventName", ""), "CloudTrailEvent": json.dumps(r)}
                  for r in ct]
        return json.dumps({"Events": events})       # no NextToken -> single page
    if "ec2 describe-flow-logs" in line:
        if "LogGroupName" in line:
            return "ir-vpc-flow-logs"
        if "FlowLogId" in line:
            return "fl-lab001"
        return json.dumps({"FlowLogs": [{"LogGroupName": "ir-vpc-flow-logs", "FlowLogId": "fl-lab001"}]})
    if "logs filter-log-events" in line:
        # S3 data-event log group (data-plane exfil) vs the VPC flow-log group.
        if "ir-s3-dataevents" in line:
            recs = data.get("s3_data_events", [])
            return json.dumps({"events": [{"message": json.dumps(r)} for r in recs]})
        lines = data.get("flow_log_lines", [])
        return json.dumps({"events": [{"message": m} for m in lines]})
    # Posture: public snapshots / AMIs / IMDSv1 instances.
    if "describe-snapshots" in line and "restorable-by-user-ids" in line:
        return json.dumps({"Snapshots": data.get("public_snapshots", [])})
    if "describe-images" in line and "is-public" in line:
        return json.dumps({"Images": data.get("public_amis", [])})
    if "ec2 describe-instances" in line and "HttpTokens" in line:
        return json.dumps(data.get("imds", []))
    if "ec2 describe-instances" in line:
        if text:
            return "i-lab0001" if "InstanceId" in line else ("vpc-lab01" if "VpcId" in line else "")
        return json.dumps({"Reservations": [{"Instances": [
            {"InstanceId": "i-lab0001", "VpcId": "vpc-lab01"}]}]})
    if "ec2 describe-security-groups" in line:
        if "--query" in line:                    # containment lookups
            return "sg-lab01" if text else json.dumps({"SecurityGroups": []})
        return json.dumps({"SecurityGroups": data.get("security_groups", [])})   # posture sweep
    # Posture: public S3 buckets (list + per-bucket public status).
    if "s3api list-buckets" in line:
        names = [b.get("name") for b in data.get("public_buckets", [])]
        return "\t".join(n for n in names if n) if text else json.dumps(
            {"Buckets": [{"Name": n} for n in names]})
    if "s3api get-bucket-policy-status" in line:
        b = _arg(line, "--bucket")
        return "True" if any(x.get("name") == b and x.get("public")
                             for x in data.get("public_buckets", [])) else "False"
    if "s3api get-public-access-block" in line:
        b = _arg(line, "--bucket")
        return "False" if any(x.get("name") == b and x.get("public")
                              for x in data.get("public_buckets", [])) else "True"
    return "" if text else "{}"


# ── Azure ───────────────────────────────────────────────────────────────────────
def _az(line, data, text):
    if "monitor diagnostic-settings subscription list" in line:
        return json.dumps(data.get("diagnostic_settings", []))
    if "monitor activity-log list" in line and "--max-events 1" in line:
        return json.dumps(data.get("activity_log", []) or [{"_": "preflight"}])
    if "monitor activity-log list" in line:
        return json.dumps(data.get("activity_log", []))
    if "security alert list" in line:
        return json.dumps(data.get("defender_alerts", []))
    if "network nsg list" in line:
        return json.dumps(data.get("nsg_rules", []))
    if "network watcher flow-log list" in line:
        return json.dumps(data.get("nsg_flow_logs", []))
    if "riskyUsers" in line:
        return json.dumps(data.get("risky_users", {"value": []}))
    if "signIns" in line:
        return json.dumps(data.get("signin_logs", {"value": []}))
    if "oauth2PermissionGrants" in line:
        return json.dumps(data.get("oauth_grants", {"value": []}))
    if "directoryAudits" in line:
        return json.dumps(data.get("directory_audit", {"value": []}))
    if "users?$select" in line or ("/users?" in line and "select" in line):
        # inbox-rule loop: advertise one mailbox to iterate
        return "lab-user-1" if text else json.dumps({"value": [{"id": "lab-user-1"}]})
    if "mailFolders/inbox/messageRules" in line:
        rules = data.get("inbox_rules", {"value": []})
        return json.dumps(rules.get("value", rules if isinstance(rules, list) else []))
    return "[]" if ("list" in line or "show" in line) else "{}"


# ── GCP ─────────────────────────────────────────────────────────────────────────
def _gcloud(line, data, text):
    if "logging sinks list" in line:
        return "ir-audit-sink"
    if "scc findings list" in line:
        return json.dumps(data.get("scc", []))
    if "logging read" in line and "vpc_flows" in line:
        return json.dumps(data.get("flow_log", []))
    if "logging read" in line:
        return json.dumps(data.get("audit_log", []))
    if "compute firewall-rules list" in line:
        return json.dumps(data.get("firewall_rules", []))
    if "projects get-iam-policy" in line:
        return json.dumps(data.get("iam_policy", {"bindings": []}))
    if "iam service-accounts list" in line:
        sas = data.get("service_accounts", [])
        return "\n".join(sas) if text else json.dumps([{"email": s} for s in sas])
    if "iam service-accounts keys list" in line:
        rows = data.get("sa_key_rows", [])
        return "\n".join(rows) if text else json.dumps([])
    if "compute instances describe" in line:
        return "" if text else "{}"
    return "" if text else "[]"


def main():
    # The shims set IR_LAB_CLI; fall back to argv[0]'s basename for direct invocation.
    prog = os.environ.get("IR_LAB_CLI") or os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    line = " ".join(args)
    # mirror the recording-mock call log so tests can assert exact invocations
    mlog = os.environ.get("IR_MOCK_LOG")
    if mlog:
        with open(mlog, "a", encoding="utf-8") as fh:
            fh.write(f"{prog} {line}\n")
    data = _provider_data(prog)          # benign baseline + scenario attack telemetry
    text = _is_text(line)
    handler = {"aws": _aws, "az": _az, "gcloud": _gcloud}.get(prog)
    _emit(handler(line, data, text) if handler else ("" if text else "{}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
