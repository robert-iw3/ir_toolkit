# 04 · Collect Telemetry (AWS)

*Pull the evidence over your incident window — control-plane logs, identity state, network flows,
and data-access events. Snapshot everything without judgment; you'll adjudicate in step 07.*

Bound every pull by the window from step 03, sweep the regions/accounts an attacker might hide in,
and save raw output to your evidence store.

---

## Multi-scope first — attackers use the region nobody watches

```bash
# Collect across ALL enabled regions (and accounts, if org-wide), not just where the alert fired
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
```

## Step 1 — CloudTrail management events (the core "who changed what")

```bash
# Full management-event history over the window (paginate; no event-name filter — cast wide)
aws cloudtrail lookup-events --start-time $WINDOW_START --end-time $WINDOW_END \
    --max-results 50 > $CASE/evidence/cloudtrail_mgmt.json
# For volume, prefer querying the delivered S3 logs (or Athena/CloudTrail Lake) over lookup-events,
# which is rate-limited and 90-day-bound. Athena over the evidence bucket scales to the full window.
```

## Step 2 — Identity state (blast-radius inputs)

```bash
# Credential report — every user, key age, last-used, MFA status (one CSV, high value)
aws iam generate-credential-report >/dev/null; sleep 3
aws iam get-credential-report --query Content --output text | base64 -d > $CASE/evidence/cred_report.csv

# The suspect principal's full permission surface + any extra keys (persistence)
aws iam list-attached-user-policies --user-name $PRINCIPAL
aws iam get-account-authorization-details > $CASE/evidence/iam_authz_details.json   # whole IAM graph
aws accessanalyzer list-findings 2>/dev/null > $CASE/evidence/access_analyzer.json  # external exposure
```

## Step 3 — Network flow logs (C2 / exfil corroboration)

```bash
# If Flow Logs land in CloudWatch Logs or S3, pull the window for the compromised ENI/instance.
# A confirmed C2 IP found in flow logs upgrades it from "asserted" to "observed on the wire".
aws logs filter-log-events --log-group-name <flowlogs-group> \
    --start-time $(date -d $WINDOW_START +%s000) --end-time $(date -d $WINDOW_END +%s000) \
    --filter-pattern '"45.66.77.88"' > $CASE/evidence/flow_c2_match.json
```

## Step 4 — S3 data events (the exfil evidence — if enabled)

```bash
# Object-level access. Requires data events to have been configured (checked in step 03).
# Source from the trail's data-event log group / bucket; look for bulk GetObject per principal.
aws s3api list-objects-v2 --bucket <ir-evidence-bucket> --prefix $CASE/s3-data-events/ \
    > $CASE/evidence/s3_dataevents_index.json
# Public-exposure sweep — buckets opened to the world
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    aws s3api get-bucket-policy-status --bucket "$b" 2>/dev/null | grep -q true && echo "PUBLIC: $b"
done | tee $CASE/evidence/public_buckets.txt
```

## Step 5 — Resource inventory in scope

```bash
# What exists that the attacker may have created/touched (crypto-mining instances, rogue keys, etc.)
aws ec2 describe-instances --query 'Reservations[].Instances[].{id:InstanceId,ip:PublicIpAddress,type:InstanceType,launch:LaunchTime,region:Placement.AvailabilityZone}' > $CASE/evidence/instances.json
aws ec2 describe-security-groups > $CASE/evidence/security_groups.json
```

**What you're gathering (don't judge yet):** the full API story, who can do what, where traffic
went, how much data was read, and what resources exist. Step 05–06 turn this into findings.

---

➡️ Next: [05-analyze-control-plane.md](05-analyze-control-plane.md)

*Toolkit parallel: `playbooks/cloud/00_collect_forensics.sh` collects all of this (GuardDuty, full
CloudTrail, S3 data events, IAM credential report + Access Analyzer, flow logs, public-bucket sweep)
over the window, optionally `--all-regions`.*
