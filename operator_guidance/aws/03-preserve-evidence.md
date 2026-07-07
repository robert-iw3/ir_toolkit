# 03 · Preserve Evidence (AWS)

*Cloud's version of "capture volatile memory first." Confirm the logs exist, freeze the window,
snapshot disks before anything is terminated, and copy evidence somewhere the attacker can't reach.*

---

## Step 1 — Pre-flight: is logging even on? (do this first)

Everything downstream depends on it, and a **disabled log source is both a blind spot and a
finding** (T1562.008 — an actor may have switched it off).

```bash
# CloudTrail — is a trail logging management (and data) events, and is it multi-region?
aws cloudtrail describe-trails --query 'trailList[].{name:Name,multiRegion:IsMultiRegionTrail,logging:HomeRegion}'
aws cloudtrail get-trail-status --name <trail>            # IsLogging: true?
aws cloudtrail get-event-selectors --trail-name <trail>   # are S3 DATA events captured? (often not)

# GuardDuty enabled? VPC Flow Logs on the relevant VPCs?
aws guardduty list-detectors
aws ec2 describe-flow-logs --query 'FlowLogs[].{id:FlowLogId,rt:ResourceId,status:FlowLogStatus}'
```

**Record the result** (`logging_status.json`). If CloudTrail was **off or was recently stopped**,
note it prominently — it bounds what you can ever learn and is itself evidence of the attack.

## Step 2 — Freeze the incident window

Cloud intrusions surface late. Pick a window that covers the whole suspected activity, and widen it
if triage suggests earlier compromise. Default to **7 days back**; go to 30/90 for late discovery.
Every collection pull in step 04 is bounded by this window (UTC).

```bash
WINDOW_START=2026-06-01T00:00:00Z
WINDOW_END=2026-07-07T00:00:00Z
```

## Step 3 — Snapshot disks BEFORE any termination (evidence preservation)

If an instance is involved, snapshot its EBS volumes now — before eradication, before anyone stops
it. Snapshots are your cloud "disk image."

```bash
# Snapshot every volume attached to the compromised instance, tagged for the case
for vol in $(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=i-xxxx \
        --query 'Volumes[].VolumeId' --output text); do
    aws ec2 create-snapshot --volume-id $vol \
        --description "IR $CASE" \
        --tag-specifications 'ResourceType=snapshot,Tags=[{Key=ir:incident,Value='"$CASE"'}]'
done | tee $CASE/evidence/ebs_snapshots.json
```

> For deep forensics, create a volume from the snapshot and attach it **read-only to a forensic
> instance in an isolated account** — never mount a suspect volume on a production box. Memory of a
> running instance is only obtainable while it runs (via SSM + a capture tool) — do it before you
> stop the instance if RAM matters.

## Step 4 — Copy logs to a locked evidence store

CloudTrail in its normal bucket is mutable by anyone with access — including the attacker. Copy the
window's logs into a **separate, locked-down evidence bucket** (different account, versioned, Object
Lock / WORM, restrictive policy) so your evidence is tamper-evident.

```bash
# Export/copy the window's CloudTrail objects into the evidence bucket, then hash them
aws s3 cp s3://<org-cloudtrail-bucket>/AWSLogs/.../ s3://<ir-evidence-bucket>/$CASE/cloudtrail/ \
    --recursive --exclude '*' --include '2026/06/*' --include '2026/07/*'
# Record object versions / ETags as your integrity anchor
```

## Step 5 — Custody note

Record who collected, when (UTC), from which account, and the evidence bucket + object versions.
Cloud gives you provider-side integrity (Object Lock, ETags) — use it.

---

➡️ Next: [04-collect-telemetry.md](04-collect-telemetry.md)

*Toolkit parallel: the forensics phase writes `logging_status.json`, honors the incident window
(`--lookback-hours`/`--window-*`), does opt-in `--snapshot-disks` (`ebs_snapshots.json`), and can
upload into a Terraform-provisioned locked evidence bucket.*
