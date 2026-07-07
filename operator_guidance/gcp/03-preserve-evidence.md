# 03 · Preserve Evidence (GCP)

*Confirm the logs exist, freeze the window, snapshot disks before deletion, copy evidence to a locked
bucket. Shared reasoning: [../aws/03-preserve-evidence.md](../aws/03-preserve-evidence.md).*

---

## Step 1 — Pre-flight: is logging on?

```bash
# Which audit-log types are enabled? Admin Activity is always on; Data Access is usually NOT.
gcloud projects get-iam-policy $PROJECT --format=json | jq '.auditConfigs'
# Log sinks (has the attacker deleted/redirected one? _Default sink changes = evasion)
gcloud logging sinks list --project=$PROJECT
# SCC enabled at the org? VPC Flow Logs on the relevant subnets?
gcloud compute networks subnets describe <subnet> --region=<r> --format='value(enableFlowLogs)'
```

Record the result (`logging_status.json`). If **Data Access logs are off**, note that you may be
blind to reads/exfil; if a **sink was recently deleted**, that's evidence of evasion.

## Step 2 — Freeze the incident window

Default 7 days; widen for late discovery. Note Cloud Logging default retention (Admin Activity 400
days; `_Default` bucket 30 days) — bound every pull to the window.

## Step 3 — Snapshot disks before any deletion

```bash
for disk in $(gcloud compute instances describe <vm> --zone=<zone> \
        --format='value(disks[].source.basename())'); do
    gcloud compute disks snapshot "$disk" --zone=<zone> \
        --snapshot-names="ir-$disk-$(date -u +%Y%m%d)" --labels=ir-incident=$CASE
done | tee $CASE/evidence/gcp_disk_snapshots.json
```

Attach a copy read-only to a forensic VM in an **isolated project** — never mount a suspect disk on
production.

## Step 4 — Export logs to a locked bucket

```bash
# Export the window's audit logs, then store in a retention/bucket-locked GCS bucket (separate project)
gcloud logging read \
  "timestamp>=\"$WINDOW_START\" AND timestamp<=\"$WINDOW_END\" AND logName:\"cloudaudit.googleapis.com\"" \
  --project=$PROJECT --format=json > $CASE/evidence/audit_logs.json
gsutil cp $CASE/evidence/audit_logs.json gs://<ir-evidence-bucket>/$CASE/
# (For durability, also create a dedicated log sink → locked bucket so future logs are captured.)
```

## Step 5 — Custody note

Record who/when (UTC), project, and the evidence bucket + object generations (GCS versioning is your
integrity anchor).

---

➡️ Next: [04-collect-telemetry.md](04-collect-telemetry.md)
