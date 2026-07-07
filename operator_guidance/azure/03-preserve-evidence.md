# 03 · Preserve Evidence (Azure)

*Confirm the logs exist, freeze the window, snapshot disks before anything is deleted, and copy
evidence to immutable storage. Shared reasoning: [../aws/03-preserve-evidence.md](../aws/03-preserve-evidence.md).*

---

## Step 1 — Pre-flight: is logging on? (per source — Azure is opt-in)

```bash
# Diagnostic settings on key resources (are logs even being emitted/retained?)
az monitor diagnostic-settings list --resource <resourceId>
# Entra sign-in/audit log retention depends on your tenant/license — confirm you can query far enough back
# M365 unified audit enabled? (Exchange Online) — required for mailbox/SharePoint evidence
# NSG flow logs configured?
az network watcher flow-log list --location <region> 2>/dev/null
```

Record which sources are on/off (`logging_status.json`). Entra logs are typically retained only
**7–30 days** without a Log Analytics/Sentinel export — a hard limit on how far back you can look,
so **move fast** and export.

## Step 2 — Freeze the incident window

Default 7 days; widen to 30/90 for late discovery (mind the Entra retention limit above). Bound
every pull in step 04.

## Step 3 — Snapshot disks before any deletion

```bash
# Snapshot the VM's OS + data managed disks, tagged for the case (do this before stop/delete)
for disk in $(az vm show -g <rg> -n <vm> --query 'storageProfile.[osDisk.managedDisk.id, dataDisks[].managedDisk.id]' -o tsv); do
    az snapshot create -g <rg> -n "ir-$(basename $disk)-$CASE" --source "$disk" --tags ir:incident=$CASE
done | tee $CASE/evidence/azure_disk_snapshots.json
```

Attach a copy read-only to a forensic VM in an **isolated subscription** for deep analysis — never
mount a suspect disk on production.

## Step 4 — Export logs to immutable storage

Entra logs age out fast, so **export the window now** into a storage account with an **immutability
policy (WORM)** in a separate subscription:

```bash
# Pull sign-in + audit + activity logs for the window and store them immutably
az rest --method GET --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=createdDateTime ge $WINDOW_START" \
    > $CASE/evidence/signins_full.json
az rest --method GET --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDateTime ge $WINDOW_START" \
    > $CASE/evidence/directory_audits.json
az monitor activity-log list --start-time $WINDOW_START --end-time $WINDOW_END > $CASE/evidence/activity_log.json
az storage blob upload-batch -d "<evidence-container>" -s "$CASE/evidence" --account-name <ir-immutable-sa>
```

## Step 5 — Custody note

Record who/when (UTC), tenant/subscription, and the immutable-storage location + versions.

---

➡️ Next: [04-collect-telemetry.md](04-collect-telemetry.md)
