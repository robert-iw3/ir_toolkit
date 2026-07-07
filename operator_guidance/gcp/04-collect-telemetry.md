# 04 · Collect Telemetry (GCP)

*Pull the evidence over the window — audit logs, IAM state, SA keys, flow logs, SCC. Snapshot without
judgment; adjudicate in step 07. Shared framing: [../aws/04-collect-telemetry.md](../aws/04-collect-telemetry.md).*

Sweep **all accessible projects** (`gcloud projects list`) — attackers pivot to the unwatched one.

---

## Step 1 — Cloud Audit Logs (Admin Activity = "who changed what")

```bash
gcloud logging read \
  "timestamp>=\"$WINDOW_START\" AND timestamp<=\"$WINDOW_END\" AND logName:\"cloudaudit.googleapis.com%2Factivity\"" \
  --project=$PROJECT --format=json --limit=5000 > $CASE/evidence/admin_activity.json

# Data Access logs (reads) — only if enabled (step 03)
gcloud logging read \
  "timestamp>=\"$WINDOW_START\" AND logName:\"cloudaudit.googleapis.com%2Fdata_access\"" \
  --project=$PROJECT --format=json --limit=5000 > $CASE/evidence/data_access.json
```

## Step 2 — IAM state + service-account keys (blast-radius + persistence)

```bash
# Full IAM policy at project (and check folder/org — inheritance!)
gcloud projects get-iam-policy $PROJECT --format=json > $CASE/evidence/iam_policy.json
gcloud resource-manager folders get-iam-policy <folder> --format=json 2>/dev/null > $CASE/evidence/iam_folder.json
gcloud organizations get-iam-policy <org> --format=json 2>/dev/null > $CASE/evidence/iam_org.json

# Every service account + its USER-MANAGED keys (the persistence inventory)
for sa in $(gcloud iam service-accounts list --project=$PROJECT --format='value(email)'); do
    gcloud iam service-accounts keys list --iam-account=$sa \
        --filter="keyType=USER_MANAGED" --format=json
done > $CASE/evidence/sa_keys.json
```

## Step 3 — Network flow logs (C2 / exfil corroboration)

```bash
# Flow logs land in Cloud Logging when enabled; search the window for a confirmed C2 IP
gcloud logging read \
  "timestamp>=\"$WINDOW_START\" AND logName:\"compute.googleapis.com%2Fvpc_flows\" AND jsonPayload.connection.dest_ip=\"45.66.77.88\"" \
  --project=$PROJECT --format=json > $CASE/evidence/flow_c2_match.json
```

## Step 4 — SCC findings + resource inventory

```bash
gcloud scc findings list <ORG_ID> --filter='state="ACTIVE"' --format=json > $CASE/evidence/scc_findings.json
# What exists that the attacker may have created/touched
gcloud compute instances list --format=json > $CASE/evidence/instances.json
gcloud compute firewall-rules list --format=json > $CASE/evidence/firewall_rules.json
# Public exposure — buckets/resources granting allUsers/allAuthenticatedUsers
for b in $(gsutil ls -p $PROJECT); do
    gsutil iam get "$b" 2>/dev/null | grep -q 'allUsers\|allAuthenticatedUsers' && echo "PUBLIC: $b"
done | tee $CASE/evidence/public_buckets.txt
```

**What you're gathering:** the API story (admin + data access), the IAM graph across the hierarchy,
the SA-key inventory, network flows, SCC context, and public exposure. Steps 05–06 turn it into
findings.

---

➡️ Next: [05-analyze-control-plane.md](05-analyze-control-plane.md)

*Toolkit parallel: `--provider gcp` collects Cloud Audit logs (admin + data-access + system-event),
SCC, project IAM + SA-key inventory, firewall rules, and VPC flow logs over the window.*
