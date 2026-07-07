# 09 · Eradicate (GCP)

*Remove the attacker's access and footholds — identity-first, reversibly. Shared principles:
[../windows/10-eradicate.md](../windows/10-eradicate.md) and [../aws/09-eradicate.md](../aws/09-eradicate.md).*

---

## The order

```
1. Disable/delete rogue SA keys + sessions     5. Remove attacker-created resources
2. Disable compromised SAs / users             6. Close public exposure (allUsers, firewall)
3. Remove rogue IAM bindings (all levels)      7. Block C2 egress
4. Rotate everything reachable                 8. Re-enable logging + re-verify
```

## Step 1–2 — Kill credentials & identities

```bash
# Delete every user-managed key on compromised SAs (you disabled the known one in step 02)
for k in $(gcloud iam service-accounts keys list --iam-account=<sa-email> \
        --filter="keyType=USER_MANAGED" --format='value(name)'); do
    gcloud iam service-accounts keys delete "$k" --iam-account=<sa-email> --quiet
done
gcloud iam service-accounts disable <sa-email>     # disable the SA itself if attacker-controlled
# Compromised human user: suspend via Workspace/Cloud Identity admin + revoke sessions/OAuth grants
```

## Step 3 — Remove rogue IAM bindings (check every hierarchy level)

```bash
# Remove attacker-granted roles at project — AND check folder/org (inheritance!)
gcloud projects remove-iam-policy-binding $PROJECT --member="user:<attacker>" --role="roles/owner"
gcloud resource-manager folders remove-iam-policy-binding <folder> --member="..." --role="..." 2>/dev/null
gcloud organizations remove-iam-policy-binding <org> --member="..." --role="..." 2>/dev/null
# Remove rogue impersonation grants (TokenCreator/serviceAccountUser) on other SAs
```

## Step 4 — Rotate everything reachable

From the blast-radius list (step 08): rotate the compromised SA's downstream credentials, any
**Secret Manager secrets** the identity could read, DB creds, and third-party API keys. Rotate
**all** user-managed keys on reachable SAs, not just the one known-leaked. Assume anything reachable
was read.

## Step 5–7 — Resources, exposure, C2

```bash
# Attacker-created instances (snapshot first if evidence)
gcloud compute instances delete <attacker-vm> --zone=<zone> --quiet
# Close public exposure — remove allUsers/allAuthenticatedUsers bindings
gsutil iam ch -d allUsers gs://<public-bucket>; gsutil iam ch -d allAuthenticatedUsers gs://<public-bucket>
# Remove attacker firewall opens
gcloud compute firewall-rules delete <attacker-allow-rule> --quiet
# Block confirmed C2 egress
gcloud compute firewall-rules create ir-block-c2 --network=<net> --action=DENY --rules=all \
    --direction=EGRESS --destination-ranges=45.x.x.x --priority=100
```

## Step 8 — Re-enable logging & re-verify

Recreate the deleted log sink / re-enable Data Access logging; re-check for new SA keys, new
bindings, re-created instances, or re-opened `allUsers`. Keep a **rollback journal** (every change +
prior value + UTC + why) — IAM/GCS changes are reversible only if you recorded the prior state.

---

➡️ Next: [10-restore-and-recover.md](10-restore-and-recover.md)
