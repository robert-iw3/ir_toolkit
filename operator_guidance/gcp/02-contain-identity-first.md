# 02 · Contain — Identity First (GCP)

*Disable the identity and its keys before the network. Shared reasoning:
[../aws/02-contain-identity-first.md](../aws/02-contain-identity-first.md) and
[../windows/02-contain-without-destroying-evidence.md](../windows/02-contain-without-destroying-evidence.md).*

---

## Order: credential/key → sessions → IAM → resource → network

## Step 1 — Neutralize the credential (disable, don't delete)

```bash
# Disable a compromised service account (stops it authenticating; preserves it for evidence)
gcloud iam service-accounts disable <sa-email>

# Disable a specific leaked user-managed SA key (preferred over delete — keeps evidence)
gcloud iam service-accounts keys disable <KEY_ID> --iam-account=<sa-email>

# For a compromised human user, revoke via Workspace/Cloud Identity admin (suspend the account,
# reset its sessions) — done in the Admin console / Directory API, not gcloud IAM.
```

## Step 2 — Kill active sessions / tokens

Short-lived OAuth/access tokens minted before you disabled the key keep working until they expire
(typically ~1h). Disabling the SA/key stops *new* tokens; for a user, **revoke sessions/OAuth grants**
in the Workspace Admin console. Then tighten IAM (step 3) so even a valid token can't act.

## Step 3 — Remove the permission path (defense in depth)

If a token might still be live, cut what it can do — remove the risky binding at the tightest scope:

```bash
gcloud projects remove-iam-policy-binding $PROJECT \
    --member="serviceAccount:<sa-email>" --role="roles/owner"
```

## Step 4 — Quarantine the compromised VM (don't delete)

```bash
# Isolate with a deny-all firewall tag/rule; snapshot disks BEFORE any stop (step 03)
gcloud compute instances add-tags <vm> --tags=ir-quarantine --zone=<zone>
gcloud compute firewall-rules create ir-deny-all --network=<net> --action=DENY --rules=all \
    --direction=INGRESS --target-tags=ir-quarantine --priority=100
# Do NOT delete the instance; capture disk snapshots first.
```

## Step 5 — Network: the three-axis risk calls

Same [risk-based model](../windows/02-contain-without-destroying-evidence.md) via VPC firewall rules:
inbound deny; **outbound is the exfil-vs-C2-visibility judgment** (regulated data/active exfil → cut
now; else observe briefly + document who approved); **lateral** = restrict firewall reachability to
peer instances and the identity's ability to impersonate/pivot across projects (contained in steps
1–3). Investigate from a separate identity, not the compromised one.

## Preserve, don't purge

Disable (don't delete) SAs/keys/bindings; snapshot before stopping the VM; don't delete log sinks.
Record every action + UTC.

---

➡️ Next: [03-preserve-evidence.md](03-preserve-evidence.md)
