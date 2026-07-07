# 02 · Contain — Identity First (Azure)

*Disable the identity and revoke its sessions before touching the network. Shared reasoning:
[../aws/02-contain-identity-first.md](../aws/02-contain-identity-first.md) and
[../windows/02-contain-without-destroying-evidence.md](../windows/02-contain-without-destroying-evidence.md).*

---

## Order: account → sessions → app credentials → resource → network

## Step 1 — Disable the account (don't delete)

```bash
# Block sign-in (preserves the object + its audit history for evidence)
az ad user update --id $UPN --account-enabled false
```

## Step 2 — Revoke active sessions & tokens (the forgotten step)

Disabling sign-in does **not** kill already-issued refresh/access tokens — they work until expiry.
Revoke them:

```bash
# Invalidate all refresh tokens / active sessions for the user
az rest --method POST --url "https://graph.microsoft.com/v1.0/users/$UPN/revokeSignInSessions"
```

## Step 3 — Neutralize app/service-principal persistence

If the attack came via a consented app or an app-registration credential, disabling the *user* does
nothing. Disable the service principal and/or remove attacker-added secrets/certs:

```bash
# Disable a malicious/compromised enterprise app (service principal)
az ad sp update --id <appId> --set accountEnabled=false
# Remove an attacker-added client secret or certificate from an app registration
az ad app credential list --id <appId>
az ad app credential delete --id <appId> --key-id <attacker-keyId>
# Revoke a suspicious OAuth consent grant
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/<grantId>"
```

## Step 4 — Quarantine the compromised VM (don't deallocate destructively)

```bash
# Isolate the NIC with a deny-all NSG; snapshot disks BEFORE any stop (step 03)
az network nic update --ids <nicId> --network-security-group <isolation-nsg>
# Do NOT delete the VM; capture disk snapshots first.
```

## Step 5 — Network: the three-axis risk calls

Same [risk-based model](../windows/02-contain-without-destroying-evidence.md): inbound deny;
**outbound is the exfil-vs-C2-visibility judgment** (regulated data/active exfil → cut now; else
observe briefly + document who approved); and **lateral** = restrict NSG peer reachability and the
identity's ability to pivot across subscriptions (contained in steps 1–3). Use a dedicated
investigation identity — not the compromised account.

## Preserve, don't purge

Don't delete users/apps/rules (deactivate); don't deallocate/delete the VM before snapshotting;
don't disable diagnostic logging. Record every action + UTC.

---

➡️ Next: [03-preserve-evidence.md](03-preserve-evidence.md)
