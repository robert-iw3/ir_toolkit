# 09 · Eradicate (Azure)

*Remove the attacker's access and footholds — identity-first, reversibly. Shared principles:
[../windows/10-eradicate.md](../windows/10-eradicate.md) and [../aws/09-eradicate.md](../aws/09-eradicate.md).*

---

## The order

```
1. Revoke user credentials + sessions         5. Remove attacker-created resources
2. Kill app/SP persistence + OAuth grants     6. Close public exposure (NSG, storage)
3. Remove IAM/RBAC persistence                7. Block C2 egress
4. Rotate everything reachable                8. Re-enable diagnostics + re-verify
```

## Step 1 — Revoke user credentials & sessions

```bash
az ad user update --id $UPN --account-enabled false
az rest --method POST --url "https://graph.microsoft.com/v1.0/users/$UPN/revokeSignInSessions"
# Force a password reset + re-register MFA when the user returns to service (step 10)
```

## Step 2 — Kill app / service-principal persistence (Azure-critical)

This is the foothold user-password-resets miss:

```bash
# Remove attacker-added secrets/certs from every affected app registration
az ad app credential delete --id <appId> --key-id <attacker-keyId>
# Disable a malicious enterprise app and revoke its consent grants
az ad sp update --id <appId> --set accountEnabled=false
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/<grantId>"
# Delete attacker-created inbox forwarding rules
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/users/$UPN/mailFolders/inbox/messageRules/<ruleId>"
```

## Step 3 — Remove RBAC / directory-role persistence

```bash
az role assignment delete --assignee <principal> --role Owner --scope <scope>   # rogue RBAC
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directoryRoles/<roleId>/members/<id>/\$ref"  # rogue directory role
```

## Step 4 — Rotate everything reachable

From the blast-radius list (step 08): passwords/MFA for implicated users, **all app/SP secrets and
certs** the attacker could have read or added, Key Vault secrets the identity could access, and any
downstream service credentials. Assume anything reachable was read.

## Step 5–7 — Resources, exposure, C2

```bash
# Remove attacker-created VMs/resources (snapshot first if evidence)
az vm delete --ids <attacker-vm> --yes
# Close public exposure — restore restrictive NSG rules, remove public storage access
az network nsg rule delete -g <rg> --nsg-name <nsg> -n <attacker-allow-rule>
az storage account update -n <sa> --allow-blob-public-access false
# Block confirmed C2 IPs at the NSG
az network nsg rule create -g <rg> --nsg-name <nsg> -n IR-Block-C2 --priority 100 \
    --direction Outbound --access Deny --destination-address-prefixes 45.x.x.x
```

## Step 8 — Re-enable diagnostics & re-verify

Restore the diagnostic settings the attacker deleted; re-check for new sign-ins from revoked
principals, re-added app credentials, recreated inbox rules, or re-opened NSG rules. Keep a
**rollback journal** (every change + prior value + UTC + why).

---

➡️ Next: [10-restore-and-recover.md](10-restore-and-recover.md)
