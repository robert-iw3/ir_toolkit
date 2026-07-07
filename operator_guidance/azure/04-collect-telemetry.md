# 04 · Collect Telemetry (Azure)

*Pull the evidence over the window — resource ops, identity events, the OAuth/inbox/M365 surface,
and network flows. Snapshot without judgment; adjudicate in step 07. Shared framing:
[../aws/04-collect-telemetry.md](../aws/04-collect-telemetry.md).*

Sweep **all subscriptions** (`az account list`) — attackers pivot to the one nobody watches.

---

## Step 1 — Activity log (resource control plane)

```bash
az monitor activity-log list --start-time $WINDOW_START --end-time $WINDOW_END \
    --query '[].{t:eventTimestamp,caller:caller,op:operationName.value,status:status.value,res:resourceId,ip:claims.ipaddr}' \
    > $CASE/evidence/activity_log.json
```

## Step 2 — Entra sign-in logs (identity plane — the primary evidence)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=createdDateTime ge $WINDOW_START&\$top=1000" \
  > $CASE/evidence/signins.json
# Key fields: userPrincipalName, ipAddress, location, clientAppUsed (legacy auth!),
# status.errorCode, mfaDetail, riskState, appDisplayName
```

## Step 3 — Directory audit logs (identity changes / persistence)

```bash
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDateTime ge $WINDOW_START&\$top=1000" \
  > $CASE/evidence/directory_audits.json
# Watch for: "Add service principal credentials", "Consent to application",
# "Add member to role", "Update conditional access policy", "Disable Strong Authentication"
```

## Step 4 — The identity-attack surface (Azure's high-value artifacts)

```bash
# OAuth consent grants (illicit-consent-grant attack)
az rest --method GET --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
    > $CASE/evidence/oauth_grants.json
# Enterprise apps / service principals + their credentials (backdoor app persistence)
az ad sp list --all --query '[].{name:displayName,appId:appId,id:id}' > $CASE/evidence/service_principals.json
# Risky users / risk detections
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" \
    > $CASE/evidence/risky_users.json
```

## Step 5 — M365 mailbox & data surface (if in scope)

```bash
# Inbox forwarding/redirect rules (BEC exfil) — per user via Graph
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$UPN/mailFolders/inbox/messageRules" \
    > $CASE/evidence/inbox_rules_$UPN.json
# M365 unified audit (download/export events) — via Exchange Online (Search-UnifiedAuditLog) or Graph
```

## Step 6 — Network flow + resource inventory

```bash
# NSG flow logs for the compromised VM's subnet/NIC (C2/exfil corroboration)
az network watcher flow-log show --location <region> --name <flowlog> 2>/dev/null
# What exists that the attacker may have created/touched
az vm list -d --query '[].{name:name,rg:resourceGroup,ip:publicIps,size:hardwareProfile.vmSize}' > $CASE/evidence/vms.json
az role assignment list --all --query '[].{p:principalName,role:roleDefinitionName,scope:scope}' > $CASE/evidence/role_assignments.json
```

**What you're gathering:** the resource ops, the full identity/sign-in story, the OAuth/app/inbox
persistence surface, the M365 exfil evidence, and network flows. Step 05–06 turn it into findings.

---

➡️ Next: [05-analyze-control-plane.md](05-analyze-control-plane.md)

*Toolkit parallel: `--provider azure` collects Activity log, Entra sign-ins, NSG flow config, risky
users, OAuth grants, directory audit, inbox rules, and M365 unified audit.*
