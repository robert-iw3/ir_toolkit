# 01 · Triage the Alert (Azure)

*"Defender for Cloud fired / Entra flagged a risky user or impossible travel / a user reports their
sent-items are full of things they didn't send — and I can't nail it down yet."*

Decide **real or noise, and how urgent**. Shared triage method:
[../windows/01-triage-the-alert.md](../windows/01-triage-the-alert.md) and the cloud framing in
[../aws/01-triage-the-alert.md](../aws/01-triage-the-alert.md).

---

## Extract who/what/where/when

- **Principal** — the Entra user (UPN), or an **app/service principal** (appId/objectId).
- **Action** — the sign-in, the resource op, the consent grant, the mailbox rule.
- **Source** — IP + geo; is it a known corporate/VPN egress or a hosting-provider IP abroad?
- **When** — UTC; how far back to widen the window.
- **Where** — tenant + subscription; and whether it's an Entra event or an Azure resource event.

## Light, read-only first look

```bash
CASE=IR-...; UPN="bob@contoso.com"

# Recent sign-ins for the user — location, MFA, legacy-auth, success/failure
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=userPrincipalName eq '$UPN'&\$top=50" \
  > $CASE/evidence/triage_signins.json

# Recent directory changes involving the user/app (consents, role grants, credential adds)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$top=50" \
  > $CASE/evidence/triage_diraudit.json

# Recent control-plane ops by the user
az monitor activity-log list --caller "$UPN" --offset 7d \
  --query '[].{t:eventTimestamp,op:operationName.value,status:status.value,res:resourceId}' \
  > $CASE/evidence/triage_activity.json

# Is the user flagged risky by Entra?
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$top=20"
```

**Read it in seconds:**
- **Impossible travel** (two sign-ins from distant geos too close in time), **legacy/basic-auth**
  success (bypasses MFA), or **MFA not satisfied** from an odd IP → strong signal.
- A **new OAuth consent grant** with mailbox/file scopes, a **new inbox-forwarding rule**, or a
  **client secret added to an app** → BEC/persistence, escalate.
- A **role assignment** to Global Admin / Owner, or a **diagnostic-settings deletion** → priv-esc /
  evasion.

> Don't disable the account or revoke the app yet unless it's actively causing harm (step 02).

## Make the call

Clear FP (known automation/expected) → close. Can't tell (common) → open, go to step 02. Obvious
active intrusion (legacy-auth login from abroad + inbox rule + mass download) → open + escalate +
identity-first containment now.

---

➡️ Next: [02-contain-identity-first.md](02-contain-identity-first.md)
