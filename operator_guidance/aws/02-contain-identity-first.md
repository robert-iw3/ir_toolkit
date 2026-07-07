# 02 · Contain — Identity First (AWS)

*In cloud, you contain the **identity** before the network. A stolen credential is the intrusion;
disabling it stops the attacker's hands even while their code keeps running.*

Shared containment principles (buy time without destroying evidence, risk-based choices, document
every action) are in [../windows/02-contain-without-destroying-evidence.md](../windows/02-contain-without-destroying-evidence.md).

---

## The cloud containment order: identity → session → resource → network

1. **Neutralize the credential** — deactivate the access key / disable the login. Stops *new* API
   calls with that credential.
2. **Revoke live sessions** — an already-issued STS token keeps working until it expires even after
   you disable the key. You must invalidate active sessions too.
3. **Quarantine the resource** — isolate the compromised EC2 instance/function without deleting it.
4. **Network** — SG/NACL isolation, the same three-axis risk calls as host IR.

## Step 1 — Neutralize the credential (preserve it, don't delete it)

**Deactivate, don't delete** — a deleted user/key destroys evidence and breaks CloudTrail
correlation. Deactivation stops use while preserving the record.

```bash
# Deactivate the access key (stops new calls; key + its history remain for evidence)
aws iam update-access-key --user-name $PRINCIPAL --access-key-id $AKID --status Inactive

# For a human user, also neutralize console login
aws iam delete-login-profile --user-name $PRINCIPAL 2>/dev/null   # removes console password
```

## Step 2 — Revoke active sessions (the step people forget)

A disabled key does **not** kill sessions already issued from it, and assumed-role STS tokens live
until expiry. Cut them:

```bash
# For a ROLE the attacker assumed: attach an inline "deny everything before now" policy —
# this invalidates all existing sessions immediately (AWS's documented session-revocation method).
aws iam put-role-policy --role-name <compromisedRole> --policy-name IR-RevokeSessions \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%FT%TZ)"'"}}}]}'

# For an IAM user: after deactivating keys, also detach permissions / apply a deny to stop any
# lingering federated sessions.
```

## Step 3 — Quarantine the compromised resource (don't terminate)

If a specific EC2 instance is compromised, **isolate it — don't terminate it** (termination destroys
volatile evidence and the disk).

```bash
# Move the instance to an isolation security group (no ingress; egress per your risk call below)
aws ec2 modify-instance-attribute --instance-id i-xxxx --groups sg-isolation
# Do NOT stop/terminate — snapshot its disks first (step 03). Stopping loses instance memory.
```

## Step 4 — Network: the same three-axis risk calls

The [host containment risk model](../windows/02-contain-without-destroying-evidence.md) applies to
Security Groups / NACLs:

- **Inbound** — restrict to kill attacker ingress.
- **Outbound** — the **risk-based** exfil-vs-C2-visibility call. Regulated/crown-jewel data or
  active bulk exfil → cut egress now (deny-all SG). Low data risk + you want to map C2 → observe
  briefly and deliberately, then cut. **Write the decision down and who approved it.**
- **East-west / lateral** — in cloud, "lateral" is often the identity pivoting via `AssumeRole` into
  other accounts (contained in step 1–2) **and** network reachability to peer instances/VPCs.
  Restrict SG references and VPC peering the compromised host can use.

> **The management-access caveat still applies:** don't leave a broad admin path open just for your
> own convenience — use a dedicated investigation role from a separate account, not the compromised
> account's credentials.

## Preserve, don't purge

- ❌ Don't **delete** the IAM user/role/key (breaks evidence + correlation) — deactivate.
- ❌ Don't **terminate/stop** the instance before snapshotting (step 03).
- ❌ Don't disable CloudTrail "to reduce noise" — you'd be doing the attacker's defense-evasion for
  them.
- ✅ Record every containment action + UTC time — timeline anchors and rollback inputs.

---

➡️ Next: [03-preserve-evidence.md](03-preserve-evidence.md)

*Toolkit parallel: `Invoke-IRCollection-Cloud.sh --contain` performs identity-first containment +
session revocation; eradication (`Invoke-Eradication-Cloud.sh`) journals revocations reversibly.*
