# 09 · Eradicate (AWS)

*Remove the attacker's access and footholds — completely, reversibly, in an order that doesn't let
the identity respawn. In cloud, eradication is mostly an **identity** operation.*

Shared principles (dry-run first, reanimation-before-body order, rollback journal, re-verify) are in
[../windows/10-eradicate.md](../windows/10-eradicate.md).

---

## The order (identity-centric)

```
1. Revoke ALL credentials of compromised principals     5. Remove attacker-created resources
2. Kill active sessions/tokens                          6. Close public exposure (buckets, snapshots, SGs)
3. Remove IAM persistence (rogue keys/users/policies)   7. Block C2 egress
4. Rotate everything the identity could read            8. Re-enable tampered logging + re-verify
```

## Step 1–2 — Revoke credentials & kill sessions

You began this in containment (step 02); now make it complete and permanent.

```bash
# Deactivate/delete ALL access keys of every compromised principal (you disabled the known one already)
for k in $(aws iam list-access-keys --user-name $PRINCIPAL --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    aws iam update-access-key --user-name $PRINCIPAL --access-key-id $k --status Inactive
done
# Revoke active role sessions (deny-before-now policy — see step 02) on every assumed role
# Rotate the instance role if instance-metadata theft was the vector (detach+recreate credentials)
```

## Step 3 — Remove IAM persistence

Attackers plant multiple footholds. Remove every one you found in step 05:

```bash
aws iam delete-user-policy --user-name $PRINCIPAL --policy-name <attacker-inline>   # rogue inline policy
aws iam detach-user-policy --user-name $PRINCIPAL --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# Attacker-created users / roles / login profiles
aws iam delete-login-profile --user-name <attacker-user> 2>/dev/null
# Widened trust policies — restore the original AssumeRolePolicyDocument
aws iam update-assume-role-policy --role-name <role> --policy-document file://original_trust.json
```

## Step 4 — Rotate everything exposed

The blast-radius list from step 08 defines this. Rotate: passwords/keys for implicated principals,
any **secrets the identity could read** (Secrets Manager / SSM Parameter Store values, DB creds,
third-party API keys), and instance role credentials. Assume anything reachable was read.

## Step 5 — Remove attacker-created resources

```bash
# Crypto-mining or pivot instances the attacker launched (terminate AFTER snapshotting if evidence)
aws ec2 terminate-instances --instance-ids <attacker-instances>
# Rogue Lambda functions, roles, key pairs, etc. from step 05
```

## Step 6 — Close public exposure

```bash
aws s3api delete-bucket-policy --bucket <public-bucket>            # or restore the private policy
aws s3api put-public-access-block --bucket <bucket> \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws ec2 reset-snapshot-attribute --snapshot-id <snap> --attribute createVolumePermission   # un-share
aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port <p> --cidr 0.0.0.0/0
```

## Step 7 — Block C2 egress

Block confirmed C2 IPs (from flow-log confirmation, step 04) at the SG/NACL, or via a network
firewall rule — the same surgical, documented approach as host IR.

## Step 8 — Re-enable logging & re-verify

```bash
aws cloudtrail start-logging --name <trail>       # undo the attacker's StopLogging
# Re-verify: any new API calls from the revoked principal? new keys created? re-shared snapshots?
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=$PRINCIPAL --max-results 20
```

Keep a **rollback journal** (every revocation/change, previous value, UTC, why) — cloud changes are
reversible only if you recorded the prior state.

---

➡️ Next: [10-restore-and-recover.md](10-restore-and-recover.md)

*Toolkit parallel: `Invoke-Eradication-Cloud.sh --apply` (dry-run default) contains identity first
(disable principal + revoke sessions), removes persistence, blocks C2, and journals reversible
revocations.*
