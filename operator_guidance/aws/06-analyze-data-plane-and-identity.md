# 06 · Analyze Data Plane & Identity (AWS)

*Control-plane analysis answered "who changed what." This answers "**who read how much**" (the
exfil end of the kill chain) and "**what could this identity reach**" (blast radius).*

---

## Part A — Data-plane: the exfiltration hunt

Works over **S3 data events** (object-level access), which are separate from management events and
often off by default (you checked in step 03). If they're on, this is where exfil shows.

```bash
# Bulk GetObject per principal — tiered by volume and bucket spread
# (from the trail's data-event sink; group by userIdentity + count GetObject)
jq -r 'select(.eventName=="GetObject") | .userIdentity.arn' $CASE/evidence/s3_dataevents.json |
    sort | uniq -c | sort -rn | head
# Cross-account / CopyObject transfers to another bucket = staged exfil
grep -E 'CopyObject|copySource' $CASE/evidence/s3_dataevents.json
```

| Signal | ATT&CK | Verdict lean |
|---|---|---|
| Bulk `GetObject` by a **human** principal | T1530 | **Likely True Positive** |
| Bulk `GetObject` by an **automation** identity (SA/assumed-role for ETL/backup) | T1530 | **Indeterminate** — verify (routine for pipelines) |
| Cross-account `CopyObject` to a foreign bucket | T1537 | **Likely True Positive** |
| Reads below any meaningful threshold | — | doesn't fire (nothing suppressed) |

> **FP discipline (downgrade, never blind):** volume alone from an automation principal is routine.
> The same volume by a *human*, any *cross-account copy*, or reads paired with a public-bucket change
> (step 05) are the strong signals. If S3 data events were **off**, record "exfil visibility: none"
> as a gap — don't conclude "no exfil."

## Part B — Identity: blast radius (what could the principal reach?)

The compromised identity's reach = its permissions + everything it can assume, everywhere. Map it so
containment/eradication (steps 09) is complete, not whack-a-mole.

```bash
# The principal's full policy surface
aws iam list-attached-user-policies --user-name $PRINCIPAL
aws iam list-user-policies --user-name $PRINCIPAL
aws iam list-groups-for-user --user-name $PRINCIPAL

# What roles can it assume? (cross-account pivot paths)
# Parse iam_authz_details.json for roles whose trust policy names this principal/account.
jq '.RoleDetailList[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS? // empty | tostring | test("'"$PRINCIPAL"'|'"$(aws sts get-caller-identity --query Account --output text)"'")) | .RoleName' $CASE/evidence/iam_authz_details.json

# Use the policy simulator to answer "can it do X on Y" for the actions that matter
aws iam simulate-principal-policy --policy-source-arn <principal-arn> \
    --action-names s3:GetObject iam:CreateAccessKey ec2:RunInstances sts:AssumeRole
```

**What you're building:** the set of accounts, roles, buckets, and services this identity touches —
that set is your eradication scope and your "which credentials are burned" list.

## Part C — Instance credential theft (the metadata-endpoint angle)

A very common cloud initial access: an app on an EC2 instance is exploited (SSRF/RCE), the attacker
reads the **instance metadata service** to steal the instance role's temporary credentials, then
uses them from *outside*. The tell:

```bash
# The instance role's credentials (ASIA...) being used from a source IP that is NOT the instance
# → temporary creds exfiltrated off-box. Compare sourceIPAddress against the instance's own IPs.
grep 'assumed-role' $CASE/evidence/cloudtrail_mgmt.json | grep -v '<instance-private-ip>'
```

If you see the instance role used from an external IP, the entry vector is app-exploitation +
metadata theft (fix in step 10: IMDSv2, least-privilege instance roles).

---

➡️ Next: [07-adjudicate-findings.md](07-adjudicate-findings.md)

*Toolkit parallel: `cloud_dataplane.py` (`normalize_s3_data_events`) does the bulk-read/copy tiering
with the automation-vs-human FP discipline; the IAM graph feeds blast-radius scoping.*
