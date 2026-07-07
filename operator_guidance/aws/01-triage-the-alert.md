# 01 · Triage the Alert (AWS)

*"GuardDuty fired / the SIEM flagged odd API activity / finance sees a surprise bill / a key showed
up in a public repo — and I can't nail it down yet."*

Same goal: decide **real or noise, and how urgent** — not solve it. Shared triage logic is in
[../windows/01-triage-the-alert.md](../windows/01-triage-the-alert.md); here's the AWS first look.

---

## Extract the who/what/where/when

Cloud alerts point at an **identity** and an **API action**. Pull out:
- **Principal** — IAM user, role, or `assumed-role/...` session; the access key ID (`AKIA…`/`ASIA…`).
- **Action** — the API call(s): `CreateAccessKey`, `RunInstances`, `GetObject` at volume, `ConsoleLogin`.
- **Source** — source IP, and whether it's a known corporate/VPN egress or a random/hosting-provider IP.
- **When** — UTC (cloud logs are already UTC); and how far back it may go (widen the window later).
- **Where** — which account and region (watch for an unusual region — actors pick ones nobody uses).

## Take a light, read-only first look

```bash
CASE=IR-...; PRINCIPAL="suspicious-user"; AKID="AKIA..."

# What has this principal been doing? (CloudTrail lookup — last events)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=$PRINCIPAL \
    --max-results 50 --query 'Events[].{t:EventTime,e:EventName,src:CloudTrailEvent}' > $CASE/evidence/triage_events.json

# GuardDuty findings for context (per detector)
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id $DET --query 'FindingIds' --output text | tr '\t' '\n' | head |
    xargs -r aws guardduty get-findings --detector-id $DET --finding-ids > $CASE/evidence/gd_findings.json 2>/dev/null

# What can this principal DO? (blast-radius preview)
aws iam list-attached-user-policies --user-name $PRINCIPAL 2>/dev/null
aws iam list-user-policies --user-name $PRINCIPAL 2>/dev/null
aws iam list-access-keys --user-name $PRINCIPAL 2>/dev/null    # extra keys = a common persistence tell
```

**Read it in seconds:**
- **Source IP** from a hosting provider / unexpected country, or **`ConsoleLogin` without MFA** →
  strong signal.
- **Sensitive API calls**: `CreateAccessKey` (for another user = persistence), `AttachUserPolicy`
  with admin, `UpdateAssumeRolePolicy`, `PutBucketPolicy` public, `StopLogging`/`DeleteTrail`
  (defense evasion) → escalate.
- **A second access key** the owner didn't create, or activity from a principal that's normally
  dormant → suspicious.
- Bulk `GetObject`/`ListBucket` from a human principal → possible exfil.

> Don't disable the key or delete the user yet (unless it's actively causing damage — see step 02).
> You're looking, not acting.

## Make the triage call

- **Clear FP** — the "anomaly" is a known automation/role behaving normally, expected source →
  document, close.
- **Can't tell** (common) — odd but unproven → **open the investigation**, go to step 02.
- **Obvious active intrusion** — leaked key being used from a strange IP, resources being spun up
  (crypto-mining `RunInstances`), logging just got disabled, bulk S3 reads → **open + escalate + go
  to identity-first containment now.**

> **The urgency exception:** a *valid credential doing active damage* (mining, exfil, resource
> creation) can't wait for full collection. Snapshot what you can, then contain the identity fast
> (step 02), and finish collecting after.

---

➡️ Next: [02-contain-identity-first.md](02-contain-identity-first.md)

*Toolkit parallel: `Invoke-IRCollection-Cloud.sh` assumes the decision to collect is made and pulls
GuardDuty + CloudTrail over the window; the human triage above decides whether to run it.*
