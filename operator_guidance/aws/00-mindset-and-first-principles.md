# 00 · Mindset & First Principles (AWS / Cloud)

The universal principles hold — read
[../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md) once
(order of volatility, collect-before-judge, don't-tip-off, the verdict ladder, custody, RoE). This
page reframes them for the cloud, where there's often no host to touch.

---

## What's fundamentally different in cloud

- **The "system" is an identity.** Most cloud intrusions are a **credential** problem: a leaked
  access key, an assumed role, an over-permissioned CI token, or an OAuth app granted consent. There
  may be no malware anywhere. You investigate *what the principal did*, via the API log.
- **CloudTrail is your RAM — but only if it was recording.** The control-plane log is the primary
  evidence. Unlike RAM you don't "capture" it, but it has its own volatility: **retention windows,
  and an attacker who can `StopLogging`/`DeleteTrail`**. Confirm logging is on and preserve the logs
  early (step 03).
- **Order of volatility, cloud version:** live sessions/tokens (revocable/expiring) → recent
  CloudTrail not yet delivered to S3 → CloudTrail in S3 (retention-bound) → snapshots you take →
  config history. Session tokens and "is logging even on" are the perishable top.
- **Time is a window, not a moment.** Cloud intrusions are found late. You collect over an
  **incident window** (default a week; widen for late discovery), and normalize everything to UTC —
  which cloud logs already use (a relief after host clock-skew).
- **Blast radius is permission-shaped.** A compromised principal's reach = its IAM policies +
  everything it can `AssumeRole` into, across every region and account. "One host" thinking will
  miss most of the incident.

## Control plane vs data plane (learn this distinction)

| | Control plane | Data plane |
|---|---|---|
| Question | *Who changed what?* | *Who read/wrote how much?* |
| AWS log | CloudTrail **management** events | CloudTrail **data** events (S3 object-level) |
| Examples | `CreateAccessKey`, `AttachUserPolicy`, `StopLogging`, SG opened to `0.0.0.0/0` | bulk `GetObject`, cross-account `CopyObject` |
| Kill-chain | Persistence, priv-esc, defense evasion | Collection, exfiltration |

Data events are often **off by default** (they cost money) — if they're not enabled you may be blind
to exfil, which itself is a gap to record.

## Don't tip off the actor (cloud flavor)

- A sudden, sloppy containment (deleting the user, killing all sessions org-wide) can alert an actor
  who then burns other footholds you haven't found yet. Scope first where you can.
- **Never investigate from the compromised account's own credentials.** Use a separate
  investigation role/account so your own API calls aren't visible to (or blockable by) the actor.
- Researching the actor's C2/infra: same OSINT-safety rules as everywhere (step 08) — hashes and
  passive lookups, don't poke the live infra from a corporate/cloud IP.

## Set up your workspace

```bash
CASE="IR-$(date -u +%Y%m%d)-aws"
mkdir -p "./$CASE"/{evidence,notes}
aws sts get-caller-identity | tee "$CASE/evidence/investigator_identity.json"   # prove WHO you are
# Know your scope
aws ec2 describe-regions --query 'Regions[].RegionName' --output text | tee "$CASE/notes/regions.txt"
aws organizations list-accounts 2>/dev/null | tee "$CASE/evidence/org_accounts.json"
```

Keep a UTC-timestamped `notes/log.md` of every command and decision — your custody trail and
timeline seed.

---

➡️ Next: [01-triage-the-alert.md](01-triage-the-alert.md)

*Toolkit parallel: `Invoke-IRCollection-Cloud.sh` records `logging_status.json` and normalizes
everything to a shared schema; the clock is already UTC in cloud logs.*
