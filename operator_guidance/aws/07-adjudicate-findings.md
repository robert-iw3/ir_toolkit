# 07 · Adjudicate Findings (AWS)

*Turn cloud findings into defensible verdicts. Same ladder as everywhere; cloud has its own trust
model and a specific FP discipline for automation identities.*

Shared method: [../windows/07-adjudicate-findings.md](../windows/07-adjudicate-findings.md).

---

## The verdict ladder (unchanged)

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

## The cloud trust model (how findings map to the ladder)

| Finding class | Default verdict | Why |
|---|---|---|
| Provider detector (GuardDuty) at **HIGH/CRITICAL** | **True-Positive class** | Purpose-built, high-precision detections |
| **Log/detector tampering** (`StopLogging`, `DeleteTrail`, `DeleteDetector`) | **True Positive** | No benign reason to blind the sensors mid-window |
| **Operator-supplied C2** confirmed in flow logs | **True Positive** | Asserted IOC now *observed on the wire* |
| IAM privesc / public exposure, **unambiguous** | **Likely True Positive** | Strong but may be a misconfigured deploy — verify intent |
| IAM privesc / exposure, ambiguous, or **informational/low** provider findings | **Indeterminate** | Needs analyst context |
| Bulk data read by an **automation** identity | **Indeterminate** | Routine for ETL/backup/analytics — verify |

## The context checks that move a finding

### 1 — Is the principal human or automation?

The single most important cloud FP question. A service account / assumed-role doing bulk reads,
creating resources, or calling APIs at machine speed is often **routine**. The same actions by a
**human** IAM user (especially outside business hours, from a new IP) are suspicious.

```bash
# Human users tend to have console logins + MFA devices; automation uses long-lived keys / roles
aws iam list-mfa-devices --user-name $PRINCIPAL
grep -c ConsoleLogin $CASE/evidence/triage_events.json
```

### 2 — Source IP & geo

Is the source a known corporate/VPN egress, the instance's own IP, or a random hosting-provider IP
in a country you don't operate in? Use **offline GeoIP** (don't whois the attacker's IP live).

### 3 — Is this a known deploy/automation pattern?

Before convicting an IAM change or resource creation, rule out CI/CD and IaC: does a Terraform/
CloudFormation/pipeline run explain it at that timestamp? A `CreateAccessKey` from your CI role is
different from one from a dormant human user.

### 4 — Corroboration (the multiplier)

A single signal stays weak; convergence convicts. Strong cloud convergence:
**`ConsoleLogin` no-MFA from a hosting-provider IP → `CreateAccessKey` → `AttachUserPolicy` admin →
bulk `GetObject` → `StopLogging`** is an unambiguous kill chain. Any one of those alone may be
Indeterminate.

## Worked examples

| Finding | Context | Verdict |
|---|---|---|
| `StopLogging` on the org trail | No change ticket, from an odd IP, mid-incident | **True Positive** (T1562.008) |
| Bulk `GetObject` (12k objects) by `role/etl-nightly` | Runs every night at 02:00, same volume, from VPC | **Likely FP** (automation baseline) |
| Same volume by `user/bob` at 03:00 from a VPS IP | Bob is on PTO, no MFA, new IP | **True Positive** (T1530 exfil) |
| `AttachUserPolicy` admin | Matches a Terraform apply in the pipeline log | **Likely FP** (verify the pipeline is legit) |
| Instance role `ASIA…` used from external IP | Not the instance's IP; app is internet-facing | **True Positive** (metadata cred theft) |

## Extract IOCs as you confirm

For every True / Likely True: **principals** (users/roles/keys to disable — your `Principals.json`),
**C2 IPs/domains**, **rogue resources** (attacker-created instances/keys/buckets), **exposed
resources** (public buckets, shared snapshots), and ATT&CK techniques. These feed eradication (09)
and the report (11).

---

➡️ Next: [08-timeline-and-blast-radius.md](08-timeline-and-blast-radius.md)

*Toolkit parallel: `adjudicate_cloud.py` applies this trust model + the automation-vs-human FP
discipline and emits `IOCs.json` / `Principals.json` at the analysis stage.*
