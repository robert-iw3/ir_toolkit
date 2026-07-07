# AWS — the manual operator workflow

Cloud IR is the same investigation with a different body. There is usually **no host to log into** —
the "system" is an **identity (IAM principal) and the control plane it acts through**. The evidence
isn't RAM and registry; it's **API logs** (CloudTrail), and it only exists *if logging was on
before the incident*. AWS is the reference cloud in this guide; [Azure](../azure/) and [GCP](../gcp/)
mirror it.

The universal mindset is unchanged — read [../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md)
once. What changes in cloud:

- **Identity is the perimeter.** Compromise is usually a stolen access key, an assumed role, or a
  consented app — not a binary on a disk. Containment starts by **disabling the principal and
  revoking its sessions**, not by pulling a network cable.
- **Logs are the evidence, and they're time-windowed.** CloudTrail/flow logs are your "memory" — but
  cloud intrusions surface days/weeks later, so you work over an **incident window**, and a
  **disabled log source is both a blind spot and a finding**.
- **Control plane vs data plane.** *Who changed what* (CloudTrail management events: IAM, SGs,
  snapshots) is different from *who read how much* (S3 data events: bulk `GetObject`, `CopyObject`).
  You investigate both.
- **Blast radius = what the identity could reach**, across every region/account it can touch — not
  one machine.

## The order (follow it top to bottom)

| # | Step | The question it answers |
|---|------|-------------------------|
| [00](00-mindset-and-first-principles.md) | **Mindset (cloud)** | How is cloud IR different, and how do I not destroy log evidence or tip off the actor? |
| [01](01-triage-the-alert.md) | **Triage the alert** | Is this GuardDuty/anomalous-API signal real, and how bad? |
| [02](02-contain-identity-first.md) | **Contain (identity-first)** | Disable the principal + revoke sessions, quarantine the resource — the risk calls. |
| [03](03-preserve-evidence.md) | **Preserve evidence** | Is logging even on? Set the window, snapshot disks, lock the evidence bucket. |
| [04](04-collect-telemetry.md) | **Collect telemetry** | Pull CloudTrail, IAM, flow logs, S3 data events over the window. |
| [05](05-analyze-control-plane.md) | **Analyze the control plane** | Who changed what — IAM privesc, log tampering, public exposure? |
| [06](06-analyze-data-plane-and-identity.md) | **Analyze data plane & identity** | Who read/exfiltrated how much? What did the identity touch? |
| [07](07-adjudicate-findings.md) | **Adjudicate** | Which findings are real (cloud trust model + automation-identity FP discipline)? |
| [08](08-timeline-and-blast-radius.md) | **Timeline & blast radius** | What happened, in order, and everything the principal could reach? |
| [09](09-eradicate.md) | **Eradicate** | Revoke keys/sessions, remove persistence, block C2, close exposure — reversibly. |
| [10](10-restore-and-recover.md) | **Restore & recover** | Return to known-good, re-enable logging, close the vector. |
| [11](11-report-and-retrospective.md) | **Report & retrospective** | Document it, and close the loop with preventive guardrails (SCPs, MFA, least privilege). |

## What you need on hand

- CLI access with an **investigation role** (read-heavy: `SecurityAudit` + CloudTrail/GuardDuty/S3
  read; separate elevated role for containment/eradication actions).
- Know your **org layout**: accounts, regions, whether CloudTrail is org-wide, where GuardDuty is
  enabled. Attackers pivot to the region/account nobody watches.
- A **locked-down evidence bucket** (separate account, versioned, object-locked) for exported logs.

## The golden rule (cloud edition)

**Collect the logs first, judge second, act last** — but note the cloud twist: **containment of a
live identity may need to come *before* full collection** (a valid credential doing active damage
can't wait). Snapshot the evidence you can, contain the identity fast, then complete collection.

➡️ Start: [00-mindset-and-first-principles.md](00-mindset-and-first-principles.md)

*Toolkit parallel: this is the by-hand version of `WORKFLOW-CLOUD.md` /
`Invoke-IRCollection-Cloud.sh --provider aws` / `adjudicate_cloud.py` / `cloud_dataplane.py`.*
