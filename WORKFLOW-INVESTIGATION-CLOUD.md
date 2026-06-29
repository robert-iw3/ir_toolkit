# Investigation Workflow (Cloud: AWS / Azure / GCP) - from toolkit output to the chain of events

**This is the hand-off.** The platform workflow ([WORKFLOW-CLOUD.md](WORKFLOW-CLOUD.md))
**collects, normalizes, and adjudicates** - it pulls the provider's control-plane and identity
telemetry over the incident window and places every signal on the verdict ladder. **This guide is
what an IR/FR analyst then does with that output** to reconstruct *what actually happened* in the
cloud account. The toolkit does the mechanical work; the analyst does the reasoning. (For hosts, see
the companion [WORKFLOW-INVESTIGATION-LINUX.md](WORKFLOW-INVESTIGATION-LINUX.md) and
[WORKFLOW-INVESTIGATION-WINDOWS.md](WORKFLOW-INVESTIGATION-WINDOWS.md).)

### In plain terms

A host investigation asks *what got in, how, what did it do, where did it call home*. A **cloud**
investigation asks the same questions, but the battlefield is different: **there is rarely an implant
on a disk.** The attacker logs in with **valid credentials** - a leaked access key, a phished OAuth
token, a stolen service-account key - and then *uses the provider's own API* to escalate, persist,
and exfiltrate. Nothing is "infected"; the control plane is simply **driven by the wrong hands**.

So in the cloud:

> **identity is the perimeter, the API log is the crime scene, and "who did what, from where, with
> which credential" is the whole story.**

The strongest evidence is the **control-plane log** (AWS CloudTrail · Azure Activity/Entra ·
GCP Cloud Audit) and the **identity surface** (IAM users/keys/roles · Entra apps/grants · GCP service
accounts). The toolkit pulls those over a configurable window, checks the logs were even on, and
adjudicates the raw API calls into ATT&CK-mapped findings. You reason over the result.

You do **not** need access to the workload. Everything here is reasoning over files the toolkit
already produced. The flow follows the natural arc of a cloud intrusion:

> **confirm you can see → find the foothold identity → trace privilege escalation → find persistence
> → catch the defense evasion → find the exfil → build the story → contain identity, then report**

> The walkthrough below follows a **representative modern cloud account takeover** - the kind that
> dominates real cloud incidents: a leaked long-term credential, API-driven privilege escalation, a
> backdoor principal for persistence, logging switched off to cover tracks, and data staged out
> through a public bucket / shared snapshot. The same chain is shown for **all three providers**.
> Network indicators are **defanged** (`hxxp`, `[.]`) - safe at rest. Substitute your own values.

---

## What the toolkit hands you

After the cloud collection + adjudication stage, the per-incident folder (`<provider>-<target>/`)
contains:

| Artifact | What it gives the analyst |
|---|---|
| `logging_status.json` | Pre-flight: **was each control-plane log even enabled** (CloudTrail/GuardDuty/flow logs · Azure diagnostic settings/Activity · GCP sinks). A disabled source is both an evidence ceiling and a finding (T1562.008) |
| `cloud_forensics/` | Raw telemetry pulled over the window: `cloudtrail_events.json` (full management events) · `gcp_audit_log.json` · `azure_activity_log.json` · GuardDuty/SCC · flow logs · NSG/SG/firewall · Entra OAuth/inbox/directory-audit |
| `Combined_Findings_*.json` / `Adjudication_*.json` | `adjudicate_cloud.py`: every signal normalized and placed on the verdict ladder, ATT&CK-mapped - **detectors *and* raw-log behaviour** |
| `IOCs.json` | Machine-readable indicators (C2 endpoints, with `sanctioned` flag) for egress blocking + eradication |
| `Principals.json` | Implicated identities (IAM users/roles · service accounts · service principals) flagged for revocation |
| `Incident_Report.md` / `Attack_Graph.md` / `Retrospective.md` | Draft report, control-plane chain, lessons |
| `_manifest_*.json` / `_custody_*.json` | SHA-256 of every artifact + tamper-evident custody seal |

Everything below is reasoning over those files. **You should not have to re-query the account** - the
data is already gathered and sealed.

### Which part of the tool produces what - and what you do with it

| The tool does this (automatic) | ...and produces | The analyst then... |
|---|---|---|
| **Logging pre-flight** | `logging_status.json` (+ `Cloud Logging Disabled` findings) | **Step 0** - know what you can and cannot see |
| **Windowed telemetry pull** (`00_collect_forensics.sh`) | `cloud_forensics/` raw logs over `--lookback`/`--window` | the evidence base |
| **Detector normalization** (GuardDuty/SCC/Entra) | `Cloud Detection` / `Cloud Identity Risk` findings | **Step 1** - the provider's own alerts |
| **Control-plane behavioral analysis** (`normalize_cloudtrail`/`_gcp_audit`/`_azure_activity`) | `Cloud Control-Plane Activity` / `Cloud Exposure` findings | **Steps 2-5** - the attacker's actual API moves |
| **Identity/SaaS analysis** (OAuth/inbox/directory audit) | `Cloud OAuth Consent Grant` / `Inbox Forwarding Rule` / `Identity Audit` | **Step 4** - identity persistence + BEC |
| **Flow-log C2 confirmation** (`normalize_flow_logs`) | `Cloud Network Flow to C2` (True Positive) | **Step 6** - asserted → observed on the wire |
| **Correlation/adjudication** (`adjudicate_cloud.py`) | the verdict ladder across all sources | **Step 7** - separate true positives from noise |
| *(nothing - this is the human part)* | - | **Step 7** - order it into the chain of events |

So the tool **gathers and labels**; the analyst **interprets and sequences**.

---

## Golden rule: investigate passively, and assume the credential is still live

> **Do not authenticate to the account with the compromised principal, and never touch the attacker's
> infrastructure.** Do not paste a recovered C2 URL/IP into a browser, `curl`, or `dig` - that alerts
> the operator. Pivot on OSINT (VirusTotal / urlscan.io / Shodan / AlienVault OTX) using the
> **defanged** indicator, never the live host.
>
> In cloud there is a second rule: **the stolen credential may still be valid right now.** Treat
> containment (disable the principal, revoke its sessions) as urgent - but **preserve first**
> (snapshot, seal custody) so eradication doesn't destroy the timeline you're about to build.

---

## Step 0 - can you even see it? (read `logging_status.json` first)

Before any analysis, check what the account was actually recording. The pre-flight wrote one line per
source:

```json
{ "provider": "aws", "sources": [
  { "name": "CloudTrail",  "enabled": false, "detail": "no CloudTrail trail found in us-east-1" },
  { "name": "GuardDuty",   "enabled": true,  "detail": "detector det-0a1b..." },
  { "name": "VPCFlowLogs", "enabled": true,  "detail": "fl-09c2..." } ] }
```

Two readings, both important:

- **A source is off** → your evidence has a ceiling. Either it was never configured (a posture gap to
  note in the retrospective) **or the attacker disabled it** - which is itself a `Cloud Logging
  Disabled` finding and a strong defense-evasion signal. Correlate with Step 5: if CloudTrail shows a
  `StopLogging` event *and then nothing*, the silence after it is evidence, not absence.
- **Everything is on** → you can trust the window. Proceed.

> The first question in cloud IR is never "what did the attacker do" - it's "would I be able to see it
> if they had". Answer that before you trust any quiet result.

---

## Step 1 - start from the provider's own alerts (the detectors)

The detector findings are the cheapest lead. Filter `Combined_Findings_*.json` for
`Type == "Cloud Detection"` / `"Cloud Identity Risk"`:

- **AWS GuardDuty** - `UnauthorizedAccess:IAMUser/*`, `CredentialAccess:*`, `Exfiltration:*`,
  `CryptoCurrency:*`. HIGH/CRITICAL severity is true-positive class.
- **GCP Security Command Center** - `MALWARE_C2`, anomalous IAM grant, public-bucket findings.
- **Azure / Entra** - risky users (impossible travel, leaked-credential), Defender alerts.

These tell you a principal and a rough technique. They **do not** tell you the full sequence - a
detector fires on one anomaly, not the whole campaign. That is what Steps 2-6 reconstruct from the raw
log. Treat Step 1 as the thread to pull, not the answer.

---

## Step 2 - find the foothold identity and trace privilege escalation

Now read the **control-plane behaviour** findings (`Type == "Cloud Control-Plane Activity"`). These
come straight from the raw API log, so they show the attacker's hands on the keyboard. Order them by
time and look for the escalation:

| Provider | What the finding looks like | Reads as |
|---|---|---|
| **AWS** | `CreateAccessKey:victim` by `svc-deploy` from `203.0.113.9` (T1098.001) | the foothold key minted a **second** key on another user - key-based persistence + lateral identity |
| **AWS** | `AttachUserPolicy:victim (admin policy)` (T1098.003, Likely TP) | attached `AdministratorAccess` - **privilege escalation to full admin** |
| **GCP** | `attacker@evil.test - user-managed service-account key created` (T1098.001) | minted a long-lived SA key - GCP's favourite persistence primitive |
| **Azure** | `roleAssignments/write` by `guest#ext#` (T1098.003) | granted itself a privileged RBAC role |

The story so far: **a low-value credential leaked, then used the API to grant itself power.** The
`sourceIPAddress` on each event is your first infrastructure pivot - one or a few IPs/ASNs will recur
across the whole chain. Note them; they go in `IOCs.json` and the egress block.

> Console-login findings matter here too: `console login WITHOUT MFA` (T1078.004) on the foothold
> account explains *how* a leaked password alone was enough. If it's the **root** account, escalate
> immediately - root use is never routine.

---

## Step 3 - find persistence (so containment actually holds)

Eradicating the foothold key is worthless if the attacker left three more ways in. The control-plane
and identity findings enumerate them:

- **AWS** - `CreateUser` / `CreateLoginProfile` (a brand-new backdoor principal), a new access key on
  an existing user, a Lambda + EventBridge rule, an `UpdateAssumeRolePolicy` widening who can assume a
  role.
- **GCP** - `CreateServiceAccount` + `CreateServiceAccountKey`, a Cloud Function, an
  `instances.setMetadata` startup-script.
- **Azure / Entra** - `Cloud OAuth Consent Grant` (illicit consent, tenant-wide `Mail.*` = mailbox
  access without a password, T1528) · `Identity Audit: Add service principal credentials`
  (T1098.001) · `Inbox Forwarding Rule` to an external domain (BEC, T1114.003).

Cross-reference every implicated identity against `Principals.json` - that is the revocation list
Step 8 will action. **Persistence you don't find now is the re-compromise next week.**

---

## Step 4 - identity persistence + business-email-compromise (Azure / M365 path)

For tenant/SaaS intrusions the highest-value persistence is identity, and the toolkit adjudicates it
directly:

- **`Cloud OAuth Consent Grant`** - an app was consented mailbox/file/tenant scopes. Tenant-wide
  (`AllPrincipals`) consent to `Mail.Read`/`full_access_as_user` is **Likely TP**: the attacker can
  read mail or exfiltrate via Graph with no password and no MFA prompt. The app survives a password
  reset - revoke the **grant and the app**, not just the user.
- **`Inbox Forwarding Rule`** - auto-forward/redirect to an external address (and often a hide
  action). This is the BEC exfil channel; external target ⇒ Likely TP.
- **`Identity Audit`** - SP credential adds, privileged role grants, MFA/CA policy weakening,
  domain-trust changes. These are the moves that make the foothold permanent.

> A password reset does **not** evict an OAuth grant or a service-principal secret. This is the
> single most common cloud-IR mistake - close the identity persistence explicitly.

---

## Step 5 - catch the defense evasion (and read the silence)

Look for `T1562.008` findings - the attacker turning the lights off:

- **AWS** - `StopLogging` / `DeleteTrail` / `DeleteFlowLogs` / `DeleteDetector` (GuardDuty).
- **GCP** - log-sink or log-bucket deletion.
- **Azure** - `diagnosticSettings/delete`.

These are near-always malicious (Likely TP) and they're also your **timeline boundary**: events
*after* a `StopLogging` may simply not exist. Tie this back to Step 0 - if the pre-flight found a
source disabled and the log shows *who* disabled it and when, you have both the gap and its cause. The
absence of activity after the cut is not innocence; it's the cover-up.

---

## Step 6 - find the exfil and confirm the C2

Two finding classes close the "what did it do / where did it call home" questions:

- **`Cloud Exposure`** - the data was staged for removal: `PutBucketPolicy` granting public access
  (T1530) · `ModifySnapshotAttribute`/`ModifyImageAttribute` sharing a disk image to an external
  account (T1537) · `SetIamPolicy` to `allUsers` on a GCS bucket · an NSG/SG/firewall opened to
  `0.0.0.0/0`. Each is the *mechanism* by which data left or the door was propped open.
- **`Cloud Network Flow to C2`** - when you supplied `--c2-ips`, the flow-log normalizer found that IP
  actually present in VPC/NSG/firewall flow records. This upgrades the indicator from *asserted* to
  **observed on the wire** (True Positive, T1071) - proof of communication, not just suspicion.

The recurring `sourceIPAddress` from Step 2 plus any confirmed C2 IP are your egress-block set and the
core of `IOCs.json`.

---

## Step 7 - build the chain of events (the human part)

Order every true-positive-class finding by timestamp into one narrative. A representative result:

```
T+00  Valid Accounts (T1078)        leaked key 'svc-deploy' used from 203.0.113.9, no MFA
T+02  Discovery (T1087/T1526)       GetCallerIdentity, ListBuckets, ListUsers
T+05  Priv-Esc (T1098.003)          AttachUserPolicy AdministratorAccess -> victim
T+07  Persistence (T1136/T1098.001) CreateUser 'support-svc' + CreateAccessKey
T+09  Defense Evasion (T1562.008)   StopLogging on the org trail   <-- timeline boundary
T+1?  Collection/Exfil (T1530/1537) PutBucketPolicy public on 'prod-backups'; snapshot shared out
T+1?  C2 (T1071)                    flow log confirms egress to 45.66.77[.]88
```

Drop each onto the ATT&CK Cloud matrix. The empty tactics tell you what to go back and look for (e.g.
no Discovery events visible ⇒ check whether they fell after the `StopLogging` boundary). `Attack_Graph.md`
gives you the tool's first draft of this; your job is to verify each edge against the raw log and fill
the gaps.

---

## Step 8 - contain identity first, then eradicate, then restore

Hand the verdicts to the eradication orchestrator. **Order matters**: kill the identity before the
infrastructure, because the credential is what re-creates everything else.

```bash
# dry-run first (default): prints exactly what it would revoke/block, changes nothing
./Invoke-Eradication-Cloud.sh --provider aws --target 10.0.0.5 --host-folder ./aws-10_0_0_5

# then apply: revoke implicated principals (Principals.json), block known-bad C2 (IOCs.json),
# stop the workload, remove persistence - and release containment last
./Invoke-Eradication-Cloud.sh --provider aws --target 10.0.0.5 \
    --host-folder ./aws-10_0_0_5 --apply --restore
```

- Reversible revocations (key deactivate, role deny, SP disable) are **journaled** so a
  later-overturned verdict can be rolled back; irreversible ones (Lambda delete) are backed up first.
- Known-bad C2 from `IOCs.json` stays blocked across restoration.
- **Don't forget the identity persistence from Step 3/4** - OAuth grants, service-principal secrets,
  and backdoor users are not closed by stopping a VM. Confirm each `Principals.json` entry is actioned.

Then write it up: `Incident_Report.md` is the draft; the sealed `_custody_*.json` + `_manifest_*.json`
make the evidence defensible.

---

## The cloud mindset, in one line

> On a host you hunt an **implant**; in the cloud you hunt a **session**. Find the credential, trace
> what it touched through the API log, close *every* door it opened - and verify your logging was on
> the whole time.
