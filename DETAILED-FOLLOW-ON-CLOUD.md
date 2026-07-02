# Detailed Follow-On Investigation — Cloud

Generic playbook for pivoting from IR Toolkit cloud output into control-plane triage across AWS, Azure, and GCP.

> **Living document.** This guide is continuously revised as investigations surface new FP patterns, additional attack vectors, and investigative shortcuts. The long-term goal is for every section here to become an automated playbook step — commands, logic branches, and disposition rules encoded into the toolkit itself.

---

## How to use this guide

```
Step 1 — Read the toolkit reports (per provider/target under reports/<provider>-<id>/)
    Combined_Findings_<stamp>.json  <- adjudicated findings + verdict ladder
    Incident_Report.md              <- human summary
    Attack_Coverage_<stamp>.md      <- ATT&CK Cloud coverage grid (which tactics were seen)

Step 2 — Pivot here
    For each Open/Suspicious finding, find the matching section by its Type.
    Run the provider CLI commands (read-only) to expand the lead.

Step 3 — Follow the rabbit hole
    Each section ends with a decision branch: discard as FP, or pivot deeper.
    The control plane IS the crime scene — every action leaves a log entry;
    walk the actor's session from first call to last.

Step 4 — Document and close
    Update disposition per finding. Confirmed TPs feed the identity-first
    response playbooks (Section 12).
```

**Cloud IR is identity-first.** Unlike host IR, there is no memory to carve — the evidence is the **control-plane log** (CloudTrail / Azure Activity+Entra / GCP Cloud Audit). The unit of compromise is a **principal** (IAM user/role, Entra user/service principal, GCP service account), not a process. Contain the identity before the resource.

**The engine:** `Invoke-IRCollection-Cloud.sh` → `collect/<provider>.sh` (read-only API pulls) → `adjudicate_cloud.py` (normalizes raw logs into scored findings on a shared verdict ladder) → reporting. Deployable via `docker/` (the container ships exactly this cloud workflow).

**Finding Types produced (each maps to a section):**

| Type | Section |
|------|---------|
| Cloud Control-Plane Activity | 1 |
| Cloud IAM Posture | 2 |
| Cloud OAuth Consent Grant | 3 |
| Cloud Inbox Forwarding Rule | 4 |
| Cloud Sign-In / Cloud Identity Risk / Cloud Identity Audit | 5 |
| Cloud Detection (GuardDuty / Defender / SCC) | 6 |
| Cloud Exposure | 7 |
| Cloud Network Flow to C2 / Cloud C2 Beacon | 8 |
| Cloud Logging Disabled | 9 |

Verdict ladder (shared across providers): **False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive**. A finding at *Indeterminate* or above is what you triage here.

---

## Prerequisites

- **Read-only credentials** for triage: AWS `SecurityAudit` + `ViewOnlyAccess`, Azure `Reader` + `Security Reader` + Entra `Global Reader`, GCP `roles/iam.securityReviewer` + `roles/logging.viewer`.
- **Response** (Section 12) needs write scopes — keep those on a separate break-glass principal, used only after a TP is confirmed.
- Investigate from a **known-clean workstation** with its own audited principal — never reuse the possibly-compromised identity.
- CLIs authenticated: `aws sts get-caller-identity`, `az account show`, `gcloud auth list`. Note the region/subscription/project scope — findings are scoped, and attackers hide in unmonitored regions/projects (Section 10).

---

## 1 — Control-Plane Activity Triage

Toolkit signal: `Cloud Control-Plane Activity` — an adjudicated API action from the audit log (privilege change, key creation, resource tamper) mapped to an ATT&CK Cloud technique. This is the backbone of cloud IR: reconstruct the actor's session.

```bash
# --- AWS: pull the actor's full session around the flagged event ---
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<principal> \
  --start-time 2026-06-25T00:00:00Z --end-time 2026-07-01T00:00:00Z \
  --query 'Events[].{t:EventTime,n:EventName,src:CloudTrailEvent}' --output json
# Pivot on the source IP / access key seen in the flagged event:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... --output json

# --- Azure: the caller's activity + Entra audit ---
az monitor activity-log list --caller <upn-or-appid> \
  --start-time 2026-06-25 --end-time 2026-07-01 -o json
az rest --method GET --url \
  "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=initiatedBy/user/userPrincipalName eq '<upn>'"

# --- GCP: the principal's audit trail ---
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="<sa-or-user>@..."' \
  --freshness=7d --format=json --project <project>
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `CreateAccessKey` / `Add-owner` / `serviceAccountKeys.create` by a user who never does this | Persistence via new long-lived credential | TP; Section 12 disables the key + principal; enumerate what the key did next |
| `AttachUserPolicy AdministratorAccess` / role assignment to `Owner` / `setIamPolicy` adding a role | Privilege escalation | TP; Section 11 (reachability) to see what the new privilege unlocks |
| `ConsoleLogin`/`sign-in` from a new ASN/country immediately before the action | Session hijack or stolen creds | Correlate with Section 5 (sign-in risk); confirm not a VPN/relocation |
| Action is by a CI/automation role from its normal IP, matching its normal pattern | Routine automation | FP after confirming the principal is the known automation identity and IP/pattern match |
| `GetCallerIdentity` / `Describe*` / `List*` bursts only | Reconnaissance (or normal tooling) | Discovery is low-signal alone; escalate only if paired with a mutating action |
| `StopLogging` / `DeleteTrail` / diagnostic-setting delete | Defense evasion — blinding the log | TP; Section 9; treat the following period as evidence-gap |
| Action succeeded but `errorCode` present on earlier attempts | Actor probing permissions before succeeding | Walk the failed→succeeded sequence to scope intent |

**Session-walk method:** take the flagged event's `(principal, access key/session, source IP)` and pull *every* call sharing any of those three. That reconstructs the intrusion timeline — recon → privesc → persistence → collection → exfil — which is what feeds the coverage grid and the response scope.

---

## 2 — IAM Posture

Toolkit signal: `Cloud IAM Posture` — from the AWS credential report / Access Analyzer, GCP IAM policy + SA keys, Azure role assignments. Standing weaknesses an attacker uses or created.

```bash
# --- AWS: credential report + external-access analyzer ---
aws iam generate-credential-report >/dev/null; sleep 3
aws iam get-credential-report --query Content --output text | base64 -d
aws accessanalyzer list-findings --analyzer-arn <arn> \
  --query 'findings[?status==`ACTIVE`]'
# For a suspect user: keys, MFA, attached policies
aws iam list-access-keys --user-name <u>
aws iam list-attached-user-policies --user-name <u>

# --- GCP: who has what, and long-lived SA keys ---
gcloud projects get-iam-policy <project> --format=json
for sa in $(gcloud iam service-accounts list --format='value(email)'); do
  gcloud iam service-accounts keys list --iam-account="$sa" \
    --managed-by=user --format='value(name,validAfterTime)'
done

# --- Azure: privileged role assignments ---
az role assignment list --all --include-inherited \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']" -o table
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| User-managed SA key / AWS access key older than policy allows, still active | Long-lived credential = theft/persistence surface | Check the key's recent use (Section 1); rotate; if unused, disable |
| Access Analyzer: resource shared with an external account/`*` principal | Data/role exposed cross-account | Confirm the external principal is an intended partner; if not, TP |
| IAM binding grants `roles/owner`/`AdministratorAccess` to a broad or unexpected member | Excess privilege or attacker-added grant | Correlate creation time with Section 1; recent add = TP |
| MFA disabled on a privileged human user | Account-takeover risk | Not an incident alone; flag for hardening; escalate if that user shows risky sign-ins (Section 5) |
| Root/management-account access key exists | Should essentially never exist | High severity; verify + remove |
| Service account with owner on the whole project | Over-privileged automation | If the SA was recently keyed/used anomalously → TP; else hardening item |

---

## 3 — OAuth Consent Grant

Toolkit signal: `Cloud OAuth Consent Grant` (Azure/Entra `oauth2PermissionGrants`, GCP OAuth) — an app was granted delegated/application permissions to tenant data. The illicit-consent-grant attack persists **without credentials**.

```bash
# --- Azure/Entra: enumerate grants, focus on high-privilege scopes ---
az rest --method GET --url \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -o json
# Resolve the app behind a grant:
az ad sp show --id <clientId> --query "{name:displayName,appId:appId,publisher:publisherName}"
# App-role (application) permissions (the dangerous kind — no user needed):
az rest --method GET --url \
  "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/appRoleAssignments"
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Grant includes `Mail.Read`/`Mail.ReadWrite`/`Files.ReadWrite.All`/`Directory.ReadWrite.All` to a non-Microsoft, recently-registered app | Illicit consent grant — mailbox/file/directory access as persistence | TP; Section 12 revokes the grant + disables the SP; enumerate what the app accessed |
| `AppRoleAssignment` (application permission) consented by an admin to an unknown app | Tenant-wide data access with no user sign-in required | TP; highest priority — this survives password resets and MFA |
| Grant to a well-known first-party or vetted SaaS app | Sanctioned integration | FP after confirming the app against the approved-app inventory |
| Grant consented by a single user (delegated, low scope like `User.Read`) | Normal app onboarding | Low signal; confirm scope is minimal |
| Consent timestamp inside the compromise window | Attacker-established persistence | TP; correlate with the consenting identity's other activity (Section 1/5) |

---

## 4 — Inbox Forwarding / Mailbox Rules

Toolkit signal: `Cloud Inbox Forwarding Rule` (Entra/Graph mailbox rules) — auto-forwarding or hidden rules used for BEC exfil and to hide attacker replies.

```bash
# Per-mailbox message rules (Graph)
az rest --method GET --url \
  "https://graph.microsoft.com/v1.0/users/<upn>/mailFolders/inbox/messageRules" -o json
# Tenant-wide external auto-forward posture (via Exchange Online PowerShell if available)
# Get-TransportRule | ? {$_.RedirectMessageTo}; Get-HostedOutboundSpamFilterPolicy
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Rule forwards to an **external** domain | Mail exfil (BEC) | TP; capture the target address; disable the rule; check what was already forwarded |
| Rule moves messages containing "invoice/payment/wire/password" to Archive/RSS/Deleted | Attacker hiding replies during fraud | TP; classic BEC concealment |
| Rule created by a sign-in from a risky/new location (Section 5) | Post-compromise mailbox manipulation | TP; correlate with the sign-in and any OAuth grant (Section 3) |
| Rule forwards internally to the user's own delegate/assistant | Legitimate delegation | FP after confirming the recipient is an intended internal delegate |
| Vendor/helpdesk rule filing tickets to a folder | Normal automation | FP after confirming the rule's origin |

---

## 5 — Sign-In & Identity Risk

Toolkit signals: `Cloud Sign-In`, `Cloud Identity Risk`, `Cloud Identity Audit` (Entra sign-in/risky-user logs, and equivalent console-login events elsewhere).

```bash
# --- Azure/Entra: risky sign-ins + risky users ---
az rest --method GET --url \
  "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskLevelDuringSignIn ne 'none'" -o json
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" -o json

# --- AWS: console logins + MFA state from CloudTrail ---
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --output json \
  | jq '.Events[].CloudTrailEvent|fromjson|{t:.eventTime,ip:.sourceIPAddress,mfa:.additionalEventData.MFAUsed,res:.responseElements.ConsoleLogin}'

# --- GCP: console/login + token grants in audit log ---
gcloud logging read 'protoPayload.methodName=~"Login|GenerateAccessToken"' --freshness=7d --format=json
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Sign-in `riskLevel=high`, impossible travel, or new ASN + immediate privileged action | Account takeover in progress | TP; Section 12 (revoke sessions + reset); walk the session (Section 1) |
| Console login with `MFAUsed=No` on a privileged account | MFA gap exploited or not enforced | Escalate; confirm whether MFA is required by policy |
| Burst of failed logins then a success | Password spray / brute force that landed | TP; the success is the foothold — pivot to its session |
| Legacy-auth / non-interactive sign-in from an automation IP | Service/automation login | FP after confirming the IP/app is the known automation |
| Risky user flagged but sign-ins all from corporate ranges | Possibly stale risk signal or VPN | Indeterminate; corroborate with actual actions before escalating |
| Token generation (`GenerateAccessToken`, service-account impersonation) by an unusual principal | SA impersonation for privilege abuse | TP; Section 11 reachability from the impersonated SA |

---

## 6 — Provider Detections (GuardDuty / Defender / SCC)

Toolkit signal: `Cloud Detection` — normalized from AWS GuardDuty, Microsoft Defender for Cloud, and GCP Security Command Center. The toolkit re-adjudicates these onto the shared ladder (High/Critical active → Likely TP) rather than trusting severity blindly.

```bash
# --- AWS GuardDuty ---
aws guardduty list-detectors --query DetectorIds --output text | \
  xargs -I{} aws guardduty list-findings --detector-id {} \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}'
aws guardduty get-findings --detector-id <id> --finding-ids <fid>

# --- Azure Defender for Cloud ---
az security alert list --query "[?properties.status=='Active']" -o json

# --- GCP Security Command Center ---
gcloud scc findings list <org-or-project> \
  --filter="state=\"ACTIVE\" AND severity=\"HIGH\"" --format=json
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| GuardDuty `UnauthorizedAccess:IAMUser/*`, `CredentialAccess:*`, `Exfiltration:*` active | Provider caught credential/exfil abuse | TP; use the finding's resource + principal to seed Section 1 session walk |
| Defender/SCC High+ active on a resource that also appears in a control-plane finding | Two independent sources agree | Strong TP; prioritize |
| Detection is `Recon:*`/`Discovery:*` only | Scanning/enumeration | Low signal alone; escalate if paired with a mutating action |
| Detection references a resource you can't correlate to any activity | Possibly stale or another team's testing | Indeterminate; confirm resource ownership before acting |
| Sample/benign finding (provider test finding) | Not real | FP — GuardDuty/SCC emit sample findings; check the finding id/type |
| Detection resolved/archived by another responder | Already handled | Confirm disposition before duplicating work |

---

## 7 — Exposure (public resources & network)

Toolkit signal: `Cloud Exposure` — public S3 buckets, public EBS snapshots / AMIs, permissive security groups / NSGs / firewall rules, and IMDSv1-enabled instances (SSRF→credential theft, T1552.005).

```bash
# --- AWS ---
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | \
  while read b; do echo "$b: $(aws s3api get-bucket-policy-status --bucket "$b" \
    --query PolicyStatus.IsPublic 2>/dev/null)"; done
aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids self --query 'Snapshots[].SnapshotId'
aws ec2 describe-images --owners self --filters Name=is-public,Values=true --query 'Images[].ImageId'
aws ec2 describe-instances --filters Name=metadata-options.http-tokens,Values=optional \
  --query 'Reservations[].Instances[].InstanceId'   # IMDSv1 allowed
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].GroupId'

# --- Azure NSG / GCP firewall ---
az network nsg list --query "[].securityRules[?access=='Allow' && sourceAddressPrefix=='*']" -o json
gcloud compute firewall-rules list --filter="sourceRanges=(0.0.0.0/0)" --format=json
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Public bucket/snapshot/AMI containing real data | Data exposure or attacker-staged public share for exfil | TP; check *when* it went public (Section 1 for the `Put*Acl`/`ModifySnapshotAttribute` event) and by whom |
| Snapshot/AMI made public inside the compromise window | Deliberate exfil via public share | TP; the actor is in the control-plane log — pivot to their session |
| IMDSv1 enabled instance reachable + an SSRF-able app | Credential-theft path (steal role creds via metadata) | Escalate; enforce IMDSv2; check CloudTrail for the instance role's creds used off-instance |
| Security group / NSG / firewall `0.0.0.0/0` to 22/3389/db ports | Management/DB exposed to the internet | TP if exposing sensitive ports; check for logins from the internet since it opened |
| Public bucket is a known static-website / CDN origin by design | Intended public content | FP after confirming it's a designed public asset with no sensitive data |
| Broad rule is a pre-existing baseline finding (not recently changed) | Standing misconfig, not an incident | Hardening item; escalate only if change correlates with the intrusion window |

---

## 8 — Network Flow to C2 / C2 Beacon

Toolkit signals: `Cloud Network Flow to C2`, `Cloud C2 Beacon` — from VPC/NSG/VPC flow logs correlated against supplied C2 IOCs, plus periodicity analysis for beaconing.

```bash
# --- AWS VPC flow logs (via CloudWatch Logs) ---
aws logs filter-log-events --log-group-name <vpc-flow-lg> \
  --filter-pattern "203.0.113.10" --start-time <epoch_ms>

# --- Azure NSG flow logs / GCP VPC flow logs ---
# az network watcher flow-log show ... ; then query the storage/Log Analytics workspace
gcloud logging read 'logName=~"vpc_flows" AND jsonPayload.connection.dest_ip="203.0.113.10"' \
  --freshness=7d --format=json
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Flow to a known C2 IP from a workload instance | Compromised instance beaconing | TP; identify the instance's role; check for that role's creds used in the control plane (pivot-to-cloud) |
| Regular, fixed-interval small flows to one external IP | Beaconing (C2 heartbeat) | TP even without an IOC match — periodicity is the signal; capture dest + instance |
| Large sustained outbound to an unknown IP/region | Data exfil | TP; correlate with public-share exposure (Section 7) and the instance's data access |
| Flow to a CDN / vendor API / package mirror | Normal egress | FP after confirming the destination owner |
| Beacon-like pattern to a monitoring/telemetry endpoint | Agent check-in | FP after confirming the agent + endpoint |
| Flow log coverage missing for the region/VNet | Blind spot | Note the gap; enable flow logs; the absence is itself a finding-adjacent risk |

---

## 9 — Logging Disabled (defense evasion)

Toolkit signal: `Cloud Logging Disabled` — CloudTrail stopped/deleted, Azure diagnostic settings removed, GCP audit sink deleted/log exclusion added. The attacker blinding the very source this workflow reads.

```bash
# AWS: trail status + who changed it
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Multi:IsMultiRegionTrail}'
aws cloudtrail get-trail-status --name <trail> --query '{Logging:IsLogging,Stopped:LatestDeliveryError}'
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventName,AttributeValue=StopLogging --output json

# Azure: diagnostic settings present?  GCP: audit sinks + exclusions
az monitor diagnostic-settings subscription list -o json
gcloud logging sinks list; gcloud logging read 'protoPayload.methodName="DeleteSink"' --freshness=30d
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `StopLogging`/`DeleteTrail`/diag-setting delete/sink delete inside the window | Deliberate evasion | TP; the responsible principal is in the log *up to* that event — pivot to their session (Section 1); treat the following period as an evidence gap |
| Logging currently off, no clear change event | Was off before, or the disabling call itself wasn't logged | High severity; reconstruct from any surviving source (provider detections, flow logs, billing) |
| Diagnostic/sink change by a platform automation (Terraform/landing-zone) | IaC reconfiguration | FP after matching the change to a known IaC run + approver |
| Logging on and healthy | No evasion | Close |
| Multi-region trail reduced to single-region | Narrowing coverage to hide activity in other regions | Investigate the other regions (Section 10); TP if it correlates with activity there |

---

## 10 — Cross-Region / Cross-Account / Cross-Project Sweep

Attackers operate in the regions/accounts/projects you don't watch. Collection is scoped; widen it when a TP is found.

```bash
# AWS: enumerate regions, re-run lookup in each; enumerate org accounts
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="; aws cloudtrail lookup-events --region "$r" \
    --lookup-attributes AttributeKey=Username,AttributeValue=<principal> --max-results 5
done
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name}'

# GCP: sweep all projects the principal can touch
gcloud projects list --format='value(projectId)' | while read p; do
  echo "== $p =="; gcloud logging read \
    'protoPayload.authenticationInfo.principalEmail="<sa>@..."' --project "$p" --freshness=7d --limit=5
done

# Azure: all subscriptions
az account list --query "[].{name:name,id:id}" -o table
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Same principal active in a region/project with no workloads | Attacker using an unmonitored area (e.g. crypto-mining, staging) | TP; expand collection there; the region choice itself is an IOC |
| New resources (instances, functions, keys) in an unused region/project | Attacker-provisioned infrastructure | TP; enumerate + include in eradication scope |
| Activity confined to expected regions/projects | Scope is complete | Continue with the known scope |
| Cross-account role assumption (`AssumeRole` into another org account) | Lateral movement across accounts | Follow the chain into the target account; repeat this guide there |

---

## 11 — Principal Reachability (privilege-escalation paths)

Toolkit tool: `principal_reachability.py` — from an IAM policy graph, computes what a principal can *reach* (which roles it can assume, which permissions escalate to admin). Use it to scope the blast radius of a compromised or newly-privileged identity.

```bash
# Reads the collected IAM policy from the host-folder; principals default to Principals.json
python3 playbooks/cloud/principal_reachability.py \
  --host-folder reports/<provider>-<id>/ \
  --principals <arn-or-email-or-objectid>[,<more>] \
  --incident-id <id>
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Compromised principal can reach `Admin`/`Owner` via a role-chain | Full-tenant blast radius | Contain every hop in the chain, not just the entry principal (Section 12) |
| Principal can create/modify IAM (`iam:*`, `setIamPolicy`) | Self-escalation capability | Treat as admin-equivalent even if not currently admin |
| Principal can assume a role that can assume another (transitive) | Multi-hop lateral path | Map the full chain; each hop is an eradication target |
| Principal is tightly scoped (read-only, single service) | Limited blast radius | Contain the principal; lower urgency on lateral movement |
| A newly-added grant (Section 1) opens a new reachable admin path | The privesc the attacker was setting up | Confirms intent; TP; remove the grant + rotate |

---

## 12 — Identity-First Response Pivot

Numbered, analyst-gated playbooks. They are **env-var driven and default to `IR_DRY_RUN=1`** — they print planned actions and change nothing until you set `IR_DRY_RUN=0`. Contain the **identity** before the resource. Common vars: `IR_CLOUD_PROVIDER` (aws|azure|gcp), `IR_INCIDENT_ID`, `IR_CONTAIN_PRINCIPALS` (comma-separated principals to contain), `IR_GCP_PROJECT` / `IR_AZURE_SUBSCRIPTION` as needed. Artifacts + rollback journal live under `/tmp/ir/<incident>/`.

```bash
# 0. Preserve control-plane evidence (export the relevant log slices) BEFORE changes
IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> ./playbooks/cloud/00_collect_forensics.sh

# 1. Contain identity: disable keys/sessions, block sign-in, revoke tokens for the principal(s)
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> \
  IR_CONTAIN_PRINCIPALS="user/attacker,role/stolen" \
  ./playbooks/cloud/01_contain_identity.sh

# (host-side, if a specific VM/instance is implicated)
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> IR_TARGET=<ip-or-name> \
  ./playbooks/cloud/01_contain_host.sh

# 2. Eradicate process/compute: stop/isolate attacker-provisioned instances/functions
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> IR_TARGET=<resource> \
  ./playbooks/cloud/02_eradicate_process.sh

# 3. Eradicate persistence: remove attacker IAM grants, keys, OAuth consents, forwarding rules
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> \
  ./playbooks/cloud/03_eradicate_persistence.sh

# 4. Block C2: security-group/NSG/firewall egress deny + DNS controls for recovered C2
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> ./playbooks/cloud/04_block_c2.sh

# 5. Restore: reverse containment once clean (rollback journal)
IR_DRY_RUN=0 IR_CLOUD_PROVIDER=<p> IR_INCIDENT_ID=<id> ./playbooks/cloud/05_restore_host.sh
```

**Logic breakdown — response:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Dry-run lists the expected principal/keys/grants | Plan correct | Re-run with `IR_DRY_RUN=0` |
| After key disable, the principal still acts | It has other credentials (another key / active session / SAML) | Revoke *all* sessions + keys; check reachable roles (Section 11) it may have pivoted to |
| Persistence removed but a new admin grant reappears | A second persistence path (another principal/OAuth app) is re-adding it | Re-sweep Sections 2/3; contain the *re-granting* identity |
| OAuth consent revoked but mailbox access continues | App had application (not delegated) permission, or another grant exists | Disable the service principal entirely, not just the grant |
| Block-C2: 0 rules changed | No C2 IOCs collected yet | Run Section 8 first; feed IOCs, re-run |
| Restore journal mismatch | State changed since containment | Manual review before restoring |

**Prerequisites before response:**
- Control-plane evidence exported (`00_collect_forensics.sh`).
- Full session walked (Section 1) — you know every action the principal took.
- Reachability mapped (Section 11) — you know the blast radius and every hop to contain.
- Cross-region/account/project sweep done (Section 10) — scope is complete.
- Every finding closed as FP or escalated to TP.

---

## Quick Reference: Common FP Patterns

| Signal | Common FP explanation | Confirm or clear |
|--------|----------------------|-----------------|
| `Control-Plane Activity` — key/role change by a CI role | Terraform/CD pipeline doing its normal job | FP if principal = known automation, IP + action pattern match the pipeline |
| `Sign-In` risk from a new country | Employee travel / corporate VPN egress | FP after confirming with the user / VPN egress ranges |
| `IAM Posture` — MFA disabled on a service account | Service accounts don't use interactive MFA | FP for non-human identities; focus MFA findings on human users |
| `Exposure` — public bucket | Intentional static-site/CDN origin | FP if it's a designed public asset with no sensitive data |
| `Detection` — GuardDuty/SCC sample finding | Provider-emitted test finding | FP — identify by the sample finding id/type |
| `OAuth Consent Grant` to a first-party/approved app | Sanctioned SaaS integration | FP after matching against the approved-app inventory |
| `Inbox Forwarding` to an internal delegate | Legitimate assistant/delegate rule | FP after confirming the recipient is intended + internal |
| `Network Flow` beacon to a telemetry endpoint | Monitoring agent check-in | FP after confirming the agent + destination owner |
| `Logging Disabled` diag-setting change by IaC | Landing-zone/Terraform reconfiguration | FP after matching to a known IaC run + approver |
| `Control-Plane` `Describe*`/`List*` bursts | Backup/inventory/CSPM tooling scanning | FP if principal is a known posture/inventory tool; escalate only if paired with mutation |
| `IAM Posture` broad rule that predates the incident | Standing misconfiguration | Hardening backlog item, not an incident, unless changed in-window |