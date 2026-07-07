# GCP — the manual operator workflow

GCP IR follows the **same cloud spine as [AWS](../aws/README.md)** — identity is the perimeter, logs
are the (time-windowed) evidence, control plane vs data plane. **Read the AWS guide for the shared
cloud reasoning**; this guide gives the GCP services, commands, and quirks (the resource **hierarchy**,
**service-account keys**, and the split **Cloud Audit Logs**).

Universal mindset: [../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md).

## GCP's evidence sources (the AWS → GCP map)

| Concept | AWS | **GCP** |
|---|---|---|
| Control-plane log | CloudTrail management | **Cloud Audit Logs — Admin Activity** (always on) |
| Data-plane log | CloudTrail data events | **Cloud Audit Logs — Data Access** (opt-in, often off) |
| Threat detector | GuardDuty | **Security Command Center (SCC)** findings |
| Identity store | IAM users/roles | **IAM** members + **service accounts** (+ SA keys) |
| Persistence credential | access key | **user-managed service-account key** |
| Network flow | VPC Flow Logs | **VPC Flow Logs** |
| Disk snapshot | EBS snapshot | **Compute disk snapshot** |
| Org-wide guardrail | SCP | **Organization Policy** + IAM Deny policies |

## GCP-specific things to know

- **Hierarchy = blast radius.** Org → Folder → Project → Resource. IAM binds at any level and
  **inherits downward**, so a role granted at the org/folder is enormous. Sweep **all accessible
  projects** (`gcloud projects list`) — attackers pivot to the project nobody watches.
- **Service-account keys are the classic persistence + exfil vector.** A `iam.serviceAccountKeys.create`
  hands the attacker a durable, downloadable credential that survives user changes.
- **Public exposure = `allUsers`/`allAuthenticatedUsers`.** A `SetIamPolicy` adding those members to
  a bucket/resource makes it world-accessible — GCP's version of a public S3 bucket.
- **Data Access logs are mostly off by default** — like AWS data events, you may be blind to reads
  unless they were explicitly enabled (a gap to record).

## The order (follow it top to bottom)

| # | Step | Focus |
|---|------|-------|
| [00](00-mindset-and-first-principles.md) | **Mindset (cloud)** | GCP hierarchy, SA keys, Cloud Audit split |
| [01](01-triage-the-alert.md) | **Triage the alert** | SCC finding / anomalous API / SA-key abuse |
| [02](02-contain-identity-first.md) | **Contain (identity-first)** | Disable the member/SA, revoke keys/sessions, isolate the VM |
| [03](03-preserve-evidence.md) | **Preserve evidence** | Logging pre-flight, window, disk snapshots, locked bucket |
| [04](04-collect-telemetry.md) | **Collect telemetry** | Admin Activity + Data Access logs, IAM, SA keys, flow logs, SCC |
| [05](05-analyze-control-plane.md) | **Analyze the control plane** | SA-key creation, IAM to allUsers, log-sink deletion, firewall opens |
| [06](06-analyze-data-plane-and-identity.md) | **Analyze data plane & identity** | Bulk object reads; SA impersonation & blast radius |
| [07](07-adjudicate-findings.md) | **Adjudicate** | Cloud trust model + automation-vs-human FP discipline |
| [08](08-timeline-and-blast-radius.md) | **Timeline & blast radius** | What the member/SA could reach across the hierarchy |
| [09](09-eradicate.md) | **Eradicate** | Delete rogue SA keys, remove IAM bindings, close exposure, block C2 |
| [10](10-restore-and-recover.md) | **Restore & recover** | Known-good, re-enable logging, close the vector |
| [11](11-report-and-retrospective.md) | **Report & retrospective** | Preventive guardrails (Org Policy, IAM Deny) |

## What you need

- `gcloud` with an **investigation role** (`roles/iam.securityReviewer` + logging/SCC viewer),
  separate from an elevated containment role.
- Know your **org / folder / project** layout and which projects have Data Access logging + SCC on.
- A **locked-down evidence bucket** (separate project, retention/bucket-lock) for exported logs.

➡️ Start: [00-mindset-and-first-principles.md](00-mindset-and-first-principles.md)

*Toolkit parallel: `WORKFLOW-CLOUD.md` / `Invoke-IRCollection-Cloud.sh --provider gcp` — Cloud Audit
logs (admin + data-access + system-event), SCC, IAM policy + SA-key inventory, firewall, flow logs.*
