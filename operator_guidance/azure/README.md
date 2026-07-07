# Azure — the manual operator workflow

Azure IR follows the **same cloud spine as [AWS](../aws/README.md)** — identity is the perimeter,
logs are the (time-windowed) evidence, control plane vs data plane. **Read the AWS guide for the
shared cloud reasoning**; this guide gives the Azure services, commands, and the extra surface Azure
adds: **Entra ID** (identity) and **M365** (mailbox/SharePoint), where a huge share of Azure
intrusions actually live.

The universal mindset: [../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md).

## Azure's evidence sources (the AWS → Azure map)

| Concept | AWS | **Azure** |
|---|---|---|
| Control-plane log | CloudTrail | **Activity log** (resource ops) |
| Identity log | IAM + CloudTrail | **Entra sign-in logs** + **directory audit logs** |
| Threat detector | GuardDuty | **Microsoft Defender for Cloud** alerts |
| Identity store | IAM | **Entra ID** (users, apps/service principals, roles) |
| SaaS data plane | S3 data events | **M365 unified audit** (SharePoint/OneDrive/Exchange) |
| Network flow | VPC Flow Logs | **NSG flow logs** |
| Disk snapshot | EBS snapshot | **Managed disk snapshot** |
| Org-wide guardrail | SCP | **Azure Policy / Conditional Access** |

## The order (follow it top to bottom)

| # | Step | Focus |
|---|------|-------|
| [00](00-mindset-and-first-principles.md) | **Mindset (cloud)** | How Azure IR differs; Entra + M365 surface |
| [01](01-triage-the-alert.md) | **Triage the alert** | Defender/Entra risky-user/impossible-travel signal |
| [02](02-contain-identity-first.md) | **Contain (identity-first)** | Disable the Entra user, revoke sessions/tokens, isolate the VM |
| [03](03-preserve-evidence.md) | **Preserve evidence** | Diagnostic-settings pre-flight, window, disk snapshots, immutable storage |
| [04](04-collect-telemetry.md) | **Collect telemetry** | Activity log, sign-ins, directory audit, OAuth grants, inbox rules, M365 audit |
| [05](05-analyze-control-plane.md) | **Analyze the control plane** | Role assignments, NSG opens, Run Command, diagnostic-settings deletion |
| [06](06-analyze-identity-and-m365.md) | **Analyze identity & M365** | Illicit OAuth consent, inbox-forwarding rules, mass download/export |
| [07](07-adjudicate-findings.md) | **Adjudicate** | Cloud trust model + automation-vs-human FP discipline |
| [08](08-timeline-and-blast-radius.md) | **Timeline & blast radius** | What the principal + its app registrations could reach |
| [09](09-eradicate.md) | **Eradicate** | Revoke, remove app/SP credentials, kill inbox rules, close exposure |
| [10](10-restore-and-recover.md) | **Restore & recover** | Known-good, re-enable diagnostics, close the vector |
| [11](11-report-and-retrospective.md) | **Report & retrospective** | Preventive guardrails (Conditional Access, Azure Policy) |

## What you need

- `az` CLI + Microsoft Graph access (`az rest`) with an **investigation role** (Security Reader /
  Reader + log access), separate from any elevated containment role.
- Know your **tenant + subscriptions + management groups** (`az account list`) — sweep them all;
  attackers pivot to the subscription nobody watches.
- **Immutable storage** for exported logs.

➡️ Start: [00-mindset-and-first-principles.md](00-mindset-and-first-principles.md)

*Toolkit parallel: `WORKFLOW-CLOUD.md` / `Invoke-IRCollection-Cloud.sh --provider azure` — Activity
log, Entra sign-ins, OAuth grants, inbox rules, M365 unified audit, NSG flow config, disk snapshots.*
