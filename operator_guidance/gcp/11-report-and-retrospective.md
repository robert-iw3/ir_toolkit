# 11 · Report & Retrospective (GCP)

*Document it, and close the loop with preventive guardrails. Full model + the **preventive-controls
feedback loop**: [../windows/12-report-and-retrospective.md](../windows/12-report-and-retrospective.md);
cloud flavor: [../aws/11-report-and-retrospective.md](../aws/11-report-and-retrospective.md).*

---

## The report (same sections, GCP content)

Executive summary → scope (**which projects/folders, principals, SAs, data**) → timeline (UTC) →
attack narrative (ATT&CK Cloud) → TP findings *with evidence* (the audit records) → adjudication
funnel → remediation → IOC appendix (principals, SA keys, C2, exposed resources) → recommendations +
coverage grid.

## Seal the evidence

Exported logs sit in a retention/bucket-locked GCS bucket — record the bucket, object generations,
and who/when (UTC).

## Close the loop — preventive guardrails (the point)

Same principle: **detection = faster next time; prevention = no next time for this vector.** GCP's
strongest guardrails are **Organization Policy** constraints and **IAM Deny policies** — org/folder-
wide, as-code, making attack classes impossible. Drive from the root cause (step 08):

| Root-cause vector | Preventive guardrail (org/folder-wide) |
|---|---|
| Leaked user-managed SA key | **Org Policy `iam.disableServiceAccountKeyCreation`**; Workload Identity Federation (keyless) |
| Public data exposure | **Org Policy `storage.publicAccessPrevention` + `iam.allowedPolicyMemberDomains`** (Domain Restricted Sharing blocks `allUsers`) |
| Over-broad IAM | Least privilege; **IAM Deny policies**; remove Owner/Editor; grant low in the hierarchy |
| Metadata token theft | Restrict metadata, minimal instance SA scopes, disable legacy metadata endpoints |
| SA impersonation abuse | Restrict `TokenCreator`/`serviceAccountUser`; periodic impersonation-grant review |
| Log tampering | Org Policy / IAM lock on log-sink config; export to a locked bucket |

**Make each a tracked, owned, verified deliverable applied at the org/folder level** (an Org Policy
at the org node protects every current and future project), and **test it blocks the technique**
(confirm SA-key creation is now denied, `allUsers` is now rejected). Bake it into the
landing-zone/Terraform baseline so new projects inherit it.

> **The loop:** *incident → root-cause vector → guardrail-as-code → org/folder-wide → verified → in
> the baseline.* A report ending at "we deleted the key" leaves the class of attack open.

## Feed detection too

Push IOCs (principals, SA keys, source IPs, C2) into SCC/SIEM; add detections for the *behavior*
(user-managed key creation, `allUsers` grant, impersonation of a privileged SA, `DeleteSink`) so the
next variant still trips.

---

## You've completed the loop

Alert → triage → identity-first containment → preserve → collect → control-plane → data-plane →
adjudicate → timeline/blast-radius → eradicate → restore → report, by hand.

➡️ Other platforms: [../windows/](../windows/) · [../linux/](../linux/) · [../aws/](../aws/) ·
[../azure/](../azure/)
