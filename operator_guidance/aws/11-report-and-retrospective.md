# 11 · Report & Retrospective (AWS)

*Write it down so others can trust it — and close the loop with preventive guardrails so the vector
can't recur.*

Full report structure, custody sealing, and the **preventive-controls feedback loop** are in
[../windows/12-report-and-retrospective.md](../windows/12-report-and-retrospective.md). Below is the
cloud-specific flavor.

---

## The report (same sections, cloud content)

Executive summary → severity/scope (**which accounts/regions, which identities, which data**) →
timeline (UTC) → attack narrative (ATT&CK Cloud) → true-positive findings *with evidence* (the
CloudTrail records, not assertions) → adjudication funnel → remediation → IOC appendix (principals,
C2, rogue/exposed resources) → recommendations. Attach the **ATT&CK coverage grid** so gaps are
visible.

## Seal the evidence

Your evidence is already provider-integrity-backed (S3 Object Lock, ETags, CloudTrail log-file
validation). Record the evidence bucket, object versions, and CloudTrail digest files; note who
collected and when (UTC).

## Close the loop — preventive guardrails (the point of the exercise)

Same principle as the host guides: **detection catches it faster next time; prevention makes sure
there's no next time for this vector.** In cloud, prevention is uniquely powerful because you can
enforce controls **org-wide as code** (SCPs, Config rules, IaC baselines) that make whole classes of
attack *impossible*, not just detectable. Drive each from the root-cause vector (step 08):

| Root-cause vector | Preventive guardrail (fleet-wide as code) |
|---|---|
| Leaked long-lived key | **SCP denying `iam:CreateAccessKey`** for humans; mandate IAM Identity Center / OIDC short-lived creds; CI secret scanning |
| No-MFA console access | **SCP / IAM policy requiring MFA**; disable password-only login org-wide |
| SSRF → metadata theft | **SCP enforcing IMDSv2** (`ec2:MetadataHttpTokens=required`); least-privilege instance roles |
| Log tampering | **SCP denying `cloudtrail:StopLogging`/`DeleteTrail`/`guardduty:DeleteDetector`** to everyone but a break-glass role; org-managed trail |
| Public data exposure | **Account-level S3 Public Access Block via SCP**; SCP denying external snapshot sharing |
| Over-permission | Permission boundaries, access-analyzer-driven right-sizing, remove `*:*` |

**Make each guardrail a tracked, owned, verified deliverable, applied at the org/OU level** (an SCP
on the org root protects every current and future account), and **test that it blocks the
technique** (confirm a no-MFA login now fails, `StopLogging` is now denied). Bake it into the
landing-zone / account-baseline so new accounts are born with it.

> **The loop:** *incident → root-cause vector → guardrail-as-code → org-wide (SCP/Config/IaC) →
> verified → in the account baseline.* A report that ends at "we revoked the key" leaves the door
> open; the org only gets stronger when the incident permanently closes the class of attack.

## Feed detection too

Push confirmed IOCs (principals, source IPs, user-agents, C2) into GuardDuty/SIEM; add custom
CloudTrail/Config detections for the *behavior* you saw (e.g., `CreateAccessKey` by a human for
another user; instance role used off-instance) so the next variant still trips.

---

## You've completed the loop

Alert → triage → identity-first containment → preserve → collect → control-plane → data-plane →
adjudicate → timeline/blast-radius → eradicate → restore → report, by hand. The automated
`WORKFLOW-CLOUD.md` will now read like old friends.

➡️ Other platforms: [../windows/](../windows/) · [../linux/](../linux/) · [../azure/](../azure/) ·
[../gcp/](../gcp/)

*Toolkit parallel: `generate_reports` (report/timeline/attack-graph/coverage/IOCs),
`correlate_campaign.py` (cross-account), Terraform-provisioned locked evidence bucket. The
guardrail loop is the analyst judgment the automation leaves to you.*
