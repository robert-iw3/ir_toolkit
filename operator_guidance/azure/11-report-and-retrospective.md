# 11 · Report & Retrospective (Azure)

*Document it, and close the loop with preventive guardrails. Full model + the **preventive-controls
feedback loop**: [../windows/12-report-and-retrospective.md](../windows/12-report-and-retrospective.md);
cloud flavor: [../aws/11-report-and-retrospective.md](../aws/11-report-and-retrospective.md).*

---

## The report (same sections, Azure content)

Executive summary → scope (**which users, apps/SPs, subscriptions, mailboxes, data**) → timeline
(UTC, three log streams) → attack narrative (ATT&CK Cloud) → TP findings *with evidence* (the sign-in
/ audit / activity records) → adjudication funnel → remediation → IOC appendix (users, malicious
appIds, C2, inbox rules) → recommendations + coverage grid.

## Seal the evidence

Your exported logs sit in immutable (WORM) storage — record the container, versions, and who/when
(UTC).

## Close the loop — preventive guardrails (the point)

Same principle: **detection = faster next time; prevention = no next time for this vector.** Azure's
strongest guardrails are **Conditional Access** and **Azure Policy** — tenant-wide, as-code, making
attack classes impossible. Drive from the root cause (step 08):

| Root-cause vector | Preventive guardrail (tenant-wide) |
|---|---|
| Legacy/basic auth (MFA bypass) | **Conditional Access: block legacy authentication** |
| Weak/no MFA | **CA: require MFA / phishing-resistant auth**; disable per-user MFA in favor of CA |
| Illicit OAuth consent | **Restrict user consent** to verified publishers + admin-consent workflow |
| App-registration credential abuse | Restrict app creation/credential add; periodic SP credential review |
| Password spray | Smart lockout + banned passwords + sign-in-risk CA policy |
| Diagnostic/log tampering | **Azure Policy** enforcing diagnostic settings; export to Sentinel; RBAC lock on log config |
| Public exposure | Azure Policy denying public storage / open NSG rules |

**Make each a tracked, owned, verified deliverable applied at the tenant / management-group level**
(a management-group Azure Policy protects every current and future subscription), and **test it
blocks the technique** (confirm legacy auth now fails, consent is now blocked). Bake it into the
landing-zone baseline.

> **The loop:** *incident → root-cause vector → guardrail-as-code → tenant/MG-wide → verified →
> in the baseline.* A report ending at "we disabled the user" leaves the class of attack open.

## Feed detection too

Push IOCs (users, appIds, source IPs, C2) into Defender/Sentinel; add analytics for the *behavior*
(legacy-auth success, `Mail.ReadWrite` consent, external inbox-forward creation, SP credential add)
so the next variant still trips.

---

## You've completed the loop

Alert → triage → identity-first containment → preserve → collect → control-plane → identity/M365 →
adjudicate → timeline/blast-radius → eradicate → restore → report, by hand.

➡️ Other platforms: [../windows/](../windows/) · [../linux/](../linux/) · [../aws/](../aws/) ·
[../gcp/](../gcp/)
