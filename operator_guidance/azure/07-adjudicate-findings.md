# 07 · Adjudicate Findings (Azure)

*Turn findings into defensible verdicts. Same ladder and cloud trust model as
[../aws/07-adjudicate-findings.md](../aws/07-adjudicate-findings.md) — read it for the full method;
here are the Azure-specific verdict cues.*

---

## The verdict ladder & cloud trust model (unchanged)

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

- **Defender for Cloud HIGH/CRITICAL**, **diagnostic-settings deletion**, **confirmed C2 in NSG flow
  logs** → **True-Positive class**.
- Role assignment / NSG opens, **unambiguous** → Likely TP; ambiguous or informational → Indeterminate.
- Bulk M365 download/read by an **automation** identity → Indeterminate (verify).

## Azure-specific context checks

### 1 — Human vs automation vs app/service-principal

Three actor types, not two. A **service principal** doing resource ops or Graph calls at machine
speed may be a legitimate app — or a backdoored one. Check whether the SP's activity matches its
known purpose and whether its **credentials were recently added** (step 06 = strong signal it's
attacker-controlled).

### 2 — Was MFA actually satisfied, and by what?

`mfaDetail`/`authenticationRequirement` in the sign-in tells you if MFA was met. **Legacy-auth
success = no MFA possible** = strong. A "compliant" sign-in via a well-known app from a corporate IP
is likely benign.

### 3 — Known deploy / Conditional Access baseline?

Rule out IaC/pipeline: does an ARM/Bicep/Terraform run or a known admin explain the role assignment
or NSG change at that timestamp? Is the OAuth app a sanctioned first-party/ISV app?

### 4 — Corroboration (the multiplier)

Strong Azure convergence: **legacy-auth sign-in from a foreign hosting IP → OAuth consent with
`Mail.ReadWrite` → inbox forwarding rule to an external domain → mass SharePoint download**. That's
an unambiguous BEC/takeover kill chain; any one alone may be Indeterminate.

## Worked examples

| Finding | Context | Verdict |
|---|---|---|
| Diagnostic-settings deleted on the sub | No change ticket, odd IP | **True Positive** (T1562.008) |
| OAuth grant `Mail.ReadWrite` + external inbox forward | User consented after a phish, PTO | **True Positive** (BEC, T1528/T1114.003) |
| Role assignment Owner | Matches a Terraform apply from the pipeline SP | **Likely FP** (verify pipeline) |
| Bulk OneDrive download by `svc-backup` | Nightly job, same volume, corporate IP | **Likely FP** (automation baseline) |
| Client secret added to app "HR-Sync" | No deploy, added by a risky user | **True Positive** (SP persistence, T1098.001) |

## Extract IOCs

For every True / Likely True: **principals** (users, **apps/SPs**, rogue credentials → your
`Principals.json`), **C2 IPs**, **malicious OAuth appIds**, **inbox-rule details**, exposed
resources, and ATT&CK techniques.

---

➡️ Next: [08-timeline-and-blast-radius.md](08-timeline-and-blast-radius.md)
