# 06 · Analyze Identity & M365 (Azure)

*Azure's equivalent of the AWS data-plane step — but the crown jewels here are **identity** (Entra
sign-ins, OAuth consent, app credentials) and **M365** (mailbox rules, mass download/export). This
is where most real Azure/BEC intrusions live.*

Shared framing: [../aws/06-analyze-data-plane-and-identity.md](../aws/06-analyze-data-plane-and-identity.md).

---

## Part A — Sign-in analysis (initial access & credential abuse)

From `signins.json`, hunt:

| Signal | Why | ATT&CK |
|---|---|---|
| **Legacy/basic auth success** (`clientAppUsed` = IMAP/POP/SMTP/"Other clients") | Bypasses MFA entirely | T1078.004 |
| **Impossible travel** (distant geos, short interval) | Account takeover | T1078 |
| **Failed-then-success from one IP** | Password spray/brute then access | T1110 |
| Sign-in from a **hosting-provider IP** / anomalous ASN | Attacker infra | T1078 |
| **MFA not satisfied but access granted** (CA gap) | Policy hole exploited | T1556 |

```bash
jq -r '.value[] | select(.clientAppUsed|test("IMAP|POP|SMTP|Other")) | [.createdDateTime,.userPrincipalName,.ipAddress,.clientAppUsed]|@tsv' \
    $CASE/evidence/signins.json
```

## Part B — Illicit OAuth consent grants (the modern phishing-less takeover)

An attacker tricks a user into consenting to a malicious app that gets **mailbox/file/tenant
scopes** — durable, MFA-proof access with no password. Check every recent grant:

```bash
jq -r '.value[] | [.clientId,.consentType,.scope] | @tsv' $CASE/evidence/oauth_grants.json
```

**Verdict logic:** tenant-wide (`AllPrincipals`) consent, or scopes like `Mail.Read`/`Mail.ReadWrite`/
`full_access_as_user`/`Files.ReadWrite.All` → **Likely True Positive** (T1528 / T1550.001). Other
high-risk scopes → Indeterminate. A well-known first-party app (Office, Teams) → likely benign.

## Part C — App / service-principal credential additions (persistence)

A **client secret or certificate added to an existing app registration** is durable persistence that
survives the user's password reset — a top Azure foothold. From `directory_audits.json`:

```bash
jq -r '.value[] | select(.activityDisplayName|test("Add service principal credentials|Update application.*certificates and secrets")) | [.activityDateTime,.initiatedBy.user.userPrincipalName,.targetResources[0].displayName]|@tsv' \
    $CASE/evidence/directory_audits.json
```

Any credential add you can't attribute to a legitimate deploy → **Likely True Positive** (T1098.001).

## Part D — Mailbox inbox rules (BEC exfil / evasion)

Auto-forward/redirect rules — especially to **external** domains or with a **hide/delete** action —
are the signature of business email compromise:

```bash
jq -r '.value[] | [.displayName, (.actions.forwardTo//.actions.redirectTo//"-"|tostring), (.actions.delete//false|tostring)] | @tsv' \
    $CASE/evidence/inbox_rules_$UPN.json
```

**Verdict:** external forward target or a hide/delete action → **Likely True Positive** (T1114.003);
internal-only → Indeterminate.

## Part E — Mass download / export (M365 data plane)

From the M365 unified audit: mass `FileDownloaded` (SharePoint/OneDrive), mailbox export, or
compliance-search export by a **human** principal → **Likely True Positive** (T1213 / T1567 /
T1114.002). The same **automation-vs-human FP discipline** as AWS applies — a backup/service
identity doing bulk reads is routine (Indeterminate, verify).

## Blast radius (identity-shaped)

Map what the compromised principal — and any **app/SP it controls** — could reach: directory roles,
subscription RBAC, and the mailbox/SharePoint data the OAuth scopes granted. That set is your
eradication scope and "assume-read" exposure.

---

➡️ Next: [07-adjudicate-findings.md](07-adjudicate-findings.md)

*Toolkit parallel: `normalize_signins`, plus the SaaS/identity normalizers for OAuth grants, inbox
rules, and directory audits (pytest-covered pure functions).*
