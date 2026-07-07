# 08 · Timeline & Blast Radius (Azure)

*Order the story and map everything the identity — and any app it controls — could reach. Shared
method: [../aws/08-timeline-and-blast-radius.md](../aws/08-timeline-and-blast-radius.md).*

---

## Step 1 — Timeline (UTC, from three log streams)

Merge **sign-in logs** (identity), **directory audit** (identity changes), and **Activity log**
(resource ops) into one UTC line. Label activity vs detection time.

```
2026-06-28T22:10Z  Sign-in bob@contoso  clientApp=IMAP (legacy!)  src 185.x.x.x (VPS)    ← initial access (MFA bypass)
2026-06-28T22:14Z  Consent to app "MailTool" scopes Mail.ReadWrite                       ← illicit consent
2026-06-28T22:16Z  Inbox rule "  " forward→attacker@evil.tld, delete                     ← BEC exfil + hide
2026-06-28T22:40Z  Add service principal credentials on app "HR-Sync"                    ← durable persistence
2026-06-29T00:10Z  roleAssignments/write → Owner on sub-prod                             ← priv-esc
2026-06-29T01:30Z  diagnosticSettings/delete                                             ← evasion (blind after)
```

## Step 2 — Cloud kill chain + coverage grid

Map to ATT&CK Cloud; blank tactics are gaps. Common Azure gap: you see the takeover but not **how
the token/credential leaked** (phish → consent? legacy-auth spray? token theft from a device?) —
chase it; it sets the preventive control (step 11).

## Step 3 — Blast radius (identity + app-shaped)

The scope = everything the principal **and every app/SP it controls** could reach:
- **Entra directory roles** (Global Admin = everything) and **Azure RBAC** across all subscriptions.
- **OAuth scopes** granted to consented apps = the mailbox/SharePoint/tenant data reachable *without*
  the user (the app's token is its own credential).
- **App-registration credentials** the attacker added = independent persistent access.

Produce the concrete list of accounts, apps/SPs, subscriptions, and M365 data in scope — that's your
eradication scope and "assume-read" exposure.

## Step 4 — Campaign scope

Check the source IP / user-agent / consented appId across **all users and subscriptions** — consent
phishing and password spray hit many identities at once. Sweep the tenant.

---

➡️ Next: [09-eradicate.md](09-eradicate.md)
