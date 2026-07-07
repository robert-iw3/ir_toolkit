# 00 · Mindset & First Principles (Azure / Cloud)

The universal principles: [../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md).
The **shared cloud mindset** (identity is the perimeter, logs are the time-windowed evidence,
control plane vs data plane, blast radius is permission-shaped): [../aws/00-mindset-and-first-principles.md](../aws/00-mindset-and-first-principles.md).
This page adds only what's Azure-specific.

---

## What's different about Azure

- **Two planes of identity, not one.** Azure has **Entra ID** (the identity/directory — users, apps,
  service principals, roles, Conditional Access) *and* **Azure RBAC** (resource permissions on
  subscriptions). A compromise may live entirely in Entra (a consented OAuth app, a mailbox rule)
  with **no VM and no resource change at all** — and the Activity log won't show it. You must look at
  **sign-in logs, directory audit logs, and Graph** too.
- **M365 is in scope.** Most "Azure" business-email-compromise lives in **M365**: mailbox
  auto-forwarding rules, mass SharePoint/OneDrive downloads, mailbox exports. The **unified audit
  log** is where that evidence is — if it's enabled.
- **Logging is opt-in per resource.** Unlike a single CloudTrail, Azure telemetry depends on
  **diagnostic settings** configured per resource + tenant-level audit toggles. "Is logging on" is a
  per-source question (step 03), and gaps are common and are findings.
- **App registrations / service principals are the sneaky persistence.** An attacker who adds a
  **client secret or certificate** to an existing app registration gets durable, MFA-proof access
  that survives a user password reset. Always check app/SP credential additions.

## Entra vs Azure RBAC (know which you're dealing with)

| | Entra ID (directory) | Azure RBAC (resources) |
|---|---|---|
| Governs | Who you are; apps; directory roles (Global Admin) | What you can do to subscriptions/resources |
| Log | Sign-in + directory audit logs | Activity log |
| Attack | Illicit OAuth consent, inbox rules, SP creds, MFA/CA tampering | Role assignment, VM Run Command, NSG opens |

## Set up your workspace

```bash
CASE="IR-$(date -u +%Y%m%d)-azure"; mkdir -p "./$CASE"/{evidence,notes}
az account show | tee "$CASE/evidence/investigator_context.json"      # who + which tenant/sub
az account list --all -o table | tee "$CASE/notes/subscriptions.txt"  # scope — sweep them all
```

Keep a UTC-timestamped notes log. Azure logs are already UTC.

---

➡️ Next: [01-triage-the-alert.md](01-triage-the-alert.md)
