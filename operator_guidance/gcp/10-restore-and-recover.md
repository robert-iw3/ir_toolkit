# 10 · Restore & Recover (GCP)

*Return to known-good, re-enable logging, close the entry vector. Shared reasoning:
[../windows/11-restore-and-recover.md](../windows/11-restore-and-recover.md) and
[../aws/10-restore-and-recover.md](../aws/10-restore-and-recover.md).*

---

## Step 1 — Confirm clean before loosening containment

No use of revoked SA keys, no new keys, no re-added IAM bindings (check org/folder/project), no
re-opened `allUsers`, no beacon to the blocked C2. Anything back → missed foothold, return to step
05/09.

## Step 2 — Restore known-good (minus known-bad)

- Re-enable legitimate SAs/users with **fresh keys** (or, better, keyless — Workload Identity);
  re-grant only the minimal bindings they need.
- Restore firewall/IAM to pre-incident state but **keep the C2 blocks** and keep `allUsers` off.
- Rebuild a compromised instance from a **known-good image**, restoring data from a snapshot
  predating the compromise window (step 08).

## Step 3 — Re-enable & harden logging

Recreate the log sink to a **locked bucket**; **enable Data Access audit logs** (you were blind to
reads this time); ensure SCC is on org-wide.

## Step 4 — Close the entry vector

| Entry vector | Preventive fix |
|---|---|
| Leaked user-managed SA key | **Org Policy `disableServiceAccountKeyCreation`**; move to Workload Identity Federation / keyless |
| Over-broad IAM / inherited role | Least privilege; remove Owner/Editor; IAM Deny policies; scope grants low in the hierarchy |
| Public bucket (`allUsers`) | **Org Policy `enforcePublicAccessPrevention` / DRS**; restrict who can set IAM |
| Metadata token theft on a VM | Minimal instance SA scopes, restrict metadata access, disable legacy metadata |
| SA impersonation abuse | Restrict `TokenCreator`/`serviceAccountUser`; audit impersonation grants |

## Step 5 — Watch it

Keep C2 blocks + elevated monitoring; a leaked-key attacker may return via a *different* key or an
impersonation path you didn't fully scope. Watch for the source IP, the SA, and the user-agent
reappearing across projects.

---

➡️ Next: [11-report-and-retrospective.md](11-report-and-retrospective.md)
