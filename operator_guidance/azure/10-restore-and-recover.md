# 10 · Restore & Recover (Azure)

*Return to known-good, re-enable diagnostics, and close the entry vector. Shared reasoning:
[../windows/11-restore-and-recover.md](../windows/11-restore-and-recover.md) and
[../aws/10-restore-and-recover.md](../aws/10-restore-and-recover.md).*

---

## Step 1 — Confirm clean before loosening containment

No active sessions from revoked users, no re-added app credentials, no recreated inbox/forwarding
rules, no re-opened NSG rules, no beacon to the blocked C2. Anything back → missed foothold, return
to step 06/09.

## Step 2 — Restore known-good (minus known-bad)

- Re-enable legitimate users with a **forced password reset + MFA re-registration**; re-consent only
  sanctioned apps.
- Restore NSG/storage to pre-incident state but **keep the C2 blocks** and keep public access off.
- Rebuild a compromised VM from a **known-good image**, restoring data from a snapshot predating the
  compromise window (step 08).

## Step 3 — Re-enable & harden logging

Restore diagnostic settings; **export Entra sign-in/audit logs to Log Analytics/Sentinel** so you're
not limited to 7–30 day retention next time; ensure M365 unified audit is on.

## Step 4 — Close the entry vector

| Entry vector | Preventive fix |
|---|---|
| Legacy/basic auth | **Disable legacy authentication** tenant-wide (Conditional Access) |
| Weak/no MFA | **Enforce MFA / phishing-resistant auth** via Conditional Access |
| Illicit OAuth consent | Restrict user consent to verified publishers / admin-consent workflow |
| Password spray | Smart lockout, banned-password list, CA sign-in risk policies |
| App-registration abuse | Restrict who can create apps/add credentials; review SP permissions |

## Step 5 — Watch it

Keep C2 blocks + elevated monitoring; a consent-phishing attacker often returns via a *different*
user or app. Watch for the source IP, the malicious appId, and the revoked UPN reappearing anywhere
in the tenant.

---

➡️ Next: [11-report-and-retrospective.md](11-report-and-retrospective.md)
