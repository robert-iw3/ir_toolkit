# 10 · Restore & Recover (AWS)

*Return the environment to known-good, re-enable what the attacker disabled, and close the entry
vector so it can't recur.*

Shared reasoning: [../windows/11-restore-and-recover.md](../windows/11-restore-and-recover.md).

---

## Step 1 — Confirm clean before you loosen containment

Re-check: no active sessions from revoked principals, no new access keys, no re-shared snapshots, no
re-opened buckets/SGs, no beacon in flow logs to the blocked C2. Anything back → you missed a
foothold; return to step 05/09.

## Step 2 — Restore known-good (minus known-bad)

- Return SGs/NACLs and bucket policies to their pre-incident state, but **keep the confirmed-C2
  blocks** and keep public access blocked.
- Rebuild any compromised instance from a **known-good AMI** (don't "clean" a compromised instance
  in place — if the app was RCE'd, re-image it), restoring data from a snapshot **predating the
  compromise window** (step 08 tells you when).
- Re-issue legitimate credentials for affected users/services (fresh keys, forced MFA re-enrollment).

## Step 3 — Re-enable and harden logging

```bash
aws cloudtrail start-logging --name <trail>
# Make the attacker's evasion harder next time:
# - Org-wide, multi-region CloudTrail with log-file validation, delivered to a locked account
# - Turn ON S3 data events (you were blind to exfil this time)
# - GuardDuty enabled in every region; Config recording on
```

## Step 4 — Close the entry vector (from your timeline)

| Entry vector | The fix that prevents recurrence |
|---|---|
| Leaked long-lived access key (repo/laptop) | Kill long-lived keys; move to short-lived roles / IAM Identity Center / OIDC federation; secret scanning in CI |
| Console login, no MFA | **Enforce MFA** org-wide via SCP; disable password-only access |
| SSRF + instance-metadata theft | **Enforce IMDSv2**; least-privilege instance roles |
| Over-permissioned principal | Least privilege; remove `*:*`; permission boundaries |
| Public bucket / shared snapshot | Account-level S3 Public Access Block; SCP denying `ModifySnapshotAttribute` to external |

## Step 5 — Watch it

Keep C2 blocks and elevated monitoring for a defined window. A cloud attacker with a leaked key may
return via a *different* key or a role you didn't fully scope — watch for the revoked principal's
name, the source IP, and the user-agent reappearing anywhere in the org.

---

➡️ Next: [11-report-and-retrospective.md](11-report-and-retrospective.md)

*Toolkit parallel: `Invoke-Eradication-Cloud.sh --restore` returns known-good state minus known-bad
C2; journaled revocations are reversible.*
