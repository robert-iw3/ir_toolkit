# 10 · Eradicate

*Evidence is secured, the story is understood. Now remove the threat — completely, reversibly, and
in the right order.*

---

## The situation

Eradication is the first genuinely *destructive* phase. Everything until now was read-only. Now
you kill processes, delete files, disable accounts, and cut C2. Two mistakes end investigations
badly: **missing a persistence tail** (it comes right back), or **breaking something you can't
undo** (and can't prove you were right). So you work from your confirmed-TP list, you keep a
rollback journal, and you do it in an order that doesn't let the implant respawn mid-cleanup.

> **Do it dry-run first.** Write out every action you *intend* to take and review the list before
> executing anything. The automation defaults to dry-run for exactly this reason.

---

## The order matters (or the implant respawns)

Kill the *reanimation* before the *body*. If you delete the payload but leave the scheduled task,
it redownloads; if you kill the process but leave the service, it restarts.

```
1. Cut C2 (now you've learned where it goes)     5. Kill running malicious processes
2. Disable persistence (tasks/services/WMI/Run)  6. Quarantine the files
3. Disable implicated accounts                   7. Remove/undo tamper (exclusions, WDigest)
4. Revoke/rotate credentials                     8. Re-verify nothing respawned
```

---

## Step 1 — Cut C2 egress (finally)

You kept outbound open to *learn* the C2 (step 02). Now block the confirmed endpoints from your
IOC list — surgically, so you don't blackhole legitimate traffic.

```powershell
# Block each confirmed C2 IP outbound (repeat per IOC)
New-NetFirewallRule -DisplayName "IR-Block-C2-45.x.x.x" -Direction Outbound -Action Block `
    -RemoteAddress 45.x.x.x
```

## Step 2 — Disable persistence (the reanimation points)

```powershell
schtasks /Delete /TN "\Updater\evil" /F                          # scheduled task
sc.exe delete "EvilSvc"                                          # service (stop first if running)
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "evil"   # Run key value
# WMI subscription: remove all three linked objects
Get-WmiObject -Namespace root\subscription __EventFilter -Filter "Name='evil'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription __FilterToConsumerBinding | Where-Object { $_.Filter -match 'evil' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription __EventConsumer -Filter "Name='evil'" | Remove-WmiObject
```

## Step 3 — Disable implicated accounts & rotate credentials

Anything the attacker created, used, or could read from LSASS (step 08) is burned.

```powershell
Disable-LocalUser -Name "svc_help"          # attacker-created account
# For domain accounts, disable via AD and force a reset; escalate to identity team.
```

Then **rotate**: passwords for every implicated account, and — because creds sat cleartext in RAM
— any service account or admin that logged into this host during the compromise window. On a
domain, treat **krbtgt** rotation as in-scope if a DC or domain admin was involved.

## Step 4 — Kill the running processes

Now, after persistence is gone, stop the live malware.

```powershell
Stop-Process -Id 1234 -Force
```

## Step 5 — Quarantine the files (don't just delete — preserve)

Keep a copy of the sample (hashed) before removing it from its live location. You may need it for
analysis, attribution, or legal.

```powershell
$src = 'C:\Users\bob\AppData\Roaming\stage2.exe'
Get-FileHash -Algorithm SHA256 $src | Tee-Object E:\IR-CASE\evidence\quarantine\stage2.sha256
Move-Item $src "E:\IR-CASE\evidence\quarantine\stage2.exe.quarantined"
```

## Step 6 — Undo the tampering

Reverse what the attacker changed to blind defenses (found in step 06):

```powershell
Remove-MpPreference -ExclusionPath 'C:\Users\bob\AppData\Roaming'    # remove attacker's AV exclusion
# Re-enable real-time protection, reset WDigest UseLogonCredential to 0, re-enable log channels, etc.
```

---

## Step 7 — Keep a rollback journal (every action, reversible)

For **every** change, log: what you changed, the previous value, when (UTC), and why. If you break
production or misjudged a finding, you can restore. This journal is also part of your report.

```
2026-07-03T10:14Z  DELETED task \Updater\evil   (was: runs stage2.exe at logon)  reason: TP #3
2026-07-03T10:15Z  BLOCKED outbound 45.x.x.x    reason: confirmed C2 (memory netscan + CS config)
2026-07-03T10:17Z  DISABLED local user svc_help (was: enabled, admin) reason: attacker-created 4720
```

## Step 8 — Re-verify nothing respawned

Re-run the quick live checks (steps 04–05): is the process back? Did the task recreate itself? New
connection to the C2? A well-built implant has **multiple** persistence mechanisms — if something
returns, you missed a tail; go back to step 05/06 and find it.

---

## When eradication isn't enough — re-image

Be honest about confidence. If the host had **kernel-level compromise** (rootkit, BYOVD), a
**domain-admin/DC compromise**, or you simply **can't prove you found every foothold**, the
correct answer is **rebuild from known-good media**, not surgical cleanup. Clean the credentials
and the entry vector regardless — re-imaging a box while the phished password still works just
gets you re-owned.

---

## Where you are, and what's next

The threat is removed and can't call home, the accounts are locked, the persistence is gone. But
the box is still in its locked-down containment state and you haven't confirmed it's truly healthy.
Time to restore it to known-good and verify.

➡️ Next: [11-restore-and-recover.md](11-restore-and-recover.md)

*Toolkit parallel: **Phase 4 — Eradicate.** `Invoke-Eradication.ps1` (dry-run by default; `-Apply`
to execute) kills/quarantines/unregisters, disables `Principals.json` accounts, blocks
`IOCs.json` C2, undoes tamper, and writes `Eradication_rollback_*.jsonl`. Optional
`Start-EgressMonitor.ps1` watches egress past your visit.*
