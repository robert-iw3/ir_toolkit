# 05 · Persistence & Execution History

*Two questions: **how does it survive a reboot**, and **what has run on this box before?**
Answer both, and you've found the attacker's foothold and their footprints.*

---

## The situation

Malware that matters wants to **persist** — to come back after a reboot or a logoff. Windows
offers dozens of autostart locations, and attackers know all of them. Separately, Windows keeps
**execution-history** artifacts that record programs that ran even after the file is deleted.
This step harvests both. Still read-only; still saving everything to your evidence drive.

---

## Part A — Persistence: every place a program can auto-start

### Step 1 — Sweep it all with Autoruns (the fast path)

Sysinternals **Autoruns** knows every autostart location Windows has. Run the command-line
version from your kit and export everything:

```powershell
# -a * = all categories, -h = show hashes, -c = CSV, -nobanner
E:\tools\autorunsc.exe -accepteula -a * -h -c -nobanner > E:\IR-CASE\evidence\autoruns.csv
```

Open the CSV and sort by **whether it's signed** and **where the image lives**. The attacker's
entry almost always: points into a user-writable path (`AppData`, `Temp`, `ProgramData`,
`Public`), is unsigned or badly signed, and has a name trying to blend in.

### Step 2 — Check the high-value locations by hand (know these cold)

Autoruns covers these, but doing the top ones manually teaches you what "normal" looks like:

```powershell
# Run / RunOnce — the most common persistence, per-user and machine-wide
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Winlogon — Userinit/Shell should be the DEFAULT values only; anything appended is persistence
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell

# Services set to auto-start from odd paths
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'Temp|AppData|ProgramData\\[^\\]+\.exe' } |
    Select-Object Name, PathName, StartName

# Scheduled tasks — a favorite; look at actions and where they point
Get-ScheduledTask | Where-Object State -ne 'Disabled' |
    ForEach-Object {
        [pscustomobject]@{ Name=$_.TaskName; Path=$_.TaskPath
            Action=($_.Actions.Execute -join ';'); Args=($_.Actions.Arguments -join ';') }
    } | Export-Csv E:\IR-CASE\evidence\schtasks.csv -NoTypeInformation
```

**Advanced autostarts attackers love (check if the incident looks targeted):** IFEO "debugger"
hijacks, AppInit_DLLs, LSA Security/Authentication packages, BootExecute, netsh helper DLLs,
COM hijacks (step 06), and WMI event subscriptions (below).

### Step 3 — WMI event subscriptions (fileless persistence)

This one has **no file and no registry Run key** — it lives in the WMI repository and survives
reboots invisibly. You must check all three linked objects together:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer          # esp. CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

**Read it looking for:** a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` that runs
PowerShell/a script, bound to a filter that triggers on startup or a timer. Legitimate ones exist
(SCCM, monitoring) but a hand-rolled one running encoded PowerShell is a classic APT foothold.

---

## Part B — Execution history: what ran here before

Even if the file is gone, Windows remembers it ran. These artifacts are how you find *patient
zero* and prove the attacker's tools executed.

| Artifact | What it proves | How to get it |
|---|---|---|
| **Prefetch** (`C:\Windows\Prefetch\*.pf`) | A program executed, when, how many times | Copy the `.pf` files; parse with PECmd |
| **Amcache** (`C:\Windows\AppCompat\Programs\Amcache.hve`) | Executables run, with **SHA1**, path, publisher, link date — survives deletion | Locked file: copy with `robocopy /B`, load offline |
| **ShimCache** (AppCompatCache registry) | Files executed since last boot (kernel-level) | Read from the registry (no lock) |
| **Event 4688** (Security log) | Process creation with command line (if auditing on) | `Get-WinEvent` |
| **UserAssist / RunMRU / ShellBags** | GUI programs launched, commands typed in Run, folders browsed | Registry, per user |

```powershell
# Amcache — copy the locked hive, then parse offline with a tool like AmcacheParser
robocopy C:\Windows\AppCompat\Programs E:\IR-CASE\evidence Amcache.hve /B

# ShimCache lives here (parse with a ShimCacheParser tool)
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" `
    E:\IR-CASE\evidence\shimcache.reg

# Prefetch — copy the whole folder
robocopy C:\Windows\Prefetch E:\IR-CASE\evidence\Prefetch /E
```

**Read it looking for:** executables that ran from `AppData\Roaming`, `Temp`, `Downloads`,
`Desktop`, or `Public`; known attacker tools (PsExec, Mimikatz, Rclone, AnyDesk) that shouldn't
be there; LOLBins running from outside `System32`. Each hit is a **pivot lead** — a name/hash/time
to chase — not yet a verdict (a missing binary in ShimCache is normal for installers; step 07
decides).

---

## Part C — Event logs (the timeline's backbone)

Export the logs *now* — an attacker with access can clear them (and clearing is itself an event).

```powershell
# Export the key channels to .evtx for offline analysis
foreach ($log in 'Security','System','Windows PowerShell','Microsoft-Windows-Sysmon/Operational') {
    $safe = $log -replace '[\\/]','_'
    wevtutil epl "$log" "E:\IR-CASE\evidence\$safe.evtx" 2>$null
}
```

The events that tell the story:

| Event ID | Log | Means |
|---|---|---|
| **4688** | Security | Process created (+ cmdline) → LOLBins, encoded PowerShell |
| **4624 / 4625** | Security | Logon success / failure-burst → brute force, lateral movement |
| **4648** | Security | Explicit-credential logon → pass-the-hash / runas |
| **4720 / 4732** | Security | New account / added to admin group |
| **7045** | System | New service installed → PsExec, persistence |
| **4698 / 4702** | Security | Scheduled task created/modified |
| **4104** | PowerShell | Script block logging → decoded scripts, Mimikatz, AMSI bypass |
| **1102 / 104** | Security/System | **Audit log cleared** → someone is covering tracks |

```powershell
# Example: hunt encoded/suspicious PowerShell in script-block logs
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } -MaxEvents 500 |
    Where-Object { $_.Message -match 'FromBase64String|IEX|DownloadString|-enc|AmsiInitFailed' } |
    Select-Object TimeCreated, Message | Tee-Object E:\IR-CASE\evidence\ps_scriptblock_hits.txt
```

> Some events (4656/4663 LSASS handle access) require audit policy that most hosts don't have on
> by default. If a query returns empty, that usually means "not audited here," not "didn't
> happen" — note the gap.

---

## Where you are, and what's next

You now have the foothold candidates (persistence) and the footprints (execution history + logs).
Next you go actively hunting for where the attacker is *hiding in the running system* — the
techniques that don't show up as a simple autostart entry.

➡️ Next: [06-hunt-the-host.md](06-hunt-the-host.md)

*Toolkit parallel: **Phase 1** — Autoruns + `Get-PersistenceSnapshot.ps1` (all autostarts, WMI
subs, LSA/Winlogon/BootExecute), `Invoke-AmcacheParser.ps1` (Amcache/ShimCache), and
`Invoke-EventLogAnalysis.ps1` (the 4688/4625/4648/7045/4104/1102 hunts) do this whole step.*
