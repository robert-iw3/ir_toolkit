# 04 · Snapshot Live System State

*The box is still running. Photograph what's alive — processes, connections, sessions, users —
before any of it changes.*

---

## The situation

Live state is the second rung on the volatility ladder. Running processes end, sockets close,
logged-on sessions drop. Capture it all now, **read-only**, and save it off-host. Don't judge yet
— just snapshot. You'll adjudicate in step 07.

> **Save every command's output to a file** on your external drive. `... | Tee-Object
> E:\IR-CASE\evidence\processes.txt` or `Export-Csv`. You want the raw record, timestamped.

---

## Step 1 — Processes, with the three facts that matter

For every process you care about: **its parent, its full command line, and where its image lives
on disk.** Name alone lies (malware calls itself `svchost.exe`); those three tell the truth.

```powershell
# Full process table with parent + command line + path — the workhorse view
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate |
    Sort-Object ParentProcessId |
    Export-Csv E:\IR-CASE\evidence\processes.csv -NoTypeInformation
```

**Read it looking for:**
- **Impossible parentage:** `winword.exe` or `excel.exe` spawning `powershell`/`cmd`/`wscript`;
  `services.exe` spawning something in `AppData`.
- **Masquerading:** `svchost.exe` *not* under `services.exe`, or running from `C:\Users\...`
  instead of `C:\Windows\System32`. `scvhost`, `lsass1`, `csrss .exe` (note the space).
- **Suspicious command lines:** `-enc`/`-EncodedCommand`, `IEX (New-Object Net.WebClient)`,
  `certutil -urlcache`, `mshta http...`, `rundll32 ...,#1`, hidden windows.

```powershell
# Zoom in on a single suspect and walk its ancestry
Get-CimInstance Win32_Process -Filter "ProcessId=1234" | Format-List Name,ParentProcessId,CommandLine,ExecutablePath
Get-CimInstance Win32_Process -Filter "ProcessId=<parent>" | Format-List Name,ParentProcessId,CommandLine
```

## Step 2 — Network connections, mapped to their process

The "who is this box talking to" view. Tie every connection back to the owning process.

```powershell
# Established outbound connections + owning PID + process name (the C2-hunting view)
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        @{n='Proc';e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }}, OwningProcess |
    Sort-Object RemoteAddress |
    Export-Csv E:\IR-CASE\evidence\netconn.csv -NoTypeInformation

# Classic one-liner that shows the same with the executable name
netstat -anob | Tee-Object E:\IR-CASE\evidence\netstat.txt

# Listeners — an unexpected LISTEN port is a backdoor/handler
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
```

**Read it looking for:** connections to **public IPs on odd ports** (not 80/443/the app's
normal port), a process that has *no business* being online (Notepad talking to the internet),
beacon-like repetition to one host, or a listener you can't explain.

```powershell
# Recently resolved domains — what names this host looked up (C2 domains show here)
Get-DnsClientCache | Select-Object Entry, Data | Tee-Object E:\IR-CASE\evidence\dnscache.txt
arp -a | Tee-Object E:\IR-CASE\evidence\arp.txt   # who it recently talked to on the LAN
```

## Step 3 — Who is (or was) logged on

Attackers use valid accounts. Capture sessions and the accounts that exist.

```powershell
query user                     # interactive/RDP sessions right now
qwinsta                        # session states
Get-SmbSession                 # inbound SMB — lateral movement lands here
Get-SmbOpenFile                # files opened over SMB
Get-LocalUser | Select-Object Name, Enabled, LastLogon, SID
Get-LocalGroupMember Administrators   # who has admin — watch for a surprise member
```

**Read it looking for:** a new/unknown local admin, a service account interactively logged on, an
RDP session from an unexpected source, or SMB sessions from a host that shouldn't be reaching in.

## Step 4 — Services and their binaries (quick pass)

```powershell
Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, StartName, PathName |
    Export-Csv E:\IR-CASE\evidence\services.csv -NoTypeInformation
```

**Read it looking for:** a service whose `PathName` points into `Temp`/`AppData`/`ProgramData`,
an unquoted path with spaces, or a random-looking service name running as `LocalSystem`. (Deeper
persistence hunting is step 05.)

---

## A note on hidden processes (advanced, but do it)

A rootkit can hide a process from the normal API while it still exists. You catch it by **asking
the same question two different ways and comparing.** If a PID appears in one list but not the
other, that gap is a strong signal — and a reason you also captured memory (step 08), which sees
processes the live OS is hiding.

```powershell
# Compare the API view against the WMI/CIM view — mismatches are suspicious
$api = (Get-Process).Id | Sort-Object
$wmi = (Get-CimInstance Win32_Process).ProcessId | Sort-Object
Compare-Object $api $wmi
```

---

## Where you are, and what's next

You've photographed the *present* — what's running and talking right now. But an intrusion has a
*past* (how did it get here, what ran before) and a *future* (how does it survive a reboot). Next
you pull the artifacts that answer both.

➡️ Next: [05-persistence-and-execution-history.md](05-persistence-and-execution-history.md)

*Toolkit parallel: **Phase 1 forensics snapshot** — `00_Collect-Forensics.ps1` and
`Invoke-NetworkHunt` capture exactly this (processes, connections, drivers, sessions, DNS/ARP)
read-only, without pre-filtering.*
