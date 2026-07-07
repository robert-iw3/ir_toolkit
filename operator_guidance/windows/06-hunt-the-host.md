# 06 · Hunt the Host

*Now go looking for the attacker where they hide from a casual glance — injection, malicious
drivers, COM hijacks, background transfers, tampered defenses, and the tools that let them back
in.*

---

## The situation

Steps 04–05 captured the obvious. This step is the active hunt through the techniques that don't
announce themselves as a process or a Run key. You don't need to run *every* check on every case
— let the alert and what you've found so far steer you. Still read-only; still saving output.

Work through these hunts. Each is short. Each hit is a **finding to adjudicate** in step 07, not
a conviction.

---

## Hunt 1 — Process injection & unsigned modules in signed processes

Attackers inject code into a trusted process (`explorer.exe`, `svchost.exe`) so their code runs
under a name you trust. On the live host, the tell is an **unsigned DLL loaded inside a signed
process**, or a module loaded from `Temp`/`AppData`.

```powershell
# List modules (DLLs) loaded by a suspect PID and check where they came from
Get-Process -Id 1234 -Module |
    Select-Object ModuleName, FileName |
    Where-Object { $_.FileName -match 'Temp|AppData|ProgramData|Users' }

# Check a loaded module's signature
Get-AuthenticodeSignature 'C:\Users\bob\AppData\Local\Temp\evil.dll' | Select-Object Status, SignerCertificate
```

> The deepest form — **injected code with no backing file at all** (reflective/manual mapping) —
> often **doesn't show as a module** on the live host. That's a job for memory forensics (step
> 08), which sees executable memory regions that no file backs.

## Hunt 2 — Malicious / vulnerable drivers (BYOVD)

"Bring Your Own Vulnerable Driver": the attacker loads a legitimately-signed but exploitable
driver to get kernel power (kill EDR, hide). Name-matching is weak (they rename it) — **hash-match**
is the strong check.

```powershell
# Enumerate loaded drivers with their on-disk paths
driverquery /v /fo csv | ConvertFrom-Csv |
    Select-Object 'Display Name','Path','Start Mode' |
    Export-Csv E:\IR-CASE\evidence\drivers.csv -NoTypeInformation

# Hash any driver outside System32\drivers, then compare against the loldrivers.io dataset (offline copy)
Get-ChildItem C:\Windows\System32\drivers\*.sys |
    Get-FileHash -Algorithm SHA256 | Export-Csv E:\IR-CASE\evidence\driver_hashes.csv -NoTypeInformation
```

**Read it looking for:** a driver loaded from a **non-standard path**, an unsigned driver, or a
SHA256 that matches a known-vulnerable driver. Cross-reference hashes against your staged
loldrivers list.

## Hunt 3 — COM hijacking

Persistence/execution by pointing a COM object's `InprocServer32` at attacker code. The classic
shape: an **HKCU** CLSID entry *shadows* an HKLM one and points at an unsigned/user-writable DLL.

```powershell
# User-hive COM servers pointing at user-writable DLLs are the red flag
Get-ChildItem "Registry::HKCU\Software\Classes\CLSID" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $ips = Join-Path $_.PSPath 'InprocServer32'
        if (Test-Path $ips) { (Get-ItemProperty $ips).'(default)' }
    } | Where-Object { $_ -match 'AppData|Temp|ProgramData|Users' }
```

## Hunt 4 — BITS jobs (stealthy download/persistence)

Background Intelligent Transfer Service is abused to download payloads and re-run them, surviving
reboots quietly.

```powershell
Get-BitsTransfer -AllUsers |
    Select-Object DisplayName, TransferType, JobState,
        @{n='URL';e={ ($_.FileList.RemoteName) -join ';' }},
        @{n='Dest';e={ ($_.FileList.LocalName) -join ';' }}
```

**Read it looking for:** a job pulling from a **non-CDN / random domain** or writing into
`Temp`/`AppData`, or a job with a name trying to look like a Windows component.

## Hunt 5 — Tampered defenses (ETW / AMSI / Defender / logs)

Before doing damage, attackers blind the sensors. Evidence of tampering is itself a strong signal.

```powershell
# AMSI provider present? (missing/renamed = bypass)
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue

# Defender turned off via policy / real-time disabled
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, IsTamperProtected
Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess

# Event-log channels stopped or size-zeroed, WDigest cleartext creds enabled, PPL disabled
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>$null
```

**Read it looking for:** Defender disabled by policy, **new exclusion paths** (attackers exclude
their own folder), AMSI provider missing, `UseLogonCredential=1` (forces cleartext creds into
LSASS), event-log channels disabled. Exclusions pointing at `AppData`/`Temp` are near-conclusive.

## Hunt 6 — Named pipes (C2 framework tell)

Cobalt Strike, Brute Ratel, and friends use named pipes with recognizable patterns for their SMB
beacons and internal comms.

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") |
    Where-Object { $_ -match 'msagent|status_|postex|MSSE-|\\ratel|interprocess_' } |
    Tee-Object E:\IR-CASE\evidence\suspicious_pipes.txt
```

## Hunt 7 — Remote-access tooling (how they get back in)

Attackers install legitimate RMM tools (AnyDesk, TeamViewer, ScreenConnect, Atera) for durable,
"clean-looking" access. And "ClickFix" lures trick users into pasting a malicious command.

```powershell
# Installed + running RMM agents (extend this name list from your RMM inventory)
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match 'anydesk|teamviewer|screenconnect|atera|splashtop|ammyy|remoteutilities|gotoassist' } |
    Select-Object Name, ProcessId, CommandLine

# RunMRU — what commands were typed into the Run box (ClickFix lands here)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
```

**Read it looking for:** an RMM tool the org doesn't use, installed right around the incident
time; a `mshta`/`powershell`/`curl` command in RunMRU the user was social-engineered into running.

## Hunt 8 — Suspicious files on disk (optional, targeted)

If you have a lead on a directory (from the alert, from `AppData`, from a download folder), scan
it. Don't boil the ocean — target high-risk paths.

```powershell
# Magic-byte vs extension mismatch: a PE ("MZ") hiding under a non-exe name
Get-ChildItem C:\Users\bob\AppData\Roaming -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        $b = Get-Content $_.FullName -TotalCount 1 -AsByteStream -ErrorAction SilentlyContinue
        if ($b -and $b[0] -eq 0x4D) { $_.FullName }   # 0x4D = 'M' (start of "MZ")
    }

# Alternate Data Streams — content hidden behind a benign file
Get-Item C:\Users\bob\Downloads\* -Stream * -ErrorAction SilentlyContinue |
    Where-Object Stream -ne ':$DATA' | Select-Object FileName, Stream

# YARA over a target folder (from your kit) — signature match against known malware families
E:\tools\yara64.exe -r E:\tools\rules\windows_index.yar C:\Users\bob\AppData\Roaming
```

**Read it looking for:** PE files masquerading under `.txt`/`.log`/`.dat`, timestamps that are
impossible (created in the future, or all-identical = timestomping), high entropy in things that
shouldn't be compressed/encrypted, and any YARA family hit.

---

## Where you are, and what's next

You now have a pile of findings from steps 04–06: odd processes, autostarts, drivers, pipes,
files, RMM tools, tamper evidence. Some are real, most are noise. The next step is the analyst's
core craft: **turning findings into defensible verdicts.**

➡️ Next: [07-adjudicate-findings.md](07-adjudicate-findings.md)

*Toolkit parallel: **Phase 1 EDR hunt** — `EDR_Toolkit.ps1` runs every hunt here (injection,
BYOVD by hash, COM, BITS, ETW/AMSI tamper, named pipes, file/YARA) plus
`Get-RemoteAccessTriage.ps1` for RMM/ClickFix.*
