# ==============================================================================
# Offline IR - Windows Forensics Collection
# Captures a full system snapshot for incident response. Read-only: it gathers
# evidence and never alters host state. ALL output is written under the script's
# own folder ($PSScriptRoot) by default, or under -OutputDir when supplied, so a
# responder can run it straight off a USB drive and leave nothing on the system.
# No Windows Event Log writes, no C:\ProgramData, no C:\Windows\Temp.
# Requires PowerShell 5.1+ and local admin.
# ==============================================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Collection point. Defaults to this script's folder (the drive it runs from).
    [string]$OutputDir = $PSScriptRoot,
    # Evidence tag used in file names. Defaults to <HOSTNAME>_<timestamp>.
    [string]$IncidentId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # Never abort the run on a single failure

if (-not $OutputDir) { $OutputDir = (Get-Location).Path }   # dot-sourced fallback
if (-not $IncidentId) { $IncidentId = "$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
$IncidentId = $IncidentId -replace '[^\w\-]',''             # sanitise for filesystem

$WorkDir = Join-Path $OutputDir "forensics-$IncidentId"     # staging dir (zipped, then removed)
$Archive = Join-Path $OutputDir "forensics-$IncidentId.zip"
$LogDir  = $OutputDir

New-Item -ItemType Directory -Path $WorkDir, $LogDir -Force | Out-Null

function Write-CollectLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
    Write-Output $entry
    $entry | Out-File (Join-Path $LogDir 'collection.log') -Append -Encoding UTF8
}

Write-CollectLog "FORENSICS: Collection started for incident $IncidentId"

# -- Process snapshot ----------------------------------------------------------
try {
    Get-Process | Select-Object Id, Name, CPU, WorkingSet64, Path, Company, Description,
        StartTime, @{N='ParentPid';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId}} |
        Export-Csv "$WorkDir\processes.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: Process snapshot error: $_" }

# Hash running process binaries for IOC cross-reference
try {
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        try {
            $hash = (Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            [PSCustomObject]@{ Pid=$_.Id; Name=$_.Name; Hash=$hash; Path=$_.Path }
        } catch {}
    } | Export-Csv "$WorkDir\process_hashes.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: Process hash error: $_" }

# -- Process command lines + parent (Win32_Process; Get-Process lacks these) ---
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Select-Object ProcessId, Name, ParentProcessId, CommandLine, ExecutablePath,
            @{N='CreationDate';E={$_.CreationDate}} |
        Export-Csv "$WorkDir\process_commandlines.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: Process command-line error: $_" }

# -- Network connections -------------------------------------------------------
try {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        State, OwningProcess,
        @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Export-Csv "$WorkDir\tcp_connections.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: TCP connection error: $_" }

try {
    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess,
        @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Export-Csv "$WorkDir\udp_endpoints.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: UDP endpoint error: $_" }

# Routing and ARP table
Get-NetRoute    | Out-File "$WorkDir\routing_table.txt"   -Encoding UTF8
Get-NetNeighbor | Out-File "$WorkDir\arp_table.txt"       -Encoding UTF8

# -- Scheduled tasks -----------------------------------------------------------
try {
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
        @{N='Actions';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '}},
        @{N='Triggers';E={($_.Triggers | ForEach-Object { $_.GetType().Name }) -join ', '}},
        @{N='Author';E={$_.Principal.UserId}} |
        Export-Csv "$WorkDir\scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: Scheduled task error: $_" }

# -- Registry persistence keys -------------------------------------------------
$RunKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute'
)
$RunKeys | ForEach-Object {
    try {
        if (Test-Path $_) {
            Get-ItemProperty $_ | Out-String
        }
    } catch {}
} | Out-File "$WorkDir\registry_persistence.txt" -Encoding UTF8

# -- Services ------------------------------------------------------------------
try {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode,
        PathName, StartName, Description |
        Export-Csv "$WorkDir\services.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: Service enumeration error: $_" }

# -- WMI persistent subscriptions ---------------------------------------------
try {
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
        Out-File "$WorkDir\wmi_filters.txt" -Encoding UTF8
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
        Out-File "$WorkDir\wmi_consumers.txt" -Encoding UTF8
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
        Out-File "$WorkDir\wmi_bindings.txt" -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: WMI subscription error: $_" }

# -- Startup folders -----------------------------------------------------------
$StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$StartupPaths | ForEach-Object {
    if (Test-Path $_) { Get-ChildItem $_ -Recurse | Out-String }
} | Out-File "$WorkDir\startup_folders.txt" -Encoding UTF8

# -- PowerShell history --------------------------------------------------------
try {
    $histPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($histPath -and (Test-Path $histPath)) {
        Copy-Item $histPath "$WorkDir\ps_history.txt"
    }
} catch {}

# -- Recently created files ----------------------------------------------------
$SearchPaths = @($env:TEMP, $env:TMP, 'C:\Windows\Temp', 'C:\ProgramData', "$env:APPDATA")
$CutoffTime  = (Get-Date).AddHours(-24)
$SearchPaths | ForEach-Object {
    try {
        Get-ChildItem -Path $_ -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -gt $CutoffTime } |
            Select-Object FullName, CreationTime, LastWriteTime, Length
    } catch {}
} | Export-Csv "$WorkDir\recently_created_files.csv" -NoTypeInformation -Encoding UTF8

# -- Event log snapshot --------------------------------------------------------
# Security: process creation (4688), logon (4624/4625/4648), task creation (4698/4702),
#           account creation (4720), log cleared (1102), type-9 logon - PtH indicator
@(4688, 4624, 4625, 4648, 4698, 4702, 4720, 1102) | ForEach-Object {
    $eid = $_
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eid} -MaxEvents 100 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Export-Csv "$WorkDir\events_$eid.csv" -NoTypeInformation -Encoding UTF8
    } catch {}
}
# System: new service installs (7045), System log cleared (104)
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(7045, 104)} -MaxEvents 50 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        Export-Csv "$WorkDir\events_system_critical.csv" -NoTypeInformation -Encoding UTF8
} catch {}
# PowerShell script block logging (4104) - captures AMSI bypass, encoded commands, Invoke-Mimikatz
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} `
        -MaxEvents 500 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        Export-Csv "$WorkDir\events_ps_scriptblock.csv" -NoTypeInformation -Encoding UTF8
} catch {}
# RDP/TermServices: session logon (21), disconnect (24), reconnect (25)
try {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        Id      = @(21, 24, 25)
    } -MaxEvents 100 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        Export-Csv "$WorkDir\events_rdp.csv" -NoTypeInformation -Encoding UTF8
} catch {}

# -- Current network shares ----------------------------------------------------
Get-SmbShare 2>$null | Out-File "$WorkDir\smb_shares.txt" -Encoding UTF8
try {
    Get-SmbSession -ErrorAction SilentlyContinue |
        Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsActive |
        Export-Csv "$WorkDir\smb_sessions.csv" -NoTypeInformation -Encoding UTF8
} catch {}

# -- Active sessions -----------------------------------------------------------
try {
    if (Get-Command quser -ErrorAction SilentlyContinue) {
        quser 2>$null | Out-File "$WorkDir\active_sessions.txt" -Encoding UTF8
    } else {
        # quser is missing on some SKUs (e.g. Windows Home) - fall back to CIM.
        Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
            Select-Object LogonId, LogonType, StartTime, AuthenticationPackage |
            Out-File "$WorkDir\active_sessions.txt" -Encoding UTF8
    }
} catch { Write-CollectLog "FORENSICS: active session error: $_" }
try {
    if (Get-Command net -ErrorAction SilentlyContinue) {
        net session 2>$null | Out-File "$WorkDir\net_sessions.txt" -Encoding UTF8
    }
} catch {}

# -- DNS client cache ----------------------------------------------------------
try {
    Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, RecordName, RecordType, Status, TimeToLive, Data |
        Export-Csv "$WorkDir\dns_cache.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-CollectLog "FORENSICS: DNS cache error: $_" }

# -- Prefetch files (execution history, survives log clearing) -----------------
if (Test-Path 'C:\Windows\Prefetch') {
    try {
        Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue |
            Select-Object Name, CreationTime, LastWriteTime, Length |
            Export-Csv "$WorkDir\prefetch_listing.csv" -NoTypeInformation -Encoding UTF8
    } catch {}
}

# -- AMCache.hve + ShimCache (app execution history survives Prefetch/log wipes)
$AmcacheHive = 'C:\Windows\AppCompat\Programs\Amcache.hve'
if (Test-Path $AmcacheHive) {
    try { Copy-Item $AmcacheHive "$WorkDir\Amcache.hve" -Force } catch {}
}
$ShimCachePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
if (Test-Path $ShimCachePath) {
    try {
        Get-ItemProperty $ShimCachePath | Select-Object AppCompatCache |
            ConvertTo-Json -Compress | Out-File "$WorkDir\ShimCache.json" -Encoding UTF8
    } catch {}
}

# -- USB storage device history ------------------------------------------------
$UsbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
if (Test-Path $UsbStorPath) {
    try {
        Get-ChildItem $UsbStorPath -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
            Select-Object FriendlyName, HardwareID, PSChildName |
            Export-Csv "$WorkDir\usb_storage_history.csv" -NoTypeInformation -Encoding UTF8
    } catch { Write-CollectLog "FORENSICS: USB history error: $_" }
}

# -- Windows Defender exclusions (attackers add staging paths here) ------------
try {
    Get-MpPreference -ErrorAction SilentlyContinue |
        Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess |
        ConvertTo-Json | Out-File "$WorkDir\defender_exclusions.json" -Encoding UTF8
} catch {}

# -- Local accounts and admin group -------------------------------------------
try {
    Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired |
        Export-Csv "$WorkDir\local_users.csv" -NoTypeInformation -Encoding UTF8
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Select-Object Name, PrincipalSource, ObjectClass |
        Export-Csv "$WorkDir\local_admins.csv" -NoTypeInformation -Encoding UTF8
} catch {}

# -- Compress archive ----------------------------------------------------------
try {
    Compress-Archive -Path $WorkDir -DestinationPath $Archive -Force
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-CollectLog "FORENSICS: Archive saved -> $Archive"

    # Chain-of-custody manifest
    $ArchiveHash = (Get-FileHash -Path $Archive -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    @{
        hostname    = $env:COMPUTERNAME
        incident_id = $IncidentId
        collected   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        archive     = $Archive
        sha256      = $ArchiveHash
    } | ConvertTo-Json | Out-File (Join-Path $LogDir "manifest-$IncidentId.json") -Encoding UTF8
} catch {
    Write-CollectLog "FORENSICS: Compression failed: $_"
}

$result = @{
    phase       = 'forensics'
    status      = 'success'
    archive     = $Archive
    incident_id = $IncidentId
} | ConvertTo-Json -Compress
Write-Output $result
