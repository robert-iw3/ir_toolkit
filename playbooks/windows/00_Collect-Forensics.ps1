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
# Collected via registry to avoid triggering AMSI heuristics on Get-MpPreference.
try {
    $defRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    $defExclusions = @{}
    foreach ($sub in @('Paths','Extensions','Processes')) {
        $subKey = Join-Path $defRegPath $sub
        if (Test-Path $subKey) {
            $defExclusions[$sub] = (Get-ItemProperty $subKey -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                Select-Object Name, Value
        }
    }
    $defExclusions | ConvertTo-Json -Depth 3 | Out-File "$WorkDir\defender_exclusions.json" -Encoding UTF8
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

# -- Autorunsc persistence breadth (optional staged tool) ----------------------
# autorunsc64 covers IFEO, Winlogon, LSA providers, AppInit, codecs, drivers,
# Office add-ins, browser extensions - far beyond what registry keys alone capture.
$autorunsc = Join-Path $PSScriptRoot '..\..\tools\autorunsc64.exe'
if (Test-Path $autorunsc) {
    try {
        Write-CollectLog "FORENSICS: Running autorunsc64 persistence sweep..."
        # -accepteula  suppress EULA dialog
        # -a *         all autorun categories
        # -s           verify digital signatures
        # -h           include file hashes
        # -c           CSV output
        # -nobanner    no version banner in output
        & $autorunsc -accepteula -a '*' -s -h -c -nobanner 2>$null |
            Out-File "$WorkDir\autoruns_all.csv" -Encoding UTF8
        Write-CollectLog "FORENSICS: Autorunsc snapshot written"
    } catch {
        Write-CollectLog "FORENSICS: Autorunsc error: $_"
    }
} else {
    Write-CollectLog "FORENSICS: autorunsc64.exe not staged (run Build-OfflineToolkit.ps1 to enable)"
}

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

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGNWwLLZB3tMqJ
# 8Pg3RksX7B1K6xS0zzMcU64o7wKC1qCCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
# rUKI1OYOaCvjMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjQyMjQ1MTNaFw0zMTA2MjQyMjU1MTNaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKCRMj2g7ekVueQgTeNVDV/Xz94PBbxt0/9qalo3
# ZcDg3e8VTErd0f6b8Ya8ibhn3tZ9zWKMpP3nuub3mlgEiO3Md4JhBx6N3bKukDN+
# Nb3uNGCoSbJTnI13pA1dkqtu41wagDdtnPDYSs5+cidAlPhZgBjxuXdoiWKzAUNw
# +dxDgaMmLxM0Qvp4z2kuOBes6C9Xd7twXNwi0Ov4pC1F0HAcKm7WCMtlRlX9i01k
# WmZkARKuPQ3eHWg0e08aC4CldRauFArRf2lO9MzquFinnD2s25q8F/PiEeyWALIe
# e/hE6L/bl/Z+5MR84dPFTfMXub9dsDsr++APaaYkZO04fTUCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQU6OnI
# wgtlYKR4+fSkiuhgK5MUVDANBgkqhkiG9w0BAQsFAAOCAQEAnw0GGGlgOpVP5ag3
# BvgHh4QYHOFColAEKbKGKDHMnvxsrlapVXCX69hnFv4701iiDn/DQirr/EUy1QRs
# v4BrQwh4EGvTU9AT8mOxRbi6svr1IKdab2iSkNqW8GTvSK6ZCyQkJn/+KAOY8u7E
# 9lO2+LM8DG2/1mgw/Ptg4jbVba/rPnLXkHnsydr2yhBw7miBEOIS9DBSul/wrxCV
# VTLcnbB1YRuJpV+dj6+YCnZT7pO6qOToHp++ueGyuw8ul/qCnhxiv89Hu/T++Pyh
# Qow09e6wDMKrbmdJD89KLTV8Zalq1sLskE8B4Q1TiWPknAr4f1V6rcJTH6BcoRMU
# 4eKB9TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zC
# pyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf
# 1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x
# 4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEio
# ZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7ax
# xLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZ
# OjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJ
# l2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz
# 2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH
# 4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb
# 5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ
# 9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuC
# MS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0g
# ADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs
# 7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq
# 3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/
# Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9
# /HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWoj
# ayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0
# MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2
# IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U
# 1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt
# 281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9R
# aUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd
# 2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25L
# CHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0
# xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVV
# WcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0
# ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/
# DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd7
# 6CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEA
# AaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZ
# UEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB
# /wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgw
# gYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEF
# BQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUq
# rfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWP
# oSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3Im
# ZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhc
# UT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp
# 7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtf
# parz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu
# /CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9
# SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnM
# G3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSe
# y2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9
# xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFQzCCBT8CAQEwZzBTMRow
# GAYDVQQLDBFJbmNpZGVudCBSZXNwb25zZTETMBEGA1UECgwKSVIgVG9vbGtpdDEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBzF7sL9NkWtQojU5g5o
# K+MwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgl9tXBB2nQhLg/i2m/yeD6oIV9qyr62K1
# DLR7xTgkOdgwDQYJKoZIhvcNAQEBBQAEggEALKYQxCYQD/EYby98XEgin6AoIgCW
# 5fa/s9I/74RugwmUYxrQT8mciGDM/WxoYkSvjTqkKB/zAo8taIrViRYe44xAy6NF
# gtgwfZtXapJcSBKzqHH/Vy58w7xzUo2ZyXQW+XXSaUPn2moVVjTN4/+xuQvIGyFy
# xwIiwjsU8yw1rGO2VMUtkCAzQ/ugCRwq4ViECOr7I8G1ZZmMhhPCoDepyFxYVgmY
# nVbeZurbJt3rIFJL+fSxbOEqS6/J/bAXiXWlj7IHfRtybDXupvKG2+k4sIGMq2z8
# xhOGwVIvwm/pPIX281/jA1I6YQOvfgb5W4QTEA3ccY4DjB+Qv+be4dTV+6GCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1MjJaMC8GCSqGSIb3DQEJBDEi
# BCCEBI5Jy7bFs4moNPMzsEBm5nf+p1Oy4QhaaHoccfKn7DANBgkqhkiG9w0BAQEF
# AASCAgBww7laWBpuUGUnM17c+jBcNknJUACzy3EN3OEtJxwZUZ3Zg4VyqqQQKBrG
# pkGVB6Bvkw55Rz9hVavPVeoU2BkgcnDVWbgrdC0gh/3i8lTRZ6wHqWFlnpgfP1nE
# 6r746hQxtJT/85OWz8K2qUu/PY7lfaTP7fvqr03rNrALW9o/FJ8iSveeezV3tGvK
# 0WDEN6zRM22QwrDHNf5XshtgYKf6z5JTsWquUbnnHvlacwwQ5pACKuvZvfgc2QXa
# WkUVjPpLqUYzLrYTPGaL+Kqz3TpSX2VNeozkTh91t6kS37U6WvdkbQrGCyMWlRq7
# dD0/xSHglL7QK2ej9dVb4w8rwGyc/54OsqBvQvrEgXju5blEkBuBl6FVfuoKacsZ
# mIL0cG+dHU+c9bCaa1MDMZ9dYZz+9GEoooPsE6q76vl2xRnC8qmVzNeUrOHgm2Y8
# uk9YIWPSDgNPNunZfQ42GSHLtHCIsa6fhl6P8LcQKyWHDKh61Se6LuhvDmrzTPTB
# uelIyCVEq0AXnphNTrCDpEpdJ2DfI/m+8kFAYU55IkciiznDPK299YSdqjmGNBeD
# UvDB78aae6Hah622qGGpujiMu28qhF5m8sE/7ihBLcYnOvIF20IznSRUlySJbOkr
# YsweiYg0sX1oo3k3rbjSUniP1xUOVqZph82fW9s8z5s61ez7nA==
# SIG # End signature block
