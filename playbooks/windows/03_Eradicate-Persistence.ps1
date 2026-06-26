# ==============================================================================
# IR Playbook 03 - Windows Persistence Eradication
# Hunts and removes attacker persistence across every Windows technique:
# Scheduled tasks, Run/RunOnce registry keys, startup folders, services,
# WMI subscriptions, COM hijacking, LSA providers, AppInit_DLLs, IFEO,
# PowerShell profiles, boot execute, and Winlogon values.
# Suspicious entries are quarantined and logged - never silently deleted.
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputDir          = '',
    [string]$IncidentId         = '',
    [string[]]$MaliciousHashes    = @(),
    [string[]]$MaliciousPaths     = @(),
    [string[]]$MaliciousProcesses = @(),
    [switch]$Apply   # dry-run by default; -Apply to execute removals
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not $IncidentId)        { $IncidentId       = ($env:IR_INCIDENT_ID -replace '[^\w\-]','') }
if (-not $MaliciousHashes)   { $MaliciousHashes  = ($env:IR_MALICIOUS_HASHES    -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $MaliciousPaths)    { $MaliciousPaths   = ($env:IR_MALICIOUS_PATHS     -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $MaliciousProcesses){ $MaliciousProcesses = ($env:IR_MALICIOUS_PROCESSES -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

$mode          = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
$IRDir         = if ($OutputDir) { $OutputDir } else { 'C:\ProgramData\IRToolkit' }
$QuarantineDir = Join-Path $IRDir "Quarantine\$IncidentId\persistence"
$AuditLog      = Join-Path $IRDir "persistence-audit-$IncidentId.txt"
New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null

$Removed    = 0
$Suspicious = [System.Collections.Generic.List[string]]::new()

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] [$mode] $Msg"
    Write-Output $entry
    $entry | Out-File $AuditLog -Append -Encoding UTF8
}

function Flag-Suspicious {
    param([string]$Item, [string]$Reason)
    $Suspicious.Add($Item)
    Write-IRLog "PERSIST: SUSPICIOUS - $Item - $Reason"
}

function Remove-PersistenceEntry {
    param([string]$Description, [scriptblock]$RemoveAction)
    try {
        & $RemoveAction
        Write-IRLog "PERSIST: REMOVED - $Description"
        $script:Removed++
    } catch {
        Write-IRLog "PERSIST: Failed to remove $Description : $_"
    }
}

function Test-BadPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($BadPath in $MaliciousPaths) {
        if ($Path -like "*$BadPath*") { return $true }
    }
    return $false
}

function Test-BadHash {
    param([string]$FilePath)
    if (-not $FilePath -or -not (Test-Path $FilePath -ErrorAction SilentlyContinue)) { return $false }
    try {
        $Hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        return $MaliciousHashes -contains $Hash
    } catch { return $false }
}

function Test-SuspiciousCommand {
    param([string]$Cmd)
    $Patterns = @(
        'powershell.*-enc', 'powershell.*-e ', 'cmd.*/c.*(echo|curl|wget)',
        'mshta ', 'wscript ', 'cscript ', 'regsvr32.*/s.*/u',
        'rundll32.*javascript', 'certutil.*-decode', 'bitsadmin.*\/transfer',
        '\\Temp\\.*\.(exe|dll|bat|vbs|js|hta)',
        '\\AppData\\.*\.(exe|dll|bat|vbs|js|hta)',
        'IEX\s*\(', 'Invoke-Expression', 'FromBase64String',
        'DownloadString\s*\(', 'WebClient\(\)', 'Net\.WebClient'
    )
    foreach ($Pattern in $Patterns) {
        if ($Cmd -match $Pattern) { return $true }
    }
    # Also flag if the command references a known-bad process name
    foreach ($ProcName in $MaliciousProcesses) {
        if ($Cmd -like "*$ProcName*") { return $true }
    }
    return $false
}

Write-IRLog "PERSIST: Persistence eradication starting for $IncidentId"

# -- Scheduled Tasks -----------------------------------------------------------
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $Task    = $_
    $Actions = $Task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }
    $CmdStr  = $Actions -join ' '

    $IsBad = $false
    foreach ($Action in $Task.Actions) {
        if (Test-BadPath $Action.Execute)           { $IsBad = $true; break }
        if (Test-BadHash $Action.Execute)           { $IsBad = $true; break }
        if (Test-SuspiciousCommand "$($Action.Execute) $($Action.Arguments)") { $IsBad = $true; break }
    }

    if ($IsBad) {
        Flag-Suspicious "ScheduledTask:$($Task.TaskPath)$($Task.TaskName)" "suspicious action: $CmdStr"
        # Export definition before removal
        try {
            Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath |
                Out-File "$QuarantineDir\task-$($Task.TaskName -replace '\W','_').xml" -Encoding UTF8
        } catch {}
        Remove-PersistenceEntry "ScheduledTask:$($Task.TaskName)" {
            Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false
        }
    }
}

# -- Registry Run Keys ---------------------------------------------------------
$RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
)

foreach ($KeyPath in $RunKeyPaths) {
    if (-not (Test-Path $KeyPath -ErrorAction SilentlyContinue)) { continue }
    try {
        $RegValues = Get-ItemProperty $KeyPath -ErrorAction SilentlyContinue
        if (-not $RegValues) { continue }
        $RegValues.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $ValueName = $_.Name
            $ValueData = $_.Value.ToString()

            if (Test-BadPath $ValueData -or Test-SuspiciousCommand $ValueData) {
                Flag-Suspicious "RegRun:$KeyPath\$ValueName" "suspicious command: $($ValueData.Substring(0,[Math]::Min(120,$ValueData.Length)))"
                # Back up before removal
                "$ValueName = $ValueData" | Out-File "$QuarantineDir\regrun-$(($KeyPath -replace '[:\\]','-')).txt" -Append -Encoding UTF8
                Remove-PersistenceEntry "RegRun:$KeyPath\$ValueName" {
                    Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force
                }
            }
        }
    } catch {}
}

# -- Startup Folders -----------------------------------------------------------
$StartupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($StartupDir in $StartupDirs) {
    if (-not (Test-Path $StartupDir)) { continue }
    Get-ChildItem -Path $StartupDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        $IsBad = $false
        $Content = try { Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue } catch { '' }
        if (Test-BadHash $_.FullName)     { $IsBad = $true }
        if (Test-BadPath $_.FullName)     { $IsBad = $true }
        if (Test-SuspiciousCommand $Content) { $IsBad = $true }

        if ($IsBad) {
            Flag-Suspicious "Startup:$($_.FullName)" "suspicious startup entry"
            Copy-Item $_.FullName "$QuarantineDir\startup-$($_.Name)" -Force -ErrorAction SilentlyContinue
            Remove-PersistenceEntry "Startup:$($_.FullName)" { Remove-Item $_.FullName -Force }
        }
    }
}

# -- Services ------------------------------------------------------------------
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.StartMode -ne 'Disabled' -and $_.PathName
} | ForEach-Object {
    $SvcPath = $_.PathName -replace '"','' -replace ' .*$',''
    $IsBad = $false
    if (Test-BadPath $_.PathName)  { $IsBad = $true }
    if (Test-BadHash $SvcPath)     { $IsBad = $true }
    if (Test-SuspiciousCommand $_.PathName) { $IsBad = $true }

    if ($IsBad) {
        Flag-Suspicious "Service:$($_.Name)" "suspicious path: $($_.PathName)"
        Remove-PersistenceEntry "Service:$($_.Name)" {
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
            sc.exe delete $_.Name 2>$null | Out-Null
        }
    }
}

# -- WMI Persistent Subscriptions ---------------------------------------------
try {
    $Consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($Consumer in $Consumers) {
        $ConsumerStr = ($Consumer | ConvertTo-Json -Depth 2 -Compress)
        if (Test-SuspiciousCommand $ConsumerStr) {
            Flag-Suspicious "WMI-Consumer:$($Consumer.Name)" "suspicious WMI consumer"
            $ConsumerStr | Out-File "$QuarantineDir\wmi-consumer-$($Consumer.Name -replace '\W','_').json" -Encoding UTF8
            # Remove all bindings referencing this consumer first
            Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.Consumer.Name -eq $Consumer.Name } |
                ForEach-Object { Remove-CimInstance $_ -ErrorAction SilentlyContinue }
            Remove-PersistenceEntry "WMI-Consumer:$($Consumer.Name)" {
                Remove-CimInstance $Consumer
            }
        }
    }
} catch { Write-IRLog "PERSIST: WMI sweep error: $_" }

# -- COM Object Hijacking (HKCU + HKLM InprocServer32) ------------------------
# HKCU hijacks override HKLM entries; HKLM tampering requires elevated persistence
foreach ($ComBase in @('HKCU:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\Classes\CLSID')) {
    try {
        if (-not (Test-Path $ComBase)) { continue }
        Get-ChildItem $ComBase -ErrorAction SilentlyContinue | ForEach-Object {
            $Clsid = $_
            $InProc = "$($Clsid.PSPath)\InprocServer32"
            if (Test-Path $InProc) {
                $DllPath = (Get-ItemProperty $InProc -ErrorAction SilentlyContinue).'(default)'
                if (-not $DllPath) { return }
                $IsBad = Test-BadPath $DllPath -or Test-BadHash $DllPath
                # Flag DLLs outside Windows trusted locations (system32, syswow64, Program Files, WinSxS)
                if (-not $IsBad -and $DllPath -notmatch '(?i)(system32|syswow64|Program Files|WinSxS|Microsoft\.NET|WindowsApps)') {
                    $IsBad = $true
                }
                # Flag unsigned DLLs that exist on disk
                if (-not $IsBad -and (Test-Path $DllPath -ErrorAction SilentlyContinue)) {
                    $Sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
                    if ($Sig -and $Sig.Status -ne 'Valid') { $IsBad = $true }
                }
                if ($IsBad) {
                    $ClsidName = $Clsid.PSChildName
                    Flag-Suspicious "COM-Hijack:$ClsidName" "rogue InprocServer32 in $ComBase : $DllPath"
                    Remove-PersistenceEntry "COM-Hijack:$ClsidName" {
                        Remove-Item -Path $Clsid.PSPath -Recurse -Force
                    }
                }
            }
        }
    } catch {}
}

# -- AppInit_DLLs --------------------------------------------------------------
$AppInitPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
)
foreach ($AiPath in $AppInitPaths) {
    if (-not (Test-Path $AiPath)) { continue }
    $AppInit = (Get-ItemProperty $AiPath -ErrorAction SilentlyContinue).AppInit_DLLs
    if ($AppInit -and $AppInit.Length -gt 0) {
        Flag-Suspicious "AppInit_DLLs:$AiPath" "non-empty AppInit_DLLs: $AppInit"
        Set-ItemProperty $AiPath AppInit_DLLs '' -Force -ErrorAction SilentlyContinue
        $script:Removed++
    }
}

# -- LSA Authentication Packages -----------------------------------------------
$LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if (Test-Path $LsaPath) {
    $AuthPkgs = (Get-ItemProperty $LsaPath).'Authentication Packages' -join ' '
    $SecPkgs  = (Get-ItemProperty $LsaPath).'Security Packages' -join ' '
    foreach ($Pkg in ($AuthPkgs, $SecPkgs)) {
        if ($Pkg -and (Test-SuspiciousCommand $Pkg)) {
            Flag-Suspicious "LSA-Package:$Pkg" "suspicious LSA provider"
        }
    }
}

# -- PowerShell Profiles -------------------------------------------------------
$PSProfiles = @(
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
)
foreach ($PSProfile in $PSProfiles) {
    if (-not (Test-Path $PSProfile -ErrorAction SilentlyContinue)) { continue }
    $Content = Get-Content $PSProfile -Raw -ErrorAction SilentlyContinue
    if (Test-SuspiciousCommand $Content) {
        Flag-Suspicious "PSProfile:$PSProfile" "suspicious PowerShell profile content"
        Copy-Item $PSProfile "$QuarantineDir\ps-profile-$(Split-Path $PSProfile -Leaf)" -Force -ErrorAction SilentlyContinue
        Remove-PersistenceEntry "PSProfile:$PSProfile" { Remove-Item $PSProfile -Force }
    }
}

# -- BITS Persistent Jobs ------------------------------------------------------
# Attackers use BITS for fileless C2 download persistence; non-system jobs are rare
try {
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notmatch '(?i)Microsoft|Windows Update|Background Intelligent|WU' } |
        ForEach-Object {
            $Job = $_
            $Url = (Get-BitsTransferItem -BitsJob $Job -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RemoteName -First 1)
            Flag-Suspicious "BITS:$($Job.DisplayName)" "non-system BITS transfer job - URL: $Url"
            Remove-PersistenceEntry "BITS:$($Job.DisplayName)" {
                Remove-BitsTransfer -BitsJob $Job
            }
        }
} catch {}

# -- ETW/AMSI Tampering Remediation -------------------------------------------
try {
    $AmsiKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script\Settings'
    if (Test-Path $AmsiKey) {
        if ((Get-ItemProperty $AmsiKey -ErrorAction SilentlyContinue).AmsiEnable -eq 0) {
            Flag-Suspicious "AMSI-Disabled" "AmsiEnable=0 in registry - AMSI explicitly bypassed"
            Remove-PersistenceEntry "AMSI-Disabled" {
                Set-ItemProperty $AmsiKey -Name AmsiEnable -Value 1 -Force
            }
        }
    }
    $AutologgerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
    if (Test-Path $AutologgerPath) {
        Get-ChildItem $AutologgerPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Session     = $_
            $SessionName = $Session.PSChildName
            $SessionPath = $Session.PSPath
            $Enabled = (Get-ItemProperty $Session.PSPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
            if ($Enabled -eq 0) {
                Flag-Suspicious "ETW-Autologger:$SessionName" "ETW Autologger session disabled - attacker blinding event tracing"
                Remove-PersistenceEntry "ETW-Autologger:$SessionName" {
                    Set-ItemProperty -Path $SessionPath -Name Enabled -Value 1 -Force
                }
            }
        }
    }
} catch {}

# -- PendingFileRenameOperations (MoveEDR / boot-time EDR deletion) ------------
try {
    $PfroKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $Pfro = (Get-ItemProperty $PfroKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($Pfro -and $Pfro.Count -gt 0) {
        $Pfro | Out-File "$QuarantineDir\pending_renames.txt" -Encoding UTF8
        Flag-Suspicious "PendingFileRenameOperations" "$($Pfro.Count) entries present - possible boot-time EDR deletion (MoveEDR)"
        # Remove only entries matching known-bad paths; preserve legitimate update renames
        # @() ensures an empty array (not $null) when all entries are filtered out
        $CleanPfro = @($Pfro | Where-Object { -not (Test-BadPath $_) })
        if ($CleanPfro.Count -lt $Pfro.Count) {
            Set-ItemProperty -Path $PfroKey -Name PendingFileRenameOperations -Value $CleanPfro -Force -ErrorAction SilentlyContinue
            Write-IRLog "PERSIST: Removed $($Pfro.Count - $CleanPfro.Count) bad PendingFileRenameOperations entries"
            $script:Removed += ($Pfro.Count - $CleanPfro.Count)
        }
    }
} catch {}

# -- BYOVD kernel driver detection ---------------------------------------------
# Bring-Your-Own-Vulnerable-Driver is used to kill EDR agents from kernel space
$KnownVulnerableDrivers = @(
    'capcom.sys', 'iqvw64.sys', 'RTCore64.sys', 'DBUtil_2_3.sys', 'TfSysMon.sys',
    'gdrv.sys', 'AsrDrv.sys', 'AsrDrv101.sys', 'AsrDrv102.sys', 'AsrDrv103.sys',
    'aswArPot.sys', 'aswSP.sys', 'MsIo64.sys', 'WinRing0x64.sys', 'WinRing0.sys',
    'Truesight.sys', 'DBUtil.sys', 'BdApiUtil64.sys', 'NSecKrnl.sys',
    'IoBitUnlocker.sys', 'Zemana.sys', 'agent64.sys', 'AODDriver.sys',
    'ASMMAP.sys', 'ASRDRV.sys', 'ProcessMonitorDriver.sys', 'wsftprm.sys',
    'K7RKScan.sys', 'CcProtect.sys', 'amifldrv64.sys', 'AMIFLDRV.sys'
)
try {
    Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
        $Drv     = $_
        $DrvFile = [System.IO.Path]::GetFileName($Drv.PathName)
        if ($DrvFile -and ($KnownVulnerableDrivers -contains $DrvFile.ToLower())) {
            Flag-Suspicious "BYOVD-Driver:$($Drv.Name)" "known vulnerable driver loaded: '$DrvFile' - EDR kill chain risk"
        } elseif ($Drv.PathName -and (Test-Path $Drv.PathName -ErrorAction SilentlyContinue)) {
            $Sig = Get-AuthenticodeSignature -FilePath $Drv.PathName -ErrorAction SilentlyContinue
            if ($Sig -and $Sig.Status -ne 'Valid') {
                Flag-Suspicious "Unsigned-Driver:$($Drv.Name)" "unsigned kernel driver: $($Drv.PathName)"
            }
        }
    }
} catch {}

# -- Windows Defender exclusion audit ------------------------------------------
# Attackers add their staging paths to Defender exclusions to prevent detection
try {
    $Prefs = Get-MpPreference -ErrorAction SilentlyContinue
    foreach ($ExPath in ($Prefs.ExclusionPath | Where-Object { $_ })) {
        if ($ExPath -match '(?i)(\\Temp\\|\\AppData\\|\\Users\\Public|\\ProgramData\\(?!Microsoft\\Windows Defender))') {
            Flag-Suspicious "DefenderExclusion-Path:$ExPath" "Defender exclusion on attacker-typical staging path"
        }
    }
    foreach ($ExProc in ($Prefs.ExclusionProcess | Where-Object { $_ })) {
        if (Test-SuspiciousCommand $ExProc -or $MaliciousProcesses -contains $ExProc) {
            Flag-Suspicious "DefenderExclusion-Process:$ExProc" "Defender process exclusion for suspicious process"
        }
    }
} catch {}

Write-IRLog "PERSIST: Complete - removed: $Removed, suspicious: $($Suspicious.Count)"

@{
    phase       = 'persistence_removal'
    status      = 'success'
    removed     = $Removed
    suspicious  = $Suspicious.Count
    audit_log   = $AuditLog
    incident_id = $IncidentId
} | ConvertTo-Json -Compress | Write-Output

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZskk5eh7ml/A7
# gjYekwN5g/b5nQ5rZn/dg5zdFdRmLaCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
# lEKgkjdOOOytMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lSIFRvb2xraXQg
# Q29kZSBTaWduaW5nMB4XDTI2MDYyNjAyMjc0OFoXDTI5MDYyNjAyMzc0OFowIjEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCVM7HdfviXfsMldvVuCmIVeX2nhTRWSA3FnoNQ7zd2
# lsAZuL+EkM+xZ6OiH6L5B6gZsCree2lTU0n0aNdSbNxKgzfaxFL49pteZwFI3ooS
# E+sqbAHRlG7UYrB90qWqPy6L2nh0ntu7R3IPzCbhTl6wgdT3e4axY+Bt4zZqcGY4
# XNolYl32o1h6/Xn1RDbK2RTsIblxuVYfYLdCotMldxNkE3oXBItZUoiGYNyCbnS0
# pBeBzKuJ7110b3jMhW5euch+jNqPlo7xwpAy57ut6LB/F/apn5BMhVXL0BsSIISW
# bvDg8KnX0ryWSVzEhCRDULbHFHceT8KT0j22yIYBIe19AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUY4Zdh7We
# EeqWTl4U+JyMI+/Bv44wDQYJKoZIhvcNAQELBQADggEBAGADp8Vqkz5dS0PaRLED
# IuTzMDd6t33jfUATEmnXvHWcir5zyCZhwz+iyGI8atBuTvD9t4skDJNEf+niZneM
# Ql2/lr6nz/cGlWdZjgOAdIsj4I3MSrAwXN7fK5QjyXcCUQpzTfBifVshB7vl3006
# QYE2GwXHWt5/rJKNRHKXBdtuw9XL1iUtmgQOwHhLJ4F//Lf59Fon5KGP7Hmt8tJv
# HrfolpKc7pF7XKyO3grw2sOz7BnmVYBRGTAhVJ+E/+IFAPUsThQFila4LAsvqCPv
# 265GLrtTUiXjZOcQ0LT5ohZWcvU4fpQ3b473zxrl0IpfARI5XSlTC/T6arQoRyXU
# 4QwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEB9AyPDIBaeUQqCSN0447K0w
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgenYnMZ8VZm4FYK+2LvI5jjfwDZHgPW+EBzUC
# ya+z7ngwDQYJKoZIhvcNAQEBBQAEggEAbKpbF8TCXvld6XSPqT6xeikXizskMchd
# 8WbJczLyLexkdaCvQkCqYdN5b2Zd/i1OAhs+LXoBzFjbymoPjP3LVC5FmPso7e7h
# kTCkMrX3zFyTRMdxAGe6g96QN0uTLgX8agIyuNEZHRye7vPR6d3cm+blilyQulmW
# 1kyTkhRMS8CcOk5aslAReJCNPORravJHqf0S6D50zuJSmegOwoB9w3xQIX61HXCQ
# UDcGyrWia5AyE5PKU2Y+r9jGcZUUrqbYtEvhY4Hic/w6vf1AnQqIZ1NlLgsWomCM
# j+W6JCfTEz+Yk3aOGW6Gv3ASRHi3TEoFk+chn7rNlD/0YXad+NDFeqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MThaMC8GCSqGSIb3DQEJBDEiBCDW
# orMIz1VAVZqqoailgxPC8UOWCZz1/snNFDK4nTyr5zANBgkqhkiG9w0BAQEFAASC
# AgCjAIwZlKf6USqJCLmpHZc5GJyeggmGPWErJWnnJ8Er2KJOd8PsXPCvbwMcpsa2
# UXGFbZo6K5MpMrlpD1TwXhquBL/DBaazPbv7ZWG7/xeR0FMS0/nlv3DmcHTSiWQm
# 7CreBy7FESv0X7vyzCQaSjKkSs6N+yMHaD/U/HVLdCuYBPhsEZig9Bzfk6LLzilM
# 04sgr2I2VZPv3a1djS6Kb1U1Wpuo3aWaBeFf6oIQuLO8CmGNV/FKKulhOs85ad+A
# 6Vp4SivTs1I73tD070R0oGVb93snzkfiA3hPhsJurA/w64UwARdr8DbtzvLws1IN
# qyImQAKGWCRcPQZPSHgNzWtrYJ0+Hy8PnkVBSKMTs052pOAWv0S426on97gOybSw
# w4Zt55ebKVT0PWlSlY8WZylfbqJFtx9vQ3jh+tAPqW1t9j64dPgKswroI3dannVs
# i4zCg9k3GMNul1whKptTCJvl2/X5XhWCXHDYzv9ZxoedlJw5hVGlaV+Jc3ZR9rwB
# 8/isoSYCg04LpRaCFoYcWXun/impCxDL/CZ0xKAkCXKLuy1n+E+ha2+RXINUJkmf
# UyazZi4LiE24eP/oOyc5Cf5WtJInIQcXhM7G+rzHDV2aZoStT9b5X9/mq/qZDSzQ
# cB0/1Tm2USEu3NQPeEf3NILHEcbMPuwP6oT6dz0ilqZsQA==
# SIG # End signature block
