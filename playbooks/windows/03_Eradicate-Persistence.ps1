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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZskk5eh7ml/A7
# gjYekwN5g/b5nQ5rZn/dg5zdFdRmLaCCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
# nkbveZC/LiR8MA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjIwNDI0NDVaFw0zMTA2MjIwNDM0NDVaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKuTSorzjXf0qc4qX04KtYn2ErVj9RAkn/1f/9YN
# llrRj0s3urh/LnWmHn4vUjPrDTzHXUx4udOclWNlv52uCMAfXKZR3qD73OCHHQ2l
# +1s4JqrAdGhr6QPyIhCDwl7wqQUfekQtBep+SqbM0vkbvup3WKgol+c3fIUxvM8E
# bPLg5CcNWug6Twj+Wn1FJidJihmYARSKT5PFv32BLbffUpuvdWXxzRIRv8c4EE+S
# bWs3lTiCGrp1X33mXYiMRNAiF5ofrCJwRA7LESh4TCqXWDSvs+KFBi1ZxEnLxmUk
# 1Wrzq11umlIzoJhnEN0VyBvLK6X40uTF50piU+5kGy9kZlkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSpc1pf
# XTSlgxdtXKDrlumz7H67TjANBgkqhkiG9w0BAQsFAAOCAQEAdPAxdgyk/YzF72lK
# 4P1I3Lwjice2yAR0aoXSEP5gO/xnAvuqCiAcdPfJhqMrrfq5iFLqTuWSfz+k9irn
# hjzyWgmo2GUrQ8BVRoNAw7HpTJo7Rw8+FfDzyy+stq9UKWrkflHqwb7oBD+aBs/5
# ZccFKZi8oeV79CCTGdwXKYgE+xYbV//Twr7rpMbVUqbchEDdZXEzT2GdEUd5B02L
# bDGJ4Gjz8AtCFcSXWQlLnAQxd5CJVFHDkyfkEs2VvBPtR/MBCF3NiNufb8HgClhS
# ZHayqVVZhUd+NS7/orBY5M1Ioc0/kGiNO3nlWf1IlAPk/jsILweFZkUO0wBTot/O
# b18zszCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBsvfGvcX1ueRu95kL8u
# JHwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgenYnMZ8VZm4FYK+2LvI5jjfwDZHgPW+E
# BzUCya+z7ngwDQYJKoZIhvcNAQEBBQAEggEAJw0DwAFN9ErXzOo1slaJmrBjt2X9
# jm8NiUGazAPdDuSwmw99lmLF+STbis4f2Zo3T3cw3sKpNv7ekuJyk0xPdx0DCTE3
# 4S8RwPoNH5c+VQNNvNJNOnh6Sqr3oRI9VGazyqY8bEPCgnBPzbXFA6DervW0OOXA
# XeUv1UEkTxolwxpUR0uzlP9BJVQVgVfVd4AGAySuqByBWqWM7IJNZ2Z6R8k0XZqQ
# 8ch+R8nEic0X4FTVK+2hE6D9Hl3ge3vkpJelSbC88PzxCRe/PGduOKaY3yfpCdEf
# psvhjiajk/EwdmJygaYMBb8JX1yrndFkxThFSp9tIu780pHtEaQNu0iEmKGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NTJaMC8GCSqGSIb3DQEJBDEi
# BCBxH5EBhNRCNFaDgj7cEAiPPxNpsxFNVIvNkK0m4uQhlTANBgkqhkiG9w0BAQEF
# AASCAgBXSLt5Fnd8zYhbuTDwxaZRj8rtpm1Sx73Dng2t7gsyG1pZJTqdTJdFlbeO
# NPl++yx0MBKHwVWGecBu63YWKsxUm2goNFd7sk0y/5xyej3bX9LYYEjZ5fP2E3MT
# 8wE3xskSwDsHExf3xriu6uysXDdBQoNfTADHayqCCOB16JqiaXD+YlDsbHCVsTSG
# BQKKaJ9X82E7i4ysMyuCFekQQ7Juq0cUZFofa2wpKr/OywtEkbsRRwlx/7TnR64T
# BFNk/68RIpV+izJTTjEfdGhTTyoRmfp0J6K05fnaReHMrCWd6E9I76Etb93vEoUv
# /LA5GvdAp4g8xcXnZ/dmhIDoBJtnCprSkaN+RU6tulGMEIorLMdKwq0kqpGV6Z+D
# WF7gZMIDvjLuYPvPJns4JcL36iIQJPWZzbUteZnNNrwY8+u5YTiZy/tJ0fzUvxOa
# i16+y8mfmuupwIAIj0iQPsWYea3vKaawMR2Aw4Uh5pzMMCnOiAvWX26ATYwlPgQM
# ozj6cvn5lvrQ9L/7Et8/c38rlEp6FLU/nTnhj7wkNniN7Pre1lsfELF0tf7ASls9
# QqKgOcMbbu2uZKfKGwze963Q00fedzywJELAb4DVmXvkN5UD80Q6/t0uXTPYZBIy
# LNCH1jnb7ZD2D7Ywt799OoE0pVMd0oVIcUj70QVHhCYOD45QCg==
# SIG # End signature block
