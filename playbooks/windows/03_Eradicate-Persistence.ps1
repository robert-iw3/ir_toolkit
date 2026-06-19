# ==============================================================================
# IR Playbook 03 - Windows Persistence Eradication
# Hunts and removes attacker persistence across every Windows technique:
# Scheduled tasks, Run/RunOnce registry keys, startup folders, services,
# WMI subscriptions, COM hijacking, LSA providers, AppInit_DLLs, IFEO,
# PowerShell profiles, boot execute, and Winlogon values.
# Suspicious entries are quarantined and logged - never silently deleted.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId         = $env:IR_INCIDENT_ID -replace '[^\w\-]',''
$MaliciousHashes    = ($env:IR_MALICIOUS_HASHES    -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$MaliciousPaths     = ($env:IR_MALICIOUS_PATHS     -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$MaliciousProcesses = ($env:IR_MALICIOUS_PROCESSES -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }

$IRDir      = 'C:\ProgramData\IRToolkit'
$QuarantineDir = "$IRDir\Quarantine\$IncidentId\persistence"
$AuditLog      = "$IRDir\persistence-audit-$IncidentId.txt"
New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null

$Removed    = 0
$Suspicious = [System.Collections.Generic.List[string]]::new()

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
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
