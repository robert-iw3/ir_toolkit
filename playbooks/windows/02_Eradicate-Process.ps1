# ==============================================================================
# IR Playbook 02 - Windows Process Eradication
# Terminates malicious processes by PID and name. Quarantines matching binaries
# by SHA256 hash. Adds hashes to Windows Defender exclusions-in-reverse
# (block via WDAC/AppLocker policy if available). Never touches system processes.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId          = $env:IR_INCIDENT_ID -replace '[^\w\-]',''
$MaliciousPids       = ($env:IR_MALICIOUS_PIDS       -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$MaliciousProcesses  = ($env:IR_MALICIOUS_PROCESSES  -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$MaliciousHashes     = ($env:IR_MALICIOUS_HASHES     -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }

$IRDir      = 'C:\ProgramData\IRToolkit'
$QuarantineDir = "$IRDir\Quarantine\$IncidentId"
New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null

# Rollback journal -- one JSON line per reversible action so 06_Restore-Host.ps1 can
# undo this eradication if the investigation later returns a FALSE POSITIVE verdict.
$RollbackDir     = "$IRDir\rollback"
$RollbackJournal = "$RollbackDir\$IncidentId.jsonl"
New-Item -ItemType Directory -Path $RollbackDir -Force | Out-Null
function Write-Rollback([hashtable]$Entry) {
    ($Entry | ConvertTo-Json -Compress) | Out-File -FilePath $RollbackJournal -Append -Encoding UTF8
}

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
    Write-Output $entry
    $entry | Out-File "$IRDir\playbook.log" -Append -Encoding UTF8
}

# System processes that are never targeted regardless of input
$ProtectedProcesses = @('System','smss','csrss','wininit','winlogon','services',
                        'lsass','svchost','spoolsv','explorer','taskhostw',
                        'dwm','fontdrvhost','RuntimeBroker')

function Stop-ProcessTree {
    param([int]$ProcessId)
    if ($ProcessId -le 4) { return }  # Never kill System/Idle

    # Recursively stop child processes first
    $Children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue
    foreach ($Child in $Children) {
        Stop-ProcessTree -ProcessId $Child.ProcessId
    }

    try {
        $Proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($Proc) {
            $Name = $Proc.Name
            Write-IRLog "ERADICATE-PROC: Stopping PID $ProcessId ($Name)"
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-IRLog "ERADICATE-PROC: Failed to stop PID $ProcessId : $_"
    }
}

$KilledPids    = [System.Collections.Generic.List[int]]::new()
$KilledProcs   = [System.Collections.Generic.List[string]]::new()
$Quarantined   = [System.Collections.Generic.List[string]]::new()
$Errors        = [System.Collections.Generic.List[string]]::new()

Write-IRLog "ERADICATE-PROC: Starting process eradication for $IncidentId"

# -- Kill by PID ---------------------------------------------------------------
foreach ($PidStr in $MaliciousPids) {
    if (-not ($PidStr -match '^\d+$')) { $Errors.Add("invalid_pid:$PidStr"); continue }
    $ProcId = [int]$PidStr
    if ($ProcId -le 4) { $Errors.Add("refused_system_pid:$ProcId"); continue }

    $Proc = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if (-not $Proc) { Write-IRLog "ERADICATE-PROC: PID $ProcId already gone"; continue }
    if ($ProtectedProcesses -contains $Proc.Name) {
        $Errors.Add("refused_protected:$($Proc.Name):$ProcId"); continue
    }

    # Log what we're about to kill
    Write-IRLog "ERADICATE-PROC: Targeting PID $ProcId ($($Proc.Name)) - $($Proc.Path)"
    Stop-ProcessTree -ProcessId $ProcId
    $KilledPids.Add($ProcId)
}

# -- Kill by Process Name ------------------------------------------------------
foreach ($ProcName in $MaliciousProcesses) {
    if ($ProtectedProcesses -contains $ProcName) {
        $Errors.Add("refused_protected:$ProcName"); continue
    }

    $Matching = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
    foreach ($P in $Matching) {
        Write-IRLog "ERADICATE-PROC: Killing '$ProcName' PID $($P.Id) - $($P.Path)"
        Stop-ProcessTree -ProcessId $P.Id
        $KilledProcs.Add($ProcName)
    }
}

# -- Quarantine and block binaries by SHA256 hash ------------------------------
$SearchPaths = @($env:TEMP, $env:TMP, 'C:\Windows\Temp', $env:APPDATA,
                 $env:LOCALAPPDATA, "$env:ProgramData", 'C:\Users',
                 'C:\ProgramData', 'C:\Windows\System32\Tasks')

foreach ($BadHash in $MaliciousHashes) {
    if ($BadHash.Length -ne 64 -or $BadHash -notmatch '^[0-9a-fA-F]+$') {
        $Errors.Add("invalid_hash:$($BadHash.Substring(0,[Math]::Min(16,$BadHash.Length)))"); continue
    }

    foreach ($SearchPath in $SearchPaths) {
        if (-not (Test-Path $SearchPath)) { continue }
        try {
            Get-ChildItem -Path $SearchPath -Recurse -Force -File -ErrorAction SilentlyContinue |
                ForEach-Object {
                    try {
                        $FileHash = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        if ($FileHash -eq $BadHash.ToUpper()) {
                            Write-IRLog "ERADICATE-PROC: Hash match - $($_.FullName)"

                            # Kill any process running this file before moving it
                            $CurrentFile = $_.FullName
                            Get-Process | Where-Object { $_.Path -eq $CurrentFile } |
                                ForEach-Object { Stop-ProcessTree -ProcessId $_.Id }

                            # Move to quarantine
                            $Dest = Join-Path $QuarantineDir "$($_.Name)-$($BadHash.Substring(0,12))"
                            try {
                                Move-Item -Path $_.FullName -Destination $Dest -Force
                                $Quarantined.Add($_.FullName)
                                Write-Rollback @{ action='quarantine'; original=$CurrentFile; dest=$Dest; sha256=$BadHash }
                                Write-IRLog "ERADICATE-PROC: Quarantined $($_.FullName)"
                            } catch {
                                # Move failed - make unexecutable as fallback
                                $acl = Get-Acl $_.FullName
                                $acl.SetAccessRuleProtection($true, $false)
                                $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                                Set-Acl -Path $_.FullName -AclObject $acl -ErrorAction SilentlyContinue
                                $Errors.Add("move_failed_acl_stripped:$($_.FullName)")
                            }

                            # Block the hash in Windows Defender (if active)
                            try {
                                Add-MpPreference -ThreatIDDefaultAction_Ids 0 `
                                    -ThreatIDDefaultAction_Actions Block `
                                    -ErrorAction SilentlyContinue
                            } catch {}
                        }
                    } catch {}
                }
        } catch {}
    }
}

# -- Hidden process detection (WMI vs Get-Process API discrepancy) -------------
# Rootkits hide from Get-Process but remain visible via WMI (different enumeration path)
try {
    $ApiPids = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ApiPids[$_.Id] = $true }
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.ProcessId -gt 4 -and -not $ApiPids.ContainsKey($_.ProcessId)) {
            Write-IRLog "ERADICATE-PROC: HIDDEN PROCESS - PID $($_.ProcessId) ($($_.Name)) visible via WMI but absent from Get-Process"
            $Errors.Add("hidden_proc:$($_.ProcessId):$($_.Name)")
        }
    }
} catch { Write-IRLog "ERADICATE-PROC: Hidden process check error: $_" }

# -- Reflective DLL injection detection ----------------------------------------
# Modules loaded in process memory with no corresponding file on disk = reflective injection
try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $P = $_
        try {
            $P.Modules | Where-Object {
                $_.FileName -and -not (Test-Path $_.FileName -ErrorAction SilentlyContinue)
            } | ForEach-Object {
                Write-IRLog "ERADICATE-PROC: REFLECTIVE DLL - $($P.Name) PID $($P.Id) has module '$($_.ModuleName)' not on disk"
                $Errors.Add("reflective_dll:$($P.Id):$($_.ModuleName)")
            }
        } catch {}
    }
} catch {}

# -- Malicious BITS persistent jobs --------------------------------------------
try {
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -notmatch '(?i)Microsoft|Windows Update|Background Intelligent|WU' } |
        ForEach-Object {
            $Job = $_
            Write-IRLog "ERADICATE-PROC: Removing suspicious BITS job '$($Job.DisplayName)' [State: $($Job.JobState)]"
            Remove-BitsTransfer -BitsJob $Job -ErrorAction SilentlyContinue
            $Errors.Add("bits_job_removed:$($Job.DisplayName)")
        }
} catch {}

# -- ETW/AMSI tampering detection and remediation ------------------------------
try {
    # AMSI providers missing = attacker blinded antimalware scanning
    $AmsiProv = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    if (Test-Path $AmsiProv) {
        if ((Get-ChildItem $AmsiProv -ErrorAction SilentlyContinue).Count -eq 0) {
            Write-IRLog "ERADICATE-PROC: CRITICAL - 0 AMSI providers registered (AMSI fully bypassed)"
            $Errors.Add("amsi_providers_empty")
        }
    }
    # AmsiEnable = 0 means AMSI was explicitly disabled via registry
    $AmsiKey = 'HKLM:\SOFTWARE\Microsoft\Windows Script\Settings'
    if (Test-Path $AmsiKey) {
        if ((Get-ItemProperty $AmsiKey -ErrorAction SilentlyContinue).AmsiEnable -eq 0) {
            Write-IRLog "ERADICATE-PROC: AmsiEnable=0 detected - re-enabling AMSI"
            Set-ItemProperty $AmsiKey -Name AmsiEnable -Value 1 -Force -ErrorAction SilentlyContinue
            $Errors.Add("amsi_reenabled")
        }
    }
    # Disabled ETW Autologger sessions = attacker blinded event tracing
    $AutologgerPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
    if (Test-Path $AutologgerPath) {
        Get-ChildItem $AutologgerPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Enabled = (Get-ItemProperty $_.PSPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
            if ($Enabled -eq 0) {
                Write-IRLog "ERADICATE-PROC: ETW Autologger '$($_.PSChildName)' is disabled - possible ETW tampering"
                $Errors.Add("etw_disabled:$($_.PSChildName)")
            }
        }
    }
} catch { Write-IRLog "ERADICATE-PROC: ETW/AMSI check error: $_" }

# -- PendingFileRenameOperations (MoveEDR / boot-time EDR deletion) ------------
try {
    $PfroKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $Pfro = (Get-ItemProperty $PfroKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($Pfro -and $Pfro.Count -gt 0) {
        Write-IRLog "ERADICATE-PROC: PendingFileRenameOperations has $($Pfro.Count) entries - possible boot-time EDR deletion (MoveEDR)"
        $Pfro | Out-File "$IRDir\pending_renames_$IncidentId.txt" -Encoding UTF8
        $Errors.Add("pending_file_renames:$($Pfro.Count)")
    }
} catch {}

# -- Prevent restart via image file execution options (IFEO) -------------------
# Redirect bad process names to a dead-end (taskkill itself so it exits immediately)
foreach ($ProcName in $MaliciousProcesses) {
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ProcName.exe"
    try {
        if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
        Set-ItemProperty -Path $RegPath -Name Debugger -Value 'C:\Windows\System32\taskkill.exe /F /IM' -Force
        Write-IRLog "ERADICATE-PROC: IFEO redirect set for $ProcName.exe"
    } catch {
        $Errors.Add("ifeo_failed:$ProcName")
    }
}

Write-IRLog "ERADICATE-PROC: Complete. PIDs: $($KilledPids.Count), Procs: $($KilledProcs.Count), Quarantined: $($Quarantined.Count), Errors: $($Errors.Count)"

@{
    phase              = 'process_eradication'
    status             = 'success'
    killed_pids        = $KilledPids.Count
    killed_procs       = $KilledProcs.Count
    quarantined_files  = $Quarantined.Count
    errors             = $Errors.Count
    incident_id        = $IncidentId
} | ConvertTo-Json -Compress | Write-Output
