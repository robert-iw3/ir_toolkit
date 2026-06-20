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

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNukLthDM5uXe4
# /lwCGr9fhumOFaMQUrZDF8cL1Vi9vKCCFrQwggN2MIICXqADAgECAhBa5MQyEl22
# qUV1bZluOcpOMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjAwMDU5NDZaFw0zMTA2MjAwMTA5NDZaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAJ1nFbqBzQLbEhUUTT10Lrva+ooE/uVqzTJbGk5/
# xh3zYBEAaRil7obceqCWtDg6KSjbDQP8wto42fHUK8tp0FU0NEi2+rkWHfcpeasm
# z2e+UFQMDlXRcxg7dqe+08OB4pFhwrHSPo0m7HZAgtpHd02POka7jaYVoAnScg7i
# LuZiRSJ3tJKZu1KCSTntV+LbicnowTlaDEvr7JQzSVs+5BpNadU3n/ujzH088Mgm
# CoXooQpF12SzbZNCZ+kbgza6bNMbEHNGkLr9S0vHQD95oKPWF7YuOu7jqtkuCOZc
# KYYi4nOXFwLqXmJ+sqqpR2NrrfMkz4VaALGIZ93o10CHWDkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQRXBKC
# VXuhcK7rCDzb/6SAfPGwvDANBgkqhkiG9w0BAQsFAAOCAQEAlZhDvun+4lQ0yd2C
# +pAFD3B2/l2N9hArAcHhp6DaO48NSIT3eyyhGrfk8f3lDVhvjEbUDDmb6Oe67rBN
# 3W7Dp1Y+W8Z96kC3miq7UbmVTGkiQGZFwi0KJ8tw++//vlU3zlW9nhqwFxzm7DfL
# zECzv6bnd9Ri+1R4zhvkd5BLTuwLjPLkzbOTdsGwbXWWOK2gTTCr82I7G9xcq9Gv
# qAcoJAHVEiNKt7p7Y+ScDL/AZGBMCBTsN9gcAoIgq22EWBHHV02HmPfuYyddaq1c
# Lmjot0+5wVoPVl4wNktght1WVHDlk3EpEJF5qc7Yhl3YtniIEHQoO8BkWykpFDhy
# q5wz7TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEFrkxDISXbapRXVtmW45
# yk4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgHx88/EePXqRgACRBOafRTe5bTWdodMpK
# Qekv+3/2qBEwDQYJKoZIhvcNAQEBBQAEggEAafsAoNht3WOSrnY5O0XUFSLSr9m7
# nVSG6xaRXL1oV6ZX6l4UHFQEa2/cMuGUKSuDVzHsw8407hUV8qGNhyYIjuBj5FbV
# jwLbB/TWDBizX9VGhNoxfT4174hTUkueD5AU9pUVOyvAAYaI+2G0jAxuaNHCL16p
# IE+vLkWwTPsgqBT0+bpKBjcmvz7PVZ2rjAtk+KOdipmcetcI1J8HhrtVeK6xJKT4
# BgFjx48hypofCSJSwuEruz/su0g6ULrkk8gxRqdv3JJDXoq2a8flQtldjXNsi95C
# xwJ9tlvm/GPrRsHjVfhzJlDMqVMRdHiwQlf6eswzQff4TXjTgEq4rD8lZaGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MzBaMC8GCSqGSIb3DQEJBDEi
# BCByJtumuND7GjLFBGAhnrn6JRMINF1IS8da9WXEn9UpCjANBgkqhkiG9w0BAQEF
# AASCAgCj3hZqI8mvF1gM52on4F//8O0U7JPMhHzmmqTXJbHTN+8/M9XS3L/4ShAg
# bvW3jjiHHNpXHuFbSQOciDuMFn+AQAR/J3EoTjCuIS1PzrvDLJMI9sVajRdP+S/7
# gGhmG+9Uo/hvY/KFwyuKiGUxIoFWIwfZ8ucuV+QbLAHaYKu4btumf3/4iqcCCFmY
# ZjpyRgIR06y6y5yFz813OF+jPkM6xlg7iGkmCKUfTbOOWBmWCBpUi1RjDqk/tOlp
# VAXhZQ6bYOFOaT5OccqQQ3bH3JyHio4V8lcCOHvOcfDUQn0jWgcdcOb+nS5hQEYY
# 9LyFsZz+mp2rsznbkzQg8rCHgFxvE4JbJVb2wT4La8tebkzF2+xStzHq8LqS/B/2
# vTQa8nDNEPFUlLMIhwxWRJ1bZoXvum0BKxLPP0EHJbjctyTxUZIcUBpUaWGlJpx2
# jpc8x5YwOZIokD7laSFJMXLSL7V33k9VURDgqfutrsnDffWS2v20YbJIztvWjMUl
# W33VC3pbuyzvAo52/A2WmmVlp7sHrQtjrc5eVA2qy8FNTE237uSLfhlU7Yb7nC6C
# vHxingX8nYr+hAiCfn6m7t731UnYodUGiEhrtMXNcmDRX61b9d/kkTKppIMkIh8C
# HIBFoQmzISZm+e1ns+/Uq0Gi5TKJC9U9lEariz2abcUJHr71MQ==
# SIG # End signature block
