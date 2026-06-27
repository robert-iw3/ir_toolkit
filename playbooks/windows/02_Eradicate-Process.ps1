# ==============================================================================
# IR Playbook 02 - Windows Process Eradication
# Terminates malicious processes by PID and name. Quarantines matching binaries
# by SHA256 hash. Adds hashes to Windows Defender exclusions-in-reverse
# (block via WDAC/AppLocker policy if available). Never touches system processes.
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputDir       = '',   # reports\<HOST>\ - passed by orchestrator
    [string]$IncidentId      = '',
    [string[]]$MaliciousPids       = @(),
    [string[]]$MaliciousProcesses  = @(),
    [string[]]$MaliciousHashes     = @(),
    [switch]$Apply                          # dry-run by default; pass -Apply to execute
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Parameter -> env var fallback
if (-not $IncidentId)        { $IncidentId       = ($env:IR_INCIDENT_ID -replace '[^\w\-]','') }
if (-not $MaliciousPids)     { $MaliciousPids    = ($env:IR_MALICIOUS_PIDS      -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $MaliciousProcesses){ $MaliciousProcesses = ($env:IR_MALICIOUS_PROCESSES -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $MaliciousHashes)   { $MaliciousHashes  = ($env:IR_MALICIOUS_HASHES    -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

$mode          = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
$IRDir         = if ($OutputDir) { $OutputDir } else { 'C:\ProgramData\IRToolkit' }
$QuarantineDir = Join-Path $IRDir "Quarantine\$IncidentId"
New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null

# Rollback journal - one JSON line per reversible action for 06_Restore-Host.ps1
$RollbackJournal = Join-Path $IRDir "Eradication_rollback_$IncidentId.jsonl"
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

    $Children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue
    foreach ($Child in $Children) { Stop-ProcessTree -ProcessId $Child.ProcessId }

    try {
        $Proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($Proc) {
            Write-IRLog "[$mode] ERADICATE-PROC: Stopping PID $ProcessId ($($Proc.Name))"
            if ($Apply) { Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue }
        }
    } catch { Write-IRLog "[$mode] ERADICATE-PROC: Failed to stop PID $ProcessId : $_" }
}

$KilledPids    = [System.Collections.Generic.List[int]]::new()
$KilledProcs   = [System.Collections.Generic.List[string]]::new()
$Quarantined   = [System.Collections.Generic.List[string]]::new()
$Errors        = [System.Collections.Generic.List[string]]::new()

Write-IRLog "[$mode] ERADICATE-PROC: Starting process eradication for $IncidentId"

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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9MvkOGokyt3rr
# KrFYtE57jOp7kwSWarvRhkObHC0hlKCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgs1IAIzrxc7w/qgbLbQfM5PMEUs7qul3smo4i
# 8M4N6QgwDQYJKoZIhvcNAQEBBQAEggEAH4rTK+I8HHtgqKHySkRbYknbohBOPSu0
# Q2c55FFk3n9WbPxWtjEMxnM4Rgurt2WRMkmXb89wEqLaIzXbYKHBVsCE0fCoDyAr
# GhlDA7wti+2Pl3HdE5Oy4YLCtUcgFlPdZdJb+msTlTiFZRjuf+WCCdpVHNr1/43X
# LtWQWV3BqmUxEAcmLjhx5X+2xvQ5aCdoAtR+lADywCz+zbn57yEaQgv+LCFjW897
# 54aPANc7l6+IhwVt5BU7Z/PP5tCSmO0HSf1Fa5ProXJglKSRdDOCPD/F8VgnQUl6
# I1hr/s0tEuyLdFBJDCDpove88ogjU/uQG4B/BGwkX7oHiXzLOJ/BUKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MTZaMC8GCSqGSIb3DQEJBDEiBCDY
# S5+RkbQlgZIs7cfN/LGvOQPK96+yM7Xxo7qehVhWvDANBgkqhkiG9w0BAQEFAASC
# AgDFKcPQnVGM8+PJEqF97CxfSkio3oMr0RnrOwr9rJKEK/WWGcxO7G2fLpOxIqwy
# 48UAeDWc286eFJPH3UOWJVCRLGHEe3/FhboFhVYkMtdnp9sKKkV8TlIMnHYKYuY2
# pzZ0Ts1IrHyweMXfCHuGRXG3c5PQ5VJcM59a17D0osawGzz8MYUqN3n8u1DxfG7O
# Sc9o5fF2cRZ5XCwbpwHKkpZvxdmIHY7fI+Twnkxa3EC7qNlTrp+a+qHlcQAZje2l
# 2kvz9RTdK9xXEZwJBw8T56idW4go5NzjpCuWV0NYZMGUHmsLenzQfW8oNYof2BUu
# JYDizVeNLevOUjsr2oYve1flMwDWAgLSOb3r4PZffB11Xg5nTr3k9IjI98tV+wM6
# hh43VA+3IZQUOCP/ngzp1ey9+JYqKey+UwbCvfp3haJf6C0iGaURc4jQFbT4dyko
# V4P9RJ019bs2J9h8AWI/07f6idnKe8vlNodpULLoOZOlvWG4GszaLO/X7F8uNEir
# J4qFZktlE4WpBrOPJdP1BiyWJ+Q5GBT4/wawr5cRLpgrGUGc22J2J+RE762bfHs+
# rn/EaPru+fPZdn63fsAVFSQZnzoS3Al8cdoWkobn3hq8OHs9T1SiM7NJFTBMFrxm
# zgQRLV8Ai1kKXXAQmQlg/vhqGie87gtXLM/e7Ucb6tCgBA==
# SIG # End signature block
