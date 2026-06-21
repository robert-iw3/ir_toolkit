<#
.SYNOPSIS
    Standalone orchestrator for the Windows RESPONSE playbooks (contain / eradicate /
    block-C2 / acquire / restore). Completely separate from the collection workflow
    (Invoke-IRCollection.ps1) - this one CHANGES the host.
.DESCRIPTION
    Runs the playbooks in playbooks\windows\ in canonical IR order, feeding each its
    inputs via the IR_* environment variables the scripts expect. Each playbook
    runs in its own powershell process and its output is logged to a Response folder.

    These actions are DESTRUCTIVE (kill processes, isolate the network, quarantine
    files, sinkhole domains). The orchestrator therefore:
      * runs nothing unless you both pass -Phases AND -Confirm (otherwise it prints
        the plan and exits - a dry run),
      * refuses Contain without -MgmtIPs (would sever remote access),
      * always runs phases in safe order regardless of the order you list them.

.PARAMETER Phases   Which playbooks to run: Collect, Contain, EradicateProcess,
                    EradicatePersistence, BlockC2, Acquire, Restore.
.PARAMETER Confirm  Required to actually execute. Without it: dry-run plan only.
.EXAMPLE
    # Dry-run plan:
    .\Invoke-WindowsPlaybooks.ps1 -Phases EradicateProcess,BlockC2 -MaliciousPids 6624 -C2IPs 8.8.8.8
.EXAMPLE
    # Execute containment + eradication:
    .\Invoke-WindowsPlaybooks.ps1 -Phases Contain,EradicateProcess,BlockC2 `
        -MgmtIPs 10.0.0.5 -MaliciousProcesses anydesk -C2IPs 45.61.2.3 -Confirm
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Collect','Contain','EradicateProcess','EradicatePersistence','BlockC2','Acquire','Restore')]
    [string[]]$Phases,
    [string]$IncidentId,
    [string]$OutputRoot = $PSScriptRoot,
    # Inputs consumed by the playbooks (comma-separated where plural):
    [string]$MgmtIPs,
    [string]$MaliciousPids,
    [string]$MaliciousProcesses,
    [string]$MaliciousHashes,
    [string]$MaliciousPaths,
    [string]$C2IPs,
    [string]$C2Domains,
    [string]$TargetPath,
    [string]$QuarantineUri,
    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $IncidentId) { $IncidentId = "$($env:COMPUTERNAME)_$RunStamp" }
if (-not $OutputRoot) { $OutputRoot = (Get-Location).Path }
$OutDir = Join-Path $OutputRoot ("Response_" + $IncidentId)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$RunLog = Join-Path $OutDir "_response_$RunStamp.log"

function Write-Log { param([string]$M,[string]$C='Gray')
    $line="[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $M"; Write-Host $line -ForegroundColor $C
    $line | Out-File -FilePath $RunLog -Append -Encoding UTF8
}

# Canonical phase order + script mapping. (00 is param-based; 01-06 read IR_* env.)
$PhaseDefs = [ordered]@{
    Collect              = @{ Order=0; Script='windows\00_Collect-Forensics.ps1';     Destructive=$false }
    Contain              = @{ Order=1; Script='windows\01_Contain-Host.ps1';          Destructive=$true  }
    EradicateProcess     = @{ Order=2; Script='windows\02_Eradicate-Process.ps1';     Destructive=$true  }
    EradicatePersistence = @{ Order=3; Script='windows\03_Eradicate-Persistence.ps1'; Destructive=$true }
    BlockC2              = @{ Order=4; Script='windows\04_Block-C2.ps1';              Destructive=$true  }
    Acquire              = @{ Order=5; Script='windows\05_Acquire-Artifact.ps1';      Destructive=$false }
    Restore              = @{ Order=6; Script='windows\06_Restore-Host.ps1';          Destructive=$true  }
}

if (-not $Phases) {
    Write-Host "No -Phases specified. Available (canonical order):" -ForegroundColor Yellow
    $PhaseDefs.Keys | ForEach-Object { Write-Host "  - $_" }
    Write-Host "Re-run with -Phases <...> (and -Confirm to execute)." -ForegroundColor Yellow
    return
}

# Map inputs to the IR_* env vars the playbooks read (set once; children inherit).
$env:IR_INCIDENT_ID = $IncidentId
if ($PSBoundParameters.ContainsKey('MgmtIPs'))            { $env:IR_MGMT_IPS            = $MgmtIPs }
if ($PSBoundParameters.ContainsKey('MaliciousPids'))      { $env:IR_MALICIOUS_PIDS      = $MaliciousPids }
if ($PSBoundParameters.ContainsKey('MaliciousProcesses')) { $env:IR_MALICIOUS_PROCESSES = $MaliciousProcesses }
if ($PSBoundParameters.ContainsKey('MaliciousHashes'))    { $env:IR_MALICIOUS_HASHES    = $MaliciousHashes }
if ($PSBoundParameters.ContainsKey('MaliciousPaths'))     { $env:IR_MALICIOUS_PATHS     = $MaliciousPaths }
if ($PSBoundParameters.ContainsKey('C2IPs'))              { $env:IR_C2_IPS              = $C2IPs }
if ($PSBoundParameters.ContainsKey('C2Domains'))          { $env:IR_C2_DOMAINS          = $C2Domains }
if ($PSBoundParameters.ContainsKey('TargetPath'))         { $env:IR_TARGET_PATH         = $TargetPath }
if ($PSBoundParameters.ContainsKey('QuarantineUri'))      { $env:IR_QUARANTINE_URI      = $QuarantineUri }

# Resolve + order the requested phases.
$plan = $Phases | Select-Object -Unique | Sort-Object { $PhaseDefs[$_].Order }

# Safety preconditions
$abort = $false
if (($plan -contains 'Contain') -and -not $MgmtIPs) {
    Write-Log "REFUSED: Contain requires -MgmtIPs (otherwise you isolate yourself out)." 'Red'; $abort = $true
}
if (($plan -contains 'Acquire') -and -not $TargetPath) {
    Write-Log "REFUSED: Acquire requires -TargetPath." 'Red'; $abort = $true
}
if ($abort) { return }

$mode = if ($Confirm) { 'EXECUTE' } else { 'DRY-RUN' }
Write-Log "===================================================" 'Green'
Write-Log " WINDOWS RESPONSE PLAYBOOKS ($mode) | incident=$IncidentId" 'Green'
Write-Log " plan: $($plan -join ' -> ')" 'Green'
Write-Log " output -> $OutDir" 'Green'
Write-Log "===================================================" 'Green'

$PSExe = (Get-Process -Id $PID).Path
if (-not $PSExe) { $PSExe = Join-Path $PSHOME 'powershell.exe' }

$results = foreach ($name in $plan) {
    $def = $PhaseDefs[$name]
    $script = Join-Path $PSScriptRoot $def.Script
    $rec = [ordered]@{ Phase=$name; Script=$def.Script; Destructive=$def.Destructive; Status='' }
    if (-not (Test-Path -LiteralPath $script)) { Write-Log "SKIP $name - not found: $script" 'Yellow'; $rec.Status='missing'; [PSCustomObject]$rec; continue }

    $tag = if ($def.Destructive) { '[DESTRUCTIVE]' } else { '' }
    if (-not $Confirm) {
        Write-Log "WOULD RUN: $name $tag -> $($def.Script)" 'Yellow'; $rec.Status='planned'; [PSCustomObject]$rec; continue
    }

    Write-Log "==== RUN: $name $tag ====" 'Cyan'
    $phaseLog = Join-Path $OutDir ("_{0}_{1}.log" -f $name, $RunStamp)
    $argList  = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $script)
    if ($name -eq 'Collect') { $argList += @('-OutputDir', $OutDir, '-IncidentId', $IncidentId) }
    try {
        & $PSExe @argList *>&1 | Tee-Object -FilePath $phaseLog -Append
        Write-Log "  $name complete (log: $(Split-Path -Leaf $phaseLog))" 'Green'; $rec.Status='ran'
    } catch { Write-Log "  ERROR in ${name}: $($_.Exception.Message)" 'Red'; $rec.Status='error' }
    [PSCustomObject]$rec
}

[ordered]@{
    incident_id=$IncidentId; host=$env:COMPUTERNAME; mode=$mode
    generated_utc=(Get-Date).ToUniversalTime().ToString('o'); plan=$plan; results=$results
} | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $OutDir "response_summary_$RunStamp.json") -Encoding UTF8

Write-Log "===================================================" 'Green'
Write-Log " RESPONSE $mode COMPLETE" 'Green'
if (-not $Confirm) { Write-Log " DRY-RUN: nothing changed. Add -Confirm to execute." 'Yellow' }
Write-Log " $OutDir" 'Green'
Write-Log "===================================================" 'Green'

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvfue9x8Sq13zw
# lX3CvyWQsOTceyNgAlauCbTLa+/MAqCCFrQwggN2MIICXqADAgECAhBa5MQyEl22
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgDdzVsiJdi+S81ftHw4qdA+y38HzGpuVN
# h/Dp9+SCeJkwDQYJKoZIhvcNAQEBBQAEggEAEzsPe+OkINIDOvB5JIxlYJOHVgb0
# Ebwslxih58AJTNXAnV1Nx7Q92wenjAIsgJgfAu4jEIeyhaTghlr3ByVVUodWYq+2
# nSJpzmAVKjLwR749/VKTKlYGZQpC5m/sEAlmZ4OAmPkrJXjhADyCN217bysXHb8M
# kgrcR+EEnPMohm8JfJVJJFjqACTpIfM4ofdF4ZJpXebhL6Fsz6YI5XFhnpd/RBp4
# dEmDjTjVsDlDgYvq7n4RXl5/LfVEFLZqTkkEWDcLRUf3ihmKoTvbjRai8Q4dTodA
# Efy8SkW2oAo8za9t3yw+hV/GHc67oaYofWwJB4zNklO0xf12vesb7td67qGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MjhaMC8GCSqGSIb3DQEJBDEi
# BCC3GgqlzTr4I1jUbVA4H/VqHVM8PktRJ4ynBJjStLNm4jANBgkqhkiG9w0BAQEF
# AASCAgCL+hS1nGOLuxDUfH4iC4h2HaDooObX0P0vU21dDf8y+Pqs3/j/K0Rpipb/
# F39Aecrf+USNAIsgErPdomsH5AWxOUyFZ5Y8IsOigVJzvZOcssk7WY7IwOGLU3//
# YEcyHIypfwEBv40moG95Oznvy8CRBhykg5Ddijq1QPsJeKOoVLbqcDLYN4tz6D4E
# CfTtudLFgq4HPMlvbgv1XLcG9kkvcn36Fdj02LxqsKagtXYqPOO9dcFQ5CbpBrav
# b2B2q2SC1n+AQR3iw3gNnCDaiZg4QMpXynoevBAEfkD52ciapTLmPNjzj/UV0EG9
# xNegiPnIVQuA893eOdbL4yobEzrjPK3mPl6X6pGkkHjwvXgIzuD0J1yd7W5vWt8Z
# TxYudPt1oMUjT3AsTc52C9Zm38M/YmrFOAwG55H3djDRGQr60SqLdDbTDul7IFC8
# ylE6SIEVFIZ2Mq9ALGe6qXUJWTnaPHq3Xl4wnrPgg6xi9YHev+Hkdfb6AsPXc6Sm
# MSl1qAPdEcrBIsg1KPhZ11GJtWwje4Nkbe5gELrmiFclQd9RGhpQWt2oLr3+IJsV
# xVmEX0xtfxsapTBHNW7tGdXwjy4fIVHTUlunnk/rN2YiR/alPqegRihXHE/n9p8q
# viTPvUN81lPy7KmIF/jn+qcV1Sx7XBn8OV5ZhEJK8FhsugeY+A==
# SIG # End signature block
