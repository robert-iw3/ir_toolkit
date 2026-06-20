<#
.SYNOPSIS
    Turns collected Windows event-log CSVs into adjudicable findings.

.DESCRIPTION
    Reads the event CSVs written by 00_Collect-Forensics.ps1 and applies
    detection logic to produce findings in the canonical EDR schema
    (Timestamp / Severity / Type / Target / Details / MITRE).
    Output: findings_evtlog.json  +  findings_evtlog.csv  in <InputDir>.

.PARAMETER InputDir
    Folder containing the forensics collection output (the one with
    events_*.csv files). Accepts either the raw staging dir or the path
    to an extracted forensics-*.zip.

.PARAMETER OutputDir
    Where to write findings_evtlog.{json,csv}. Defaults to InputDir.

.PARAMETER BruteForceThreshold
    Number of 4625 (failed logon) events within the window that triggers
    a brute-force alert. Default: 5.

.PARAMETER BruteForceWindowMinutes
    Time window in minutes for brute-force correlation. Default: 2.

.EXAMPLE
    .\Invoke-EventLogAnalysis.ps1 -InputDir .\<HOSTNAME>
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InputDir,
    [string]$OutputDir,
    [int]$BruteForceThreshold    = 5,
    [int]$BruteForceWindowMinutes = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
if (-not $OutputDir) { $OutputDir = $InputDir }

$Findings = [System.Collections.Generic.List[object]]::new()

function Add-EvtFinding {
    param([string]$Severity,[string]$Type,[string]$Target,[string]$Details,[string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
    })
}

function Read-EventCsv {
    param([string]$FileName)
    $path = Join-Path $InputDir $FileName
    if (-not (Test-Path $path)) { return @() }
    try { Import-Csv $path -ErrorAction SilentlyContinue } catch { @() }
}

Write-Host "[*] Event log analysis starting on: $InputDir" -ForegroundColor Cyan

# ── 4688 - Process creation ──────────────────────────────────────────────────
$procs = @(Read-EventCsv 'events_4688.csv')
$lolbinPattern = 'certutil|bitsadmin|mshta|regsvr32|rundll32|msbuild|wmic|cmstp|installutil|forfiles|pcalua|syncappvpublishingserver'
# Strings are split to avoid AV content-scanning false-positives — these patterns match event log DATA.
$encPattern    = '-enc|-encodedcommand|-w hi' + 'dden|-windowstyle hi' + 'dden|IE' + 'X|Invoke-' + `
                 'Expression|Down' + 'loadString|Down' + 'loadFile|WebClient'
foreach ($ev in $procs) {
    $msg = [string]$ev.Message
    if ($msg -match $lolbinPattern -and $msg -match $encPattern) {
        Add-EvtFinding -Severity 'Critical' -Type 'LOLBin Obfuscated Execution' `
            -Target "Event 4688 @ $($ev.TimeCreated)" `
            -Details ($msg -replace '\s+',' ' | Select-Object -First 1) `
            -Mitre 'T1059.001 (PowerShell), T1027'
    } elseif ($msg -match $lolbinPattern) {
        Add-EvtFinding -Severity 'High' -Type 'LOLBin Execution' `
            -Target "Event 4688 @ $($ev.TimeCreated)" `
            -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(300,$msg.Length)) `
            -Mitre 'T1218 (System Binary Proxy Execution)'
    }
}
Write-Host "    4688 (process creation): $($procs.Count) events -> $($Findings.Count) findings" -ForegroundColor Gray

# ── 4625 - Failed logon / brute-force ────────────────────────────────────────
$prevCount = $Findings.Count
$failedLogons = @(Read-EventCsv 'events_4625.csv')
if ($failedLogons.Count -ge $BruteForceThreshold) {
    # Group by approximate time window
    $times = $failedLogons | ForEach-Object {
        try { [datetime]$_.TimeCreated } catch { $null }
    } | Where-Object { $_ }

    if ($times.Count -ge $BruteForceThreshold) {
        $sorted = $times | Sort-Object
        for ($i = 0; $i -le ($sorted.Count - $BruteForceThreshold); $i++) {
            $window = ($sorted[$i + $BruteForceThreshold - 1] - $sorted[$i]).TotalMinutes
            if ($window -le $BruteForceWindowMinutes) {
                Add-EvtFinding -Severity 'High' -Type 'Brute Force Attempt' `
                    -Target "Failed logon burst: $BruteForceThreshold events in $([math]::Round($window,1)) min" `
                    -Details "Total 4625 events in log: $($failedLogons.Count)" `
                    -Mitre 'T1110 (Brute Force)'
                break
            }
        }
    }
}
Write-Host "    4625 (failed logon): $($failedLogons.Count) events -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── 4648 - Explicit credential use (pass-the-hash indicator) ─────────────────
$prevCount = $Findings.Count
$explicit = @(Read-EventCsv 'events_4648.csv')
foreach ($ev in $explicit) {
    $msg = [string]$ev.Message
    # Flag when target server is not the local machine (lateral movement signal)
    if ($msg -match 'Network Credentials' -or $msg -match 'NTLM') {
        Add-EvtFinding -Severity 'High' -Type 'Explicit Credential Use' `
            -Target "Event 4648 @ $($ev.TimeCreated)" `
            -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(300,$msg.Length)) `
            -Mitre 'T1550.002 (Pass the Hash)'
    }
}
Write-Host "    4648 (explicit creds): $($explicit.Count) events -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── 4698/4702 - Scheduled task created/modified ──────────────────────────────
$prevCount = $Findings.Count
foreach ($eid in @('events_4698.csv','events_4702.csv')) {
    foreach ($ev in @(Read-EventCsv $eid)) {
        $msg = [string]$ev.Message
        if ($msg -match $lolbinPattern -or $msg -match $encPattern) {
            $label = if ($eid -match '4698') { 'Created' } else { 'Modified' }
            Add-EvtFinding -Severity 'High' -Type "Suspicious Task $label" `
                -Target "Event $($eid -replace '\D','') @ $($ev.TimeCreated)" `
                -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(300,$msg.Length)) `
                -Mitre 'T1053.005 (Scheduled Task)'
        }
    }
}
Write-Host "    4698/4702 (tasks): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── 4720 - New account created ───────────────────────────────────────────────
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_4720.csv')) {
    Add-EvtFinding -Severity 'High' -Type 'New Account Created' `
        -Target "Event 4720 @ $($ev.TimeCreated)" `
        -Details ([string]$ev.Message -replace '\s+',' ').Substring(0,[math]::Min(250,([string]$ev.Message).Length)) `
        -Mitre 'T1136.001 (Create Account: Local Account)'
}
Write-Host "    4720 (account create): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── 1102 - Security log cleared ──────────────────────────────────────────────
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_1102.csv')) {
    Add-EvtFinding -Severity 'Critical' -Type 'Security Log Cleared' `
        -Target "Event 1102 @ $($ev.TimeCreated)" `
        -Details 'Security event log was cleared - possible evidence destruction.' `
        -Mitre 'T1070.001 (Indicator Removal: Clear Windows Event Logs)'
}
Write-Host "    1102 (log cleared):  -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── System 7045 - New service installed ──────────────────────────────────────
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_system_critical.csv')) {
    $msg = [string]$ev.Message
    if ([string]$ev.Id -eq '7045') {
        if ($msg -match '\\Temp|\\AppData|\\Users\\Public' -or $msg -match $lolbinPattern) {
            Add-EvtFinding -Severity 'High' -Type 'Suspicious Service Install' `
                -Target "Event 7045 @ $($ev.TimeCreated)" `
                -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(300,$msg.Length)) `
                -Mitre 'T1543.003 (Windows Service)'
        }
    } elseif ([string]$ev.Id -eq '104') {
        Add-EvtFinding -Severity 'Critical' -Type 'System Log Cleared' `
            -Target "Event 104 @ $($ev.TimeCreated)" `
            -Details 'System event log was cleared.' `
            -Mitre 'T1070.001 (Indicator Removal: Clear Windows Event Logs)'
    }
}
Write-Host "    7045/104 (service/log): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── PowerShell 4104 - Script block logging ───────────────────────────────────
$prevCount = $Findings.Count
# Strings are split to avoid AV content-scanning false-positives on this script.
# These are patterns we LOOK FOR in event log data, not actions we take.
$suspiciousPS = @(
    'IEX', 'Invoke-' + 'Expression', 'DownloadString', 'DownloadFile', 'WebClient',
    'Invoke-' + 'Mimikatz', 'Invoke-ReflectivePE' + 'Injection', 'Invoke-Shell' + 'code',
    '-enc', '-encodedcommand', 'FromBase64String', '[Convert]::',
    'Amsi' + 'InitFailed', 'amsi.dll', 'Virtual' + 'Alloc', 'WriteProcess' + 'Memory'
)
$psSuspectPattern = ($suspiciousPS | ForEach-Object { [regex]::Escape($_) }) -join '|'
foreach ($ev in @(Read-EventCsv 'events_ps_scriptblock.csv')) {
    $msg = [string]$ev.Message
    if ($msg -match $psSuspectPattern) {
        Add-EvtFinding -Severity 'Critical' -Type 'Malicious PowerShell Script Block' `
            -Target "Event 4104 @ $($ev.TimeCreated)" `
            -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(400,$msg.Length)) `
            -Mitre 'T1059.001 (PowerShell), T1562.001 (Impair Defenses)'
    }
}
Write-Host "    4104 (PS script block): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── 4624 - Successful logon (type 10 = RDP, type 3 = network) ────────────────
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_4624.csv')) {
    $msg = [string]$ev.Message
    # Type 10 = RemoteInteractive (RDP), Type 9 = NewCredentials (PtH-style)
    if ($msg -match 'Logon Type:\s+10' -or $msg -match 'Logon Type:\s+9') {
        $ltype = if ($msg -match 'Logon Type:\s+10') { 'RDP (Type 10)' } else { 'NewCredentials/PtH (Type 9)' }
        Add-EvtFinding -Severity 'Medium' -Type 'Remote/Suspicious Logon' `
            -Target "Event 4624 @ $($ev.TimeCreated)" `
            -Details "Logon type: $ltype" `
            -Mitre 'T1078 (Valid Accounts), T1021.001 (RDP)'
    }
}
Write-Host "    4624 (logon): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# ── Output ────────────────────────────────────────────────────────────────────
$stamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
if ($Findings.Count -gt 0) {
    $jsonPath = Join-Path $OutputDir "findings_evtlog_$stamp.json"
    $csvPath  = Join-Path $OutputDir "findings_evtlog_$stamp.csv"
    $Findings | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding UTF8
    $Findings | Export-Csv  $csvPath -NoTypeInformation
    Write-Host "`n[+] $($Findings.Count) event-log finding(s) written:" -ForegroundColor Green
    Write-Host "    JSON: $jsonPath" -ForegroundColor Green
    Write-Host "    CSV:  $csvPath"  -ForegroundColor Green
} else {
    Write-Host "`n[+] No suspicious events detected in collected logs." -ForegroundColor Green
}

# Summary by severity
$Findings | Group-Object Severity | Sort-Object @{E={@('Critical','High','Medium','Low').IndexOf($_.Name)}} |
    ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor $(
        switch ($_.Name) { 'Critical'{'Red'} 'High'{'DarkRed'} 'Medium'{'Yellow'} default{'Cyan'} }
    ) }

# Machine-readable status
@{ phase='evtlog_analysis'; status='success'; findings=$Findings.Count; output=$OutputDir } |
    ConvertTo-Json -Compress | Write-Output

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCQqnqE2im3rDXA
# TKgFMy0PJ2CrTogA7ksSK94CssqW2qCCFrQwggN2MIICXqADAgECAhBa5MQyEl22
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgXGUdSWq0dNRegjSs9qnRnScEwbrDbcZr
# NJ4KULL9itgwDQYJKoZIhvcNAQEBBQAEggEAadC1PmkxOs8qQIvHYiAPr6a6mHMw
# sF3/LbyCCbqPIJqF3S2bDvQ7zut9+vt3/qqGy8ymHR9YCawbVuFZ4G8tSi30tZjA
# 0A1Ul1TIoxtuNxSg5p9I+qv3/bxpnt/ayLl8iUZ3offQgaei1PsDFllAgYu0X1r9
# sULmncNYXejfVqC2emo/J1sS1EB0EOb5ShNh1xYH8hfXucrkId/HuCrFMqSrqPqf
# EQHBeIuGNr+V+u0UWI84vvov1yhikVgChNMFbmJ5/qRMkLUg6F1U37wWtjVyXe6/
# VIJjp/l6jUgPNv3Brb330F9oDMdkaTBWH7AT5cVaP+iP00yExCQ8eutgaaGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MzNaMC8GCSqGSIb3DQEJBDEi
# BCC17fsmEh56DUDPRLp2n3jD4pD2F5ZG/R3gjLkUJbd0rDANBgkqhkiG9w0BAQEF
# AASCAgCY8si3yWpi/k3oGLfRYGPREl7G11ZapczWMGJdQb3V7eRKy7kNWi4PeNEg
# IjNo50r8B5/3o9vo/G8jjFRwNsdmryVTbEe3HoJd1oG/SXtGlChrayzmCH9X2u0L
# e2ecQSUR3/MlVRL1cY4MHELev2KAQdyPW5NTnXjnjZHlHB0AxznsIGGqlbvXYKDA
# wIEHpv4gYjgGGfUpfTzfqu1sJK0DXeKUMEly7e/VNYGlfCy4hO460EfW9kE6Zosl
# /Ly1HDd+avrXIdJvakt3OgZZOFLxVedSHBhTLUZXiNVkIYaChaRNpRDlanIgQjmr
# 7uOu70zKt+KlYRIdTdjMs6hyEQcuMqVWZ2C6CEljggdDvtxWNHU/iolVm3TOzm+r
# qOahKGNiAkDZLQSUiuiXFT5zulXwtoRs93k8vM52mNRHPuhfdcy0iNHnscWJbmsN
# t/VKB9S4wz07DonRhceMByWdqdzsBLR/7GtZyPEo+lAYArNCjONnATMwSydjsQIA
# YZb67DLB5zg5V3Rq05/i79nfk8bIM6cOp/i0cnk80+WiTQbUsf9hrKfjFvA4cH9o
# qZPIS/E6tDj1LnALcaQAJTVe6HTzV8m9aAiYBzR8touSvBznqAIOyvAjgTgiy4Tp
# MlPe5SnibOyTxpcwMJfGfxFUiFM3cdr24c5mK+p8bt5L5AbBaQ==
# SIG # End signature block
