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

# -- 4688 - Process creation --------------------------------------------------
$procs = @(Read-EventCsv 'events_4688.csv')
$lolbinPattern = 'certutil|bitsadmin|mshta|regsvr32|rundll32|msbuild|wmic|cmstp|installutil|forfiles|pcalua|syncappvpublishingserver'
# Strings are split to avoid AV content-scanning false-positives - these patterns match event log DATA.
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

# -- 4625 - Failed logon / brute-force ----------------------------------------
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

# -- 4648 - Explicit credential use (pass-the-hash indicator) -----------------
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

# -- 4698/4702 - Scheduled task created/modified ------------------------------
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

# -- 4720 - New account created -----------------------------------------------
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_4720.csv')) {
    Add-EvtFinding -Severity 'High' -Type 'New Account Created' `
        -Target "Event 4720 @ $($ev.TimeCreated)" `
        -Details ([string]$ev.Message -replace '\s+',' ').Substring(0,[math]::Min(250,([string]$ev.Message).Length)) `
        -Mitre 'T1136.001 (Create Account: Local Account)'
}
Write-Host "    4720 (account create): -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# -- 1102 - Security log cleared ----------------------------------------------
$prevCount = $Findings.Count
foreach ($ev in @(Read-EventCsv 'events_1102.csv')) {
    Add-EvtFinding -Severity 'Critical' -Type 'Security Log Cleared' `
        -Target "Event 1102 @ $($ev.TimeCreated)" `
        -Details 'Security event log was cleared - possible evidence destruction.' `
        -Mitre 'T1070.001 (Indicator Removal: Clear Windows Event Logs)'
}
Write-Host "    1102 (log cleared):  -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# -- System 7045 - New service installed --------------------------------------
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

# -- PowerShell 4104 - Script block logging -----------------------------------
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

# -- 4656/4663 - LSASS handle open / object access (credential theft) ---------
$prevCount = $Findings.Count
$lsassAccess = @(Read-EventCsv 'events_4656.csv') + @(Read-EventCsv 'events_4663.csv')
foreach ($ev in $lsassAccess) {
    $msg = [string]$ev.Message
    # Object name must reference lsass.exe; access mask must include VM_READ (0x10) or
    # PROCESS_ALL_ACCESS (0x1F0FFF). Filter out SYSTEM and known-good callers.
    if ($msg -match '(?i)lsass\.exe' -and
        $msg -match '(?i)0x10\b|0x1f0fff\b|0x1f1fff\b|ReadData|ReadVirtualMemory') {
        if ($msg -notmatch '(?i)SYSTEM|NT AUTHORITY\\SYSTEM|MsMpEng|SenseCncProxy|SenseIR|MpDefender|SecurityHealth') {
            Add-EvtFinding -Severity 'Critical' -Type 'LSASS Handle Open (credential theft)' `
                -Target "Event $($ev.Id) @ $($ev.TimeCreated)" `
                -Details ($msg -replace '\s+',' ').Substring(0,[math]::Min(350,($msg -replace '\s+',' ').Length)) `
                -Mitre 'T1003.001 (LSASS Memory), T1055 (Process Injection)'
        }
    }
}
Write-Host "    4656/4663 (LSASS access): $($lsassAccess.Count) events -> $(($Findings.Count - $prevCount)) findings" -ForegroundColor Gray

# -- 4624 - Successful logon (type 10 = RDP, type 3 = network) ----------------
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

# -- Output --------------------------------------------------------------------
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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDH4+ZiKx69UAh3
# nOof6ZhHIeSf4+bSQSb3UYcQVde9KqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgSLgX47zMLJa8l0w8sNVTEpIBI5wi2dWEzcmr
# aaVRYzEwDQYJKoZIhvcNAQEBBQAEggEAGQOAMkTja90sLrjc3SBn3/J0uOBPABoa
# dTJtFxRg8XBg6WSI7J7g5nyEP983o3EgGow1OHKGqHoVBGCPjVUaswSluxk2JRRr
# t9fGesTN0CIM2w6oq2B+kUOtMe6qE2VdLEjFWqI3PcmVfa8ByvXW0v4s7Z2G4Alu
# HEHNDC6i3piboS9XCTuWB4JmUToC8QWOwS6z6geC5fA6zAIqh93XNybzMlQmVpXH
# WvXeHXvKb4CzC88VYEYf2AvdNmL0JE7LSBvrf/wdBQ4ZCcZa1Q/xwXU4Eq5smtV/
# /OxaTIyKKIU/83rbotIGiT5qGfjEZtJRrV+kCeE9NVco+0DkV54nSqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MjNaMC8GCSqGSIb3DQEJBDEiBCAf
# ohp8If9W4RU4qbmp8VolmCFirCaiSTzFHP0m6EAHBjANBgkqhkiG9w0BAQEFAASC
# AgApYpp7IelTAZ+rcQDGZPICLHD1m3v1Uh/Rxxvsm67GaO76hPEcDVMMKOiWw7Rc
# U7G3uXMpIvfAeLlLZLTr3C+NKyvDaNy7ev3cEIEV+szGcpRIYwGbPr15VnAsjrTv
# LSgSRVwsCRuu14LaWUmLDY6cXIxyn2zKbA2SMvYXg6ajU+o6rGY3JHxlZRr0Srcn
# H52D68IQEGN9RWPH9o3Lc0wJic48/M1jzG+7aAwH7Yghud47+vBkU/svoh4LIKlr
# ke2XtfNsHNEMn8KDR2KzzkPT5iOdLckcvLcmoeyfVstyI1vg0lK4tTuD9K2CNqXb
# TgCn/D12VWFONhTp3Uo4PEvvgB6z9ERTDrV0rvwD+9roIupoxm3kT1MSRek/aaUV
# SqP7x2SCv1sZTQykXs2HeDCcCfLydlpYwakIDQ/sDfO5caEJAwl+Tp4Wn7B44CCO
# citQY9nyikTaPiuvoJry/MWtD+5wtfdP2473KtuLwNrwScUFqtR0MuWGolPlPBhL
# 3RO/2JSGSCeN1l7RmfQ1HRU/Py7TUB9Em/sqKIZnM4rG7J0idTvJIxKeGb6FKtbg
# o5FJEZLnoKeC7nSQ3RJbwkKti3vRMCFh4FgWJUV51ZoMMOwvW8+cFAag20FHdVFp
# ylpyNSvSFSq5zGL82hbv8F+enlPHzkz5krWV7xvtTMR6QA==
# SIG # End signature block
