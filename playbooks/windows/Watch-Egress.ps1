# ==============================================================================
# IR Playbook - Windows Egress Observation Sensor + Deferred Outbound Blackhole
#
# WHY THIS EXISTS
#   Inbound is locked down during containment (Enforce-StrictFirewall.ps1), but
#   outbound is deliberately left OPEN during the analysis window so we can SEE
#   where the implant beacons / exfils to. C2 beacons jitter and can dwell for
#   HOURS, so a single point-in-time netstat at collection time routinely misses
#   them. This sensor registers a scheduled task that snapshots outbound
#   connections on a cadence over an extended window (default 24h), appends every
#   external egress flow to an append-only evidence log, then AUTOMATICALLY
#   blackholes outbound (Enforce-StrictFirewall.ps1 -BlockOutbound) when the
#   window closes.
#
#   This changes the workflow: after collection the responder LEAVES the sensor
#   running and RETURNS later to (1) collect the egress evidence log and (2)
#   confirm the blackhole fired. See WORKFLOW-WINDOWS.md "Egress observation".
#
#   OPTIONAL. Observation tolerates continued exfil during the window. For a
#   DATA-SENSITIVE host, do NOT observe - fully isolate the network stack first
#   (01_Contain-Host.ps1 = inbound+outbound) and skip this (-NoEgressMonitor):
#   eliminating further data loss outranks mapping the C2 when the data matters.
#
# USAGE
#   Watch-Egress.ps1 -Start [-WindowHours 24] [-IntervalMin 1] [-IncidentId ID]
#                    [-MgmtIP a,b]
#   Watch-Egress.ps1 -Status    [-IncidentId ID]
#   Watch-Egress.ps1 -Collect   [-IncidentId ID]   # report the evidence log
#   Watch-Egress.ps1 -Blackhole [-IncidentId ID]   # blackhole outbound NOW
#   Watch-Egress.ps1 -Stop      [-IncidentId ID]   # tear sensor down (no blackhole)
#   Watch-Egress.ps1 -Snapshot  -IncidentId ID     # internal (called by the task)
#
# Reversible: the outbound blackhole is applied via Enforce-StrictFirewall.ps1,
# whose .wfw binary backup restores the pre-incident firewall (-Rollback).
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Start')]    [switch]$Start,
    [Parameter(ParameterSetName = 'Snapshot')] [switch]$Snapshot,
    [Parameter(ParameterSetName = 'Blackhole')][switch]$Blackhole,
    [Parameter(ParameterSetName = 'Stop')]     [switch]$Stop,
    [Parameter(ParameterSetName = 'Collect')]  [switch]$Collect,
    [Parameter(ParameterSetName = 'Status')]   [switch]$Status,
    [int]$WindowHours = 24,
    [int]$IntervalMin = 1,
    [string]$IncidentId = $(if ($env:IR_INCIDENT_ID) { $env:IR_INCIDENT_ID } else { 'UNKNOWN' }),
    [string[]]$MgmtIP = @($(if ($env:IR_MGMT_IPS) { $env:IR_MGMT_IPS -split ',' } ))
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId = ($IncidentId -replace '[^\w\-]', '')
$StateDir   = Join-Path $env:ProgramData "IRToolkit\egress-$IncidentId"
$Log        = Join-Path $StateDir "egress-$IncidentId.log"
$Meta       = Join-Path $StateDir "meta.json"
$DoneMarker = Join-Path $StateDir "blackhole.done"
$PollTask   = "IR-Egress-Poll-$IncidentId"
$BHTask     = "IR-Egress-Blackhole-$IncidentId"
$SelfPath   = $MyInvocation.MyCommand.Path
$MgmtIP     = @($MgmtIP | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Out-Json { param([hashtable]$H) ($H | ConvertTo-Json -Compress) | Write-Output }

# External = not loopback / RFC1918 / link-local / unspecified / management.
function Test-External {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    if ($ip -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { return $false }
    if ($ip -match '^(10\.|192\.168\.|169\.254\.|fe80:|ff|224\.|127\.)') { return $false }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $false }
    if ($MgmtIP -contains $ip) { return $false }
    return $true
}

function Invoke-Snapshot {
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    try {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-External $_.RemoteAddress) {
                $proc = ''
                try { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
                "$ts | tcp | $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) | $proc(pid=$($_.OwningProcess))" |
                    Out-File -FilePath $Log -Append -Encoding UTF8
            }
        }
    } catch {}
}

switch ($PSCmdlet.ParameterSetName) {
'Start' {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    @{ start = (Get-Date).ToUniversalTime().ToString('o'); window_hours = $WindowHours
       interval_min = $IntervalMin; mgmt_ip = $MgmtIP } | ConvertTo-Json | Set-Content $Meta -Encoding UTF8
    "# IR egress observation - incident $IncidentId - started $((Get-Date).ToUniversalTime().ToString('o'))" |
        Out-File $Log -Encoding UTF8

    # Polling task: snapshot every IntervalMin minutes for the whole window
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`" -Snapshot -IncidentId $IncidentId"
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin) `
        -RepetitionDuration  (New-TimeSpan -Hours   $WindowHours)
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $PollTask -Action $act -Trigger $trg -Principal $pr -Force | Out-Null

    # One-shot blackhole task at window close: blackhole egress + remove the poller
    $bhArg = "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`" -Blackhole -IncidentId $IncidentId"
    if ($MgmtIP.Count) { $bhArg += " -MgmtIP $($MgmtIP -join ',')" }
    $bhAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $bhArg
    $bhTrg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours($WindowHours)
    Register-ScheduledTask -TaskName $BHTask -Action $bhAct -Trigger $bhTrg -Principal $pr -Force | Out-Null

    Invoke-Snapshot
    Out-Json @{ phase = 'egress_observation'; status = 'started'; incident_id = $IncidentId
                window_hours = $WindowHours; log = $Log; poll_task = $PollTask; blackhole_task = $BHTask }
}
'Snapshot' { Invoke-Snapshot }
'Blackhole' {
    if (Test-Path $DoneMarker) { Write-Output "egress already blackholed for $IncidentId"; break }
    $enforce = Join-Path $PSScriptRoot 'Enforce-StrictFirewall.ps1'
    $bhParams = @{ BlockOutbound = $true }
    if ($MgmtIP.Count) { $bhParams['AllowOutboundPort'] = @(22, 3389, 5985, 5986); $bhParams['AllowOutboundRemoteAddress'] = $MgmtIP }
    if (Test-Path $enforce) { & $enforce @bhParams }
    else { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block }
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    New-Item -ItemType File -Path $DoneMarker -Force | Out-Null
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
    try { Write-EventLog -LogName Application -Source 'IRToolkit' -EventId 7702 -EntryType Warning `
            -Message "EGRESS BLACKHOLED for $IncidentId after observation window" -ErrorAction SilentlyContinue } catch {}
    Out-Json @{ phase = 'egress_blackhole'; status = 'success'; incident_id = $IncidentId; evidence_log = $Log }
}
'Stop' {
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $BHTask   -Confirm:$false -ErrorAction SilentlyContinue
    Out-Json @{ phase = 'egress_observation'; status = 'stopped'; incident_id = $IncidentId }
}
'Collect' {
    if (Test-Path $Log) {
        $flows = (Get-Content $Log | Where-Object { $_ -notmatch '^#' }).Count
        $uniq  = (Get-Content $Log | Select-String -Pattern '-> ([0-9a-fA-F:.]+):' -AllMatches |
                  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique).Count
        Out-Json @{ phase = 'egress_observation'; status = 'collect'; incident_id = $IncidentId
                    evidence_log = $Log; flows_logged = $flows; unique_destinations = $uniq
                    blackhole = $(if (Test-Path $DoneMarker) { 'done' } else { 'pending' }) }
    } else { Write-Error "no egress log for $IncidentId at $Log" }
}
default {
    if (Test-Path $Meta) {
        $m = Get-Content $Meta -Raw | ConvertFrom-Json
        Out-Json @{ phase = 'egress_observation'; status = 'running'; incident_id = $IncidentId
                    started = $m.start; window_hours = $m.window_hours; log = $Log
                    blackhole = $(if (Test-Path $DoneMarker) { 'done' } else { 'pending' }) }
    } else { Write-Error "no egress observation active for $IncidentId" }
}
}

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcqJPlbr5UDhlQ
# FONJpjDblKaNckscN7FYMc3MdM85DKCCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQggk4aETBOTjcY0/aQIVCtFvx2UnOnQAPq
# jDC13qs3008wDQYJKoZIhvcNAQEBBQAEggEAP8EeLUYb48+jAeLjkMO2L/6cF5qR
# 0i6EnNZp2XfdhhuKrBMIWxZW90RBUB+R2MCVVJhoCOKSGFRlvR2tOgJ2GPbCRU8J
# FAwLw4Y1bBY9CyCIyjdr+PB0LWXVpKegD/xD8a3hKl5PUPqhEI4nlX7+Ib7uFRZk
# +MLid4JmPbiQhzuqfQHv0XQ8FcZm3ER9KCZUoFPRLOYACXtX/h6RIST02QjRKE+H
# RKRcXXbNZ65cVaM4WzE0/zk2AfqrSESBsQGlrfMstyiWIJgEJw2NPIRwDaAe+zY4
# Y9raDgEMJtuvYtLexWhYEIFwLLQbYv0PqteGO2xFjOB8T5xa4X0eqzkr0qGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1MzdaMC8GCSqGSIb3DQEJBDEi
# BCCuRuPPURrO5Mu3EW0MVP9UlZ76skzaq3WDGaOlaCthUzANBgkqhkiG9w0BAQEF
# AASCAgAVMlf7EYGocGSPXca62bFGG9UOHAc8ipx5YlTP3iPnM2OF2UhcAxzeoZr+
# e2Kn4z1pdQRthxKsBUMi4tsvLKUj3stBSyZ4hB40kPHhlz2dVexNTaYaBjbW6A8G
# u9OI/3Dl/n6EN3TS4iq8ESG6tQ26AUv9nWTa8HQfVFqG+6muD6Nb4yqTw+xHCp1I
# 0A6+nVLvpCVqcqY83VF5FR0eCA7w114K4Pxs95llaFqLfjzig3ql36TbeUBXaaUP
# DWL2BAD3x599S8pdJtZbXt+wpaPRav3yBmjS9Oik0rfQsw1i50D0nmEQLs96IAl4
# h31qYcK+SKx7yOlHj8DJKr76y6ISlkbqwE8suZnDMzUQG8QL8e5KTTkaQXKQK+My
# VaeAX4SGsgJuty5531KO/qzQPWTf+ubtxW9kJSoTVmgI7LM+BaZe2todGMuEB7zh
# o7zpJSHoBtfoHY482OWc4op4HIZkD2QRnuDQazfewmhHNie00pf4/8xk+RPRG1qd
# 0y17ww8ngvn8J9s6jcnCxCoS2xI2WitrQB5svSbQODDuo+eOKhxEcn5dcVXcsk7J
# J8VOhYOGbyIfq2nW8LMlT8rKwMC/qBmif6lJzNduRgkBn729cDfbMUMNVffNN6oV
# JUwgiGJU87v894Mcb4Uw+3uaujZH6/Ckn6liFp6TAKxC34QSeQ==
# SIG # End signature block
