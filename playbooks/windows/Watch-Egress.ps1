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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcqJPlbr5UDhlQ
# FONJpjDblKaNckscN7FYMc3MdM85DKCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQggk4aETBOTjcY0/aQIVCtFvx2UnOnQAPqjDC1
# 3qs3008wDQYJKoZIhvcNAQEBBQAEggEAHiiQBMCBfefKUUzocHXIGQdI37qxhpMR
# jitfXj9ozKV94Pjnbl/gBdl4hNAx+MbmMEIXEoYsO95rSTOXC9ORUhK/Ykhn1SKK
# QvnKbSMSyOdX1xQ16uPPAqBEN34Ef49rSuINWtzE8bITV3im6aWu1L/x1mbZiDE1
# 23Deiw4UhETpToedAykIWdSDME8Bx2esRypzsNL7BIsSlbNzJ2aXYzTPON5J+LeJ
# MQJCTc4C2M8SmP6NKDUtr27xzQSWpqZTv7nR1zaQneMEqf99lrXCpV62YFQCfLOM
# rTTV4EpqOryndxtZxO1PS9GAjYYIMhb5LExfCHQhZ9mMLN8drgi4ZaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MjBaMC8GCSqGSIb3DQEJBDEiBCDp
# 9y7RkAEcd32i86V8284P3GkZWfh2q8jMu9reVGScmjANBgkqhkiG9w0BAQEFAASC
# AgB6Cu75fxSx6/3uVnxlRyWWJPuxOFIH6GxHJdcgnSScT0wONy8MUhachWeKELFs
# 0EUIyA/u+qsxKhxwcBM81U2ulIYhZ8v0q9KFpW7OIbUhK7E7HREps3gmhwjDmiLi
# Z/+B4t8UqW3roNdmMxE4jQwcx2MZ9/T2MHPMo87/xmqzpqaoeVJt27GfN19/4KAD
# 4TtqMU3wf4NOOUhN9h70nZMIDW8W84Pz28namAcvnAOcHfAALImMPOZhLXDnZ6Y4
# /uX+3UOADKZ1VdtFO1L6qHkhKpNSETOuPvWTmiqwQq0nZyY4v5N7FqwKak6h1wbg
# yGmq1mEszwDBwtz8L8b9493600Yzc80LfX4HwW2uyxkkUpXsAfuL4IoWL54zDd3t
# 5Ro0j4xTt53v0luivxJfvMIqh8yhiSpbM+npAEiTrCZw7wQvD9oXDdzHNLErT83v
# 2ttbk1bVpwyWeemswiXa0ZBWQyx8XWYxSwfv0AZMx6eUHqDDculZ/MT/pvZa2f5s
# 2wZVhFVb//JLyNtncX1cAhBRtZ1cLQvOTVcYLOoJrpU+p1/quAsipfysZrjIEHOW
# i/hq6rCXKPpcJ0s0oI0g/R+L3rYmFFhguUDwrQ/Zi7pwFP+grip8HQjKaGPpxSdu
# IrkdxAe5tzQn1i4WZakgxj+lLh86tcO5jvFWY6FuPcz5jw==
# SIG # End signature block
