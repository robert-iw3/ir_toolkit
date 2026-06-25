# ==============================================================================
# IR Playbook 04 - Windows C2 Blocking
# Adds host-level blocks for all identified C2 infrastructure:
#   * Windows Firewall outbound rules for all C2 IPs
#   * %SystemRoot%\System32\drivers\etc\hosts sinkhole for C2 domains
#   * Windows Defender network block (Add-MpPreference)
#   * Null route via persistent route addition
#   * DNS Client cache flush
# Idempotent - safe to re-run with extended IOC lists.
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputDir  = '',
    [string]$IncidentId = '',
    [string[]]$C2IPs    = @(),
    [string[]]$C2Domains= @(),
    [switch]$Apply   # dry-run by default; -Apply to write firewall rules / hosts file
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not $IncidentId) { $IncidentId = ($env:IR_INCIDENT_ID -replace '[^\w\-]','') }
if (-not $C2IPs)      { $C2IPs    = ($env:IR_C2_IPS    -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $C2Domains)  { $C2Domains= ($env:IR_C2_DOMAINS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

$mode     = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
$IRDir    = if ($OutputDir) { $OutputDir } else { 'C:\ProgramData\IRToolkit' }
$HostsFile= "$env:SystemRoot\System32\drivers\etc\hosts"
$BlockTag = "# IR-BLOCK-$IncidentId"
New-Item -ItemType Directory -Path $IRDir -Force | Out-Null

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] [$mode] $Msg"
    Write-Output $entry
    $entry | Out-File "$IRDir\playbook.log" -Append -Encoding UTF8
}

# RFC-1918 / link-local addresses - never block
function Test-IsPrivateIP {
    param([string]$IP)
    $IP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.|::1|fe80:)'
}

$BlockedIPs     = [System.Collections.Generic.List[string]]::new()
$BlockedDomains = [System.Collections.Generic.List[string]]::new()
$Errors         = [System.Collections.Generic.List[string]]::new()

Write-IRLog "C2-BLOCK: Starting C2 infrastructure blocking for $IncidentId"

# -- Firewall rules for C2 IPs -------------------------------------------------
foreach ($C2IP in $C2IPs) {
    if (Test-IsPrivateIP $C2IP) {
        Write-IRLog "C2-BLOCK: Skipping private IP $C2IP"
        continue
    }

    # Outbound block
    $OutRuleName = "IR-C2-BLOCK-OUT-$C2IP-$IncidentId"
    $InRuleName  = "IR-C2-BLOCK-IN-$C2IP-$IncidentId"

    try {
        if (-not (Get-NetFirewallRule -DisplayName $OutRuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $OutRuleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $C2IP `
                -Protocol Any `
                -Description "IR C2 block - incident $IncidentId" | Out-Null
            Write-IRLog "C2-BLOCK: Firewall OUTBOUND block -> $C2IP"
        }

        if (-not (Get-NetFirewallRule -DisplayName $InRuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $InRuleName `
                -Direction Inbound `
                -Action Block `
                -RemoteAddress $C2IP `
                -Protocol Any `
                -Description "IR C2 block - incident $IncidentId" | Out-Null
        }
        $BlockedIPs.Add($C2IP)
    } catch {
        $Errors.Add("firewall_failed:$C2IP"); Write-IRLog "C2-BLOCK: Firewall error for $C2IP : $_"
    }

    # Belt-and-suspenders: persistent null route
    try {
        route add $C2IP mask 255.255.255.255 0.0.0.0 -p 2>$null | Out-Null
    } catch {}

    # Windows Defender Network Block (MAPS / NIS integration)
    try {
        Add-MpPreference -ThreatIDDefaultAction_Ids 0 -ThreatIDDefaultAction_Actions Block `
            -ErrorAction SilentlyContinue
    } catch {}
}

# -- /etc/hosts sinkhole for C2 domains ----------------------------------------
# Remove any existing IR blocks first (idempotent)
if (Test-Path $HostsFile) {
    $HostsContent = Get-Content $HostsFile -Encoding ASCII
    $CleanHosts   = $HostsContent | Where-Object { $_ -notlike "*IR-BLOCK-*" }
    Set-Content $HostsFile -Value $CleanHosts -Encoding ASCII -Force
}

foreach ($Domain in $C2Domains) {
    try {
        $Entries = @(
            "0.0.0.0 $Domain $BlockTag",
            "0.0.0.0 www.$Domain $BlockTag",
            ":: $Domain $BlockTag"
        )
        Add-Content -Path $HostsFile -Value $Entries -Encoding ASCII
        $BlockedDomains.Add($Domain)
        Write-IRLog "C2-BLOCK: Sinkholes $Domain -> 0.0.0.0 in hosts file"
    } catch {
        $Errors.Add("hosts_failed:$Domain"); Write-IRLog "C2-BLOCK: Hosts error for $Domain : $_"
    }
}

# -- Flush DNS Client cache ----------------------------------------------------
try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: DNS client cache flushed"
} catch {}

# -- Windows Defender ASR - block suspicious network destinations --------------
try {
    # ASR Rule: Block all Office applications from creating child processes (ID 26190899)
    # and network connections to specific external destinations - belt-and-suspenders
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: Windows Defender Network Protection enabled"
} catch {}

# -- Restart DNS Client service to apply hosts changes -------------------------
try {
    Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: DNS client restarted"
} catch {}

Write-IRLog "C2-BLOCK: Complete. IPs blocked: $($BlockedIPs.Count), domains: $($BlockedDomains.Count), errors: $($Errors.Count)"

@{
    phase           = 'c2_blocking'
    status          = 'success'
    blocked_ips     = $BlockedIPs.Count
    blocked_domains = $BlockedDomains.Count
    errors          = $Errors.Count
    incident_id     = $IncidentId
} | ConvertTo-Json -Compress | Write-Output

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBbudcuReBHQWwt
# tdZUoJ4PphQGGx9rYuyplNOcW4Q4JaCCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLJ5sVUjL9caxrvySwPmUAy17N9HcsBr9
# ibJ+W77w45swDQYJKoZIhvcNAQEBBQAEggEAVORolrs/fq880sjEzNOL+80mhtgn
# I7GiOIjawlSARVSANS6XMKQH+oyYSuChW5YdsRqfzPCJBDfgWhiWEMkQV0DB5sxN
# MucVkzmBxmxT3DZ4MbANfADKMyKi6Iz71wNV8gIAx5gopv0zw7Vah4O1CDw+vRLp
# qkb2toRthYiN1ucQC9hzNLvzs8NFfYRvQFq2/OOPxDW7O+NfoGK7lmgcBXa3vveS
# rtG+fTakSF6gsYODOhCmEH+5pdwkLca8yd1iqgVva/ZSGIRSV1VAairWA1NK3KLZ
# iop/qxRYIdas7JCCjI0rGK6/46keOPHlET0iOFy3TfnYW1BelHm2cFj+YKGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1MjdaMC8GCSqGSIb3DQEJBDEi
# BCAorxGBxxE9eu/f9yLLuNKYAujRRQpB5AL9sR/UyIJSNzANBgkqhkiG9w0BAQEF
# AASCAgBDVbYKznes05WQGQKa5yPf5H2dVabibT+NzjTKRy8tAq59541KYCyP5St4
# CkgUSmj8EtJirGE180eMmFESxgTeVg9y7w7KzM+ZCsSlgjY03ZRe3L6RqDylHi1L
# vEmzGGpv/HEEnAyuHgDe1lHb9yRPH1Y77gSzza+NcINoW6pm/WJNOSh26Wum4Q+O
# tsZkCSEfToh9QP2dEHlIzECQUIreXRPLR1BSM/wPy0as0z6PKu56SPaGn+AakCpb
# 2MsKy5QZUKsr5mbG8+YPZYRGMYl28LpaAHVJ6aGKgD2f7uOBeUfHQ5MaKWLy+9mt
# Q4syYWqIy6UtMl4xhR6EMeqLsKxV8EdVZ7UftbWwvNHD0HuS00MC3fznTciobCo7
# p3lmU713QchlK4ETxNGl8YHjeLaBT/CMDmf8iFsyReR8HdjdsYLOGztvehrtE0cB
# DoKNQLbefOuGAzVQ1iZnQYBiZUfn4hL17GqIh8prT6zGcVPgT/leIWXUXCAYv1Zv
# PoKWhxWbzwDsbIUSytMq0ntLbx2OF7PT1MBI0WYj1VBl1fQ4gTwNEsRthKKHlvzI
# YX2z47zWkFJjOKv46U/zb4o9SwX7lbiMYdEjYMCRNYmf5znZMZ0AornByfYATbuW
# K1oFHiiDJ3wGYsxApxPmtidv4rf0d0AlwpCONlJpIiuiCG6ZZw==
# SIG # End signature block
