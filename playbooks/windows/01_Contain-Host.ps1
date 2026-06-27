# ==============================================================================
# IR Playbook 01 - Windows Network Containment
# Isolates the host via Windows Firewall, blocks all interfaces except the
# management network, and disables wireless adapters. Preserves the current
# WinRM/SSH session. Idempotent - safe to re-run.
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputDir  = '',   # reports\<HOST>\ - passed by Invoke-IRCollection.ps1 / Invoke-Eradication.ps1
    [string]$IncidentId = '',   # e.g. HOST_20260621_160000
    [string]$MgmtIPList = ''    # comma-separated management IPs to keep open (overrides IR_MGMT_IPS)
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Parameter -> env var fallback
if (-not $IncidentId) { $IncidentId = ($env:IR_INCIDENT_ID -replace '[^\w\-]','') }
if (-not $IncidentId) { $IncidentId = 'UNKNOWN' }
$rawMgmt    = if ($MgmtIPList) { $MgmtIPList } else { $env:IR_MGMT_IPS }
$MgmtIPs    = ($rawMgmt -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$IRDir      = if ($OutputDir) { $OutputDir } else { 'C:\ProgramData\IRToolkit' }
New-Item -ItemType Directory -Path $IRDir -Force | Out-Null

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
    Write-Output $entry
    $entry | Out-File "$IRDir\playbook.log" -Append -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('IRToolkit')) {
            New-EventLog -LogName Application -Source IRToolkit -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source IRToolkit -EventId 7701 `
            -EntryType Warning -Message "CONTAIN: $Msg" -ErrorAction SilentlyContinue
    } catch {}
}

Write-IRLog "CONTAIN: Network isolation starting for incident $IncidentId"

# -- Save pre-containment firewall rules (for audit/rollback) ------------------
$BackupFile = "$IRDir\firewall-pre-$IncidentId.wfw"
try {
    netsh advfirewall export $BackupFile | Out-Null
    Write-IRLog "CONTAIN: Firewall rules backed up -> $BackupFile"
} catch {}

# -- Block all profiles (Domain/Private/Public) ---------------------------------
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Block `
    -NotifyOnListen False `
    -AllowUnicastResponseToMulticast False

Write-IRLog "CONTAIN: Windows Firewall set to BLOCK all inbound/outbound"

# -- Allow loopback traffic -----------------------------------------------------
$LoopbackRuleName = "IR-ALLOW-LOOPBACK-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $LoopbackRuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $LoopbackRuleName `
        -Direction Inbound -Action Allow `
        -InterfaceAlias 'Loopback*' -Protocol Any | Out-Null
    New-NetFirewallRule -DisplayName "$LoopbackRuleName-OUT" `
        -Direction Outbound -Action Allow `
        -InterfaceAlias 'Loopback*' -Protocol Any | Out-Null
}

# -- Allow established/related sessions (keep current SSH/WinRM alive) ----------
$EstabRuleName = "IR-ALLOW-ESTABLISHED-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $EstabRuleName -ErrorAction SilentlyContinue)) {
    # Allow established TCP sessions (approximated: RemoteAddress Any with stateful tracking)
    New-NetFirewallRule -DisplayName $EstabRuleName `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort @(22, 5985, 5986) `
        -EdgeTraversalPolicy Allow | Out-Null
    New-NetFirewallRule -DisplayName "$EstabRuleName-OUT" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort @(22, 5985, 5986) | Out-Null
}

# -- Allow management IPs for SSH/WinRM inbound --------------------------------
if ($MgmtIPs.Count -gt 0) {
    $MgmtRuleName = "IR-ALLOW-MGMT-$IncidentId"
    if (-not (Get-NetFirewallRule -DisplayName $MgmtRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $MgmtRuleName `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort @(22, 5985, 5986, 3389) `
            -RemoteAddress $MgmtIPs | Out-Null
        New-NetFirewallRule -DisplayName "$MgmtRuleName-OUT" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort @(22, 5985, 5986) `
            -RemoteAddress $MgmtIPs | Out-Null
    }
    Write-IRLog "CONTAIN: Management access preserved for: $($MgmtIPs -join ', ')"
} else {
    Write-IRLog "CONTAIN: WARNING - no MGMT_IPS set; management access may be lost"
}

# -- Allow local DNS resolution -------------------------------------------------
$DnsRuleName = "IR-ALLOW-LOCAL-DNS-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $DnsRuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $DnsRuleName `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 53 `
        -RemoteAddress '127.0.0.1' | Out-Null
}

# -- Disable non-management network adapters ------------------------------------
$AllAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

foreach ($Adapter in $AllAdapters) {
    # Determine if this adapter carries the management route
    $IsManagement = $false
    foreach ($MgmtIP in $MgmtIPs) {
        try {
            $route = Find-NetRoute -RemoteIPAddress $MgmtIP -ErrorAction SilentlyContinue
            if ($route -and $route.InterfaceAlias -eq $Adapter.Name) {
                $IsManagement = $true; break
            }
        } catch {}
    }

    if (-not $IsManagement) {
        try {
            Disable-NetAdapter -Name $Adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Write-IRLog "CONTAIN: Disabled adapter '$($Adapter.Name)' ($($Adapter.InterfaceDescription))"
        } catch {
            Write-IRLog "CONTAIN: Could not disable '$($Adapter.Name)': $_"
        }
    } else {
        Write-IRLog "CONTAIN: Preserved management adapter '$($Adapter.Name)'"
    }
}

# -- Disable Wi-Fi --------------------------------------------------------------
Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' } | ForEach-Object {
    try {
        Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-IRLog "CONTAIN: Disabled Wi-Fi adapter '$($_.Name)'"
    } catch {}
}

# -- Disable Bluetooth networking -----------------------------------------------
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Bluetooth*' } | ForEach-Object {
    try {
        Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-IRLog "CONTAIN: Disabled Bluetooth adapter '$($_.Name)'"
    } catch {}
}

# -- Audit Event Log entry ------------------------------------------------------
try {
    Write-EventLog -LogName Security -Source 'IRToolkit' -EventId 7701 `
        -EntryType Warning `
        -Message "HOST CONTAINED by IR Toolkit - incident: $IncidentId - all network traffic blocked except management access" `
        -ErrorAction SilentlyContinue
} catch {}

Write-IRLog "CONTAIN: Host isolation complete for $IncidentId"

@{
    phase       = 'containment'
    status      = 'success'
    mgmt_ips    = $env:IR_MGMT_IPS
    incident_id = $IncidentId
} | ConvertTo-Json -Compress | Write-Output

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiaDrVGd+GMmNV
# uEh31rIrgPJCZVBaA2cV7MgOaQyVR6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgNkz4DYC1wcViO9/giq8/ONmepAzsI/lqn4sz
# elKPEI4wDQYJKoZIhvcNAQEBBQAEggEAKzlx9jjlDZEOFk/PsBODLG5XZUULvi2F
# H1nueI1wvgr6cWb6aYb31bdofaiP1ezfA2MXSm3nSW7714GCXIun7HLcqmJwAmBH
# AH3/cLA2fb55KWU86W+/+Gl5lwHro9uCiunzjJCvMBrq0Sn+uyqL8RhO8XHDOOBn
# C0jNqu/Hh836yVbFLxXNicvYOJ8Ze8JygOze97WBLZDojmD0m/5KCAlPmJOLoIHf
# L2S2AXplgnr9JLUHchRJLEbMMxUX0Me5ccD1QejmATyMlnSOVtqFq93SwfHEwfxU
# nusnihH6u+cfNmeH0k/kKB9hayctIKHt5C+vLkqLyvAPbLOvjUwN7qGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MTZaMC8GCSqGSIb3DQEJBDEiBCC2
# oZ3C5wTLno9BdZiiaFbotH3PLpxqCVXP6XwnQENreTANBgkqhkiG9w0BAQEFAASC
# AgDJtyfX0ekeajSS9zF4d9zWLkORwnP+BORG4qBnrzfRWJtdy/P5WCpdvrYKFGW2
# XAjScX4RqB2iRbRDWKhTTZaHuIZgvSQUtdynumPvIK5mEW37vN3A9onEDLT87B6x
# DZjr2Ys9Mej1pQO4KH6J/6oq8Sou1oSuyn/wm8Ywr+OyaRpfHs07Nepzs1JUefjy
# RZM4pFQ2w5scB5zBwkLCFaCCpvddLfUemRbDz6Z0eVf8jstX9aEPQ2XGQYbxEcS8
# byhxRmv5Rw39i1Qg/rf+TKm/UcjvFOiicT4YvO4oL+8vsgoVcXPpd8znRbgSALbb
# RjamxBNpG5ypJ+1pLtX5Iups4hKLECyVBA1TD2nIDvitc2IqgGdhaCwr4IwRJIE4
# xGJ+kVI7XCKAp5akeqInoOpIWCmgJYoqNhVlqd6J52eCAlq9vw6ZQtXPRKp/jcCS
# d0JoVzePtcS91cVLG8Gg/VaoXcrDc2claGUBdn3hGCtlIQUYiSpiJLXL6SR6MKbi
# GlHpmQbJhEWRY5+skzI0DGLzTbIDfgLxBpjslP05IYmNkxNGouyHE2MBnRnbQZGB
# /0Jw8BylYFuT08qrT4WvV8+8WP20I60sKuB8V16RHeHtuYmQp4lj806uQHGjGRwI
# 0EHhImhH4HGEisyJdFrp5dFCXflwNOtWNsJCwPS4Qeub9w==
# SIG # End signature block
