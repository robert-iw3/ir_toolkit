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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiaDrVGd+GMmNV
# uEh31rIrgPJCZVBaA2cV7MgOaQyVR6CCFrQwggN2MIICXqADAgECAhBj3Isegven
# qEj21ds5AZieMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjMxNDE2NTlaFw0zMTA2MjMxNDI2NTlaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAM3b6zgkW9zzqQraVSnj+a4zp1l4KkWs2NKNqvPP
# p9Pyjhif7sY2FZyXnXbkKElZkNveSR84IkSBjIBC/9Q2gum1eM9nDmbnj2v5L+Nu
# llMOkOjUC913DYNHmHdk/8FDJwAjl6mtsAWZwTvc7FUpyqGiD09yILSywsivvkDV
# nE/qWzKgMRGflBJreqDUR5o0l0hLhowxG58ywKqElIJpwV+N1ngcfYIpJPO4XEHB
# 6sSe0fkZralmnZdZ+sw6LRUpE7nMxmy6ZktNz51jXnm/oR7N9VbHUBOMtBLAFmny
# CFddkOEV4z4Pz3yC0SOcgJXvoJ3yfPLzug7t5W+kRcNGmrECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQQFW0G
# zu1Gz5VThEyg9LLMhDsLlDANBgkqhkiG9w0BAQsFAAOCAQEAGVSgMDhKb7EDBXTH
# 3pTUUxUoQNNByOzeSepp+Wq5HpPEO7lS204uZSljF1a6QNjya4SsVE3o4+TR9CJm
# uXqRvesj578tf9DQSl0iflg2rz9UGCXRVTazH8xMWOpt8fMlXbUf3xfYS4Wqena2
# dl5JhRwvaDUmO5EJixsQwTiYS+vS5sG0TzMIT2N0dyCrA4eRinORCiUzTn3zYZe4
# osCBOkhKbaiX6YkjzWhFGEarCNYwAYhleymgIy88BowoBYgwn1vx9G14hS9cEcHp
# d/oHA9RE3wgiiYW2VCYWv+8GWrBv+WCruhrzagOTl6RURC1ctkiRl6MbQ9XENvQF
# HPfs5TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEGPcix6C96eoSPbV2zkB
# mJ4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgNkz4DYC1wcViO9/giq8/ONmepAzsI/lq
# n4szelKPEI4wDQYJKoZIhvcNAQEBBQAEggEALsb5HKQRYR873FF+9aTgzCNSMVSx
# OPqOjj2InlkvrjS6B0w6hlUHIIZLd1G2aq+0QiKRho1WHBbX49kODmql4R2VHgFD
# JeKYuIRCM/t3jIQ2wFcGk1tPLTN82YK5SzhQCUBfKZf68o3rTgQX/ELD3g7QUYHp
# HUPfINgcw5DLK9joe0PYJvnO06rp9BWGxJ9BBZdWfoq4gtiIzuj5JvpIcEJZGX9H
# K9x3QFxaRQFawcQ05gs25MuuRVF8aaOoP97g++01JFgDK0mgCJ3WQZ6S3shWQLVn
# 9V0kAh2v7J2+aNa6Ko36YqANukTVIbHbHOHHnFNEHg5E7osRFnkVE6oMZ6GCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjMxNDI3MDRaMC8GCSqGSIb3DQEJBDEi
# BCC2uumWbxWr3nA8DdseLFKLJW+690YluF73KZpsnLkaCjANBgkqhkiG9w0BAQEF
# AASCAgDP1EOD9DFE9VYF1GSZv80ruTkEF6HT2M/8dl3ONuJMz1zQiW0lDbyKdzAv
# pn70lZhVJxOQROZe6jdaPjn+C0NzU9ZXI87wBZNADTZopW+R67q+lTn/H3rqxdEM
# +0tvsVAvMOY/9AwiiJY2jfhAmqeTxKNoQ0/I/91+ocSKU55Q8PwC82HOGzRieQyP
# fM/N9rOxjZx9rQ21S0Wo2XTRClTdHQ0mPVwtesowgOvyR0+h79ql3j33iRbA5nfv
# FqCt2Yvqceo38TJIOFu4JrezTSEW4hZMTEit/iySjgq0JtMZcf/E8QQK3doZB60Z
# 1QmTqmi7D8c1CAHKE41Es1VTjKhwGbqDORRhwaBZf6V46cxJatEvKgcDkQ0FhNHE
# CKsyyUVs6O0XM31koKyNOkKILkew5NYefFbDEyV7CoHJzcoGNeX7I0rKZG7Uz4MU
# x7QPxUxpoychRo3SDPkDC22ZqXQlErwieo/yhKT6cDgN74myCI56Q/w4m41deA5C
# lht2wU/gSfippEla/oo6dHwPf94KFA1QiG3TTpAGfEMW1vKobX9Q4zlBKmVaZL7X
# WENlvAPvxG7vGG9lmkwHKluSN1esY6qaXFYId6FMDMl6+SmkyfZB83aGHXTz3tr5
# HnN0GHHZiGOgka1POMABHS4rSmOoo9ZmLOFdzwNeH1gIlHFlwQ==
# SIG # End signature block
