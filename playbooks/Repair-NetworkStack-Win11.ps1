#requires -Version 5.1
<#
.SYNOPSIS
    Repairs a broken Windows 10/11 TCP/IP network stack (no connectivity / "nothing works").

.DESCRIPTION
    Runs the standard, Microsoft-sanctioned recovery sequence for a wedged network
    stack, in least-destructive-first order, with a full transcript and a pre-change
    state snapshot so the repair is auditable and the steps are reversible by reboot.

    Default (safe) actions - reversible by a reboot, no rule/config loss:
        1. Snapshot current state (ipconfig /all, adapters, routes, services).
        2. Restart core networking services (NSI, Dhcp, Dnscache, NlaSvc, netprofm...).
        3. Re-enable any administratively-disabled network adapters.
        4. Reset the Winsock catalog          (netsh winsock reset).
        5. Reset the TCP/IP stack             (netsh int ip reset).
        6. Release / renew DHCP + flush DNS.
        7. Clear the WinHTTP proxy            (netsh winhttp reset proxy).

    Opt-in actions (more invasive - off unless you pass the switch):
        -EnforceOutboundOnly  : lock the firewall to OUTBOUND-ONLY (block all inbound,
                                allow outbound, firewall stays ENABLED). Does NOT reset
                                or open the firewall - existing rules are left intact.
        -IncludeIPv6Reset     : also reset the IPv6 stack (netsh int ipv6 reset).

    A reboot is REQUIRED for winsock/ip reset to take full effect. The script prompts.

.NOTES
    Must be run from an ELEVATED PowerShell prompt (Run as Administrator).
    Context: drafted to recover a Win11 host after an IR scan run. NOTE: the
    EDR_Toolkit.ps1 *scan* is read-only and does not modify the network stack -
    this script repairs damage from whatever the actual cause was, generically.

.EXAMPLE
    .\Repair-NetworkStack-Win11.ps1
        Runs the safe recovery sequence, prompts for reboot.

.EXAMPLE
    .\Repair-NetworkStack-Win11.ps1 -EnforceOutboundOnly -IncludeIPv6Reset -Reboot
        Repair + lock firewall to outbound-only + reset IPv6, auto-reboots when done.

.EXAMPLE
    .\Repair-NetworkStack-Win11.ps1 -WhatIf
        Shows every action without changing anything.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$EnforceOutboundOnly,
    [switch]$IncludeIPv6Reset,
    [switch]$Reboot,                       # auto-reboot when finished (no prompt)
    [string]$LogDir = "$env:SystemDrive\IR_NetRepair"
)

$ErrorActionPreference = 'Continue'

# --- Elevation check ----------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[X] This script must be run from an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    Write-Host "    Right-click PowerShell -> Run as administrator, then re-run." -ForegroundColor Yellow
    exit 1
}

# --- Logging ------------------------------------------------------------------
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$transcript = Join-Path $LogDir "NetRepair_$stamp.log"
$snapshot   = Join-Path $LogDir "PreRepair_State_$stamp.txt"
try { Start-Transcript -Path $transcript -Force | Out-Null } catch {}

function Write-Step  ([string]$m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok    ([string]$m) { Write-Host "    [+] $m"  -ForegroundColor Green }
function Write-Warn2 ([string]$m) { Write-Host "    [!] $m"  -ForegroundColor Yellow }

# Run a native command under -WhatIf/-Confirm gating via ShouldProcess.
function Invoke-Native {
    param([string]$Target, [string]$Action, [scriptblock]$Script)
    if ($PSCmdlet.ShouldProcess($Target, $Action)) {
        & $Script
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
            Write-Warn2 "$Action returned exit code $LASTEXITCODE (may be benign)."
        } else {
            Write-Ok "$Action complete."
        }
    }
}

Write-Host "===================================================" -ForegroundColor Green
Write-Host "   Windows 10/11 Network Stack Repair" -ForegroundColor White
Write-Host "   Host: $env:COMPUTERNAME   $(Get-Date)" -ForegroundColor Gray
Write-Host "   Log : $transcript" -ForegroundColor Gray
Write-Host "===================================================" -ForegroundColor Green

# --- 0. Pre-change state snapshot --------------------------------------------
Write-Step "Capturing pre-repair state snapshot -> $snapshot"
try {
    "==== ipconfig /all ===="            | Out-File $snapshot
    ipconfig /all                        | Out-File $snapshot -Append
    "`n==== Get-NetAdapter ===="         | Out-File $snapshot -Append
    Get-NetAdapter | Format-Table -Auto  | Out-File $snapshot -Append
    "`n==== Get-NetIPConfiguration ====" | Out-File $snapshot -Append
    Get-NetIPConfiguration               | Out-File $snapshot -Append
    "`n==== route print ===="            | Out-File $snapshot -Append
    route print                          | Out-File $snapshot -Append
    "`n==== netsh winhttp show proxy ====" | Out-File $snapshot -Append
    netsh winhttp show proxy             | Out-File $snapshot -Append
    Write-Ok "Snapshot saved (keep this - it records the broken-state config for comparison)."
} catch { Write-Warn2 "Snapshot partially failed: $($_.Exception.Message)" }

# --- 1. Restart core networking services -------------------------------------
# Order matters: dependencies (nsi/Tcpip) before consumers (Dhcp/Dnscache/NlaSvc).
$services = 'nsi','Dhcp','Dnscache','NlaSvc','netprofm','WlanSvc','iphlpsvc','Winmgmt'
Write-Step "Restarting core networking services"
foreach ($svc in $services) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if (-not $s) { continue }
    if ($s.StartType -eq 'Disabled') {
        Write-Warn2 "$svc is DISABLED. Setting to Manual so it can start."
        if ($PSCmdlet.ShouldProcess($svc, 'Set-Service StartupType Manual')) {
            Set-Service -Name $svc -StartupType Manual -ErrorAction SilentlyContinue
        }
    }
    if ($PSCmdlet.ShouldProcess($svc, 'Restart-Service')) {
        Restart-Service -Name $svc -Force -ErrorAction SilentlyContinue
        $now = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status
        if ($now -eq 'Running') { Write-Ok "$svc running." } else { Write-Warn2 "$svc status: $now" }
    }
}

# --- 2. Re-enable administratively disabled adapters --------------------------
Write-Step "Checking for disabled network adapters"
$disabled = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.AdminStatus -eq 'Down' -or $_.Status -eq 'Disabled' }
if ($disabled) {
    foreach ($a in $disabled) {
        Write-Warn2 "Adapter '$($a.Name)' is disabled - re-enabling."
        if ($PSCmdlet.ShouldProcess($a.Name, 'Enable-NetAdapter')) {
            Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
} else { Write-Ok "No administratively-disabled adapters found." }

# --- 3. Winsock catalog reset (fixes corrupt LSP / Winsock layered providers) -
Write-Step "Resetting Winsock catalog"
Invoke-Native -Target 'Winsock' -Action 'netsh winsock reset' -Script { netsh winsock reset }

# --- 4. TCP/IP stack reset ----------------------------------------------------
Write-Step "Resetting TCP/IP (IPv4) stack"
Invoke-Native -Target 'TCP/IP v4' -Action 'netsh int ip reset' -Script {
    netsh int ip reset "$LogDir\netsh_ipreset_$stamp.log"
}
if ($IncludeIPv6Reset) {
    Write-Step "Resetting IPv6 stack (-IncludeIPv6Reset)"
    Invoke-Native -Target 'TCP/IP v6' -Action 'netsh int ipv6 reset' -Script { netsh int ipv6 reset }
}

# --- 5. DHCP release/renew + DNS flush ----------------------------------------
Write-Step "Releasing/renewing DHCP and flushing DNS"
Invoke-Native -Target 'DHCP' -Action 'ipconfig /release' -Script { ipconfig /release  | Out-Null }
Invoke-Native -Target 'DHCP' -Action 'ipconfig /renew'   -Script { ipconfig /renew    | Out-Null }
Invoke-Native -Target 'DNS'  -Action 'ipconfig /flushdns'-Script { ipconfig /flushdns | Out-Null }
if (Get-Command Register-DnsClient -ErrorAction SilentlyContinue) {
    Invoke-Native -Target 'DNS' -Action 'Register-DnsClient' -Script { Register-DnsClient }
}

# --- 6. Clear WinHTTP proxy (a stale/poisoned proxy makes "nothing work") -----
Write-Step "Resetting WinHTTP proxy to direct"
Invoke-Native -Target 'WinHTTP proxy' -Action 'netsh winhttp reset proxy' -Script { netsh winhttp reset proxy }

# --- 7. (Opt-in) Enforce outbound-only firewall posture ----------------------
# Does NOT reset or open the firewall. Keeps it ENABLED and locks inbound shut:
# default INBOUND = Block (no listening exposure), default OUTBOUND = Allow.
# Existing rules are left intact - this only sets the default policy + state.
if ($EnforceOutboundOnly) {
    Write-Step "Enforcing outbound-only firewall posture (-EnforceOutboundOnly)"
    Write-Warn2 "Inbound = BLOCK, Outbound = ALLOW, firewall ENABLED on all profiles. Firewall is NOT opened or reset."
    if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Invoke-Native -Target 'Firewall profiles' -Action 'block inbound / allow outbound (enabled)' -Script {
            Set-NetFirewallProfile -All -Enabled True `
                -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
        }
    } else {
        Invoke-Native -Target 'Firewall profiles' -Action 'netsh set policy blockinbound,allowoutbound' -Script {
            netsh advfirewall set allprofiles state on
            netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
        }
    }
} else {
    Write-Warn2 "Firewall left untouched (pass -EnforceOutboundOnly to lock inbound shut / allow outbound)."
}

# --- Summary + reboot ---------------------------------------------------------
Write-Host "`n===================================================" -ForegroundColor Green
Write-Host " Repair sequence complete." -ForegroundColor White
Write-Host " A REBOOT is required for the Winsock/TCP-IP reset to take effect." -ForegroundColor Yellow
Write-Host " Pre-repair snapshot: $snapshot" -ForegroundColor Gray
Write-Host " Transcript         : $transcript" -ForegroundColor Gray
Write-Host "===================================================" -ForegroundColor Green

try { Stop-Transcript | Out-Null } catch {}

if ($WhatIfPreference) { Write-Host "[i] -WhatIf: no changes were made, no reboot." -ForegroundColor Magenta; return }

if ($Reboot) {
    Write-Host "[*] Rebooting in 15 seconds (Ctrl+C to cancel)..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    Restart-Computer -Force
} else {
    $ans = Read-Host "Reboot now to finish the repair? (Y/N)"
    if ($ans -match '^(y|yes)$') { Restart-Computer -Force }
    else { Write-Host "[i] Remember to reboot manually - the stack reset is not fully applied until you do." -ForegroundColor Yellow }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQQXfCKXs6sfk8
# qIWnG47bnXLeDIs85CpaGNKOmRTr7qCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgW1BYb6cqaU/eaD33TUcHhFGc+4cP9+9VoPhI
# 8xdJYiIwDQYJKoZIhvcNAQEBBQAEggEAXkVDia2Rv+Ufyf0SDY1dtZVsAv9gXTCv
# 8l5mgfIyq0MAMExhrGrma76//TP6L9NXY7/9fVrBxMTOqj1ZDXPAa300Y5/qRQFs
# hMP2WsLcxGxmjCNiExziCqTuBd3YnGEfvwJlktdd7MF1WYddTtcFiQ3937Y3bi8O
# lQ/ZfI/0ceQ3WVgAFbc3p9ojIaKcPGHayjaezgQ9OQtK9gMjaidWsS9jHn4QBZ+R
# AGWGf/CDQDCdTMedIE5Gq8EC+g2++LijEgQ5GfVpfDAfCTl6qICTPi62jcmICaU0
# C7018HAaUsvwWc5HjKfP+v7+90fI+bLBc9Re1kkNz1mBTgJMAwgXYqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzFaMC8GCSqGSIb3DQEJBDEiBCBY
# K4uSEm6Ub0aOqT0Y1Onp+L4+LC3d6/ck7ZEZ7nrJYzANBgkqhkiG9w0BAQEFAASC
# AgDKx9p6ttttdkOQvRY8KDYGT3LmjYblJTJCj7RJw+XmsZIABFEGamnk8PuLl/Cy
# 7oZFNcroad150JdeYlyIPLz7OWuIxYaCXId33aOORfYDTYcqGgv5wLVZg1Q4nU2u
# 5LoBuIxPRcsFaqzFheuK6wStndvnKBTQfiWT7mCid0yrK2C6nWBSdIG+s2g7swh1
# ItpUumK9iPjRb0NlSM21Nwq4vqdbcZ+AOVl/JQ8tYqgFwZqW0tMju06Px4cMmptr
# RtZFhIK1DIr2z6d1q0CVYRUVxxp56HHj6WdsHd44TPXPRx30X/IPZATpygbLxFMR
# Vh7gdmLRxAJy5uUn+56hsgaMYXuFPVAiwSZ/fb7N6mPIzW/Rp5HlR6WN5vG2dMZP
# ylhn5gDYzlw451fmZW6OcAtNqCxigNb5i9QTPo+sOnbTWSSagc7/l9mYqsAs62mY
# d3msyqe3Q+ExZ3WkEgFgcwpKJl2UfH+NTXjZGS4bsuFLYNd+zfkLEW/QvJV2RRFu
# NbF6avaS9wMRMP0Deuhm3sgvj2WuFJbY56jJDizkMhqOJ7xgm2lQesWXGfKXIdBF
# +XV2LbqotHrtnrnMEVhext4UxLymlrEMrZY8TSerEvBKt7exFoWwHxqBOq5p4CIo
# wZnqpDfKWeMNFKid5tGo9f7m1hb6VMA4ODH1U/LkDsptBA==
# SIG # End signature block
