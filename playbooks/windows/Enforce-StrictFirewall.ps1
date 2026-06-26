<#
.SYNOPSIS
    Enforces a strict Default-Deny inbound Windows Firewall posture (and, as a deferred
    follow-on, an outbound blackhole) with binary state rollback.

.DESCRIPTION
    Safely transitions the Windows Defender Firewall to a strict 'Block Inbound' default.
    Generates a full binary export of the firewall state prior to mutation.
    Includes built-in validation to ensure pre-existing explicit 'Allow' rules continue to function.

    Two-stage network posture:
      • Analysis window (default): inbound Block, outbound ALLOW - so the C2/egress sensor can
        observe where the implant beacons and exfils to (beacons jitter / dwell for hours).
      • Follow-on (-BlockOutbound): after the egress-observation window closes, also set
        DefaultOutboundAction=Block to blackhole egress, keeping a management pinhole
        (-AllowOutboundPort / -AllowOutboundRemoteAddress). Reversible via -Rollback.

.PARAMETER Rollback
    Switch. Triggers the restoration of a previous firewall state.

.PARAMETER BackupPath
    String. The absolute path to the .wfw backup file to restore (Required if -Rollback is used).

.EXAMPLE
    # Enforce strict policy (Auto-creates backup in C:\FirewallBackups)
    .\Enforce-StrictFirewall.ps1

.EXAMPLE
    # Rollback to a known good state
    .\Enforce-StrictFirewall.ps1 -Rollback -BackupPath "C:\FirewallBackups\FW_State_20260417_1300.wfw"

.NOTES
    Enforcing a strict "Default Deny" inbound firewall posture physically neutralizes an adversary's ability to
    establish listening posts or execute lateral movement across the network. By eliminating these quiet,
    peer-to-peer pathways, we force the attacker to rely exclusively on outbound beaconing to maintain command
    and control. Pairing this inbound lockdown with the ML-driven outbound C2 sensor creates a strategic,
    unavoidable chokepoint. We operate under the "Assume Breach" paradigm: by denying horizontal movement, we
    force the adversary's traffic vertically into our behavioral analytics engine, ensuring rapid, mathematical
    detection of evasive tradecraft.

@RW
#>

param (
    [switch]$Rollback,
    [string]$BackupPath,
    # True inbound lockdown: also DISABLE all enabled inbound Allow rules so that
    # nothing inbound is permitted (DefaultInboundAction=Block alone does not do this).
    [switch]$FullInboundLockdown,
    # Optional management pinhole kept open during full lockdown (e.g. 3389 for RDP,
    # 5985/5986 for WinRM) so a remote responder is not locked out.
    [int[]]$AllowInboundPort = @(),
    [string[]]$AllowInboundRemoteAddress = @(),
    # FOLLOW-ON outbound blackhole: after the egress-observation window has captured
    # where the implant beacons/exfils, set DefaultOutboundAction=Block to cut all
    # egress (a management pinhole is kept so the responder is not locked out). This
    # is the deferred second stage - NOT used during the analysis window, when
    # outbound is deliberately left open so the C2 sensor can observe beaconing.
    [switch]$BlockOutbound,
    [int[]]$AllowOutboundPort = @(),
    [string[]]$AllowOutboundRemoteAddress = @()
)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = "Windows Firewall State Manager"

# ==============================================================================
# 1. ELEVATION CHECK
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[CRITICAL FATAL] This script requires NT AUTHORITY\SYSTEM or High Integrity Administrator privileges."
    Exit
}

# ==============================================================================
# 2. ROLLBACK EXECUTION PATH
# ==============================================================================
if ($Rollback) {
    Write-Host "[*] INITIATING FIREWALL STATE ROLLBACK..." -ForegroundColor Yellow
    if ([string]::IsNullOrWhiteSpace($BackupPath) -or -not (Test-Path $BackupPath)) {
        Write-Error "[CRITICAL] Rollback aborted. Invalid or missing backup file: $BackupPath"
        Exit
    }

    try {
        Write-Host "    -> Restoring binary state from: $BackupPath" -ForegroundColor Cyan
        $importResult = netsh advfirewall import $BackupPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw $importResult }

        Write-Host "[SUCCESS] Firewall state successfully rolled back to exact backup configuration." -ForegroundColor Green
    } catch {
        Write-Error "[CRITICAL FATAL] Failed to import firewall state. Exception: $($_.Exception.Message)"
    }
    Exit
}

# ==============================================================================
# 3. ENFORCEMENT EXECUTION PATH
# ==============================================================================
Write-Host "[*] INITIATING STRICT INBOUND ENFORCEMENT..." -ForegroundColor Cyan

$BackupDir = "C:\FirewallBackups"
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$ActiveBackupPath = Join-Path $BackupDir "FW_State_$Timestamp.wfw"
# First-write-wins baseline pointer: prevents a second lockdown from capturing the
# already-isolated state as "known-good" (which would make restoration restore an
# isolated host). Mirrors playbooks/lib/fw_baseline.sh::ir_baseline_record.
$BaselineMarker = Join-Path $BackupDir "baseline.txt"

try {
    # --- A. BINARY STATE BACKUP (first-write-wins) ---
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }

    if ((Test-Path $BaselineMarker) -and (Test-Path (Get-Content -LiteralPath $BaselineMarker -Raw).Trim())) {
        $ActiveBackupPath = (Get-Content -LiteralPath $BaselineMarker -Raw).Trim()
        Write-Host "    -> [1/4] Baseline already recorded; REUSING known-good $ActiveBackupPath (not re-exporting)." -ForegroundColor Gray
    } else {
        Write-Host "    -> [1/4] Exporting active state to $ActiveBackupPath" -ForegroundColor Gray
        $exportResult = netsh advfirewall export $ActiveBackupPath 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ActiveBackupPath)) {
            throw "Binary export failed or file not created. Halting to prevent data loss."
        }
        Set-Content -LiteralPath $BaselineMarker -Value $ActiveBackupPath -Encoding ASCII
    }

    # --- B. INBOUND POSTURE ---
    if ($FullInboundLockdown) {
        # DefaultInboundAction=Block only drops UNMATCHED inbound; existing enabled
        # Allow rules still permit traffic. For a true "nothing in" posture we must
        # disable those Allow rules too. (Reversible via the .wfw backup / -Rollback.)
        Write-Host "    -> [2/4] FULL LOCKDOWN: disabling all enabled inbound Allow rules..." -ForegroundColor Yellow
        $inAllow = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue
        $cnt = @($inAllow).Count
        if ($cnt -gt 0) { $inAllow | Disable-NetFirewallRule -ErrorAction SilentlyContinue }
        Write-Host "       Disabled $cnt inbound Allow rule(s). Loopback remains (Windows-implicit)." -ForegroundColor Gray

        if (@($AllowInboundPort).Count -gt 0) {
            $p = @{ DisplayName = "IR-MGMT-PINHOLE"; Direction = 'Inbound'; Action = 'Allow'
                    Protocol = 'TCP'; LocalPort = $AllowInboundPort }
            if (@($AllowInboundRemoteAddress).Count -gt 0) { $p['RemoteAddress'] = $AllowInboundRemoteAddress }
            New-NetFirewallRule @p | Out-Null
            Write-Host "       Management pinhole kept open: TCP $($AllowInboundPort -join ',') from $(@($AllowInboundRemoteAddress) -join ',')" -ForegroundColor Gray
        }
    } else {
        # Default-deny mode: unmatched inbound drops, but existing Allow rules remain.
        Write-Host "    -> [2/4] Verifying Core Networking rules are explicitly permitted..." -ForegroundColor Gray
        Enable-NetFirewallRule -DisplayGroup "Core Networking" -ErrorAction SilentlyContinue
    }

    # --- B2. OUTBOUND BLACKHOLE (deferred follow-on) ---
    # During analysis OutboundAction stays Allow so the C2 sensor can watch beaconing.
    # -BlockOutbound is the second stage, run AFTER the egress-observation window.
    $OutboundAction = 'Allow'
    if ($BlockOutbound) {
        $OutboundAction = 'Block'
        Write-Host "    -> [2b/4] OUTBOUND BLACKHOLE: setting DefaultOutboundAction = Block..." -ForegroundColor Yellow
        # Keep a management egress pinhole so the responder is not cut off
        if (@($AllowOutboundPort).Count -gt 0) {
            $op = @{ DisplayName = "IR-MGMT-EGRESS-PINHOLE"; Direction = 'Outbound'; Action = 'Allow'
                     Protocol = 'TCP'; RemotePort = $AllowOutboundPort }
            if (@($AllowOutboundRemoteAddress).Count -gt 0) { $op['RemoteAddress'] = $AllowOutboundRemoteAddress }
            New-NetFirewallRule @op | Out-Null
            Write-Host "       Management egress pinhole kept open: TCP $($AllowOutboundPort -join ',') to $(@($AllowOutboundRemoteAddress) -join ',')" -ForegroundColor Gray
        }
        # Allow local DNS so name resolution for management does not hard-fail
        New-NetFirewallRule -DisplayName "IR-ALLOW-LOCAL-DNS-EGRESS" -Direction Outbound -Action Allow `
            -Protocol UDP -RemotePort 53 -RemoteAddress LocalSubnet -ErrorAction SilentlyContinue | Out-Null
    }

    # --- C. ENFORCE DEFAULT DENY ---
    Write-Host "    -> [3/4] Mutating DefaultInboundAction=Block, DefaultOutboundAction=$OutboundAction across all profiles..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction $OutboundAction

    # --- D. STATE VALIDATION ---
    Write-Host "    -> [4/4] Validating state enforcement..." -ForegroundColor Gray
    # -All returns the Domain, Private and Public profiles. ('Any' is not a valid
    # profile name and throws "No MSFT_NetFirewallProfile objects found ... 'Any'".)
    $profiles = Get-NetFirewallProfile -All

    foreach ($fwProfile in $profiles) {
        if ($fwProfile.DefaultInboundAction -ne 'Block') {
            throw "State Mismatch: $($fwProfile.Name) profile is currently set to $($fwProfile.DefaultInboundAction). Expected: Block."
        }
    }

    $remaining = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue).Count
    Write-Host "`n[SUCCESS] DefaultInboundAction = Block on all profiles." -ForegroundColor Green
    if ($FullInboundLockdown) {
        $note = if (@($AllowInboundPort).Count -gt 0) { " (management pinhole only)" } else { " - nothing inbound is permitted" }
        Write-Host "[INFO] Full inbound lockdown: $remaining enabled inbound Allow rule(s) remaining$note." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Default-deny is active, but $remaining enabled inbound Allow rule(s) STILL PERMIT matching inbound traffic." -ForegroundColor Yellow
        Write-Host "[WARN] Re-run with -FullInboundLockdown to disable those and allow nothing inbound." -ForegroundColor Yellow
    }
    Write-Host "[INFO] Backup safely stored at: $ActiveBackupPath" -ForegroundColor DarkGray

} catch {
    Write-Host "`n[!] CRITICAL ERROR DURING ENFORCEMENT" -ForegroundColor Red
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The firewall state may be inconsistent. It is highly recommended to rollback using the previous backup." -ForegroundColor Yellow
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZfXcJy+LyRGRj
# 6aUUyHfWheoGIq4zG9apTNSRn8QHb6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgN8675QQ8JLRYxyXsTHVtUhOSVzSKzOdRtm+e
# PbYSn5gwDQYJKoZIhvcNAQEBBQAEggEASQGtNet4FANv8ymJ0LgYlXVVq4Gy1iMP
# Nqe1wd2BmBDVytua4DC9yMSqiT1gHRn4EZKDIUoRVjEfAx5lbnYrsKYvvTrI9FYp
# LCymzyS4GW/aTyfks4yyPFEVMU5NIpgE3K0FKXNKMuj1WGWNhVDWKsnlyrjUSkGJ
# g/1zBwY+wfR0t4IRGdtruKhCMXDJJYuWMD9prrBm8+EHoUn+syhUR9ncT3C8K+ms
# KCATAIwaly4f95EGr1Mh5NZ7J3T2yO4uQRyYLtfBNYa9Ut51fb1Bp3cY/CXBO3v4
# azkTgdyO/xWZzQWzQAnR3yvT2yzy8dm+EImCeQlhO/S64JB2S8w+eaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MTlaMC8GCSqGSIb3DQEJBDEiBCDa
# v734Xbfi3UbwOOqm+4Pwyya6UxlGEHcfYkPLk5mKaDANBgkqhkiG9w0BAQEFAASC
# AgAhCPE9SrRxqYT7A+m53YSJBrVLbVyG8+xKyuOqBK2kLgWTauCg63aY3zinNa+3
# QRsTKW1QwJxSlLDZZaXTMZZ/QMmWPLKJYuef95ViWFzMLiuocCnZGG/izTLA1C61
# 0PAjaFZHsQNj2NbdXo5EHSr1vWDCD0nF+6PdyzjfAfZDTty1NCo7ai5l2qBKxOfG
# SBArFblMbbkl9AHsMLHW3o6+OVckIvzsq+7W5WB9MWu6+DKstybzjREJkfxHBTPv
# E01ZcFI785svakwl3zEeXloypvtczWG/nRtbvCkdIvyEhYiAzfLttl6/0d26QSqj
# MFFuSxQLlf9GXDBhOcvZJ6mNVzO+CD8jqEvWk731CdaJH7kbMi4doXIpjF+EZRxG
# eD5Zs4GNFFiHX3RNud67wwgwyQND2KI0Cz2gf8+CXHxPzzRfGFR8/yegulH1i7js
# HIzSu5brQeOwm2kY3c1YT3wQPvdmQrGqbYqCuHVrJdks/ilkYBwbyGakMTBlT2uW
# cPEo0zDnzWH3tfte7vtFQ8bHW6TUUOdDzm0vxCIIZflcsfmqBCR1tLRK0UhhbYcj
# ljsSQdktDOO8930YaUFQBP5hg8F8haqklmx4bgzjz2KyzYKJy/AQAoxby0SaHBgu
# ePLJ3501tKY9VahHxBQ1gk3bQMR3ApWNzMiegqYiMTgMfA==
# SIG # End signature block
