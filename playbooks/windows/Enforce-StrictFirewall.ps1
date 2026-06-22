<#
.SYNOPSIS
    Enforces a strict Default Deny (Block) inbound Windows Firewall posture with binary state rollback.

.DESCRIPTION
    Safely transitions the Windows Defender Firewall to a strict 'Block Inbound' default.
    Generates a full binary export of the firewall state prior to mutation.
    Includes built-in validation to ensure pre-existing explicit 'Allow' rules continue to function.

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
    [string[]]$AllowInboundRemoteAddress = @()
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

    # --- C. ENFORCE DEFAULT DENY ---
    Write-Host "    -> [3/4] Mutating DefaultInboundAction to 'Block' across all profiles..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB/pcavQ3DQxM4f
# 0XQt5Qukx5cj+r8aq6+SYo5rFWvY3aCCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
# nkbveZC/LiR8MA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjIwNDI0NDVaFw0zMTA2MjIwNDM0NDVaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKuTSorzjXf0qc4qX04KtYn2ErVj9RAkn/1f/9YN
# llrRj0s3urh/LnWmHn4vUjPrDTzHXUx4udOclWNlv52uCMAfXKZR3qD73OCHHQ2l
# +1s4JqrAdGhr6QPyIhCDwl7wqQUfekQtBep+SqbM0vkbvup3WKgol+c3fIUxvM8E
# bPLg5CcNWug6Twj+Wn1FJidJihmYARSKT5PFv32BLbffUpuvdWXxzRIRv8c4EE+S
# bWs3lTiCGrp1X33mXYiMRNAiF5ofrCJwRA7LESh4TCqXWDSvs+KFBi1ZxEnLxmUk
# 1Wrzq11umlIzoJhnEN0VyBvLK6X40uTF50piU+5kGy9kZlkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSpc1pf
# XTSlgxdtXKDrlumz7H67TjANBgkqhkiG9w0BAQsFAAOCAQEAdPAxdgyk/YzF72lK
# 4P1I3Lwjice2yAR0aoXSEP5gO/xnAvuqCiAcdPfJhqMrrfq5iFLqTuWSfz+k9irn
# hjzyWgmo2GUrQ8BVRoNAw7HpTJo7Rw8+FfDzyy+stq9UKWrkflHqwb7oBD+aBs/5
# ZccFKZi8oeV79CCTGdwXKYgE+xYbV//Twr7rpMbVUqbchEDdZXEzT2GdEUd5B02L
# bDGJ4Gjz8AtCFcSXWQlLnAQxd5CJVFHDkyfkEs2VvBPtR/MBCF3NiNufb8HgClhS
# ZHayqVVZhUd+NS7/orBY5M1Ioc0/kGiNO3nlWf1IlAPk/jsILweFZkUO0wBTot/O
# b18zszCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBsvfGvcX1ueRu95kL8u
# JHwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgoZCifmjJe2sLYctI2wBTseUMOdQcOSSP
# nX4mbPddK9gwDQYJKoZIhvcNAQEBBQAEggEAUAm+Av8CHNPY7Q0dmWSEp4hElVbv
# MoviyNOEfBYxVOflks68GbdEumWD52qN9Aflb15deiYlC/wAKbxX5q2ERWBMjtuB
# H+chwinGU72XZt8U3aeiiEoUTxyJQQTFCDqsx/UXUov7Y7MVol7IIfudafa3I++k
# ZXvgUEeY1+Wxon8Ci0+mBHaMrCIijQDaHAb8AFGk3+0GT6VzuPVJ0Fezc+L6JpM9
# oV1PDZhEvoDxbgfwZqeppxwwaUurr3TXzuM6E4S7TNU7IpfBJwn9dlqLYPOeab7n
# GhN33IzSVwHbwjV08ZJ+7k+R0MzV48XDfVargrAbrRng0BrokQFK1H+peqGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NTNaMC8GCSqGSIb3DQEJBDEi
# BCBTggQvUhfhgIkcNsnO/UaIPvY6w3Vl+XOojDbjcYA9wzANBgkqhkiG9w0BAQEF
# AASCAgBN6nHkBxbqCA/ZMKjoGs1rPyoI/C6Wc2obgQBmb7ZHCxzutPG/5hmc/SA4
# 6jzEdKvo2FmsOxW93P8dqoELvq4Dk60h+7w1RjQLH4oKolkajZhQfUIquMs3DTQ6
# sDdnUbaAxdJcksvV7IVx3LwEb5LzngFZafP/hn1uoBrBgWFrxldKZq1tc4gKeIEt
# /xZGP7R3bQV16Ph/SDFL6vgw9sJsLJhjrr0yUggW//dJccn99KgP3OL+BVnZkrwu
# 0hyKNny7ZsVVtt2ZYXX8lgbqPnZwMHCDChE35ChD3FZ0opUI0RJqxKhcgBMKv/rb
# 04+9PPW0fezA4CYY7xzJQhfgJ1PhWWK5BlEgoWgeFVciLsVdpFpJYqaVuhDJFxC6
# KJdOMSH1Z3+g6AKfGy9+OMWz5JT77Pghw/4tJEdmrosfZJJwef/t6Pe9XON/76mS
# amqC8q3Bb5aomv9fE0GITN/8ZpX+nXjlj07bD0tslj6plm7ViF6AM0tuRjUitWk7
# O63eBUig8w7yNdLKMyVk96qM4T7ukvXRtulAfsq9MSqPnjm8iaVmmsZR9S4IQlQC
# VEVpiPToR3kW606nNEWyWZNbR7GFxMjw3nvke6WeHOF9SJgHt+VqnvierotDJbqb
# PfLSuOLftmcZgZ0qeJAgUx3P8huPpvREROBvOY/Rke3AC5fVvA==
# SIG # End signature block
