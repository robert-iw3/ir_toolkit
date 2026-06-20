<#
.SYNOPSIS
    One-time Defender setup for the IR Toolkit. Automates every step that CAN be
    automated; guides the user through the two GUI clicks that cannot.

.DESCRIPTION
    Windows Defender Tamper Protection prevents programmatic changes to real-time
    protection settings, exclusions, and AMSI scanning — even from an Administrator.
    The only supported way to change those settings is through the Windows Security
    GUI while Tamper Protection is active.

    This script:
      1. Opens Windows Security directly to the correct settings page.
      2. Guides you through toggling Tamper Protection OFF (one click).
      3. Automatically adds all required folder + process exclusions.
      4. Guides you through toggling Tamper Protection back ON (one click).
      5. Verifies the exclusions are in place and prints a ready confirmation.

    Run this script ONCE per machine before your first IR collection run.
    The exclusions persist across reboots; you do not need to re-run it.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Invoke-PrepareDefender.ps1
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$ToolkitRoot = $PSScriptRoot
$ToolsDir    = Join-Path $ToolkitRoot 'tools'

function Write-Step {
    param([string]$Msg, [string]$Color = 'Cyan')
    Write-Host "`n$Msg" -ForegroundColor $Color
}

function Get-TamperStatus {
    try { return (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected }
    catch { return $null }
}

function Get-DefenderActive {
    try { return (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled }
    catch { return $false }
}

function Open-DefenderSettings {
    # Opens Virus & threat protection settings — where the Tamper Protection toggle lives.
    try {
        Start-Process 'windowsdefender://threatsettings' -ErrorAction Stop
    } catch {
        try { Start-Process 'ms-settings:windowsdefender' -ErrorAction Stop }
        catch { Start-Process 'C:\Program Files\Windows Defender\MSASCui.exe' -ErrorAction SilentlyContinue }
    }
}

function Add-AllExclusions {
    Write-Step "Adding folder and process exclusions..." 'Green'

    # Folder exclusions — covers all scripts and output
    $foldersToExclude = @($ToolkitRoot)
    foreach ($folder in $foldersToExclude) {
        try {
            Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
            Write-Host "  [+] Folder excluded: $folder" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Could not add folder exclusion '$folder': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Process exclusions — all staged binaries that would be flagged behaviorally
    $processExes = @(
        'autorunsc64.exe', 'autorunsc.exe',
        'yara64.exe',      'yarac64.exe',
        'winpmem.exe',
        'procdump64.exe',  'procdump.exe',
        'sigcheck64.exe',  'sigcheck.exe',
        'handle64.exe',    'handle.exe',
        'strings64.exe',   'strings.exe',
        'Listdlls64.exe',  'Listdlls.exe',
        'tcpvcon64.exe',   'tcpvcon.exe',
        'pslist64.exe',    'pslist.exe',
        'PsLoggedon64.exe','PsLoggedon.exe',
        'PsService64.exe', 'PsService.exe'
    )

    $excluded = 0
    foreach ($exe in $processExes) {
        $fullPath = Join-Path $ToolsDir $exe
        if (Test-Path $fullPath) {
            try {
                Add-MpPreference -ExclusionProcess $fullPath -ErrorAction Stop
                $excluded++
            } catch {}
        }
    }
    Write-Host "  [+] $excluded staged tool process exclusions added." -ForegroundColor Green

    # Verify exclusions were actually written
    $current = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
    if ($current -and ($current | Where-Object { $_ -like "*IR_Toolkit*" })) {
        Write-Host "  [+] Folder exclusion confirmed in Defender." -ForegroundColor Green
        return $true
    } else {
        Write-Host "  [!] Folder exclusion could not be verified - check Windows Security manually." -ForegroundColor Yellow
        return $false
    }
}

function Enable-ForensicAuditing {
    # Enable process creation (4688) and command-line auditing.
    # Without these, Amcache/ShimCache findings cannot be correlated with parent processes
    # or command lines — the single biggest gap in post-collection forensic pivoting.
    # This is a one-time setup that persists across reboots.
    Write-Step "Enabling forensic audit policies (4688 process creation + cmdline logging)..." 'Cyan'
    $errors = 0

    # 4688 — Process Creation (Success)
    try {
        & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
        Write-Host "  [+] Audit: Process Creation (4688) enabled." -ForegroundColor Green
    } catch { Write-Host "  [!] Could not enable Process Creation audit." -ForegroundColor Yellow; $errors++ }

    # Include command line in 4688 events (registry key, requires admin)
    try {
        $cmdKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        if (-not (Test-Path $cmdKey)) { New-Item -Path $cmdKey -Force | Out-Null }
        Set-ItemProperty -Path $cmdKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  [+] Audit: Command-line logging in 4688 enabled." -ForegroundColor Green
    } catch { Write-Host "  [!] Could not enable cmdline logging in 4688." -ForegroundColor Yellow; $errors++ }

    # 4698/4702 — Scheduled Task Created/Modified (needed for task persistence detection)
    try {
        & auditpol /set /subcategory:"Other Object Access Events" /success:enable 2>$null | Out-Null
        Write-Host "  [+] Audit: Other Object Access Events (task 4698/4702) enabled." -ForegroundColor Green
    } catch { $errors++ }

    # 7045 — New Service Installed is in System log; verify it is captured
    Write-Host "  [i] Service install events (7045) are in the System log — always recorded." -ForegroundColor Gray

    if ($errors -eq 0) {
        Write-Host "  [+] All forensic audit policies applied. Process parent chains will be in Security log on next collection." -ForegroundColor Green
    } else {
        Write-Host "  [!] $errors audit policy change(s) failed — may need Group Policy override." -ForegroundColor Yellow
    }
}

function Wait-TamperOff {
    Write-Host "`nWaiting for Tamper Protection to be disabled..." -ForegroundColor Yellow
    Write-Host "    (Toggle it OFF in the Windows Security window, then return here)" -ForegroundColor Gray
    $dots = 0
    while ((Get-TamperStatus) -eq $true) {
        Start-Sleep -Seconds 2
        $dots++
        if ($dots % 5 -eq 0) { Write-Host "    still waiting..." -ForegroundColor DarkGray }
        if ($dots -gt 60) {
            Write-Host "`n[!] Timed out waiting for Tamper Protection to be disabled." -ForegroundColor Red
            Write-Host "    Toggle it OFF in Windows Security and re-run this script." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "  [+] Tamper Protection is OFF." -ForegroundColor Green
}

function Wait-TamperOn {
    Write-Host "`nWaiting for Tamper Protection to be re-enabled..." -ForegroundColor Yellow
    Write-Host "    (Toggle it back ON in the Windows Security window)" -ForegroundColor Gray
    $dots = 0
    while ((Get-TamperStatus) -eq $false) {
        Start-Sleep -Seconds 2
        $dots++
        if ($dots % 5 -eq 0) { Write-Host "    still waiting..." -ForegroundColor DarkGray }
        if ($dots -gt 60) {
            Write-Host "`n[!] Tamper Protection was not re-enabled within 2 minutes." -ForegroundColor Yellow
            Write-Host "    Please enable it manually in Windows Security." -ForegroundColor Yellow
            return
        }
    }
    Write-Host "  [+] Tamper Protection is back ON." -ForegroundColor Green
}

# -- Main -----------------------------------------------------------------------

Write-Host @"
============================================================
  IR Toolkit — Defender Setup
  Toolkit root: $ToolkitRoot
============================================================
"@ -ForegroundColor Cyan

# -- Step 0: Import code-signing certificate (if scripts are signed) -----------
# Importing the IR Toolkit cert into TrustedPublisher lets Defender trust the
# scripts at AMSI content-scan time WITHOUT requiring Tamper Protection to be off.
# This is a PKI operation (CertEnroll API), not a Defender API call — TP does not block it.
$irCert = Join-Path $ToolsDir 'ir_toolkit.cer'
if (Test-Path -LiteralPath $irCert) {
    Write-Step "Code-signing certificate found — importing into TrustedPublisher store..." 'Cyan'
    try {
        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($irCert)
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                    'TrustedPublisher',
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        # Only add if not already present
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $x509.Thumbprint }
        if (-not $existing) {
            $store.Add($x509)
            Write-Host "  [+] IR Toolkit cert imported: $($x509.Subject)" -ForegroundColor Green
            Write-Host "  [+] Thumbprint: $($x509.Thumbprint)" -ForegroundColor Gray
        } else {
            Write-Host "  [i] Cert already trusted: $($x509.Thumbprint)" -ForegroundColor Gray
        }
        $store.Close()
        Write-Host "  [+] Signed IR Toolkit scripts are now trusted by Defender at script load time." -ForegroundColor Green
        Write-Host "      AMSI content scanning will not block these scripts." -ForegroundColor Gray
    } catch {
        Write-Host "  [!] Could not import cert: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "      Continuing with exclusion-based setup as fallback." -ForegroundColor Gray
    }
} else {
    Write-Host "  [i] No ir_toolkit.cer found — scripts are not signed." -ForegroundColor Gray
    Write-Host "      Run .\Invoke-SignToolkit.ps1 on the analyst machine to sign all scripts." -ForegroundColor Gray
    Write-Host "      Signed scripts eliminate the need for Tamper Protection toggle on future runs." -ForegroundColor Gray
}

# Check Defender is present
if (-not (Get-DefenderActive)) {
    Write-Step "Windows Defender real-time protection is not active." 'Yellow'
    Write-Host "  No Defender exclusions needed. The toolkit should run without interference." -ForegroundColor Gray
    Write-Host "  If another AV product is active, add exclusions manually per the README." -ForegroundColor Gray
    exit 0
}

$tamperStatus = Get-TamperStatus

if ($tamperStatus -eq $false) {
    # TP already off — add exclusions and audit policies immediately
    Write-Step "Tamper Protection is already OFF." 'Green'
    $ok = Add-AllExclusions
    Enable-ForensicAuditing
    if ($ok) {
        Write-Step "Setup complete. Re-enable Tamper Protection now." 'Cyan'
        Open-DefenderSettings
        Write-Host "  Opening Windows Security... toggle Tamper Protection back ON." -ForegroundColor Yellow
        Wait-TamperOn
    }
} else {
    # TP is on — guide the user through turning it off
    Write-Step "Tamper Protection is ON — it must be toggled off via the GUI." 'Yellow'
    Write-Host @"

  Why this is required:
    Microsoft blocks all programmatic changes to Defender settings when Tamper
    Protection is enabled, even from an Administrator account. This is intentional
    security hardening. The GUI toggle is the only supported mechanism.

  What to do:
    1. Windows Security will open now.
    2. Click "Virus & threat protection".
    3. Click "Manage settings" under "Virus & threat protection settings".
    4. Scroll to "Tamper Protection" and toggle it OFF.
    5. Confirm the UAC prompt.
    6. Return to this window — setup continues automatically.

"@ -ForegroundColor White

    Write-Host "  Opening Windows Security..." -ForegroundColor Cyan
    Open-DefenderSettings
    Start-Sleep -Seconds 2

    Wait-TamperOff
    $ok = Add-AllExclusions
    Enable-ForensicAuditing

    Write-Step "Re-enable Tamper Protection." 'Cyan'
    Write-Host @"

  Tamper Protection should be turned back ON immediately after exclusions are set.
  The IR Toolkit exclusions you just added will persist after TP is re-enabled.

  1. In the Windows Security window (still open), toggle Tamper Protection back ON.
  2. Confirm the UAC prompt.

"@ -ForegroundColor White

    Open-DefenderSettings
    Wait-TamperOn
}

# -- Summary --------------------------------------------------------------------
Write-Host @"

============================================================
  Setup complete.

  Defender is configured. You can now run:

    powershell.exe -ExecutionPolicy Bypass -NoProfile ``
        -File .\Invoke-IRCollection.ps1 ``
        -DeepFileScan -ScanYara

  The toolkit's pre-flight will temporarily suspend Defender
  real-time monitoring during the run and restore it on exit.
  Tamper Protection does not need to be disabled again.
============================================================
"@ -ForegroundColor Green

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDAPk57wRu7LvLZ
# HB7RzJQMg0eGW6hL5i0HLoaWjVZ3aKCCFrQwggN2MIICXqADAgECAhBa5MQyEl22
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgqqx4ufPIIrnHGZNBmGa82naIt1CMMqse
# ExbiDvmBHPQwDQYJKoZIhvcNAQEBBQAEggEAY49pCX5AeW2au3NFDdCf2bbuM0Yg
# OekcVmJtzP3URwoZaifjFTTAXZWI4Nfh3C7PSmfmc1l1RHjFK80rQTK+npkXNbBb
# BnLAtxbWxOFCKwmO2Dt1+m1NW384LRKNVL9jxWjscdZ7LQTWACX5XuJUy8MN+yUu
# D4SWPKWm7TopjDsweNA3Zmiy/I8OopohGnjDs4uDdI8crNV7ErAn12QyBUP0p6K9
# s4Q/zQL9hbOE2IaRaUNI41fcO7fc2E52zN4lUPm9sNh1T+GSt0z6alQCBi943jxT
# J+QbzBSNUTD5Reh+AW9cJZfwTvjqdIJiM5AjQia8UJlubRbqD8EI4y59HKGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MjhaMC8GCSqGSIb3DQEJBDEi
# BCBVtleE4APdQoSv04shY8yN5MdyoaphEPYjqIg9fD/ckTANBgkqhkiG9w0BAQEF
# AASCAgCl2opOeUwbNLKa9QAuFOOKnKidRg8f5KK1EhRuwtnv3vKlLLT8IGX4ApRs
# oiSrrK3Kw4vQli2fQE0LbcumSNpvrkyQfd0VVblXbhQUs0h7qAgj4Siaj3KkVKlx
# WL73YMCA34c3rVXWNuh8y4Wq9eYYkgfa1VYRQWkqn+mtjnz64O09U3me//KF6qWU
# eBQu6MHvpwq0bLWRRVzFeeCTlo3f40RSBGscExYAHXPZmVwX9Ucob+FLKLFbtT9L
# 8nrZPx3AfrDYz+39OBM8vHWuzUyy8NI90g+NcLpILQ+PRyker0sfN+yZZJdQmooP
# z4YpQnQN3MVSqGHl5XaeqqWSkOeoXzBX/Rc8dT+OQFJ8pp3TS7RJwPpp/v4JxFtS
# Bga53eFQ34EYumOAYa3TuY9Jv1d7AuRtdUkMI3oc+pyaO4XZNjG2MzDd73Yhgjfv
# KhVm7AvUDxlUhFo+43H67F/ldbjTggVVU1zrrnqVaC+/3ItPgmfVUy7IS9LZEC1w
# UrU9z7HeKnrg+0lPdEVbLw5YsOS/Sq/lUEo+jzeXb4zXOHEhkx3AmNFBIBNkV7/o
# Do1I8hqTRrj0PbnnhZW1p9xLrUoUnIPnBJsQIzqIkka3pUgZi0oegELKj9VgrTsI
# 18EZ9IMzoEjcUDYS6Ol6oNVPDudU/tmnjfucsZXCI/zWnneFUw==
# SIG # End signature block
