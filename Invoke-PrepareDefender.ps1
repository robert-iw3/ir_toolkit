<#
.SYNOPSIS
    One-time Defender setup for the IR Toolkit. Automates every step that CAN be
    automated; guides the user through the two GUI clicks that cannot.

.DESCRIPTION
    Windows Defender Tamper Protection prevents programmatic changes to real-time
    protection settings, exclusions, and AMSI scanning - even from an Administrator.
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
    # Opens Virus & threat protection settings - where the Tamper Protection toggle lives.
    try {
        Start-Process 'windowsdefender://threatsettings' -ErrorAction Stop
    } catch {
        try { Start-Process 'ms-settings:windowsdefender' -ErrorAction Stop }
        catch { Start-Process 'C:\Program Files\Windows Defender\MSASCui.exe' -ErrorAction SilentlyContinue }
    }
}

function Add-AllExclusions {
    Write-Step "Adding folder and process exclusions..." 'Green'

    # Folder exclusions - covers all scripts and output
    $foldersToExclude = @($ToolkitRoot)
    foreach ($folder in $foldersToExclude) {
        try {
            Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
            Write-Host "  [+] Folder excluded: $folder" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Could not add folder exclusion '$folder': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Process exclusions - all staged binaries that would be flagged behaviorally
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
    # or command lines - the single biggest gap in post-collection forensic pivoting.
    # This is a one-time setup that persists across reboots.
    Write-Step "Enabling forensic audit policies (4688 process creation + cmdline logging)..." 'Cyan'
    $errors = 0

    # 4688 - Process Creation (Success)
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

    # 4698/4702 - Scheduled Task Created/Modified (needed for task persistence detection)
    try {
        & auditpol /set /subcategory:"Other Object Access Events" /success:enable 2>$null | Out-Null
        Write-Host "  [+] Audit: Other Object Access Events (task 4698/4702) enabled." -ForegroundColor Green
    } catch { $errors++ }

    # 7045 - New Service Installed is in System log; verify it is captured
    Write-Host "  [i] Service install events (7045) are in the System log - always recorded." -ForegroundColor Gray

    if ($errors -eq 0) {
        Write-Host "  [+] All forensic audit policies applied. Process parent chains will be in Security log on next collection." -ForegroundColor Green
    } else {
        Write-Host "  [!] $errors audit policy change(s) failed - may need Group Policy override." -ForegroundColor Yellow
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

# -- Main -----------------------------------------------------------------------

Write-Host @"
============================================================
  IR Toolkit - Defender Setup
  Toolkit root: $ToolkitRoot
============================================================
"@ -ForegroundColor Cyan

# -- Step 0: Import code-signing certificate (if scripts are signed) -----------
# Importing the IR Toolkit cert into TrustedPublisher lets Defender trust the
# scripts at AMSI content-scan time WITHOUT requiring Tamper Protection to be off.
# This is a PKI operation (CertEnroll API), not a Defender API call - TP does not block it.
$irCert = Join-Path $ToolsDir 'ir_toolkit.cer'
if (Test-Path -LiteralPath $irCert) {
    Write-Step "Code-signing certificate found - importing into TrustedPublisher store..." 'Cyan'
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
    Write-Host "  [i] No ir_toolkit.cer found - scripts are not signed." -ForegroundColor Gray
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
    # TP already off - add exclusions and audit policies immediately
    Write-Step "Tamper Protection is already OFF." 'Green'
    $ok = Add-AllExclusions
    Enable-ForensicAuditing
    if ($ok) {
        Write-Step "Setup complete." 'Cyan'
        Write-Host "  Leave Tamper Protection OFF - it must stay off for the whole scan." -ForegroundColor Yellow
        Write-Host "  Invoke-IRCollection.ps1 re-enables it automatically when the scan finishes." -ForegroundColor Yellow
    }
} else {
    # TP is on - guide the user through turning it off
    Write-Step "Tamper Protection is ON - it must be toggled off via the GUI." 'Yellow'
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
    6. Return to this window - setup continues automatically.

"@ -ForegroundColor White

    Write-Host "  Opening Windows Security..." -ForegroundColor Cyan
    Open-DefenderSettings
    Start-Sleep -Seconds 2

    Wait-TamperOff
    $ok = Add-AllExclusions
    Enable-ForensicAuditing

    Write-Step "Exclusions are set - LEAVE Tamper Protection OFF." 'Cyan'
    Write-Host @"

  Do NOT turn Tamper Protection back on yet. It must stay OFF for the entire
  collection scan, or Defender's AMSI will block the toolkit scripts.
  Invoke-IRCollection.ps1 re-enables Tamper Protection automatically when the
  scan finishes.

"@ -ForegroundColor White
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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDV6KKDkPIx564x
# Ppa4z3WUPfJZObVKrelrpPJD5QOzpaCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgZnrEHGOlaKJKrlNBxQNsafDryCnngl1qotc7
# dGWBEyQwDQYJKoZIhvcNAQEBBQAEggEAc1UA/vEKm+7AnnLSRQd/EwCn9Uq8w62G
# VSGx5lgWInes1fZwgaR5XHIdijJcfToLukRcu08+ktlaLqx9n4AqGBIIv3X74MP8
# uegy+Dryfj53Cw7ENykc1oe/X2ayRyslQZu6mlkbYZxkgB23kQAGXttPv4o4qy1K
# pqujxlAK57M24ZRt596kRTLitOQjUo7SFSg8ujLGAYH8em1lD2eIDrFAYu3UyMqh
# TAYiLZdphw54fC9n+5vkwIz7/6FO923gls/RR4xXYehcjsfsqrZzbrUIWrlJzwYL
# UMeCfbdDii3UIRHpr7NtbYtfv7iXIT4C++M5qc/2ziKfS3BAtF6c9aGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MTZaMC8GCSqGSIb3DQEJBDEiBCDZ
# fLXAHWtNKS4bIyVMAE/++0gZ7P7AHTXWMJnBXahHizANBgkqhkiG9w0BAQEFAASC
# AgAjNmxyxof0BKcAHdGVhEXwFTBtop23PSK9CLUSpOnbmMC/VvTGAC1o0wEUfjMf
# bdptOEYzQT2vBqiecgGp3MTe2zhARLlWkMRUyiQ6BjNOtswgxTyhrLT+1RHJip5Y
# GuGE0ZyTRhtrO155lovfFb7vYsq6qrkNKELjcVIaBKRsVxbp9tW3EB2sVcDze8b/
# WDLFHMzreH9Qwz1iGgVMUMVJl/lfa9iSLXHESLO8IQ7oyNUpll9quI2O1hz/F8L7
# Tx4MRajJ9YuYsPtfqUJQu1pA+s3a/18WmgLm3c4/kQ/ryroNsUbPfEav5ggTm7ly
# K/OKeBjIV68eSMrk+RV1KLwsY3j4P+k4hgzQQF7dfqZ5+EvY5Lp36uPzduHH5qk1
# xmZKgoeLLcbSevKFTsLWGsWXWxBEZ5TB+S0R206hS3eSXNYZkmxF9wAMf3xgJhCF
# ecHSTpVEsM3oUfRiEDrZmnoDTG5ZA7ko5snFVpiwmpFDWBnkOADNLnCa1ecItRUM
# jP55ARnXNld24pdVH6ExLSp6njcDzHzrFJPSdVtYUTFp6Wxcz4MGaFpH4kL/R6lt
# n5Qv9VMKxChG/SV+QNb0L3dtIIGn5gWe+2badldCZZdgjpZx06/wLyrofjx4EjJm
# h5F2W21lRx/LyKPLQlWZunhHtePsRZsb+41wFUdGqbzokQ==
# SIG # End signature block
