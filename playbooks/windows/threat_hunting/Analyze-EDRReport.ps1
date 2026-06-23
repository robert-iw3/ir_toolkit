<#
.SYNOPSIS
    EDR Toolkit - Fleet Analysis & Tuning Engine
.DESCRIPTION
    Ingests JSON reports from the EDR Toolkit. Applies a universal Windows baseline
    to filter out OS-level noise, leaving only actionable anomalies.
    Designed to be deployed centrally to parse logs from multiple endpoints.
.PARAMETER ReportPath
    Path to the EDR_Report_*.json file (or a directory of JSON files).
.PARAMETER ExportCSV
    Exports the filtered findings to a clean CSV for SIEM ingestion.
.PARAMETER ShowGrid
    Opens the actionable alerts in an interactive Out-GridView.
.EXAMPLE
    .\Analyze-EDRReport.ps1 -ReportPath .\EDR_Report_20260402_011825.json -ShowGrid
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [String]$ReportPath,
    [Switch]$ExportCSV,
    [Switch]$ShowGrid
)

# =============================================================================
# 1. THE TUNING BLOCK (Universal Windows Baselines)
# =============================================================================

# Universal NT Kernel & Core OS Processes
$Global_FP_Processes = @(
    "^\s*System Idle Process\s*$",
    "^\s*System\s*$",
    "^\s*Secure System\s*$",
    "^\s*Registry\s*$",
    "^\s*Memory Compression\s*$",
    "smss\.exe", "csrss\.exe", "wininit\.exe", "services\.exe", "lsass\.exe", "winlogon\.exe"
)

# Standard Microsoft/Windows Component Paths
$Global_FP_Paths = @(
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\Microsoft\.NET\\",
    "\\Program Files\\Common Files\\System\\",
    "\\Program Files\\Microsoft Office\\",
    "\\Program Files \(x86\)\\Microsoft Office\\",
    "\\ProgramData\\Microsoft\\Office\\"
)

# Known benign boot-time operations (OS Updates, Temp cleanup)
$Global_FP_Renames = @(
    "\\Windows\\Temp\\",
    "\\Windows\\Prefetch\\",
    "\\Windows\\SoftwareDistribution\\Download\\",
    "\\Windows\\servicing\\Packages\\"
)

# =============================================================================
# 2. INGESTION ENGINE
# =============================================================================

$filesToProcess = @()
if (Test-Path $ReportPath -PathType Container) {
    $filesToProcess = Get-ChildItem -Path $ReportPath -Filter "*.json" -File
} else {
    $filesToProcess = Get-Item -Path $ReportPath
}

if ($filesToProcess.Count -eq 0) {
    Write-Host "[-] No JSON reports found at specified path." -ForegroundColor Red
    exit
}

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($file in $filesToProcess) {
    $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    if ($content) {
        foreach ($item in $content) {
            $allFindings.Add($item)
        }
    }
}

Write-Host "[*] Ingested $($allFindings.Count) total raw events across $($filesToProcess.Count) report(s)." -ForegroundColor Gray
Write-Host "[*] Applying Universal Windows Baseline filters..." -ForegroundColor Cyan

# =============================================================================
# 3. FILTERING LOGIC
# =============================================================================

$actionableFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($finding in $allFindings) {
    $isFP = $false

    switch ($finding.Type) {

        "Hidden Process" {
            foreach ($proc in $Global_FP_Processes) {
                if ($finding.Details -match $proc) { $isFP = $true; break }
            }
        }

        "PendingFileRenameOperations" {
            foreach ($path in $Global_FP_Renames) {
                if ($finding.Details -match [regex]::Escape($path)) { $isFP = $true; break }
            }
        }

        # Check COM Hijacking, Cloaked Files, and High Entropy against trusted paths
        { $_ -in "COM Hijacking", "Cloaked File", "High Entropy File" } {
            $targetPath = if ($finding.Target) { $finding.Target } else { $finding.Details }
            foreach ($path in $Global_FP_Paths) {
                if ($targetPath -match [regex]::Escape($path)) { $isFP = $true; break }
            }
        }

        "Alternate Data Stream" {
            if ($finding.Details -match "Zone\.Identifier") { $isFP = $true }
        }
    }

    if (-not $isFP) {
        $actionableFindings.Add($finding)
    }
}

# =============================================================================
# 4. TRIAGE & OUTPUT
# =============================================================================

$fpCount = $allFindings.Count - $actionableFindings.Count
Write-Host "[+] Baseline Tuning Complete. Filtered out $fpCount normal OS/App events." -ForegroundColor Green
Write-Host "==================================================================="

if ($actionableFindings.Count -eq 0) {
    Write-Host "[+] ZERO ACTIONABLE FINDINGS. Fleet baseline is clean." -ForegroundColor Green
    exit
}

Write-Host "[!] ACTIONABLE FINDINGS: $($actionableFindings.Count)" -ForegroundColor Red

# Quick Console Summary
$actionableFindings | Group-Object Severity | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
$actionableFindings | Group-Object Type | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize

if ($ShowGrid) {
    Write-Host "[*] Launching interactive triage grid..." -ForegroundColor Gray
    $actionableFindings | Out-GridView -Title "Actionable EDR Alerts (Tuned)"
}

if ($ExportCSV) {
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $outPath = ".\Fleet_Actionable_Alerts_$timestamp.csv"
    $actionableFindings | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "[+] Actionable alerts exported to: $outPath" -ForegroundColor Green
}

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcm6V7lMVmLLWP
# aSWrWrkEUUwU22czUNCWB56g9XiQLaCCFrQwggN2MIICXqADAgECAhBj3Isegven
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgwUlJIu9h9BXPyC8jpXbc77TgqDi49mWk
# SqqIc/mudIwwDQYJKoZIhvcNAQEBBQAEggEAJSSFItbMq/0YgVUZBifSEAwlBGg1
# yGpM0eNghspDHar19es3b4AhceWP6AGqptpPXAxoiOp1SKA7JIiysiAO4vEgn+iv
# 12Z8n3VSsHMWtMJCN/rR63XINt2pKo8DF924VpsZ6F76ZWpyoAR/rxP3rt9G85Nb
# 36UfBmoJxqzxgaf18pR5Owxmq1/5rUAzdoRCuE8ll40ihkftuC65mnAs+FVjCfSx
# Ocdp6b9b3N6XBICx9/F8f0wvuzeEZBWLU1GYa+moovqED+dZXiNmUScfLy+deXLA
# X0LD7nKXtnHD3G52uMqHki3s8V/O9G3nRcdleJJCD1/t+DJU43iaiTqD7aGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjMxNDI3MTNaMC8GCSqGSIb3DQEJBDEi
# BCD3qsFz+Q7mZzg2qGPQZFJFJeShG98g371TcnmWdsCrhjANBgkqhkiG9w0BAQEF
# AASCAgBQbv6m6koxredY+CJIsatCgpDBY3V/8wffNWwTvLKZGJscTTjVD/DgZ0Kj
# g35EQojWgUQkrHbaH74JzP2gMSLg+k38CcdXmdzSDku2n/tJA9YvOCwatU4apDCK
# gt2lPyU1vR/5L5iEc3dbKtB3U2lm1LTv5u+QmL38FRso6fGamPsrJTlq3OinhqyT
# haJVPKeMdiWiCT8nlrQ1tlozin79OxGDxYmC08x9V4IFvqAVZrsiKWYQAeivUpUG
# dwGthgMXOu+GLDVvMKme7BQLDmGGHywpGij0gRI0qpAOPWLW85dDZaOe3lxle/cU
# yVCzDfJiGU2Mm+MDvbG6aJb5a7JmdagYc/AHUclhKucyziKB0RDWA8faKqJr59m5
# K1Ed+//brvfFPzLxKPqhBUthmDjR9ixyOW9dzR94yXwquEGMbQXYMnoY0AgapQvQ
# mUbSlC8np4d/d62WQyAHWTilmxSLBL9WpGNy00+bCHUqpcZk23ea+1Y0aHfRlWVc
# 5i4kD+SV7Sgn8BIToKd0P7455hn3zbnnVX3zkbOGynxqXsbeCBF/TAeOj6haweRx
# 6FRrSW363x5fFqIRRchekkap7bzk772HNRSKzm4TYLpBcX0P6fHbXoc5B0FtKzQ0
# iCxnvjYvZuRDsBXXDpO0r1Vr5LEqU2mbz9iXLthuWu+W2jPucQ==
# SIG # End signature block
