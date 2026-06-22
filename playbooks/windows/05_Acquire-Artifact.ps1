# ==============================================================================
# IR Playbook 05 - Windows Artifact Acquisition
# Delivered to the endpoint over WinRM (ssh_playbook_v1). Given a confirmed-TP file
# path, it ACQUIRES the file for detonation: hashes it (chain of custody), zips it
# for safe transport, writes a manifest, and uploads to the quarantine bucket.
# It NEVER executes the sample. Mirrors det_chamber/agents/acquire_core.py.
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputDir     = '',
    [string]$IncidentId    = '',
    [string]$TargetPath    = '',
    [string]$HostName      = '',
    [string]$QuarantineUri = '',
    [long]$MaxSizeBytes    = 104857600   # 100 MB
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # was 'Stop' - changed to match orchestrator standard

if (-not $IncidentId)    { $IncidentId    = ($env:IR_INCIDENT_ID -replace '[^\w\-]','') }
if (-not $IncidentId)    { $IncidentId    = 'UNKNOWN' }
if (-not $TargetPath)    { $TargetPath    = $env:IR_TARGET_PATH }
if (-not $HostName)      { $HostName      = if ($env:IR_HOST) { $env:IR_HOST } else { $env:COMPUTERNAME } }
if (-not $QuarantineUri) { $QuarantineUri = $env:IR_QUARANTINE_URI }
if ($MaxSizeBytes -eq 104857600 -and $env:IR_MAX_ACQUIRE_BYTES) { $MaxSizeBytes = [long]$env:IR_MAX_ACQUIRE_BYTES }

$IRDir   = if ($OutputDir) { $OutputDir } else { 'C:\ProgramData\IRToolkit' }
$WorkDir = Join-Path $IRDir "Acquire\$IncidentId"

function Deny([string]$Msg) { Write-Error "ACQUIRE-REFUSED: $Msg"; exit 2 }

# -- Path safety: refuse OS-critical files, traversal, wildcards ---------------
$Deny = @('\windows\system32\config\', '\windows\ntds\', 'ntds.dit',
          '\windows\system32\lsass', 'pagefile.sys', '\system32\sam')
if (-not $TargetPath)                 { Deny "no target path" }
if ($TargetPath -match '[\*\?]')      { Deny "wildcard not allowed" }
if ($TargetPath -match '\.\.')        { Deny "path traversal not allowed" }
$Real = (Resolve-Path -LiteralPath $TargetPath -ErrorAction SilentlyContinue)
if (-not $Real) { Deny "not found: $TargetPath" }
$RealLower = $Real.Path.ToLower()
foreach ($d in $Deny) { if ($RealLower.Contains($d)) { Deny "OS-critical path $d" } }
if (-not (Test-Path -LiteralPath $Real.Path -PathType Leaf)) { Deny "not a regular file" }

# -- Size cap ------------------------------------------------------------------
$Item = Get-Item -LiteralPath $Real.Path
if ($Item.Length -gt $MaxSize) { Deny "file exceeds size cap ($($Item.Length) > $MaxSize)" }

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$FileName = $Item.Name
$Sha256   = (Get-FileHash -LiteralPath $Real.Path -Algorithm SHA256).Hash.ToLower()

# -- Package (zip) for safe transport - read/copied, never run -----------------
$Artifact = Join-Path $WorkDir "$FileName.zip"
Compress-Archive -LiteralPath $Real.Path -DestinationPath $Artifact -Force

# -- Manifest (chain-of-custody record the intake service verifies) ------------
$Manifest = Join-Path $WorkDir 'manifest.json'
[ordered]@{
    incident_id = $IncidentId
    host        = $HostName
    src_path    = $Real.Path
    filename    = $FileName
    sha256      = $Sha256
    size        = $Item.Length
    os_family   = 'windows'
    acquired_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
} | ConvertTo-Json | Out-File -FilePath $Manifest -Encoding UTF8

# -- Upload to the quarantine bucket (if configured) ---------------------------
if ($QuarantineUri -and (Get-Command aws -ErrorAction SilentlyContinue)) {
    aws s3 cp $Artifact "$QuarantineUri/$IncidentId/$FileName.zip" --only-show-errors
    aws s3 cp $Manifest "$QuarantineUri/$IncidentId/manifest.json" --only-show-errors
}

Write-Output "ACQUIRE-OK: $Artifact sha256=$Sha256 size=$($Item.Length)"

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAyTqFdhDEiaqzp
# 1rp++75r6LwJ0y6StkFJLeyu4cWHuqCCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgoxsemWH7PPp/vqQ58Z99xLjsUKbGjoZO
# QcHvGT+mE1wwDQYJKoZIhvcNAQEBBQAEggEAeZfqgiq71ks/wbNGUmQljHqIVVvg
# mi6IgcSfzAaTIZpJZhYffI1xEVehDlzQhMwS3OsF6tqhD3zejof/N6yVCqsEAQDm
# 1oKuMhng88I9U0FUKdGKClEr6RhbSx8vqGOgS5sRHOuRoLO3vVcY+SDWKxyajiOY
# 4fT7EUg+W98SJldyIHTqSKAdn/PkUlqw8lIiQV1i5ayBsxZR2f3Fg75YcyKdyiVI
# LJ3g3Wt9e10kDsyWwGoqCzIWXFhGnAs1Kp8xRTcEJwYJo+bBsL4QAbW4uz/9VfqY
# wsWwLJpMlMKmhibkcTSdA9wWhrkRfZcovvmycPLybTtA3mX8U6bwb3rObqGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NTJaMC8GCSqGSIb3DQEJBDEi
# BCAL7o+sTALUA0s3xXgIr4fWME6R2qxtZMXlM9eQsxPlZjANBgkqhkiG9w0BAQEF
# AASCAgDOnHQIVmZsaQ++bKqre1KeyWpIKxIGv2poRL4+bpxu11nPm5kUkgXQ0ERM
# 90iUgPqd+4Hgc4fhaUC/5xR0xCu9VccL4pQkf2Ks1p8RW7dGBDzGA8OVQmUGkZdA
# tWZO9U9phTjmg90i3JgwbwBQwwifoToOGEijK9e1srmDpj5Z9u3zBMN/ekIBCJeg
# 1WHPaYn70gA4cTKBx1iQeSL9t1/ft84tT4hTLlaUKcyHlRAfIshsFUPwWmzTJL1i
# /V2bhjoA1X4ZXBypDElsBixGF7kUJxUdXWWsatFtjLY10qcrlFpcvMupjxG1RA6w
# gUMcEmjr8KgoeywqYRdAz6uhThL/Ls74PTyasmF8gYoZlN7hNuvV+7rCpPSCA9wc
# WG8A0xxLeClQOiw2eG1ds0X+TVxmB1rqZ4yXMbKDYgD/C5U6eJaZRPC7gq6i5E8L
# xxcKHI8R2hdgpo31AEhlYigdRQ9UcjuY1G9NPJVoCqVVX0uTGKfIuhT8L966IZvC
# GoaJqVdIBeIgbkSaZHbQXM9oeK++J9RpWFGy/O1cC1ZxSx6q/oYyFDDTiWrGX7Op
# 4yY8zfSX7Lrt2Vw+6UmUuvNbm3FJhxUaCg7bAdWsvKGT4UkgXn8Zy7rbTUh4zj5v
# 47dy9GsbsJ0mXXdVjoZ4uzmf2QDBQv40p2ty8mWz/QDkM+cvfw==
# SIG # End signature block
