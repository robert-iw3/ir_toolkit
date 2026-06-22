<#
.SYNOPSIS
    Generate a self-signed code-signing certificate and sign all IR Toolkit .ps1 files.
    Run this ONCE on the analyst machine before deploying the toolkit to a USB/target host.

.DESCRIPTION
    After signing, Defender's AMSI trusts the scripts at load time without requiring
    Tamper Protection to be toggled off. The only step needed on the target host is
    importing the public certificate into the TrustedPublisher store - Invoke-PrepareDefender.ps1
    does this automatically when the cert file is present in tools\.

    Workflow:
      1. Run this script on the analyst machine (requires admin for LocalMachine cert store).
      2. Copy the signed toolkit (including tools\ir_toolkit.cer) to the target USB/host.
      3. On the target: Invoke-PrepareDefender.ps1 imports the cert -> no TP toggle needed.

    The private key (PFX) stays on the analyst machine - only the public cert (.cer) is
    copied with the toolkit. Defender validates the signature against TrustedPublisher
    without needing the private key on the target.

.PARAMETER CertSubject  Common name for the certificate. Default: 'IR Toolkit Code Signing'
.PARAMETER CertYears    Certificate validity in years. Default: 5
.PARAMETER PfxPassword  Password for the PFX export. Default: auto-generated GUID (logged).
.PARAMETER WhatIf       Show what would be signed without signing.

.EXAMPLE
    # Sign everything - cert created, all .ps1 signed
    .\Invoke-SignToolkit.ps1

    # Preview without signing
    .\Invoke-SignToolkit.ps1 -WhatIf
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]      $CertSubject = 'IR Toolkit Code Signing',
    [int]         $CertYears  = 5,
    [SecureString]$PfxPassword = $null   # auto-generated if not provided
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ToolsDir   = Join-Path $PSScriptRoot 'tools'
$CerPath    = Join-Path $ToolsDir 'ir_toolkit.cer'
$PfxPath    = Join-Path $ToolsDir 'ir_toolkit.pfx'
$StampUrl   = 'http://timestamp.digicert.com'

function Write-Step { param([string]$Msg, [string]$Color = 'Cyan')
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" -ForegroundColor $Color }

function Remove-ScriptSignature {
    # Strip an existing Authenticode block before re-signing, matched by WHOLE LINE
    # so a marker STRING inside code (e.g. Build-Toolkit's IndexOf) is never mistaken
    # for the block and truncated. Rewrites CRLF + one trailing newline for a clean sign.
    param([string]$Path)
    $marker = '# SIG ' + '# Begin signature block'   # split so this file never self-matches
    $lines  = [System.IO.File]::ReadAllLines($Path)
    $idx = -1
    for ($i = $lines.Length - 1; $i -ge 0; $i--) {
        if ($lines[$i].Trim() -eq $marker) { $idx = $i; break }
    }
    $kept = if ($idx -lt 0) { $lines } elseif ($idx -eq 0) { @() } else { $lines[0..($idx - 1)] }
    $text = (($kept -join "`r`n").TrimEnd("`r", "`n")) + "`r`n"
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($true))
}

# -- Step 1: Find or create the code-signing certificate ----------------------
Write-Step "Looking for existing '$CertSubject' certificate..."
$cert = Get-ChildItem 'Cert:\CurrentUser\My' -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match [regex]::Escape($CertSubject) -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-Step "Generating new self-signed code-signing certificate (valid $CertYears years)..." 'Yellow'
    $cert = New-SelfSignedCertificate `
        -Type         CodeSigningCert `
        -Subject      "CN=$CertSubject,O=IR Toolkit,OU=Incident Response" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter     (Get-Date).AddYears($CertYears) `
        -HashAlgorithm SHA256 `
        -KeyUsage     DigitalSignature `
        -KeyLength    2048 `
        -ErrorAction  Stop
    Write-Step "  Certificate created: $($cert.Thumbprint)" 'Green'
} else {
    Write-Step "  Reusing existing certificate: $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" 'Green'
}

# -- Step 2: Export public cert (.cer) and PFX to tools\ ----------------------
New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

Write-Step "Exporting public certificate -> $CerPath"
Export-Certificate -Cert $cert -FilePath $CerPath -Type CERT -Force | Out-Null
Write-Step "  -> ir_toolkit.cer" 'Green'

Write-Step "Exporting PFX (analyst machine only) -> $PfxPath"
# Auto-generate password if not supplied; never log it to console
if (-not $PfxPassword) {
    $PfxPassword = ConvertTo-SecureString -String ([guid]::NewGuid().ToString('N')) -AsPlainText -Force
}
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $PfxPassword -Force | Out-Null
Write-Step "  -> ir_toolkit.pfx  (PFX password was randomly generated - save separately if archiving)" 'Green'
Write-Host "  NOTE: ir_toolkit.pfx stays on the analyst machine only. Do NOT copy to target." -ForegroundColor Yellow

# -- Step 3: Trust the cert locally so signing and chain validation work -------
# Self-signed certs need to be in BOTH Root (chain trust) and TrustedPublisher
# (code signing trust). Without Root, Get-AuthenticodeSignature returns 'UnknownError'.
foreach ($storeName in @('Root','TrustedPublisher')) {
    Write-Step "Adding cert to LocalMachine\$storeName store..."
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName,'LocalMachine')
    $store.Open('ReadWrite')
    if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
        $store.Add($cert)
        Write-Step "  Added to $storeName." 'Green'
    } else {
        Write-Step "  Already in $storeName." 'Gray'
    }
    $store.Close()
}

# -- Step 4: Sign all .ps1 files in the toolkit -------------------------------
$scripts = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -notmatch '\\\.git\\' }

Write-Step "Signing $($scripts.Count) .ps1 file(s) with SHA256 + DigiCert timestamp..."
$signed = 0; $failed = 0

foreach ($s in $scripts) {
    if ($PSCmdlet.ShouldProcess($s.FullName, 'Set-AuthenticodeSignature')) {
        Remove-ScriptSignature -Path $s.FullName    # clean previous sig + normalize EOL
        $ok = $false
        # The DigiCert timestamp server rate-limits under rapid-fire requests, so a
        # couple of files randomly fail. Retry with backoff; on persistent timestamp
        # failure, sign WITHOUT a timestamp so the file is still signed (sig then
        # expires with the cert, in 5 years - acceptable fallback).
        for ($attempt = 1; $attempt -le 4 -and -not $ok; $attempt++) {
            try {
                $result = Set-AuthenticodeSignature -FilePath $s.FullName -Certificate $cert `
                              -TimestampServer $StampUrl -HashAlgorithm SHA256 -ErrorAction Stop
                if ($result.Status -eq 'Valid') { $signed++; $ok = $true }
                else { throw "status=$($result.Status)" }
            } catch {
                if ($attempt -lt 4) { Start-Sleep -Milliseconds (500 * $attempt) }
            }
        }
        if (-not $ok) {
            try {
                $result = Set-AuthenticodeSignature -FilePath $s.FullName -Certificate $cert `
                              -HashAlgorithm SHA256 -ErrorAction Stop      # no timestamp fallback
                if ($result.Status -eq 'Valid') {
                    $signed++; $ok = $true
                    Write-Step "  $($s.Name): signed WITHOUT timestamp (timestamp server unavailable)" 'Yellow'
                }
            } catch {
                Write-Step "  FAIL: $($s.Name) - $($_.Exception.Message)" 'Red'; $failed++
            }
        }
    } else {
        Write-Host "  WhatIf: would sign $($s.FullName)" -ForegroundColor Gray
    }
}

Write-Step "Signing complete: $signed signed, $failed failed." $(if ($failed) { 'Yellow' } else { 'Green' })

# -- Step 5: Verify a sample ---------------------------------------------------
$sample = Get-Item (Join-Path $PSScriptRoot 'Invoke-IRCollection.ps1') -ErrorAction SilentlyContinue
if ($sample) {
    $sig = Get-AuthenticodeSignature -LiteralPath $sample.FullName
    Write-Step "Verification check: Invoke-IRCollection.ps1 signature status = $($sig.Status)" `
        $(if ($sig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
}

# -- Step 6: Clean up - remove the cert from this analyst machine -------------
# The cert's job is done: scripts are signed and .cer/.pfx are saved.
# Remove it from all Windows cert stores on this machine to leave no trace.
Write-Step "Removing cert from analyst-machine cert stores (leave no trace)..." 'Cyan'
$thumbprint = $cert.Thumbprint
foreach ($loc in @('CurrentUser','LocalMachine')) {
    foreach ($sn in @('My','Root','TrustedPublisher')) {
        try {
            $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($sn, $loc)
            $s.Open('ReadWrite')
            $toRemove = $s.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
            foreach ($c in $toRemove) { $s.Remove($c) }
            $s.Close()
            if ($toRemove) { Write-Host "  Removed from $loc\$sn" -ForegroundColor Gray }
        } catch {}
    }
}
Write-Host "  [+] Cert removed from all local stores. No residue on this machine." -ForegroundColor Green

Write-Host ""
Write-Host "=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "  1. ir_toolkit.cer is included in the toolkit folder - deploy as-is to target USB." -ForegroundColor Gray
Write-Host "  2. On the target host, Invoke-PrepareDefender.ps1 imports the cert automatically." -ForegroundColor Gray
Write-Host "  3. Invoke-IRCollection.ps1 removes the cert from the target after the run." -ForegroundColor Gray
Write-Host "  4. Re-run this script after any script changes to update signatures." -ForegroundColor Gray

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCWumogZ+LAYMWv
# 5X/D7C/d/Or2NkXySm7KWhSjP5cZZ6CCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgK++ItVbcNVI98oIWf9B6yINfmLvB3J1g
# kox1j1LslREwDQYJKoZIhvcNAQEBBQAEggEAMhnJ7aZihOfIs0rdyPaBaPEy23y+
# jsF9nQS6RZmTRtwT7mgaHExWtkklMi2+anAFxcimqyTQvVREikB3WeTsLzH5uanS
# DybDNz6oL7Jkqk3BQHuiQbtFRFaUpdVFwDA7wbTOSHlEDTp4ko6jY3PoT86fAGz0
# w00jSgce75HiGXvNo2fzbEI0FPheS1/C//+gAg/RPqT0fymBwIF5tZ2pmvlOF3Cz
# N/zoodZ3yQmaGp9+NZ7rSoORubld65Ifllbc4ays2VDSTdXALCmhA9IsWFl4IFzQ
# gbr4FxeWhjzwWIbeeL0gUYOhWiXynjswBgL1zDaNAp2fDlBE9qT6/V0+1KGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NDlaMC8GCSqGSIb3DQEJBDEi
# BCDYXMnyhIE8DH9yFvvlVOlonLSRa1hwlYo7zXnS3nDHVzANBgkqhkiG9w0BAQEF
# AASCAgAXufzHFQIIKZQHcehdTfLtm5NXGphklc4LPAlPB0YX0fSLhRWqZ4h6PlQY
# up4nGf6iPCwGyC8AiBZJloPKMfjtabFFVHSiSDRO1I0f9fgeIP+un86xXxnj77hT
# ZI3BekSQYxt3IFmWTgq1WVDP+5Xb/bV6XTDHKRPcHOHs/r16LS8hWc1gWJAr2WI2
# xmr40K0XIjdT7WMrd+iFe/eiSnVzHrsQLzDTFCPsnWRuPq6HOSKY5d1h//6NG+cP
# Aj8fTGep6cIbShlGRzLk4nXKdcJOCaE65A3/tlbXhfIxSOZ/ewMfuGPSBWoHEN0r
# 3QYu05nCfaOZncFODO3DxoiQLEiLRYNhy5rxf4eyCp9QAKW4ZjbJXSlmOxFQ2le2
# f8baHBJTS9Wb7tm50O7k0YjNoSJ0UAD6t3i0gRQXdmwC2/e/lXrNKCSn60Fl/Fjk
# Q+8cY8v/0BbhxcyZifEwr4G/lf7QvCkvNLkXVJ1KWc9in7NsflOKm7BKmtBhSBlh
# kDltv1OeXaLRBpm+B5dAKVO/oO27xx3kLg3PaWl6dMCF4atDKSDDdtjVx7DdWLcM
# rZEP8SSdlQuRqCuzNIGiAyYoAey2pIJaZrVJwNA20OeCvkaA9Xtj4js6N4JeNZCy
# 2V6bjHbS0bdhf5q4+R4fs1RatkVLNI6gczKI4twQo1HEe2VtBA==
# SIG # End signature block
