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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCWumogZ+LAYMWv
# 5X/D7C/d/Or2NkXySm7KWhSjP5cZZ6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgK++ItVbcNVI98oIWf9B6yINfmLvB3J1gkox1
# j1LslREwDQYJKoZIhvcNAQEBBQAEggEARF69bC9/uB300FZXuqsznaoQ295vymtS
# 4JSf6CrlKBjBEp4Dc0pZW5DgT3FirCasfcuseM7YsJuqEub+ME2r3D/i3XSv75QN
# fWv1xdKYfyksp9gOO6zkV3G6TcIFZ/1oYuIXoh5bDVJssHwMDo8xAKl1OGBvcMhB
# Ug7Hb1nPGfH/9euPQF0w65pZpz8eIpOCAv6FQvce2WSFpRVbd+TFoDxAIcLM1cKt
# oF10XtKD4SPqNCbjpKmQPwRagqMpFuMZuES/vYqtnlgAf8uWw+nDdGFWs3Ev82rj
# wHwTwynIDEAmIzTWI65sQDhA/iJB/LA8fwyVRZVzqFPa8GkFjDZByaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MTZaMC8GCSqGSIb3DQEJBDEiBCCU
# OH7XGQEQIaue9Bpudqq321Ji5sOz47CNmlPboJVXXjANBgkqhkiG9w0BAQEFAASC
# AgBBJcy+VTq7RHGSOkh8EAizBldS5bXYVd+jcWdj09gSMJuX6f6hlEyu5D3G4jPM
# rRYz3iEJVuI1GqhE9a1pVSpg8aEhuyOniV8MANn6wP5tBulTLtEX/rzr1/QRs9x1
# kJ7vfrxWtFj3e08Hi7txGeLiLOkIOUqyncu1yp85rUhD0BvqDIDt/PhPWsASoY3W
# PuEBvAeA3e73OlfOLFfx6u4gDKVR1v1xVMeyAIfNFAulNQykzxUcYjG+WYrXd8C4
# cb3Q4a1oIYYBsehFUMuXOQbNwcTpWUEiJPKW6Nz9lEgKkMFLMtK8VdAfMbLLji27
# KYBfWzsl0iCmUvYeXh/bkXyzneSLVm8J6TFtUIMmoCyzOtsCIB+D7dMKgTs1dzs8
# 9hL3Smgg2ubL1rZr5kb6/OzoTUSPZlqnbWRnJ3QoKnU7ah05dyDOL34ogIHFxbfp
# eLX1MA9ibGS1MBTRSPa+LQQAqwC8mbqgBIR11CIfBK8kuI1dluIlrbfs36b1e5nn
# 1RP34WWZQEE10WLOa58sHyTRB3Vy8lI7vBD9YbLVnr/D7ao9tlIEh9tdsl2WOevT
# 78CrseBu6wxiZD8Eeu8aHrcguQwwGLPz7rACaBMLRHhEGrPs1I5I8nEgPN7zuK8M
# TKY9N/muUNF1BTBiefbP1D9N62jEG+Gz4YujxQLIFcDoBQ==
# SIG # End signature block
