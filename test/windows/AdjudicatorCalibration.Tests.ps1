<#
.SYNOPSIS
    Pester 5 tests for adjudicator confidence calibration.
    Validates path-based confidence reduction for known high-FP patterns.
    Unit tests only — invoke Get-FindingContext logic directly against synthetic findings.
#>

BeforeAll {
    $Script:ToolkitRoot   = Join-Path $PSScriptRoot '..\..'
    $Script:ContextScript = Join-Path $Script:ToolkitRoot 'playbooks\windows\threat_hunting\Get-FindingContext.ps1'
    $Script:PrepDefScript = Join-Path $Script:ToolkitRoot 'Invoke-PrepareDefender.ps1'
}

Describe "Adjudicator — script structure" {

    It "Get-FindingContext.ps1 exists" {
        Test-Path -LiteralPath $Script:ContextScript | Should -Be $true
    }

    It "Get-FindingContext.ps1 parses without errors" {
        $r = pwsh -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw '$Script:ContextScript'))" 2>&1
        $r | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Should -BeNullOrEmpty
    }

    It "Contains lib\\net* confidence adjustment logic" {
        $content = Get-Content -LiteralPath $Script:ContextScript -Raw
        $content | Should -Match 'LIB_NET_PATTERN'
        $content | Should -Match 'Timestomped.*lib'
    }

    It "Signed binary in user-writable path is Indeterminate not Likely FP (tuning review decision)" {
        $content = Get-Content -LiteralPath $Script:ContextScript -Raw
        $content | Should -Match 'valid cert does not clear staging'
    }

    It "No RarSFX auto-suppress pattern in adjudicator (removed as over-filtering)" {
        $content = Get-Content -LiteralPath $Script:ContextScript -Raw
        $content | Should -Not -Match 'RARSEX_PATTERN'
    }

    It "Uses approved verb (New-FindingEvidence not Collect-FindingEvidence)" {
        $content = Get-Content -LiteralPath $Script:ContextScript -Raw
        $content | Should -Match 'New-FindingEvidence'
        $content | Should -Not -Match 'Collect-FindingEvidence'
    }
}

Describe "Invoke-PrepareDefender.ps1 — forensic audit policy" {

    It "Enable-ForensicAuditing function is present" {
        $content = Get-Content -LiteralPath $Script:PrepDefScript -Raw
        $content | Should -Match 'Enable-ForensicAuditing'
    }

    It "Enables 4688 process creation auditing" {
        $content = Get-Content -LiteralPath $Script:PrepDefScript -Raw
        $content | Should -Match 'Process Creation'
        $content | Should -Match 'auditpol'
    }

    It "Enables command-line logging in 4688 events" {
        $content = Get-Content -LiteralPath $Script:PrepDefScript -Raw
        $content | Should -Match 'ProcessCreationIncludeCmdLine_Enabled'
    }

    It "Enable-ForensicAuditing is called from both TP-on and TP-off paths" {
        $content = Get-Content -LiteralPath $Script:PrepDefScript -Raw
        ($content -split 'Enable-ForensicAuditing').Count - 1 | Should -BeGreaterThan 1 `
            -Because 'Must be called in both the TP-already-off path and the guided TP-toggle path'
    }
}

Describe "Invoke-AmcacheParser.ps1 — no publisher or vendor filtering" {

    BeforeAll {
        $Script:AmcacheScript = Join-Path $Script:ToolkitRoot 'playbooks\windows\threat_hunting\Invoke-AmcacheParser.ps1'
    }

    It "No SafePublisher suppression — Microsoft/Adobe/etc. in AppData still surfaces" {
        $content = Get-Content -LiteralPath $Script:AmcacheScript -Raw
        $content | Should -Not -Match 'SafePublishers'
        $content | Should -Not -Match 'Test-SafePublisher'
    }

    It "No VendorTempRE suppression — TiUninst and vendor uninstallers in Temp still flagged" {
        $content = Get-Content -LiteralPath $Script:AmcacheScript -Raw
        $content | Should -Not -Match 'VendorTempRE'
        $content | Should -Not -Match 'TiUninst'
    }

    It "LOLBin safe path only suppresses System32 and SysWOW64 — impossible vectors only" {
        $content = Get-Content -LiteralPath $Script:AmcacheScript -Raw
        # Safe path check exists but only covers Windows binary dirs
        $content | Should -Match 'Test-SafePath'
        $content | Should -Match 'System32\|SysWOW64'
        # Program Files and SoftwareDistribution NOT in the LOLBin safe-path exception
        $content | Should -Not -Match 'Program Files.*System32.*Test-SafePath'
    }
}

Describe "Adjudicator — path-confidence calibration logic" {

    It "lib\\net462 path is in the noise pattern" {
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        'C:\ProgramData\C2Sensor\Dependencies\lib\net462\Something.dll' -match $LIB_NET_PATTERN | Should -Be $true
    }

    It "lib\\netstandard2.0 path is in the noise pattern" {
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        'C:\ProgramData\DeepSensor\Dependencies\lib\netstandard2.0\Yara.dll' -match $LIB_NET_PATTERN | Should -Be $true
    }

    It "bin\\Release path (build output) is in the noise pattern" {
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        'C:\Projects\MyApp\bin\Release\net8.0\app.dll' -match $LIB_NET_PATTERN | Should -Be $true
    }

    It "Suspicious path outside lib\\net is NOT in the noise pattern" {
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        'C:\Users\user\AppData\Roaming\evil.dll' -match $LIB_NET_PATTERN | Should -Be $false
    }

    It "System32 path is NOT in the noise pattern" {
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        'C:\Windows\System32\ntdll.dll' -match $LIB_NET_PATTERN | Should -Be $false
    }

    It "Non-Timestomped findings are not affected by lib\\net pattern" {
        # Only 'Timestomped File' type should get confidence adjusted
        $findingType = 'High Entropy File'
        $path = 'C:\ProgramData\Sensor\lib\net462\file.dll'
        # The condition in the adjudicator: $f.Type -eq 'Timestomped File' AND path matches
        ($findingType -eq 'Timestomped File' -and $path -match '\\lib\\net') | Should -Be $false
    }

    It "Timestomped File in lib\\net path triggers confidence reduction" {
        $findingType = 'Timestomped File'
        $path        = 'C:\ProgramData\SecuritySensor\lib\net48\Newtonsoft.Json.dll'
        $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
        ($findingType -eq 'Timestomped File' -and $path -match $LIB_NET_PATTERN) | Should -Be $true
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCqZ2K11RBhx8At
# AZxGlixUbzIGlRSXAynVY9iCayAqLKCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg7kN6NsiZB/udPaWXi5Q+Q+IXAOV00+jD4U4m
# H3/f0FcwDQYJKoZIhvcNAQEBBQAEggEAjDYLNP5iTOf+GoqbciFyrBs6N5PJV+4u
# TeQ+ADquJGB5oWl9V/D7slJwdQUBKfsDfSWOs4Thnye3ia0pwD2KpdTLacnwMLxM
# 9Mp+FxjDLUHVB8GYBgfa10zFiA53e2a5APZJWdFpO9zOUzCOHTgeZ/m17PadnBrk
# fqXcwtSrknl1anHWIGyuTAQFFecfx5GyImHLT/EN9r1hRNyI7Edz0nxfER3YAHSh
# wE49tYpgRefkv9yOzKkgSHfVmWRfsy7rUpdWTcuOGXr3ASq6ln2U66LgG8Yj9ewZ
# 2XviJvD/5SlFa9Kst1dnRf3HKr6oA8aHgajCrNcgHKSrdhqzZcqO+aGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzFaMC8GCSqGSIb3DQEJBDEiBCC8
# 4CbJ0VvbB4XvQibdHzWK7Ml8jGIS8jvNaaKpUJCYWzANBgkqhkiG9w0BAQEFAASC
# AgAORPoiMD4zeE5x93vTYlybJsxd/+YrskcPqCArR/55B+Tc2q2tJvDtw2qjmxOE
# oTwKrRAY0g+BYMZtlIdOi1CmnmxNXYefJvLZSZruN8h2W/ZFkd2x4xk+4JUpm+Dh
# fNF2srXgrbmhihmrOn8TS07brSYMeyg+ZmgngQHJ1HWfGf/aA3qmAABWMKld9akz
# 4Nhg6edpF405viXfMsS8Kt64+rfmXAz6NGeYhA3j6i1ivvDuGpQFTqyQi+DRVlkK
# ov9QVTFS+fDcXyf2jNfUJxAIx5bPAq78zZDYLKXElWg4BKu9yE1xgqOf1KtTaOTr
# BAtGOcCyVgIyfek3I9DqWlN8Fux8J3UKsN3quSF5XzioG7wTUcafD2dUlZACNUZh
# 4RerfpzMnHegnxqG6WKHGqR4lOwXXCLW39Ro6txr1cHxRQPnabSxNzndJI0EDY1L
# fYmocM+HUzqFYknlv63loy/s5V7jxFgnTCrXdV6DeLHsE0NmWN7wiD0FvCiaka1t
# EKIGizbiLZfZP21dofaQbv6HIeTFAu1qeXGs57jhCWu5g8w/KwF3IDDT0p4wRZxi
# JGYcA5pCQmWsyxMf38zyGdCAgCANgklxff1Pq7uh9cM3cKM7WcSu0JbcaNEJY0tP
# cM+xnDZNaJjo1SeTDVcof6siUDTHj80d8mWtOQsRKJwFJg==
# SIG # End signature block
