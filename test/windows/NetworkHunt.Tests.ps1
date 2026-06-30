<#
.SYNOPSIS
    Pester 5 Tests for GAP-N01 - Invoke-NetworkHunt
    Covers: suspicious outbound connections, unexpected listeners, suspicious named pipes
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "06_Network.ps1")

    function script:New-FakeConn {
        param([string]$Remote, [int]$RemotePort, [int]$OwnerPid = 9001, [string]$State = 'Established')
        [PSCustomObject]@{
            RemoteAddress  = $Remote
            RemotePort     = $RemotePort
            LocalPort      = 54321
            OwningProcess  = $OwnerPid
            State          = $State
        }
    }
}

Describe "GAP-N01 Invoke-NetworkHunt" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Mock Get-CimInstance   { @() }
        # Default: no pipes. Never let a test hit the real \\.\pipe\ namespace.
        Mock Get-NamedPipeName { @() }
    }

    It "Should flag ESTABLISHED outbound to public IP on unusual port as suspicious" {
        $conn = New-FakeConn -Remote '1.2.3.4' -RemotePort 4444
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match '1\.2\.3\.4'
        $f[0].Details  | Should -Match '4444'
    }

    It "Should NOT flag ESTABLISHED outbound to public IP on port 443 (HTTPS)" {
        $conn = New-FakeConn -Remote '8.8.8.8' -RemotePort 443
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }) | Should -HaveCount 0
    }

    It "Should NOT flag ESTABLISHED outbound to private RFC1918 IP on any port" {
        $conn = New-FakeConn -Remote '192.168.1.100' -RemotePort 4444
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }) | Should -HaveCount 0
    }

    It "Should flag a listener on a non-standard privileged port (<1024) as High" {
        $listener = [PSCustomObject]@{
            LocalPort = 666; RemoteAddress = '0.0.0.0'; RemotePort = 0
            OwningProcess = 9002; State = 'Listen'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Listen') { @($listener) } else { @() }
        }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Unexpected Network Listener' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match '666'
    }

    It "Should DOWNGRADE a listener owned by a validly-signed process to Low (vendor/Windows FP)" {
        $listener = [PSCustomObject]@{
            LocalPort = 2179; RemoteAddress = '0.0.0.0'; RemotePort = 0
            OwningProcess = 2880; State = 'Listen'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Listen') { @($listener) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 2880; Name = 'vmms.exe'; ExecutablePath = 'C:\Windows\System32\vmms.exe' })
        }
        Mock Test-Path { $true }
        Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status = 'Valid' } }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Unexpected Network Listener' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'Low' -Because 'a validly-signed listener owner is likely a legit service'
    }

    It "Should KEEP a listener owned by an unsigned process at Medium/High" {
        $listener = [PSCustomObject]@{
            LocalPort = 8080; RemoteAddress = '0.0.0.0'; RemotePort = 0
            OwningProcess = 6666; State = 'Listen'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Listen') { @($listener) } else { @() }
        }
        Mock Get-CimInstance {
            @([PSCustomObject]@{ ProcessId = 6666; Name = 'backdoor.exe'; ExecutablePath = 'C:\Users\victim\AppData\Local\Temp\backdoor.exe' })
        }
        Mock Test-Path { $true }
        Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status = 'NotSigned' } }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Unexpected Network Listener' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'Medium'
    }

    It "Should NOT flag a listener on port 445 (expected Windows SMB)" {
        $listener = [PSCustomObject]@{
            LocalPort = 445; RemoteAddress = '0.0.0.0'; RemotePort = 0
            OwningProcess = 4; State = 'Listen'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Listen') { @($listener) } else { @() }
        }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Unexpected Network Listener' }) | Should -HaveCount 0
    }

    It "Should NOT flag a listener on ephemeral port 55000 (dynamic RPC)" {
        $listener = [PSCustomObject]@{
            LocalPort = 55000; RemoteAddress = '0.0.0.0'; RemotePort = 0
            OwningProcess = 4; State = 'Listen'
        }
        Mock Get-NetTCPConnection {
            if ($State -eq 'Listen') { @($listener) } else { @() }
        }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Unexpected Network Listener' }) | Should -HaveCount 0
    }

    It "Should flag a named pipe matching Cobalt Strike default pattern" {
        Mock Get-NamedPipeName { @('\\.\pipe\msagent_c2b3f1') }
        Mock Get-NetTCPConnection { @() }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match 'msagent'
    }

    It "Should flag a PsExec service pipe (PSEXESVC)" {
        Mock Get-NamedPipeName { @('\\.\pipe\PSEXESVC') }
        Mock Get-NetTCPConnection { @() }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }) | Should -HaveCount 1
    }

    It "Should NOT flag a benign named pipe like lsass or RpcSs" {
        Mock Get-NamedPipeName { @('\\.\pipe\lsass') }
        Mock Get-NetTCPConnection { @() }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }) | Should -HaveCount 0
    }

    It "Should NOT flag legitimate Chromium/Edge mojo IPC pipes (FP-storm regression)" {
        Mock Get-NamedPipeName {
            @('\\.\pipe\mojo.5832.8472.118490347713010101',
              '\\.\pipe\mojo.1234.5678.999',
              '\\.\pipe\crashpad_5832_ABCDEF')
        }
        Mock Get-NetTCPConnection { @() }
        Invoke-NetworkHunt
        ($script:Findings | Where-Object { $_.Type -eq 'Suspicious Named Pipe' }) | Should -HaveCount 0 `
            -Because 'mojo.* and crashpad_* are legitimate browser IPC and must not be flagged'
    }

    It "Should flag medium severity for public IP on non-well-known but non-RAT port" {
        $conn = New-FakeConn -Remote '203.0.113.5' -RemotePort 8181
        Mock Get-NetTCPConnection {
            if ($State -eq 'Established') { @($conn) } else { @() }
        }
        Invoke-NetworkHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious Outbound Connection' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -Be 'Medium'
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA84F9py+ndRX0L
# poUpD5drcnSg1dp65IRnUmSU3u9zt6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg345+UXboWz7COK5u+8K0r123mSvCKzXnr55L
# UgFSsUgwDQYJKoZIhvcNAQEBBQAEggEAcmp6NJIff1hEHAPsN47/Zjbz1Fx4+oz7
# qyfs5xrTDwg8fW88xRg5UYmxwHWkdIGl2CwmAoD8EZd/wbumE2xw6nJvk2wh8zMo
# T+9J1B5QJRNFNATcE+Y7JDjXpttJjj1lHm21iLbYbJj2qWlpu7zXXodT0zoibj42
# xwpHDhwfPR8OGujqkLo1aiJ4w3AdG3HtEAqwhqphXhsEFy+elAqdFfJZau03ekmU
# Jdn7myeiBOoEDa4xFxw8ULU4SRKL7dmp7tLUtbgffAiLNWWH/jHFforryWhfVdZj
# tEhPmGyCTw5KLcJ4XUMgomMXxyA5g08QtvW7nzKYNvuKgPMltQZeuaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3NDFaMC8GCSqGSIb3DQEJBDEiBCCj
# k1bia1CzQ85O5cdv6c8GsvQF37WUreV8wSYdIKCjbTANBgkqhkiG9w0BAQEFAASC
# AgC9nZjTutxO2/M5CHB+1q9ekZrydbwlgGqUpqGUvCNmgrsG/qoBOmT93PO3Qthx
# k0c7E6Ylzv9EDOdvgwgmyvv5gMs1tQT70JRhtFDkzftQbvB2crSgSYT/UNGl89gP
# y6xOoiL3YcBnydQJiHvV+i5YlAA42fS5AJQQpZAXw+0ieGmWIJxFDT8sGOeG8LbS
# vfFiCr+0pzdriH1xd484hjRlRveT/VbTJ8gjiRJkvQYPlRlu0FCYdSHEBzzry4Lz
# Gsn/02VEfqRuCckJzLrjsOhIOlQ+A20es/5Rkn+3f7hIDgdQRTbWge0CYHcVM07b
# ws+ojoKqQcHsbLsrnlft5wZ5pKHkn02+vb8Nzu0+v24tMj/dSQYf6L3Ya1084iZl
# z4EsnbExEiRFuReqCdXOuUJ5b/k/Tz/lc9gPeWpYshH+lfvfj+DJpBFbIbqPDUko
# G4EGlCkyHobWmazNw6ZoCV9z7M5/FbNcJlVeC5xMgwG1NsIjnFg8jufMCNdhWvtO
# YHerPsvePYyo36vfDMv9MHwernjg27nlDMjeFAQQMa4ULScaCyQ2DLKFma+whuWv
# QB8VGG4DlaUUT8cBZxlBS4OC4HByd2FsAX2nXjxT+8ems/DsJ+n1Fqfz2wBX6Egj
# Y1pgBjYC6PKIweEfzIMoN2p1l7cDO0uR1Rn0lFw+3M0PcA==
# SIG # End signature block
