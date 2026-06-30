<#
.SYNOPSIS
    Pester 5 Tests for GAP-B01, GAP-E01, GAP-E02
    GAP-B01: BITS job URL and destination path inspection
    GAP-E01: ETW event log channel status (disabled/tiny max-size)
    GAP-E02: PendingRename entries targeting security tool paths
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "03_BITS_COM_ETW_AMSI.ps1")

    function script:Set-BITSBaselineMocks {
        Mock Get-BitsTransfer  { @() }
        Mock Test-Path         { $false }
        Mock Get-ItemProperty  { [PSCustomObject]@{} }
        Mock Get-ChildItem     { @() }
        Mock Get-WinEvent      { throw "channel not found" }
    }

    function script:New-FakeBitsJob {
        param([string]$Name, [string]$Url = '', [string]$Dest = '', [string]$State = 'Transferring')
        $fl = [PSCustomObject]@{ RemoteName = $Url; LocalName = $Dest }
        [PSCustomObject]@{
            DisplayName = $Name
            JobState    = $State
            FileList    = @($fl)
        }
    }
}

# ---------------------------------------------------------------------------
# GAP-B01: BITS URL / Destination inspection
# ---------------------------------------------------------------------------
Describe "GAP-B01 BITS Job Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-BITSBaselineMocks
    }

    It "Should flag a job with exe URL to staging path as High (behavior signal)" {
        # After refactor: name is irrelevant; executable-to-staging is the mechanism.
        Mock Get-BitsTransfer { @(New-FakeBitsJob -Name 'TotallyLegit' -Url 'http://example.com/payload.exe' -Dest 'C:\Users\Public\payload.exe') }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should flag a job downloading an .exe to TEMP as High regardless of display name" {
        Mock Get-BitsTransfer { @(New-FakeBitsJob -Name 'WindowsUpdate' -Url 'http://evil.com/payload.exe' -Dest 'C:\Windows\Temp\payload.exe') }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match 'SuspiciousURL|SuspiciousDestination'
    }

    It "Should flag a job with an IP-based URL as High" {
        Mock Get-BitsTransfer { @(New-FakeBitsJob -Name 'DataSync' -Url 'http://192.168.1.100/stage.dll' -Dest 'C:\Users\Public\stage.dll') }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
    }

    It "Should DOWNGRADE (not suppress) a job from a CDN to a protected path -- name is attacker-controlled" {
        # After refactor: CDN names (azureedge.net) are used for domain fronting.
        # Display name 'MicrosoftEdgeUpdate' is attacker-controlled. The behavior:
        # exe download to Program Files (not staging) = Medium (downgrade not suppress).
        Mock Get-BitsTransfer { @(New-FakeBitsJob -Name 'MicrosoftEdgeUpdate' -Url 'https://msedge.azureedge.net/packages/edge.exe' -Dest 'C:\Program Files\Edge\edge.exe') }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium' -Because "exe download from CDN but not to staging = downgraded, not suppressed"
    }

    It "Details field should contain URL and destination" {
        Mock Get-BitsTransfer { @(New-FakeBitsJob -Name 'BackdoorSync' -Url 'http://attacker.io/c2.ps1' -Dest 'C:\AppData\c2.ps1') }
        Invoke-BITSHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'Suspicious BITS Job' }
        $f[0].Details | Should -Match 'URL='
        $f[0].Details | Should -Match 'Dest='
    }
}

# ---------------------------------------------------------------------------
# GAP-E01: ETW Channel Status
# ---------------------------------------------------------------------------
Describe "GAP-E01 ETW Event Log Channel Status" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-BITSBaselineMocks
    }

    It "Should flag a disabled Security log channel as Critical" {
        Mock Get-WinEvent {
            [PSCustomObject]@{ IsEnabled = $false; MaximumSizeInBytes = 20971520 }
        } -ParameterFilter { $ListLog -eq 'Security' }
        Invoke-ETWAMSITamperHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'ETW Tampering' -and $_.Target -match 'Security' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
    }

    It "Should flag a Security log with max-size under 1MB as High (log rotation attack)" {
        Mock Get-WinEvent {
            [PSCustomObject]@{ IsEnabled = $true; MaximumSizeInBytes = 65536 }
        } -ParameterFilter { $ListLog -eq 'Security' }
        Invoke-ETWAMSITamperHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'ETW Tampering' -and $_.Target -match 'Security' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'High'
        $f[0].Details  | Should -Match 'KB'
    }

    It "Should NOT flag a Security log that is enabled with normal size" {
        Mock Get-WinEvent {
            [PSCustomObject]@{ IsEnabled = $true; MaximumSizeInBytes = 20971520 }
        } -ParameterFilter { $ListLog -eq 'Security' }
        Invoke-ETWAMSITamperHunt
        ($script:Findings | Where-Object { $_.Target -match 'Security' }) | Should -HaveCount 0
    }

    It "Should flag WER disabled as Medium" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Windows Error Reporting' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ Disabled = 1 }
        } -ParameterFilter { $Path -match 'Windows Error Reporting' }
        Invoke-ETWAMSITamperHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'ETW Tampering' -and $_.Target -match 'Windows Error Reporting' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Medium'
    }
}

# ---------------------------------------------------------------------------
# GAP-E02: PendingRename Security Tool Targeting
# ---------------------------------------------------------------------------
Describe "GAP-E02 PendingRename Security Tool Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
    }

    It "Should flag pending rename targeting MsMpEng as Critical" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Session Manager' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\Windows\System32\MsMpEng.exe', '\??\NUL') }
        } -ParameterFilter { $Path -match 'Session Manager' -and $Name -eq 'PendingFileRenameOperations' }
        Invoke-PendingRenameHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'PendingFileRenameOperations' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Details  | Should -Match 'MsMpEng'
    }

    It "Should flag pending rename targeting Sysmon as Critical" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Session Manager' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\Windows\Sysmon64.exe', '\??\NUL') }
        } -ParameterFilter { $Path -match 'Session Manager' -and $Name -eq 'PendingFileRenameOperations' }
        Invoke-PendingRenameHunt
        $f = $script:Findings | Where-Object { $_.Severity -eq 'Critical' }
        $f | Should -HaveCount 1
    }

    It "Should flag routine installer pending renames as Low (not Critical)" {
        Mock Test-Path { $true } -ParameterFilter { $Path -match 'Session Manager' }
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = @('\??\C:\Windows\Installer\tmp1234.tmp', '') }
        } -ParameterFilter { $Path -match 'Session Manager' -and $Name -eq 'PendingFileRenameOperations' }
        Invoke-PendingRenameHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'PendingFileRenameOperations' }
        $f | Should -HaveCount 1
        $f[0].Severity | Should -Be 'Low'
    }

    It "Should produce no finding when no PendingFileRenameOperations exist" {
        Mock Get-ItemProperty {
            [PSCustomObject]@{ PendingFileRenameOperations = $null }
        } -ParameterFilter { $Path -match 'Session Manager' -and $Name -eq 'PendingFileRenameOperations' }
        Invoke-PendingRenameHunt
        ($script:Findings | Where-Object { $_.Type -eq 'PendingFileRenameOperations' }) | Should -HaveCount 0
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiwTrbkKKOvy5O
# S2W6tydrdUYe4eK1qmftQEBMUpXYwqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQguEgqPd++BBHQQ5r2NHM7oWop3ieOEZ0Z/FNK
# pTEIGjMwDQYJKoZIhvcNAQEBBQAEggEAfkudTffy9op1b0d4aQs7rHNUDuVRYZUR
# CVSJi9UHOLd5ak1TBAfEky9VVWnXq8hICnAlyThWXm/+wXF6o5Wl0zO2N4lJ2eIX
# JHVNE9JueKMvGM3jfuCnHF5tpvO/atDXYPhueD9jM6Y0JVPS3G0+o+8YXiTXnlRp
# onUJ0Hczn88Yq/fCLG4xRG6hM133UFP3DZJ10M8qCKEF0ONg6f24K22fY4dML9pT
# PCqfqsptefYUhxaQOt3N8YVHr6N66ooMfJvGb2DlF8N1anUFP+f0GOyLlmUSjhKD
# kw1vYeGQG0gS2t+dZISVccsUxfhYlvSFaVow24wK4m7YCpS8CRGI96GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzJaMC8GCSqGSIb3DQEJBDEiBCAf
# j5jtWC6mit3p2zjkbE6lX3xnqlbr4UBULtA5ZELfXTANBgkqhkiG9w0BAQEFAASC
# AgAaC83dA2hcgvI/k6/1be7bTKFOvOX31xiJWgxsFqLzBS2hYVN7pmaiDB4Gw5WV
# EoiDIkS6IDZsZFz5YhVMFNFfA0Qqkh5Hnxqfwgpe0pa8cZVvPBWfw7O8udPpS8yQ
# 4yZHVeFl2YPjykwUxMCuC7hle+RcoBG1xAsrNd4FPdT7iz8CAjiR9PAn7cP3D0sS
# /BrXxYVTFUFtnoPJq+yVpF81APvJm5GCMuDJRnDieogSgqmNGEaic0oV/Jg3rZEV
# +2A2P3PAFAr3IlNekenS4hKu1LONuuvl1rNQeHvsEPpgQODAQ0A+QR2F29uyxtkd
# 3Q3vJUgf667d9Ur5hNNekwfcek1UAAgkIQaO+pmMDUx841t/FBLW2sjG17MBfHgn
# 4H8FOa42kizWibz6PDOMJWdoAMojlSzILhp3lyBjgQPz2CMBew9da0wuk2hopFzU
# 99MmKYs5IQEeYNFUdfeJeKPsgyLSYX/NoQRPYPbXmnheyL3JDBlFcn946PL4Va7F
# zmS5tRmp6n56VC5mz5Nuppy1nD37Gj/vNTRI3dq/sHq1Q9uZuvqMpqBO29SE/qL1
# gXQx1La58cCq/fOcsWDn0cqDgyznMaGM0sTDEhOxIHh+AEKLNbiZ3masnDN+TnjD
# uZaK2P4skJAi8t/lcoxa8GinybfN77ZiNTfr87rhU2D5Nw==
# SIG # End signature block
