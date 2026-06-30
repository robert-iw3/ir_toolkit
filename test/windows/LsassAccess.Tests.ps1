<#
.SYNOPSIS
    Pester 5 Tests for SEDR-002 - LSASS credential access detection
    Covers: comsvcs.dll MiniDump cmdline, dump file hunt, EID 4656/4663 event detection.
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "01_Process_And_Injection.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")

    $script:EvtScript = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\Invoke-EventLogAnalysis.ps1"
}

Describe "SEDR-002 comsvcs.dll MiniDump Process Detection" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet = $true
    }

    It "Should emit Critical finding when comsvcs MiniDump is detected" {
        Mock Get-Process {
            @( [PSCustomObject]@{ Id = 2001; ProcessName = "rundll32" } )
        }
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{ ProcessId = 4;    Name = "System";       ParentProcessId = 0;  CommandLine = "" },
                [PSCustomObject]@{ ProcessId = 2001; Name = "rundll32.exe"; ParentProcessId = 4;  CommandLine = 'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 624 C:\Users\Public\lsass.dmp full' }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "LSASS Memory Dump" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Target | Should -Match "PID: 2001"
        $Alert.Severity | Should -Be "Critical"
        $Alert.Details | Should -Match "comsvcs"
    }

    It "Should fire on comsvcs MiniDump regardless of case" {
        Mock Get-Process {
            @( [PSCustomObject]@{ Id = 2002; ProcessName = "rundll32" } )
        }
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{ ProcessId = 4;    Name = "System";       ParentProcessId = 0;  CommandLine = "" },
                [PSCustomObject]@{ ProcessId = 2002; Name = "rundll32.exe"; ParentProcessId = 4;  CommandLine = "RUNDLL32 COMSVCS.DLL,MINIDUMP 624 dump.dmp full" }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "LSASS Memory Dump" }
        $Alert | Should -Not -BeNullOrEmpty
        $Alert.Severity | Should -Be "Critical"
    }

    It "Should NOT flag rundll32 loading a legitimate DLL that is not comsvcs" {
        Mock Get-Process {
            @( [PSCustomObject]@{ Id = 2003; ProcessName = "rundll32" } )
        }
        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{ ProcessId = 4;    Name = "System";       ParentProcessId = 0;  CommandLine = "" },
                [PSCustomObject]@{ ProcessId = 2003; Name = "rundll32.exe"; ParentProcessId = 4;  CommandLine = "rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl" }
            )
        }

        Invoke-ProcessHunt

        $Alert = $script:Findings | Where-Object { $_.Type -eq "LSASS Memory Dump" }
        $Alert | Should -BeNullOrEmpty
    }
}

Describe "SEDR-002 LSASS Dump File Hunt" {

    BeforeAll {
        # Use a unique prefix so test artifacts are never confused with real dumps
        # and can be swept by AfterAll even if a test is killed mid-run.
        $script:TestDumpPrefix = "irtoolkit_test_lsass_"
    }

    BeforeEach {
        $script:Findings = @()
        $script:Quiet = $true
    }

    AfterAll {
        # Remove any test dump files left behind by killed/failed runs.
        $tmpDir = [System.IO.Path]::GetTempPath()
        Get-ChildItem $tmpDir -Filter "irtoolkit_test_lsass_*.dmp" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    It "Should flag a large .dmp file in TEMP as High" {
        $tmpDir = [System.IO.Path]::GetTempPath()
        $dumpFile = Join-Path $tmpDir "$($script:TestDumpPrefix)generic_$(Get-Random).dmp"
        $bytes = New-Object byte[] (11MB)
        [System.IO.File]::WriteAllBytes($dumpFile, $bytes)

        try {
            Invoke-LsassDumpHunt

            $Alert = $script:Findings | Where-Object {
                ($_.Type -eq "LSASS Memory Dump") -and ($_.Target -match [regex]::Escape($dumpFile))
            }
            $Alert | Should -Not -BeNullOrEmpty
            $Alert.Severity | Should -BeIn @("High", "Critical")
        }
        finally {
            Remove-Item $dumpFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Should flag a .dmp file with 'lsass' in the name as Critical" {
        $tmpDir = [System.IO.Path]::GetTempPath()
        $dumpFile = Join-Path $tmpDir "$($script:TestDumpPrefix)lsass_$(Get-Random).dmp"
        $bytes = New-Object byte[] (12MB)
        [System.IO.File]::WriteAllBytes($dumpFile, $bytes)

        try {
            Invoke-LsassDumpHunt

            $Alert = $script:Findings | Where-Object {
                ($_.Type -eq "LSASS Memory Dump") -and ($_.Target -match [regex]::Escape($dumpFile))
            }
            $Alert | Should -Not -BeNullOrEmpty
            $Alert.Severity | Should -Be "Critical"
        }
        finally {
            Remove-Item $dumpFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Should NOT flag a small .dmp file (crash dump smaller than 10MB threshold)" {
        $tmpDir = [System.IO.Path]::GetTempPath()
        $dumpFile = Join-Path $tmpDir "$($script:TestDumpPrefix)small_$(Get-Random).dmp"
        $bytes = New-Object byte[] (500KB)
        [System.IO.File]::WriteAllBytes($dumpFile, $bytes)

        try {
            Invoke-LsassDumpHunt

            $Alert = $script:Findings | Where-Object {
                ($_.Type -eq "LSASS Memory Dump") -and ($_.Target -match [regex]::Escape($dumpFile))
            }
            $Alert | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item $dumpFile -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe "SEDR-002 EID 4656/4663 LSASS Handle Detection (EventLog)" {

    It "Script should define the 4656/4663 detection logic" {
        $content = Get-Content -LiteralPath $script:EvtScript -Raw
        # Verify the LSASS access section was added
        $content | Should -Match "4656"
        $content | Should -Match "4663"
        $content | Should -Match "lsass"
        $content | Should -Match "credential theft"
    }

    It "Script should suppress SYSTEM and known AV callers" {
        $content = Get-Content -LiteralPath $script:EvtScript -Raw
        $content | Should -Match "NT AUTHORITY"
        $content | Should -Match "MsMpEng"
    }

    It "Script should include VM_READ access mask patterns" {
        $content = Get-Content -LiteralPath $script:EvtScript -Raw
        $content | Should -Match "0x10"
        $content | Should -Match "ReadVirtualMemory|ReadData"
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBXHdwgQTt4cAKM
# Y5Xn2Cw69XIP0q74YpIJgH1B56xLsqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgrmtKf0Wz9t2/CmLLkHTGA8DmiN9vPmqm2SUv
# kVA5Rv0wDQYJKoZIhvcNAQEBBQAEggEAOIjtvNiqmFN5LmliCihUn7ItvQ1DkyuB
# zShn1Im1RGYepxwGYyKo0xPNM3mM7uC1qGTGh8KsmXMfRpntVXmHVyRiydvCa1Rn
# rTdZblXfkNNL2oz+sGtU12+qNjEhHihXPIanY5PJqtJFFl/uguHYc0uwx8GTwjPu
# 5kwQRgtnD0mpNbUP9sqg8TxMFHGF2HTVqzvlrJ/VY/WH5GwkG5dfeLQs6JuNGJDN
# qfSLp7V049WmTZKpbfm4/8WKXAcGbczvGCmJo5X+WHHoinKNqRP6brSZNVfC8e8Y
# IxetMdzNi6HDe56e+YUq/nkti/yyaPRJMJwAVCepARkfkt7GHmtysKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzhaMC8GCSqGSIb3DQEJBDEiBCD9
# rgMiDmmKDMunj7s5iP/qP1SVkAH2BKmhd/5fqCUdZTANBgkqhkiG9w0BAQEFAASC
# AgAH0Zqzza6vTsdFCI5jO71hBNvjDhKGMwWeeKKe9vU1BJr4hN61SeEj8ejK+X7+
# j8SGdn2XYtMi7CFVTCUV62vn/HLsy65Rgrk7m+/hL3nlF5hrGSWp+/l6lAoZezYn
# AvqBrxRA4TtUkemjtyK7X/2cFxKW+0Q9L1DgpxM/Kutmb6mkJzknL8mPuF3RREwW
# YVHpexA/n468mFitrvstA+JOx/YjZBmbcbjSz1rclciEja7VVVMdX4rm7SPLC1Mm
# mqVJSagfjPkwQelYI68KL0RuR8r5q0U3beqxaiG4eaT7zFdfNa9vwIL6BIg7DvWg
# PNIvRIsx4G3hE7LeZ9/6+YmpTLb6KE1CUT2ZiP7/Do3/AHQT2bdMQwF8bqcMRs7f
# CMB3A4l+5BZYGF9KNWGLQKr7vUNvORfHksx8/fNMlGB9cRAAQyEhRcUo8OVzbmaP
# sxv5YfZMoNe8LWnLn1DvWFfShRwdg3TIEIUGHydI2eRr9xCLItYC3b/ml2javrln
# 3Kg97/NGuzW8RAx/PZ8nDioxijFvVeOE3gPMoppcv0oWOks5SCpIuc1r26r+i9Fr
# pybAAfAuy0yhJNNhuCF/JGJo9pXS7jyKhClTBgLQThkctY6ZfuMRiA6opBlZxPga
# WPQhM4c/F9BCvH2JUg/wtp638FKiYIfKIxjqulmoEwCk5g==
# SIG # End signature block
