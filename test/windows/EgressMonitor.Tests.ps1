<#
.SYNOPSIS
    Pester 5 tests for Watch-Egress.ps1 (egress observation sensor).
    Mirrors the Python twin test_35_egress_monitor.py: the external-IP classifier
    must never skip real C2 (no blindspot) and never log internal noise, the
    management IP is excluded, IncidentId is sanitized, and Collect parses the log.

    Pure-logic tests: no admin, scheduled tasks, or live connections required.
#>

BeforeAll {
    $Script:Egress   = Join-Path $PSScriptRoot '..\..\playbooks\windows\Watch-Egress.ps1'
    $Script:Firewall = Join-Path $PSScriptRoot '..\..\playbooks\windows\Enforce-StrictFirewall.ps1'
    $Script:Collector= Join-Path $PSScriptRoot '..\..\Invoke-IRCollection.ps1'
    $Script:EgressSrc = Get-Content -LiteralPath $Script:Egress -Raw
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:Egress, [ref]$tokens, [ref]$errors)
    $Script:ParseErrors = $errors
    # Extract the pure functions and exercise the real source (no admin needed).
    foreach ($name in 'Test-External','Invoke-Snapshot') {
        $fn = $ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $n.Name -eq $name }, $true) | Select-Object -First 1
        if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)) }
    }
}

Describe "Watch-Egress.ps1 — parses + structure" {
    It "Parses without errors" { $Script:ParseErrors | Should -BeNullOrEmpty }

    It "Exposes the documented parameter sets" {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:Egress, [ref]$null, [ref]$null)
        $names = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        foreach ($p in 'Start','Snapshot','Blackhole','Stop','Collect','Status') { $names | Should -Contain $p }
    }
}

Describe "Test-External — external IPs are logged (no C2 blindspot)" {
    BeforeEach { $MgmtIP = @() }
    It "Classifies real public dest <Ip> as external" -ForEach @(
        @{ Ip='8.8.8.8' }, @{ Ip='1.1.1.1' }, @{ Ip='203.0.113.5' }, @{ Ip='45.66.77.88' },
        @{ Ip='172.32.0.1' }, @{ Ip='11.0.0.1' }, @{ Ip='2606:4700:4700::1111' }
    ) {
        Test-External $Ip | Should -BeTrue -Because "$Ip is a routable destination and must be logged"
    }
}

Describe "Test-External — internal / loopback / link-local skipped (noise)" {
    BeforeEach { $MgmtIP = @() }
    It "Classifies <Ip> as internal (not logged)" -ForEach @(
        @{ Ip='10.0.0.5' }, @{ Ip='192.168.1.10' }, @{ Ip='172.16.5.5' }, @{ Ip='172.31.0.1' },
        @{ Ip='127.0.0.1' }, @{ Ip='169.254.1.1' }, @{ Ip='::1' }, @{ Ip='fe80::1' },
        @{ Ip='224.0.0.251' }, @{ Ip='0.0.0.0' }, @{ Ip='' }
    ) {
        Test-External $Ip | Should -BeFalse -Because "$Ip is internal/non-routable noise"
    }
}

Describe "Test-External — management IP excluded but real egress still logged" {
    It "Excludes a configured management IP" {
        $MgmtIP = @('203.0.113.5')
        Test-External '203.0.113.5' | Should -BeFalse
    }
    It "Still logs other external IPs when a management IP is set" {
        $MgmtIP = @('203.0.113.5')
        Test-External '8.8.8.8' | Should -BeTrue
    }
}

Describe "IncidentId sanitization (path-safety)" {
    It "Strips non-word characters used to build state paths" {
        # mirrors:  $IncidentId = ($IncidentId -replace '[^\w\-]', '')
        ('..\evil/;rm-rf  HOST_1' -replace '[^\w\-]', '') | Should -Be 'evilrm-rfHOST_1'
    }
}

Describe "Collect — evidence log parsing (flows + unique destinations)" {
    It "Counts flows and unique external destinations from the log" {
        $log = Join-Path $TestDrive 'egress.log'
        @(
            '# IR egress observation - incident X',
            '2026-06-22T00:00:00Z | tcp | 10.0.0.2:5000 -> 8.8.8.8:443 | chrome(pid=10)',
            '2026-06-22T00:01:00Z | tcp | 10.0.0.2:5001 -> 8.8.8.8:443 | chrome(pid=10)',
            '2026-06-22T00:02:00Z | tcp | 10.0.0.2:5002 -> 45.66.77.88:1337 | evil(pid=66)'
        ) | Set-Content $log -Encoding UTF8

        $flows = (Get-Content $log | Where-Object { $_ -notmatch '^#' }).Count
        $uniq  = (Get-Content $log | Select-String -Pattern '-> ([0-9a-fA-F:.]+):' -AllMatches |
                  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique).Count
        $flows | Should -Be 3
        $uniq  | Should -Be 2   # 8.8.8.8 and 45.66.77.88
    }
}

Describe "Invoke-Snapshot — logs external flows, skips internal (mocked)" {
    It "Appends a well-formed line for external dests and skips internal" {
        $MgmtIP = @()
        $Log = Join-Path $TestDrive 'snap.log'
        Mock Get-NetTCPConnection {
            @(
                [pscustomobject]@{ State='Established'; LocalAddress='10.0.0.2'; LocalPort=5000; RemoteAddress='8.8.8.8';  RemotePort=443; OwningProcess=1234 },
                [pscustomobject]@{ State='Established'; LocalAddress='10.0.0.2'; LocalPort=5001; RemoteAddress='10.0.0.9'; RemotePort=445; OwningProcess=4 }
            )
        }
        Mock Get-Process { [pscustomobject]@{ ProcessName = 'evil' } }
        Invoke-Snapshot
        $lines = @(Get-Content $Log)
        $lines.Count | Should -Be 1                         # only the external flow logged
        $lines[0] | Should -Match 'tcp \| 10\.0\.0\.2:5000 -> 8\.8\.8\.8:443'
        $lines[0] | Should -Match 'evil\(pid=1234\)'
        $lines[0] | Should -Not -Match '10\.0\.0\.9'        # internal dest skipped
    }
}

# The -Start/-Blackhole/-Stop branches require admin (#Requires) + register real
# scheduled tasks / firewall rules, so verify the wiring by source contract instead.
Describe "Watch-Egress — sensor wiring (poll + auto-blackhole)" {
    It "Registers a poll task and a blackhole task as SYSTEM/Highest" {
        $Script:EgressSrc | Should -Match 'IR-Egress-Poll-'
        $Script:EgressSrc | Should -Match 'IR-Egress-Blackhole-'
        $Script:EgressSrc | Should -Match "New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest"
        ([regex]::Matches($Script:EgressSrc, 'Register-ScheduledTask')).Count | Should -BeGreaterOrEqual 2
    }
    It "-Stop unregisters both tasks" {
        $Script:EgressSrc | Should -Match 'Unregister-ScheduledTask -TaskName \$PollTask'
        $Script:EgressSrc | Should -Match 'Unregister-ScheduledTask -TaskName \$BHTask'
    }
    It "-Blackhole applies the outbound blackhole via Enforce-StrictFirewall and marks it done" {
        $Script:EgressSrc | Should -Match 'Enforce-StrictFirewall\.ps1'
        $Script:EgressSrc | Should -Match 'BlockOutbound'
        $Script:EgressSrc | Should -Match 'blackhole\.done'
    }
    It "-Collect reports the unique destination count" {
        $Script:EgressSrc | Should -Match 'unique_destinations'
    }
}

Describe "Enforce-StrictFirewall — outbound blackhole + mgmt pinhole" {
    It "Exposes -BlockOutbound and -Rollback" {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Script:Firewall, [ref]$null, [ref]$null)
        $names = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        $names | Should -Contain 'BlockOutbound'
        $names | Should -Contain 'Rollback'
    }
    It "-BlockOutbound sets DefaultOutboundAction Block and creates the mgmt pinhole" {
        $fw = Get-Content -LiteralPath $Script:Firewall -Raw
        $fw | Should -Match 'DefaultOutboundAction'
        $fw | Should -Match 'Block'
        $fw | Should -Match 'IR-MGMT-EGRESS-PINHOLE'
    }
}

Describe "Invoke-IRCollection — egress phase gating" {
    It "Exposes -NoEgressMonitor and gates the egress phase on it" {
        $col = Get-Content -LiteralPath $Script:Collector -Raw
        $col | Should -Match 'NoEgressMonitor'
        $col | Should -Match 'if \(-not \$NoEgressMonitor\)'
        $col | Should -Match 'Watch-Egress\.ps1'
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqM45ulGDtVCep
# 0+j8ssMMUrfci/dm+0W2bfhpPOPB0aCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgfZAmcS5S6h/wncmdq/mYgsxd5qoefRlnnoTS
# J+7gNNEwDQYJKoZIhvcNAQEBBQAEggEAW85lCdqPi+xYKAPOf/QA/7+C4rs/Cdjc
# EL16bunhhWY+yZcE5Ky5Xw9XRjlt3PwxCHvlPM1khUjhrej2Ts921dp65t0hNdsW
# uDM0vjP1dR91y1/QAsl5Sj+ByJ0J9MMdfPDgB9rZdJTo3Q8L9vn7GNXGULNOWWCW
# KC4lyrbm92K7DdZDRMUPUBJi3mgywDw8iefwDsoz4KKlhZ9d0MvHPJfSlLqO4uu1
# +XImZJIptZYCSDY4tLSVtEA6FxwHqmOe7xlX8BZXD0tVOzi8hgDBl2GknesnDdUx
# xVcjdlkBmR95Umj+L+LQegypvvtebJqpzSoyg4e6xZwwU7M8bytTVKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzNaMC8GCSqGSIb3DQEJBDEiBCCR
# xkuxHmYLh1FB98rCOSdp7dRK3xVLfCLfCdp97KwyGDANBgkqhkiG9w0BAQEFAASC
# AgBRINBGaa0GOO6e6ggP+agW1bEmz40M9SyD4fbsgB4ALPBc9DbptaIC5ZUKJuoX
# YOE8wu5F9vjIfykpCjcHOkdKDNgzxcV850xMI5bkm/eUExjcaoKDAyu8NXaw0l5+
# X9jKbR/sVz5WEz+XvILgLXSutX09pByG1hg8+zXT6vzP/HZu3tjJnh9/NAvxjtGY
# GnMIpKUMPDsJmS1cg3KQeAJs83Mi7I+bIejt/4El5AvkRS0FUNyGCKltGYmUV5vb
# NfCbFEnty/lztKcUjxFTBxJ/nteKm/LZ8AHmvxIsgdSXDIsNWPKhUWX+qlGyzyD4
# Gca+z2rRhy83diNahajl3z3pjQ/gEtCzNC5tlqp95sb6Gr45axV1z8TzCDptNDW9
# frtV0Ihr8DXP3taZYOzd+4wF8Lp+MKfK9yUySnp333F6MeLwyMkqSPjV23IqHyra
# Ueer0hh+dcHNTihuQVws5qRDB13w+VWN8oUGZFI2aGkJF+vipCTSspE16LNO2tC3
# 1dcx/l5DLoOP9sp9CbSMirkxsUA5eOxCz83dtzI4KyV4cuHVzCobSfCwmYHRQ9e1
# FNL+9w1eHSYfS1GVifr5ERJu98bA9jW5I47YVcUXIjZiS9Y62V5YyDt1zC7B2kn7
# M40XkCc2ix2RWrH1i2K3eQV/a4TVo/1FNW+hSHBWnZXYbg==
# SIG # End signature block
