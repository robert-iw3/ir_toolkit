<#
.SYNOPSIS
    Pester 5 tests: memory YARA findings roll up into the workflow reports.

    generate_reports.ps1 builds Incident_Report.md + Attack_Graph.md from the newest
    Adjudication_*.json (else Combined_Findings) generically, so any memory finding in
    that adjudication appears in the reports. Analyze-Memory.ps1 -Adjudicate must merge
    memory findings, adjudicate, AND regenerate the reports so the rollup actually happens.
#>

BeforeAll {
    $Script:MemScript    = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Analyze-Memory.ps1'
    $Script:ReportScript = Join-Path $PSScriptRoot '..\..\playbooks\reporting\generate_reports.ps1'
}

Describe "generate_reports rolls memory findings into all reports" {

    It "A memory YARA TP finding appears in Incident_Report + Attack_Graph + IOC/Principal artifacts" {
        $hf = Join-Path $TestDrive 'GOTEM'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Timestamp='2026-06-21 22:00:00'; Severity='Critical'; Type='YARA Match (Memory)';
                Target='PID 1234 (svchost.exe)'; Details='Rule: REDLEAVES_CoreImplant | 3 match(es)';
                MITRE='T1055 (Process Injection)'; Verdict='True Positive'; Confidence='High'; Source='Memory' }
            [pscustomobject]@{ Timestamp='2026-06-21 22:00:01'; Severity='High'; Type='YARA Match (Memory)';
                Target='PID 5678 (rundll32.exe)'; Details='Rule: WiltedTulip_Windows_UM_Task | 1 match(es)';
                MITRE='T1053'; Verdict='Likely True Positive'; Confidence='Medium'; Source='Memory' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260621_220000.json') -Encoding UTF8

        & $Script:ReportScript -HostFolder $hf -IncidentId 'GOTEM_test' *>$null

        $ir = Get-Content (Join-Path $hf 'Incident_Report.md') -Raw
        $ir | Should -Match 'YARA Match \(Memory\)'   -Because 'memory findings must surface in the incident report'
        $ir | Should -Match 'svchost\.exe'
        Test-Path (Join-Path $hf 'Attack_Graph.md') | Should -BeTrue
        # ATT&CK technique from the memory finding should be in the navigator layer
        (Get-Content (Join-Path $hf 'attck_navigator_layer.json') -Raw) | Should -Match 'T1055'
    }

    It "Reports show 2 true-positive-class memory findings in the funnel" {
        $hf = Join-Path $TestDrive 'HOST2'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='Critical'; Type='YARA Match (Memory)'; Target='PID 1 (a.exe)';
                Details='Rule: X'; MITRE='T1055'; Verdict='True Positive' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260621_220500.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null
        (Get-Content (Join-Path $hf 'Incident_Report.md') -Raw) | Should -Match 'true-positive-class'
    }
}

Describe "Memory YARA matches cluster per PID in the report" {

    It "Groups multiple hits on one PID into a single entry with a count + rule list" {
        $hf = Join-Path $TestDrive 'CLUSTER'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            # PID 5308 matched THREE rules -> should cluster to one row, count 3
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 5308 (SecHealthUI.exe)';
                Details='Rule: Webshell_China_Chopper | 1 match(es)'; MITRE='T1027'; Verdict='True Positive' }
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 5308 (SecHealthUI.exe)';
                Details='Rule: Webshell_PHP_Generic | 1 match(es)'; MITRE='T1027'; Verdict='True Positive' }
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 5308 (SecHealthUI.exe)';
                Details='Rule: Suspicious_PowerShell_WebDownload_1 | 1 match(es)'; MITRE='T1027'; Verdict='True Positive' }
            # PID 1234 matched once
            [pscustomobject]@{ Severity='Critical'; Type='YARA Match (Memory)'; Target='PID 1234 (svchost.exe)';
                Details='Rule: REDLEAVES_CoreImplant | 3 match(es)'; MITRE='T1055'; Verdict='True Positive' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260621_221000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null

        $ir = Get-Content (Join-Path $hf 'Incident_Report.md') -Raw
        # A clustered section keyed by process, with a count column
        $ir | Should -Match 'YARA.*[Pp]rocess'
        $ir | Should -Match 'SecHealthUI\.exe'
        # the 3 rules on PID 5308 should be represented together (count 3)
        $ir | Should -Match 'Webshell_China_Chopper'
        $ir | Should -Match 'Suspicious_PowerShell_WebDownload_1'
        # the clustered row for 5308 should show a hit count of 3
        ($ir -split "`n" | Where-Object { $_ -match 'SecHealthUI\.exe' -and $_ -match '\b3\b' }) |
            Should -Not -BeNullOrEmpty
    }
}

Describe "Memory YARA cluster shows VAD context (injected vs file-backed)" {
    It "Renders anon-exec (injected) context and the Injected Code type" {
        $hf = Join-Path $TestDrive 'CTX'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='Critical'; Type='Injected Code (memory YARA)'; Target='PID 1234 (svchost.exe)';
                Details='Rule: REDLEAVES_CoreImplant | 3 match(es) | anon-exec region (rwx) -- injected/unbacked code';
                MITRE='T1055'; Verdict='True Positive' }
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 5308 (SecHealthUI.exe)';
                Details='Rule: Webshell_China_Chopper | 1 match(es) | file-backed r-x SecHealthUI.dll -- verify signature/hash';
                MITRE='T1027'; Verdict='Likely True Positive' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260623_000000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null
        $ir = Get-Content (Join-Path $hf 'Incident_Report.md') -Raw
        $ir | Should -Match 'anon-exec'                  # injected context surfaced
        $ir | Should -Match 'verify signature'           # file-backed -> verify
        $ir | Should -Match 'Injected Code \(memory YARA\)'  # escalated type in TP table
    }
}

Describe "Analyze-Memory.ps1 -Adjudicate regenerates reports" {
    It "The -Adjudicate path invokes generate_reports.ps1" {
        (Get-Content -LiteralPath $Script:MemScript -Raw) | Should -Match 'generate_reports\.ps1'
    }
}

Describe "Separate YARA pivot report (YARA_Pivot_Report.md)" {

    It "A named malware/APT-family hit with multiple rules on one PID leads as Likely True Positive" {
        $hf = Join-Path $TestDrive 'PIVOT_CORR'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 13680 (ShellExperienceHost.exe)';
                Details='Rule: REDLEAVES_CoreImplant_UniqueStrings | 3 match(es)'; MITRE='T1055'; Verdict='True Positive' }
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 13680 (ShellExperienceHost.exe)';
                Details='Rule: LOLBin_Mshta_Scriptlet | 1 match(es)'; MITRE='T1218'; Verdict='True Positive' }
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 13680 (ShellExperienceHost.exe)';
                Details='Rule: LOLBin_BITS_Drop | 1 match(es)'; MITRE='T1197'; Verdict='True Positive' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260624_000000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf -IncidentId 'GOTEM_piv' *>$null

        $p = Join-Path $hf 'YARA_Pivot_Report.md'
        Test-Path $p | Should -BeTrue -Because 'a YARA hit must produce the separate pivot report'
        $r = Get-Content $p -Raw
        $r | Should -Match 'Likely True Positive'
        $r | Should -Match 'PID 13680'
        $r | Should -Match 'REDLEAVES_CoreImplant_UniqueStrings'
        $r | Should -Match '1 true-positive-class'
        $r | Should -Match 'Eradication scope'             # the TP carries the enrichment directive
    }

    It "A lone generic LOLBin hit (even with a path-spoof FP) is reported but NOT escalated" {
        $hf = Join-Path $TestDrive 'PIVOT_LONE'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 620 (svchost.exe)';
                Details='Rule: LOLBin_BITS_Drop | 1 match(es)'; MITRE='T1197'; Verdict='Indeterminate' }
            [pscustomobject]@{ Severity='Critical'; Type='Process Path Spoofing (Memory)'; Target='PID 620 (svchost.exe)';
                Details='System process running from unexpected path: \Device\HarddiskVolume3\Windows\System32\svchost.exe'; MITRE='T1036'; Verdict='Indeterminate' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260624_001000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null

        $r = Get-Content (Join-Path $hf 'YARA_Pivot_Report.md') -Raw
        $r | Should -Match 'PID 620'                        # present, never suppressed
        $r | Should -Match 'LOLBin_BITS_Drop'
        $r | Should -Match '0 true-positive-class'
        $r | Should -Not -Match 'Likely True Positive'      # not escalated on a path-spoof FP
    }

    It "No pivot report is written when there are no YARA hits" {
        $hf = Join-Path $TestDrive 'PIVOT_NONE'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='Low'; Type='Network Connection (Memory)'; Target='PID 100 (svchost.exe)';
                Details='External 8.8.8.8:53'; MITRE='T1071'; Verdict='False Positive' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260624_002000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null
        Test-Path (Join-Path $hf 'YARA_Pivot_Report.md') | Should -BeFalse
    }
}

Describe "YARA pivot -- single generic rule demotion" {

    It "A lone generic rule with no corroborating signals is footnoted, NOT a main section" {
        $hf = Join-Path $TestDrive 'DEMOTE_BITS'
        New-Item -ItemType Directory -Force $hf | Out-Null
        $adj = @(
            [pscustomobject]@{ Severity='High'; Type='YARA Match (Memory)'; Target='PID 9999 (svchost.exe)';
                Details='Rule: LOLBin_BITS_Drop | 1 match(es)'; MITRE='T1197'; Verdict='Indeterminate' }
        )
        ($adj | ConvertTo-Json -Depth 6) | Out-File (Join-Path $hf 'Adjudication_20260628_000000.json') -Encoding UTF8
        & $Script:ReportScript -HostFolder $hf *>$null
        $r = Get-Content (Join-Path $hf 'YARA_Pivot_Report.md') -Raw
        $r | Should -Match 'LOLBin_BITS_Drop'               # still visible, not suppressed
        $r | Should -Not -Match '(?m)^## PID 9999'           # NOT a full H2 main-body section
        $r | Should -Match '(?i)(demoted|pivot.leads only|generic.*rule|single.*generic)' -Because 'demoted PIDs must appear in a footer note, not as a main section'
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD6/fzRrJd0r7QO
# 2EejIck6j7fKdhsSp5gN490djqLsv6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgG7qV03djkdOp0faahxjzov3Wly9yWiWYJev8
# jdxGwREwDQYJKoZIhvcNAQEBBQAEggEAbQHHIj5Dm+23FxMUaIQLdUl5SxJR/nmq
# aGMahdxcEshyMRF5YOFruBmnl1RQ/Kr8EGzh4ctXCI0QOZ1yiTC0K5GxJA1A9fZj
# 0Ls6HtR45q+6KzWD884UEKM6hyrXBrPziq0P6TCDnZ5pGqJcIKanDl7CMaAKFAIW
# zuVPe2a4oTQyJpL3CAXaiwxZq6yZ3I/17WXmBcPDJboZhYbdx9WPeum40RpwfWrO
# JcQOdnNuAwL1jxH6DzZrNaV9SBnLfssL4qRk/cQbiGqZGPaFp0/HzCSMTFZ+AHKQ
# iMjleuxuAYWZVGpxWlKcG2HXdBnvINxdcXZVKXndSsZdxLhvL3j5/6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3NDFaMC8GCSqGSIb3DQEJBDEiBCCC
# TrGSeWQsyXSmPbghf8eABQmaN6fkRUVyPC0NhzXrRDANBgkqhkiG9w0BAQEFAASC
# AgB4kR54nh2GEXNNJT/vIgNFQdB4LmaaadMXZ1CufMvCP0pcBFSo18rolEqLKmQl
# fH6SCkxdaGHiMgrLKd+0hboFQYGB5S4uvcMOHLQQDloo5/Fq1AWplc8FAD+6M6TT
# z+ypKwyGtuEXLMkIka6yYwzgRxg5pNd1C8MqPGY3XsTE/Ow+mYJPl2DvjmGLJjOl
# WkLb8fkBn2695ETlhMipwjE5BKIthe5g1QQbFFqPa3tOom3b4vFHUbuscZVPrAmZ
# dE03fjzArf4RMrPxjv5LwImmwmBKv6MZ+AThEz/B7bqAFe1jhAR3uRwM8ErTctfS
# BMdekLgwsfHgaEw76P97a4nZ08zXwCC1PEFUl23q0HFm0+KKDu5JhfjpeCK62xHZ
# rSEx0ZMfIG9dLjcH6kIlv6HSfIFXse/pyAH1Zt/ReDPusEPVBpXA/lWc4TEVC6Jg
# 3EFoRyCGWdLjeSeOmsygPJzqi0DzIhz6WRF0KClLM+fxkWNqdvA+nLAb5UBPEyab
# 96llQ8k3QANoTh0N4pmDCKMYeqKEn54SSTBv/nzdViudnWactj0mFWmQ6gyTycGc
# NrnYUFl8QeOsjHqN+lukRMIsD+hB3D7f5Z7xssPL05tUhmkyMYRG5iGWeI7YPG59
# +bIRnwIO5qkalhmT1vCKOSB9afjNllsNh3lWzBX+vs2VbQ==
# SIG # End signature block
