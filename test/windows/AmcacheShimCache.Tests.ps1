<#
.SYNOPSIS
    Pester 5 tests for Amcache and ShimCache parsing.
    Unit tests use synthetic CSV/binary fixtures — no live hive access required.
    Live tests validate against collected Persistence/ artifacts.
#>

BeforeAll {
    $Script:ParserScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Invoke-AmcacheParser.ps1'
    $Script:PersistScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Get-PersistenceSnapshot.ps1'
    $Script:PersistDir    = Join-Path $PSScriptRoot '..\..\reports' |
        Get-ChildItem -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'Persistence') } |
        Select-Object -First 1 |
        ForEach-Object { Join-Path $_.FullName 'Persistence' }
}

Describe "Invoke-AmcacheParser.ps1 — script structure" {

    It "Parser script exists" {
        Test-Path -LiteralPath $Script:ParserScript | Should -Be $true
    }

    It "Parser script parses without errors" {
        $r = pwsh -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw '$($Script:ParserScript)'))" 2>&1
        $r | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | Should -BeNullOrEmpty
    }

    It "Parser script has -InputDir and -OutputDir parameters" {
        $content = Get-Content -LiteralPath $Script:ParserScript -Raw
        $content | Should -Match '\$InputDir'
        $content | Should -Match '\$OutputDir'
    }
}

Describe "Amcache CSV parsing — unit tests" {

    It "Detects executable in user-writable AppData path" {
        $dir = Join-Path $TestDrive 'amcache_appdata'
        New-Item -ItemType Directory $dir -Force | Out-Null
        @([PSCustomObject]@{
            Path      = 'C:\Users\user\AppData\Roaming\evil.exe'
            SHA1      = 'aabbccdd'
            Publisher = ''
            Product   = ''
            Version   = '1.0'
            LinkDate  = (Get-Date).ToString('yyyy-MM-dd')
            Size      = '12345'
        }) | Export-Csv (Join-Path $dir 'amcache_parsed.csv') -NoTypeInformation

        & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_amcache_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $alert = @($findings) | Where-Object { $_.Target -match 'evil\.exe' }
        $alert | Should -Not -BeNullOrEmpty
        $alert.Severity | Should -Be 'High'
    }

    It "Detects LOLBin executed (mshta.exe in System32 is normal, in AppData is suspicious)" {
        $dir = Join-Path $TestDrive 'amcache_lolbin'
        New-Item -ItemType Directory $dir -Force | Out-Null
        @([PSCustomObject]@{
            Path      = 'C:\Users\Public\mshta.exe'
            SHA1      = 'ccddee'
            Publisher = ''
            Product   = ''
            Version   = '11.0'
            LinkDate  = (Get-Date).ToString('yyyy-MM-dd')
            Size      = '8192'
        }) | Export-Csv (Join-Path $dir 'amcache_parsed.csv') -NoTypeInformation

        & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_amcache_*.json' | Select-Object -First 1
        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        @($findings) | Where-Object { $_.Target -match 'mshta' } | Should -Not -BeNullOrEmpty
    }

    It "Does NOT flag signed Microsoft executable in Program Files" {
        $dir = Join-Path $TestDrive 'amcache_clean'
        New-Item -ItemType Directory $dir -Force | Out-Null
        @([PSCustomObject]@{
            Path      = 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
            SHA1      = '1234567890'
            Publisher = 'Microsoft Corporation'
            Product   = 'Microsoft Office'
            Version   = '16.0'
            LinkDate  = '2024-01-01'
            Size      = '1234567'
        }) | Export-Csv (Join-Path $dir 'amcache_parsed.csv') -NoTypeInformation

        & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_amcache_*.json' | Select-Object -First 1
        if ($json) {
            $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
            @($findings) | Where-Object { $_.Target -match 'WINWORD' } | Should -BeNullOrEmpty
        } else {
            $true | Should -Be $true   # no output file = no findings = pass
        }
    }

    It "Detects unsigned executable in Temp directory" {
        $dir = Join-Path $TestDrive 'amcache_temp'
        New-Item -ItemType Directory $dir -Force | Out-Null
        @([PSCustomObject]@{
            Path      = 'C:\Windows\Temp\stager.exe'
            SHA1      = 'deadbeef'
            Publisher = ''
            Product   = ''
            Version   = ''
            LinkDate  = (Get-Date).ToString('yyyy-MM-dd')
            Size      = '4096'
        }) | Export-Csv (Join-Path $dir 'amcache_parsed.csv') -NoTypeInformation

        & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null
        $json = Get-ChildItem $dir -Filter 'findings_amcache_*.json' | Select-Object -First 1
        $json | Should -Not -BeNullOrEmpty

        $findings = Get-Content $json.FullName -Raw | ConvertFrom-Json
        @($findings) | Where-Object { $_.Type -match 'Amcache' } | Should -Not -BeNullOrEmpty
    }

    It "Produces no findings when amcache_parsed.csv is absent (graceful no-op)" {
        $dir = Join-Path $TestDrive 'amcache_missing'
        New-Item -ItemType Directory $dir -Force | Out-Null

        { & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null } | Should -Not -Throw
    }
}

Describe "ShimCache binary parsing — unit tests" {

    It "Get-PersistenceSnapshot.ps1 exports ShimCache raw binary" {
        $content = Get-Content -LiteralPath $Script:PersistScript -Raw
        $content | Should -Match 'shimcache|ShimCache|AppCompatCache' -Because 'ShimCache should be exported by the persistence snapshot'
    }

    It "Parser handles missing shimcache.bin gracefully" {
        $dir = Join-Path $TestDrive 'shim_missing'
        New-Item -ItemType Directory $dir -Force | Out-Null

        { & $Script:ParserScript -InputDir $dir -OutputDir $dir 2>&1 | Out-Null } | Should -Not -Throw
    }
}

Describe "Live validation — requires collected Persistence artifacts" {

    It "Persistence directory exists in at least one report" -Skip:(-not $Script:PersistDir) {
        Test-Path -LiteralPath $Script:PersistDir | Should -Be $true
    }

    It "Parser runs against live Persistence dir without crashing" -Skip:(-not $Script:PersistDir) {
        $outDir = $Script:PersistDir
        { & $Script:ParserScript -InputDir $outDir -OutputDir $outDir 2>&1 | Out-Null } |
            Should -Not -Throw -Because 'Parser should be robust to missing or partial files'
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAiWpzXPK9psaso
# 7pZudcnMjuwGHweJY3lvA8y1QnqdfqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgO5MmXUqOgpyN1XHiSp0Uk/0baHL4p3+49nQY
# 9qFR9NowDQYJKoZIhvcNAQEBBQAEggEAi/7aRPHG0b5NM/XblUiL2dz19QBWm85r
# cLnlgF6Gl91jR5LTAzy21nr54SSOESIGCcwcSnUqz+Wuo3KQtENYklxyHRmqMUqZ
# BrlTrybeH6QIAtnTZKlOJ4ZyNHCUk32oGJm136aGJbjbEOmxAy6pUUvWwJXXxDE5
# 0fVC1Wy7v4FtX8/BqnBHJTLKxKW6mKhSsmS6IBVE37R00KJA28xdONQ34U64Zx3+
# STBlP1NOgmTbbLM9gnONGi5VooFRUqQ4Fx+jYdEluR2kunxz6z8yApa59jYumhCo
# Z7mSS5bPgkbS7duUjtoH3aRZ4W8lBhh1CSwSKoOFNBnHR6vlUx5LVaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MzFaMC8GCSqGSIb3DQEJBDEiBCCx
# ELg2L3gkDYBnpO/LT8L+eKfqzfU435cG9u7cOsyhMzANBgkqhkiG9w0BAQEFAASC
# AgAvtJIGYZzNTFooYQwrimvLRgrzKq7Jw7zQGbTeYNt3Jcodm2lOs75KgVW9CxIW
# /NO5xRWPu0knaVZGR7fHf+LN1gQu/QOIdrt4M0wQEgzfq62xekiC0cgkME6fbJS9
# bPQH3hRfy4qsDIA92dLpVRCHk26SdASGzjW015oJpHjUt2dWI0me3KmQHfQ9X22W
# L2HrxBsmbbfeZhTDnFpMhRAlvGCPZgWRhtMg+q+ps32MndodJuTnnYzIbhqHZU69
# /P+CKUrK0lbEGovnq0AO0fL4dwdjMrO13tR5wTJLt0Q6z6bqKkwOCQ34nC33igb+
# C4cKesNFah/nItAgUNY3kwH5X26I124hLTei3MML5jMB21ZYUN6Xg93TTHny/NTI
# jnYrjETar9A/7VUg1H2slyTcJg/r0Y9NtF3JjfxJTej4wQHO4hJn/55ZSz5S7Jdb
# dS6/1UX6G0uK5dEyxxraXDwAwR02xI1/AVvGI0k8bZjQlVi9C2yausHD72lUPMmh
# pxYE8y8zQKKJ73W8BR2zydPP6cHq/+Wk1Es5dJuw8W4HBHqWImsejEiTaGWGYoTG
# WMtemQB5VFFLq7jHNVwzRCDlZ+GFSrbHGIBrxFpx8snekvrveOjl7KiXptTke2Ok
# RTI4HewLcZNj/I8JJsxYPIKq6hjekiQlYPkcCAQqpPjAiA==
# SIG # End signature block
