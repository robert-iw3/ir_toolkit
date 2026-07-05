<#
.SYNOPSIS
    Pester 5 tests for the pure-logic functions in Invoke-Eradication.ps1
    (Test-Protected, Get-EradicationOrder, Test-AlreadySinkholed).

    Invoke-Eradication.ps1 carries #Requires -RunAsAdministrator, which triggers
    even on dot-sourcing -- and this session has no admin rights. Following the
    established pattern in CodeSigning.Tests.ps1 (structural/text testing of
    admin-gated scripts), the functions under test are bracketed in the source
    with "# PESTER-EXTRACT-START" / "# PESTER-EXTRACT-END" markers. BeforeAll
    extracts just that text substring and evaluates it via Invoke-Expression,
    entirely avoiding the #Requires gate since only a fragment (not the whole
    script) is parsed/executed.
#>

BeforeAll {
    $Script:ToolkitRoot = Join-Path $PSScriptRoot '..\..\'
    $Script:EradScript  = Join-Path $Script:ToolkitRoot 'Invoke-Eradication.ps1'

    $raw = Get-Content -LiteralPath $Script:EradScript -Raw
    $startTag = '# PESTER-EXTRACT-START: pure-logic functions (Test-Protected, Get-EradicationOrder, Test-AlreadySinkholed)'
    $endTag   = '# PESTER-EXTRACT-END'
    $startIdx = $raw.IndexOf($startTag)
    $endIdx   = $raw.IndexOf($endTag)
    if ($startIdx -lt 0 -or $endIdx -lt 0 -or $endIdx -le $startIdx) {
        throw "Could not locate PESTER-EXTRACT markers in $Script:EradScript"
    }
    $Script:ExtractedLogic = $raw.Substring($startIdx, $endIdx - $startIdx)

    Invoke-Expression $Script:ExtractedLogic
}

Describe "Invoke-Eradication.ps1 -- script structure" {

    It "Eradication script exists" {
        Test-Path -LiteralPath $Script:EradScript | Should -Be $true
    }

    It "Eradication script requires RunAsAdministrator" {
        $content = Get-Content -LiteralPath $Script:EradScript -Raw
        $content | Should -Match '#Requires -RunAsAdministrator'
    }

    It "Extraction markers are present exactly once each" {
        $content = Get-Content -LiteralPath $Script:EradScript -Raw
        ([regex]::Matches($content, [regex]::Escape('# PESTER-EXTRACT-START'))).Count | Should -Be 1
        ([regex]::Matches($content, [regex]::Escape('# PESTER-EXTRACT-END'))).Count | Should -Be 1
    }
}

Describe "Test-Protected -- path-masquerade safety rail" {

    It "protects svchost.exe on its correct System32 path" {
        Test-Protected -Name 'svchost.exe' -Path 'C:\Windows\System32\svchost.exe' -Sig 'NotSigned' |
            Should -Match 'path-verified'
    }

    It "protects svchost.exe on its correct SysWOW64 path" {
        Test-Protected -Name 'svchost.exe' -Path 'C:\Windows\SysWOW64\svchost.exe' -Sig 'NotSigned' |
            Should -Match 'path-verified'
    }

    It "does NOT protect svchost.exe masquerading from an arbitrary path" {
        Test-Protected -Name 'svchost.exe' -Path 'C:\Users\Public\svchost.exe' -Sig 'NotSigned' |
            Should -BeNullOrEmpty
    }

    It "does NOT protect lsass.exe masquerading from a temp path" {
        Test-Protected -Name 'lsass.exe' -Path 'C:\Windows\Temp\lsass.exe' -Sig 'NotSigned' |
            Should -BeNullOrEmpty
    }

    It "protects lsass.exe on its correct path" {
        Test-Protected -Name 'lsass.exe' -Path 'C:\Windows\System32\lsass.exe' -Sig 'NotSigned' |
            Should -Match 'path-verified'
    }

    It "protects MsMpEng.exe under either of its known install roots" {
        Test-Protected -Name 'MsMpEng.exe' -Path 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.0\MsMpEng.exe' -Sig 'NotSigned' |
            Should -Match 'path-verified'
    }

    It "does NOT protect MsMpEng.exe from an unexpected path" {
        Test-Protected -Name 'MsMpEng.exe' -Path 'C:\Users\Public\MsMpEng.exe' -Sig 'NotSigned' |
            Should -BeNullOrEmpty
    }

    It "falls back to name-only protection for kernel pseudo-processes with no path table entry" {
        Test-Protected -Name 'System' -Path '' -Sig 'NotSigned' | Should -Match "protected process name 'System'"
    }

    It "falls back to name-only protection when no path evidence is supplied at all" {
        Test-Protected -Name 'lsass.exe' -Path '' -Sig 'NotSigned' | Should -Match "protected process name 'lsass'"
    }

    It "protects any validly code-signed binary regardless of name" {
        Test-Protected -Name 'totallyrandom.exe' -Path 'C:\Users\Public\totallyrandom.exe' -Sig 'Valid' |
            Should -Match 'code-signed'
    }

    It "protects any binary located under a protected OS directory regardless of name" {
        Test-Protected -Name 'notaknownname.exe' -Path 'C:\Windows\System32\notaknownname.exe' -Sig 'NotSigned' |
            Should -Match 'protected OS location'
    }

    It "does NOT protect an unsigned, unnamed binary outside any protected location" {
        Test-Protected -Name 'evil.exe' -Path 'C:\Users\Public\Downloads\evil.exe' -Sig 'NotSigned' |
            Should -BeNullOrEmpty
    }
}

Describe "Get-EradicationOrder -- containment sequencing" {

    It "orders persistence/config-removal types before process-kill types" {
        Get-EradicationOrder 'Scheduled Task' | Should -BeLessThan (Get-EradicationOrder 'Hidden Process')
        Get-EradicationOrder 'COM Hijack'     | Should -BeLessThan (Get-EradicationOrder 'Injection')
        Get-EradicationOrder 'BITS'           | Should -BeLessThan (Get-EradicationOrder 'LOLBin')
    }

    It "orders process-kill types before the default/fallback bucket" {
        Get-EradicationOrder 'Process' | Should -BeLessThan (Get-EradicationOrder 'SomeOtherFindingType')
    }

    It "sorting a mixed action list yields persistence-removal first" {
        $items = @(
            [pscustomobject]@{ Type = 'Hidden Process' },
            [pscustomobject]@{ Type = 'Scheduled Task' },
            [pscustomobject]@{ Type = 'RemoteAccessTool' },
            [pscustomobject]@{ Type = 'Defender Exclusion' }
        )
        $sorted = @($items | Sort-Object { Get-EradicationOrder $_.Type })
        $sorted[0].Type | Should -Be 'Scheduled Task'
        $sorted[-1].Type | Should -Be 'RemoteAccessTool'
    }
}

Describe "Test-AlreadySinkholed -- hosts-file de-dup" {

    It "returns false when the hosts file has no matching line" {
        $lines = @('127.0.0.1 localhost', '0.0.0.0 other-host.example.com # unrelated')
        Test-AlreadySinkholed -ExistingLines $lines -TargetHost 'evil.example.com' | Should -Be $false
    }

    It "returns true when the target host is already sinkholed" {
        $lines = @('127.0.0.1 localhost', '0.0.0.0 evil.example.com # IR sinkhole - adversary C2 (INC-1)')
        Test-AlreadySinkholed -ExistingLines $lines -TargetHost 'evil.example.com' | Should -Be $true
    }

    It "returns false against an empty hosts file" {
        Test-AlreadySinkholed -ExistingLines @() -TargetHost 'evil.example.com' | Should -Be $false
    }

    It "matches case-insensitively (PowerShell -match default)" {
        $lines = @('0.0.0.0 EVIL.EXAMPLE.COM # IR sinkhole - adversary C2 (INC-1)')
        Test-AlreadySinkholed -ExistingLines $lines -TargetHost 'evil.example.com' | Should -Be $true
    }

    It "escapes regex metacharacters in the target host (literal dot, not any-char)" {
        $lines = @('0.0.0.0 evilXexampleXcom # a dot got treated as a literal X, should NOT match')
        Test-AlreadySinkholed -ExistingLines $lines -TargetHost 'evil.example.com' | Should -Be $false
    }
}
