<#
.SYNOPSIS
    Pester 5 tests for the Batch 5 Volatility-branch additions to Analyze-Memory.ps1:
      windows.privileges (TTP-015 token theft / privilege escalation)
      windows.callbacks  (TTP-016 kernel notify callback anomalies)

    These are structural/wiring tests plus behavioral extraction of the pure
    filtering expressions (no vol.exe, image, or admin rights needed) -- same
    approach as MemoryYaraVolatility.Tests.ps1 and MemoryAnalysisRouting.Tests.ps1.
#>

BeforeAll {
    $Script:MemScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Analyze-Memory.ps1'
    $Script:Src        = Get-Content -LiteralPath $Script:MemScript -Raw

    function Script:Get-SectionBlock([string]$StartMarker, [string]$EndMarker) {
        $s = $Script:Src.IndexOf($StartMarker)
        if ($s -lt 0) { return $null }
        $e = $Script:Src.IndexOf($EndMarker, $s)
        if ($e -lt 0) { $e = $Script:Src.Length }
        return $Script:Src.Substring($s, $e - $s)
    }
}

Describe "Analyze-Memory Volatility branch — windows.privileges wiring (TTP-015)" {

    It "Runs windows.privileges in the Volatility path" {
        $Script:Src | Should -Match 'windows\.privileges'
    }

    It "Is gated by the 'privileges' skip key" {
        $Script:Src | Should -Match "'privileges' -notin \`$skipSet"
    }

    It "Only flags a fixed set of high-impact privileges" {
        $block = Get-SectionBlock '-- 9. Token privilege' '-- 10. Kernel callback'
        $block | Should -Not -BeNullOrEmpty
        foreach ($p in 'SeDebugPrivilege','SeTcbPrivilege','SeImpersonatePrivilege') {
            $block | Should -Match $p
        }
    }

    It "Produces the 'Token Privilege Runtime-Enabled (Memory)' finding type" {
        $Script:Src | Should -Match 'Token Privilege Runtime-Enabled \(Memory\)'
    }

    It "Excludes EnabledByDefault privileges (baseline OS behavior, not a signal)" {
        $block = Get-SectionBlock '-- 9. Token privilege' '-- 10. Kernel callback'
        $block | Should -Match 'isByDefault'
        $block | Should -Match '-not \$isEnabled -or \$isByDefault'
    }
}

Describe "windows.privileges filter — behavioral (Enabled-but-not-Default)" {

    BeforeAll {
        $m = [regex]::Match($Script:Src, "(?s)\`$isEnabled\s+=\s+\`$attrs -match '[^']+'\r?\n\s+\`$isByDefault\s+=\s+\`$attrs -match '[^']+'")
        $m.Success | Should -BeTrue -Because 'the isEnabled/isByDefault expressions must exist verbatim in source'
        Set-Variable -Scope Script -Name FilterSrc -Value $m.Value
    }

    function Script:Test-PrivilegeFlagged([string]$Attrs) {
        $attrs = $Attrs
        Invoke-Expression $Script:FilterSrc
        return (-not (-not $isEnabled -or $isByDefault))   # mirrors the 'continue if' guard, inverted
    }

    It "Flags a privilege that is Enabled but not EnabledByDefault" {
        Test-PrivilegeFlagged 'Enabled' | Should -BeTrue
    }

    It "Does NOT flag a privilege that is EnabledByDefault" {
        Test-PrivilegeFlagged 'Enabled, Default' | Should -BeFalse
    }

    It "Does NOT flag a privilege that is merely Present (not enabled)" {
        Test-PrivilegeFlagged 'Present' | Should -BeFalse
    }
}

Describe "Analyze-Memory Volatility branch — windows.callbacks wiring (TTP-016)" {

    It "Runs windows.callbacks in the Volatility path" {
        $Script:Src | Should -Match 'windows\.callbacks'
    }

    It "Is gated by the 'callbacks' skip key" {
        $Script:Src | Should -Match "'callbacks' -notin \`$skipSet"
    }

    It "Produces the 'Unbacked Kernel Callback (Memory)' finding type" {
        $Script:Src | Should -Match 'Unbacked Kernel Callback \(Memory\)'
    }

    It "Flags only callbacks unresolved to a loaded driver module (not by name)" {
        $block = Get-SectionBlock '-- 10. Kernel callback' '}   # end else'
        $block | Should -Not -BeNullOrEmpty
        $block | Should -Match 'unresolved'
    }
}

Describe "windows.callbacks filter — behavioral (unresolved module)" {

    BeforeAll {
        $m = [regex]::Match($Script:Src, "\`$unresolved = \(-not \`$module\) -or \(\`$module -match '[^']+'\)")
        $m.Success | Should -BeTrue -Because 'the unresolved-module expression must exist verbatim in source'
        Set-Variable -Scope Script -Name UnresolvedSrc -Value $m.Value
    }

    function Script:Test-CallbackUnresolved([string]$Module) {
        $module = $Module
        Invoke-Expression $Script:UnresolvedSrc
        return $unresolved
    }

    It "Flags an empty module (no resolution at all)" {
        Test-CallbackUnresolved '' | Should -BeTrue
    }

    It "Flags a literal 'UNKNOWN' module" {
        Test-CallbackUnresolved 'UNKNOWN' | Should -BeTrue
    }

    It "Does NOT flag a real driver module name" {
        Test-CallbackUnresolved 'ntoskrnl.exe' | Should -BeFalse
        Test-CallbackUnresolved 'ci.dll' | Should -BeFalse
    }
}

Describe "Analyze-Memory.ps1 — still parses cleanly after Batch 5 additions" {
    It "Has zero AST parse errors" {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $Script:MemScript, [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }
}
