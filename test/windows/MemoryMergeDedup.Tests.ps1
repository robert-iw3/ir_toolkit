<#
.SYNOPSIS
    Pester 5 regression guard: Analyze-Memory.ps1 -Adjudicate must not double-count
    findings when re-run in a directory that already has a Combined_Findings JSON.

    Root cause of the original bug:
        Merge-FindingSets is a plain concat (by design).  The -Adjudicate block
        loaded $existing from the most recent Combined_Findings, which already
        contained all memory findings from a prior run, then concatenated the new
        memory findings on top -- producing exactly 2x every finding count.

    Fix required:
        Strip memory-typed findings from $existing before the merge so the new
        memory scan REPLACES the old memory findings rather than appending to them.
        Non-memory findings (persistence, events, amcache, etc.) are preserved.
#>

BeforeAll {
    $Script:MemScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Analyze-Memory.ps1'
    $Script:Raw = Get-Content -LiteralPath $Script:MemScript -Raw
}

Describe "Analyze-Memory -Adjudicate: prior-run memory finding deduplication" {

    It "re-assigns existing to a filtered subset before merging with new memory findings" {
        # Without this guard re-running -Adjudicate in a dir that already has a
        # Combined_Findings doubles every finding count.
        $Script:Raw | Should -Match '\$existing\s*=.*Where-Object'
    }

    It "filter pattern covers the (Memory) type suffix used by most memory module types" {
        # Nearly all memory finding types end with (Memory); the filter must match them
        # by pattern so future module additions are covered automatically.
        $Script:Raw | Should -Match 'notmatch.*Memory'
    }

    It "filter pattern explicitly covers Injected Memory Region (no (Memory) suffix)" {
        # 'Injected Memory Region' is the one memory finding type that does NOT end
        # in (Memory); it must be named explicitly in the notmatch pattern.
        $Script:Raw | Should -Match 'notmatch.*Injected Memory Region'
    }
}
