<#
.SYNOPSIS
    Pester 5 tests for the Prefetch/Autoruns corroboration pass in Get-FindingContext.ps1
    (Batch 3 item 8: prefetch_listing.csv and autoruns_all.csv were already collected by
    00_Collect-Forensics.ps1 but had zero consumer -- collected, never analyzed).

    Follows RunToDelta.Tests.ps1's established pattern for this file: re-implement the
    core matching logic standalone (fast, no fixture/zip setup needed) plus structural
    markers confirming the real script contains the same key pieces.
#>

BeforeAll {
    $Script:ContextScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Get-FindingContext.ps1'
    $Script:Content = Get-Content -LiteralPath $Script:ContextScript -Raw
}

Describe "Prefetch/Autoruns corroboration -- script structure" {

    It "Get-FindingContext.ps1 contains the prefetch/autoruns correlation pass" {
        $Script:Content | Should -Match 'prefetch_listing'
        $Script:Content | Should -Match 'autoruns_all'
        $Script:Content | Should -Match 'PREFETCH:'
        $Script:Content | Should -Match 'AUTORUNS:'
    }

    It "Only runs for already-confirmed TP-class verdicts (not identity/name-only matching)" {
        # The gate must reference both TP-class verdicts before doing any correlation
        $Script:Content | Should -Match "Verdict -notin @\('True Positive','Likely True Positive'\)"
    }

    It "Autoruns match requires a SubjectPath (not name-only matching)" {
        # $subjectPath must gate the autoruns lookup -- avoids the coreAllowed/
        # LISTENER_ALLOWLIST class of mistake (bare name match with no path evidence)
        $Script:Content | Should -Match '\$autorunsRows\.Count -and \$subjectPath'
    }
}

Describe "Prefetch correlation -- unit logic" {

    It "Matches prefetch entries by full base name incl. extension (case-insensitive)" {
        # Prefetch filenames are '<ORIGINAL_FILENAME_INCL_EXTENSION>-<hash>.pf' -- the
        # match must be against the base name WITH its extension, not the stripped stem,
        # or a real .exe name never matches its own prefetch entry (caught by this test
        # failing against the original stem-only regex before the fix).
        $baseName = 'evil.exe'
        $prefetchRows = @(
            [PSCustomObject]@{ Name = 'EVIL.EXE-A1B2C3D4.pf'; CreationTime = '1/1/2026 10:00:00 AM'; LastWriteTime = '1/2/2026 3:00:00 PM' }
            [PSCustomObject]@{ Name = 'NOTEPAD.EXE-FFFFFFFF.pf'; CreationTime = '1/1/2026 9:00:00 AM'; LastWriteTime = '1/1/2026 9:00:00 AM' }
        )
        $hits = @($prefetchRows | Where-Object { $_.Name -match "(?i)^$([regex]::Escape($baseName))-" })
        $hits.Count | Should -Be 1
        $hits[0].Name | Should -Be 'EVIL.EXE-A1B2C3D4.pf'
    }

    It "Does not match an unrelated executable name (no false cross-match)" {
        $baseName = 'notepad.exe'
        $prefetchRows = @([PSCustomObject]@{ Name = 'EVIL.EXE-A1B2C3D4.pf' })
        $hits = @($prefetchRows | Where-Object { $_.Name -match "(?i)^$([regex]::Escape($baseName))-" })
        $hits.Count | Should -Be 0
    }

    It "Picks earliest CreationTime as first execution across multiple prefetch entries" {
        $pfHits = @(
            [PSCustomObject]@{ CreationTime = '1/5/2026 10:00:00 AM' }
            [PSCustomObject]@{ CreationTime = '1/1/2026 8:00:00 AM' }
        )
        $earliest = ($pfHits | Sort-Object { [datetime]$_.CreationTime } | Select-Object -First 1).CreationTime
        $earliest | Should -Be '1/1/2026 8:00:00 AM'
    }

    It "A verdict below TP-class (Indeterminate) must not be enriched" {
        $results = @([PSCustomObject]@{ Verdict = 'Indeterminate'; SubjectPath = 'C:\Windows\Temp\evil.exe'; Notes = '' })
        $TpClass = @('True Positive','Likely True Positive')
        $eligible = @($results | Where-Object { $_.Verdict -in $TpClass })
        $eligible.Count | Should -Be 0
    }

    It "A True Positive verdict IS eligible for enrichment" {
        $results = @([PSCustomObject]@{ Verdict = 'True Positive'; SubjectPath = 'C:\Windows\Temp\evil.exe'; Notes = '' })
        $TpClass = @('True Positive','Likely True Positive')
        $eligible = @($results | Where-Object { $_.Verdict -in $TpClass })
        $eligible.Count | Should -Be 1
    }
}

Describe "Autoruns correlation -- unit logic" {

    It "Matches autoruns entries by exact Image Path (case-insensitive)" {
        $subjectPath = 'C:\Windows\Temp\evil.exe'
        $autorunsRows = @(
            [PSCustomObject]@{ 'Image Path' = 'c:\windows\temp\evil.exe'; 'Entry Location' = 'HKLM\...\Run\Evil'; Category = 'Logon'; Enabled = 'enabled' }
            [PSCustomObject]@{ 'Image Path' = 'C:\Windows\System32\svchost.exe'; 'Entry Location' = 'Services'; Category = 'Boot Execute'; Enabled = 'enabled' }
        )
        $hits = @($autorunsRows | Where-Object { $_.'Image Path' -and $_.'Image Path'.Trim().ToLower() -eq $subjectPath.Trim().ToLower() })
        $hits.Count | Should -Be 1
        $hits[0].'Entry Location' | Should -Be 'HKLM\...\Run\Evil'
    }

    It "Does not match a different executable's autorun entry" {
        $subjectPath = 'C:\Windows\Temp\evil.exe'
        $autorunsRows = @([PSCustomObject]@{ 'Image Path' = 'C:\Windows\System32\svchost.exe'; 'Entry Location' = 'Services' })
        $hits = @($autorunsRows | Where-Object { $_.'Image Path' -and $_.'Image Path'.Trim().ToLower() -eq $subjectPath.Trim().ToLower() })
        $hits.Count | Should -Be 0
    }

    It "Blank/missing Image Path entries never match (avoids null-vs-empty-string false match)" {
        $subjectPath = 'C:\Windows\Temp\evil.exe'
        $autorunsRows = @([PSCustomObject]@{ 'Image Path' = ''; 'Entry Location' = 'Logon' })
        $hits = @($autorunsRows | Where-Object { $_.'Image Path' -and $_.'Image Path'.Trim().ToLower() -eq $subjectPath.Trim().ToLower() })
        $hits.Count | Should -Be 0
    }
}
