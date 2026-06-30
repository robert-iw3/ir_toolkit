<#
.SYNOPSIS
    Tests for mwcp scan performance improvements:
    Fix 1 -- Large-file skip with user warning (not extension filter -- pdfs/jpgs can carry config)
    Fix 2 -- Batch file list in a single mwcp_scan.py call (eliminate per-file subprocess overhead)
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")
    . (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1")

    $script:MwcpScan = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\mwcp_scan.py"

    function script:Set-PerfBaseline {
        Mock Get-Command      { $null }
        Mock Test-Path        { $false }
        Mock Get-ChildItem    { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Get-BitsTransfer { @() }
    }
}

# ---------------------------------------------------------------------------
# Fix 1: Large-file skip with user warning
# Rationale: PDFs/JPGs/docs CAN carry embedded config -- don't filter by type.
# Skip only files above a size threshold; alert analyst to do a one-off scan.
# ---------------------------------------------------------------------------
Describe "Fix-1 Large-file skip: warn analyst, skip multi-GB files in directory mode" {

    It "mwcp_scan.py must have a size threshold concept" {
        $src = Get-Content $script:MwcpScan -Raw
        # Should reference a file size limit somewhere in the scan logic
        $src | Should -Match 'size|getsize|stat|length|MAX_FILE|max_size|too.large'
    }

    It "Invoke-MWCPFileScan source must skip files above a size threshold with warning" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpFunc = ($src -split 'function\s+Invoke-MWCPFileScan')[1]
        $mwcpFunc | Should -Match 'Length|size.*MB|MB.*size|MaxSize|large.*file|skip.*large'
    }

    It "Invoke-MWCPFileScan source must warn user about skipped large files" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpFunc = ($src -split 'function\s+Invoke-MWCPFileScan')[1]
        # Should print a message telling the user to do a one-off scan
        $mwcpFunc | Should -Match 'one.off|FilePath.*directly|too large|skipping.*large'
    }
}

# ---------------------------------------------------------------------------
# Fix 2: Batch mode -- single Python process for multiple files
# ---------------------------------------------------------------------------
Describe "Fix-2 Batch mode: multiple files in one mwcp_scan.py invocation" {

    It "mwcp_scan.py must accept multiple file paths from argv[3:] for batch mode" {
        $src = Get-Content $script:MwcpScan -Raw
        $src | Should -Match 'sys\.argv\[3:\]|argv\[3\]|file_paths|files\s*='
    }

    It "mwcp_scan.py batch output must be a JSON array (one entry per file)" {
        $src = Get-Content $script:MwcpScan -Raw
        $src | Should -Match 'results\.append|json_list|output.*list|json\.dumps\(results\)'
    }

    It "Invoke-MWCPFileScan source must use --filelist to pass targets (avoids Windows 32KB cmdline limit)" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpFunc = ($src -split 'function\s+Invoke-MWCPFileScan')[1]
        # Must write to a temp file and pass via --filelist, not raw @targets on argv
        $mwcpFunc | Should -Match '\-\-filelist|listFile|WriteAllLines'
    }
}

# ---------------------------------------------------------------------------
# Integration: graceful behavior
# ---------------------------------------------------------------------------
Describe "Invoke-MWCPFileScan: handles oversized files gracefully" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-PerfBaseline
    }

    It "Should not throw when all files exceed the size threshold" {
        Mock Test-Path { $true }
        $bigFiles = @(
            [PSCustomObject]@{ FullName='C:\dl\huge.zip'; Length=2GB; Extension='.zip' },
            [PSCustomObject]@{ FullName='C:\dl\bigvid.mp4'; Length=5GB; Extension='.mp4' }
        )
        Mock Get-ChildItem { $bigFiles } -ParameterFilter { $Path -match 'dl' }

        { Invoke-MWCPFileScan -FilePath 'C:\dl' -Recursive -Quiet } | Should -Not -Throw
    }

    It "Should not create mwcp Config Extraction findings for oversized files" {
        Mock Test-Path { $true }
        $bigFiles = @(
            [PSCustomObject]@{ FullName='C:\dl\huge.zip'; Length=2GB; Extension='.zip' }
        )
        Mock Get-ChildItem { $bigFiles } -ParameterFilter { $Path -match 'dl' }

        Invoke-MWCPFileScan -FilePath 'C:\dl' -Recursive -Quiet

        ($script:Findings | Where-Object { $_.Type -eq 'mwcp Config Extraction' }) |
            Should -HaveCount 0
    }
}
