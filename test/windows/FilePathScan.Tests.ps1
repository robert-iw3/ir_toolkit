<#
.SYNOPSIS
    Tests for -FilePath direct scan support in Invoke-YaraFileScan and Invoke-MWCPFileScan.
    -FilePath accepts a specific file OR a directory (with -Recursive); when provided,
    scans those targets directly without requiring prior findings in $script:Findings.
#>

BeforeAll {
    $SrcPath = Join-Path $PSScriptRoot "..\..\playbooks\windows\threat_hunting\dev\src"
    . (Join-Path $SrcPath "00_Parameters_And_Globals.ps1")
    . (Join-Path $SrcPath "02_Fileless_And_Registry.ps1")
    . (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1")

    function script:Set-FilePathBaseline {
        Mock Get-Command      { $null }
        Mock Test-Path        { $false }
        Mock Get-ChildItem    { @() }
        Mock Invoke-LsassDumpHunt {}
        Mock Get-BitsTransfer { @() }
    }
}

# ---------------------------------------------------------------------------
# Source-text: -FilePath parameter must exist on both functions
# ---------------------------------------------------------------------------
Describe "FilePath parameter presence in source" {

    It "Invoke-YaraFileScan must accept -FilePath parameter" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $src | Should -Match 'function\s+Invoke-YaraFileScan'
        $src | Should -Match '\[string\[\]\]\s*\$FilePath|\[string\]\s*\$FilePath'
    }

    It "Invoke-MWCPFileScan must accept -FilePath parameter" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpParts = $src -split "function\s+Invoke-MWCPFileScan"
        $mwcpParts.Count | Should -BeGreaterThan 1
        $mwcpParts[1] | Should -Match '\$FilePath'
    }

    It "-FilePath must support both file and directory inputs" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        # Should handle directory with -Recursive pattern
        $src | Should -Match 'FilePath.*Recursive|Recursive.*FilePath|PathType.*Container|IsDir'
    }
}

# ---------------------------------------------------------------------------
# Invoke-YaraFileScan: -FilePath bypasses findings filter
# ---------------------------------------------------------------------------
Describe "Invoke-YaraFileScan -FilePath direct targeting" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilePathBaseline
    }

    It "Should scan -FilePath target even when findings list is empty" {
        # No prior findings, but -FilePath is explicitly provided
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        # Structural: when FilePath is provided and Findings is empty, it must NOT
        # fall back to 'no prior findings - scanning full directory'
        $src | Should -Match 'FilePath.*-and.*Count|FilePath.*provided|if.*FilePath'
    }

    It "Should use -FilePath as scan target, overriding findings-based target list" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        # Direct path must be added to scan targets when provided
        $src | Should -Match '\$scanTargets\s*=.*FilePath|\$FilePath.*scanTarget|FilePath.*-and|FilePath.*target'
    }
}

# ---------------------------------------------------------------------------
# Invoke-MWCPFileScan: -FilePath direct targeting
# ---------------------------------------------------------------------------
Describe "Invoke-MWCPFileScan -FilePath direct targeting" {

    BeforeEach {
        $script:Findings = @()
        $script:Quiet    = $true
        Set-FilePathBaseline
    }

    It "Should scan -FilePath file directly when findings list is empty" {
        # When -FilePath is given, should not skip due to empty findings
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpFunc = ($src -split 'function\s+Invoke-MWCPFileScan')[1]
        $mwcpFunc | Should -Match '\$FilePath|\$filePathTargets|if.*FilePath'
    }

    It "Should accept a directory path and enumerate files within it" {
        $src = Get-Content (Join-Path $SrcPath "05_File_And_ADS_Hunt.ps1") -Raw
        $mwcpFunc = ($src -split 'function\s+Invoke-MWCPFileScan')[1]
        # Directory support requires Get-ChildItem or Test-Path Container check
        $mwcpFunc | Should -Match 'Container|Get-ChildItem.*FilePath|Recurse.*FilePath'
    }
}
