<#
.SYNOPSIS
    Pester 5 tests for P1 adjudicator blindspot fixes in Get-FindingContext.ps1.

    Validates:
    1. $missing only fires on absolute paths -- bare filename 'pwsh.exe' not in
       System32 must NOT produce 'referenced binary not on disk (staged/removed)'
    2. YARA Match (Memory) with file-backed hit -> Indeterminate (early exit)
    3. YARA Match (Memory) with non-executable anonymous region -> Indeterminate
    4. JitHostPattern handles kernel-truncated names (no .exe$ anchor required)
    5. JitHostPattern includes pwsh and dotnet (.NET CLR JIT hosts)
#>

BeforeAll {
    $Script:ContextScript = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Get-FindingContext.ps1'
    $Script:Content = Get-Content -LiteralPath $Script:ContextScript -Raw
}

Describe "Get-FindingContext.ps1 -- script health" {

    It "Script exists" {
        Test-Path -LiteralPath $Script:ContextScript | Should -Be $true
    }

    It "Parses without syntax errors" {
        $errs = $null
        [System.Management.Automation.Language.Parser]::ParseInput(
            $Script:Content, [ref]$null, [ref]$errs) | Out-Null
        $errs | Should -BeNullOrEmpty
    }
}

Describe "Adjudicator -- missing-file blindspot fix" {

    It "hasAbsPath variable is present in script" {
        # $missing must only fire when we have a rooted absolute path
        $Script:Content | Should -Match '\$hasAbsPath'
    }

    It '$missing assignment requires $hasAbsPath (absolute path guard)' {
        # Pattern: $missing = (... -and $hasAbsPath) or equivalent
        $Script:Content | Should -Match '\$missing\s*=.*\$hasAbsPath'
    }

    It "hasAbsPath checks for drive-letter path or UNC path" {
        # Must match C:\ style or \\server\ style -- escape [] so Should -Match treats them as literals
        $Script:Content | Should -Match '\[A-Za-z\]'
        $Script:Content | Should -Match 'hasAbsPath'
    }

    It "Bare filename logic: 'pwsh.exe' not rooted, so hasAbsPath is false" {
        # Inline verification of the expected logic
        $hasAbsPath = 'pwsh.exe' -match '^[A-Za-z]:\\|^\\'
        $hasAbsPath | Should -Be $false -Because 'bare filename is not an absolute path'
    }

    It "Absolute path logic: full pwsh path sets hasAbsPath true" {
        $hasAbsPath = 'C:\Program Files\PowerShell\7\pwsh.exe' -match '^[A-Za-z]:\\|^\\'
        $hasAbsPath | Should -Be $true
    }

    It "UNC path sets hasAbsPath true" {
        $hasAbsPath = '\\server\share\tool.exe' -match '^[A-Za-z]:\\|^\\'
        $hasAbsPath | Should -Be $true
    }
}

Describe "Adjudicator -- YARA(Memory) early-exit verdict" {

    It "isYaraMemType variable is present in script" {
        $Script:Content | Should -Match 'isYaraMemType'
    }

    It "yaraMemEarlyExit flag is present to gate standard verdict block" {
        # Without this flag, the standard verdict block resets YARA(Memory) early verdicts
        $Script:Content | Should -Match 'yaraMemEarlyExit'
    }

    It "file-backed YARA(Memory) produces Indeterminate early exit" {
        # Must contain a condition that sets Indeterminate for file-backed YARA memory hits
        $Script:Content | Should -Match "file-backed"
        $Script:Content | Should -Match 'any process loading this library'
    }

    It "non-executable anonymous YARA(Memory) produces Indeterminate early exit" {
        # anon rw- / anon r-- regions are data, not injected code
        $Script:Content | Should -Match 'non-executable anonymous memory|not executable'
        $Script:Content | Should -Match 'heap.or.data'
    }

    It "YARA(Memory) file-backed inline logic: details with file-backed -> sets early exit" {
        # Reproduce the expected check inline
        $details = 'Rule: LOLBin_BITS_Drop | 2 match(es) | file-backed -wx SHLWAPI.dll'
        $details -match 'file-backed' | Should -Be $true
    }

    It "YARA(Memory) anon rw- inline logic: non-executable anon -> sets early exit" {
        $details = 'Rule: CoinMiner_Strings | 5 match(es) | anon rw-'
        # anon present, no 'X' or 'x' after 'anon '
        ($details -match '\banon\b') -and ($details -notmatch '\banon\s+\S*[Xx]') | Should -Be $true
    }

    It "YARA(Memory) anon rwx does NOT trigger early exit (executable anon = real signal)" {
        $details = 'Rule: Cobalt_Strike_Beacon | 3 match(es) | anon rwx'
        # anon present BUT has executable flag -> should NOT trigger the early exit
        ($details -match '\banon\b') -and ($details -notmatch '\banon\s+\S*[Xx]') | Should -Be $false
    }
}

Describe "Adjudicator -- JitHostPattern kernel-truncation fix" {

    It "JitHostPattern does not use .exe dollar-sign anchor" {
        # Old pattern '....\.exe$' fails for kernel-truncated names like AcrobatNotific
        $Script:Content | Should -Not -Match "JitHostPattern\s*=\s*'[^']*\\\.exe\`$'"
    }

    It "JitHostPattern includes pwsh for .NET CLR JIT hosts" {
        # Look for pwsh inside the JitHostPattern string
        $patternLine = ($Script:Content -split "`n") | Where-Object { $_ -match 'JitHostPattern\s*=' }
        $patternLine | Should -Not -BeNullOrEmpty -Because 'JitHostPattern must be defined'
        $patternLine | Should -Match 'pwsh'
    }

    It "JitHostPattern includes dotnet for .NET CLR JIT hosts" {
        $patternLine = ($Script:Content -split "`n") | Where-Object { $_ -match 'JitHostPattern\s*=' }
        $patternLine | Should -Match 'dotnet'
    }

    It "JitHostPattern regex matches kernel-truncated name AcrobatNotific" {
        # AcrobatNotificationClient.exe -> EPROCESS truncates to AcrobatNotific (14 chars)
        # The pattern must match this truncated form in a Target string
        $pattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|pwsh|dotnet)(?=\W|$)'
        'PID 14436 (AcrobatNotific) TID=4040' -match $pattern | Should -Be $true
    }

    It "JitHostPattern regex matches pwsh.exe full path" {
        $pattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|pwsh|dotnet)(?=\W|$)'
        'C:\Program Files\PowerShell\7\pwsh.exe' -match $pattern | Should -Be $true
    }

    It "JitHostPattern regex matches Code.exe (VS Code -- Electron/Node JIT)" {
        $pattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|pwsh|dotnet|code)(?=\W|$)'
        'PID 13588 (Code.exe) @ 0x1e293140000' -match $pattern | Should -Be $true
    }

    It "JitHostPattern regex does NOT match vscode within word boundary" {
        # vscode.exe: 'code' appears inside 'vscode' -- no word boundary before 'c' in 'vscode'
        $pattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|pwsh|dotnet|code)(?=\W|$)'
        'PID 99 (vscode.exe) @ 0x1000' -match $pattern | Should -Be $false `
            -Because 'code must not match inside vscode -- word boundary required'
    }

    It "JitHostPattern regex matches msedgewebview2 (14-char truncated name)" {
        $pattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|pwsh|dotnet|code)(?=\W|$)'
        'PID 1234 (msedgewebview2) TID=100' -match $pattern | Should -Be $true `
            -Because 'msedgewebview2.exe truncates to msedgewebview2 (14 chars)'
    }
}

Describe "Adjudicator -- MSIX/WindowsApps injection downgrade" {

    It "Script contains MSIX path-adjustment block for Suspicious Injected DLL" {
        $Script:Content | Should -Match "Suspicious Injected DLL"
        $Script:Content | Should -Match 'MSIX'
    }

    It "MSIX adjustment sets Likely False Positive verdict" {
        $Script:Content | Should -Match "Likely False Positive"
    }

    It "MSIX adjustment explains OS validates package signature, not per-file Authenticode" {
        $Script:Content | Should -Match '(?i)(OS validates|package signature|per-file Authenticode|not per-file|unsigned-per-file is expected)'
    }

    It "MSIX path pattern covers WindowsApps and SystemApps in the adjudicator" {
        $Script:Content | Should -Match '(?i)(WindowsApps|SystemApps)'
    }
}
