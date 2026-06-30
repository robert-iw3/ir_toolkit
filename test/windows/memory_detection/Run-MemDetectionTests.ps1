<#
.SYNOPSIS
    Memory detection test orchestrator.

    Gate: unit tests (pytest + Pester) must all pass before live-image tests run.
    Live tests run each phase script against both captures in C:\captures\ and
    save timestamped JSON results to results\. A diff summary is printed after
    each live run so regressions and improvements are visible immediately.

.PARAMETER Phase
    Which phases to run. Comma-separated subset, e.g. 'A,B1,B5' or 'all' (default).

.PARAMETER SkipUnit
    Skip pytest + Pester unit tests and jump straight to live runs. Use only when
    iterating on live-test logic after unit tests already pass.

.PARAMETER SkipLive
    Run unit tests only -- do not open the memory images. Useful in CI.

.PARAMETER BaselineCapture
    If set, copies this run's results into results\baseline\ as the new expected
    baseline. Used after a detection has been validated and its output is confirmed.

.PARAMETER PythonExe
    Path to the bundled Python. Defaults to tools\memprocfs\python\python.exe.

.EXAMPLE
    .\Run-MemDetectionTests.ps1
    .\Run-MemDetectionTests.ps1 -Phase A,B5 -SkipUnit
    .\Run-MemDetectionTests.ps1 -SkipLive
    .\Run-MemDetectionTests.ps1 -BaselineCapture
#>
[CmdletBinding()]
param(
    [string]   $Phase           = 'all',
    [switch]   $SkipUnit,
    [switch]   $SkipLive,
    [switch]   $BaselineCapture,
    [string]   $PythonExe       = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root        = Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')
$TestDir     = $PSScriptRoot
$ResultsDir  = Join-Path $TestDir 'results'
$BaselineDir = Join-Path $ResultsDir 'baseline'
$UnitDir     = Join-Path $TestDir 'unit'
$PesterDir   = Join-Path $TestDir 'pester'
$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'

$Captures = @(
    'C:\captures\memory_GOTEM.aff4',
    'C:\captures\memory_GOTEM2.aff4'
)

# Phase -> script filename mapping
$PhaseScripts = [ordered]@{
    'A'  = 'phase_A_dormant_beacon.py'
    'B1' = 'phase_B1_process_hollowing.py'
    'B2' = 'phase_B2_apc_suspended.py'
    'B3' = 'phase_B3_dr7_hooks.py'
    'B4' = 'phase_B4_callstack_spoof.py'
    'B5' = 'phase_B5_ntdll_stubs.py'
    'B6' = 'phase_B6_ekko_correlation.py'
    'B7' = 'phase_B7_token_theft.py'
    'B8' = 'phase_B8_kernel_integrity.py'
    'B9' = 'phase_B9_peb_cmdline.py'
    'C1' = 'phase_C1_dll_sideload.py'
    'C2' = 'phase_C2_clr_assembly.py'
    'C3' = 'phase_C3_ppid_spoof.py'
    'C4' = 'phase_C4_com_vtable.py'
}

# Resolve which phases to run.
if ($Phase -eq 'all') {
    $ActivePhases = $PhaseScripts.Keys
} else {
    $ActivePhases = $Phase -split '\s*,\s*' | ForEach-Object { $_.Trim().ToUpper() }
    $bad = $ActivePhases | Where-Object { -not $PhaseScripts.Contains($_) }
    if ($bad) { throw "Unknown phase(s): $($bad -join ', '). Valid: $($PhaseScripts.Keys -join ', ')" }
}

# Resolve Python.
if (-not $PythonExe) {
    $PythonExe = Join-Path $Root 'tools\memprocfs\python\python.exe'
}
if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python not found at $PythonExe -- pass -PythonExe or stage MemProcFS"
}

$global:Passed  = 0
$global:Failed  = 0
$global:Skipped = 0

function Write-Header([string]$msg) {
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host $('=' * 70) -ForegroundColor Cyan
}

function Write-Step([string]$msg, [string]$color = 'White') {
    Write-Host "[*] $msg" -ForegroundColor $color
}

function Write-OK([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green;  $global:Passed++ }
function Write-Fail([string]$msg) { Write-Host "[-] $msg" -ForegroundColor Red;    $global:Failed++ }
function Write-Skip([string]$msg) { Write-Host "[~] $msg" -ForegroundColor Yellow; $global:Skipped++ }


# ==============================================================================
# STEP 1: Python unit tests (pytest)
# ==============================================================================
if (-not $SkipUnit) {
    Write-Header 'STEP 1: Python unit tests (pytest)'

    $pytestExe = (& $PythonExe -m pytest --version 2>&1 | Out-Null) ; $pytestExe = $PythonExe
    $unitArgs  = @('-m', 'pytest', $UnitDir, '-v', '--tb=short', '--no-header',
                   '--color=yes', '-p', 'no:cacheprovider')

    Write-Step "Running: $PythonExe $($unitArgs -join ' ')"
    $result = & $PythonExe @unitArgs 2>&1
    $result | ForEach-Object { Write-Host $_ }

    if ($LASTEXITCODE -eq 0) {
        Write-OK 'All pytest unit tests passed'
    } else {
        Write-Fail "pytest unit tests FAILED (exit $LASTEXITCODE)"
        if (-not $SkipLive) {
            Write-Host "`n[!] Halting: fix unit tests before running live-image tests." -ForegroundColor Red
            exit 1
        }
    }

    # ---------------------------------------------------------------------------
    # Pester tests
    # ---------------------------------------------------------------------------
    Write-Step 'Running Pester 5 tests...'
    try {
        $pesterMod = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $pesterMod -or $pesterMod.Version.Major -lt 5) {
            Write-Skip 'Pester 5 not available -- skipping PS unit tests (install: Install-Module Pester -Force)'
        } else {
            Import-Module Pester -RequiredVersion $pesterMod.Version -Force
            $pCfg = New-PesterConfiguration
            $pCfg.Run.Path       = $PesterDir
            $pCfg.Output.Verbosity = 'Detailed'
            $pCfg.Run.Exit       = $false
            $pResult = Invoke-Pester -Configuration $pCfg -PassThru
            if ($pResult.FailedCount -eq 0) {
                Write-OK "Pester: $($pResult.PassedCount) passed"
            } else {
                Write-Fail "Pester: $($pResult.FailedCount) failed / $($pResult.PassedCount) passed"
                if (-not $SkipLive) { exit 1 }
            }
        }
    } catch {
        Write-Skip "Pester run error: $_"
    }
}


# ==============================================================================
# STEP 2: Live-image tests
# ==============================================================================
if (-not $SkipLive) {
    Write-Header 'STEP 2: Live-image tests'
    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null

    foreach ($cap in $Captures) {
        if (-not (Test-Path -LiteralPath $cap)) {
            Write-Skip "Capture not found: $cap"
            continue
        }
        $capName = [System.IO.Path]::GetFileNameWithoutExtension($cap)
        Write-Header "Image: $capName"

        foreach ($phaseKey in $ActivePhases) {
            $script  = $PhaseScripts[$phaseKey]
            $outDir  = Join-Path $ResultsDir "${capName}_${phaseKey}_${Stamp}"
            $pyScript = Join-Path $TestDir $script

            if (-not (Test-Path -LiteralPath $pyScript)) {
                Write-Skip "Phase $phaseKey script not found: $pyScript"
                continue
            }

            Write-Step "Phase $phaseKey | $capName"
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $out = & $PythonExe $pyScript $cap $outDir 2>&1
                $sw.Stop()
                $out | ForEach-Object { Write-Host "    $_" }

                $jsonFiles = Get-ChildItem -Path $outDir -Filter '*.json' -ErrorAction SilentlyContinue
                $findings  = @()
                foreach ($jf in $jsonFiles) {
                    $findings += (Get-Content -LiteralPath $jf.FullName -Raw | ConvertFrom-Json)
                }

                $crit = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
                $high = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
                $med  = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count

                Write-OK ("Phase $phaseKey/$capName done in $($sw.Elapsed.TotalSeconds.ToString('F1'))s" +
                          " | Critical=$crit High=$high Medium=$med")

                # Compare against baseline if one exists.
                $baseFile = Join-Path $BaselineDir "${capName}_${phaseKey}.json"
                if (Test-Path -LiteralPath $baseFile) {
                    $baseline  = Get-Content -LiteralPath $baseFile -Raw | ConvertFrom-Json
                    $baseCount = @($baseline).Count
                    $nowCount  = @($findings).Count
                    $delta     = $nowCount - $baseCount
                    if ($delta -eq 0) {
                        Write-Host "    [=] Baseline match: $nowCount finding(s)" -ForegroundColor Gray
                    } elseif ($delta -gt 0) {
                        Write-Host "    [+] NEW findings vs baseline: +$delta (total $nowCount vs $baseCount)" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] FEWER findings vs baseline: $delta (total $nowCount vs $baseCount)" -ForegroundColor Yellow
                    }
                }

            } catch {
                $sw.Stop()
                Write-Fail "Phase $phaseKey/$capName FAILED: $_"
            }
        }
    }
}


# ==============================================================================
# STEP 3: Baseline update (optional)
# ==============================================================================
if ($BaselineCapture) {
    Write-Header 'STEP 3: Updating baseline'
    New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
    $allJson = Get-ChildItem -Path $ResultsDir -Filter '*.json' -Recurse -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -notlike "*\baseline\*" }
    foreach ($jf in $allJson) {
        $baseName = $jf.Name -replace '_\d{8}_\d{6}', ''   # strip timestamp
        $dest     = Join-Path $BaselineDir $baseName
        Copy-Item -LiteralPath $jf.FullName -Destination $dest -Force
        Write-Step "Baseline updated: $baseName"
    }
    Write-OK "Baseline files written to $BaselineDir"
}


# ==============================================================================
# Summary
# ==============================================================================
Write-Header 'Run Summary'
Write-Host "  Passed:  $global:Passed"  -ForegroundColor Green
Write-Host "  Failed:  $global:Failed"  -ForegroundColor $(if ($global:Failed) { 'Red' } else { 'Gray' })
Write-Host "  Skipped: $global:Skipped" -ForegroundColor Yellow

if ($global:Failed -gt 0) {
    Write-Host "`n[!] $global:Failed step(s) failed. Fix and re-run before rolling to production." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n[+] All steps passed." -ForegroundColor Green
}
