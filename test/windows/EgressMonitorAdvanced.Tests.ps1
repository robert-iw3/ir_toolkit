#Requires -Module Pester
<#
.SYNOPSIS
    Pester tests for egress_monitor/ (advanced beacon detection daemon).
    Covers: file presence, beacon_classifier safety, carve API correctness,
    daemon sequencing, Build-OfflineToolkit staging, Invoke-IRCollection wiring.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param()

# Pester 5: variables accessible inside It/Describe blocks need $script: prefix
# and must be set in BeforeAll, not at script scope.
#
# IMPORTANT naming: PS variables are case-insensitive. Path vars ($script:PathPS1)
# and content vars ($script:cPS1) are deliberately named differently to avoid collision.
BeforeAll {
    $script:Root        = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName
    $script:EgressDir   = Join-Path $script:Root 'playbooks\windows\threat_hunting\egress_monitor'
    $script:PathPS1     = Join-Path $script:EgressDir 'Start-EgressMonitor.ps1'
    $script:PathClassifier = Join-Path $script:EgressDir 'beacon_classifier.py'
    $script:PathMonitor    = Join-Path $script:EgressDir 'egress_monitor.py'
    $script:PathCarve      = Join-Path $script:EgressDir 'carve_and_scan.py'
    $script:PathBuild      = Join-Path $script:Root 'Build-OfflineToolkit.ps1'
    $script:PathInvoke     = Join-Path $script:Root 'Invoke-IRCollection.ps1'

    if (-not (Test-Path $script:PathBuild)) {
        throw "RootPath wrong: $($script:Root)"
    }

    # Pre-read source content into distinctly-named vars (c-prefix = content)
    $script:cPS1        = Get-Content $script:PathPS1        -Raw -ErrorAction SilentlyContinue
    $script:cClassifier = Get-Content $script:PathClassifier -Raw -ErrorAction SilentlyContinue
    $script:cMonitor    = Get-Content $script:PathMonitor    -Raw -ErrorAction SilentlyContinue
    $script:cCarve      = Get-Content $script:PathCarve      -Raw -ErrorAction SilentlyContinue
    $script:cBuild      = Get-Content $script:PathBuild      -Raw -ErrorAction SilentlyContinue
    $script:cInvoke     = Get-Content $script:PathInvoke     -Raw -ErrorAction SilentlyContinue

    # Extract active (non-comment) BROWSER_LIKE_PROCS content for injection safety tests
    $bm = [regex]::Match($script:cClassifier, '(?s)BROWSER_LIKE_PROCS\s*=\s*\{(.+?)\}')
    $script:activeProcs = if ($bm.Success) {
        ($bm.Groups[1].Value -split "`n" |
         Where-Object { $_ -notmatch '^\s*#' -and $_ -match "'" }) -join ' '
    } else { '' }
}

Describe 'Advanced EgressMonitor - File Presence' {
    It 'Start-EgressMonitor.ps1 exists' { Test-Path $script:PathPS1        | Should -BeTrue }
    It 'egress_monitor.py exists'       { Test-Path $script:PathMonitor    | Should -BeTrue }
    It 'beacon_classifier.py exists'    { Test-Path $script:PathClassifier | Should -BeTrue }
    It 'carve_and_scan.py exists'       { Test-Path $script:PathCarve      | Should -BeTrue }
}

Describe 'Advanced EgressMonitor - Injection Target Safety (beacon_classifier.py)' {
    $injectionTargets = @(
        'svchost', 'lsass', 'taskhostw', 'rundll32', 'regsvr32',
        'powershell', 'pwsh', 'explorer', 'dllhost', 'msiexec',
        'wscript', 'cscript', 'mshta', 'wmic', 'cmd'
    )
    foreach ($proc in $injectionTargets) {
        It "BROWSER_LIKE_PROCS must NOT contain '$proc'" {
            $script:activeProcs | Should -Not -Match "'$proc'"
        }
    }
    It 'BROWSER_LIKE_PROCS contains a reference browser entry (chrome)' {
        $script:activeProcs | Should -Match "'chrome'"
    }
}

Describe 'Advanced EgressMonitor - Long-dwell / Jitter blind spots (beacon_classifier.py)' {
    It 'MAX_INTERVAL_SEC >= 3 days (no APT blind spot)' {
        $script:cClassifier | Should -Match 'MAX_INTERVAL_SEC\s*=\s*3\s*\*\s*24\s*\*\s*3600'
    }
    It 'MIN_SAMPLES_FOR_INTERVAL <= 2 (long-dwell beacons seen twice still scored)' {
        $script:cClassifier | Should -Match 'MIN_SAMPLES_FOR_INTERVAL\s*=\s*[12]\b'
    }
    It 'IQR-based variation used (robust to high-jitter configs)' {
        $script:cClassifier | Should -Match '_iqr_variation'
    }
    It 'MONITOR verdict exists so single-event connections are not silently CLEAN' {
        $script:cClassifier | Should -Match "'MONITOR'"
    }
    It 'Layer 0 pre-flagged PID logic exists' {
        $script:cClassifier | Should -Match 'pre_flagged_pids'
    }
    It 'UA spoofing comment present (explains process-name vs UA-header distinction)' {
        $script:cClassifier | Should -Match 'UA.*spoof|spoofed.*UA|User-Agent.*header|process.*name.*not.*UA'
    }
}

Describe 'Advanced EgressMonitor - carve_and_scan.py API correctness' {
    It 'calls proc.maps.vad() as a method (parentheses required)' {
        $script:cCarve | Should -Match 'proc\.maps\.vad\(\)'
    }
    It 'uses proc.memory.read() in code (not .file_data)' {
        # Check active code lines only -- docstring may mention .file_data as a warning
        $activeLines = ($script:cCarve -split "`n") |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*"""' -and $_ -notmatch '^\s*NOT' }
        $activeLines -join "`n" | Should -Not -Match '\.file_data\s*\)'
    }
    It 'passes --filelist to mwcp_scan.py (avoids Windows 32KB cmdline limit)' {
        $script:cCarve | Should -Match '\-\-filelist'
    }
    It 'blackhole logic is NOT in carve_and_scan.py (daemon controls timing)' {
        $script:cCarve | Should -Not -Match 'advfirewall|DefaultOutboundAction\s*Block'
    }
}

Describe 'Advanced EgressMonitor - egress_monitor.py sequencing' {
    It 'carve call appears before blackhole call in source (correct sequencing)' {
        # Use the CALL site (not the function def): carve_and_scan.run( then _blackhole_ip(ip,
        $carveIdx = $script:cMonitor.IndexOf('carve_and_scan.run(')
        $bhIdx    = $script:cMonitor.IndexOf('_blackhole_ip(ip,')   # call, not definition
        $carveIdx | Should -Not -Be -1
        $bhIdx    | Should -Not -Be -1
        $carveIdx | Should -BeLessThan $bhIdx
    }
    It 'BEACON_DETECTED event string exists in monitor source' {
        $script:cMonitor | Should -Match "'BEACON_DETECTED'"
    }
    It '_append_evidence is called in the beacon detection section' {
        $script:cMonitor | Should -Match "_append_evidence\(out_dir, det_record\)"
    }
    It 'CARVE_COMPLETE event string exists in monitor source' {
        $script:cMonitor | Should -Match "'CARVE_COMPLETE'"
    }
    It 'BLACKHOLE_APPLIED event string exists in monitor source' {
        $script:cMonitor | Should -Match "'BLACKHOLE_APPLIED'"
    }
    It 'duration=0 runs indefinitely' {
        $script:cMonitor | Should -Match "float\('inf'\)"
    }
    It 'netstat fallback exists when MemProcFS unavailable' {
        $script:cMonitor | Should -Match 'Get-NetTCPConnection|netstat'
    }
}

Describe 'Advanced EgressMonitor - Start-EgressMonitor.ps1 structure' {
    It 'WindowHours parameter present' {
        $script:cPS1 | Should -Match '\$WindowHours'
    }
    It 'WindowHours validated 0-72' {
        $script:cPS1 | Should -Match 'ValidateRange'
    }
    It 'Deploy-ToStateDir called on Start' {
        $script:cPS1 | Should -Match 'Deploy-ToStateDir'
    }
    It 'registers scheduled task for Python daemon' {
        $script:cPS1 | Should -Match 'Register-ScheduledTask'
    }
    It 'has -Collect mode for reading evidence' {
        $script:cPS1 | Should -Match "'Collect'"
    }
    It 'deploys mwcp_scan.py to StateDir' {
        $script:cPS1 | Should -Match 'mwcp_scan\.py'
    }
    It 'passes --blackhole-on-confirm flag to Python daemon' {
        $script:cPS1 | Should -Match 'blackhole.on.confirm'
    }
}

Describe 'Advanced EgressMonitor - Build-OfflineToolkit.ps1 stages egress tools' {
    It 'references IncludeEgressMonitor flag' {
        $script:cBuild | Should -Match 'IncludeEgressMonitor|IncludeEgress'
    }
    It 'stages memprocfs into egress_monitor tools' {
        $script:cBuild | Should -Match '(?s)IncludeEgressMonitor.{1,2000}memprocfs'
    }
    It 'stages mwcp into egress_monitor tools' {
        $script:cBuild | Should -Match '(?s)IncludeEgressMonitor.{1,2000}mwcp'
    }
}

Describe 'Advanced EgressMonitor - Invoke-IRCollection.ps1 wiring' {
    It 'references Start-EgressMonitor.ps1' {
        $script:cInvoke | Should -Match 'Start-EgressMonitor'
    }
    It 'passes FlaggedPid from enrichment to advanced monitor' {
        $script:cInvoke | Should -Match 'FlaggedPid|flaggedPids|flagged.pid'
    }
    It 'passes BlackholeOnConfirm flag' {
        $script:cInvoke | Should -Match 'BlackholeOnConfirm'
    }
}
