<#
.SYNOPSIS
    Offline IR collection orchestrator. Runs every collection-phase script and
    drops ALL artifacts into a folder named after the hostname, next to this
    script. Read-only: nothing is written to the system.

.DESCRIPTION
    End-to-end, single-command collection + enrichment. Every phase below runs
    automatically off one invocation; output lands in <hostname>\. Fully offline -
    no network calls. Pure built-in PowerShell except the two clearly-optional,
    staged-tool phases (1b Autoruns, 1d Memory), which auto-skip if not staged.

    Phases (automatic):
      1   Forensics snapshot ...... 00_Collect-Forensics.ps1
      1b  Extended persistence .... staged autorunsc (optional; auto-skips)
      1c  Persistence/config/NTFS . Get-PersistenceSnapshot.ps1 (pure PS: IFEO/
                                    Winlogon/LSA/AppInit, USN timeline, Amcache,
                                    full .evtx, firewall, auditpol, creds)
      1d  Memory image ............ staged winpmem (only with -CaptureMemory)
      2   Fileless/evasion hunt ... EDR_Toolkit.ps1
      2b  Remote-access triage .... Get-RemoteAccessTriage.ps1 (RMM/ClickFix/browser)
      3   Baseline tuning ......... Analyze-EDRReport.ps1
      -   Merge all findings ...... EDR + remote-access + persistence -> combined
      4   Adjudication ............ Get-FindingContext.ps1 -Live (proves TP/FP +
                                    acquires Evidence\ bundles)

    Sets process execution policy to Bypass for the run, then a secure policy
    (default RemoteSigned) afterward. Writes a full runtime log to the host folder.

.EXAMPLE
    # The one command - runs the entire pipeline:
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Invoke-IRCollection.ps1
.EXAMPLE
    # Same, plus optional staged-tool extras (memory image, full-disk file hunt):
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Invoke-IRCollection.ps1 -CaptureMemory -DeepFileScan
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputRoot = $PSScriptRoot,
    [string]$IncidentId,
    [switch]$DeepFileScan,
    [switch]$SkipForensics,
    [switch]$SkipHunt,
    [switch]$CaptureMemory,                 # needs a STAGED tool (tools\winpmem.exe)
    [switch]$SkipReports,                   # skip automated Incident_Report/Attack_Graph
    # Containment: enforce a strict Default-Deny inbound firewall as the FIRST act
    # of collection so no new inbound C2/lateral-movement session can land mid-run.
    # On by default; the pre-lockdown firewall state is exported so eradication can
    # restore it to known-good afterward (keeping known-bad blocked).
    [switch]$NoFirewallLockdown,
    [int[]]$AllowInboundPort = @(),         # management pinhole(s) kept open (e.g. 5985 WinRM)
    [string[]]$AllowInboundRemoteAddress = @(),
    [ValidateSet('Restricted','AllSigned','RemoteSigned')]
    [string]$PostRunExecutionPolicy = 'RemoteSigned'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Identity / output folder (computed first so everything can be logged) -----
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$HostName = $env:COMPUTERNAME
if (-not $IncidentId) { $IncidentId = "${HostName}_${RunStamp}" }
if (-not $OutputRoot) { $OutputRoot = (Get-Location).Path }
$OutDir = Join-Path $OutputRoot $HostName
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$RunLog = Join-Path $OutDir "_runtime_$RunStamp.log"
function Write-Log {
    param([string]$Msg, [string]$Color = 'Gray')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Msg"
    Write-Host $line -ForegroundColor $Color
    $line | Out-File -FilePath $RunLog -Append -Encoding UTF8
}

# Set the execution policy across a chain of scopes; log the outcome of each.
function Set-EPWithFallback {
    param([string]$Policy)
    foreach ($scope in 'LocalMachine','CurrentUser','Process') {
        try {
            Set-ExecutionPolicy $Policy -Scope $scope -Force -ErrorAction Stop
            Write-Log "Execution policy '$Policy' applied at scope $scope." 'Green'
            return $true
        } catch {
            Write-Log "Could not set '$Policy' at $scope : $($_.Exception.Message)" 'Yellow'
        }
    }
    Write-Log "Execution policy unchanged (all scopes blocked, likely Group Policy)." 'Yellow'
    return $false
}

# -- Execution policy: bypass for this session --------------------------------
$PriorEP = Get-ExecutionPolicy -Scope Process
Write-Log "Prior process execution policy: $PriorEP"
try {
    Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    Write-Log "Execution policy set to Bypass (Process scope) for this run." 'Green'
} catch {
    Write-Log "Bypass at Process scope failed: $($_.Exception.Message)" 'Yellow'
}

try {
    $PSExe = (Get-Process -Id $PID).Path
    if (-not $PSExe) { $PSExe = Join-Path $PSHOME 'powershell.exe' }

    $ForensicsScript = Join-Path $PSScriptRoot 'playbooks\windows\00_Collect-Forensics.ps1'
    $FirewallScript  = Join-Path $PSScriptRoot 'playbooks\windows\Enforce-StrictFirewall.ps1'
    $HuntDir         = Join-Path $PSScriptRoot 'playbooks\windows\threat_hunting'
    $EDRScript       = Join-Path $HuntDir 'EDR_Toolkit.ps1'
    $AnalyzeScript   = Join-Path $HuntDir 'Analyze-EDRReport.ps1'
    $ContextScript   = Join-Path $HuntDir 'Get-FindingContext.ps1'
    $TriageScript    = Join-Path $HuntDir 'Get-RemoteAccessTriage.ps1'
    $PersistScript   = Join-Path $HuntDir 'Get-PersistenceSnapshot.ps1'
    $ReportScript    = Join-Path $PSScriptRoot 'playbooks\reporting\generate_reports.ps1'

    $script:PhaseResults = [ordered]@{}
    function Invoke-Phase {
        param([string]$Name, [string]$ScriptPath, [string[]]$Arguments = @())
        Write-Log "==== PHASE: $Name ====" 'Cyan'
        if (-not (Test-Path -LiteralPath $ScriptPath)) {
            Write-Log "  SKIP - not found: $ScriptPath" 'Yellow'; $script:PhaseResults[$Name]='skipped'; return
        }
        $phaseLog = Join-Path $OutDir ("_{0}_{1}.log" -f ($Name -replace '\W','_'), $RunStamp)
        $argList  = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $ScriptPath) + $Arguments
        try {
            & $PSExe @argList *>&1 | Tee-Object -FilePath $phaseLog -Append
            Write-Log "  $Name complete (log: $(Split-Path -Leaf $phaseLog))." 'Green'
            $script:PhaseResults[$Name]='success'
        } catch { Write-Log "  ERROR in ${Name}: $($_.Exception.Message)" 'Red'; $script:PhaseResults[$Name]='failed' }
    }

    Write-Log "===================================================" 'Green'
    Write-Log " IR COLLECTION | host=$HostName | incident=$IncidentId" 'Green'
    Write-Log " output -> $OutDir" 'Green'
    Write-Log "===================================================" 'Green'

    # PHASE 0: CONTAINMENT - strict Default-Deny inbound firewall FIRST.
    # This neutralises any inbound C2 / lateral-movement landing during the run.
    # The pre-lockdown firewall is exported to a .wfw backup; we record its path in
    # the host folder so Invoke-Eradication.ps1 can restore known-good afterwards
    # while keeping known-bad (C2 egress) blocked.
    if (-not $NoFirewallLockdown) {
        Write-Log "==== PHASE: Firewall Lockdown (Default-Deny inbound) ====" 'Cyan'
        if (Test-Path -LiteralPath $FirewallScript) {
            $fwArgs = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $FirewallScript, '-FullInboundLockdown')
            if (@($AllowInboundPort).Count -gt 0)          { $fwArgs += @('-AllowInboundPort')          + ($AllowInboundPort          | ForEach-Object { "$_" }) }
            if (@($AllowInboundRemoteAddress).Count -gt 0)  { $fwArgs += @('-AllowInboundRemoteAddress')  + $AllowInboundRemoteAddress }
            $fwLog = Join-Path $OutDir ("_Firewall_$RunStamp.log")
            try {
                & $PSExe @fwArgs *>&1 | Tee-Object -FilePath $fwLog -Append
                # Use the FIRST-WRITE-WINS baseline pointer (baseline.txt), NOT the
                # newest .wfw, so a re-run does not record the already-locked state
                # as known-good. Enforce-StrictFirewall.ps1 maintains baseline.txt.
                $marker = 'C:\FirewallBackups\baseline.txt'
                $baseline = if (Test-Path -LiteralPath $marker) { (Get-Content -LiteralPath $marker -Raw).Trim() } else { $null }
                $stateFile = Join-Path $OutDir '_firewall_state.json'
                [ordered]@{
                    locked_down_utc = (Get-Date).ToUniversalTime().ToString('o')
                    backup_wfw      = $baseline
                    full_lockdown   = $true
                    mgmt_pinhole    = @($AllowInboundPort)
                } | ConvertTo-Json | Out-File -FilePath $stateFile -Encoding UTF8
                Write-Log "  Inbound locked down. Known-good baseline: $(if($baseline){$baseline}else{'<not found>'})" 'Green'
            } catch { Write-Log "  Firewall lockdown error: $($_.Exception.Message)" 'Red' }
        } else {
            Write-Log "  SKIP - Enforce-StrictFirewall.ps1 not found: $FirewallScript" 'Yellow'
        }
    } else {
        Write-Log "Firewall lockdown skipped (-NoFirewallLockdown)." 'Yellow'
    }

    # PHASE 1: forensics snapshot (writes straight into $OutDir)
    if (-not $SkipForensics) {
        Invoke-Phase -Name 'Forensics' -ScriptPath $ForensicsScript `
            -Arguments @('-OutputDir', $OutDir, '-IncidentId', $IncidentId)

        # PHASE 1b: full persistence breadth via STAGED Sysinternals autorunsc
        # (covers IFEO/Winlogon/LSA/AppInit/etc). Offline; skipped if not staged.
        $autoruns = Get-ChildItem -Path (Join-Path $PSScriptRoot 'tools') -Filter 'autorunsc*.exe' -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
        if ($autoruns) {
            Write-Log "==== PHASE: Autoruns (staged $($autoruns.Name)) ====" 'Cyan'
            try {
                & $autoruns.FullName -accepteula -nobanner -a * -c -h -s 2>$null |
                    Out-File -FilePath (Join-Path $OutDir 'autoruns.csv') -Encoding UTF8
                Write-Log "  Extended persistence snapshot -> autoruns.csv" 'Green'
            } catch { Write-Log "  Autoruns error: $($_.Exception.Message)" 'Yellow' }
        } else {
            Write-Log "Autoruns not staged (tools\autorunsc*.exe) - skipping extended persistence (run Build-OfflineToolkit.ps1 to add it)." 'Gray'
        }

        # PHASE 1c: pure-PowerShell persistence breadth + config tamper + NTFS/evtx
        # (IFEO/Winlogon/LSA/AppInit, USN timeline, Amcache, full .evtx, firewall, creds)
        Invoke-Phase -Name 'Persistence' -ScriptPath $PersistScript -Arguments @('-OutputDir', $OutDir)

        # PHASE 1d: OPTIONAL live memory capture (needs staged tools\winpmem.exe)
        if ($CaptureMemory) {
            $winpmem = Join-Path $PSScriptRoot 'tools\winpmem.exe'
            if (Test-Path -LiteralPath $winpmem) {
                Write-Log "==== PHASE: Memory (staged winpmem) ====" 'Cyan'
                try {
                    & $winpmem (Join-Path $OutDir "memory_$HostName.raw") 2>&1 |
                        Tee-Object -FilePath (Join-Path $OutDir "_Memory_$RunStamp.log") -Append
                    Write-Log "  Memory image -> memory_$HostName.raw" 'Green'
                } catch { Write-Log "  Memory capture error: $($_.Exception.Message)" 'Yellow' }
            } else {
                Write-Log "-CaptureMemory set but tools\winpmem.exe not staged (run Build-OfflineToolkit.ps1 -IncludeMemory)." 'Yellow'
            }
        }
    } else { Write-Log "Skipping forensics (-SkipForensics)." 'Yellow' }

    # PHASE 2: EDR fileless/evasion hunt (offline; no driver auto-update)
    if (-not $SkipHunt) {
        $edrArgs = @('-ScanProcesses','-ScanFileless','-ScanTasks','-ScanDrivers',
            '-ScanInjection','-ScanRegistry','-ScanETWAMSI','-ScanPendingRename',
            '-ScanBITS','-ScanCOM','-ReportPath', $OutDir)
        if ($DeepFileScan) {
            $edrArgs += @('-TargetDirectory','C:\','-Recursive','-ScanADS','-QuickMode')
            Write-Log "Deep file scan ENABLED (C:\ recursive)." 'Yellow'
        }
        Invoke-Phase -Name 'EDR_Hunt' -ScriptPath $EDRScript -Arguments $edrArgs

        # PHASE 2b: remote-access / ClickFix / browser / session triage (T1219 vector)
        Invoke-Phase -Name 'RemoteAccess' -ScriptPath $TriageScript -Arguments @('-OutputDir', $OutDir)

        # PHASE 3: baseline tuning of the newest EDR JSON
        $edrJson = Get-ChildItem -Path $OutDir -Filter 'EDR_Report_*.json' -File -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($edrJson) {
            Push-Location $OutDir   # Analyze writes its CSV to the current dir
            Invoke-Phase -Name 'Analysis' -ScriptPath $AnalyzeScript `
                -Arguments @('-ReportPath', $edrJson.FullName, '-ExportCSV')
            Pop-Location
        } else { Write-Log "No EDR JSON (zero EDR findings)." 'Gray' }

        # Merge ALL finding sources (EDR + remote-access + persistence) for adjudication
        $allFindings = @()
        foreach ($pat in 'EDR_Report_*.json','RemoteAccess_Findings_*.json','Persistence_Findings_*.json') {
            $newest = Get-ChildItem -Path $OutDir -Filter $pat -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest) { try { $c = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json; if ($c) { $allFindings += $c } } catch {} }
        }

        if ($allFindings.Count -gt 0) {
            $combined = Join-Path $OutDir "Combined_Findings_$RunStamp.json"
            $allFindings | ConvertTo-Json -Depth 5 | Out-File -FilePath $combined -Encoding UTF8
            Write-Log "Merged $($allFindings.Count) finding(s) (EDR + remote-access) -> $(Split-Path -Leaf $combined)" 'Gray'

            # PHASE 4: definitive adjudication (live, on-host) - proves TP vs FP
            Invoke-Phase -Name 'Adjudication' -ScriptPath $ContextScript `
                -Arguments @('-HostFolder', $OutDir, '-ReportPath', $combined, '-Live')
        } else { Write-Log "No findings - skipping adjudication." 'Gray' }

        # Analysis-stage IOC bundle (independent of reporting) so eradication's
        # known-bad re-block never depends on -SkipReports.
        if (Test-Path -LiteralPath $ReportScript) {
            Write-Log "==== PHASE: IOCs (analysis hand-off) ====" 'Cyan'
            try {
                & $PSExe -ExecutionPolicy Bypass -NoProfile -File $ReportScript `
                    -HostFolder $OutDir -IncidentId $IncidentId -IocsOnly *>&1 |
                    Tee-Object -FilePath (Join-Path $OutDir "_IOCs_$RunStamp.log") -Append
                Write-Log "  IOCs.json emitted." 'Green'
            } catch { Write-Log "  IOC emission error: $($_.Exception.Message)" 'Red' }
        }

        # Analysis-stage implicated-principal bundle (accounts to revoke at eradication).
        # Native PowerShell - no Python on Windows.
        if (Test-Path -LiteralPath $ReportScript) {
            Write-Log "==== PHASE: Principals (analysis hand-off) ====" 'Cyan'
            try {
                & $PSExe -ExecutionPolicy Bypass -NoProfile -File $ReportScript `
                    -HostFolder $OutDir -IncidentId $IncidentId -PrincipalsOnly *>&1 |
                    Tee-Object -FilePath (Join-Path $OutDir "_Principals_$RunStamp.log") -Append
                Write-Log "  Principals.json emitted." 'Green'
            } catch { Write-Log "  Principal extraction error: $($_.Exception.Message)" 'Red' }
        }
    } else { Write-Log "Skipping hunt + triage + analysis (-SkipHunt)." 'Yellow' }

    # PHASE 5: automated reporting - Incident_Report.md, Attack_Graph.md, IOCs.json
    # correlated straight from the adjudicated findings. Native PowerShell generator -
    # Windows runs entirely on PowerShell, no Python dependency.
    if (-not $SkipReports) {
        Write-Log "==== PHASE: Reporting (Incident_Report + Attack_Graph) ====" 'Cyan'
        try {
            if (Test-Path -LiteralPath $ReportScript) {
                & $PSExe -ExecutionPolicy Bypass -NoProfile -File $ReportScript `
                    -HostFolder $OutDir -IncidentId $IncidentId *>&1 |
                    Tee-Object -FilePath (Join-Path $OutDir "_Reporting_$RunStamp.log") -Append
                Write-Log "  Reports generated (Incident_Report, Attack_Graph, Retrospective, Timeline, IOCs)." 'Green'
            } else {
                Write-Log "  Native report generator not found: $ReportScript - skipping." 'Yellow'
            }
        } catch { Write-Log "  Reporting error: $($_.Exception.Message)" 'Red' }
    } else { Write-Log "Skipping automated reports (-SkipReports)." 'Yellow' }

    # Manifest of everything collected
    $artifacts = Get-ChildItem -Path $OutDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $RunLog } |
        Select-Object Name, @{N='SizeBytes';E={$_.Length}},
            @{N='SHA256';E={(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}}
    [ordered]@{
        incident_id  = $IncidentId
        hostname     = $HostName
        collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        output_dir   = $OutDir
        deep_scan    = [bool]$DeepFileScan
        artifacts    = $artifacts
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $OutDir "_manifest_$RunStamp.json") -Encoding UTF8

    # Status contract: uniform _status.json for SOAR gating (matches Linux/cloud).
    $tpCount = 0
    $adjFile = Get-ChildItem -Path $OutDir -Filter 'Adjudication_*.json' -File -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($adjFile) {
        try {
            $adjData = Get-Content -LiteralPath $adjFile.FullName -Raw | ConvertFrom-Json
            $tpCount = @($adjData | Where-Object { $_.Verdict -in 'True Positive','Likely True Positive' }).Count
        } catch {}
    }
    $failed = @($script:PhaseResults.Values | Where-Object { $_ -eq 'failed' }).Count
    $okCnt  = @($script:PhaseResults.Values | Where-Object { $_ -eq 'success' }).Count
    $overall = if ($failed -eq 0) { 'COMPLETED' } elseif ($okCnt -gt 0) { 'PARTIAL' } else { 'FAILED' }
    [ordered]@{
        incident_id=$IncidentId; hostname=$HostName; platform='windows'
        status=$overall; tp_count=$tpCount; phases=$script:PhaseResults
    } | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $OutDir '_status.json') -Encoding UTF8

    Write-Log "===================================================" 'Green'
    Write-Log " COLLECTION $overall - $($artifacts.Count) artifact(s), $tpCount true-positive-class" 'Green'
    Write-Log " $OutDir" 'Green'
    Write-Log "===================================================" 'Green'
}
finally {
    # Harden: set a secure execution policy now that collection is done.
    Write-Log "Restoring secure execution policy ($PostRunExecutionPolicy)..."
    Set-EPWithFallback -Policy $PostRunExecutionPolicy | Out-Null
    Write-Log "Runtime log: $RunLog" 'Green'
}
