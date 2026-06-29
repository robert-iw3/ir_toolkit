#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Advanced egress monitor with beacon detection, memory carving, mwcp config
    extraction, and automatic C2 IP blackholing.

.DESCRIPTION
    Replaces/extends Watch-Egress.ps1 with a Python-backed daemon that:
      - Polls live process network connections via MemProcFS (falls back to
        Get-NetTCPConnection when the live driver is unavailable)
      - Classifies connections as CONFIRMED_BEACON / SUSPECTED_BEACON / MONITOR
        using multi-layer scoring: process context + periodicity + family hints
      - On beacon confirmation: carves suspect PID VAD regions, runs mwcp
        (CobaltStrikeConfig, GenericC2, PowerShellDecoder), extracts config,
        hunts persistence (registry, scheduled tasks, named pipes)
      - Once config is extracted and beacon confirmed: blackholes C2 IP via
        Windows Firewall outbound block
      - Runs for -WindowHours (24 default, 1-72 configurable, 0 = indefinite)

    All findings written to:
      $StateDir\egress_evidence.jsonl  -- append-only JSONL audit trail
      $StateDir\egress_report.json     -- live summary (updated each poll)
      $StateDir\egress_monitor.log     -- verbose Python daemon log
      $StateDir\carved_<proc>_<pid>\   -- carved memory regions + mwcp output

    The Python daemon and all tools are deployed to $StateDir on start, making
    the monitor fully self-contained and runnable without the source tree.

.PARAMETER Start
    Start the monitor daemon.

.PARAMETER Status
    Show current status from egress_report.json.

.PARAMETER Collect
    Print the evidence log (egress_evidence.jsonl) in readable form.

.PARAMETER Blackhole
    Apply outbound firewall block NOW (without waiting for window to close).
    Also triggered automatically on beacon confirmation when running with -Start.

.PARAMETER Stop
    Stop the monitor scheduled task without blackholing.

.PARAMETER WindowHours
    Duration in hours (1-72, or 0 for indefinite). Default 24.

.PARAMETER PollSec
    Connection poll interval in seconds. Default 5.

.PARAMETER IncidentId
    Identifier used in task names and output paths.

.PARAMETER MgmtIP
    Comma-separated IPs to exclude from external classification (management access).

.PARAMETER FlaggedPid
    Comma-separated PIDs pre-flagged by enrichment (anonymous exec VAD, ETW-TI).
    Any external connection from these triggers immediate carve (Layer 0).

.PARAMETER BlackholeOnConfirm
    Automatically block confirmed C2 IPs after successful carve + config extraction.
    Default: true (pass -NoBlackhole to disable for observe-only mode).

.PARAMETER NoBlackhole
    Disable automatic IP blackholing (observe-only mode).
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Start')]    [switch]$Start,
    [Parameter(ParameterSetName = 'Status')]   [switch]$Status,
    [Parameter(ParameterSetName = 'Collect')]  [switch]$Collect,
    [Parameter(ParameterSetName = 'Blackhole')][switch]$Blackhole,
    [Parameter(ParameterSetName = 'Stop')]     [switch]$Stop,

    [string]$IncidentId  = 'egress',
    [ValidateRange(0, 72)]
    [int]$WindowHours    = 24,
    [int]$PollSec        = 5,
    [string]$MgmtIP      = '',
    [string]$FlaggedPid  = '',
    [switch]$BlackholeOnConfirm = $true,
    [switch]$NoBlackhole
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId  = ($IncidentId -replace '[^\w\-]', '')
$StateDir    = Join-Path $env:ProgramData "IRToolkit\egress-$IncidentId"
$EvidenceLog = Join-Path $StateDir 'egress_evidence.jsonl'
$ReportJson  = Join-Path $StateDir 'egress_report.json'
$PollTask    = "IR-EgressMon-Poll-$IncidentId"
$BHTask      = "IR-EgressMon-Blackhole-$IncidentId"
$TaskLog     = Join-Path $StateDir 'egress_monitor.log'

# All paths below are WITHIN $StateDir on the TARGET SYSTEM.
# The scheduled task (SYSTEM) uses ONLY these paths.
# No reference to $PSScriptRoot after Deploy-ToStateDir returns.
$DeployedPython  = Join-Path $StateDir 'tools\memprocfs\python\python.exe'
$DeployedScript  = Join-Path $StateDir 'egress_monitor.py'
$DeployedToolDir = Join-Path $StateDir 'tools'
$DeployedEnforcePS1 = Join-Path $StateDir 'Enforce-StrictFirewall.ps1'

function Deploy-ToStateDir {
    <#
    Copy the ENTIRE egress_monitor bundle to $StateDir on the target system.
    After this returns the scheduled task ONLY uses $StateDir paths.
    The source drive/USB/share can be removed immediately after -Start returns.
    #>
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

    # 1. Python daemon scripts (egress_monitor.py, beacon_classifier.py, carve_and_scan.py)
    foreach ($f in @('egress_monitor.py', 'beacon_classifier.py', 'carve_and_scan.py')) {
        $src = Join-Path $PSScriptRoot $f
        if (Test-Path $src) {
            Copy-Item $src $StateDir -Force
        } else {
            Write-Warning "  [!] Source missing: $src"
        }
    }

    # 2. Tools bundle: memprocfs/ (Python runtime + DLLs + vmmpyc), mwcp/, yara/
    #    Staged by: Build-OfflineToolkit.ps1 -IncludeEgressMonitor
    $toolsSrc = Join-Path $PSScriptRoot 'tools'
    if (Test-Path $toolsSrc) {
        if (-not (Test-Path $DeployedToolDir)) {
            Write-Host "  [*] Deploying tools/ to system ($([math]::Round((Get-ChildItem $toolsSrc -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB, 0)) MB) ..." -ForegroundColor Cyan
            Copy-Item -Path $toolsSrc -Destination $DeployedToolDir -Recurse -Force
            Write-Host "  [+] tools/ deployed" -ForegroundColor Green
        } else {
            Write-Host "  [~] tools/ already on system" -ForegroundColor Gray
        }
    } else {
        Write-Warning "  [!] egress_monitor/tools/ not staged"
        Write-Warning "      Run: Build-OfflineToolkit.ps1 -IncludeEgressMonitor"
        Write-Warning "      MemProcFS and mwcp will not be available; netstat fallback only"
    }

    # 3. mwcp_scan.py (sibling of egress_monitor/ in threat_hunting/)
    foreach ($candidate in @(
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'mwcp_scan.py'),
        (Join-Path $PSScriptRoot 'mwcp_scan.py')
    )) {
        if (Test-Path $candidate) {
            Copy-Item $candidate $StateDir -Force
            break
        }
    }

    # 4. Enforce-StrictFirewall.ps1 for the deferred blackhole task
    #    Search up the source tree; deploy to $StateDir so task has no source dependency
    $searchDir = $PSScriptRoot
    for ($i = 0; $i -lt 6; $i++) {
        $candidate = Join-Path $searchDir 'Enforce-StrictFirewall.ps1'
        if (Test-Path $candidate) {
            Copy-Item $candidate $StateDir -Force
            break
        }
        $parent = Split-Path $searchDir -Parent
        if (-not $parent -or $parent -eq $searchDir) { break }
        $searchDir = $parent
    }

    # Verify the critical deployed paths exist
    $ok = $true
    if (-not (Test-Path $DeployedScript))  { Write-Warning "  [!] egress_monitor.py not deployed"; $ok = $false }
    if (-not (Test-Path $DeployedPython))  { Write-Warning "  [!] Python not deployed (no tools/memprocfs/python/python.exe)" }
    return $ok
}

# ---- Parameter set handlers ---------------------------------------------------

switch ($PSCmdlet.ParameterSetName) {

# ==============================================================================
'Start' {
    Write-Host "[*] Egress monitor deploy + start (incident=$IncidentId, ${WindowHours}h, poll=${PollSec}s)" -ForegroundColor Cyan

    # Step 1: deploy everything to $StateDir on the target system
    $ok = Deploy-ToStateDir
    if (-not $ok) { Write-Error "Deployment failed -- aborting."; exit 1 }

    # Step 2: resolve Python -- ONLY from deployed location.
    # The scheduled task runs as SYSTEM; SYSTEM's PATH differs from the analyst session.
    # Using the deployed Python guarantees the same interpreter and all DLLs are present.
    $pyExe = if (Test-Path $DeployedPython) {
        $DeployedPython
    } else {
        # Staged tools not present -- warn and fall back to system Python for netstat mode only
        Write-Warning "[!] Deployed Python not found at $DeployedPython"
        Write-Warning "    Run Build-OfflineToolkit.ps1 -IncludeEgressMonitor to stage tools"
        Write-Warning "    Falling back to system Python (netstat mode, no MemProcFS, no mwcp)"
        $sys = (Get-Command python.exe -ErrorAction SilentlyContinue)
        if ($sys) { $sys.Source } else { $null }
    }
    if (-not $pyExe) { Write-Error "No Python available. Cannot start."; exit 1 }

    # Step 3: build daemon args -- ALL paths point into $StateDir
    $doBlackhole = ($BlackholeOnConfirm -and -not $NoBlackhole)
    $pyArgs = @(
        "`"$DeployedScript`"",
        '--out-dir',     "`"$StateDir`"",
        '--tool-dir',    "`"$DeployedToolDir`"",
        '--duration',    "$WindowHours",
        '--poll-sec',    "$PollSec",
        '--incident-id', $IncidentId
    )
    if ($MgmtIP)     { $pyArgs += "--mgmt-ip `"$MgmtIP`"" }
    if ($FlaggedPid) { $pyArgs += "--flagged-pid `"$FlaggedPid`"" }
    if ($doBlackhole){ $pyArgs += '--blackhole-on-confirm' }
    if (-not (Test-Path $DeployedPython)) { $pyArgs += '--no-memprocfs' }

    $argStr = $pyArgs -join ' '

    # Step 4: register the poll task as SYSTEM / RunLevel Highest
    # WorkingDirectory = $StateDir so relative imports resolve correctly
    $act = New-ScheduledTaskAction `
        -Execute "`"$pyExe`"" `
        -Argument $argStr `
        -WorkingDirectory $StateDir
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
    $set = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours ([math]::Max($WindowHours + 1, 2))) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $PollTask -Action $act -Trigger $trg `
        -Principal $pr -Settings $set -Force | Out-Null
    Write-Host "  [+] Poll task registered (SYSTEM/Highest): $PollTask" -ForegroundColor Green

    # Step 5: register deferred full-outbound blackhole at window close.
    # Uses the deployed Enforce-StrictFirewall.ps1 if present; falls back to
    # Set-NetFirewallProfile which is always available as SYSTEM.
    if ($WindowHours -gt 0) {
        $bhArgStr = if (Test-Path $DeployedEnforcePS1) {
            "-NoProfile -ExecutionPolicy Bypass -File `"$DeployedEnforcePS1`" -BlockOutbound"
        } else {
            "-NoProfile -Command `"Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block`""
        }
        if ($MgmtIP) {
            $bhArgStr += " -AllowOutboundRemoteAddress $($MgmtIP -replace ',', ' ')"
        }
        $bhAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $bhArgStr
        $bhTrg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours($WindowHours)
        Register-ScheduledTask -TaskName $BHTask -Action $bhAct -Trigger $bhTrg `
            -Principal $pr -Force | Out-Null
        Write-Host "  [+] Blackhole task registered: fires automatically at +${WindowHours}h" -ForegroundColor Yellow
    }

    Write-Host "  [+] Evidence log: $EvidenceLog" -ForegroundColor Green
    Write-Host "  [+] Live report:  $ReportJson" -ForegroundColor Green
    Write-Host "  [+] Python exe:   $pyExe" -ForegroundColor Gray
    Write-Host "  [+] State dir:    $StateDir" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Source drive can now be removed. All tools are on the target system." -ForegroundColor Cyan
    Write-Host "  Return after the window to run: Start-EgressMonitor.ps1 -Collect -IncidentId $IncidentId" -ForegroundColor Yellow

    [PSCustomObject]@{
        phase         = 'egress_monitor'; status = 'started'
        incident_id   = $IncidentId;  window_hours = $WindowHours
        poll_task     = $PollTask;    blackhole_task = $BHTask
        python_exe    = $pyExe;       state_dir = $StateDir
        evidence_log  = $EvidenceLog; report_json  = $ReportJson
        blackhole_on_confirm = $doBlackhole
    } | ConvertTo-Json -Compress
}

# ==============================================================================
'Status' {
    if (Test-Path $ReportJson) {
        Get-Content $ReportJson | ConvertFrom-Json | Format-List
    } else {
        Write-Warning "No active monitor found for incident '$IncidentId' (report not found: $ReportJson)"
    }
    $task = Get-ScheduledTask -TaskName $PollTask -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "Scheduled task '$PollTask': $($task.State)" -ForegroundColor Cyan
    }
}

# ==============================================================================
'Collect' {
    if (-not (Test-Path $EvidenceLog)) {
        Write-Warning "No evidence log found: $EvidenceLog"; return
    }
    Write-Host "=== Egress Evidence Log: $IncidentId ===" -ForegroundColor Cyan
    Get-Content $EvidenceLog | ForEach-Object {
        try {
            $r = $_ | ConvertFrom-Json
            $ts = $r.timestamp; $ev = $r.event
            switch ($ev) {
                'BEACON_DETECTED' {
                    Write-Host "[$ts] $($r.verdict) PID=$($r.pid) ($($r.process)) -> $($r.remote_ip):$($r.remote_port) confidence=$($r.confidence) family=$($r.family_hint)" -ForegroundColor $(if ($r.verdict -eq 'CONFIRMED_BEACON') {'Red'} else {'Yellow'})
                }
                'CARVE_COMPLETE' {
                    Write-Host "[$ts] CARVE PID=$($r.pid) regions=$($r.regions_carved) findings=$($r.regions_findings) C2=$($r.c2_addresses -join ',') SpawnTo=$($r.spawn_to)" -ForegroundColor Magenta
                }
                'BLACKHOLE_APPLIED' {
                    Write-Host "[$ts] BLACKHOLE $($r.ip) -> rule=$($r.rule)" -ForegroundColor Red
                }
                'MONITOR_STOPPED' {
                    Write-Host "[$ts] STOPPED confirmed=$($r.beacons_confirmed) suspected=$($r.beacons_suspected) blackholed=$($r.ips_blackholed -join ',')" -ForegroundColor Cyan
                }
            }
        } catch { Write-Host $_ -ForegroundColor Gray }
    }
}

# ==============================================================================
'Blackhole' {
    # Use deployed Enforce-StrictFirewall.ps1 first (preserves pre-incident state for rollback).
    # Falls back to Set-NetFirewallProfile (always available as SYSTEM, no rollback capability).
    if (Test-Path $DeployedEnforcePS1) {
        $bhParams = @{ BlockOutbound = $true }
        if ($MgmtIP) { $bhParams['AllowOutboundRemoteAddress'] = ($MgmtIP -split ',') }
        & $DeployedEnforcePS1 @bhParams
    } else {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    }
    Write-Host "[+] Outbound blackhole applied" -ForegroundColor Red
    Unregister-ScheduledTask -TaskName $BHTask  -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
}

# ==============================================================================
'Stop' {
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $BHTask   -Confirm:$false -ErrorAction SilentlyContinue
    # Stop daemon process -- spawned as SYSTEM so use Get-WmiObject for CommandLine access
    Get-WmiObject Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*egress_monitor.py*" -and $_.CommandLine -like "*$IncidentId*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host "[+] Egress monitor stopped (no blackhole applied)" -ForegroundColor Yellow
}

} # end switch
