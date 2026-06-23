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
    [string]$OutputRoot = '',
    [string]$IncidentId,
    # File scan mode (choose one):
    #   -DeepFileScan   C:\ recursive, QuickMode ON  (skip old files + fast entropy) ~5-10 min
    #   -FullScan       C:\ recursive, QuickMode OFF  (all files, full entropy)       ~45+ min
    [switch]$DeepFileScan,
    [switch]$FullScan,
    [int]$QuickModeDaysBack = 90,           # QuickMode: only scan files touched in last N days
    [string]$ScanTarget = 'C:\',            # Override the directory targeted by DeepFileScan/FullScan
    [switch]$ScanYara,                      # YARA sig scan (needs staged tools\yara64.exe + tools\yara_rules\)
    [switch]$SkipForensics,
    [switch]$SkipHunt,
    [switch]$CaptureMemory,                 # needs a staged memory capture tool in tools\
    # Which memory capture tool to use.
    # go-winpmem : DEFAULT - AFF4 with sparse streams, no MMIO gap padding, signed, ~RAM size output
    # winpmem    : mini WinPmem - RAW only, pads MMIO gaps (image can be >> physical RAM)
    # ftk        : FTK Imager CLI - place ftkimager.exe + DLLs in tools\ manually (paid/gated)
    # magnet     : Magnet RAM Capture - place MRC.exe in tools\ manually (registration required)
    # Stage with: Build-OfflineToolkit.ps1 -IncludeMemory  (stages both go-winpmem + winpmem mini)
    [ValidateSet('go-winpmem','winpmem','ftk','magnet')]
    [string]$MemoryTool = 'go-winpmem',
    [string]$MemoryOutputPath = '',         # redirect image to a different volume when output drive lacks space
    [switch]$SkipReports,                   # skip automated Incident_Report/Attack_Graph
    # Containment: enforce a strict Default-Deny inbound firewall as the FIRST act
    # of collection so no new inbound C2/lateral-movement session can land mid-run.
    # On by default; the pre-lockdown firewall state is exported so eradication can
    # restore it to known-good afterward (keeping known-bad blocked).
    [switch]$NoFirewallLockdown,
    [int[]]$AllowInboundPort = @(),         # management pinhole(s) kept open (e.g. 5985 WinRM)
    [string[]]$AllowInboundRemoteAddress = @(),
    # Egress observation: after collection, start a scheduled sensor that logs outbound
    # connections over a window (default 24h), then auto-blackholes egress. Outbound is
    # left open during the window so jittered/long-dwell C2 beacons are observed. On by
    # default; the responder returns later to collect the egress evidence log.
    [switch]$NoEgressMonitor,
    [int]$EgressWindowHours = 24,
    [string[]]$EgressMgmtIP = @(),          # management IP(s) kept open in the egress blackhole
    [ValidateSet('Restricted','AllSigned','RemoteSigned')]
    [string]$PostRunExecutionPolicy = 'RemoteSigned',
    # Per-phase timeout safety net. A hung sub-step (stuck native tool, locked file)
    # cannot stall the whole collection: the phase is killed at this limit, marked
    # 'partial', and every later phase still runs. Default 30 min covers deep file
    # scans + YARA; raise with -PhaseTimeoutSec for very large -FullScan targets.
    [int]$PhaseTimeoutSec = 1800
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Identity / output folder (computed first so everything can be logged) -----
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$HostName = $env:COMPUTERNAME
if (-not $IncidentId) { $IncidentId = "${HostName}_${RunStamp}" }
if (-not $OutputRoot) {
    $OutputRoot = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'reports' } `
                  else               { Join-Path (Get-Location).Path 'reports' }
}
$OutDir = Join-Path $OutputRoot $HostName
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$RunLog = Join-Path $OutDir "_runtime_$RunStamp.log"
function Write-Log {
    param([string]$Msg, [string]$Color = 'Gray')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Msg"
    # Cap at Yellow - nothing prints in Red; errors are warnings, not stop conditions.
    if ($Color -eq 'Red') { $Color = 'Yellow' }
    Write-Host $line -ForegroundColor $Color
    [Console]::ResetColor()
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

    $ForensicsScript   = Join-Path $PSScriptRoot 'playbooks\windows\00_Collect-Forensics.ps1'
    $ClockScript       = Join-Path $PSScriptRoot 'playbooks\windows\Get-ClockContext.ps1'
    $FirewallScript    = Join-Path $PSScriptRoot 'playbooks\windows\Enforce-StrictFirewall.ps1'
    $EgressScript      = Join-Path $PSScriptRoot 'playbooks\windows\Watch-Egress.ps1'
    $HuntDir           = Join-Path $PSScriptRoot 'playbooks\windows\threat_hunting'
    $EDRScript         = Join-Path $HuntDir 'EDR_Toolkit.ps1'
    $AnalyzeScript     = Join-Path $HuntDir 'Analyze-EDRReport.ps1'
    $ContextScript     = Join-Path $HuntDir 'Get-FindingContext.ps1'
    $TriageScript      = Join-Path $HuntDir 'Get-RemoteAccessTriage.ps1'
    $PersistScript     = Join-Path $HuntDir 'Get-PersistenceSnapshot.ps1'
    $ReportScript      = Join-Path $PSScriptRoot 'playbooks\reporting\generate_reports.ps1'
    $EvtLogScript      = Join-Path $HuntDir 'Invoke-EventLogAnalysis.ps1'
    $AmcacheScript     = Join-Path $HuntDir 'Invoke-AmcacheParser.ps1'
    $PrepareDefenderScript = Join-Path $PSScriptRoot 'Invoke-PrepareDefender.ps1'
    $ToolsDir              = Join-Path $PSScriptRoot 'tools'

    $script:PhaseResults = [ordered]@{}
    function Invoke-Phase {
        param(
            [string]$Name,
            [string]$ScriptPath,
            [string[]]$Arguments = @(),
            [int]$TimeoutSec = $PhaseTimeoutSec   # phase-level safety net (script param)
        )
        Write-Log "==== PHASE: $Name ====" 'Cyan'
        if (-not (Test-Path -LiteralPath $ScriptPath)) {
            Write-Log "  SKIP - not found: $ScriptPath" 'Yellow'; $script:PhaseResults[$Name]='skipped'; return
        }
        $phaseLog = Join-Path $OutDir ("_{0}_{1}.log" -f ($Name -replace '\W','_'), $RunStamp)
        $argList  = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $ScriptPath) + $Arguments

        # Run the child as a tracked process with stdout/stderr redirected to temp files,
        # then poll with a deadline so a single hung sub-step (e.g. a stuck native tool)
        # cannot stall the entire collection. On timeout the process tree is killed and
        # the phase is marked 'partial' — every later phase still runs (full-capture goal).
        $outTmp = [System.IO.Path]::GetTempFileName()
        $errTmp = [System.IO.Path]::GetTempFileName()
        try {
            $proc = Start-Process -FilePath $PSExe -ArgumentList $argList -PassThru -NoNewWindow `
                -RedirectStandardOutput $outTmp -RedirectStandardError $errTmp -ErrorAction Stop

            $deadline   = (Get-Date).AddSeconds($TimeoutSec)
            $lastOutLen = 0; $lastErrLen = 0
            $timedOut   = $false

            while (-not $proc.HasExited) {
                Start-Sleep -Milliseconds 750
                # Tail new stdout/stderr to console + phase log for live visibility
                try {
                    $o = Get-Content -LiteralPath $outTmp -Raw -ErrorAction SilentlyContinue
                    if ($o -and $o.Length -gt $lastOutLen) {
                        $new = $o.Substring($lastOutLen); $lastOutLen = $o.Length
                        $new.TrimEnd("`r","`n") -split "`r?`n" | ForEach-Object {
                            if ($_ -ne '') { Write-Host "  $_" -ForegroundColor Gray; "  $_" | Out-File -FilePath $phaseLog -Append -Encoding UTF8 }
                        }
                    }
                    $e = Get-Content -LiteralPath $errTmp -Raw -ErrorAction SilentlyContinue
                    if ($e -and $e.Length -gt $lastErrLen) {
                        $new = $e.Substring($lastErrLen); $lastErrLen = $e.Length
                        $new.TrimEnd("`r","`n") -split "`r?`n" | ForEach-Object {
                            if ($_ -ne '') { Write-Host "  [stderr] $_" -ForegroundColor Yellow; "  [stderr] $_" | Out-File -FilePath $phaseLog -Append -Encoding UTF8 }
                        }
                    }
                } catch {}

                if ((Get-Date) -gt $deadline) {
                    $timedOut = $true
                    Write-Log "  $Name TIMED OUT after ${TimeoutSec}s - killing phase and continuing (partial capture)." 'Yellow'
                    try {
                        # Kill the child and any grandchildren (native tools it spawned)
                        Get-CimInstance Win32_Process -Filter "ParentProcessId = $($proc.Id)" -ErrorAction SilentlyContinue |
                            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    } catch {}
                    break
                }
            }

            if (-not $timedOut) {
                $proc.WaitForExit()
                # Flush any remaining tail
                foreach ($pair in @(@($outTmp,'Gray',''),@($errTmp,'Yellow','[stderr] '))) {
                    $c = Get-Content -LiteralPath $pair[0] -Raw -ErrorAction SilentlyContinue
                    $seen = if ($pair[0] -eq $outTmp) { $lastOutLen } else { $lastErrLen }
                    if ($c -and $c.Length -gt $seen) {
                        $c.Substring($seen).TrimEnd("`r","`n") -split "`r?`n" | ForEach-Object {
                            if ($_ -ne '') { Write-Host "  $($pair[2])$_" -ForegroundColor $pair[1]; "  $($pair[2])$_" | Out-File -FilePath $phaseLog -Append -Encoding UTF8 }
                        }
                    }
                }
                $exit = $proc.ExitCode
                if ($exit -eq 0 -or $null -eq $exit) {
                    Write-Log "  $Name complete (log: $(Split-Path -Leaf $phaseLog))." 'Green'
                    $script:PhaseResults[$Name] = 'success'
                } else {
                    Write-Log "  $Name ended with exit $exit - security software may have blocked it (log: $(Split-Path -Leaf $phaseLog))." 'Yellow'
                    Write-Log "  Add '$PSScriptRoot' to your AV Script Protection approved list and re-run." 'Yellow'
                    $script:PhaseResults[$Name] = 'partial'
                }
            } else {
                $script:PhaseResults[$Name] = 'partial'
            }
        } catch {
            Write-Log "  ERROR in ${Name}: $($_.Exception.Message)" 'Yellow'; $script:PhaseResults[$Name]='failed'
        } finally {
            Remove-Item -LiteralPath $outTmp,$errTmp -Force -ErrorAction SilentlyContinue
        }
    }

    # -- Pre-flight: Windows Defender automatic exclusion ---------------------
    # If Defender is active, add path + process exclusions now before any phase
    # touches a staged tool or script that Defender would otherwise quarantine.
    # Requires admin (already enforced by #Requires -RunAsAdministrator above).
    $defenderActive = $false
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $defenderActive = $mpStatus.RealTimeProtectionEnabled
    } catch {}

    # Check Tamper Protection before attempting any Defender changes.
    $tamperOn = $false
    try { $tamperOn = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}

    if ($defenderActive -and $tamperOn) {
        Write-Log "Windows Defender TAMPER PROTECTION is ON - launching Invoke-PrepareDefender.ps1 for guided setup..." 'Yellow'
        if (Test-Path -LiteralPath $PrepareDefenderScript) {
            # Run the guided setup interactively - it opens Windows Security, polls until
            # the user toggles TP off, adds all exclusions, then guides TP back on.
            # Output is streamed live so the user sees every step.
            & $PSExe -ExecutionPolicy Bypass -NoProfile -File $PrepareDefenderScript 2>&1 |
                ForEach-Object { Write-Host "  $_" }
            # Re-check tamper status after the prep script completes
            try { $tamperOn = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}
            if ($tamperOn) {
                Write-Log "Tamper Protection still ON after setup. Phases may be blocked by AMSI." 'Yellow'
            } else {
                Write-Log "Tamper Protection is now OFF - proceeding with automatic exclusion setup." 'Green'
                $defenderActive = $true   # trigger the exclusion block below
            }
        } else {
            Write-Log "Invoke-PrepareDefender.ps1 not found at $PrepareDefenderScript" 'Yellow'
            Write-Log "Manually: Windows Security -> Virus & threat protection -> Manage settings -> Exclusions -> Add $PSScriptRoot" 'Yellow'
        }
    }

    if ($defenderActive -and -not $tamperOn) {
        Write-Log "Windows Defender active - configuring exclusions before phases start..." 'Cyan'
        $toolsDir = Join-Path $PSScriptRoot 'tools'

        # Step 1: Strip the Zone.Identifier ADS from all toolkit scripts.
        # Defender's AMSI treats files marked as downloaded from the internet with
        # extra scrutiny regardless of path exclusions. Unblock-File removes the mark.
        Get-ChildItem -Path $PSScriptRoot -Recurse -Include '*.ps1','*.sh' -ErrorAction SilentlyContinue |
            ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }
        Write-Log "  Zone.Identifier unblocked on all toolkit scripts." 'Green'

        # Step 2: Write exclusions directly to the Defender registry key.
        # This propagates faster than Add-MpPreference (which goes through MpClient.dll).
        # Value 0 = exclude the path. Both path and AMSI scanning respect this key.
        $regKey = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        foreach ($folder in @($PSScriptRoot, $OutDir)) {
            try {
                if (-not (Test-Path $regKey)) { New-Item -Path $regKey -Force | Out-Null }
                Set-ItemProperty -Path $regKey -Name $folder -Value 0 -Type DWord -ErrorAction Stop
                Write-Log "  Registry exclusion set: $folder" 'Green'
            } catch {
                # Fallback to cmdlet if registry write fails (policy restriction)
                try { Add-MpPreference -ExclusionPath $folder -ErrorAction Stop } catch {}
                Write-Log "  Cmdlet exclusion set: $folder" 'Green'
            }
        }

        # Step 3: Process exclusions for staged tools via cmdlet.
        $processesToExclude = @(
            'autorunsc64.exe','autorunsc.exe',
            'yara64.exe','yarac64.exe',
            'go-winpmem.exe','winpmem.exe',
            'ftkimager.exe',
            'procdump64.exe','procdump.exe',
            'sigcheck64.exe','sigcheck.exe',
            'handle64.exe','handle.exe',
            'strings64.exe','strings.exe',
            'Listdlls64.exe','Listdlls.exe',
            'tcpvcon64.exe','tcpvcon.exe',
            'pslist64.exe','pslist.exe'
        )
        # Also add Magnet RAM Capture (versioned filename, e.g. MRCv120.exe)
        $mrcExe = Get-ChildItem -Path (Join-Path $PSScriptRoot 'tools') `
                      -Filter 'MRC*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mrcExe) { $processesToExclude += $mrcExe.Name }
        foreach ($proc in $processesToExclude) {
            $fullPath = Join-Path $toolsDir $proc
            if (Test-Path $fullPath) {
                try { Add-MpPreference -ExclusionProcess $fullPath -ErrorAction SilentlyContinue } catch {}
            }
        }
        Write-Log "  Staged tool process exclusions added." 'Green'

        # Step 4: Suspend Defender real-time monitoring for the duration of this run.
        # DisableScriptScanning only affects scheduled scans; WdFilter.sys enforces
        # AMSI scanning at kernel level regardless. DisableRealtimeMonitoring stops
        # WdFilter and is the standard approach for IR collection on a live host.
        # Restored unconditionally in the finally block.
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Write-Log "  Defender real-time monitoring suspended for collection (restored on exit)." 'Green'
        } catch {
            Write-Log "  Could not suspend Defender real-time monitoring: $($_.Exception.Message)" 'Yellow'
        }
    }

    # Suspend ALL AMSI providers for the duration of this run.
    # Each installed AV/EDR registers its AMSI provider under this key. Child processes
    # spawned AFTER the rename won't load any AMSI provider, so our scripts run clean.
    # The original GUIDs are saved and restored unconditionally in the finally block.
    $amsiRegKey  = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    $amsiSuspended = [System.Collections.Generic.List[string]]::new()
    try {
        $providers = Get-ChildItem $amsiRegKey -ErrorAction SilentlyContinue
        foreach ($p in $providers) {
            $disabled = "$($p.PSChildName)_ir_disabled"
            Rename-Item -Path $p.PSPath -NewName $disabled -ErrorAction SilentlyContinue
            $amsiSuspended.Add($disabled)
            Write-Log "  AMSI provider suspended: $($p.PSChildName)" 'Gray'
        }
        if ($amsiSuspended.Count -gt 0) {
            Write-Log "  $($amsiSuspended.Count) AMSI provider(s) suspended - restored on exit." 'Green'
        }
    } catch {
        Write-Log "  Could not suspend AMSI providers: $($_.Exception.Message)" 'Yellow'
    }

    Start-Sleep -Seconds 1

    # -- Pre-flight: AV/EDR detection -----------------------------------------
    # Two-pass detection: (1) WMI SecurityCenter2 - traditional AV products;
    # (2) process scan - EDR/XDR agents that don't register with Security Center.
    # Neither source alone is complete, so both are checked.

    # Pass 1 - WMI-registered AV/AS products
    $wmiFriendly = @(Get-CimInstance -Namespace root\SecurityCenter2 `
        -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty displayName)

    # Pass 2 - EDR/XDR process signatures (process name -> product label)
    # Format: ProcessName (no extension) = "Display Name"
    $edrProcessMap = [ordered]@{
        # CrowdStrike Falcon
        'CSFalconService'       = 'CrowdStrike Falcon'
        'CSFalconContainer'     = 'CrowdStrike Falcon'
        'falcon-sensor'         = 'CrowdStrike Falcon'
        # Carbon Black (VMware/Broadcom)
        'CbDefense'             = 'VMware Carbon Black'
        'cb'                    = 'VMware Carbon Black'
        'RepMgr'                = 'VMware Carbon Black'
        'RepUtils'              = 'VMware Carbon Black'
        # SentinelOne
        'SentinelAgent'         = 'SentinelOne'
        'SentinelServiceHost'   = 'SentinelOne'
        'SentinelStaticEngine'  = 'SentinelOne'
        # Elastic Security / Elastic Agent
        'elastic-agent'         = 'Elastic Security'
        'elastic-endpoint'      = 'Elastic Security'
        'filebeat'              = 'Elastic Security'
        'winlogbeat'            = 'Elastic Security'
        # Microsoft Defender for Endpoint (MDE/ATP)
        'MsSense'               = 'Microsoft Defender for Endpoint'
        'SenseCncProxy'         = 'Microsoft Defender for Endpoint'
        'SenseIR'               = 'Microsoft Defender for Endpoint'
        # Trellix / McAfee Enterprise / FireEye
        'xagt'                  = 'Trellix (FireEye/McAfee)'
        'mfemactl'              = 'Trellix (McAfee)'
        'masvc'                 = 'Trellix (McAfee)'
        'mcshield'              = 'Trellix (McAfee)'
        'FireEyeAgent'          = 'Trellix (FireEye)'
        # Cortex XDR (Palo Alto)
        'cortex-xdr'            = 'Palo Alto Cortex XDR'
        'CyveraService'         = 'Palo Alto Cortex XDR'
        'CortexXDR'             = 'Palo Alto Cortex XDR'
        # Cybereason
        'CybereasonAV'          = 'Cybereason'
        'CybereasonSensor'      = 'Cybereason'
        'minionhost'            = 'Cybereason'
        # Trend Micro Apex One / OfficeScan
        'TmCCSF'                = 'Trend Micro Apex One'
        'NTRtScan'              = 'Trend Micro Apex One'
        'Udt'                   = 'Trend Micro Apex One'
        'TmListen'              = 'Trend Micro Apex One'
        'PccNTMon'              = 'Trend Micro Apex One'
        'TmPfw'                 = 'Trend Micro'
        # ESET Endpoint Security
        'ekrn'                  = 'ESET Endpoint Security'
        'egui'                  = 'ESET Endpoint Security'
        'EsetSvc'               = 'ESET Endpoint Security'
        # Symantec / Broadcom SEP
        'ccSvcHst'              = 'Symantec Endpoint Protection'
        'Rtvscan'               = 'Symantec Endpoint Protection'
        'SMCgui'                = 'Symantec Endpoint Protection'
        # Sophos Intercept X
        'SophosAV'              = 'Sophos Intercept X'
        'SSPService'            = 'Sophos Intercept X'
        'SophosSafestore'       = 'Sophos Intercept X'
        'McsAgent'              = 'Sophos Intercept X'
        'SophosClean'           = 'Sophos Intercept X'
        # Kaspersky
        'avp'                   = 'Kaspersky'
        'kavtray'               = 'Kaspersky'
        # Bitdefender GravityZone
        'bdagent'               = 'Bitdefender GravityZone'
        'bdredline'             = 'Bitdefender GravityZone'
        'vsserv'                = 'Bitdefender GravityZone'
        # Malwarebytes
        'MBAMService'           = 'Malwarebytes'
        'mbam'                  = 'Malwarebytes'
        'MBAMAgent'             = 'Malwarebytes'
        # Cylance / BlackBerry Protect
        'CylanceSvc'            = 'BlackBerry Cylance'
        'CylanceUI'             = 'BlackBerry Cylance'
        # Tanium
        'TaniumClient'          = 'Tanium'
        'TaniumExecWrapper'     = 'Tanium'
        # Cisco Secure Endpoint (AMP)
        'sfc'                   = 'Cisco Secure Endpoint'
        'iptray'                = 'Cisco Secure Endpoint'
        'CiscoAMP'              = 'Cisco Secure Endpoint'
        # Deep Instinct
        'DeepInstinct'          = 'Deep Instinct'
        'DiPluginService'       = 'Deep Instinct'
        # Darktrace
        'darktrace-probe'       = 'Darktrace'
        # WithSecure / F-Secure
        'fssm32'                = 'WithSecure (F-Secure)'
        'fsav32'                = 'WithSecure (F-Secure)'
        'fshoster32'            = 'WithSecure (F-Secure)'
        # Qualys Cloud Agent
        'QualysAgent'           = 'Qualys Cloud Agent'
        'qualys-cloud-agent'    = 'Qualys Cloud Agent'
        # FortiClient / FortiEDR
        'FortiESNAC'            = 'Fortinet FortiClient'
        'FortiTray'             = 'Fortinet FortiClient'
        'fortiedr'              = 'Fortinet FortiEDR'
        # Check Point Harmony Endpoint
        'cpda'                  = 'Check Point Harmony'
        'TracSrvWrapper'        = 'Check Point Harmony'
        # Wazuh (open-source EDR/SIEM agent)
        'wazuh-agent'           = 'Wazuh Agent'
        'ossec-agent'           = 'Wazuh/OSSEC Agent'
        # Huntress
        'HuntressAgent'         = 'Huntress'
        'HuntressUpdater'       = 'Huntress'
        # Secureworks Taegis
        'iSensor'               = 'Secureworks Taegis'
        'RedCloakService'       = 'Secureworks Taegis'
        # Harfanglab
        'hurukai'               = 'HarfangLab EDR'
        # WatchGuard / Panda
        'PSANHost'              = 'WatchGuard Endpoint'
        'PCSF'                  = 'WatchGuard Endpoint'
    }

    $runningProcs = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName)
    $detectedEDR  = [System.Collections.Generic.List[string]]::new()
    foreach ($procName in $edrProcessMap.Keys) {
        if ($runningProcs -contains $procName) {
            $label = $edrProcessMap[$procName]
            if ($label -notin $detectedEDR) { $detectedEDR.Add($label) }
        }
    }

    # Merge both sources into a unified detected-product list
    $allDetected = @(@($wmiFriendly) + @($detectedEDR) | Where-Object { $_ } | Select-Object -Unique | Sort-Object)

    if ($allDetected.Count -gt 0) {
        Write-Log "Security software detected ($($allDetected.Count) product(s)):" 'Yellow'
        foreach ($p in $allDetected) { Write-Log "    $p" 'Yellow' }
        Write-Log "  ACTION REQUIRED before re-running on a production system:" 'Yellow'
        Write-Log "  Add the following exclusions in your security console:" 'Yellow'
        Write-Log "    Folder  : $PSScriptRoot  (entire toolkit - scripts + tools)" 'Yellow'
        Write-Log "    Folder  : $OutDir  (evidence output directory)" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\autorunsc64.exe" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\yara64.exe" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\winpmem.exe" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\procdump64.exe" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\strings64.exe" 'Yellow'
        Write-Log "    Process : $PSScriptRoot\tools\sigcheck64.exe" 'Yellow'
        Write-Log "  Continuing - phases use resilient wrappers, AV kills are logged not fatal." 'Yellow'

        # Check AMSI providers - script content scanning blocks PS scripts at load time.
        # Folder exclusions alone are NOT enough; Script Protection must also be excluded.
        $amsiProviders = @(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*' `
            -Name '(default)' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '(default)')
        $amsiStr = $amsiProviders -join ', '
        if ($amsiStr) { Write-Log "  AMSI providers active: $amsiStr" 'Yellow' }
        Write-Log "  AMSI blocks scripts at load time regardless of file-scan exclusions." 'Yellow'
        Write-Log "  Required: add '$PSScriptRoot' to Script Protection approved list in your AV console." 'Yellow'
    } else {
        Write-Log "Pre-flight: no known security software detected." 'Gray'
    }

    Write-Log "===================================================" 'Green'
    Write-Log " IR COLLECTION | host=$HostName | incident=$IncidentId" 'Green'
    Write-Log " output -> $OutDir" 'Green'
    Write-Log "===================================================" 'Green'

    # PHASE -1: Clock context - capture timezone, NTP status, and skew BEFORE any phase.
    # Cross-host timeline correlation requires every host's UTC offset and NTP sync state.
    # The responder's own epoch (reference) is passed so skew is measurable.
    if (Test-Path -LiteralPath $ClockScript) {
        $refEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        try {
            & $PSExe -ExecutionPolicy Bypass -NoProfile -File $ClockScript `
                -HostFolder $OutDir -IncidentId $IncidentId `
                -ReferenceEpoch $refEpoch -Quiet *>&1 | Out-Null
            Write-Log "  Clock context captured -> _clock.json" 'Gray'
        } catch { Write-Log "  Clock context capture skipped: $($_.Exception.Message)" 'Gray' }
    }

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
            } catch { Write-Log "  Firewall lockdown error: $($_.Exception.Message)" 'Yellow' }
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
        # Runs in a DETACHED Start-Process with timeout so AV terminating autorunsc
        # cannot propagate an exception back into the orchestrator pipeline.
        $autoruns = Get-ChildItem -Path (Join-Path $PSScriptRoot 'tools') -Filter 'autorunsc*.exe' -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
        if ($autoruns) {
            Write-Log "==== PHASE: Autoruns (staged $($autoruns.Name)) ====" 'Cyan'
            $autorunsOut = Join-Path $OutDir 'autoruns.csv'
            try {
                $proc = Start-Process -FilePath $autoruns.FullName `
                    -ArgumentList '-accepteula','-nobanner','-a','*','-c','-h','-s' `
                    -RedirectStandardOutput $autorunsOut `
                    -RedirectStandardError  'NUL' `
                    -NoNewWindow -PassThru -ErrorAction Stop

                # Wait up to 3 minutes; if AV kills or hangs, move on
                $done = $proc.WaitForExit(180000)
                if ($done -and $proc.ExitCode -eq 0) {
                    Write-Log "  Extended persistence snapshot -> autoruns.csv (exit 0)" 'Green'
                } elseif ($done) {
                    Write-Log "  Autoruns exited with code $($proc.ExitCode) - AV may have intervened; partial output kept." 'Yellow'
                } else {
                    $proc.Kill()
                    Write-Log "  Autoruns timed out after 3 min - killed; partial output kept." 'Yellow'
                }
            } catch {
                Write-Log "  Autoruns could not start: $($_.Exception.Message)" 'Yellow'
            }
        } else {
            Write-Log "Autoruns not staged (tools\autorunsc*.exe) - skipping (run Build-OfflineToolkit.ps1)." 'Gray'
        }

        # PHASE 1c: pure-PowerShell persistence breadth + config tamper + NTFS/evtx
        # (IFEO/Winlogon/LSA/AppInit, USN timeline, Amcache, full .evtx, firewall, creds)
        Invoke-Phase -Name 'Persistence' -ScriptPath $PersistScript -Arguments @('-OutputDir', $OutDir)

        # PHASE 1e: event-log CSV -> findings (runs on output from Phase 1c)
        Invoke-Phase -Name 'EventLogAnalysis' -ScriptPath $EvtLogScript `
            -Arguments @('-InputDir', $OutDir, '-OutputDir', $OutDir)

        # PHASE 1f: Amcache + ShimCache execution history -> findings
        # Reads amcache_parsed.csv and shimcache.bin from Persistence/ and emits
        # findings for programs executed from suspicious paths. Flows into adjudication.
        $persistenceDir = Join-Path $OutDir 'Persistence'
        if (Test-Path -LiteralPath $persistenceDir) {
            Invoke-Phase -Name 'AmcacheShimCache' -ScriptPath $AmcacheScript `
                -Arguments @('-InputDir', $persistenceDir, '-OutputDir', $OutDir)
        } else {
            Write-Log "AmcacheShimCache: Persistence dir not found, skipping." 'Gray'
        }

        # PHASE 1d: OPTIONAL live memory capture. Select tool with -MemoryTool:
        #   winpmem (default) - auto-staged via Build-OfflineToolkit.ps1 -IncludeMemory
        #                       RAW format; pads MMIO gaps (image may >> actual RAM)
        #   ftk               - FTK Imager CLI; place ftkimager.exe + DLLs in tools\ manually
        #                       compact output, captures only physical RAM pages
        #   magnet            - Magnet RAM Capture; place MRC.exe in tools\ manually
        #                       RAW format, captures only physical RAM pages
        if ($CaptureMemory) {
            # Resolve the actual exe path - Magnet ships with version suffix (e.g. MRCv120.exe).
            $memToolPath = $null
            switch ($MemoryTool) {
                'go-winpmem' { $memToolPath = Join-Path $PSScriptRoot 'tools\go-winpmem.exe' }
                'winpmem'    { $memToolPath = Join-Path $PSScriptRoot 'tools\winpmem.exe' }
                'ftk'        { $memToolPath = Join-Path $PSScriptRoot 'tools\ftkimager.exe' }
                'magnet'     {
                    # Accept MRC.exe or MRCv*.exe (Magnet ships with version suffix)
                    $mrc = Get-ChildItem -Path (Join-Path $PSScriptRoot 'tools') `
                               -Filter 'MRC*.exe' -ErrorAction SilentlyContinue |
                           Sort-Object Name -Descending | Select-Object -First 1
                    if ($mrc) { $memToolPath = $mrc.FullName }
                }
            }
            if (-not $memToolPath -or -not (Test-Path -LiteralPath $memToolPath)) {
                Write-Log "  SKIP: -MemoryTool '$MemoryTool' not found in tools\." 'Yellow'
                switch ($MemoryTool) {
                    'go-winpmem' { Write-Log "  Run: .\Build-OfflineToolkit.ps1 -IncludeMemory  to auto-stage go-winpmem." 'Yellow' }
                    'winpmem'    { Write-Log "  Run: .\Build-OfflineToolkit.ps1 -IncludeMemory  to auto-stage WinPmem." 'Yellow' }
                    'ftk'        { Write-Log "  Manual: install FTK Imager from exterro.com, copy ftkimager.exe + DLLs into tools\" 'Yellow' }
                    'magnet'     { Write-Log "  Manual: download Magnet RAM Capture from magnetforensics.com, place MRCv*.exe in tools\" 'Yellow' }
                }
                $memToolPath = $null
            }
            $memTool = $memToolPath

            if ($memTool) {
                $toolName = [System.IO.Path]::GetFileNameWithoutExtension($memTool)
                Write-Log "==== PHASE: Memory ($toolName) ====" 'Cyan'
                # Use -MemoryOutputPath when the output drive lacks space.
                # WinPmem RAW images pad ALL MMIO gaps - can be far larger than physical RAM.
                # FTK Imager captures only actual RAM pages, producing a more compact image.
                # Extension: .aff4 for go-winpmem (sparse, compact), .mem for FTK Imager, .raw otherwise.
                $memExt = switch ($MemoryTool) {
                    'go-winpmem' { '.aff4' }
                    'ftk'        { '.mem'  }
                    default      { '.raw'  }
                }
                $memImagePath = if ($MemoryOutputPath) { $MemoryOutputPath } `
                                else { Join-Path $OutDir "memory_$HostName$memExt" }
                $memLogPath   = Join-Path $OutDir "_Memory_$RunStamp.log"

                # Pre-flight: check free space on the target volume.
                # Space multiplier by tool:
                #   go-winpmem: AFF4 sparse streams - only physical RAM pages stored -> 1.25x
                #   ftk:        RAM pages only, compact output                       -> 1.25x
                #   magnet:     RAW, physical RAM only (no MMIO padding)             -> 1.25x
                #   winpmem:    RAW, pads FULL physical address space (MMIO gaps)    -> 4.0x
                $ramBytes = 0
                try { $ramBytes = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory } catch {}
                $spaceMultiplier = if ($MemoryTool -eq 'winpmem') { 4.0 } else { 1.25 }
                $requiredBytes   = [long]($ramBytes * $spaceMultiplier)
                $freeBytes = 0
                $memDriveRoot = [System.IO.Path]::GetPathRoot($memImagePath)
                try {
                    # PSDrive name is the letter only: 'C', 'D', etc.
                    $driveLetterOnly = $memDriveRoot.TrimEnd('\').TrimEnd(':')
                    $freeBytes = (Get-PSDrive -Name $driveLetterOnly -ErrorAction Stop).Free
                } catch {
                    try {
                        $diskId = $memDriveRoot.TrimEnd('\')
                        $freeBytes = (Get-CimInstance Win32_LogicalDisk `
                            -Filter "DeviceID='$diskId'" -ErrorAction SilentlyContinue).FreeSpace
                    } catch {}
                }

                # Detect filesystem type for the output volume.
                # Used both for the FAT32 file-size-limit check and for --nosparse dispatch below.
                $driveLetterOnly = $memDriveRoot.TrimEnd('\').TrimEnd(':')
                $memFs = $null
                try { $memFs = (Get-Volume -DriveLetter $driveLetterOnly -ErrorAction Stop).FileSystemType } catch {}

                $preflightOk = $true
                # Tracks whether we redirected capture to a temp path and need to move after.
                $memTempPath = $null

                # FAT32 hard limit: max file size = 4 GiB - 1 byte regardless of free space.
                # Auto-redirect: capture to C:\ (NTFS) then move to reports/<hostname>/ when done.
                if ($memFs -eq 'FAT32' -and $ramBytes -gt 0 -and $requiredBytes -gt 4GB) {
                    $needGiB = [math]::Round($requiredBytes / 1GB, 1)
                    Write-Log "  ${driveLetterOnly}: is FAT32 (4 GiB file size limit) - image needs ~${needGiB} GiB." 'Yellow'
                    Write-Log "  Auto-redirecting capture to C:\ (NTFS); will move to reports after completion." 'Cyan'
                    $memTempPath  = "C:\memory_$HostName$memExt"
                    $memImagePath = $memTempPath
                    # Recalculate free bytes on C: for the space check below
                    $freeBytes = 0
                    try { $freeBytes = (Get-PSDrive -Name 'C' -ErrorAction Stop).Free } catch {
                        try { $freeBytes = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue).FreeSpace } catch {}
                    }
                }

                if ($preflightOk -and $ramBytes -gt 0 -and $freeBytes -gt 0 -and $freeBytes -lt $requiredBytes) {
                    $needGiB = [math]::Round($requiredBytes / 1GB, 1)
                    $haveGiB = [math]::Round($freeBytes    / 1GB, 1)
                    Write-Log "  SKIP: insufficient disk space for memory image (need ~${needGiB} GiB, have ${haveGiB} GiB free on $memDriveRoot)." 'Yellow'
                    Write-Log "  Use -MemoryOutputPath to redirect to a volume with more free space (e.g. -MemoryOutputPath C:\memory_$HostName.aff4)." 'Yellow'
                    $script:PhaseResults['Memory'] = 'skipped'
                    $preflightOk = $false
                } elseif ($preflightOk -and $ramBytes -eq 0) {
                    Write-Log "  WARN: could not determine physical RAM size - skipping pre-flight disk space check." 'Yellow'
                } elseif ($preflightOk -and $freeBytes -eq 0) {
                    Write-Log "  WARN: could not determine free disk space on $memDriveRoot - proceeding without pre-flight check." 'Yellow'
                }

                if ($preflightOk) {
                    try {
                        # Dispatch to the selected memory capture tool.
                        switch ($MemoryTool) {
                            'go-winpmem' {
                                # $memFs detected in pre-flight above.
                                # --nosparse required on non-NTFS (FAT32 blocked by pre-flight; exFAT reaches here).
                                # Nosparse: MMIO gaps zero-padded -> image ~ physical address space.
                                # Sparse:   MMIO gaps omitted     -> image ~ physical RAM (NTFS only).
                                if ($memFs -and $memFs -ne 'NTFS') {
                                    Write-Log "  Filesystem on ${driveLetterOnly}: is '$memFs' - using --nosparse." 'Yellow'
                                    & $memTool 'acquire' '--nosparse' '--progress' $memImagePath 2>&1 | Tee-Object -FilePath $memLogPath -Append
                                } else {
                                    & $memTool 'acquire' '--progress' $memImagePath 2>&1 | Tee-Object -FilePath $memLogPath -Append
                                }
                            }
                            'ftk' {
                                # FTK Imager CLI: --memory captures only physical RAM pages.
                                & $memTool '--memory' $memImagePath 2>&1 | Tee-Object -FilePath $memLogPath -Append
                            }
                            'magnet' {
                                # Magnet RAM Capture v1.2.x: /accepteula bypasses the EULA dialog.
                                # Output path is selected via a GUI file-save dialog - no CLI flag.
                                # The application opens; save the capture to: $memImagePath
                                Write-Log "  Magnet RAM Capture: GUI required to select output path." 'Yellow'
                                Write-Log "  App opening - save capture to: $memImagePath" 'Yellow'
                                Write-Log "  Waiting for Magnet RAM Capture to finish (save and close the app)..." 'Cyan'
                                $mrcProc = Start-Process -FilePath $memTool -ArgumentList '/accepteula' `
                                    -PassThru -ErrorAction Stop
                                $mrcProc.WaitForExit()
                            }
                            default {
                                # WinPmem mini: positional output path, RAW format.
                                & $memTool $memImagePath 2>&1 | Tee-Object -FilePath $memLogPath -Append
                            }
                        }
                        $exitCode  = $LASTEXITCODE
                        $imageSize = 0
                        if (Test-Path -LiteralPath $memImagePath) {
                            $imageSize = (Get-Item -LiteralPath $memImagePath).Length
                        }
                        # Sanity floor: image must be at least 10% of physical RAM
                        $minValidBytes = [long]($ramBytes * 0.10)
                        if ($exitCode -eq 0 -and $imageSize -ge $minValidBytes) {
                            $sizeGiB = [math]::Round($imageSize / 1GB, 2)
                            $finalPath = $memImagePath
                            # If we captured to a temp path (FAT32 redirect), move to reports/<hostname>/.
                            if ($memTempPath -and (Test-Path -LiteralPath $memTempPath)) {
                                $destPath = Join-Path $OutDir "memory_$HostName$memExt"
                                $destRoot = [System.IO.Path]::GetPathRoot($destPath).TrimEnd('\').TrimEnd(':')
                                $destFree = 0
                                try { $destFree = (Get-PSDrive -Name $destRoot -ErrorAction Stop).Free } catch {
                                    try { $destFree = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${destRoot}:'" -ErrorAction SilentlyContinue).FreeSpace } catch {}
                                }
                                if ($destFree -gt $imageSize) {
                                    try {
                                        Move-Item -LiteralPath $memTempPath -Destination $destPath -Force -ErrorAction Stop
                                        $finalPath = $destPath
                                        Write-Log "  Moved memory image -> $destPath" 'Green'
                                    } catch {
                                        Write-Log "  Could not move to $destPath : $($_.Exception.Message)" 'Yellow'
                                        Write-Log "  Image remains at: $memTempPath" 'Yellow'
                                        $finalPath = $memTempPath
                                    }
                                } else {
                                    Write-Log "  Not enough space on ${destRoot}: to move image - leaving at $memTempPath" 'Yellow'
                                    $finalPath = $memTempPath
                                }
                            }
                            Write-Log "  Memory image captured: $finalPath (${sizeGiB} GiB)" 'Green'
                            $script:PhaseResults['Memory'] = 'success'
                        } else {
                            $sizeGiB = [math]::Round($imageSize / 1GB, 2)
                            Write-Log "  Memory capture FAILED (exit=$exitCode, size=${sizeGiB} GiB) - image is truncated or empty. See _Memory_*.log." 'Yellow'
                            $spaceNote = if ($MemoryTool -eq 'winpmem') { 'disk full (need RAM * 4x free - WinPmem RAW pads MMIO gaps)' } `
                                         else { 'disk full (need RAM * 1.25x free)' }
                            Write-Log "  Common causes: $spaceNote, AV blocked $toolName, HVCI/Memory Integrity blocking kernel driver, insufficient privileges." 'Yellow'
                            # Rename to INVALID_ so Analysis/Reporting don't treat it as a complete image.
                            if (Test-Path -LiteralPath $memImagePath) {
                                Rename-Item -LiteralPath $memImagePath `
                                    -NewName "INVALID_memory_$HostName$memExt" -ErrorAction SilentlyContinue
                            }
                            $script:PhaseResults['Memory'] = 'failed'
                        }
                    } catch {
                        Write-Log "  Memory capture error: $($_.Exception.Message)" 'Yellow'
                        $script:PhaseResults['Memory'] = 'failed'
                    }
                }
            } else {
                Write-Log "-CaptureMemory set but -MemoryTool '$MemoryTool' binary not found in tools\." 'Yellow'
            }
        }
    } else { Write-Log "Skipping forensics (-SkipForensics)." 'Yellow' }

    # PHASE 2: EDR fileless/evasion hunt (offline; no driver auto-update)
    if (-not $SkipHunt) {
        $edrArgs = @('-ScanProcesses','-ScanFileless','-ScanTasks','-ScanDrivers',
            '-ScanInjection','-ScanRegistry','-ScanETWAMSI','-ScanPendingRename',
            '-ScanBITS','-ScanCOM','-ReportPath', $OutDir)

        $fileScanEnabled = $DeepFileScan -or $FullScan
        if ($fileScanEnabled) {
            $edrArgs += @('-TargetDirectory', $ScanTarget, '-Recursive', '-ScanADS')
        }
        if ($DeepFileScan) {
            # QuickMode: excludes System32/SysWOW64/ProgramFiles + skips files older
            # than QuickModeDaysBack. Target runtime ~5-10 min on a typical C:\.
            $edrArgs += @('-QuickMode', '-QuickModeDaysBack', $QuickModeDaysBack)
            Write-Log "DeepFileScan: QuickMode ON, last $QuickModeDaysBack days, target=$ScanTarget" 'Yellow'
        }
        if ($FullScan) {
            # No QuickMode: scans all files and all ages. Thorough but slow (~45+ min on C:\).
            Write-Log "FullScan: QuickMode OFF, all files, target=$ScanTarget" 'Yellow'
        }
        if ($ScanYara) {
            if (-not $fileScanEnabled) { $edrArgs += @('-TargetDirectory', $ScanTarget, '-Recursive') }
            $edrArgs += '-ScanYara'
            Write-Log "YARA scan ENABLED." 'Yellow'
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
        foreach ($pat in 'EDR_Report_*.json','RemoteAccess_Findings_*.json','Persistence_Findings_*.json','findings_evtlog_*.json','findings_amcache_*.json','Memory_Findings_*.json') {
            $newest = Get-ChildItem -Path $OutDir -Filter $pat -File -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest) { try { $c = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json; if ($c) { $allFindings += $c } } catch {} }
        }

        if ($allFindings.Count -gt 0) {
            $combined = Join-Path $OutDir "Combined_Findings_$RunStamp.json"
            $allFindings | ConvertTo-Json -Depth 5 | Out-File -FilePath $combined -Encoding UTF8
            Write-Log "Merged $($allFindings.Count) finding(s) (EDR + remote-access + persistence + evtlog) -> $(Split-Path -Leaf $combined)" 'Gray'

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
            } catch { Write-Log "  IOC emission error: $($_.Exception.Message)" 'Yellow' }
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
            } catch { Write-Log "  Principal extraction error: $($_.Exception.Message)" 'Yellow' }
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
        } catch { Write-Log "  Reporting error: $($_.Exception.Message)" 'Yellow' }
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

    # PHASE: Egress observation (deferred). Start a scheduled sensor that logs outbound
    # connections over a window (default 24h) then auto-blackholes egress. Outbound stays
    # OPEN during the window so jittered/long-dwell C2 beacons are observed; the responder
    # RETURNS later to collect the egress evidence log. Runs after collection so it does not
    # compete with the live triage. Off with -NoEgressMonitor.
    if (-not $NoEgressMonitor) {
        Write-Log "==== PHASE: Egress Observation (start sensor; auto-blackhole at +$EgressWindowHours h) ====" 'Cyan'
        if (Test-Path -LiteralPath $EgressScript) {
            $egArgs = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $EgressScript,
                        '-Start','-IncidentId', $IncidentId, '-WindowHours', "$EgressWindowHours")
            $egMgmt = if (@($EgressMgmtIP).Count -gt 0) { $EgressMgmtIP } else { $AllowInboundRemoteAddress }
            if (@($egMgmt).Count -gt 0) { $egArgs += @('-MgmtIP') + ($egMgmt -join ',') }
            try {
                & $PSExe @egArgs *>&1 | Tee-Object -FilePath (Join-Path $OutDir "_Egress_$RunStamp.log") -Append
                Write-Log "  Egress sensor started. Return after the window to collect the evidence log + confirm blackhole." 'Green'
            } catch { Write-Log "  Egress monitor start error: $($_.Exception.Message)" 'Yellow' }
        } else {
            Write-Log "  SKIP - Watch-Egress.ps1 not found: $EgressScript" 'Yellow'
        }
    } else {
        Write-Log "Egress observation skipped (-NoEgressMonitor)." 'Yellow'
    }

    # Seal evidence custody - chain-of-custody record + manifest SHA256 + optional HMAC.
    # PS twin of playbooks/reporting/evidence_custody.py.
    $SealScript = Join-Path $PSScriptRoot 'playbooks\windows\Seal-EvidenceCustody.ps1'
    if (Test-Path -LiteralPath $SealScript) {
        try {
            & $PSExe -ExecutionPolicy Bypass -NoProfile -File $SealScript `
                -HostFolder $OutDir -IncidentId $IncidentId -Quiet *>&1 | Out-Null
            Write-Log "  Evidence custody sealed -> _custody_$RunStamp.json" 'Gray'
        } catch { Write-Log "  Custody seal skipped: $($_.Exception.Message)" 'Gray' }
    }

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
    # Remove the temporary Defender exclusions added at pre-flight.
    if ($defenderActive) {
        Write-Log "Removing temporary Defender exclusions..." 'Cyan'
        $toolsDir = Join-Path $PSScriptRoot 'tools'
        $regKey   = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        foreach ($folder in @($PSScriptRoot, $OutDir)) {
            # Remove from registry (primary method used at pre-flight)
            try { Remove-ItemProperty -Path $regKey -Name $folder -ErrorAction SilentlyContinue } catch {}
            # Also via cmdlet in case cmdlet fallback was used
            try { Remove-MpPreference -ExclusionPath $folder -ErrorAction SilentlyContinue } catch {}
        }
        $processesToExclude = @(
            'autorunsc64.exe','autorunsc.exe',
            'yara64.exe','yarac64.exe',
            'go-winpmem.exe','winpmem.exe',
            'ftkimager.exe',
            'procdump64.exe','procdump.exe',
            'sigcheck64.exe','sigcheck.exe',
            'handle64.exe','handle.exe',
            'strings64.exe','strings.exe',
            'Listdlls64.exe','Listdlls.exe',
            'tcpvcon64.exe','tcpvcon.exe',
            'pslist64.exe','pslist.exe'
        )
        # Also add Magnet RAM Capture (versioned filename, e.g. MRCv120.exe)
        $mrcExe = Get-ChildItem -Path (Join-Path $PSScriptRoot 'tools') `
                      -Filter 'MRC*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mrcExe) { $processesToExclude += $mrcExe.Name }
        foreach ($proc in $processesToExclude) {
            $fullPath = Join-Path $toolsDir $proc
            if (Test-Path $fullPath) {
                try { Remove-MpPreference -ExclusionProcess $fullPath -ErrorAction SilentlyContinue } catch {}
            }
        }
        # Restore Defender real-time monitoring
        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } catch {}
        Write-Log "Defender exclusions removed and real-time monitoring restored." 'Green'
    }

    # Restore all suspended AMSI providers unconditionally.
    if ($amsiSuspended -and $amsiSuspended.Count -gt 0) {
        $amsiRegKey = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
        foreach ($disabled in $amsiSuspended) {
            $original = $disabled -replace '_ir_disabled$',''
            $path = Join-Path $amsiRegKey $disabled
            if (Test-Path $path) {
                Rename-Item -Path $path -NewName $original -ErrorAction SilentlyContinue
            }
        }
        Write-Log "AMSI providers restored ($($amsiSuspended.Count))." 'Green'
    }

    # Remove IR Toolkit code-signing cert from this host - leave no trace.
    # Invoke-PrepareDefender.ps1 imported it; remove unconditionally on exit.
    $irCer = Join-Path $PSScriptRoot 'tools\ir_toolkit.cer'
    if (Test-Path -LiteralPath $irCer) {
        try {
            $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($irCer)
            foreach ($sn in @('Root','TrustedPublisher')) {
                $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($sn,'LocalMachine')
                $st.Open('ReadWrite')
                $found = @($st.Certificates | Where-Object { $_.Thumbprint -eq $x509.Thumbprint })
                foreach ($c in $found) { $st.Remove($c) }
                $st.Close()
            }
            Write-Log "IR Toolkit code-signing cert removed from LocalMachine cert stores." 'Green'
        } catch { Write-Log "  Cert removal warning: $($_.Exception.Message)" 'Yellow' }
    }

    # Harden: restore a secure execution policy now that collection is done.
    Write-Log "Restoring secure execution policy ($PostRunExecutionPolicy)..."
    Set-EPWithFallback -Policy $PostRunExecutionPolicy | Out-Null
    Write-Log "Runtime log: $RunLog" 'Green'

    # Re-enable Tamper Protection - it was left OFF for the entire scan so AMSI would
    # not block the phase scripts. Microsoft blocks programmatic re-enable, so this is
    # the one GUI toggle the user must do; we open Windows Security and wait for it.
    $tpNow = $null
    try { $tpNow = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}
    if ($tpNow -eq $false) {
        Write-Log "Re-enabling Tamper Protection (manual GUI step - it must be turned back ON)." 'Cyan'
        Write-Host ""
        Write-Host "  Tamper Protection is still OFF. Turn it back ON now:" -ForegroundColor Yellow
        Write-Host "    1. Windows Security > Virus & threat protection > Manage settings" -ForegroundColor Yellow
        Write-Host "    2. Toggle Tamper Protection ON and confirm the UAC prompt." -ForegroundColor Yellow
        try { Start-Process 'windowsdefender://threatsettings' -ErrorAction SilentlyContinue } catch {}
        $tpDots = 0
        while (((Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected) -eq $false) {
            Start-Sleep -Seconds 2; $tpDots++
            if ($tpDots % 5 -eq 0) { Write-Host "    waiting for Tamper Protection to be re-enabled..." -ForegroundColor DarkGray }
            if ($tpDots -gt 90) { Write-Log "Tamper Protection not re-enabled within 3 min - please enable it manually." 'Yellow'; break }
        }
        if (((Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected) -eq $true) {
            Write-Log "Tamper Protection re-enabled." 'Green'
        }
    }
}

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA00cGApcufORjG
# YTsWv5ila7oMIb17Mpe70BEnitZSdKCCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
# nkbveZC/LiR8MA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjIwNDI0NDVaFw0zMTA2MjIwNDM0NDVaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKuTSorzjXf0qc4qX04KtYn2ErVj9RAkn/1f/9YN
# llrRj0s3urh/LnWmHn4vUjPrDTzHXUx4udOclWNlv52uCMAfXKZR3qD73OCHHQ2l
# +1s4JqrAdGhr6QPyIhCDwl7wqQUfekQtBep+SqbM0vkbvup3WKgol+c3fIUxvM8E
# bPLg5CcNWug6Twj+Wn1FJidJihmYARSKT5PFv32BLbffUpuvdWXxzRIRv8c4EE+S
# bWs3lTiCGrp1X33mXYiMRNAiF5ofrCJwRA7LESh4TCqXWDSvs+KFBi1ZxEnLxmUk
# 1Wrzq11umlIzoJhnEN0VyBvLK6X40uTF50piU+5kGy9kZlkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSpc1pf
# XTSlgxdtXKDrlumz7H67TjANBgkqhkiG9w0BAQsFAAOCAQEAdPAxdgyk/YzF72lK
# 4P1I3Lwjice2yAR0aoXSEP5gO/xnAvuqCiAcdPfJhqMrrfq5iFLqTuWSfz+k9irn
# hjzyWgmo2GUrQ8BVRoNAw7HpTJo7Rw8+FfDzyy+stq9UKWrkflHqwb7oBD+aBs/5
# ZccFKZi8oeV79CCTGdwXKYgE+xYbV//Twr7rpMbVUqbchEDdZXEzT2GdEUd5B02L
# bDGJ4Gjz8AtCFcSXWQlLnAQxd5CJVFHDkyfkEs2VvBPtR/MBCF3NiNufb8HgClhS
# ZHayqVVZhUd+NS7/orBY5M1Ioc0/kGiNO3nlWf1IlAPk/jsILweFZkUO0wBTot/O
# b18zszCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zC
# pyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf
# 1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x
# 4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEio
# ZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7ax
# xLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZ
# OjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJ
# l2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz
# 2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH
# 4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb
# 5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ
# 9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuC
# MS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0g
# ADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs
# 7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq
# 3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/
# Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9
# /HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWoj
# ayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0
# MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2
# IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U
# 1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt
# 281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9R
# aUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd
# 2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25L
# CHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0
# xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVV
# WcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0
# ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/
# DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd7
# 6CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEA
# AaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZ
# UEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB
# /wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgw
# gYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEF
# BQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUq
# rfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWP
# oSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3Im
# ZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhc
# UT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp
# 7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtf
# parz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu
# /CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9
# SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnM
# G3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSe
# y2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9
# xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFQzCCBT8CAQEwZzBTMRow
# GAYDVQQLDBFJbmNpZGVudCBSZXNwb25zZTETMBEGA1UECgwKSVIgVG9vbGtpdDEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBsvfGvcX1ueRu95kL8u
# JHwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0Z0TJwkWOa/iGbZMK9o5OOGBw1YSvgVh
# 932nXfY7joowDQYJKoZIhvcNAQEBBQAEggEApG2jXws+QWxddTZn9YkUktHSD80b
# rhPKQU0vkHVSLi6bx2BHaStULlWnaYbbS6cGw2OuPEwJIbZdNNFiA3HJvM27rBsL
# ftQ9pWb8Vnrc9Co5Z4kKCAFAFzYYy3cOv+P85TZcIeqSTaajMM2+cI/Q2qs0cAro
# vFuNBx468rIMWAGX+MZsKdz6RoY5q2rVtgveUsMdOMaqj/vQXQOmF5TakeFPUmZa
# +5dadVwNmClO5VJ2c0Dye1RRygYVuIEfGcRqUMaKKqbfQBKtmNeOFzZmLBVVAWZA
# 1IJ2JoAS9pwp9a0bhnwKWGlC9YiwygSn5pTnHJ8A4qdHlOXGqFdWzhvb6qGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NDlaMC8GCSqGSIb3DQEJBDEi
# BCB0wUdWc4A76J+sak/NjiCHuBatihoBK3oHseJR11GDgzANBgkqhkiG9w0BAQEF
# AASCAgCpPPHPtU8w2zpzUsyzx5jhn1pShcc5MYQ9dGuHUhkhba7F31jYq2AfQfHU
# FPtMYIA7mON341QecsT2UwIEZPJcGEfK2dsiuoBdvU7HMxK5kTl8KLrZcP9MQDQc
# dqAOnKhU+1I3BEI1fQOo0g8lLd3p1qU1aTBYYWsss1YJ3XSRyu58UfkAVMmqdC+M
# JLFCeUQuS4DXyZ96J1jPoJqNGlpq83L9Cq928NgIJmhnhnhVguRpgz5Yp/ZyoNAB
# maKZPV7PlG9pvP1BQ7qiTODwtkGNJBZ7U37qxNn7GiNTTnzN+Dia73I9qH2+fdMH
# kWx/TDDEIZO4SZSJL8qEtVU3zLXBNNpv5ujEhR3+ped8AtLVkqiQFIPmHibS7w1P
# /vbRV+cia0LYuvK7jhWXuHbJN6eDCX/qRRz49r8SO8k8GoYGl42fDP68zNptgJfw
# 4pRDyi/V62YPQ191M59pJYcs3WyLu1uf3O3pU9opMkKReT1JVZq+FQ7p5/jR08PE
# dOMj7bDHOV2ufdtDCtLf5UynjS4TjqW/Buqy6z8nmQr8LMZpCLx8f1t3gEOzYxDN
# vCKeeIhGMbfOKzI093Xgw+BM8ZXx5dkwnrGnEHzxqGBvAx6wb8TFOuN/0XyYh6gH
# /GCTAeF+cKx4BGCIV8Q0gh0ZdnvIpD0y9GyMOibkRMxvYEFm6g==
# SIG # End signature block
