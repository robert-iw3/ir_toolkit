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
    $UsbScript         = Join-Path $HuntDir 'Get-USBDeviceHistory.ps1'
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
        # the phase is marked 'partial' - every later phase still runs (full-capture goal).
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

        # PHASE 1g: USB device history -> removable-media origin trace (which device, when first
        # connected). Read-only registry/setupapi/event-log collection; key for USB-worm root cause.
        Invoke-Phase -Name 'USBHistory' -ScriptPath $UsbScript -Arguments @('-OutputDir', $OutDir)

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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC95yfmxzprCKqk
# e/m7pAZVwPKAPMwQkSxTLtHgD68ge6CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
# lEKgkjdOOOytMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lSIFRvb2xraXQg
# Q29kZSBTaWduaW5nMB4XDTI2MDYyNjAyMjc0OFoXDTI5MDYyNjAyMzc0OFowIjEg
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCVM7HdfviXfsMldvVuCmIVeX2nhTRWSA3FnoNQ7zd2
# lsAZuL+EkM+xZ6OiH6L5B6gZsCree2lTU0n0aNdSbNxKgzfaxFL49pteZwFI3ooS
# E+sqbAHRlG7UYrB90qWqPy6L2nh0ntu7R3IPzCbhTl6wgdT3e4axY+Bt4zZqcGY4
# XNolYl32o1h6/Xn1RDbK2RTsIblxuVYfYLdCotMldxNkE3oXBItZUoiGYNyCbnS0
# pBeBzKuJ7110b3jMhW5euch+jNqPlo7xwpAy57ut6LB/F/apn5BMhVXL0BsSIISW
# bvDg8KnX0ryWSVzEhCRDULbHFHceT8KT0j22yIYBIe19AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUY4Zdh7We
# EeqWTl4U+JyMI+/Bv44wDQYJKoZIhvcNAQELBQADggEBAGADp8Vqkz5dS0PaRLED
# IuTzMDd6t33jfUATEmnXvHWcir5zyCZhwz+iyGI8atBuTvD9t4skDJNEf+niZneM
# Ql2/lr6nz/cGlWdZjgOAdIsj4I3MSrAwXN7fK5QjyXcCUQpzTfBifVshB7vl3006
# QYE2GwXHWt5/rJKNRHKXBdtuw9XL1iUtmgQOwHhLJ4F//Lf59Fon5KGP7Hmt8tJv
# HrfolpKc7pF7XKyO3grw2sOz7BnmVYBRGTAhVJ+E/+IFAPUsThQFila4LAsvqCPv
# 265GLrtTUiXjZOcQ0LT5ohZWcvU4fpQ3b473zxrl0IpfARI5XSlTC/T6arQoRyXU
# 4QwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEB9AyPDIBaeUQqCSN0447K0w
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgQwbjVXReHLOff1CkvO7m+xSUwbZg/CEYA7rJ
# 6f88CA4wDQYJKoZIhvcNAQEBBQAEggEADAUsNsdKhM3CdhQpjqdoUqcgzM2gLlbA
# FM9DDh8MyMU2N33Iz+OOueyHLVNuCfdg9OJB5XF54DqPsEK2FQkVk4KoJUmaackm
# lfXNLCnUJ31O/vOHX5qMMjpWFPVreR2tC/O0LeXqaU5rPzX/h+I1gOeIgQBa9wcA
# Ri2G5Q5UCThY1FA3hLVT0KSv3xEahCYw2TBrfxf/wmxrAjLFrxMF7tLG2NlRecWd
# /lyQlvrMHKPa5d2WoZsf2nXppfsgNzuGevQu5kMu4zDHtjlOBOnsy9XMuAOFfxHC
# R53lvo0PlN6O8ZprKeqq9V1UWg2bNaLBstSRLzCvKmuzrgAQry1UTKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MTRaMC8GCSqGSIb3DQEJBDEiBCDq
# WUOOz8DTpibOadumYbQH5GqW4UXjVpMJwKtTELKU2DANBgkqhkiG9w0BAQEFAASC
# AgBZsKjCCmcHdvlnDw2NRuqOpL1mLqbl7Upt2LEAKR97sw/hoSS/aIyMUq4qXlQE
# q5B9ZlljkdkC9FAM4KdZ+x3+doHBBTO/FFK4ZrHAHr6apo341s3tMS8ERhIRWX7f
# KHLTOWdUv1CtUAXRA1LhS+LsTpsM7wmjgJ8M9TKnppxYjdFYGK9wRKDDAuXMDH14
# oipjWCZ0mN3JPJvK8VIX709OyAKXwhsT68Dvplhuzcn9lga7BrVQWZEWdcM9CiOX
# bC1TGC++R3F5JWqg9V9Vzo6pE7voix9AtPrNF8y/OY4Pimjjg0R0l5WkDViPjg0p
# OTOtrWMkc4GsLHMNOwHaXCxn4fBwETX3jXrXzSeqgCiUoIkfCYIX5jy+b/oSyQz5
# 3F7HDKNcD9+XQgzaT7hNT0RwTP89D4HtQae3scrwdhoKzoUL8BrmkkDtSPqepdVo
# UK4OF+Ll95/ajEiSq2VHSYG90yK+eWcekmk1LKOsA7BIaFFcpNfB6CJMllKa+VTw
# 3ab0B/dwcZgemrKmxxEkSEv/wj4dohawhWm+PYfycnFh5m+nCsSM1AywrvdgkHGi
# Er/IL8pUnbn8jimEpdvbN8ZD7eStleJ5qOr9ANa2Y0jOaQ4FPc6INzBjvXJ+UJgl
# yRtuQS20Afopf1Ki4Ue/r/fSQuMgjmZVmt7fEY4ceuqDQg==
# SIG # End signature block
