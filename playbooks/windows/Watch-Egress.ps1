# ==============================================================================
# IR Playbook - Windows Egress Observation Sensor + Deferred Outbound Blackhole
#
# WHY THIS EXISTS
#   Inbound is locked down during containment (Enforce-StrictFirewall.ps1), but
#   outbound is deliberately left OPEN during the analysis window so we can SEE
#   where the implant beacons / exfils to. C2 beacons jitter and can dwell for
#   HOURS, so a single point-in-time netstat at collection time routinely misses
#   them. This sensor registers a scheduled task that snapshots outbound
#   connections on a cadence over an extended window (default 24h), appends every
#   external egress flow to an append-only evidence log, then AUTOMATICALLY
#   blackholes outbound (Enforce-StrictFirewall.ps1 -BlockOutbound) when the
#   window closes.
#
#   This changes the workflow: after collection the responder LEAVES the sensor
#   running and RETURNS later to (1) collect the egress evidence log and (2)
#   confirm the blackhole fired. See WORKFLOW-WINDOWS.md "Egress observation".
#
#   OPTIONAL. Observation tolerates continued exfil during the window. For a
#   DATA-SENSITIVE host, do NOT observe - fully isolate the network stack first
#   (01_Contain-Host.ps1 = inbound+outbound) and skip this (-NoEgressMonitor):
#   eliminating further data loss outranks mapping the C2 when the data matters.
#
# USAGE
#   Watch-Egress.ps1 -Start [-WindowHours 24] [-IntervalMin 1] [-IncidentId ID]
#                    [-MgmtIP a,b]
#   Watch-Egress.ps1 -Status    [-IncidentId ID]
#   Watch-Egress.ps1 -Collect   [-IncidentId ID]   # report the evidence log
#   Watch-Egress.ps1 -Blackhole [-IncidentId ID]   # blackhole outbound NOW
#   Watch-Egress.ps1 -Stop      [-IncidentId ID]   # tear sensor down (no blackhole)
#   Watch-Egress.ps1 -Snapshot  -IncidentId ID     # internal (called by the task)
#
# Reversible: the outbound blackhole is applied via Enforce-StrictFirewall.ps1,
# whose .wfw binary backup restores the pre-incident firewall (-Rollback).
# ==============================================================================
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Start')]    [switch]$Start,
    [Parameter(ParameterSetName = 'Snapshot')] [switch]$Snapshot,
    [Parameter(ParameterSetName = 'Blackhole')][switch]$Blackhole,
    [Parameter(ParameterSetName = 'Stop')]     [switch]$Stop,
    [Parameter(ParameterSetName = 'Collect')]  [switch]$Collect,
    [Parameter(ParameterSetName = 'Status')]   [switch]$Status,
    [int]$WindowHours = 24,
    [int]$IntervalMin = 1,
    [string]$IncidentId = $(if ($env:IR_INCIDENT_ID) { $env:IR_INCIDENT_ID } else { 'UNKNOWN' }),
    [string[]]$MgmtIP = @($(if ($env:IR_MGMT_IPS) { $env:IR_MGMT_IPS -split ',' } ))
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId = ($IncidentId -replace '[^\w\-]', '')
$StateDir   = Join-Path $env:ProgramData "IRToolkit\egress-$IncidentId"
$Log        = Join-Path $StateDir "egress-$IncidentId.log"
$Meta       = Join-Path $StateDir "meta.json"
$DoneMarker = Join-Path $StateDir "blackhole.done"
$PollTask   = "IR-Egress-Poll-$IncidentId"
$BHTask     = "IR-Egress-Blackhole-$IncidentId"
$SelfPath   = $MyInvocation.MyCommand.Path
$MgmtIP     = @($MgmtIP | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Out-Json { param([hashtable]$H) ($H | ConvertTo-Json -Compress) | Write-Output }

# External = not loopback / RFC1918 / link-local / unspecified / management.
function Test-External {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    if ($ip -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { return $false }
    if ($ip -match '^(10\.|192\.168\.|169\.254\.|fe80:|ff|224\.|127\.)') { return $false }
    if ($ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $false }
    if ($MgmtIP -contains $ip) { return $false }
    return $true
}

function Invoke-Snapshot {
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    try {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-External $_.RemoteAddress) {
                $proc = ''
                try { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
                "$ts | tcp | $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) | $proc(pid=$($_.OwningProcess))" |
                    Out-File -FilePath $Log -Append -Encoding UTF8
            }
        }
    } catch {}
}

switch ($PSCmdlet.ParameterSetName) {
'Start' {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    @{ start = (Get-Date).ToUniversalTime().ToString('o'); window_hours = $WindowHours
       interval_min = $IntervalMin; mgmt_ip = $MgmtIP } | ConvertTo-Json | Set-Content $Meta -Encoding UTF8
    "# IR egress observation - incident $IncidentId - started $((Get-Date).ToUniversalTime().ToString('o'))" |
        Out-File $Log -Encoding UTF8

    # Polling task: snapshot every IntervalMin minutes for the whole window
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`" -Snapshot -IncidentId $IncidentId"
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin) `
        -RepetitionDuration  (New-TimeSpan -Hours   $WindowHours)
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $PollTask -Action $act -Trigger $trg -Principal $pr -Force | Out-Null

    # One-shot blackhole task at window close: blackhole egress + remove the poller
    $bhArg = "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`" -Blackhole -IncidentId $IncidentId"
    if ($MgmtIP.Count) { $bhArg += " -MgmtIP $($MgmtIP -join ',')" }
    $bhAct = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $bhArg
    $bhTrg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours($WindowHours)
    Register-ScheduledTask -TaskName $BHTask -Action $bhAct -Trigger $bhTrg -Principal $pr -Force | Out-Null

    Invoke-Snapshot
    Out-Json @{ phase = 'egress_observation'; status = 'started'; incident_id = $IncidentId
                window_hours = $WindowHours; log = $Log; poll_task = $PollTask; blackhole_task = $BHTask }
}
'Snapshot' { Invoke-Snapshot }
'Blackhole' {
    if (Test-Path $DoneMarker) { Write-Output "egress already blackholed for $IncidentId"; break }
    $enforce = Join-Path $PSScriptRoot 'Enforce-StrictFirewall.ps1'
    $bhParams = @{ BlockOutbound = $true }
    if ($MgmtIP.Count) { $bhParams['AllowOutboundPort'] = @(22, 3389, 5985, 5986); $bhParams['AllowOutboundRemoteAddress'] = $MgmtIP }
    if (Test-Path $enforce) { & $enforce @bhParams }
    else { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block }
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    New-Item -ItemType File -Path $DoneMarker -Force | Out-Null
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
    try { Write-EventLog -LogName Application -Source 'IRToolkit' -EventId 7702 -EntryType Warning `
            -Message "EGRESS BLACKHOLED for $IncidentId after observation window" -ErrorAction SilentlyContinue } catch {}
    Out-Json @{ phase = 'egress_blackhole'; status = 'success'; incident_id = $IncidentId; evidence_log = $Log }
}
'Stop' {
    Unregister-ScheduledTask -TaskName $PollTask -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $BHTask   -Confirm:$false -ErrorAction SilentlyContinue
    Out-Json @{ phase = 'egress_observation'; status = 'stopped'; incident_id = $IncidentId }
}
'Collect' {
    if (Test-Path $Log) {
        $flows = (Get-Content $Log | Where-Object { $_ -notmatch '^#' }).Count
        $uniq  = (Get-Content $Log | Select-String -Pattern '-> ([0-9a-fA-F:.]+):' -AllMatches |
                  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique).Count
        Out-Json @{ phase = 'egress_observation'; status = 'collect'; incident_id = $IncidentId
                    evidence_log = $Log; flows_logged = $flows; unique_destinations = $uniq
                    blackhole = $(if (Test-Path $DoneMarker) { 'done' } else { 'pending' }) }
    } else { Write-Error "no egress log for $IncidentId at $Log" }
}
default {
    if (Test-Path $Meta) {
        $m = Get-Content $Meta -Raw | ConvertFrom-Json
        Out-Json @{ phase = 'egress_observation'; status = 'running'; incident_id = $IncidentId
                    started = $m.start; window_hours = $m.window_hours; log = $Log
                    blackhole = $(if (Test-Path $DoneMarker) { 'done' } else { 'pending' }) }
    } else { Write-Error "no egress observation active for $IncidentId" }
}
}
