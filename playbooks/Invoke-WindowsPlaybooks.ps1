<#
.SYNOPSIS
    Standalone orchestrator for the Windows RESPONSE playbooks (contain / eradicate /
    block-C2 / acquire / restore). Completely separate from the collection workflow
    (Invoke-IRCollection.ps1) - this one CHANGES the host.
.DESCRIPTION
    Runs the playbooks in playbooks\windows\ in canonical IR order, feeding each its
    inputs via the IR_* environment variables the scripts expect. Each playbook
    runs in its own powershell process and its output is logged to a Response folder.

    These actions are DESTRUCTIVE (kill processes, isolate the network, quarantine
    files, sinkhole domains). The orchestrator therefore:
      * runs nothing unless you both pass -Phases AND -Confirm (otherwise it prints
        the plan and exits - a dry run),
      * refuses Contain without -MgmtIPs (would sever remote access),
      * always runs phases in safe order regardless of the order you list them.

.PARAMETER Phases   Which playbooks to run: Collect, Contain, EradicateProcess,
                    EradicatePersistence, BlockC2, Acquire, Restore.
.PARAMETER Confirm  Required to actually execute. Without it: dry-run plan only.
.EXAMPLE
    # Dry-run plan:
    .\Invoke-WindowsPlaybooks.ps1 -Phases EradicateProcess,BlockC2 -MaliciousPids 6624 -C2IPs 8.8.8.8
.EXAMPLE
    # Execute containment + eradication:
    .\Invoke-WindowsPlaybooks.ps1 -Phases Contain,EradicateProcess,BlockC2 `
        -MgmtIPs 10.0.0.5 -MaliciousProcesses anydesk -C2IPs 45.61.2.3 -Confirm
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Collect','Contain','EradicateProcess','EradicatePersistence','BlockC2','Acquire','Restore')]
    [string[]]$Phases,
    [string]$IncidentId,
    [string]$OutputRoot = $PSScriptRoot,
    # Inputs consumed by the playbooks (comma-separated where plural):
    [string]$MgmtIPs,
    [string]$MaliciousPids,
    [string]$MaliciousProcesses,
    [string]$MaliciousHashes,
    [string]$MaliciousPaths,
    [string]$C2IPs,
    [string]$C2Domains,
    [string]$TargetPath,
    [string]$QuarantineUri,
    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $IncidentId) { $IncidentId = "$($env:COMPUTERNAME)_$RunStamp" }
if (-not $OutputRoot) { $OutputRoot = (Get-Location).Path }
$OutDir = Join-Path $OutputRoot ("Response_" + $IncidentId)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$RunLog = Join-Path $OutDir "_response_$RunStamp.log"

function Write-Log { param([string]$M,[string]$C='Gray')
    $line="[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $M"; Write-Host $line -ForegroundColor $C
    $line | Out-File -FilePath $RunLog -Append -Encoding UTF8
}

# Canonical phase order + script mapping. (00 is param-based; 01-06 read IR_* env.)
$PhaseDefs = [ordered]@{
    Collect              = @{ Order=0; Script='windows\00_Collect-Forensics.ps1'; Destructive=$false }
    Contain              = @{ Order=1; Script='windows\01_Contain-Host.ps1';      Destructive=$true  }
    EradicateProcess     = @{ Order=2; Script='windows\02_Eradicate-Process.ps1'; Destructive=$true  }
    EradicatePersistence = @{ Order=3; Script='windows\03_Eradicate-Persistence.ps1'; Destructive=$true }
    BlockC2              = @{ Order=4; Script='windows\04_Block-C2.ps1';           Destructive=$true  }
    Acquire              = @{ Order=5; Script='windows\05_Acquire-Artifact.ps1';   Destructive=$false }
    Restore              = @{ Order=6; Script='windows\06_Restore-Host.ps1';       Destructive=$true  }
}

if (-not $Phases) {
    Write-Host "No -Phases specified. Available (canonical order):" -ForegroundColor Yellow
    $PhaseDefs.Keys | ForEach-Object { Write-Host "  - $_" }
    Write-Host "Re-run with -Phases <...> (and -Confirm to execute)." -ForegroundColor Yellow
    return
}

# Map inputs to the IR_* env vars the playbooks read (set once; children inherit).
$env:IR_INCIDENT_ID = $IncidentId
if ($PSBoundParameters.ContainsKey('MgmtIPs'))            { $env:IR_MGMT_IPS            = $MgmtIPs }
if ($PSBoundParameters.ContainsKey('MaliciousPids'))      { $env:IR_MALICIOUS_PIDS      = $MaliciousPids }
if ($PSBoundParameters.ContainsKey('MaliciousProcesses')) { $env:IR_MALICIOUS_PROCESSES = $MaliciousProcesses }
if ($PSBoundParameters.ContainsKey('MaliciousHashes'))    { $env:IR_MALICIOUS_HASHES    = $MaliciousHashes }
if ($PSBoundParameters.ContainsKey('MaliciousPaths'))     { $env:IR_MALICIOUS_PATHS     = $MaliciousPaths }
if ($PSBoundParameters.ContainsKey('C2IPs'))              { $env:IR_C2_IPS              = $C2IPs }
if ($PSBoundParameters.ContainsKey('C2Domains'))          { $env:IR_C2_DOMAINS          = $C2Domains }
if ($PSBoundParameters.ContainsKey('TargetPath'))         { $env:IR_TARGET_PATH         = $TargetPath }
if ($PSBoundParameters.ContainsKey('QuarantineUri'))      { $env:IR_QUARANTINE_URI      = $QuarantineUri }

# Resolve + order the requested phases.
$plan = $Phases | Select-Object -Unique | Sort-Object { $PhaseDefs[$_].Order }

# Safety preconditions
$abort = $false
if (($plan -contains 'Contain') -and -not $MgmtIPs) {
    Write-Log "REFUSED: Contain requires -MgmtIPs (otherwise you isolate yourself out)." 'Red'; $abort = $true
}
if (($plan -contains 'Acquire') -and -not $TargetPath) {
    Write-Log "REFUSED: Acquire requires -TargetPath." 'Red'; $abort = $true
}
if ($abort) { return }

$mode = if ($Confirm) { 'EXECUTE' } else { 'DRY-RUN' }
Write-Log "===================================================" 'Green'
Write-Log " WINDOWS RESPONSE PLAYBOOKS ($mode) | incident=$IncidentId" 'Green'
Write-Log " plan: $($plan -join ' -> ')" 'Green'
Write-Log " output -> $OutDir" 'Green'
Write-Log "===================================================" 'Green'

$PSExe = (Get-Process -Id $PID).Path
if (-not $PSExe) { $PSExe = Join-Path $PSHOME 'powershell.exe' }

$results = foreach ($name in $plan) {
    $def = $PhaseDefs[$name]
    $script = Join-Path $PSScriptRoot $def.Script
    $rec = [ordered]@{ Phase=$name; Script=$def.Script; Destructive=$def.Destructive; Status='' }
    if (-not (Test-Path -LiteralPath $script)) { Write-Log "SKIP $name - not found: $script" 'Yellow'; $rec.Status='missing'; [PSCustomObject]$rec; continue }

    $tag = if ($def.Destructive) { '[DESTRUCTIVE]' } else { '' }
    if (-not $Confirm) {
        Write-Log "WOULD RUN: $name $tag -> $($def.Script)" 'Yellow'; $rec.Status='planned'; [PSCustomObject]$rec; continue
    }

    Write-Log "==== RUN: $name $tag ====" 'Cyan'
    $phaseLog = Join-Path $OutDir ("_{0}_{1}.log" -f $name, $RunStamp)
    $argList  = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $script)
    if ($name -eq 'Collect') { $argList += @('-OutputDir', $OutDir, '-IncidentId', $IncidentId) }
    try {
        & $PSExe @argList *>&1 | Tee-Object -FilePath $phaseLog -Append
        Write-Log "  $name complete (log: $(Split-Path -Leaf $phaseLog))" 'Green'; $rec.Status='ran'
    } catch { Write-Log "  ERROR in ${name}: $($_.Exception.Message)" 'Red'; $rec.Status='error' }
    [PSCustomObject]$rec
}

[ordered]@{
    incident_id=$IncidentId; host=$env:COMPUTERNAME; mode=$mode
    generated_utc=(Get-Date).ToUniversalTime().ToString('o'); plan=$plan; results=$results
} | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $OutDir "response_summary_$RunStamp.json") -Encoding UTF8

Write-Log "===================================================" 'Green'
Write-Log " RESPONSE $mode COMPLETE" 'Green'
if (-not $Confirm) { Write-Log " DRY-RUN: nothing changed. Add -Confirm to execute." 'Yellow' }
Write-Log " $OutDir" 'Green'
Write-Log "===================================================" 'Green'
