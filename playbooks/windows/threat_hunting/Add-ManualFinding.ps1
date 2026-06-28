<#
.SYNOPSIS
    Appends a manually-discovered finding to ManualFindings_<host>.json in the
    format expected by Invoke-Eradication.ps1 -AdjudicationPath.

.DESCRIPTION
    Invoke-Eradication.ps1 reads from Adjudication_*.json produced by the toolkit's
    automatic pipeline. When further investigation (manual VAD analysis, live triage,
    enrichment) surfaces additional true positives, use this script to record them in
    the same schema so the eradication script can act on them without modification.

    It also handles two supplemental IOC types that feed the firewall-restore and
    memory-scope sections of Invoke-Eradication.ps1 via IOCs.json:
        -AddC2Endpoint    -> c2_endpoints[] (firewall block + hosts sinkhole)
        -AddMemoryArtifact -> memory_eradication{} (analyst-review surface)

    Dry-run by default. Shows the planned eradication action without writing anything
    until you add -Confirm.

.PARAMETER HostFolder
    Per-host report folder (e.g. .\reports\MAIN-SYS). Default: current directory.

.PARAMETER Type
    Finding type. Controls which eradication handler fires:
        Process           -> kill PID + quarantine binary
        ScheduledTask     -> disable + unregister task
        COM               -> remove HKCU/HKLM CLSID server key
        BITS              -> remove BITS transfer job
        RemoteAccess      -> kill process + disable/remove service
        DefenderExclusion -> remove Defender exclusion path
        Manual            -> surfaces in report but no automated action

.PARAMETER Target
    Identifier for the finding. Format varies by Type:
        Process           -> "ProcessName (PID: 1234)"
        ScheduledTask     -> "Task: \TaskPath\TaskName"
        COM               -> "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
        BITS              -> "Job: DisplayName"
        RemoteAccess      -> "ToolName"
        DefenderExclusion -> "C:\Path\To\Exclusion"
        Manual            -> any descriptive string

.PARAMETER SubjectPath
    Full path to the binary or file implicated by this finding.

.PARAMETER Verdict
    "True Positive" or "Likely True Positive". Default: "True Positive".

.PARAMETER Details
    Free-text description of why this is a true positive (evidence summary).

.PARAMETER SHA256
    SHA-256 hash of the subject file (if known).

.PARAMETER MITRE
    ATT&CK technique string, e.g. "T1055 (Process Injection)".

.PARAMETER Notes
    Additional investigator notes (links to VAD output, enrichment, etc.).

.PARAMETER AddC2Endpoint
    Add a C2 endpoint to IOCs.json (feeds the firewall-block step).
    Format: "hostname_or_ip:port"  e.g. "192.168.1.200:4444" or "evil.example.com:443"

.PARAMETER AddMemoryArtifact
    Add a memory-derived artifact to IOCs.json memory_eradication section.
    Use multiple times for different artifact types; specify -ArtifactKind.

.PARAMETER ArtifactKind
    Kind of memory artifact being added:
        File      -> files_to_remove[]
        RegKey    -> registry_keys_to_remove[]
        Mutex     -> mutexes[]
        Pid       -> implicated_pids[]

.PARAMETER Confirm
    Actually write to disk. Without this flag, output is shown but nothing is saved.

.EXAMPLE
    # Preview a process finding (dry-run)
    .\Add-ManualFinding.ps1 -HostFolder .\reports\MAIN-SYS `
        -Type Process -Target "svchost (PID: 4392)" `
        -SubjectPath "C:\Windows\System32\svchost.exe" `
        -Details "AMSI in-memory hash mismatch; amsi.dll CoW-patched in this PID" `
        -MITRE "T1562.001 (Disable or Modify Tools)" `
        -Notes "VAD showed -wx on amsi.dll page; on-disk hash differs"

    # Write the finding and run eradication dry-run
    .\Add-ManualFinding.ps1 -HostFolder .\reports\MAIN-SYS `
        -Type Process -Target "svchost (PID: 4392)" `
        -SubjectPath "C:\Windows\System32\svchost.exe" `
        -Details "AMSI in-memory hash mismatch confirmed" `
        -MITRE "T1562.001 (Disable or Modify Tools)" `
        -Confirm
    .\Invoke-Eradication.ps1 -HostFolder .\reports\MAIN-SYS `
        -AdjudicationPath .\reports\MAIN-SYS\ManualFindings_MAIN-SYS.json

    # Add a C2 endpoint discovered during investigation
    .\Add-ManualFinding.ps1 -HostFolder .\reports\MAIN-SYS `
        -AddC2Endpoint "198.51.100.44:4444" -Confirm

    # Add a dropped file discovered from memory enrichment
    .\Add-ManualFinding.ps1 -HostFolder .\reports\MAIN-SYS `
        -AddMemoryArtifact "C:\Users\Public\svc.exe" -ArtifactKind File -Confirm

    # Add a registry persistence key
    .\Add-ManualFinding.ps1 -HostFolder .\reports\MAIN-SYS `
        -AddMemoryArtifact "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater" `
        -ArtifactKind RegKey -Confirm
#>

#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Finding')]
param(
    [string]$HostFolder = (Get-Location).Path,

    # -- Finding parameters (ParameterSet: Finding) --
    [Parameter(ParameterSetName='Finding', Mandatory)]
    [ValidateSet('Process','ScheduledTask','COM','BITS','RemoteAccess','DefenderExclusion','Manual')]
    [string]$Type,

    [Parameter(ParameterSetName='Finding', Mandatory)]
    [string]$Target,

    [Parameter(ParameterSetName='Finding')]
    [string]$SubjectPath = '',

    [Parameter(ParameterSetName='Finding')]
    [ValidateSet('True Positive','Likely True Positive')]
    [string]$Verdict = 'True Positive',

    [Parameter(ParameterSetName='Finding')]
    [ValidateSet('High','Medium','Low')]
    [string]$ConfidenceLevel = 'High',

    [Parameter(ParameterSetName='Finding')]
    [string]$Details = '',

    [Parameter(ParameterSetName='Finding')]
    [string]$SHA256 = '',

    [Parameter(ParameterSetName='Finding')]
    [string]$MITRE = '',

    [Parameter(ParameterSetName='Finding')]
    [string]$Notes = '',

    # -- IOC supplement parameters --
    [Parameter(ParameterSetName='C2', Mandatory)]
    [string]$AddC2Endpoint,

    [Parameter(ParameterSetName='MemArtifact', Mandatory)]
    [string]$AddMemoryArtifact,

    [Parameter(ParameterSetName='MemArtifact', Mandatory)]
    [ValidateSet('File','RegKey','Mutex','Pid')]
    [string]$ArtifactKind,

    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$hostName = Split-Path -Leaf ($HostFolder.TrimEnd('\','/'))

# Map Type to the string patterns Invoke-Eradication.ps1 switch expects
$typeMap = @{
    'Process'           = 'Suspicious Process'
    'ScheduledTask'     = 'Suspicious Scheduled Task'
    'COM'               = 'COM Hijack'
    'BITS'              = 'BITS'
    'RemoteAccess'      = 'Remote Access'
    'DefenderExclusion' = 'Defender Exclusion'
    'Manual'            = 'Manual'
}

function Get-TargetFormat {
    param([string]$t, [string]$tgt)
    switch ($t) {
        'Process'           { "Expects format: 'ProcessName (PID: NNN)' -- you provided: '$tgt'" }
        'ScheduledTask'     { "Expects format: 'Task: \\TaskPath\\TaskName' -- you provided: '$tgt'" }
        'COM'               { "Expects format: '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' -- you provided: '$tgt'" }
        'BITS'              { "Expects format: 'Job: DisplayName' -- you provided: '$tgt'" }
        'RemoteAccess'      { "Expects format: 'ToolName' (matched by process/service name) -- you provided: '$tgt'" }
        'DefenderExclusion' { "Expects format: 'C:\\Path\\To\\Exclusion' -- you provided: '$tgt'" }
        'Manual'            { "No automated action -- manual review only: '$tgt'" }
    }
}

# Validate required parameters for automated handlers
function Test-TargetFormat {
    param([string]$t, [string]$tgt)
    switch ($t) {
        'Process'     { if ($tgt -notmatch 'PID:\s*\d+') { return "Process Target must contain 'PID: NNN' e.g. 'svchost (PID: 4392)'" } }
        'ScheduledTask' { if ($tgt -notmatch '^Task:') { return "ScheduledTask Target must start with 'Task: \\Path\\Name'" } }
        'COM'         { if ($tgt -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { return "COM Target must be a bare CLSID e.g. '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}'" } }
        'BITS'        { if ($tgt -notmatch '^Job:') { return "BITS Target must start with 'Job: DisplayName'" } }
    }
    return $null
}

# ---- ParameterSet: C2 -------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'C2') {
    $iocPath = Join-Path $HostFolder 'IOCs.json'
    if (-not (Test-Path -LiteralPath $iocPath)) {
        throw "IOCs.json not found in '$HostFolder'. Run collection first or create it manually."
    }
    $ioc = Get-Content -LiteralPath $iocPath -Raw | ConvertFrom-Json

    # Parse host:port
    if ($AddC2Endpoint -notmatch '^(.+):(\d+)$') {
        throw "C2 endpoint format must be 'host:port' e.g. '198.51.100.44:4444'"
    }
    $c2Host = $Matches[1]
    $c2Port = [int]$Matches[2]

    $entry = [ordered]@{ host = $c2Host; port = $c2Port; sanctioned = $false }

    Write-Host ""
    Write-Host "C2 endpoint to add to IOCs.json:" -ForegroundColor Cyan
    Write-Host "  host : $c2Host" -ForegroundColor Yellow
    Write-Host "  port : $c2Port" -ForegroundColor Yellow
    Write-Host "  Effect: Invoke-Eradication.ps1 will block outbound TCP $c2Host`:$c2Port and" -ForegroundColor Gray
    Write-Host "          sinkhole $c2Host -> 0.0.0.0 in hosts file (if FQDN)" -ForegroundColor Gray

    if (-not $Confirm) {
        Write-Host ""
        Write-Host "[DRY-RUN] Nothing written. Add -Confirm to save." -ForegroundColor Yellow
        return
    }

    # Append to c2_endpoints
    $existing = if ($ioc.c2_endpoints) { @($ioc.c2_endpoints) } else { @() }
    $already = $existing | Where-Object { $_.host -eq $c2Host -and $_.port -eq $c2Port }
    if ($already) {
        Write-Host "[i] C2 endpoint $c2Host`:$c2Port already in IOCs.json -- no change." -ForegroundColor Gray
        return
    }
    $updated = $existing + [PSCustomObject]$entry
    $ioc | Add-Member -NotePropertyName 'c2_endpoints' -NotePropertyValue $updated -Force
    $ioc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $iocPath -Encoding UTF8
    Write-Host "[+] Added C2 endpoint $c2Host`:$c2Port to $iocPath" -ForegroundColor Green
    return
}

# ---- ParameterSet: MemArtifact ----------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'MemArtifact') {
    $iocPath = Join-Path $HostFolder 'IOCs.json'
    if (-not (Test-Path -LiteralPath $iocPath)) {
        throw "IOCs.json not found in '$HostFolder'. Run collection first or create it manually."
    }
    $ioc = Get-Content -LiteralPath $iocPath -Raw | ConvertFrom-Json

    $kindMap = @{
        'File'   = 'files_to_remove'
        'RegKey' = 'registry_keys_to_remove'
        'Mutex'  = 'mutexes'
        'Pid'    = 'implicated_pids'
    }
    $field = $kindMap[$ArtifactKind]

    Write-Host ""
    Write-Host "Memory artifact to add to IOCs.json memory_eradication:" -ForegroundColor Cyan
    Write-Host "  Kind  : $ArtifactKind ($field)" -ForegroundColor Yellow
    Write-Host "  Value : $AddMemoryArtifact" -ForegroundColor Yellow
    Write-Host "  Effect: Surfaces in Invoke-Eradication.ps1 memory-derived review section" -ForegroundColor Gray

    if (-not $Confirm) {
        Write-Host ""
        Write-Host "[DRY-RUN] Nothing written. Add -Confirm to save." -ForegroundColor Yellow
        return
    }

    # Build or update memory_eradication block
    $me = $null
    try { $me = $ioc.memory_eradication } catch {}
    if (-not $me) {
        $me = [PSCustomObject]@{
            files_to_remove          = @()
            registry_keys_to_remove  = @()
            mutexes                  = @()
            implicated_pids          = @()
        }
    }
    $current = @($me.$field)
    if ($current -contains $AddMemoryArtifact) {
        Write-Host "[i] '$AddMemoryArtifact' already in memory_eradication.$field -- no change." -ForegroundColor Gray
        return
    }
    $me | Add-Member -NotePropertyName $field -NotePropertyValue ($current + $AddMemoryArtifact) -Force
    $ioc | Add-Member -NotePropertyName 'memory_eradication' -NotePropertyValue $me -Force
    $ioc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $iocPath -Encoding UTF8
    Write-Host "[+] Added $ArtifactKind artifact '$AddMemoryArtifact' to $iocPath" -ForegroundColor Green
    return
}

# ---- ParameterSet: Finding --------------------------------------------------
$eradType = $typeMap[$Type]

# Validate target format for automated handlers
$fmtErr = Test-TargetFormat -t $Type -tgt $Target
if ($fmtErr) {
    Write-Warning $fmtErr
    Write-Host "  Tip: $($( Get-TargetFormat -t $Type -tgt $Target ))" -ForegroundColor Gray
    if ($Type -ne 'Manual') {
        Write-Host "  Proceeding anyway - eradication handler may not match without correct format." -ForegroundColor Yellow
    }
}

$finding = [ordered]@{
    Verdict      = $Verdict
    Confidence   = $ConfidenceLevel
    Type         = $eradType
    Target       = $Target
    Details      = $Details
    MITRE        = $MITRE
    SubjectPath  = $SubjectPath
    FileExists   = if ($SubjectPath -and (Test-Path -LiteralPath $SubjectPath -ErrorAction SilentlyContinue)) { $true } else { $false }
    SigStatus    = ''
    Signer       = ''
    Company      = ''
    PathTrust    = 'Unknown'
    SHA256       = $SHA256
    CommandLine  = ''
    Owner        = ''
    ParentPid    = ''
    ParentName   = ''
    StartTime    = ''
    Network      = ''
    PublicEgress = $false
    EvidenceDir  = $null
    Pivots       = ''
    Notes        = $Notes
}

# Try to fill in signature info for the subject file
if ($SubjectPath -and (Test-Path -LiteralPath $SubjectPath -ErrorAction SilentlyContinue)) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $SubjectPath -ErrorAction SilentlyContinue
        if ($sig) {
            $finding['SigStatus'] = $sig.Status.ToString()
            if ($sig.SignerCertificate) { $finding['Signer'] = $sig.SignerCertificate.Subject }
        }
        if (-not $SHA256) {
            $finding['SHA256'] = (Get-FileHash -LiteralPath $SubjectPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
    } catch {}
}

Write-Host ""
Write-Host "Finding to append to ManualFindings_$hostName.json:" -ForegroundColor Cyan
Write-Host "  Verdict : $Verdict" -ForegroundColor Yellow
Write-Host "  Type    : $eradType" -ForegroundColor Yellow
Write-Host "  Target  : $Target" -ForegroundColor Yellow
Write-Host "  Subject : $SubjectPath" -ForegroundColor Yellow
Write-Host "  Details : $Details" -ForegroundColor Yellow
Write-Host ""

# Show planned action
Write-Host "Planned eradication action:" -ForegroundColor Cyan
switch ($Type) {
    'Process'           { Write-Host "  -> kill PID$(if($Target -match 'PID:\s*(\d+)'){' '+$Matches[1]}else{' (parse from Target)'}) + quarantine $SubjectPath" -ForegroundColor Yellow }
    'ScheduledTask'     { Write-Host "  -> disable + unregister task '$($Target -replace '^Task:\s*','')'" -ForegroundColor Yellow }
    'COM'               { Write-Host "  -> remove CLSID HKCU/HKLM $Target" -ForegroundColor Yellow }
    'BITS'              { Write-Host "  -> remove BITS job '$($Target -replace '^Job:\s*','')'" -ForegroundColor Yellow }
    'RemoteAccess'      { Write-Host "  -> kill process + disable service matching '$Target'" -ForegroundColor Yellow }
    'DefenderExclusion' { Write-Host "  -> Remove-MpPreference -ExclusionPath '$Target'" -ForegroundColor Yellow }
    'Manual'            { Write-Host "  -> Manual review only - no automated action. Appears in eradication report." -ForegroundColor Gray }
}

if (-not $Confirm) {
    Write-Host ""
    Write-Host "[DRY-RUN] Nothing written. Add -Confirm to save." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After saving, run eradication with:" -ForegroundColor Gray
    $outPath = Join-Path $HostFolder "ManualFindings_$hostName.json"
    Write-Host "  .\Invoke-Eradication.ps1 -HostFolder '$HostFolder' -AdjudicationPath '$outPath'" -ForegroundColor Gray
    return
}

# Load or create the manual findings file
$outFile = Join-Path $HostFolder "ManualFindings_$hostName.json"
$existing = @()
if (Test-Path -LiteralPath $outFile) {
    try {
        $loaded = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
        $existing = if ($loaded -is [System.Array]) { @($loaded) } else { @($loaded) }
    } catch {
        Write-Warning "Could not parse existing $outFile -- starting fresh."
    }
}

$existing += [PSCustomObject]$finding
$existing | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outFile -Encoding UTF8

Write-Host "[+] Finding appended to $outFile ($($existing.Count) total)" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  Dry-run eradication:" -ForegroundColor Gray
Write-Host "    .\Invoke-Eradication.ps1 -HostFolder '$HostFolder' -AdjudicationPath '$outFile'" -ForegroundColor Gray
Write-Host "  Apply eradication:" -ForegroundColor Gray
Write-Host "    .\Invoke-Eradication.ps1 -HostFolder '$HostFolder' -AdjudicationPath '$outFile' -Apply" -ForegroundColor Gray
