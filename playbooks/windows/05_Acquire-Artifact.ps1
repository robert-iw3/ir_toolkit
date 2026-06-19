# ==============================================================================
# IR Playbook 05 - Windows Artifact Acquisition
# Delivered to the endpoint over WinRM (ssh_playbook_v1). Given a confirmed-TP file
# path, it ACQUIRES the file for detonation: hashes it (chain of custody), zips it
# for safe transport, writes a manifest, and uploads to the quarantine bucket.
# It NEVER executes the sample. Mirrors det_chamber/agents/acquire_core.py.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$IncidentId   = ($env:IR_INCIDENT_ID -replace '[^\w\-]','')
if (-not $IncidentId) { $IncidentId = 'UNKNOWN' }
$TargetPath   = $env:IR_TARGET_PATH
$HostName     = if ($env:IR_HOST) { $env:IR_HOST } else { $env:COMPUTERNAME }
$QuarantineUri = $env:IR_QUARANTINE_URI
$MaxSize      = if ($env:IR_MAX_ACQUIRE_BYTES) { [int64]$env:IR_MAX_ACQUIRE_BYTES } else { 104857600 }  # 100 MB
$WorkDir      = "C:\ProgramData\IRToolkit\Acquire\$IncidentId"

function Deny([string]$Msg) { Write-Error "ACQUIRE-REFUSED: $Msg"; exit 2 }

# -- Path safety: refuse OS-critical files, traversal, wildcards ---------------
$Deny = @('\windows\system32\config\', '\windows\ntds\', 'ntds.dit',
          '\windows\system32\lsass', 'pagefile.sys', '\system32\sam')
if (-not $TargetPath)                 { Deny "no target path" }
if ($TargetPath -match '[\*\?]')      { Deny "wildcard not allowed" }
if ($TargetPath -match '\.\.')        { Deny "path traversal not allowed" }
$Real = (Resolve-Path -LiteralPath $TargetPath -ErrorAction SilentlyContinue)
if (-not $Real) { Deny "not found: $TargetPath" }
$RealLower = $Real.Path.ToLower()
foreach ($d in $Deny) { if ($RealLower.Contains($d)) { Deny "OS-critical path $d" } }
if (-not (Test-Path -LiteralPath $Real.Path -PathType Leaf)) { Deny "not a regular file" }

# -- Size cap ------------------------------------------------------------------
$Item = Get-Item -LiteralPath $Real.Path
if ($Item.Length -gt $MaxSize) { Deny "file exceeds size cap ($($Item.Length) > $MaxSize)" }

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$FileName = $Item.Name
$Sha256   = (Get-FileHash -LiteralPath $Real.Path -Algorithm SHA256).Hash.ToLower()

# -- Package (zip) for safe transport - read/copied, never run -----------------
$Artifact = Join-Path $WorkDir "$FileName.zip"
Compress-Archive -LiteralPath $Real.Path -DestinationPath $Artifact -Force

# -- Manifest (chain-of-custody record the intake service verifies) ------------
$Manifest = Join-Path $WorkDir 'manifest.json'
[ordered]@{
    incident_id = $IncidentId
    host        = $HostName
    src_path    = $Real.Path
    filename    = $FileName
    sha256      = $Sha256
    size        = $Item.Length
    os_family   = 'windows'
    acquired_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
} | ConvertTo-Json | Out-File -FilePath $Manifest -Encoding UTF8

# -- Upload to the quarantine bucket (if configured) ---------------------------
if ($QuarantineUri -and (Get-Command aws -ErrorAction SilentlyContinue)) {
    aws s3 cp $Artifact "$QuarantineUri/$IncidentId/$FileName.zip" --only-show-errors
    aws s3 cp $Manifest "$QuarantineUri/$IncidentId/manifest.json" --only-show-errors
}

Write-Output "ACQUIRE-OK: $Artifact sha256=$Sha256 size=$($Item.Length)"
