<#
.SYNOPSIS
    Parse Amcache and ShimCache execution artifacts into adjudicable findings.

.DESCRIPTION
    Reads artifacts written by Get-PersistenceSnapshot.ps1:
      amcache_parsed.csv  - programme execution history (path, SHA1, publisher, link date)
      shimcache.bin       - AppCompatCache binary blob (executed-file evidence)

    Emits findings in the canonical EDR schema for executables that:
      - Ran from user-writable or suspicious paths (AppData, Temp, Downloads, Public)
      - Match known LOLBin names but from non-system directories
      - Have no publisher (unsigned) and ran from a non-Microsoft path
      - Ran from network paths (\\server\share)

    Output: findings_amcache_<stamp>.json in -OutputDir.

.PARAMETER InputDir   Folder containing amcache_parsed.csv / shimcache.bin.
                       Defaults to the Persistence sub-folder of OutputDir.
.PARAMETER OutputDir  Where to write findings JSON. Defaults to InputDir.

.EXAMPLE
    .\Invoke-AmcacheParser.ps1 -InputDir .\reports\HOST\Persistence -OutputDir .\reports\HOST
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InputDir  = '',
    [string]$OutputDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not $InputDir)  { $InputDir  = $PSScriptRoot }
if (-not $OutputDir) { $OutputDir = $InputDir }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$Stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutFile  = Join-Path $OutputDir "findings_amcache_$Stamp.json"
$Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param([string]$Severity, [string]$Type, [string]$Target, [string]$Details, [string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
    })
}

# -- Detection patterns --------------------------------------------------------
# Suspicious execution paths — user-writable or unusual locations
$SuspiciousPathRE = '(?i)(\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\Downloads\\|' +
                    '\\ProgramData\\(?!Microsoft\\Windows\\|Microsoft\\Windows Defender\\|Microsoft\\VisualStudio\\|Microsoft\\Edge|Package Cache)|' +
                    '\\Desktop\\|\\Documents\\|\\Music\\|\\Videos\\)'

# Network path execution
$NetworkPathRE = '^\\\\[^\\]+'

# LOLBin names that should NOT run from user-writable locations.
# A LOLBin copy ANYWHERE outside System32/SysWOW64 is a finding — no exceptions.
$LolBinRE = '(?i)^(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|' +
             'installutil|msbuild|regasm|regsvcs|odbcconf|cmstp|msiexec|' +
             'appsync|syncappvpublishingserver)\.exe$'

function Test-SafePath { param([string]$path)
    # Only suppress LOLBin findings when the binary is in Windows' own binary directories.
    # These are the only locations where LOLBins are expected to live.
    # Everything else — including Program Files, SoftwareDistribution, ProgramData — gets flagged.
    return $path -match '(?i)^(C:\\Windows\\(System32|SysWOW64|WinSxS)\\)'
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. Amcache CSV (written by Get-PersistenceSnapshot.ps1)
# ══════════════════════════════════════════════════════════════════════════════
$amcacheCsv = Join-Path $InputDir 'amcache_parsed.csv'
if (Test-Path -LiteralPath $amcacheCsv) {
    Write-Host "[*] Amcache: $amcacheCsv" -ForegroundColor Cyan
    try {
        $entries = Import-Csv -LiteralPath $amcacheCsv -ErrorAction Stop
        $flagged = 0
        foreach ($e in $entries) {
            $path = [string]($e.Path ?? '')
            if (-not $path) { continue }
            $name = [System.IO.Path]::GetFileName($path)
            $pub  = [string]($e.Publisher ?? '')

            # Rule 1: Suspicious execution path — surface ALL executions regardless of publisher.
            # A Microsoft-signed binary in AppData is still suspicious. Adjudicator adds context.
            if ($path -match $SuspiciousPathRE) {
                # High: Temp dirs and AppData\Roaming (primary malware staging locations)
                # Medium: Desktop, Downloads, Documents (accessible but less common)
                $sev = if ($path -match '(?i)\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\Temp\\') { 'High' } else { 'Medium' }
                Add-Finding $sev 'Amcache: Execution from Suspicious Path' $path `
                    "Publisher='$pub'  SHA1=$($e.SHA1)  LinkDate=$($e.LinkDate)" `
                    'T1036 (Masquerading), T1059 (Command and Scripting Interpreter)'
                $flagged++
            }
            # Rule 2: Network path execution
            elseif ($path -match $NetworkPathRE) {
                Add-Finding 'High' 'Amcache: Execution from Network Path' $path `
                    "Publisher='$pub'  SHA1=$($e.SHA1)" `
                    'T1021 (Remote Services), T1570 (Lateral Tool Transfer)'
                $flagged++
            }
            # Rule 3: LOLBin outside System32
            elseif ($name -match $LolBinRE -and -not (Test-SafePath $path)) {
                Add-Finding 'High' 'Amcache: LOLBin Executed from Non-System Path' $path `
                    "LOLBin '$name' executed from unexpected location. Publisher='$pub'" `
                    'T1218 (System Binary Proxy Execution)'
                $flagged++
            }
        }
        Write-Host "    $($entries.Count) entries, $flagged flagged" -ForegroundColor Gray
    } catch {
        Write-Host "    Parse error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] amcache_parsed.csv not found — skipping Amcache analysis" -ForegroundColor Gray
    Write-Host "    (Collection may have failed: Amcache.hve requires backup privilege)" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. ShimCache binary (AppCompatCache registry export)
# ══════════════════════════════════════════════════════════════════════════════
$shimBin = Join-Path $InputDir 'shimcache.bin'
if (Test-Path -LiteralPath $shimBin) {
    Write-Host "[*] ShimCache: $shimBin" -ForegroundColor Cyan
    try {
        $raw     = [System.IO.File]::ReadAllBytes($shimBin)
        $flagged = 0

        # Windows 10/11 AppCompatCache (ShimCache) entry structure:
        #   +0  "10ts" tag (4 bytes)
        #   +4  FILETIME last-modified (8 bytes)
        #   +12 path length in bytes (2 bytes, UTF-16LE so chars = bytes/2)
        #   +14 path (UTF-16LE, pathlen bytes)
        #   +14+pathlen: variable extra data until next "10ts"
        # Each entry starts with "10ts" — scan for all markers then extract paths.
        $magic      = [BitConverter]::ToUInt32($raw, 0)
        $entryCount = [BitConverter]::ToUInt32($raw, 4)
        Write-Host "    magic=0x$($magic.ToString('X8'))  declared_entries=$entryCount  raw=$($raw.Length) bytes" -ForegroundColor Gray

        # Single-pass: collect all "10ts" marker offsets
        $markerOffsets = [System.Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $raw.Length - 14; $i++) {
            if ($raw[$i] -eq 0x31 -and $raw[$i+1] -eq 0x30 -and $raw[$i+2] -eq 0x74 -and $raw[$i+3] -eq 0x73) {
                $markerOffsets.Add($i)
            }
        }
        Write-Host "    '10ts' markers found: $($markerOffsets.Count)" -ForegroundColor Gray

        $parsed = 0
        foreach ($o in $markerOffsets) {
            $pathLen = [BitConverter]::ToUInt16($raw, $o + 12)
            if ($pathLen -eq 0 -or $pathLen -gt 2000) { continue }
            $pathStart = $o + 14
            if ($pathStart + $pathLen -gt $raw.Length) { continue }

            $path = [System.Text.Encoding]::Unicode.GetString($raw, $pathStart, $pathLen)
            $name = [System.IO.Path]::GetFileName($path)
            $parsed++

            if ($path -match $SuspiciousPathRE) {
                $sev = if ($path -match '(?i)\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\Temp\\') { 'High' } else { 'Medium' }
                Add-Finding $sev 'ShimCache: Execution from Suspicious Path' $path `
                    'Recorded in AppCompatCache — executed from user-writable path. Pivot: check Amcache for SHA1, Event 4688 for cmdline.' `
                    'T1036 (Masquerading), T1059 (Command and Scripting Interpreter)'
                $flagged++
            } elseif ($path -match $NetworkPathRE) {
                Add-Finding 'High' 'ShimCache: Execution from Network Path' $path `
                    'AppCompatCache records execution from network share. Pivot: check lateral movement indicators, 4648/4624 logon events.' `
                    'T1021 (Remote Services), T1570 (Lateral Tool Transfer)'
                $flagged++
            } elseif ($name -match $LolBinRE -and -not (Test-SafePath $path)) {
                Add-Finding 'High' 'ShimCache: LOLBin Executed from Non-System Path' $path `
                    "LOLBin '$name' recorded in ShimCache outside System32. Pivot: check Event 4688 cmdline for encoded/downloaded payload." `
                    'T1218 (System Binary Proxy Execution)'
                $flagged++
            }
        }
        Write-Host "    $parsed entries parsed, $flagged flagged" -ForegroundColor Gray
    } catch {
        Write-Host "    ShimCache parse error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] shimcache.bin not found — skipping ShimCache analysis" -ForegroundColor Gray
    Write-Host "    (Run Get-PersistenceSnapshot.ps1 to collect ShimCache)" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════════════════════
# Output
# ══════════════════════════════════════════════════════════════════════════════
$count = $Findings.Count
if ($count -gt 0) {
    $Findings | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Host "`n[+] $count finding(s) -> $(Split-Path $OutFile -Leaf)" -ForegroundColor Green
    $Findings | Group-Object Severity | Sort-Object @{E={@('Critical','High','Medium','Low').IndexOf($_.Name)}} |
        ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor $(
            switch ($_.Name) { 'Critical'{'Red'} 'High'{'DarkRed'} 'Medium'{'Yellow'} default{'Cyan'} }
        ) }
} else {
    Write-Host "`n[+] No suspicious Amcache/ShimCache entries detected." -ForegroundColor Green
    '[]' | Out-File -FilePath $OutFile -Encoding UTF8
}
