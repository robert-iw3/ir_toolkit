<#
.SYNOPSIS
    Triage for interactive-remote-control compromise: RMM/remote-access tooling,
    ClickFix / fake-update execution lures, browser artifacts, and active sessions.

.DESCRIPTION
    Targets the gap that process/persistence hunts miss: a signed remote-access tool
    + a social-engineering lure (e.g. a fake full-screen "Windows Update" page with a
    cursor moving on its own). Emits findings in the SAME schema as EDR_Toolkit
    (Timestamp/Severity/Type/Target/Details/MITRE) so they flow into the adjudicator
    and eradicator, and copies raw artifacts (RMM connection logs, browser history,
    RunMRU) into <OutputDir>\RemoteAccess\ for manual review.

.PARAMETER OutputDir   Where findings + artifacts are written. Default: script folder.
.EXAMPLE
    .\Get-RemoteAccessTriage.ps1 -OutputDir .\KIMBAP
#>

#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDir = $PSScriptRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
if (-not $OutputDir) { $OutputDir = (Get-Location).Path }
$ArtRoot = Join-Path $OutputDir 'RemoteAccess'
New-Item -ItemType Directory -Path $ArtRoot -Force | Out-Null

$Findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Severity,[string]$Type,[string]$Target,[string]$Details,[string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity; Type = $Type; Target = $Target; Details = $Details; MITRE = $Mitre
    })
}
function Copy-Artifact { param([string]$Src,[string]$DestName)
    try { if (Test-Path -LiteralPath $Src) { Copy-Item -LiteralPath $Src -Destination (Join-Path $ArtRoot $DestName) -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}

# ============================================================================
# 1. Remote-access / RMM tooling (MITRE T1219). Catalog of name + log hints.
# ============================================================================
$RMM = @(
    @{ N='AnyDesk';            P='anydesk';        Logs=@("$env:ProgramData\AnyDesk\connection_trace.txt","$env:ProgramData\AnyDesk\ad.trace","$env:APPDATA\AnyDesk\connection_trace.txt") }
    @{ N='TeamViewer';         P='teamviewer';     Logs=@("$env:ProgramData\TeamViewer\Connections_incoming.txt","${env:ProgramFiles(x86)}\TeamViewer\Connections_incoming.txt","$env:ProgramFiles\TeamViewer\Connections_incoming.txt") }
    @{ N='ScreenConnect';      P='screenconnect';  Logs=@("$env:ProgramData\ScreenConnect Client") }
    @{ N='ConnectWiseControl'; P='connectwise';    Logs=@() }
    @{ N='Splashtop';          P='splashtop|srservice|srmanager'; Logs=@("$env:ProgramData\Splashtop\Temp\log") }
    @{ N='RustDesk';           P='rustdesk';       Logs=@("$env:APPDATA\RustDesk\log","$env:ProgramData\RustDesk\log") }
    @{ N='NetSupport';         P='client32|pcicfgui'; Logs=@("$env:ProgramFiles\NetSupport","${env:ProgramFiles(x86)}\NetSupport") }
    @{ N='Atera';              P='ateraagent';     Logs=@() }
    @{ N='Action1';            P='action1';        Logs=@() }
    @{ N='LogMeIn';            P='logmein|lmiguardiansvc'; Logs=@() }
    @{ N='GoToAssist';         P='gotoassist|g2'; Logs=@() }
    @{ N='ZohoAssist';         P='zaservice|zohomeeting|za_connect'; Logs=@() }
    @{ N='VNC';                P='winvnc|tvnserver|vncserver|uvnc'; Logs=@() }
    @{ N='ChromeRemoteDesktop';P='remoting_host'; Logs=@() }
    @{ N='DWAgent';            P='dwagent';        Logs=@() }
    @{ N='Supremo';            P='supremo';        Logs=@() }
    @{ N='MeshAgent';          P='meshagent';      Logs=@() }
    @{ N='QuickAssist';        P='quickassist';    Logs=@() }
    @{ N='RemoteAssistance';   P='msra';           Logs=@() }
)
$procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
$svcs  = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
foreach ($tool in $RMM) {
    $hitProc = $procs | Where-Object { $_.Name -match "(?i)$($tool.P)" }
    $hitSvc  = $svcs  | Where-Object { ($_.Name -match "(?i)$($tool.P)") -or ($_.PathName -match "(?i)$($tool.P)") }
    if ($hitProc -or $hitSvc) {
        if ($hitProc) {
            $first = @($hitProc) | Select-Object -First 1
            $where = "running (PID $($first.ProcessId))"
            $path  = $first.ExecutablePath
        } else {
            $firstSvc = @($hitSvc) | Select-Object -First 1
            $where = "service: $($firstSvc.Name)"
            $path  = $firstSvc.PathName
        }
        Add-Finding 'High' 'Remote Access Tool' "$($tool.N)" "Detected $where; path: $path" 'T1219 (Remote Access Software)'
        foreach ($lg in $tool.Logs) { if ($lg -and (Test-Path -LiteralPath $lg)) { Copy-Artifact $lg ("rmm_{0}_{1}" -f $tool.N, (Split-Path -Leaf $lg)) } }
    } else {
        # not running, but capture connection logs if the tool was ever installed
        foreach ($lg in $tool.Logs) {
            if ($lg -and (Test-Path -LiteralPath $lg)) {
                Add-Finding 'Medium' 'Remote Access Tool' "$($tool.N) (residual)" "Not running, but connection log present: $lg" 'T1219 (Remote Access Software)'
                Copy-Artifact $lg ("rmm_{0}_{1}" -f $tool.N, (Split-Path -Leaf $lg))
            }
        }
    }
}

# ============================================================================
# 2. ClickFix / fake-update lure: RunMRU (Win+R history) across loaded users.
# ============================================================================
$badCmd = '(?i)(mshta|powershell|pwsh|cmd(\.exe)?\s|/c\s|curl|certutil|bitsadmin|msiexec\s+/i\s+http|iwr|invoke-webrequest|iex|invoke-expression|frombase64|-enc|hidden|\\\\|http)'
$runMru = [System.Collections.Generic.List[string]]::new()
try {
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '_Classes$' } | ForEach-Object {
        $k = "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (Test-Path -LiteralPath $k) {
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -match '^[a-z]$' -and $prop.Value) {
                    $runMru.Add("$($_.Name) | $($prop.Name) = $($prop.Value)")
                    if ($prop.Value -match $badCmd) {
                        Add-Finding 'High' 'ClickFix / RunMRU' "Win+R: $($prop.Name)" "Suspicious Run command: $($prop.Value)" 'T1204.001 (User Execution), T1059'
                    }
                }
            }
        }
    }
} catch {}
if ($runMru.Count) { $runMru | Set-Content -LiteralPath (Join-Path $ArtRoot 'runmru.txt') -Encoding UTF8 }

# Live LOLBin processes with network/encoded args (active lure execution)
foreach ($p in $procs) {
    $cl = "$($p.CommandLine)"
    if ($p.Name -match '(?i)^(mshta|powershell|pwsh|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\.exe$' -and $cl -match $badCmd) {
        Add-Finding 'High' 'LOLBin Execution' "$($p.Name) PID $($p.ProcessId)" "Command line: $cl" 'T1059, T1218'
    }
}

# ============================================================================
# 3. Browser artifacts (the fake "update" page lives here). Copy for review.
# ============================================================================
$browsers = @(
    @{ N='Edge';    H="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History";  E="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" }
    @{ N='Chrome';  H="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History";   E="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" }
)
foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    foreach ($b in $browsers) {
        $h = $b.H -replace [regex]::Escape($env:LOCALAPPDATA), "$($u.FullName)\AppData\Local"
        $e = $b.E -replace [regex]::Escape($env:LOCALAPPDATA), "$($u.FullName)\AppData\Local"
        if (Test-Path -LiteralPath $h) {
            Copy-Artifact $h ("browser_{0}_{1}_History.sqlite" -f $u.Name, $b.N)
            Add-Finding 'Low' 'Browser Artifact' "$($u.Name)/$($b.N)" "History DB collected for review: $h" 'T1204 (User Execution)'
        }
        if (Test-Path -LiteralPath $e) {
            try { (Get-ChildItem -LiteralPath $e -Directory -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime) |
                Out-File -LiteralPath (Join-Path $ArtRoot ("browser_{0}_{1}_extensions.txt" -f $u.Name, $b.N)) -Encoding UTF8 } catch {}
        }
    }
    # Firefox places.sqlite
    $ff = Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ff) {
        Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $places = Join-Path $_.FullName 'places.sqlite'
            if (Test-Path -LiteralPath $places) { Copy-Artifact $places ("browser_{0}_Firefox_places.sqlite" -f $u.Name) }
        }
    }
}

# ============================================================================
# 4. Active / interactive sessions (who was at the console when it moved).
# ============================================================================
try {
    if (Get-Command qwinsta -ErrorAction SilentlyContinue) {
        qwinsta 2>$null | Out-File -LiteralPath (Join-Path $ArtRoot 'sessions_qwinsta.txt') -Encoding UTF8
    }
} catch {}
try {
    Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -in 2,10,11 } |   # interactive / remote-interactive / cached-interactive
        Select-Object LogonId, LogonType, StartTime |
        Export-Csv -LiteralPath (Join-Path $ArtRoot 'interactive_logon_sessions.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# ============================================================================
# 5. Defender tamper (attacker-added exclusions / disabled protection).
# ============================================================================
try {
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mp) {
        foreach ($ex in @($mp.ExclusionPath)) { if ($ex) { Add-Finding 'Medium' 'Defender Exclusion' "$ex" "Defender path exclusion present (attacker staging paths hide here)" 'T1562.001 (Impair Defenses)' } }
    }
    $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($st -and (-not $st.RealTimeProtectionEnabled)) {
        Add-Finding 'High' 'Defender Disabled' 'RealTimeProtection' "Defender real-time protection is OFF" 'T1562.001 (Impair Defenses)'
    }
} catch {}

# ============================================================================
# Output findings (EDR-compatible schema) + summary
# ============================================================================
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $OutputDir "RemoteAccess_Findings_$stamp.json"
if ($Findings.Count -gt 0) { $Findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $out -Encoding UTF8 }
else { '[]' | Set-Content -LiteralPath $out -Encoding UTF8 }

Write-Host "[+] Remote-access triage: $($Findings.Count) finding(s) -> $(Split-Path -Leaf $out)" -ForegroundColor Green
Write-Host "[+] Artifacts -> $ArtRoot" -ForegroundColor Green
$Findings | Group-Object Type | Select-Object @{N='Type';E={$_.Name}}, Count | Format-Table -AutoSize
