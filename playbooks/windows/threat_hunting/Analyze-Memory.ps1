<#
.SYNOPSIS
    Offline post-collection memory analysis. Runs Volatility 3 plugins against a
    captured .raw image and emits ONLY concerning findings in the same JSON schema
    used by the adjudicator (Timestamp/Severity/Type/Target/Details/MITRE).

.DESCRIPTION
    Run this on your ANALYST machine after copying the memory image from the target.
    The target must be running Windows. Accepts .raw, .mem, and .aff4 image files.

    Prerequisites (analyst machine):
      tools\vol.exe        - Volatility 3 standalone build (PyInstaller).
                             Stage with: .\Build-OfflineToolkit.ps1 -IncludeVolatility
      tools\go-winpmem.exe - Required only if image is .aff4 AND vol.exe lacks AFF4 support
                             (the standard standalone build does not include pyaff4).
                             go-winpmem extract will auto-convert AFF4 -> raw before analysis.
                             Stage with: .\Build-OfflineToolkit.ps1 -IncludeMemory
      Symbols              - vol.exe auto-fetches from Microsoft on first run (internet needed).
                             Pre-stage offline: .\Build-OfflineToolkit.ps1 -IncludeVolatility -StageSymbols

    Plugins run:
      windows.pslist + windows.psscan  - cross-check for hidden processes
      windows.malfind                  - injected/unbacked executable memory
      windows.cmdline                  - suspicious command lines in process memory
      windows.netscan                  - network connections (C2 / lateral movement)
      windows.hashdump                 - NTLM hashes (credential access)
      windows.svcscan                  - rogue services not in the SCM
      windows.ldrmodules               - unlinked DLLs (process injection)
      windows.vadyarascan              - YARA scan of process memory (staged rules)

    Output: Memory_Findings_<stamp>.json in -OutputDir (defaults to image parent folder).
    Integrate with the main pipeline: add Memory_Findings_*.json to Combined_Findings and
    re-run Get-FindingContext.ps1 -Live for adjudication.

.PARAMETER ImagePath   Path to the .raw memory image.
.PARAMETER OutputDir   Where to write Memory_Findings_<stamp>.json. Default: image folder.
.PARAMETER VolExe      Path to vol.exe. Default: <toolkit>\tools\vol.exe (auto-located).
.PARAMETER SymbolDir   Extra Volatility 3 symbol dir. Default: <toolkit>\tools\vol_symbols.
.PARAMETER SkipPlugins Comma-separated plugin names to skip (e.g. 'hashdump,ldrmodules').

.EXAMPLE
    .\Analyze-Memory.ps1 -ImagePath "E:\Evidence\<HOSTNAME>\memory_<HOSTNAME>.raw"

.EXAMPLE
    .\Analyze-Memory.ps1 -ImagePath ".\reports\<HOSTNAME>\memory_<HOSTNAME>.raw" `
                         -OutputDir ".\reports\<HOSTNAME>"
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ImagePath,

    [string]$OutputDir   = '',
    [string]$VolExe      = '',
    [string]$SymbolDir   = '',
    [string]$SkipPlugins = '',

    # Merge memory findings into Combined_Findings and run Get-FindingContext.ps1 -Live.
    [switch]$Adjudicate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Helpers -------------------------------------------------------------------
# Safe property accessor - returns $Default when property is missing or null.
function Get-Prop {
    param($Obj, [string[]]$Names, $Default = '')
    foreach ($n in $Names) {
        try {
            $v = $Obj.$n
            # Member access on a collection (or a JSON array value) yields Object[];
            # take the first element so downstream [long]/[string] casts can't blow up.
            if ($v -is [System.Array]) { $v = @($v)[0] }
            if ($null -ne $v -and [string]$v -ne '') { return $v }
        } catch {}
    }
    return $Default
}

function Import-MemoryFindings {
    # Read a Memory_Findings JSON file into a List of findings. Returns a List (never
    # $null) so .Count is correct on PS 5.1 and 7+; an array return mis-counts the
    # empty case across versions. Callers use .Count directly (no @() wrap).
    param([Parameter(Mandatory)][string]$Path)
    $list = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $Path)) { return ,$list }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return ,$list }
    $data = $null
    try { $data = $raw | ConvertFrom-Json -ErrorAction Stop } catch { return ,$list }
    if ($null -ne $data) {
        foreach ($item in @($data)) { if ($null -ne $item) { $list.Add($item) } }
    }
    return ,$list
}

function ConvertTo-FindingsJson {
    # Serialize findings to a JSON string that is always an array on 5.1 and 7+.
    # (5.1 collapses a single finding to a bare object / a List to {value,Count}.)
    param($Findings)
    $arr = @($Findings)
    if ($arr.Count -eq 0) { return '[]' }
    $json = ConvertTo-Json -InputObject $arr -Depth 6
    if ($json.TrimStart()[0] -ne '[') { $json = "[`r`n$json`r`n]" }
    return $json
}

# -- YARA helpers (shared by the Volatility branch; parity with memory_yara.py) --
function Test-YaraNoiseRule {
    # True for high-FP noise rule-name prefixes.
    param([string]$Name)
    return [bool]($Name -match '(?i)^(generic_|test_|debug_|example_|placeholder|with_|pua_|riskware_|grayware_)')
}

function Get-YaraSeverity {
    # Critical for high-signal rule names, otherwise High.
    param([string]$Name)
    $low = ([string]$Name).ToLower()
    foreach ($k in 'cobalt','beacon','meterpreter','mimikatz','shellcode','inject','empire') {
        if ($low.Contains($k)) { return 'Critical' }
    }
    return 'High'
}

function New-CombinedYaraFile {
    # Build one vol3 --yara-file include file from a rules dir; $null if no rules.
    param([string]$RulesDir)
    if (-not (Test-Path -LiteralPath $RulesDir)) { return $null }
    $files = @(Get-ChildItem -LiteralPath $RulesDir -Recurse -Include '*.yar','*.yara' -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) { return $null }
    $combined = Join-Path ([System.IO.Path]::GetTempPath()) ("yara_combined_{0}.yar" -f [guid]::NewGuid().ToString('N'))
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in $files) { [void]$sb.AppendLine('include "' + $f.FullName + '"') }
    Set-Content -LiteralPath $combined -Value $sb.ToString() -Encoding UTF8
    return $combined
}

function Merge-FindingSets {
    # Concatenate two finding sets into one List (version-safe; drops nulls).
    param($Existing, $New)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Existing)) { if ($null -ne $f) { $list.Add($f) } }
    foreach ($f in @($New))      { if ($null -ne $f) { $list.Add($f) } }
    return ,$list
}

# -- Resolve paths -------------------------------------------------------------
$ImagePath = (Resolve-Path -LiteralPath $ImagePath -ErrorAction Stop).Path

if (-not $OutputDir) {
    # Default: reports\<hostname>\ under the toolkit root, derived from the image filename.
    # Image convention: memory_<HOSTNAME>.aff4 / memory_<HOSTNAME>.raw / memory_<HOSTNAME>.mem
    $imgBase   = [System.IO.Path]::GetFileNameWithoutExtension($ImagePath)  # e.g. memory_<HOSTNAME>
    $hostname  = $imgBase -replace '^memory_',''                            # e.g. <HOSTNAME>
    # Walk up from PSScriptRoot to find the toolkit root (contains 'reports\')
    $toolkitRoot = $PSScriptRoot
    for ($i = 0; $i -lt 6; $i++) {
        if (Test-Path (Join-Path $toolkitRoot 'reports')) { break }
        $parent = Split-Path $toolkitRoot -Parent
        if (-not $parent -or $parent -eq $toolkitRoot) { $toolkitRoot = $PSScriptRoot; break }
        $toolkitRoot = $parent
    }
    $OutputDir = Join-Path $toolkitRoot "reports\$hostname"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if (-not $VolExe) {
    $search = $PSScriptRoot
    for ($i = 0; $i -lt 6; $i++) {
        $c = Join-Path $search 'tools\vol.exe'
        if (Test-Path -LiteralPath $c) { $VolExe = $c; break }
        $parent = Split-Path $search -Parent
        if (-not $parent -or $parent -eq $search) { break }
        $search = $parent
    }
}
# -- Tool routing by image-file extension -------------------------------------
# Explicit per-format decision. MemProcFS is the DEFAULT engine (it reads AFF4
# natively); Volatility 3 is used ONLY for the raw-style formats it can parse --
# vol.exe's standalone build has no pyaff4 and cannot open AFF4 at all, so AFF4
# and any unknown/extensionless image must never be sent to Volatility.
function Get-MemoryEngine {
    param([Parameter(Mandatory)][string]$ImagePath)
    $ext = [System.IO.Path]::GetExtension($ImagePath).ToLower()
    switch ($ext) {
        '.aff4'  { 'MemProcFS' }   # go-winpmem capture format
        '.raw'   { 'Volatility' }  # raw physical-memory dump
        '.mem'   { 'Volatility' }
        '.dmp'   { 'Volatility' }
        '.lime'  { 'Volatility' }
        '.vmem'  { 'Volatility' }
        '.bin'   { 'Volatility' }
        '.dump'  { 'Volatility' }
        '.crash' { 'Volatility' }
        '.img'   { 'Volatility' }
        default  { 'MemProcFS' }   # unknown -> default to the AFF4-capable engine
    }
}

$AnalysisEngine = Get-MemoryEngine -ImagePath $ImagePath
$useMemProcFS   = $AnalysisEngine -eq 'MemProcFS'

if ($useMemProcFS) {
    # AFF4 files from go-winpmem are analyzed with MemProcFS, which supports AFF4 natively.
    # Volatility 3 standalone (vol.exe) does not include pyaff4 in its standard build.
    if (-not $VolExe) { $VolExe = 'not-needed' }   # suppress the vol.exe requirement below
    $toolsDir   = $null
    $SymbolDir  = ''

    # Locate MemProcFS in tools\memprocfs\
    $mpcSearch = $PSScriptRoot
    $mpcExe    = $null
    $sqlite3   = $null
    for ($i = 0; $i -lt 6; $i++) {
        $c = Join-Path $mpcSearch 'tools\memprocfs\MemProcFS.exe'
        if (Test-Path -LiteralPath $c) {
            $mpcExe  = $c
            $sqlite3 = Join-Path (Split-Path $c -Parent) 'sqlite3.exe'
            break
        }
        $parent = Split-Path $mpcSearch -Parent
        if (-not $parent -or $parent -eq $mpcSearch) { break }
        $mpcSearch = $parent
    }
    if (-not $mpcExe) {
        Write-Host '[!] MemProcFS not found in tools\memprocfs\. Stage it first:' -ForegroundColor Red
        Write-Host '    .\Build-OfflineToolkit.ps1 -IncludeMemProcFS' -ForegroundColor Yellow
        exit 1
    }
    if (-not (Test-Path -LiteralPath $sqlite3)) {
        Write-Host '[!] sqlite3.exe not found in tools\memprocfs\. Re-run staging:' -ForegroundColor Red
        Write-Host '    .\Build-OfflineToolkit.ps1 -IncludeMemProcFS' -ForegroundColor Yellow
        exit 1
    }
} else {
    # raw / mem / dmp files use Volatility 3
    if (-not $VolExe -or -not (Test-Path -LiteralPath $VolExe)) {
        Write-Host '[!] vol.exe not found. Stage it first:' -ForegroundColor Red
        Write-Host '    .\Build-OfflineToolkit.ps1 -IncludeVolatility' -ForegroundColor Yellow
        exit 1
    }
    if (-not $SymbolDir) {
        $toolsDir  = Split-Path $VolExe -Parent
        $SymbolDir = Join-Path $toolsDir 'vol_symbols'
    }
}

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutFile  = Join-Path $OutputDir "Memory_Findings_$RunStamp.json"
$LogFile  = Join-Path $OutputDir "_MemoryAnalysis_$RunStamp.log"

$skipSet = @($SkipPlugins -split ',' |
    ForEach-Object { $_.Trim().ToLower() } |
    Where-Object { $_ })

function Write-Log {
    param([string]$Msg, [string]$Color = 'Gray')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Msg"
    Write-Host $line -ForegroundColor $Color
    [Console]::ResetColor()
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

$script:Findings = [System.Collections.Generic.List[object]]::new()
$findingsWrittenByPython = $false   # set true once the Python path writes the findings file

function Add-Finding {
    param([string]$Severity, [string]$Type, [string]$Target, [string]$Details, [string]$Mitre)
    $script:Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
    })
}

function Invoke-VolPlugin {
    param([string]$Plugin, [string[]]$PluginArgs = @(), [int]$TimeoutSec = 0)
    Write-Log "  [vol] $Plugin ..." 'Cyan'
    $plugLog  = Join-Path $OutputDir "_vol_${Plugin}_$RunStamp.log"
    $argList  = [System.Collections.Generic.List[string]]::new()
    $argList.Add('-r'); $argList.Add('json')
    $argList.Add('-f'); $argList.Add($ImagePath)
    if ($SymbolDir -and (Test-Path -LiteralPath $SymbolDir)) {
        $argList.Add('--symbol-dirs'); $argList.Add($SymbolDir)
    }
    $argList.Add($Plugin)
    foreach ($a in $PluginArgs) { $argList.Add($a) }   # plugin-specific args follow the plugin
    try {
        $raw  = & $VolExe @argList 2>$plugLog
        if ($LASTEXITCODE -ne 0) {
            Write-Log "    exit $LASTEXITCODE -- see $plugLog" 'Yellow'
            return $null
        }
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
        $cnt  = if ($json) { @($json).Count } else { 0 }
        Write-Log "    ok ($cnt row(s))" 'Green'
        return $json
    } catch {
        Write-Log "    parse error: $($_.Exception.Message)" 'Yellow'
        return $null
    }
}

if ($useMemProcFS) {
    Write-Log '===================================================' 'Green'
    Write-Log " Memory Analysis (MemProcFS / AFF4)" 'Green'
    Write-Log " image : $(Split-Path $ImagePath -Leaf)" 'Green'
    Write-Log " tool  : $mpcExe" 'Green'
    Write-Log '===================================================' 'Green'

    # Dokany/VFS fallback runs only if the primary vmmpyc Python path does NOT
    # complete the analysis. This is a SEPARATE flag from $useMemProcFS so that a
    # successful Python run can skip Dokany without disturbing tool routing.
    $runDokany = $true

    # -- Primary path: vmmpyc Python API (no Dokany/WinFsp required) ----------
    # Uses vmmpyc.pyd bundled with MemProcFS. No system-level changes - nothing
    # to install or revert. Requires Python 3.x (python.exe in PATH).
    $pyScript  = Join-Path $PSScriptRoot 'memory_forensic.py'
    # Prefer bundled Python in tools\memprocfs\python\ (staged offline, no system Python needed).
    $bundledPy = Join-Path (Split-Path $mpcExe -Parent) 'python\python.exe'
    $pyExe     = $null
    if (Test-Path -LiteralPath $bundledPy) {
        $pyExe = $bundledPy
    } else {
        # Fall back to system Python if bundled not staged yet
        foreach ($c in @('python','python3')) {
            try { $v = & $c --version 2>&1; if ($LASTEXITCODE -eq 0 -and $v -match 'Python 3') { $pyExe = $c; break } } catch {}
        }
        if ($pyExe) { Write-Log "  Using system Python (bundle tools\memprocfs\python\ not staged - run Build-OfflineToolkit.ps1 -IncludeMemProcFS)" 'Yellow' }
    }

    if ($pyExe -and (Test-Path -LiteralPath $pyScript)) {
        Write-Log "  Using vmmpyc Python API (no driver install required) ..." 'Cyan'
        $pyLog = Join-Path $OutputDir "_MemProcFS_$RunStamp.log"
        & $pyExe $pyScript $ImagePath $OutputDir 2>&1 | Tee-Object -FilePath $pyLog -Append
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  Python analysis complete." 'Green'
            # Python already wrote the canonical Memory_Findings_*.json (a proper array).
            $pyFindings = Get-ChildItem -Path $OutputDir -Filter "Memory_Findings_*.json" |
                          Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($pyFindings) {
                Write-Log "  Findings: $($pyFindings.FullName)" 'Green'
                $script:Findings = Import-MemoryFindings -Path $pyFindings.FullName
                # Report on (and don't clobber) Python's own findings file.
                $OutFile = $pyFindings.FullName
                $findingsWrittenByPython = $true
            }
            # Primary analysis done by Python - skip the Dokany/VFS fallback.
            $runDokany = $false
        } else {
            Write-Log "  vmmpyc analysis failed (exit $LASTEXITCODE) - falling back to MemProcFS/Dokany path." 'Yellow'
        }
    } else {
        if (-not $pyExe)      { Write-Log '  Python 3 not found - falling back to MemProcFS/Dokany path.' 'Yellow' }
        if (-not (Test-Path $pyScript)) { Write-Log "  memory_forensic.py not found at $pyScript" 'Yellow' }
    }

    if ($runDokany) {
    $sqliteDb   = Join-Path $OutputDir 'vmm.sqlite3'
    $mpcLogPath = Join-Path $OutputDir "_MemProcFS_$RunStamp.log"

    # -- Dokany auto-install ---------------------------------------------------
    # MemProcFS v5.x requires Dokany for VFS mounting (forensic mode writes
    # vmm.sqlite3 via the mounted VFS). Install from tools\dokan_x64.msi if
    # not already present; uninstall unconditionally in the finally block.
    $dokanMsi         = Join-Path (Split-Path $mpcExe -Parent | Split-Path -Parent) 'dokan_x64.msi'
    $dokanInstalled   = $false
    $dokanWeInstalled = $false
    try { $dokanInstalled = [bool](Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
        Get-ItemProperty | Where-Object { $_.DisplayName -match 'Dokan' }) } catch {}
    if (-not $dokanInstalled) { $dokanInstalled = Test-Path "$env:SystemRoot\System32\dokan2.dll" }

    if (-not $dokanInstalled) {
        if (-not (Test-Path -LiteralPath $dokanMsi)) {
            Write-Log '[!] Dokany not installed and tools\dokan_x64.msi not staged.' 'Yellow'
            Write-Log '    Run: .\Build-OfflineToolkit.ps1 -IncludeMemProcFS  to download it.' 'Yellow'
            exit 1
        }
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log '[!] AFF4 analysis requires Administrator - Dokany MSI cannot install without elevation.' 'Yellow'
            Write-Log '    Re-run from an elevated PowerShell (Run as Administrator).' 'Yellow'
            Write-Log "    pwsh -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -ImagePath `"$ImagePath`" -OutputDir `"$OutputDir`"" 'Yellow'
            exit 1
        }
        Write-Log '  Installing Dokany from tools\dokan_x64.msi (will uninstall on exit) ...' 'Cyan'
        $inst = Start-Process msiexec.exe -ArgumentList "/i `"$dokanMsi`" /quiet /norestart" -PassThru -Wait
        if ($inst.ExitCode -eq 0) {
            Write-Log '  Dokany installed.' 'Green'
            $dokanWeInstalled = $true
        } else {
            Write-Log "[!] Dokany install failed (exit $($inst.ExitCode))." 'Yellow'
            exit 1
        }
    } else {
        Write-Log '  Dokany already installed.' 'Gray'
    }

    # -- MemProcFS forensic scan -----------------------------------------------
    # Forensic mode 4: writes vmm.sqlite3 to working directory then exits.
    Write-Log '=== Running MemProcFS forensic scan (may take several minutes) ===' 'Cyan'
    Push-Location $OutputDir
    try {
        & $mpcExe '-device' $ImagePath '-forensic' '4' `
            '-disable-python' '-disable-symbolserver' `
            '-license-accept-elastic-license-2-0' 2>&1 |
            Tee-Object -FilePath $mpcLogPath -Append
    } finally {
        Pop-Location
        # Uninstall Dokany if we installed it - leave no forensic footprint on the analyst machine.
        if ($dokanWeInstalled) {
            Write-Log '  Uninstalling Dokany ...' 'Cyan'
            $uninst = Start-Process msiexec.exe -ArgumentList "/x `"$dokanMsi`" /quiet /norestart" -PassThru -Wait
            if ($uninst.ExitCode -eq 0) { Write-Log '  Dokany uninstalled.' 'Green' }
            else { Write-Log "  Dokany uninstall returned exit $($uninst.ExitCode) - may need manual removal." 'Yellow' }
        }
    }

    if (-not (Test-Path -LiteralPath $sqliteDb)) {
        Write-Log '[!] vmm.sqlite3 not written - check _MemProcFS_*.log for errors.' 'Yellow'
        exit 1
    }
    Write-Log "  Forensic database: $sqliteDb" 'Green'

    # Helper: run sqlite3 query, return parsed JSON rows
    function Invoke-Sqlite {
        param([string]$Query)
        try {
            $out = & $sqlite3 $sqliteDb '.mode json' $Query 2>&1
            if ($LASTEXITCODE -eq 0 -and $out) { return ($out | ConvertFrom-Json -ErrorAction Stop) }
        } catch {}
        return @()
    }

    # Helper: safely get a column value from a sqlite row (handles schema variations)
    function Col { param($Row, [string[]]$Names, $Default='')
        foreach ($n in $Names) {
            $v = $Row.$n; if ($null -ne $v -and [string]$v -ne '') { return $v }
        } ; return $Default
    }

    # Discover actual column names (schema varies by MemProcFS version)
    $procCols = @(& $sqlite3 $sqliteDb "PRAGMA table_info(process);" 2>&1 |
        ForEach-Object { ($_ -split '\|')[1] } | Where-Object { $_ })
    $netCols  = @(& $sqlite3 $sqliteDb "PRAGMA table_info(net);" 2>&1 |
        ForEach-Object { ($_ -split '\|')[1] } | Where-Object { $_ })

    # -- 1. Suspicious processes (LOLBin cmdline patterns) --------------------
    $cmdlineCol = if ('commandline' -in $procCols) { 'commandline' } `
                  elseif ('cmdline'     -in $procCols) { 'cmdline' } else { $null }
    if ($cmdlineCol -and 'pslist' -notin $skipSet) {
        Write-Log '=== Process / LOLBin scan ===' 'Cyan'
        $procs = Invoke-Sqlite "SELECT pid, ppid, name, $cmdlineCol FROM process WHERE state='active' OR state='Active';"
        $lolPatterns = @(
            @{ re='(?i)-enc\b|-encodedcommand';                              score=2; label='-EncodedCommand' }
            @{ re='(?i)\bIEX\b|Invoke-' + 'Expression';                      score=2; label='IEX' }
            @{ re='(?i)\bmshta\b';                                           score=2; label='mshta' }
            @{ re='(?i)certutil.+(-decode|-urlcache|-f)';                    score=2; label='certutil' }
            @{ re='(?i)Down' + 'loadString|Down' + 'loadFile|WebClient';     score=2; label='WebClient' }
            @{ re='(?i)-w\s+hid|-windowstyle\s+hid';                         score=1; label='-WindowStyle Hidden' }
            @{ re='(?i)-nop\b|-noprofile\b';                                 score=1; label='-NoProfile' }
            @{ re='(?i)FromBase64String';                                    score=1; label='Base64' }
        )
        foreach ($p in @($procs)) {
            $cmd  = [string](Col $p @('commandline','cmdline') '')
            $procId = Col $p @('pid') '?'
            $name = [string](Col $p @('name') 'unknown')
            if (-not $cmd) { continue }
            $score = 0; $hits = [System.Collections.Generic.List[string]]::new()
            foreach ($pat in $lolPatterns) {
                if ($cmd -match $pat.re) { $score += $pat.score; $hits.Add($pat.label) }
            }
            if ($score -ge 3) {
                $sev = if ($score -ge 6) { 'Critical' } elseif ($score -ge 4) { 'High' } else { 'Medium' }
                Add-Finding $sev 'Suspicious Command Line (Memory)' "PID $procId ($name)" `
                    "Score=$score [$($hits -join ', ')] CMD=$($cmd.Substring(0,[math]::Min(300,$cmd.Length)))" `
                    'T1059.001 (PowerShell), T1027 (Obfuscated Files)'
            }
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Suspicious Command Line (Memory)' }).Count
        Write-Log "  Suspicious cmdlines: $n" 'Yellow'
    }

    # -- 2. External network connections --------------------------------------
    if ($netCols -and 'netscan' -notin $skipSet) {
        Write-Log '=== Network Connections ===' 'Cyan'
        $dstCol = if ('dst_addr' -in $netCols) { 'dst_addr' } `
                  elseif ('dst_ip'   -in $netCols) { 'dst_ip'  } else { $null }
        $srcCol = if ('src_addr' -in $netCols) { 'src_addr' } `
                  elseif ('src_ip'   -in $netCols) { 'src_ip'  } else { $null }
        if ($dstCol -and $srcCol) {
            $privateRe = '(?i)^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:)'
            $nets = Invoke-Sqlite "SELECT * FROM net WHERE state='ESTABLISHED' OR state='LISTEN';"
            foreach ($c in @($nets)) {
                $dst  = [string](Col $c @('dst_addr','dst_ip','ForeignAddr') '')
                $dPrt = [string](Col $c @('dst_port','ForeignPort') '')
                $procId  = Col $c @('pid') '?'
                $proc = [string](Col $c @('process_name','name') 'unknown')
                $state= [string](Col $c @('state') '')
                if (-not $dst -or $dst -in @('0.0.0.0','::','*','N/A')) { continue }
                if ($dst -match $privateRe) { continue }
                $sev = if ($state -eq 'ESTABLISHED') { 'High' } else { 'Medium' }
                Add-Finding $sev 'Network Connection (Memory)' "PID $procId ($proc)" `
                    "$state to $dst`:$dPrt" 'T1071 (Application Layer Protocol)'
            }
            $n = @($script:Findings | Where-Object { $_.Type -eq 'Network Connection (Memory)' }).Count
            Write-Log "  External connections: $n" 'Yellow'
        }
    }
    }   # end inner if ($runDokany) - Dokany/VFS fallback (no else clause)

} else {
# NOTE: this else binds to the OUTER if ($useMemProcFS). It runs ONLY for
# Volatility-supported image formats - never as a fallback when AFF4/MemProcFS
# routing was chosen (a failed MemProcFS run does NOT silently fall through here).

Write-Log '===================================================' 'Green'
Write-Log " Memory Analysis (Volatility / raw)" 'Green'
Write-Log " image : $(Split-Path $ImagePath -Leaf)" 'Green'
Write-Log " vol   : $VolExe" 'Green'
Write-Log '===================================================' 'Green'

# -- 1. Hidden processes (pslist vs psscan) ------------------------------------
if ('pslist' -notin $skipSet -and 'psscan' -notin $skipSet) {
    Write-Log '=== Hidden Process Detection ===' 'Cyan'
    $pslistData = Invoke-VolPlugin 'windows.pslist'
    $psscanData = Invoke-VolPlugin 'windows.psscan'
    if ($pslistData -and $psscanData) {
        $listedPids = [System.Collections.Generic.HashSet[long]]::new()
        foreach ($p in @($pslistData)) {
            $procId = [long](Get-Prop $p @('PID','Pid') 0)
            if ($procId) { $null = $listedPids.Add($procId) }
        }
        foreach ($p in @($psscanData)) {
            $procId  = [long](Get-Prop $p @('PID','Pid') 0)
            $name = [string](Get-Prop $p @('ImageFileName','Name') 'unknown')
            $ppid = [long](Get-Prop $p @('PPID','PPid') 0)
            if ($procId -and -not $listedPids.Contains($procId)) {
                Add-Finding 'High' 'Hidden Process (Memory)' `
                    "PID $procId ($name)" `
                    "Process in psscan but NOT in pslist -- DKOM rootkit artifact. PPID=$ppid" `
                    'T1014 (Rootkit), T1055 (Process Injection)'
            }
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Hidden Process (Memory)' }).Count
        Write-Log "  Hidden processes: $n" 'Yellow'
    }
}

# -- 2. Injected / unbacked executable memory (malfind) ------------------------
if ('malfind' -notin $skipSet) {
    Write-Log '=== Injected Memory (malfind) ===' 'Cyan'
    $malfindData = Invoke-VolPlugin 'windows.malfind'
    if ($malfindData) {
        $execProtections = @(
            'PAGE_EXECUTE', 'PAGE_EXECUTE_READ',
            'PAGE_EXECUTE_READWRITE', 'PAGE_EXECUTE_WRITECOPY'
        )
        foreach ($r in @($malfindData)) {
            $prot    = [string](Get-Prop $r @('Protection') '')
            $procId     = Get-Prop $r @('PID','Pid') '?'
            $proc    = [string](Get-Prop $r @('Process','ImageFileName') 'unknown')
            $start   = [string](Get-Prop $r @('Start VPN','StartVPN','VPN') '?')
            $hexdump = [string](Get-Prop $r @('Hexdump','hexdump') '')
            if ($prot -notin $execProtections) { continue }
            $hasPE = $hexdump -match '^4d\s*5a|^MZ'
            $sev   = if ($hasPE) { 'Critical' } else { 'High' }
            $note  = if ($hasPE) { 'PE header (MZ) present -- injected DLL or EXE' } else { 'Executable unbacked memory region' }
            Add-Finding $sev 'Injected Memory Region' `
                "PID $procId ($proc) @ $start" `
                "$note. Protection=$prot" `
                'T1055 (Process Injection), T1027 (Obfuscated Files or Information)'
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Injected Memory Region' }).Count
        Write-Log "  Injected regions (exec): $n" 'Yellow'
    }
}

# -- 3. Suspicious command lines -----------------------------------------------
if ('cmdline' -notin $skipSet) {
    Write-Log '=== Suspicious Command Lines ===' 'Cyan'
    $cmdlineData = Invoke-VolPlugin 'windows.cmdline'
    if ($cmdlineData) {
        $lolPatterns = @(
            @{ re='(?i)-enc\b|-encodedcommand';                               score=2; label='-EncodedCommand' }
            @{ re='(?i)\bIEX\b|Invoke-Expression';                            score=2; label='IEX/Invoke-Expression' }
            @{ re='(?i)\bmshta\b';                                            score=2; label='mshta' }
            @{ re='(?i)certutil.+(-decode|-urlcache|-f)';                     score=2; label='certutil decode/download' }
            @{ re='(?i)bitsadmin.+(/transfer|/create)';                       score=2; label='bitsadmin transfer' }
            @{ re='(?i)DownloadString|DownloadFile|WebClient|Net\.WebClient'; score=2; label='WebClient download' }
            @{ re='(?i)-w\s+hid|-windowstyle\s+hid';                          score=1; label='-WindowStyle Hidden' }
            @{ re='(?i)-nop\b|-noprofile\b';                                  score=1; label='-NoProfile' }
            @{ re='(?i)FromBase64String|ToBase64String';                      score=1; label='Base64' }
        )
        foreach ($row in @($cmdlineData)) {
            $procId  = Get-Prop $row @('PID','Pid') '?'
            $proc = [string](Get-Prop $row @('Process','ImageFileName') 'unknown')
            $cmd  = [string](Get-Prop $row @('Args','CommandLine','Cmd') '')
            if (-not $cmd) { continue }
            $score = 0
            $hits  = [System.Collections.Generic.List[string]]::new()
            foreach ($pat in $lolPatterns) {
                if ($cmd -match $pat.re) { $score += $pat.score; $hits.Add($pat.label) }
            }
            if ($score -ge 3) {
                $sev = if ($score -ge 6) { 'Critical' } elseif ($score -ge 4) { 'High' } else { 'Medium' }
                $cmdTrunc = $cmd.Substring(0, [math]::Min(300, $cmd.Length))
                Add-Finding $sev 'Suspicious Command Line (Memory)' `
                    "PID $procId ($proc)" `
                    "Score=$score Indicators=[$($hits -join ', ')] CMD=$cmdTrunc" `
                    'T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)'
            }
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Suspicious Command Line (Memory)' }).Count
        Write-Log "  Suspicious cmdlines: $n" 'Yellow'
    }
}

# -- 4. Network connections (C2 / lateral movement) ----------------------------
if ('netscan' -notin $skipSet) {
    Write-Log '=== Network Connections ===' 'Cyan'
    $netscanData = Invoke-VolPlugin 'windows.netscan'
    if ($netscanData) {
        $privateRe     = '(?i)^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:)'
        $flaggedStates = @('ESTABLISHED','LISTEN','CLOSE_WAIT','SYN_SENT')
        foreach ($c in @($netscanData)) {
            $state   = [string](Get-Prop $c @('State') '')
            $foreign = [string](Get-Prop $c @('ForeignAddr','Foreign Addr','RemoteAddr') '')
            $fport   = [string](Get-Prop $c @('ForeignPort','Foreign Port','RemotePort') '')
            $procId     = Get-Prop $c @('PID','Pid','Owner PID') '?'
            $owner   = [string](Get-Prop $c @('Owner','Process') 'unknown')
            if ($state -notin $flaggedStates) { continue }
            if (-not $foreign -or $foreign -in @('0.0.0.0','::','*','N/A')) { continue }
            if ($foreign -match $privateRe) { continue }
            $sev = if ($state -eq 'ESTABLISHED') { 'High' } else { 'Medium' }
            Add-Finding $sev 'Network Connection (Memory)' `
                "PID $procId ($owner)" `
                "$state to $foreign`:$fport -- external address present at time of capture" `
                'T1071 (Application Layer Protocol), T1021 (Remote Services)'
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Network Connection (Memory)' }).Count
        Write-Log "  External connections: $n" 'Yellow'
    }
}

# -- 5. Credential material (hashdump) -----------------------------------------
if ('hashdump' -notin $skipSet) {
    Write-Log '=== Credential Material (hashdump) ===' 'Cyan'
    $hashData = Invoke-VolPlugin 'windows.hashdump'
    if ($hashData) {
        $count = @($hashData).Count
        if ($count -gt 0) {
            # Hash values are in raw plugin log only (not embedded in findings for OpSec).
            Add-Finding 'Critical' 'Credential Material in Memory' `
                "NTLM hashes ($count account(s))" `
                "windows.hashdump extracted $count NTLM hash(es) from memory. Raw hashes in _vol_windows.hashdump_*.log. Rotate all account passwords immediately." `
                'T1003.001 (LSASS Memory), T1078 (Valid Accounts)'
            Write-Log "  Hashes extracted: $count (see raw plugin log)" 'Yellow'
        }
    }
}

# -- 6. Rogue services (svcscan) -----------------------------------------------
if ('svcscan' -notin $skipSet) {
    Write-Log '=== Service Scan ===' 'Cyan'
    $svcscanData = Invoke-VolPlugin 'windows.svcscan'
    if ($svcscanData) {
        $sysPaths = '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Program Files\\'
        foreach ($svc in @($svcscanData)) {
            $name   = [string](Get-Prop $svc @('ServiceName','Name') 'unknown')
            $binary = [string](Get-Prop $svc @('Binary','ImagePath') '')
            $state  = [string](Get-Prop $svc @('State') '')
            if (-not $binary -or $binary -match $sysPaths) { continue }
            if ($state -notin @('SERVICE_RUNNING','Running','RUNNING')) { continue }
            Add-Finding 'High' 'Suspicious Service (Memory)' `
                $name `
                "Running service with non-system binary path: $binary" `
                'T1543.003 (Windows Service), T1574 (Hijack Execution Flow)'
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Suspicious Service (Memory)' }).Count
        Write-Log "  Suspicious services: $n" 'Yellow'
    }
}

# -- 7. Unlinked DLLs (ldrmodules) --------------------------------------------
if ('ldrmodules' -notin $skipSet) {
    Write-Log '=== Unlinked DLLs (ldrmodules) ===' 'Cyan'
    $ldrData = Invoke-VolPlugin 'windows.ldrmodules'
    if ($ldrData) {
        foreach ($m in @($ldrData)) {
            $inLoad  = [string](Get-Prop $m @('InLoad','InLoadOrderList') 'True')
            $inMem   = [string](Get-Prop $m @('InMem','InMemoryOrderList') 'True')
            $inInit  = [string](Get-Prop $m @('InInit','InInitializationOrderList') 'True')
            $mapped  = [string](Get-Prop $m @('MappedPath','Path','mapped_path') '')
            $procId     = Get-Prop $m @('Pid','PID') '?'
            $proc    = [string](Get-Prop $m @('Process','ImageFileName') 'unknown')
            # Unlinked: visible in InMem list but missing from InLoad or InInit
            $memOk   = $inMem  -notin @('False','0','')
            $loadOk  = $inLoad -notin @('False','0','')
            $initOk  = $inInit -notin @('False','0','')
            if ($memOk -and (-not $loadOk -or -not $initOk) -and $mapped) {
                Add-Finding 'High' 'Unlinked DLL (Memory)' `
                    "PID $procId ($proc)" `
                    "DLL unlinked from PEB loader lists (InLoad=$inLoad InInit=$inInit) -- injection artifact. Path: $mapped" `
                    'T1055 (Process Injection), T1014 (Rootkit)'
            }
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'Unlinked DLL (Memory)' }).Count
        Write-Log "  Unlinked DLLs: $n" 'Yellow'
    }
}   # end if ('ldrmodules' ...) within the Volatility branch

# -- 8. YARA scan of process memory (vadyarascan) ------------------------------
# Parity with the MemProcFS/Python path: scan process VADs with the staged rules.
if ('yara' -notin $skipSet -and 'vadyarascan' -notin $skipSet) {
    Write-Log '=== YARA memory scan (vadyarascan) ===' 'Cyan'
    $rulesDir = Join-Path $toolsDir 'yara_rules'
    $combined = New-CombinedYaraFile -RulesDir $rulesDir
    if (-not $combined) {
        Write-Log "  SKIP: no YARA rules in $rulesDir" 'Yellow'
    } else {
        try {
            $yaraData = Invoke-VolPlugin 'windows.vadyarascan' @('--yara-file', $combined)
            $seen  = [System.Collections.Generic.HashSet[string]]::new()
            $yHits = 0
            foreach ($row in @($yaraData)) {
                if ($yHits -ge 200) { break }                 # cap noise
                $rule = [string](Get-Prop $row @('Rule') '')
                if (-not $rule -or (Test-YaraNoiseRule $rule)) { continue }
                $procId = Get-Prop $row @('PID','Pid') '?'
                $proc   = [string](Get-Prop $row @('Process','ImageFileName') 'unknown')
                if (-not $seen.Add("$procId|$rule")) { continue }   # one finding per PID+rule
                Add-Finding (Get-YaraSeverity $rule) 'YARA Match (Memory)' `
                    "PID $procId ($proc)" `
                    "Rule: $rule (vadyarascan)" `
                    'T1055 (Process Injection), T1027 (Obfuscated Files)'
                $yHits++
            }
        } finally {
            if (Test-Path -LiteralPath $combined) {
                Remove-Item -LiteralPath $combined -Force -ErrorAction SilentlyContinue
            }
        }
        $n = @($script:Findings | Where-Object { $_.Type -eq 'YARA Match (Memory)' }).Count
        Write-Log "  YARA matches: $n" 'Yellow'
    }
}

}   # end else (Volatility branch = else of the outer if ($useMemProcFS))

# -- Output --------------------------------------------------------------------
$count = $script:Findings.Count   # always a List (Add-Finding or Import-MemoryFindings)
Write-Log '===================================================' 'Green'
Write-Log " Memory analysis complete -- $count concerning finding(s)" 'Green'
Write-Log " Output: $OutFile" 'Green'
Write-Log '===================================================' 'Green'

# The Python/MemProcFS path already wrote a correct findings array; only the
# Volatility/Dokany path (which builds $script:Findings here) needs to serialize.
if (-not $findingsWrittenByPython) {
    ConvertTo-FindingsJson $script:Findings | Out-File -FilePath $OutFile -Encoding UTF8
}

if ($count -gt 0) {
    Write-Host "`n[+] $count finding(s) -> $(Split-Path $OutFile -Leaf)" -ForegroundColor Green
    if (-not $Adjudicate) {
        Write-Host '[i] To adjudicate now, re-run with -Adjudicate (merges into Combined_Findings + Get-FindingContext.ps1 -Live)' -ForegroundColor Cyan
    }
} else {
    Write-Host "`n[+] No concerning findings from memory analysis." -ForegroundColor Green
}

# -- Auto-wire into adjudication (opt-in) --------------------------------------
# Merge memory findings into the host's Combined_Findings and adjudicate live,
# instead of leaving it as a manual analyst step.
if ($Adjudicate) {
    $ctxScript = Join-Path $PSScriptRoot 'Get-FindingContext.ps1'
    if (-not (Test-Path -LiteralPath $ctxScript)) {
        Write-Log "  -Adjudicate: Get-FindingContext.ps1 not found next to this script - skipping." 'Yellow'
    } else {
        $memFindings = Import-MemoryFindings -Path $OutFile
        $prevCombined = Get-ChildItem -Path $OutputDir -Filter 'Combined_Findings_*.json' -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $existing = if ($prevCombined) { Import-MemoryFindings -Path $prevCombined.FullName } else { @() }
        $merged = Merge-FindingSets $existing $memFindings
        $combinedOut = Join-Path $OutputDir "Combined_Findings_$RunStamp.json"
        ConvertTo-FindingsJson $merged | Out-File -FilePath $combinedOut -Encoding UTF8
        Write-Log "  Merged $($merged.Count) finding(s) -> $(Split-Path $combinedOut -Leaf)" 'Green'
        Write-Log "  Adjudicating (Get-FindingContext.ps1 -Live) ..." 'Cyan'
        & $ctxScript -HostFolder $OutputDir -ReportPath $combinedOut -Live

        # Roll the adjudicated memory findings through to ALL workflow reports
        # (Incident_Report, Attack_Graph, IOCs, Principals, ATT&CK Navigator).
        $reportScript = Join-Path $PSScriptRoot '..\..\reporting\generate_reports.ps1'
        if (Test-Path -LiteralPath $reportScript) {
            Write-Log "  Regenerating reports (Incident_Report, Attack_Graph, IOCs, Principals) ..." 'Cyan'
            & $reportScript -HostFolder $OutputDir
            Write-Log "  Reports updated with memory findings." 'Green'
        } else {
            Write-Log "  Report generator not found at $reportScript - reports not regenerated." 'Yellow'
        }
    }
}

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1WZx7XIT+d7ds
# 3Mj876pZ9cf/z5lzd9wTQvl2LtQ1hqCCFrQwggN2MIICXqADAgECAhBj3Isegven
# qEj21ds5AZieMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjMxNDE2NTlaFw0zMTA2MjMxNDI2NTlaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAM3b6zgkW9zzqQraVSnj+a4zp1l4KkWs2NKNqvPP
# p9Pyjhif7sY2FZyXnXbkKElZkNveSR84IkSBjIBC/9Q2gum1eM9nDmbnj2v5L+Nu
# llMOkOjUC913DYNHmHdk/8FDJwAjl6mtsAWZwTvc7FUpyqGiD09yILSywsivvkDV
# nE/qWzKgMRGflBJreqDUR5o0l0hLhowxG58ywKqElIJpwV+N1ngcfYIpJPO4XEHB
# 6sSe0fkZralmnZdZ+sw6LRUpE7nMxmy6ZktNz51jXnm/oR7N9VbHUBOMtBLAFmny
# CFddkOEV4z4Pz3yC0SOcgJXvoJ3yfPLzug7t5W+kRcNGmrECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQQFW0G
# zu1Gz5VThEyg9LLMhDsLlDANBgkqhkiG9w0BAQsFAAOCAQEAGVSgMDhKb7EDBXTH
# 3pTUUxUoQNNByOzeSepp+Wq5HpPEO7lS204uZSljF1a6QNjya4SsVE3o4+TR9CJm
# uXqRvesj578tf9DQSl0iflg2rz9UGCXRVTazH8xMWOpt8fMlXbUf3xfYS4Wqena2
# dl5JhRwvaDUmO5EJixsQwTiYS+vS5sG0TzMIT2N0dyCrA4eRinORCiUzTn3zYZe4
# osCBOkhKbaiX6YkjzWhFGEarCNYwAYhleymgIy88BowoBYgwn1vx9G14hS9cEcHp
# d/oHA9RE3wgiiYW2VCYWv+8GWrBv+WCruhrzagOTl6RURC1ctkiRl6MbQ9XENvQF
# HPfs5TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEGPcix6C96eoSPbV2zkB
# mJ4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgMMnle70U2xQsnQRow9leHKtp12lB9Z2l
# 5P/MOSH0QX4wDQYJKoZIhvcNAQEBBQAEggEAXpOeo6qOGnkAQNxAHv1pHtb4g305
# sbv4iaBOFCj6w3axGWzTp22u5nXMovymjPzSghsKHJmvAbsC+ma9NgCbs/MXSmIE
# XwPjGJmS2EoBM0V+/HaUHJ/KoWYl2EShawJoE0uHIcWHTgT3HqPtJzzmN4Hwitfp
# wcA30O8VQBzwvbQqIazeL0EWxBaFk7IV1Imjqjheg1JI24kT/KKycjbu3lGBp9iw
# wDlm2lmI1EK5P+79gRlxMqtHhNmrEbZM85nWGbgXKG+/0gKDZnAyKI/XOm1F9pog
# z7r4GvsSCrJ3GJE3FRtkDGgzA2zroPnUoERgF1mnviFXLPoO7aHjg/ra2KGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjMxNDI3MTNaMC8GCSqGSIb3DQEJBDEi
# BCAurFOwYbnkH9obGqUqAPuoyZ7k60G4XvL2/BffeEkUVzANBgkqhkiG9w0BAQEF
# AASCAgCCtk9dXSch4MOyM3E4hyDvZbpDP7Ut1jTitdlFzK+9771bFSIK/5Lhu5X/
# /6FkFP8NYzYeczOvpUp97DLBEQvxz1M1D/DWFiikhHySR5Ul3YyPD9eyesqI42fl
# 0b8uv6esfdwMyHiwBSCJFcbkqmYnt4YYaETIH95Oue7I1SVyKF6wbu2SLJAaZT4B
# s508W4gxo4+U0LlGV4/TbFrU0t9Mty3EqMAhVz4Xa26wO2skaqKRiQPHjGcdbZh5
# cY0ZV0E+NvE1eKTp3/YsSB7euEGCU9GpsbKIA9DMGLOFgVhz6d7nYLzdyDz1H37b
# QJ+jP2AMLocywQS5VBFNltFhQ2pE6zFsOdbG3l/ZhlF4UHfwewYjbl6B2qbmf+w2
# tz+PJYu7JkO5D3q3r12kHlse5jclPFTFM0klSr+PNNCkJt8ahuyywgijwTFW1HbA
# OIoEbmkOzetNWhj9wOiCsN5jaytMkiEKhinWRSkzIdZEpoPSWDYwDLpB5l0RqQXt
# 3U92Ljbyq/O529GZYuH6tWZcFUhGWzAZ7Nr9p/vC6bl7YYK3iQk4auo80DX4LjPq
# A7U4mIVzDzwHK6PftMLzTErpSRABNOp2c3E2wTpGf8x2O/tV8zXxThiHnXcAjCj+
# X4/DsUIur5ltOko3WACzjzNQn5mBqyi/au2QZALQ/OAvOnMD+Q==
# SIG # End signature block
