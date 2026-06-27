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
    [switch]$Adjudicate,

    # Carve true-positive (Private+executable / injected) memory regions that YARA hits, as raw
    # .bin + JSON sidecar, into tools\binja\data\<stamp>\ for offline Binary Ninja RE. Optional.
    [switch]$Carve,
    # Override the carve output dir. Default: <toolkit>\tools\binja\data\<stamp>\.
    [string]$CarveDir = '',
    # Triage: carve EVERY YARA-hit region (incl. file-backed), not just injected ones.
    [switch]$CarveAny
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

# -- Optional carve of TP regions -> tools\binja\data\ for offline Binary Ninja RE ----------------
# The YARA worker (memory_yara_worker.py, under memory_forensic.py) carves Private+exec/injected
# regions when IR_CARVE_DIR is set. We set it here so the whole python subprocess tree inherits it;
# unset otherwise so a prior run cannot leak carving into this one.
if ($Carve) {
    if (-not $CarveDir) {
        $toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
        $CarveDir    = Join-Path $toolkitRoot ("tools\binja\data\" + $RunStamp)
    }
    $env:IR_CARVE_DIR = $CarveDir
    if ($CarveAny) { $env:IR_CARVE_ANY = '1' } else { Remove-Item Env:\IR_CARVE_ANY -ErrorAction SilentlyContinue }
} else {
    Remove-Item Env:\IR_CARVE_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:\IR_CARVE_ANY -ErrorAction SilentlyContinue
}

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
    if ($Carve) { Write-Log " carve : TP$(if($CarveAny){' + ALL'}) regions -> $env:IR_CARVE_DIR (Binary Ninja)" 'Cyan' }
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

        # Per-true-positive memory enrichment (eradication scope): for each YARA true positive the
        # pivot identified, extract its full memory footprint (handles/modules/injected regions/
        # lineage/C2), carve injected regions for offline decode, and merge the eradication IOCs
        # into IOCs.json. Needs MemProcFS (live vmm) - skip on a Volatility-only image. Eradication
        # stays analyst-gated; this only gathers + populates indicators, it deletes nothing.
        $tpFile = Join-Path $OutputDir 'YARA_Pivot_TP.json'
        if ((Test-Path -LiteralPath $tpFile) -and ($AnalysisEngine -eq 'MemProcFS')) {
            $tpPids = @()
            try { $tpPids = @((Get-Content -LiteralPath $tpFile -Raw | ConvertFrom-Json) | ForEach-Object { [int]$_.pid }) } catch {}
            $enrichScript = Join-Path $PSScriptRoot 'memory_enrich.py'
            $enrichPy = Join-Path (Split-Path (Join-Path $PSScriptRoot '..\..\..\tools\memprocfs') -Resolve) 'python\python.exe'
            if ($tpPids.Count -and (Test-Path -LiteralPath $enrichScript) -and (Test-Path -LiteralPath $enrichPy)) {
                Write-Log "  Enriching $($tpPids.Count) true-positive PID(s) for eradication scope: $($tpPids -join ', ')" 'Cyan'
                $enrichLog = Join-Path $OutputDir "_MemEnrich_$RunStamp.log"
                & $enrichPy $enrichScript $ImagePath $OutputDir ($tpPids -join ',') 2>&1 | Tee-Object -FilePath $enrichLog -Append
                Write-Log "  Memory enrichment complete -> Memory_Enrichment_*.json (eradication IOCs merged into IOCs.json)." 'Green'
            }
        }
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD52VWhgH21BVqf
# o6TAn22sImmaSoO73g0YAzsYbBJAGaCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg3aDrpQ3WbVJyyXpF5t4pgaKDc41rdeLt6Rs0
# PvM5sAIwDQYJKoZIhvcNAQEBBQAEggEAJI4wdsc/mAbLoNygX7HCbTvcbwwzUvMg
# aT7KbAzKpsbzQmQc6MLjK6jw1FiOCY5pAGGHot2Fcqa1V0uFkposKRi+M5SeuHAB
# 2+gQYXyQKpNWQBmd9SAh3fcyMu2HRaQM7pJph+WRi4z+ZOfpvvON8LfLxRaDsapQ
# wp2ZpfV1zH/jeYPl/BAzsABoB2jKgWrXyZbrED7rWY4ugpshZFkklvYSVkdS+h2+
# /9Ny3vJWb2F0nTd3KezJze4Q6fJSW1xDslvU4HubJ5fOO0eee905ukr4r+j2D23q
# ZCrVVSuwCs3SbSsfn0l0BBIScjS+8UJQMD4xqSXXSeme+yMDQ6gtlaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MjBaMC8GCSqGSIb3DQEJBDEiBCDO
# HuOqjRSq/ehdk2bE3XfxIorLnXiDE329KvMrwup3wTANBgkqhkiG9w0BAQEFAASC
# AgC1sOtSb6IYpyn8vWOCCSUa4xbmB9fUEcxF0849/noEME1zl6S2fyHaCnT/8Rx1
# 4u5tNV87A3UZgl3zNURfn/9wQs2KnzMeTL3M2CNEAwzVPGvyTJNAHADLB/NI1+dl
# fPi5q99dTq0mVAtGs2uckVJMipfEHkMrQADqBj/zu0JRhChDXhT1v5dNrYdcH9iE
# MiEDjPKPDgX95S17+5LSXaD9xizCDVRI1lDpvoS/S7oxwXgCNDmhI8Xe5xphXr+3
# s3ntrahFtDHDGh8e7ndZaD0Uy60VXT25Dr+QhyZ6QM2MCxGAz+wtv2xiDuTtAGfe
# 6UQDP4Qo6aMAmHhhpeeapkse21p9XljwHjCuIUYpiiE5nIDmJyFmP8m6stRjl7r4
# sNz8/tK6p/NQIQTYvS13NDiJ1tpDPftzeD1livbGyvZJ3F8YIU35nNa5lXI7wor/
# 8sLLPosMRLMbM1Rjk2jOjyrWT1QqFToRkjstHuHWfKTBqayLsUykTf5jAUUszEhX
# AEmy6KXlhzwATXIaafFwomt6oRaDeI9iwFP98DmEurekAGue5y9DR8nmxQ1UPXd0
# BHTUBcRDmimZnRIkwLoE2OxEZRPg/VBOkLV33tsIwfZuA2A6KwCHaTzCmGzAmTLv
# D2L3nNKAe72OvDSHCw9Euxs1WbTUQmuuKQEE2BdxoOikrw==
# SIG # End signature block
