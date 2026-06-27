<#
.SYNOPSIS
    Stage all OPTIONAL third-party tools into the toolkit BEFORE it goes to an
    isolated host. Run this on an INTERNET-CONNECTED machine.

.DESCRIPTION
    The core IR workflow (Invoke-IRCollection.ps1) needs nothing but built-in
    PowerShell and runs fully offline. This staging step is only for the optional
    DEPTH tools that the isolated host can't download itself:

        Autoruns/autorunsc  -> complete persistence breadth (IFEO, Winlogon, LSA,
                               AppInit, codecs, drivers, ...) in one offline pass
        Sigcheck            -> Authenticode + PE metadata
        Handle / ListDlls   -> open handles, loaded modules
        PsTools / Tcpvcon   -> process + connection enumeration
        Strings             -> static triage of suspect binaries
        (-IncludeMemory)    -> WinPmem - default auto-staged memory capture tool.
                               RAW format; images pad MMIO gaps (image > actual RAM on
                               some systems). Works without any manual steps.
        (-IncludeFTKImager) -> Print FTK Imager manual staging instructions.
                               FTK Imager 8+ is paid/gated; cannot be auto-downloaded.
                               Place ftkimager.exe + DLLs in tools\ manually.
        (-IncludeMagnet)    -> Print Magnet RAM Capture manual staging instructions.
                               Registration required; place MRC.exe in tools\ manually.
        (-IncludeVolatility)-> Volatility 3 standalone (vol.exe) for post-collection
                               memory analysis on the analyst machine.
        (-IncludeSysmon)    -> Sysmon binary (for deployment, not required)

    Memory tool priority in Invoke-IRCollection.ps1 -CaptureMemory:
      Override:  -MemoryTool [winpmem | ftk | magnet]
      Default:   winpmem (always auto-staged; no registration needed)

    Everything is written to <toolkit>\tools\ with a hash manifest. The collection
    workflow auto-detects and uses these if present, and silently skips them if not,
    so the kit still works with zero tools staged.

    Memory capture tool preference order (Invoke-IRCollection.ps1 checks in this order):
      1. tools\ftkimager.exe  (compact, AV-stable, recommended)
      2. tools\winpmem.exe    (fallback, RAW only, MMIO padding)

.PARAMETER ToolsDir          Destination. Default: <script folder>\tools
.PARAMETER IncludeMemory     Fetch ProcDump + WinPmem (default memory capture tool, no
                             registration required, auto-staged from GitHub).
.PARAMETER IncludeFTKImager  Print FTK Imager manual staging instructions. FTK Imager 8+
                             is a paid product and cannot be auto-downloaded. Place
                             ftkimager.exe + runtime DLLs in tools\ manually.
.PARAMETER IncludeMagnet     Print Magnet RAM Capture manual staging instructions. Requires
                             free registration at magnetforensics.com. Place MRC.exe in tools\.
.PARAMETER IncludeSysmon     Also fetch the Sysmon binary.
.PARAMETER IncludeVolatility Also fetch Volatility 3 standalone (vol.exe). Used by Analyze-Memory.ps1
                             for .raw and .dmp images. Does NOT support AFF4 in the standalone build.
.PARAMETER IncludeMemProcFS  Also fetch MemProcFS (memprocfs.exe). Used by Analyze-Memory.ps1
                             for AFF4 images from go-winpmem. Supports AFF4 natively, no mount
                             driver needed for forensic analysis mode.
.PARAMETER StageSymbols      (With -IncludeVolatility) Download the Windows symbol pack into
                             tools\vol_symbols\. ~500 MB. Required if analyst machine is air-gapped.
.PARAMETER VolExeUrl         Override the Volatility 3 standalone exe URL.
.PARAMETER WinPmemUrl        Override the WinPmem release asset URL if the default 404s.

.EXAMPLE
    # Full analyst-machine kit (recommended): memory tools + analysis
    .\Build-OfflineToolkit.ps1 -IncludeMemory -IncludeVolatility -IncludeMemProcFS -IncludeYaraRules
    # Minimum for memory analysis
    .\Build-OfflineToolkit.ps1 -IncludeMemory -IncludeVolatility -IncludeMemProcFS
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ToolsDir    = (Join-Path $PSScriptRoot 'tools'),
    [switch]$IncludeMemory,
    [switch]$IncludeFTKImager,
    [switch]$IncludeMagnet,
    [switch]$IncludeSysmon,
    [switch]$IncludeYaraRules,
    [switch]$IncludeVolatility,
    [switch]$IncludeMemProcFS,
    [switch]$IncludeCapa,
    [switch]$IncludeFloss,
    [switch]$IncludeGeoIP,
    [switch]$StageSymbols,
    [string]$VolExeUrl   = '',   # leave blank to auto-resolve from GitHub API; override if needed
    [string]$WinPmemUrl  = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe',
    [string]$CapaUrl     = 'https://github.com/mandiant/capa/releases/download/v7.4.0/capa-v7.4.0-windows.zip',
    [string]$FlossUrl    = 'https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("stage_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$manifest = [System.Collections.Generic.List[object]]::new()

# Sysinternals individual download zips and the exe(s) to keep from each.
$Sysinternals = 'https://download.sysinternals.com/files'
$catalog = @(
    @{ Name='Autoruns'; Url="$Sysinternals/Autoruns.zip"; Keep=@('autorunsc.exe','autorunsc64.exe') }
    @{ Name='Sigcheck'; Url="$Sysinternals/Sigcheck.zip"; Keep=@('sigcheck.exe','sigcheck64.exe') }
    @{ Name='Handle';   Url="$Sysinternals/Handle.zip";   Keep=@('handle.exe','handle64.exe') }
    @{ Name='ListDlls'; Url="$Sysinternals/ListDlls.zip"; Keep=@('Listdlls.exe','Listdlls64.exe') }
    @{ Name='PsTools';  Url="$Sysinternals/PSTools.zip";  Keep=@('pslist.exe','pslist64.exe','PsService.exe','PsService64.exe','psloggedon.exe','psloggedon64.exe') }
    @{ Name='TCPView';  Url="$Sysinternals/TCPView.zip";  Keep=@('tcpvcon.exe','tcpvcon64.exe') }
    @{ Name='Strings';  Url="$Sysinternals/Strings.zip";  Keep=@('strings.exe','strings64.exe') }
)
if ($IncludeMemory) { $catalog += @{ Name='ProcDump'; Url="$Sysinternals/Procdump.zip"; Keep=@('procdump.exe','procdump64.exe') } }
if ($IncludeSysmon) { $catalog += @{ Name='Sysmon';   Url="$Sysinternals/Sysmon.zip";   Keep=@('Sysmon.exe','Sysmon64.exe') } }

function Save-Hash { param([string]$Name,[string]$Url,[string]$File,[string]$Status)
    $h = $null; $sz = $null
    if ($File -and (Test-Path -LiteralPath $File)) {
        $h = (Get-FileHash -LiteralPath $File -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $sz = (Get-Item -LiteralPath $File).Length
        # Normalise timestamps to download time so IR tools don't flag their own
        # staged binaries as timestomped (build date < download date).
        try {
            $fi = [System.IO.FileInfo]::new($File)
            $now = Get-Date
            $fi.LastWriteTime = $now
            $fi.CreationTime  = $now
        } catch {}
    }
    $manifest.Add([PSCustomObject][ordered]@{
        Name=$Name; Source=$Url; File=$(if($File){Split-Path -Leaf $File}else{$null})
        SHA256=$h; Bytes=$sz; Status=$Status; Downloaded=(Get-Date).ToUniversalTime().ToString('o')
    })
}

# --- Sysinternals (zip -> extract -> keep selected exes) ---------------------
foreach ($t in $catalog) {
    Write-Host "[*] $($t.Name) ..." -ForegroundColor Cyan
    $zip = Join-Path $tmp "$($t.Name).zip"
    try {
        Invoke-WebRequest -Uri $t.Url -OutFile $zip -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
        $ex = Join-Path $tmp $t.Name
        Expand-Archive -LiteralPath $zip -DestinationPath $ex -Force
        $found = $false
        foreach ($keep in $t.Keep) {
            $src = Get-ChildItem -LiteralPath $ex -Recurse -Filter $keep -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($src) {
                $dst = Join-Path $ToolsDir $src.Name
                Copy-Item -LiteralPath $src.FullName -Destination $dst -Force
                Save-Hash $t.Name $t.Url $dst 'ok'; $found = $true
                Write-Host "    -> $($src.Name)" -ForegroundColor Green
            }
        }
        if (-not $found) { Save-Hash $t.Name $t.Url $null 'no-matching-exe' }
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash $t.Name $t.Url $null "failed: $($_.Exception.Message)"
    }
}

# --- FTK Imager CLI (optional - requires manual staging) ---------------------
# FTK Imager 8+ is a paid product from Exterro. Older free versions (4.7.x) require
# registration form + email delivery. Neither can be auto-downloaded.
# Manual staging: place ftkimager.exe + its runtime DLLs into tools\.
#   1. Buy/download from https://www.exterro.com/forensic-toolkit/ftk-imager
#   2. Install, then copy C:\Program Files\Exterro\FTK Imager\ftkimager.exe
#      + all DLLs in that folder into tools\
# Use: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool ftk
if ($IncludeFTKImager) {
    Write-Host "[i] FTK Imager - manual staging required (paid/gated download)." -ForegroundColor Yellow
    Write-Host "    1. Download from https://www.exterro.com/forensic-toolkit/ftk-imager" -ForegroundColor Yellow
    Write-Host "    2. Install, then copy ftkimager.exe + DLLs from the install dir into $ToolsDir\" -ForegroundColor Yellow
    Write-Host "    3. Run: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool ftk" -ForegroundColor Yellow
    if (Test-Path (Join-Path $ToolsDir 'ftkimager.exe')) {
        Write-Host "    [+] ftkimager.exe already present in tools\" -ForegroundColor Green
        Save-Hash 'FTKImager' 'manual' (Join-Path $ToolsDir 'ftkimager.exe') 'ok-manual'
    } else {
        Save-Hash 'FTKImager' 'manual' $null 'manual-staging-required'
    }
}

# --- Magnet RAM Capture (optional - requires manual staging) -----------------
# Magnet RAM Capture is a free tool from Magnet Forensics but requires registration.
# Manual staging: download from https://www.magnetforensics.com/resources/magnet-ram-capture/
# Place MRCv*.exe (e.g. MRCv120.exe) directly into tools\ - no rename needed.
# Note: MRC v1.2.x is GUI-only for output path selection; /accepteula is the only CLI flag.
# Use: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool magnet
if ($IncludeMagnet) {
    Write-Host "[i] Magnet RAM Capture - manual staging required (free, registration at magnetforensics.com)." -ForegroundColor Yellow
    Write-Host "    1. Register and download MRCv*.exe from https://www.magnetforensics.com/resources/magnet-ram-capture/" -ForegroundColor Yellow
    Write-Host "    2. Place MRCv*.exe (e.g. MRCv120.exe) directly in $ToolsDir\" -ForegroundColor Yellow
    Write-Host "    3. Run: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool magnet" -ForegroundColor Yellow
    Write-Host "    NOTE: MRC v1.2.x opens a GUI file-save dialog - output path is selected manually." -ForegroundColor Gray
    $mrcExe = Get-ChildItem -Path $ToolsDir -Filter 'MRC*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mrcExe) {
        Write-Host "    [+] $($mrcExe.Name) already present in tools\" -ForegroundColor Green
        Save-Hash 'MagnetRAMCapture' 'manual' $mrcExe.FullName 'ok-manual'
    } else {
        Save-Hash 'MagnetRAMCapture' 'manual' $null 'manual-staging-required'
    }
}

# --- go-winpmem (primary - AFF4 with sparse streams, no MMIO gap padding) ----
# The Go rewrite of WinPmem: signed, compact AFF4 output, free from GitHub.
# AFF4 uses sparse streams - MMIO gaps are not zero-padded, so the image is
# close to physical RAM size rather than the full physical address space.
# This is the DEFAULT tool for -CaptureMemory.
if ($IncludeMemory) {
    Write-Host "[*] go-winpmem (AFF4, signed, compact) ..." -ForegroundColor Cyan
    $goUrl = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/go-winpmem_amd64_1.0-rc2_signed.exe'
    $dst   = Join-Path $ToolsDir 'go-winpmem.exe'
    try {
        Invoke-WebRequest -Uri $goUrl -OutFile $dst -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        Save-Hash 'go-winpmem' $goUrl $dst 'ok'
        Write-Host "    -> go-winpmem.exe (AFF4 default, compact - run with -MemoryTool go-winpmem)" -ForegroundColor Green
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'go-winpmem' $goUrl $null "failed: $($_.Exception.Message)"
    }

    # Also stage mini WinPmem as RAW fallback
    Write-Host "[*] WinPmem mini (RAW fallback) ..." -ForegroundColor Cyan
    $dst = Join-Path $ToolsDir 'winpmem.exe'
    try {
        Invoke-WebRequest -Uri $WinPmemUrl -OutFile $dst -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        Save-Hash 'WinPmem' $WinPmemUrl $dst 'ok'
        Write-Host "    -> winpmem.exe (RAW - use -MemoryTool winpmem)" -ForegroundColor Green
    } catch {
        Write-Host "    FAILED (override with -WinPmemUrl): $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'WinPmem' $WinPmemUrl $null "failed: $($_.Exception.Message)"
    }
}

# --- YARA (file + memory signature engine) -----------------------------------
Write-Host "[*] YARA (win64) ..." -ForegroundColor Cyan
$yaraZip = Join-Path $tmp 'yara.zip'
$yaraUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
try {
    Invoke-WebRequest -Uri $yaraUrl -OutFile $yaraZip -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    $yaraEx = Join-Path $tmp 'yara'
    Expand-Archive -LiteralPath $yaraZip -DestinationPath $yaraEx -Force
    $yara64 = Get-ChildItem -LiteralPath $yaraEx -Recurse -Filter 'yara64.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $yarac64 = Get-ChildItem -LiteralPath $yaraEx -Recurse -Filter 'yarac64.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    foreach ($bin in @($yara64, $yarac64) | Where-Object { $_ }) {
        $dst = Join-Path $ToolsDir $bin.Name
        Copy-Item -LiteralPath $bin.FullName -Destination $dst -Force
        Save-Hash 'YARA' $yaraUrl $dst 'ok'
        Write-Host "    -> $($bin.Name)" -ForegroundColor Green
    }
} catch {
    Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
    Save-Hash 'YARA' $yaraUrl $null "failed: $($_.Exception.Message)"
}

# --- LOLDrivers vulnerable-driver list (offline-usable BYOVD cache) ----------
Write-Host "[*] LOLDrivers list ..." -ForegroundColor Cyan
$dst = Join-Path $ToolsDir 'loldrivers.json'
try {
    Invoke-WebRequest -Uri 'https://www.loldrivers.io/api/drivers.json' -OutFile $dst -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    Save-Hash 'LOLDrivers' 'loldrivers.io/api/drivers.json' $dst 'ok'
    Write-Host "    -> loldrivers.json" -ForegroundColor Green
} catch {
    Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
    Save-Hash 'LOLDrivers' 'loldrivers.io' $null "failed: $($_.Exception.Message)"
}

# --- GeoIP country DB (optional, -IncludeGeoIP) ------------------------------
# Offline IP-to-country for memory_enrich.py (ties each recovered IP to real infrastructure with no
# DNS/whois/API call). db-ip.com Country Lite is keyless and CC-BY (GeoLite2-equivalent); a MaxMind
# GeoLite2-Country.mmdb can also be dropped into tools\geoip\ if preferred.
if ($IncludeGeoIP) {
    Write-Host "[*] GeoIP country DB (db-ip Lite) ..." -ForegroundColor Cyan
    $geoDir = Join-Path $ToolsDir 'geoip'
    if (-not (Test-Path $geoDir)) { New-Item -ItemType Directory -Path $geoDir -Force | Out-Null }
    $geoDst = Join-Path $geoDir 'dbip-country-lite.csv.gz'
    # db-ip publishes a fresh file each month; try the current month, then fall back a few months.
    $ok = $false
    foreach ($back in 0,1,2,3) {
        $ym  = (Get-Date).AddMonths(-$back).ToString('yyyy-MM')
        $url = "https://download.db-ip.com/free/dbip-country-lite-$ym.csv.gz"
        try {
            Invoke-WebRequest -Uri $url -OutFile $geoDst -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            Save-Hash 'GeoIP' "db-ip country-lite $ym" $geoDst 'ok'
            Write-Host "    -> tools\geoip\dbip-country-lite.csv.gz ($ym)" -ForegroundColor Green
            $ok = $true; break
        } catch { }
    }
    if (-not $ok) {
        Write-Host "    FAILED: could not fetch db-ip country-lite (tried last 4 months)" -ForegroundColor Yellow
        Save-Hash 'GeoIP' 'db-ip.com country-lite' $null 'failed'
    }
}

# --- YARA community rule packs (optional, -IncludeYaraRules) ----------------
if ($IncludeYaraRules) {
    $yaraRulesDir = Join-Path $ToolsDir 'yara_rules'
    New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null

    $ruleSources = @(
        @{
            Name   = 'AbuseCh'
            Url    = 'https://yaraify.abuse.ch/yarahub/yaraify-rules.zip'
            SubDir = 'abusech'
            Filter = '*.yar'
            Within = ''           # flat zip (rules at the root) - keep all .yar
        }
        @{
            Name   = 'Elastic'
            Url    = 'https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip'
            SubDir = 'elastic'
            Filter = '*.yar'
            Within = 'yara'       # only extract files under this subfolder of the zip
        }
        @{
            Name   = 'ReversingLabs'
            Url    = 'https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip'
            SubDir = 'reversinglabs'
            Filter = '*.yara'
            Within = 'yara'
        }
        @{
            Name   = 'Neo23x0'
            Url    = 'https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip'
            SubDir = 'neo23x0'
            Filter = '*.yar'
            Within = 'yara'
        }
    )

    foreach ($src in $ruleSources) {
        Write-Host "[*] YARA rules - $($src.Name) ..." -ForegroundColor Cyan
        $zipPath = Join-Path $tmp "$($src.Name).zip"
        $exPath  = Join-Path $tmp "$($src.Name)_ex"
        $destDir = Join-Path $yaraRulesDir $src.SubDir
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        try {
            Invoke-WebRequest -Uri $src.Url -OutFile $zipPath -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
            Expand-Archive -LiteralPath $zipPath -DestinationPath $exPath -Force
            $rules = Get-ChildItem -LiteralPath $exPath -Recurse -Filter $src.Filter -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match [regex]::Escape($src.Within) }
            $count = 0
            foreach ($rule in $rules) {
                Copy-Item -LiteralPath $rule.FullName -Destination (Join-Path $destDir $rule.Name) -Force
                $count++
            }
            Write-Host "    -> $count rule file(s) staged to yara_rules\$($src.SubDir)\" -ForegroundColor Green
            Save-Hash $src.Name $src.Url $null "ok ($count rules)"
        } catch {
            Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
            Save-Hash $src.Name $src.Url $null "failed: $($_.Exception.Message)"
        }
    }
}

# --- capa standalone (optional, -IncludeCapa) -------------------------------
# capa identifies capabilities/ATT&CK in the injected regions memory_enrich.py carves. The
# standalone build bundles its rules, so capa.exe alone is enough; memory_enrich auto-runs it
# (tools\capa\capa.exe) over each carved shellcode region.
if ($IncludeCapa) {
    Write-Host "[*] capa (standalone) ..." -ForegroundColor Cyan
    $capaDir = Join-Path $ToolsDir 'capa'
    New-Item -ItemType Directory -Path $capaDir -Force | Out-Null
    $capaZip = Join-Path $tmp 'capa.zip'
    $capaEx  = Join-Path $tmp 'capa_ex'
    $dst     = Join-Path $capaDir 'capa.exe'
    try {
        Invoke-WebRequest -Uri $CapaUrl -OutFile $capaZip -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
        Expand-Archive -LiteralPath $capaZip -DestinationPath $capaEx -Force
        $exe = Get-ChildItem -LiteralPath $capaEx -Recurse -Filter 'capa.exe' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($exe) {
            Copy-Item -LiteralPath $exe.FullName -Destination $dst -Force
            Write-Host "    -> capa.exe staged to tools\capa\" -ForegroundColor Green
            Save-Hash 'capa' $CapaUrl $dst 'ok'
        } else {
            Write-Host "    FAILED: capa.exe not found in archive" -ForegroundColor Yellow
            Save-Hash 'capa' $CapaUrl $null 'no-capa-exe-in-zip'
        }
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'capa' $CapaUrl $null "failed: $($_.Exception.Message)"
    }
}

# --- FLOSS standalone (optional, -IncludeFloss) -----------------------------
# FLOSS (FLARE Obfuscated String Solver) complements capa: it extracts static + stack + tight +
# decoded strings from the injected regions memory_enrich.py carves, recovering an implant's
# deobfuscated config/strings that plain `strings`/capa miss. memory_enrich auto-runs tools\floss\floss.exe.
if ($IncludeFloss) {
    Write-Host "[*] FLOSS (standalone) ..." -ForegroundColor Cyan
    $flossDir = Join-Path $ToolsDir 'floss'
    New-Item -ItemType Directory -Path $flossDir -Force | Out-Null
    $flossZip = Join-Path $tmp 'floss.zip'
    $flossEx  = Join-Path $tmp 'floss_ex'
    $dst      = Join-Path $flossDir 'floss.exe'
    try {
        Invoke-WebRequest -Uri $FlossUrl -OutFile $flossZip -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
        Expand-Archive -LiteralPath $flossZip -DestinationPath $flossEx -Force
        $exe = Get-ChildItem -LiteralPath $flossEx -Recurse -Filter 'floss.exe' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($exe) {
            Copy-Item -LiteralPath $exe.FullName -Destination $dst -Force
            Write-Host "    -> floss.exe staged to tools\floss\" -ForegroundColor Green
            Save-Hash 'floss' $FlossUrl $dst 'ok'
        } else {
            Write-Host "    FAILED: floss.exe not found in archive" -ForegroundColor Yellow
            Save-Hash 'floss' $FlossUrl $null 'no-floss-exe-in-zip'
        }
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'floss' $FlossUrl $null "failed: $($_.Exception.Message)"
    }
}

# --- MemProcFS (AFF4-native memory analysis, no mount driver required) -------
# MemProcFS by Ulf Frisk - free, open source, directly downloadable from GitHub.
# Used by Analyze-Memory.ps1 when the image is .aff4 (go-winpmem output).
# Supports AFF4 natively; Volatility standalone does not.
# Forensic mode (-forensic 1) writes CSV/JSON output without needing to mount.
if ($IncludeMemProcFS) {
    Write-Host "[*] MemProcFS (memprocfs.exe) ..." -ForegroundColor Cyan
    try {
        $rel = Invoke-WebRequest -Uri 'https://api.github.com/repos/ufrisk/MemProcFS/releases/latest' `
                   -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop |
               Select-Object -ExpandProperty Content | ConvertFrom-Json
        # Windows x64 zip - prefer the versioned "latest" alias asset
        $asset = $rel.assets |
                 Where-Object { $_.name -match 'win_x64-latest\.zip$' } |
                 Select-Object -First 1
        if (-not $asset) {
            $asset = $rel.assets |
                     Where-Object { $_.name -match 'win_x64.*\.zip$' } |
                     Sort-Object name -Descending | Select-Object -First 1
        }
        if ($asset) {
            Write-Host "    Latest: $($rel.tag_name) -> $($asset.name)" -ForegroundColor Gray
            $mpcZip = Join-Path $tmp 'memprocfs.zip'
            $mpcEx  = Join-Path $tmp 'memprocfs_ex'
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $mpcZip `
                -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
            Expand-Archive -LiteralPath $mpcZip -DestinationPath $mpcEx -Force
            # Copy memprocfs.exe and all required DLLs into tools\
            $mpcBin = Get-ChildItem -LiteralPath $mpcEx -Recurse -Filter 'memprocfs.exe' `
                          -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($mpcBin) {
                $binDir  = $mpcBin.DirectoryName
                $mpcDir  = Join-Path $ToolsDir 'memprocfs'
                New-Item -ItemType Directory -Path $mpcDir -Force | Out-Null
                $copied = 0
                Get-ChildItem -LiteralPath $binDir -File | ForEach-Object {
                    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $mpcDir $_.Name) -Force
                    $copied++
                }
                Save-Hash 'MemProcFS' $asset.browser_download_url (Join-Path $mpcDir 'MemProcFS.exe') 'ok'
                Write-Host "    -> tools\memprocfs\MemProcFS.exe + $copied file(s)" -ForegroundColor Green

                # Also stage sqlite3.exe for querying the MemProcFS forensic database (-forensic 4).
                # Probe versioned SQLite.org URLs newest-first; format: YYYY/sqlite-tools-win-x64-VVVV.zip
                Write-Host "    [*] sqlite3.exe (for forensic db queries) ..." -ForegroundColor Gray
                $sqLiteUrl = $null
                $sqLiteCandidates = @(
                    'https://www.sqlite.org/2026/sqlite-tools-win-x64-3500000.zip',
                    'https://www.sqlite.org/2025/sqlite-tools-win-x64-3490000.zip',
                    'https://www.sqlite.org/2025/sqlite-tools-win-x64-3480000.zip',
                    'https://www.sqlite.org/2024/sqlite-tools-win-x64-3470000.zip'
                )
                foreach ($sc in $sqLiteCandidates) {
                    try {
                        $h = Invoke-WebRequest -Uri $sc -Method Head -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
                        if ($h.StatusCode -eq 200) { $sqLiteUrl = $sc; break }
                    } catch {}
                }
                if ($sqLiteUrl) {
                    $sqZip = Join-Path $tmp 'sqlite3.zip'
                    $sqEx  = Join-Path $tmp 'sqlite3_ex'
                    try {
                        Invoke-WebRequest -Uri $sqLiteUrl -OutFile $sqZip -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
                        Expand-Archive -LiteralPath $sqZip -DestinationPath $sqEx -Force
                        $sq = Get-ChildItem -LiteralPath $sqEx -Recurse -Filter 'sqlite3.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($sq) {
                            Copy-Item -LiteralPath $sq.FullName -Destination (Join-Path $mpcDir 'sqlite3.exe') -Force
                            Save-Hash 'SQLite3' $sqLiteUrl (Join-Path $mpcDir 'sqlite3.exe') 'ok'
                            Write-Host "    -> tools\memprocfs\sqlite3.exe" -ForegroundColor Green
                        }
                    } catch {
                        Write-Host "    sqlite3 download failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "    sqlite3: no URL resolved - MemProcFS forensic db queries will not be available." -ForegroundColor Yellow
                }
            } else {
                Write-Host "    memprocfs.exe not found in archive." -ForegroundColor Yellow
                Save-Hash 'MemProcFS' $asset.browser_download_url $null 'exe-not-found'
            }
        } else {
            Write-Host "    No Windows x64 zip asset found in latest release." -ForegroundColor Yellow
            Save-Hash 'MemProcFS' 'github' $null 'asset-not-found'
        }
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'MemProcFS' 'github' $null "failed: $($_.Exception.Message)"
    }

    # Also stage Python 3.12 embeddable - used by vmmpyc for AFF4 analysis (no Dokany needed).
    # Embeddable package: self-contained zip, no installer, no system changes, bare-Windows safe.
    Write-Host "[*] Python 3.12 embeddable (vmmpyc runtime) ..." -ForegroundColor Cyan
    $pyDir = Join-Path $mpcDir 'python'
    New-Item -ItemType Directory -Path $pyDir -Force | Out-Null
    # Resolve latest Python 3.12.x embeddable from python.org
    $pyUrl = $null
    try {
        $pyPage = Invoke-WebRequest -Uri 'https://www.python.org/downloads/windows/' -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $pyUrl  = ([regex]::Matches($pyPage.Content, 'href="(https://www\.python\.org/ftp/python/3\.12\.[^/]+/python-3\.12\.[^-]+-embed-amd64\.zip)"') |
                  ForEach-Object { $_.Groups[1].Value } | Select-Object -First 1)
    } catch {}
    if (-not $pyUrl) { $pyUrl = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip' }
    $pyZip = Join-Path $tmp 'python_embed.zip'
    $pyEx  = Join-Path $tmp 'python_embed_ex'
    try {
        Invoke-WebRequest -Uri $pyUrl -OutFile $pyZip -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
        Expand-Archive -LiteralPath $pyZip -DestinationPath $pyEx -Force
        Get-ChildItem -LiteralPath $pyEx -File | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $pyDir $_.Name) -Force
        }
        Save-Hash 'Python312' $pyUrl (Join-Path $pyDir 'python.exe') 'ok'
        Write-Host "    -> tools\memprocfs\python\python.exe  ($([System.IO.Path]::GetFileName($pyUrl)))" -ForegroundColor Green
    } catch {
        Write-Host "    Python 3.12 embeddable download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'Python312' $pyUrl $null "failed: $($_.Exception.Message)"
    }

    # Also stage Dokany x64 MSI - MemProcFS requires Dokany for VFS mounting.
    # Analyze-Memory.ps1 installs Dokany before analysis and uninstalls after.
    Write-Host "[*] Dokany x64 MSI (MemProcFS VFS driver) ..." -ForegroundColor Cyan
    $dokanDst = Join-Path $ToolsDir 'dokan_x64.msi'
    try {
        $dokanRel = Invoke-WebRequest -Uri 'https://api.github.com/repos/dokan-dev/dokany/releases/latest' `
                        -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop |
                    Select-Object -ExpandProperty Content | ConvertFrom-Json
        $dokanAsset = $dokanRel.assets | Where-Object { $_.name -eq 'Dokan_x64.msi' } | Select-Object -First 1
        if ($dokanAsset) {
            Invoke-WebRequest -Uri $dokanAsset.browser_download_url -OutFile $dokanDst `
                -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            Save-Hash 'Dokany' $dokanAsset.browser_download_url $dokanDst 'ok'
            Write-Host "    -> tools\dokan_x64.msi  ($($dokanRel.tag_name))" -ForegroundColor Green
        } else {
            Write-Host "    No Dokan_x64.msi asset found in Dokany latest release." -ForegroundColor Yellow
            Save-Hash 'Dokany' 'github' $null 'asset-not-found'
        }
    } catch {
        Write-Host "    Dokany download failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'Dokany' 'github' $null "failed: $($_.Exception.Message)"
    }
}

# --- Volatility 3 standalone (analyst-machine memory analysis) ---------------
if ($IncludeVolatility) {
    Write-Host "[*] Volatility 3 (vol.exe) ..." -ForegroundColor Cyan
    $dst = Join-Path $ToolsDir 'vol.exe'

    # Resolve the latest release zip URL via GitHub API if not overridden.
    $resolvedVolUrl = $VolExeUrl
    if (-not $resolvedVolUrl) {
        try {
            $rel = Invoke-WebRequest -Uri 'https://api.github.com/repos/volatilityfoundation/volatility3/releases/latest' `
                       -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop | Select-Object -ExpandProperty Content | ConvertFrom-Json
            $asset = $rel.assets | Where-Object { $_.name -match 'win-exes.*\.zip$' } | Select-Object -First 1
            if ($asset) { $resolvedVolUrl = $asset.browser_download_url }
            if ($resolvedVolUrl) { Write-Host "    Latest: $($rel.tag_name) -> $($asset.name)" -ForegroundColor Gray }
        } catch {
            Write-Host "    GitHub API failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if ($resolvedVolUrl) {
        $volZip = Join-Path $tmp 'volatility3.zip'
        $volEx  = Join-Path $tmp 'volatility3_ex'
        try {
            Invoke-WebRequest -Uri $resolvedVolUrl -OutFile $volZip -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
            Expand-Archive -LiteralPath $volZip -DestinationPath $volEx -Force
            $volBin = Get-ChildItem -LiteralPath $volEx -Recurse -Filter 'vol.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($volBin) {
                Copy-Item -LiteralPath $volBin.FullName -Destination $dst -Force
                Save-Hash 'Volatility3' $resolvedVolUrl $dst 'ok'
                Write-Host "    -> vol.exe  ($([math]::Round((Get-Item $dst).Length/1MB,0)) MB)" -ForegroundColor Green
            } else {
                Write-Host "    vol.exe not found in archive contents." -ForegroundColor Yellow
                Save-Hash 'Volatility3' $resolvedVolUrl $null 'vol.exe-not-in-archive'
            }
        } catch {
            Write-Host "    FAILED (override with -VolExeUrl): $($_.Exception.Message)" -ForegroundColor Yellow
            Save-Hash 'Volatility3' $resolvedVolUrl $null "failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "    Could not resolve Volatility 3 download URL." -ForegroundColor Yellow
        Write-Host "    Override: .\Build-OfflineToolkit.ps1 -IncludeVolatility -VolExeUrl <url>" -ForegroundColor Yellow
        Save-Hash 'Volatility3' 'auto-resolve' $null 'url-not-found'
    }

    if ($StageSymbols) {
        Write-Host "[*] Volatility 3 Windows symbols (~500 MB) ..." -ForegroundColor Cyan
        $symUrl  = 'https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip'
        $symZip  = Join-Path $tmp 'vol_symbols_windows.zip'
        $symDir  = Join-Path $ToolsDir 'vol_symbols'
        New-Item -ItemType Directory -Path $symDir -Force | Out-Null
        try {
            Invoke-WebRequest -Uri $symUrl -OutFile $symZip -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
            Expand-Archive -LiteralPath $symZip -DestinationPath $symDir -Force
            Save-Hash 'Vol3Symbols' $symUrl $null 'ok'
            Write-Host "    -> vol_symbols\ (Windows ISF pack)" -ForegroundColor Green
        } catch {
            Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Yellow
            Save-Hash 'Vol3Symbols' $symUrl $null "failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "    [i] Symbols not staged (-StageSymbols not set). vol.exe will auto-fetch from" -ForegroundColor Gray
        Write-Host "        Microsoft on first run (requires internet on the analyst machine)." -ForegroundColor Gray
    }
}

# --- Manifest + cleanup ------------------------------------------------------
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ToolsDir 'STAGED_MANIFEST.json') -Encoding UTF8
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

$ok   = @($manifest | Where-Object { $_.Status -eq 'ok' }).Count
$fail = @($manifest | Where-Object { $_.Status -like 'failed*' -or $_.Status -eq 'no-matching-exe' }).Count
Write-Host "`n=== Staging complete ===" -ForegroundColor Green
Write-Host "[+] $ok tool(s) staged to $ToolsDir  ($fail failed)" -ForegroundColor Green
Write-Host "[i] Core workflow runs offline WITHOUT these; they only enable optional depth." -ForegroundColor Gray
Write-Host "[i] Now copy the whole toolkit folder to the responder drive and run Invoke-IRCollection.ps1 on the isolated host." -ForegroundColor Gray
$manifest | Select-Object Name, Status, File | Format-Table -AutoSize

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCs1X56cO8fP0x2
# tVK3iF5+SzxkoWnMpNkI3sqQg7ZnDqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgcijf40zLFB43gYLDoyaj57JcyGyvBJe286a7
# JXjxPT4wDQYJKoZIhvcNAQEBBQAEggEAFp+tZBnOsRaFNGuEKyvuB+ZLJ4NJAnca
# zHBr8sP6IibgG1OYsxlcKvz169/IqTv2UUqzp3X4j3YgzPHGvuLv1dEkV1QPTKxK
# 0SaARA4+xwaPNSzKGnuJpH0dI+RYvscB6Q1ViaPlbvjBc9EJxTZJZAiOBW3v9FQ3
# FiyB6dsi/tBJ6hk7P476/bv0fXY38TJsjvvdRZw+sM1DTVQYCw+LcVULx6/xu3Cv
# VU9QVDin3VeRQoi5eZa8psLcv5Hg9eeXTggvOGXO0Wc38otMo0DWmQFu9vTBpIq3
# +uZnyDUjEqYn/tBQXRKiwFzb3v1pmNWG/FxKoNkK2tBdv4BfUxUvd6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MTRaMC8GCSqGSIb3DQEJBDEiBCBL
# PClIZTviAMODNslOE65iChS1B3wz/JNTb4nFeNExPDANBgkqhkiG9w0BAQEFAASC
# AgAiPHicenA1uS53XvhgCB0F+zLmRfnBAWtlJUHxCIfVCgGkH/cYBYN36+jVrK9g
# 2xezJ4MNu0BJLr4jMUrRUeJboAaRtGs9h7rsHD8nVb5pxsfEULEaVzsU2sVGi4+4
# LWG23KOXN65TkCxqY2uuThdY9xWfmj5aauAnhi8xE5+aKmy1Gi9enPlVe8nPbtjE
# 25X/BpqjsZDwWBXlvIXyWvZEuZlE5oWkRvv0Bwz7KfH2QxNszy3hnfQGL/eUdPlo
# QC2Ic1Z4o9icYew/ba1XuuiNJa4JMWhoe0BOXqXK12gn7mu5rhDNXnvUlu1dyl0D
# keOm1gDDM+rdX6gN1YZ/lI6rAUAu6xxno/NRDfYdATs13pjv5bw2yzzUi0usTFtK
# PFkYlef1MCUpzy5MH5rBsM0AglRUS8wpq/VnIYNiO6Efw/x7pDzRI9376/E2S0IF
# 5g6P9ucqzOHrO3jaa0RvFHnpGuyDcYffq969ngt/dEr1WsC0NzWkFCwzBC75Kzs8
# g/2h36ZZmXqvlqtfXrMM8fGgL4BK5j+ugsk4nHloKPo/iElKPDsJSOXCbG5cOZnD
# kYHjwwiLweZw8IJaXRO7oiCBPajQZ1go96tP3/BLvzN83HbTctIMFKfI8BeZSyvY
# XUCyDBcOjdLTZK4yDTxdTf3xcb+1kof/Rg6sqQNYM4AQ4w==
# SIG # End signature block
