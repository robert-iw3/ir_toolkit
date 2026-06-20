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
        (-IncludeMemory)    -> WinPmem — default auto-staged memory capture tool.
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
    [switch]$StageSymbols,
    [string]$VolExeUrl   = '',   # leave blank to auto-resolve from GitHub API; override if needed
    [string]$WinPmemUrl  = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe'
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

# --- FTK Imager CLI (optional — requires manual staging) ---------------------
# FTK Imager 8+ is a paid product from Exterro. Older free versions (4.7.x) require
# registration form + email delivery. Neither can be auto-downloaded.
# Manual staging: place ftkimager.exe + its runtime DLLs into tools\.
#   1. Buy/download from https://www.exterro.com/forensic-toolkit/ftk-imager
#   2. Install, then copy C:\Program Files\Exterro\FTK Imager\ftkimager.exe
#      + all DLLs in that folder into tools\
# Use: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool ftk
if ($IncludeFTKImager) {
    Write-Host "[i] FTK Imager — manual staging required (paid/gated download)." -ForegroundColor Yellow
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

# --- Magnet RAM Capture (optional — requires manual staging) -----------------
# Magnet RAM Capture is a free tool from Magnet Forensics but requires registration.
# Manual staging: download from https://www.magnetforensics.com/resources/magnet-ram-capture/
# Place MRCv*.exe (e.g. MRCv120.exe) directly into tools\ — no rename needed.
# Note: MRC v1.2.x is GUI-only for output path selection; /accepteula is the only CLI flag.
# Use: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool magnet
if ($IncludeMagnet) {
    Write-Host "[i] Magnet RAM Capture — manual staging required (free, registration at magnetforensics.com)." -ForegroundColor Yellow
    Write-Host "    1. Register and download MRCv*.exe from https://www.magnetforensics.com/resources/magnet-ram-capture/" -ForegroundColor Yellow
    Write-Host "    2. Place MRCv*.exe (e.g. MRCv120.exe) directly in $ToolsDir\" -ForegroundColor Yellow
    Write-Host "    3. Run: Invoke-IRCollection.ps1 -CaptureMemory -MemoryTool magnet" -ForegroundColor Yellow
    Write-Host "    NOTE: MRC v1.2.x opens a GUI file-save dialog — output path is selected manually." -ForegroundColor Gray
    $mrcExe = Get-ChildItem -Path $ToolsDir -Filter 'MRC*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mrcExe) {
        Write-Host "    [+] $($mrcExe.Name) already present in tools\" -ForegroundColor Green
        Save-Hash 'MagnetRAMCapture' 'manual' $mrcExe.FullName 'ok-manual'
    } else {
        Save-Hash 'MagnetRAMCapture' 'manual' $null 'manual-staging-required'
    }
}

# --- go-winpmem (primary — AFF4 with sparse streams, no MMIO gap padding) ----
# The Go rewrite of WinPmem: signed, compact AFF4 output, free from GitHub.
# AFF4 uses sparse streams — MMIO gaps are not zero-padded, so the image is
# close to physical RAM size rather than the full physical address space.
# This is the DEFAULT tool for -CaptureMemory.
if ($IncludeMemory) {
    Write-Host "[*] go-winpmem (AFF4, signed, compact) ..." -ForegroundColor Cyan
    $goUrl = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/go-winpmem_amd64_1.0-rc2_signed.exe'
    $dst   = Join-Path $ToolsDir 'go-winpmem.exe'
    try {
        Invoke-WebRequest -Uri $goUrl -OutFile $dst -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        Save-Hash 'go-winpmem' $goUrl $dst 'ok'
        Write-Host "    -> go-winpmem.exe (AFF4 default, compact — run with -MemoryTool go-winpmem)" -ForegroundColor Green
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
        Write-Host "    -> winpmem.exe (RAW — use -MemoryTool winpmem)" -ForegroundColor Green
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

# --- YARA community rule packs (optional, -IncludeYaraRules) ----------------
if ($IncludeYaraRules) {
    $yaraRulesDir = Join-Path $ToolsDir 'yara_rules'
    New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null

    $ruleSources = @(
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
        Write-Host "[*] YARA rules — $($src.Name) ..." -ForegroundColor Cyan
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

# --- MemProcFS (AFF4-native memory analysis, no mount driver required) -------
# MemProcFS by Ulf Frisk — free, open source, directly downloadable from GitHub.
# Used by Analyze-Memory.ps1 when the image is .aff4 (go-winpmem output).
# Supports AFF4 natively; Volatility standalone does not.
# Forensic mode (-forensic 1) writes CSV/JSON output without needing to mount.
if ($IncludeMemProcFS) {
    Write-Host "[*] MemProcFS (memprocfs.exe) ..." -ForegroundColor Cyan
    try {
        $rel = Invoke-WebRequest -Uri 'https://api.github.com/repos/ufrisk/MemProcFS/releases/latest' `
                   -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop |
               Select-Object -ExpandProperty Content | ConvertFrom-Json
        # Windows x64 zip — prefer the versioned "latest" alias asset
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
                    Write-Host "    sqlite3: no URL resolved — MemProcFS forensic db queries will not be available." -ForegroundColor Yellow
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

    # Also stage Python 3.12 embeddable — used by vmmpyc for AFF4 analysis (no Dokany needed).
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

    # Also stage Dokany x64 MSI — MemProcFS requires Dokany for VFS mounting.
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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD5OuuTiPkKCt8o
# 0eXuZkYZYGhSZnpywGN2UJMVXN1az6CCFrQwggN2MIICXqADAgECAhBa5MQyEl22
# qUV1bZluOcpOMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjAwMDU5NDZaFw0zMTA2MjAwMTA5NDZaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAJ1nFbqBzQLbEhUUTT10Lrva+ooE/uVqzTJbGk5/
# xh3zYBEAaRil7obceqCWtDg6KSjbDQP8wto42fHUK8tp0FU0NEi2+rkWHfcpeasm
# z2e+UFQMDlXRcxg7dqe+08OB4pFhwrHSPo0m7HZAgtpHd02POka7jaYVoAnScg7i
# LuZiRSJ3tJKZu1KCSTntV+LbicnowTlaDEvr7JQzSVs+5BpNadU3n/ujzH088Mgm
# CoXooQpF12SzbZNCZ+kbgza6bNMbEHNGkLr9S0vHQD95oKPWF7YuOu7jqtkuCOZc
# KYYi4nOXFwLqXmJ+sqqpR2NrrfMkz4VaALGIZ93o10CHWDkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQRXBKC
# VXuhcK7rCDzb/6SAfPGwvDANBgkqhkiG9w0BAQsFAAOCAQEAlZhDvun+4lQ0yd2C
# +pAFD3B2/l2N9hArAcHhp6DaO48NSIT3eyyhGrfk8f3lDVhvjEbUDDmb6Oe67rBN
# 3W7Dp1Y+W8Z96kC3miq7UbmVTGkiQGZFwi0KJ8tw++//vlU3zlW9nhqwFxzm7DfL
# zECzv6bnd9Ri+1R4zhvkd5BLTuwLjPLkzbOTdsGwbXWWOK2gTTCr82I7G9xcq9Gv
# qAcoJAHVEiNKt7p7Y+ScDL/AZGBMCBTsN9gcAoIgq22EWBHHV02HmPfuYyddaq1c
# Lmjot0+5wVoPVl4wNktght1WVHDlk3EpEJF5qc7Yhl3YtniIEHQoO8BkWykpFDhy
# q5wz7TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEFrkxDISXbapRXVtmW45
# yk4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgwyw7UiZAVP8hBOVSzn6fiuXn6VLJqGgi
# n7EZwONENtkwDQYJKoZIhvcNAQEBBQAEggEAD33rILhT9UArEkGYODvKThVA+nMF
# iccjjKXfpaHa6Obkp3CiY5z8shY84pbBkNXFQWRrqSz3cSa9E4zbC5t6t5ojZaV0
# eHsNyvCdmwtIq3UzayyD6LORFrSqI6G/3SNmSXMbybgO7cU+QwTCHBYVV7xIMdFv
# 09Jc7U9kieuQRugXJnrXMOH7iEWeupRpbu2D+Zvy686Nu5+pgjnJMqECkL4KnBK5
# diDUk/0Jq87KMAckLFIQAsgFt++RiT0BfFJsOhVPWqlR0Yo6edgpdeedXk7vafbe
# 5N+gV9j6OPkEMX7N2cZe4ZZE2bMzojhfkKUTAg6NONiRnwQC9Bqsk63ENKGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MjdaMC8GCSqGSIb3DQEJBDEi
# BCC2+064ljIq7KJt0u543KNBHd66TyLaUDijPd+HbqVzYjANBgkqhkiG9w0BAQEF
# AASCAgBrO0cU0xOH6AURG7JV9SJS24X8FaS4fXgoZmJznLS/8THsoJBo5ressn5I
# d0lHSIHvroud+fD6uI1Pmj1cDA1tcFJGb0Nvg4Lja1/lmnIVuEb271aAvxZLZaXU
# rr8p8b+bPm6+fYPQj2BfGgamDfKfks/+22qazCIPA3ZuEQGRRTT3MYVuluRTPJYc
# afjHEY4LANX7SgdRcopWEyfoAEBMDBGFLt1//Qwq0HKug/XCIo9Q1k9Jy4t5RgnV
# 33onJhHuOrKs6AIYyxu5NdByDFt0ms/021uiKP12YGj0RlEkOWUJJlgQaDdclz52
# AfwuN/J4gjIeAIOjQ1Xm8sMo+x2KtJQIBmEGSzwvitzn8ReIxJ3ErMtK6xIrzDXY
# yVrmcPUVozsVzzoNTSo07K+5WzK/rsUExhC6Nx+Jpt1HCLnVCNwqF/4newqe9iPW
# VIujrsTrkt3i3HyqWTaOOzD8cmcFEPp6Ic6KmxrkasamMTu2tJprD3VG/B2YtNLv
# XUrPru8DfnEOfmHcWTgZFT4p55+Hk3P1OwfAPTW24zBYQUK8EhR1MgiiFPO1+pIh
# ibgm2VC+JeJcrkf+tBEG1S2AJsW2SwlZotnvHfd0GqfESFPqYN6laxFL0XWPXcCD
# +oaKpDDGrRUcJmjjzMOIUnNzwM5bEXY2RlGnCkmQl9MrhARzBA==
# SIG # End signature block
