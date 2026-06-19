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
        (-IncludeMemory)    -> ProcDump + WinPmem for optional memory capture
        (-IncludeSysmon)    -> Sysmon binary (for deployment, not required)

    Everything is written to <toolkit>\tools\ with a hash manifest. The collection
    workflow auto-detects and uses these if present, and silently skips them if not,
    so the kit still works with zero tools staged.

.PARAMETER ToolsDir       Destination. Default: <script folder>\tools
.PARAMETER IncludeMemory  Also fetch ProcDump + WinPmem (optional memory capture).
.PARAMETER IncludeSysmon  Also fetch the Sysmon binary.
.PARAMETER WinPmemUrl     Override the WinPmem release asset URL if the default 404s.

.EXAMPLE
    .\Build-OfflineToolkit.ps1                 # core depth tools
    .\Build-OfflineToolkit.ps1 -IncludeMemory  # + ProcDump/WinPmem
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ToolsDir = (Join-Path $PSScriptRoot 'tools'),
    [switch]$IncludeMemory,
    [switch]$IncludeSysmon,
    [string]$WinPmemUrl = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe'
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

# --- WinPmem (single exe, optional) ------------------------------------------
if ($IncludeMemory) {
    Write-Host "[*] WinPmem ..." -ForegroundColor Cyan
    $dst = Join-Path $ToolsDir 'winpmem.exe'
    try {
        Invoke-WebRequest -Uri $WinPmemUrl -OutFile $dst -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        Save-Hash 'WinPmem' $WinPmemUrl $dst 'ok'
        Write-Host "    -> winpmem.exe" -ForegroundColor Green
    } catch {
        Write-Host "    FAILED (override with -WinPmemUrl): $($_.Exception.Message)" -ForegroundColor Yellow
        Save-Hash 'WinPmem' $WinPmemUrl $null "failed: $($_.Exception.Message)"
    }
}

# --- LOLDrivers vulnerable-driver list (optional refresh, offline-usable) ----
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
