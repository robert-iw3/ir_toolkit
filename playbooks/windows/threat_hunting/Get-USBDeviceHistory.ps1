<#
.SYNOPSIS
    Removable-media (USB) forensic timeline - trace a host infection back to its origin device.

.DESCRIPTION
    Read-only collection of every USB-storage device that was ever connected to a host: vendor /
    product / serial, the human "FriendlyName" (volume label), and first-connect / last-connect /
    last-removed timestamps from the most reliable source available (USBSTOR property cache, then the
    event logs, then setupapi.dev.log). When a reference time is supplied (-InfectionTime, and/or a
    -PayloadName whose first execution is read from Prefetch), each device is correlated to it:
    connected BEFORE the reference -> entry-vector candidate; connected AFTER -> introduced after the
    fact (not the source). Generic and case-agnostic; nothing is modified.

    Sources (most authoritative first):
        SYSTEM\...\Enum\USBSTOR\...\Properties\{83da6326-...}\0064/0066/0067   first/last connect, removal
        Microsoft-Windows-Partition/Diagnostic 1006                            disk arrival (serial + time)
        Microsoft-Windows-DriverFrameworks-UserMode/Operational 2003/2102      device pnp arrival/removal
        %WinDir%\INF\setupapi.dev.log                                          first-install (plug-in) time
        SOFTWARE\...\Windows Portable Devices\Devices                          friendly name / volume label

    LIVE (default): reads the running system. OFFLINE: point at extracted hives from a powered-off
    host (load SYSTEM/SOFTWARE + setupapi.dev.log). Nothing is modified.

.PARAMETER OutputDir       Where to write USB_Forensics_*.{json,csv,md}. Default: cwd.
.PARAMETER InfectionTime   Reference time to correlate against. Devices connected at/before it are
                           flagged as origin candidates.
.PARAMETER PayloadName     One or more payload file names; their earliest Prefetch execution time is
                           used as the reference (overrides -InfectionTime when found).
.PARAMETER SystemHive      OFFLINE: path to an extracted SYSTEM hive (mounted via reg load).
.PARAMETER SoftwareHive    OFFLINE: path to an extracted SOFTWARE hive.
.PARAMETER SetupApiLog     OFFLINE: path to an extracted setupapi.dev.log.

.EXAMPLE
    .\Get-USBDeviceHistory.ps1 -InfectionTime '2026-06-19 14:00'
.EXAMPLE
    .\Get-USBDeviceHistory.ps1 -PayloadName 'evil.exe','dropper.dll'   # auto reference from Prefetch
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDir = (Get-Location).Path,
    [datetime]$InfectionTime,
    [string[]]$PayloadName = @(),
    [string]$SystemHive,
    [string]$SoftwareHive,
    [string]$SetupApiLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$HostName = $env:COMPUTERNAME

# Win8+ device-property GUID holding install/first/last timestamps under each USBSTOR instance.
$PROP_GUID = '{83da6326-97a6-4088-9453-a1923f573b29}'
# 0064 = first install, 0066 = last arrival (connected), 0067 = last removal.
$PROP_FIRST = '0064'; $PROP_ARRIVAL = '0066'; $PROP_REMOVAL = '0067'

# -- pure helpers (unit-tested) -----------------------------------------------
function Convert-FileTimeBytes {
    # REG_BINARY 8-byte little-endian FILETIME -> [datetime] (local), or $null.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 8) { return $null }
    try {
        $ft = [BitConverter]::ToInt64($Bytes, 0)
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTime($ft)
    } catch { return $null }
}

function Get-DeviceSuspicion {
    # Risk note from Vendor/Product/FriendlyName. Generic/no-name mass storage and placeholder
    # descriptors are the classic anonymous malware carriers; flag, never clear.
    param([string]$Vendor, [string]$Product, [string]$FriendlyName)
    $b = "$Vendor $Product $FriendlyName"
    $notes = @()
    if ($b -match '(?i)generic|mass\s*storage|usb\s*(disk|flash|drive)\b|flash\s*disk|removable|\bUFD\b|no[\s-]?name') {
        $notes += 'generic/removable mass-storage (common malware carrier)'
    }
    if ($b -match '(?i)vendorc|productco?de|usb\s*disk|disk\s*usb') {
        $notes += 'placeholder/no-name descriptors (cloned/anonymous device)'
    }
    if ($Vendor -and $Vendor -notmatch '(?i)[a-z]{3,}') {
        $notes += 'no real vendor string'
    }
    return (($notes | Select-Object -Unique) -join '; ')
}

function Convert-SerialKey {
    # Normalise a USBSTOR serial for cross-source matching: drop the '&N' instance suffix and any
    # non-alphanumeric, lowercase. e.g. '0339617030005183&0' -> '0339617030005183'.
    param([string]$Serial)
    return ((("$Serial" -replace '&\d+$','') -replace '[^0-9A-Za-z]','').ToLower())
}

function Find-OriginCandidate {
    # Devices first-connected AT or BEFORE the reference time, earliest first.
    param([object[]]$Devices, [datetime]$InfectionTime)
    if (-not $Devices) { return @() }
    $cand = $Devices | Where-Object {
        $_.FirstConnect -and ($_.FirstConnect -is [datetime]) -and ($_.FirstConnect -le $InfectionTime)
    }
    return @($cand | Sort-Object FirstConnect)
}

function Get-VectorVerdict {
    # Correlate ONE device's first-connect to the reference time (first-execution if known, else the
    # supplied infection time). Before -> entry-vector candidate; after -> introduced post-infection.
    param($FirstConnect, $InfectionTime, $FirstExec)
    if (-not ($FirstConnect -is [datetime])) { return 'UNKNOWN - no connect time captured (cannot place on timeline)' }
    $ref = if ($FirstExec -is [datetime]) { $FirstExec } elseif ($InfectionTime -is [datetime]) { $InfectionTime } else { $null }
    if (-not ($ref -is [datetime])) { return 'NO REFERENCE - pass -InfectionTime and/or -PayloadName to correlate' }
    $deltaH = [math]::Round((New-TimeSpan -Start $FirstConnect -End $ref).TotalHours, 1)
    if ($FirstConnect -le $ref) {
        if ($deltaH -le 24) { return "ENTRY-VECTOR CANDIDATE - connected ${deltaH}h BEFORE the reference time" }
        return "possible (weak) - connected ${deltaH}h before the reference time (large gap)"
    }
    return "LIKELY NOT SOURCE - connected $([math]::Abs($deltaH))h AFTER the reference time (introduced post-infection)"
}

# -- registry root resolution (live or offline hive) --------------------------
$LoadedHives = @()
function Resolve-HiveRoot {
    param([ValidateSet('SYSTEM','SOFTWARE')][string]$Which, [string]$OfflinePath)
    if ($OfflinePath -and (Test-Path -LiteralPath $OfflinePath)) {
        $mount = "IRUSB_$Which"
        try {
            reg load "HKLM\$mount" "$OfflinePath" *>$null
            $script:LoadedHives += $mount
            return "Registry::HKEY_LOCAL_MACHINE\$mount"
        } catch { Write-Warning "Could not load $Which hive: $($_.Exception.Message)"; return $null }
    }
    if ($Which -eq 'SYSTEM') { return 'Registry::HKEY_LOCAL_MACHINE\SYSTEM' }
    return 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE'
}

# -- collectors ---------------------------------------------------------------
function Get-USBStorDevices {
    param([string]$SystemRoot)
    $devices = @()
    # CurrentControlSet on a live host; an offline SYSTEM hive uses ControlSet001.
    $bases = @("$SystemRoot\CurrentControlSet\Enum\USBSTOR", "$SystemRoot\ControlSet001\Enum\USBSTOR")
    foreach ($base in $bases) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($cls in (Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            # class name = Disk&Ven_<v>&Prod_<p>&Rev_<r>
            $ven  = if ($cls.PSChildName -match 'Ven_([^&]+)')  { $Matches[1] } else { '' }
            $prod = if ($cls.PSChildName -match 'Prod_([^&]+)') { $Matches[1] } else { '' }
            foreach ($inst in (Get-ChildItem -LiteralPath $cls.PSPath -ErrorAction SilentlyContinue)) {
                $serial = $inst.PSChildName
                $friendly = (Get-ItemProperty -LiteralPath $inst.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
                $first = $arr = $rem = $null
                $propBase = Join-Path $inst.PSPath "Properties\$PROP_GUID"
                foreach ($p in @{$PROP_FIRST='first';$PROP_ARRIVAL='arr';$PROP_REMOVAL='rem'}.GetEnumerator()) {
                    $pk = Join-Path $propBase $p.Key
                    if (Test-Path -LiteralPath $pk) {
                        $data = $null
                        $regKey = Get-Item -LiteralPath $pk -ErrorAction SilentlyContinue
                        if ($null -ne $regKey) { try { $data = $regKey.GetValue($null) } catch {} }
                        $dt = if ($null -ne $data) { Convert-FileTimeBytes ([byte[]]$data) } else { $null }
                        if ($p.Value -eq 'first') { $first = $dt } elseif ($p.Value -eq 'arr') { $arr = $dt } else { $rem = $dt }
                    }
                }
                $devices += [pscustomobject][ordered]@{
                    Vendor=$ven; Product=$prod; Serial=$serial; FriendlyName=$friendly
                    FirstConnect=$first; LastConnect=$arr; LastRemoved=$rem
                    Suspicion=(Get-DeviceSuspicion -Vendor $ven -Product $prod -FriendlyName $friendly)
                    Source='USBSTOR'
                }
            }
        }
        if (@($devices).Count -gt 0) { break }   # prefer CurrentControlSet if it resolved
    }
    return $devices
}

function Get-USBStorDevicesPnP {
    # LIVE primary: the PnP property cache via Get-PnpDevice / Get-PnpDeviceProperty. This reads the
    # first-install / last-arrival / last-removal dates that the raw registry exposes only behind a
    # SYSTEM ACL ("Requested registry access is not allowed"). Includes historical (not-present)
    # devices, so it covers everything ever connected - not just what is plugged in now.
    $out = @()
    foreach ($d in @(Get-PnpDevice -InstanceId 'USBSTOR*' -ErrorAction SilentlyContinue)) {
        $id = "$($d.InstanceId)"
        $ven  = if ($id -match 'Ven_([^&\\]+)')  { $Matches[1] } else { '' }
        $prod = if ($id -match 'Prod_([^&\\]+)') { $Matches[1] } else { '' }
        $serial = ($id -split '\\')[-1]
        $first = $arr = $rem = $null
        try { $first = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_FirstInstallDate' -ErrorAction Stop).Data } catch {}
        try { $arr   = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LastArrivalDate'  -ErrorAction Stop).Data } catch {}
        try { $rem   = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LastRemovalDate'  -ErrorAction Stop).Data } catch {}
        if (-not ($first -is [datetime])) { $first = $null }
        if (-not ($arr   -is [datetime])) { $arr   = $null }
        if (-not ($rem   -is [datetime])) { $rem   = $null }
        $out += [pscustomobject][ordered]@{
            Vendor=$ven; Product=$prod; Serial=$serial; FriendlyName=$d.FriendlyName
            FirstConnect=$first; LastConnect=$arr; LastRemoved=$rem
            Suspicion=(Get-DeviceSuspicion -Vendor $ven -Product $prod -FriendlyName $d.FriendlyName)
            Source='PnP'
        }
    }
    return $out
}

function Get-PortableDeviceNames {
    param([string]$SoftwareRoot)
    $names = @{}
    $base = "$SoftwareRoot\Microsoft\Windows Portable Devices\Devices"
    if (Test-Path -LiteralPath $base) {
        foreach ($d in (Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $fn = (Get-ItemProperty -LiteralPath $d.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
            if ($d.PSChildName -match '#([0-9A-Za-z&_]+)#') { $names[$Matches[1]] = $fn }
            elseif ($fn) { $names[$d.PSChildName] = $fn }
        }
    }
    return $names
}

function Get-SetupApiUSB {
    param([string]$LogPath)
    $out = @()
    if (-not (Test-Path -LiteralPath $LogPath)) { return $out }
    $lines = @(Get-Content -LiteralPath $LogPath -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(?i)Device Install.*USBSTOR\\(.+)') {
            $dev = $Matches[1].Trim()
            $time = $null
            if ($i + 1 -lt $lines.Count -and $lines[$i+1] -match '(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})') {
                try { $time = [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', $null) } catch {}
            }
            $out += [pscustomobject]@{ Device=$dev; FirstInstall=$time; Source='setupapi.dev.log' }
        }
    }
    return $out
}

function Get-USBConnectTimes {
    # Per-serial first/last connect from the event logs (reliable when USBSTOR property times are
    # blank). Returns: normalisedSerial -> [pscustomobject]@{ First; Last; Count; Source }.
    param([string[]]$Serials)
    $want = @{}; foreach ($s in $Serials) { if ($s) { $want[(Convert-SerialKey $s)] = $true } }
    $times = @{}
    function _bump($key, $when, $src) {
        if (-not $times.ContainsKey($key)) { $times[$key] = [pscustomobject]@{ First=$when; Last=$when; Count=0; Source=$src } }
        if ($when -lt $times[$key].First) { $times[$key].First = $when }
        if ($when -gt $times[$key].Last)  { $times[$key].Last  = $when }
        $times[$key].Count++
    }
    # Partition/Diagnostic 1006 - serial is in EventData
    try {
        foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Partition/Diagnostic'; Id=1006 } -ErrorAction Stop)) {
            $blob = ''
            try { $blob = (([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { "$($_.'#text')" }) -join '' } catch { $blob = $e.Message }
            $nb = (("$blob") -replace '[^0-9A-Za-z]','').ToLower()
            foreach ($k in @($want.Keys)) { if ($k.Length -ge 6 -and $nb.Contains($k)) { _bump $k $e.TimeCreated 'Partition/Diagnostic 1006' } }
        }
    } catch {}
    # DriverFrameworks-UserMode - instance-path based
    try {
        foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Id=2003,2102,2100,2105,2106 } -ErrorAction Stop)) {
            $m = [regex]::Match("$($e.Message)", '(?i)USBSTOR\\[^\s"<\\]+\\([0-9A-Za-z&]+)')
            if ($m.Success) { $k = Convert-SerialKey $m.Groups[1].Value; if ($want.ContainsKey($k)) { _bump $k $e.TimeCreated 'DriverFrameworks' } }
        }
    } catch {}
    return $times
}

function Get-PayloadFirstExec {
    # Earliest execution of the payloads from Prefetch (.pf CreationTime ~ first run). Returns the
    # earliest [datetime], or $null.
    param([string[]]$Names)
    $earliest = $null
    $pfDir = Join-Path $env:WinDir 'Prefetch'
    foreach ($n in $Names) {
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($n)
        if ($stem -and (Test-Path -LiteralPath $pfDir)) {
            foreach ($pf in (Get-ChildItem -LiteralPath $pfDir -Filter "*$stem*.pf" -ErrorAction SilentlyContinue)) {
                if (-not $earliest -or $pf.CreationTime -lt $earliest) { $earliest = $pf.CreationTime }
            }
        }
    }
    return $earliest
}

# -- run ----------------------------------------------------------------------
Write-Host "[*] USB device-history forensics on $HostName ($(if($SystemHive){'OFFLINE'}else{'LIVE'}))" -ForegroundColor Cyan
$sysRoot = Resolve-HiveRoot -Which SYSTEM   -OfflinePath $SystemHive
$swRoot  = Resolve-HiveRoot -Which SOFTWARE -OfflinePath $SoftwareHive

# LIVE: PnP property cache (reliable times); OFFLINE: registry hive read.
$usbstor = if ($SystemHive) { @(Get-USBStorDevices -SystemRoot $sysRoot) } else { @(Get-USBStorDevicesPnP) }
if (@($usbstor).Count -eq 0) { $usbstor = @(Get-USBStorDevices -SystemRoot $sysRoot) }   # fallback
$friendly = Get-PortableDeviceNames -SoftwareRoot $swRoot
foreach ($d in $usbstor) {
    if (-not $d.FriendlyName -and $friendly.ContainsKey($d.Serial)) { $d.FriendlyName = $friendly[$d.Serial] }
}
$setupPath = if ($SetupApiLog) { $SetupApiLog } else { Join-Path $env:WinDir 'INF\setupapi.dev.log' }
$setup   = @(Get-SetupApiUSB -LogPath $setupPath)

# connect times from the event logs (used when the USBSTOR property timestamps come back blank)
$evTimes = if ($SystemHive) { @{} } else { Get-USBConnectTimes -Serials @($usbstor.Serial) }

# reference time: earliest payload execution from Prefetch (when -PayloadName given, live)
$firstExec = $null
if (@($PayloadName).Count -gt 0 -and -not $SystemHive) { $firstExec = Get-PayloadFirstExec -Names @($PayloadName) }

foreach ($d in $usbstor) {
    $k = Convert-SerialKey $d.Serial
    $src = ''
    if ($d.FirstConnect -or $d.LastConnect) { $src = $d.Source }   # 'PnP' (live) or 'USBSTOR' (offline)
    if ((-not $d.FirstConnect) -and $evTimes.ContainsKey($k)) { $d.FirstConnect = $evTimes[$k].First; $src = $evTimes[$k].Source }
    if ((-not $d.LastConnect)  -and $evTimes.ContainsKey($k)) { $d.LastConnect  = $evTimes[$k].Last;  if (-not $src) { $src = $evTimes[$k].Source } }
    if (-not $d.FirstConnect) {
        $m = @($setup | Where-Object { (Convert-SerialKey $_.Device).Contains($k) } | Sort-Object FirstInstall) | Select-Object -First 1
        if ($m) { $d.FirstConnect = $m.FirstInstall; $src = 'setupapi.dev.log' }
    }
    $verdict = Get-VectorVerdict -FirstConnect $d.FirstConnect -InfectionTime $InfectionTime -FirstExec $firstExec
    $d | Add-Member -NotePropertyName ConnectSource -NotePropertyValue $src -Force
    $d | Add-Member -NotePropertyName Verdict -NotePropertyValue $verdict -Force
}

$origin = @()
if ($InfectionTime) { $origin = @(Find-OriginCandidate -Devices $usbstor -InfectionTime $InfectionTime) }

foreach ($m in $LoadedHives) { try { [gc]::Collect(); reg unload "HKLM\$m" *>$null } catch {} }

# -- output -------------------------------------------------------------------
$refTime = if ($firstExec) { "$firstExec (Prefetch first-exec of payload)" } elseif ($InfectionTime) { "$InfectionTime (supplied -InfectionTime)" } else { 'UNKNOWN - pass -InfectionTime and/or -PayloadName' }
$bundle = [ordered]@{
    host=$HostName; generated=(Get-Date).ToString('s'); mode=$(if($SystemHive){'offline'}else{'live'})
    reference_time=$refTime; usb_devices=$usbstor; setupapi_installs=$setup; origin_candidates=$origin
}
$jsonOut = Join-Path $OutputDir "USB_Forensics_${HostName}_$stamp.json"
$csvOut  = Join-Path $OutputDir "USB_Forensics_${HostName}_$stamp.csv"
$mdOut   = Join-Path $OutputDir "USB_Forensics_${HostName}_$stamp.md"
($bundle | ConvertTo-Json -Depth 6) | Out-File -FilePath $jsonOut -Encoding UTF8
$usbstor | Export-Csv -NoTypeInformation -Path $csvOut -Encoding UTF8

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# USB Device History - $HostName"); $md.Add("")
$md.Add("Generated $($bundle.generated) - mode: $($bundle.mode)"); $md.Add("")
$md.Add("## Correlation assessment"); $md.Add("")
$md.Add("Reference time: **$refTime**"); $md.Add("")
foreach ($d in @($usbstor | Sort-Object FirstConnect)) {
    $md.Add("- **$($d.Vendor) $($d.Product)** (serial ``$($d.Serial)``): **$($d.Verdict)**" + $(if($d.Suspicion){" - $($d.Suspicion)"}))
}
$md.Add("")
$md.Add("## Connected USB storage devices ($(@($usbstor).Count))"); $md.Add("")
$md.Add("| Vendor | Product | Serial | FriendlyName | First connect | Last connect | Source | Verdict |")
$md.Add("|---|---|---|---|---|---|---|---|")
foreach ($d in @($usbstor | Sort-Object FirstConnect)) {
    $md.Add("| $($d.Vendor) | $($d.Product) | $($d.Serial) | $($d.FriendlyName) | $($d.FirstConnect) | $($d.LastConnect) | $($d.ConnectSource) | $($d.Verdict) |")
}
$md.Add("")
$md.Add("> A device first-connected BEFORE the reference time is an entry-vector candidate; one connected AFTER was introduced post-infection (not the source). If no device connected before the reference time, the entry vector is likely non-USB (download / fake-update / malvertising). A device with UNKNOWN time had no retained connect record - examine the physical device directly.")
$md -join "`n" | Out-File -FilePath $mdOut -Encoding UTF8
Write-Host "[+] $(@($usbstor).Count) USB device(s); reference time: $refTime" -ForegroundColor Green
Write-Host "[+] $mdOut" -ForegroundColor Green
