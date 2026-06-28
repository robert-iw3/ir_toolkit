<#
.SYNOPSIS
    Definitive adjudication layer for EDR collection results.

.DESCRIPTION
    Wave 1 (EDR_Toolkit) is a wide net - it flags anything that *looks* suspicious.
    This is wave 2: for EVERY base finding it dynamically resolves the concrete
    on-disk / in-registry artifact behind it and gathers hard evidence to decide
    True Positive vs False Positive - it does not guess from names.

    For each finding it:
      1. Extracts pivot indicators (PID, path, hash, IPv4, CLSID, DLL/EXE/SYS
         name, task name) from Target+Details - type-agnostic.
      2. Resolves the SUBJECT artifact:
           - CLSID  -> live InProcServer32/LocalServer32 from the registry
           - PID    -> live process path + command line + parent + owner
           - path / bare name -> on-disk file (System32/SysWOW64 search for bare names)
           - task   -> the action binary
      3. Proves it: SHA256, Authenticode status + signer, file existence,
         version/company, path trust, and (PIDs) live network egress.
      4. Renders a definitive verdict: False Positive / Likely False Positive /
         Likely True Positive / True Positive / Indeterminate.

    Offline forensic CSVs (forensics-*.zip) are also loaded so context survives
    even for processes that have since exited. Run WITHOUT -Live to adjudicate a
    folder copied off-box (best-effort, no live signatures); run WITH -Live on the
    source host for signature-grade proof. Invoke-IRCollection runs it with -Live.

.PARAMETER HostFolder   The per-host collection folder (e.g. .\<HOSTNAME>). Default: cwd.
.PARAMETER ReportPath   Explicit EDR_Report_*.json. Default: newest in HostFolder.
.PARAMETER Live         Gather live evidence (signatures, registry, command lines).

.EXAMPLE
    .\Get-FindingContext.ps1 -HostFolder .\<HOSTNAME> -Live
#>

[CmdletBinding()]
param(
    [string]$HostFolder = (Get-Location).Path,
    [string]$ReportPath,
    [switch]$Live,
    [switch]$NoEvidence,                       # skip the Evidence\ bundle
    [long]$MaxEvidenceBytes = 104857600        # 100 MB per-file copy cap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Locate inputs -------------------------------------------------------------
if (-not (Test-Path -LiteralPath $HostFolder)) { throw "HostFolder not found: $HostFolder" }
if (-not $ReportPath) {
    $ReportPath = Get-ChildItem -Path $HostFolder -Filter 'EDR_Report_*.json' -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $ReportPath -or -not (Test-Path -LiteralPath $ReportPath)) {
    throw "No EDR_Report_*.json found in $HostFolder (pass -ReportPath)."
}
$findings = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
if ($findings -isnot [System.Array]) { $findings = @($findings) }
Write-Host "[*] Adjudicating $($findings.Count) base finding(s) from $(Split-Path -Leaf $ReportPath)" -ForegroundColor Cyan
if (-not $Live) { Write-Host "[!] -Live not set: signatures/registry not available; verdicts capped at 'Likely'." -ForegroundColor Yellow }

# -- Load collected forensic CSVs (for exited-process / network context) -------
$Data = @{}
$zip  = Get-ChildItem -Path $HostFolder -Filter 'forensics-*.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
$rawDir = $null
$cleanupRawDir = $false
if ($zip) {
    $rawDir = Join-Path ([System.IO.Path]::GetTempPath()) ("fctx_" + [guid]::NewGuid().ToString('N'))
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $rawDir -Force
    $cleanupRawDir = $true
} else {
    # Unzipped forensics folder (present when collection ran without zip bundling)
    $forensicsDir = Get-ChildItem -Path $HostFolder -Filter 'forensics-*' -Directory -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($forensicsDir) { $rawDir = $forensicsDir.FullName }
}
if ($rawDir) {
    $csvRoot = Get-ChildItem -Path $rawDir -Directory | Select-Object -First 1
    if (-not $csvRoot) { $csvRoot = Get-Item $rawDir }
    foreach ($csv in Get-ChildItem -Path $csvRoot.FullName -Filter '*.csv' -File) {
        try { $Data[$csv.BaseName] = @(Import-Csv -LiteralPath $csv.FullName) } catch {}
    }
}
function New-Index { param($Rows,$Key) $h=@{}; foreach($r in $Rows){ $k="$($r.$Key)"; if($k){ if(-not $h.ContainsKey($k)){$h[$k]=@()}; $h[$k]+=$r } }; return $h }
$ProcById  = if ($Data.ContainsKey('processes'))       { New-Index $Data['processes'] 'Id' }            else { @{} }
$script:HashByPid = if ($Data.ContainsKey('process_hashes'))  { New-Index $Data['process_hashes'] 'Pid' }      else { @{} }
# HashByPid is reserved for hash-correlation enrichment in a future adjudicator pass.
$TcpByPid  = if ($Data.ContainsKey('tcp_connections')) { New-Index $Data['tcp_connections'] 'OwningProcess' } else { @{} }
$UdpByPid  = if ($Data.ContainsKey('udp_endpoints'))   { New-Index $Data['udp_endpoints'] 'OwningProcess' }   else { @{} }
$TaskByName= if ($Data.ContainsKey('scheduled_tasks')) { New-Index $Data['scheduled_tasks'] 'TaskName' }      else { @{} }

# -- Generic helpers -----------------------------------------------------------
function Get-PathTrust { param([string]$p)
    if (-not $p) { return 'Unknown' }
    $l = $p.ToLower()
    foreach ($t in '\windows\system32\','\windows\syswow64\','\windows\winsxs\','\windows\microsoft.net\',
                   '\program files\','\program files (x86)\','driverstore\filerepository','\windows\servicing\') {
        if ($l.Contains($t)) { return 'Trusted-Location' } }
    foreach ($u in '\appdata\','\users\public\','\programdata\','\temp\','\downloads\','\windows\temp\',
                   '\$recycle.bin\','\perflogs\','\desktop\','\users\') {
        if ($l.Contains($u)) { return 'User-Writable' } }
    return 'Other'
}
function Test-PublicIP { param([string]$ip)
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $o = $ip.Split('.') | ForEach-Object { [int]$_ }
    if ($ip -like '127.*' -or $ip -eq '0.0.0.0' -or $ip -like '169.254.*' -or $ip -like '224.*' -or $ip -like '255.*') { return $false }
    if ($o[0] -eq 10) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    return $true
}
function Get-Indicators { param([string]$Text)
    $i = @{ Pid=@(); Path=@(); FileName=@(); Sha256=@(); Ipv4=@(); Clsid=@(); Task=@() }
    if (-not $Text) { return $i }
    foreach ($m in [regex]::Matches($Text,'(?i)\bPID[:\s]+(\d{1,6})\b'))               { $i.Pid += $m.Groups[1].Value }
    foreach ($m in [regex]::Matches($Text,'(?i)(?:[a-z]:|%[^%]+%)\\[^"|<>\r\n]+?\.[a-z0-9]{1,5}')) { $i.Path += $m.Value.Trim() }
    foreach ($m in [regex]::Matches($Text,'(?i)\b[\w.\-]+\.(?:dll|exe|sys|cmd|bat|ps1|scr|vbs|js)\b')) { $i.FileName += $m.Value }
    foreach ($m in [regex]::Matches($Text,'\b[0-9a-fA-F]{64}\b'))                      { $i.Sha256 += $m.Value }
    # Reject dotted-quads embedded in a path or version token (e.g. ...\3.0.0.18\...):
    # negative lookarounds drop matches preceded/followed by a backslash, digit, or dot
    # so only standalone IPs (in command lines / network details) are treated as real.
    foreach ($m in [regex]::Matches($Text,'(?<![\d.\\])\d{1,3}(?:\.\d{1,3}){3}(?![\d.\\])')) { $i.Ipv4 += $m.Value }
    foreach ($m in [regex]::Matches($Text,'\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}')) { $i.Clsid += $m.Value }
    if ($Text -match '(?i)Task:\s*([^|]+?)\s*(?:\||$)') { $i.Task += $Matches[1].Trim() }
    foreach ($k in @($i.Keys)) { $i[$k] = @($i[$k] | Select-Object -Unique) }
    return $i
}

# -- LIVE resolvers ------------------------------------------------------------
function Resolve-ComServer { param([string]$Clsid)
    if (-not $Live) { return $null }
    foreach ($base in 'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID','HKCU:\SOFTWARE\Classes\CLSID') {
        foreach ($srv in 'InprocServer32','LocalServer32','InprocHandler32') {
            $key = "$base\$Clsid\$srv"
            if (Test-Path -LiteralPath $key) {
                $v = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).'(default)'
                if ($v) { return [Environment]::ExpandEnvironmentVariables("$v") }
            }
        }
    }
    return $null
}
# Take a raw command/path string -> the executable/dll path it points at
function Get-BinaryFromCommand { param([string]$s)
    if (-not $s) { return $null }
    $s = [Environment]::ExpandEnvironmentVariables($s)
    $m = [regex]::Match($s,'(?i)"?([a-z]:\\[^"]+?\.(?:dll|exe|sys|cmd|bat|ps1|scr|vbs|js))"?')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}
# Definitive file proof
function Resolve-File { param([string]$Path)
    $r = [ordered]@{ Path=$Path; Exists=$null; Sha256=$null; SigStatus=$null; Signer=$null; Company=$null; Trust='Unknown' }
    if (-not $Path) { return $r }
    $Path = [Environment]::ExpandEnvironmentVariables($Path)
    if ($Live -and ($Path -notmatch '[\\/]')) {   # bare DLL/exe name -> resolve via system dirs
        foreach ($d in "$env:SystemRoot\System32","$env:SystemRoot\SysWOW64") {
            $c = Join-Path $d $Path; if (Test-Path -LiteralPath $c) { $Path = $c; break }
        }
    }
    $r.Path = $Path
    $r.Trust = Get-PathTrust $Path
    if ($Live) {
        $exists = Test-Path -LiteralPath $Path -PathType Leaf
        $r.Exists = $exists
        if ($exists) {
            try { $r.Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch {}
            try { $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
                  $r.SigStatus = "$($s.Status)"; $r.Signer = "$($s.SignerCertificate.Subject)" } catch {}
            try { $r.Company = (Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).VersionInfo.CompanyName } catch {}
        }
    }
    return $r
}

# -- Evidence bundle: preserve everything needed to investigate a finding ------
function New-FindingEvidence {
    param($Finding,[int]$Index,[string]$Verdict,[string]$Confidence,$File,$Indicators,$ProcIds,[string]$CommandLine)
    if ($NoEvidence) { return $null }
    if ($Verdict -in 'False Positive','Likely False Positive') { return $null }   # cleared; no need to acquire
    $safe = ($Finding.Target -replace '[^\w.\-]','_'); if ($safe.Length -gt 40) { $safe = $safe.Substring(0,40) }
    $evDir = Join-Path $EvidenceRoot ("{0:D3}_{1}_{2}" -f $Index, ($Finding.Type -replace '\W','_'), $safe)
    New-Item -ItemType Directory -Path $evDir -Force | Out-Null

    $ev = [ordered]@{
        type=$Finding.Type; target=$Finding.Target; details=$Finding.Details; mitre=$Finding.MITRE
        verdict=$Verdict; confidence=$Confidence; subject=$File.Path
        collected_utc=(Get-Date).ToUniversalTime().ToString('o'); host=$env:COMPUTERNAME
    }
    # Subject file: deep metadata + raw byte copy (read-only, never executed)
    if ($Live -and $File.Exists) {
        try {
            $it = Get-Item -LiteralPath $File.Path -Force -ErrorAction Stop
            $ev.size=$it.Length
            $ev.created_utc ="$($it.CreationTimeUtc.ToString('o'))"
            $ev.modified_utc="$($it.LastWriteTimeUtc.ToString('o'))"
            $ev.accessed_utc="$($it.LastAccessTimeUtc.ToString('o'))"
            $ev.md5   =(Get-FileHash -LiteralPath $File.Path -Algorithm MD5    -ErrorAction SilentlyContinue).Hash
            $ev.sha1  =(Get-FileHash -LiteralPath $File.Path -Algorithm SHA1   -ErrorAction SilentlyContinue).Hash
            $ev.sha256=$File.Sha256
            $ev.signature=$File.SigStatus; $ev.signer=$File.Signer
            $vi=$it.VersionInfo
            $ev.file_version="$($vi.FileVersion)"; $ev.product="$($vi.ProductName)"; $ev.original_name="$($vi.OriginalFilename)"
            if ($it.Length -le $MaxEvidenceBytes) {
                $dest = Join-Path $evDir ("subject_" + $it.Name)
                Copy-Item -LiteralPath $File.Path -Destination $dest -Force
                try { (Get-Item -LiteralPath $dest).IsReadOnly = $true } catch {}
                $ev.copied = $dest
            } else { $ev.copied = "skipped (> $MaxEvidenceBytes bytes)" }
        } catch { $ev.file_error = "$_" }
    }
    if ($CommandLine) { $ev.command_line = $CommandLine }
    # PID context: loaded modules (DLLs in the address space)
    foreach ($pidVal in $ProcIds) {
        if (-not $Live) { break }
        try {
            $mods = Get-Process -Id ([int]$pidVal) -Module -ErrorAction SilentlyContinue |
                Select-Object ModuleName, FileName, @{N='Version';E={$_.FileVersionInfo.FileVersion}}
            if ($mods) { $mods | Export-Csv -LiteralPath (Join-Path $evDir "pid_${pidVal}_modules.csv") -NoTypeInformation }
        } catch {}
    }
    # Scheduled task: full XML definition
    foreach ($tn in $Indicators.Task) {
        if ($Live -and $TaskByName.ContainsKey($tn)) {
            try {
                $xml = Export-ScheduledTask -TaskName $tn -TaskPath $TaskByName[$tn][0].TaskPath -ErrorAction SilentlyContinue
                if ($xml) { $xml | Set-Content -LiteralPath (Join-Path $evDir 'task.xml') -Encoding UTF8 }
            } catch {}
        }
    }
    # COM CLSID: registry key export (proves what InProcServer32 really points at)
    foreach ($cl in $Indicators.Clsid) {
        if (-not $Live) { break }
        foreach ($base in 'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID','HKCU:\SOFTWARE\Classes\CLSID') {
            $k = "$base\$cl"
            if (Test-Path -LiteralPath $k) {
                try {
                    Get-ChildItem -LiteralPath $k -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        "$($_.PSPath)"; (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue | Out-String)
                    } | Set-Content -LiteralPath (Join-Path $evDir 'clsid_registry.txt') -Encoding UTF8
                } catch {}
                break
            }
        }
    }
    $ev | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evDir 'evidence.json') -Encoding UTF8
    return $evDir
}

# -- Adjudicate each finding ---------------------------------------------------
$EvidenceRoot = Join-Path $HostFolder 'Evidence'
$rownum = 0
$results = foreach ($f in $findings) {
    $rownum++
    $text = "$($f.Target) $($f.Details)"
    $ind  = Get-Indicators $text
    $notes  = [System.Collections.Generic.List[string]]::new()
    $pivots = [System.Collections.Generic.List[string]]::new()
    $subjectPath=$null; $cmdLine=$null; $owner=$null
    $parentPid=$null; $parentName=$null; $startTime=$null
    $net=[System.Collections.Generic.List[string]]::new(); $publicNet=$false

    # ----- choose + resolve the SUBJECT artifact -----
    # 1) CLSID -> authoritative COM server path (live registry)
    foreach ($c in $ind.Clsid) {
        $sp = Resolve-ComServer $c
        if ($sp) { $subjectPath = (Get-BinaryFromCommand $sp); if (-not $subjectPath) { $subjectPath = $sp }
                   $pivots.Add("CLSID $c -> $subjectPath"); break }
    }
    # 2) PID -> live process, else collected processes.csv
    foreach ($pidVal in $ind.Pid) {
        if ($Live) {
            $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$pidVal" -ErrorAction SilentlyContinue
            if ($wp) {
                if (-not $subjectPath) { $subjectPath = $wp.ExecutablePath }
                $cmdLine = $wp.CommandLine; $parentPid = "$($wp.ParentProcessId)"
                try { $owner = ($wp | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue) } catch {}
                if ($owner) { $owner = "$($owner.Domain)\$($owner.User)" }
                $pivots.Add("live PID $pidVal -> $($wp.Name)")
            }
        }
        if ($ProcById.ContainsKey($pidVal)) {
            $p = $ProcById[$pidVal][0]
            if (-not $subjectPath) { $subjectPath = $p.Path }
            if (-not $parentPid) { $parentPid = $p.ParentPid }
            $startTime = $p.StartTime; $pivots.Add("collected PID $pidVal -> $($p.Name)")
        }
        if ($parentPid -and $ProcById.ContainsKey($parentPid)) { $parentName = $ProcById[$parentPid][0].Name }
        foreach ($cn in @($TcpByPid[$pidVal]) + @($UdpByPid[$pidVal])) {
            if (-not $cn) { continue }
            # UDP endpoints have no RemoteAddress/RemotePort/State; guard for StrictMode.
            $ra = if ($cn.PSObject.Properties['RemoteAddress']) { $cn.RemoteAddress } else { $null }
            if ($ra) {
                $rp = if ($cn.PSObject.Properties['RemotePort']) { $cn.RemotePort } else { '' }
                $st = if ($cn.PSObject.Properties['State'])      { $cn.State }      else { 'UDP' }
                $net.Add("${ra}:${rp} $st")
                if (Test-PublicIP $ra) { $publicNet = $true }
            }
        }
    }
    # 3) Scheduled task -> action binary
    foreach ($tn in $ind.Task) {
        if ($TaskByName.ContainsKey($tn)) {
            $t = $TaskByName[$tn][0]; $notes.Add("task action: $($t.Actions) (author $($t.Author))")
            if (-not $subjectPath) { $subjectPath = Get-BinaryFromCommand $t.Actions }
            $pivots.Add("task $tn resolved")
        }
    }
    # 4) explicit path / bare filename from the finding text
    if (-not $subjectPath -and $ind.Path.Count)     { $subjectPath = $ind.Path[0] }
    if (-not $subjectPath -and $ind.FileName.Count) { $subjectPath = $ind.FileName[0] }

    # ----- prove the subject -----
    $file = Resolve-File $subjectPath
    if ($ind.Sha256.Count -and -not $file.Sha256) { $file.Sha256 = $ind.Sha256[0] }
    foreach ($ip in $ind.Ipv4) { if (Test-PublicIP $ip) { $publicNet = $true } }

    # ----- IR Toolkit self-recognition (impossible attack vector) ----------------
    # The responder's own staged tools (yara64, autorunsc, winpmem, procdump, ...) run
    # during collection and surface in ShimCache/Amcache/entropy scans on EVERY host.
    # A binary inside an IR_Toolkit\tools\ folder is our own kit - clear it outright.
    $leaf = if ($subjectPath) { Split-Path -Leaf $subjectPath } else { '' }
    $ownToolName = '(?i)^(autorunsc(64)?|yarac?64|yara|go-winpmem|winpmem|procdump(64)?|sigcheck(64)?|handle(64)?|strings(64)?|listdlls(64)?|tcpvcon(64)?|pslist(64)?|psservice(64)?|psloggedon(64)?|ftkimager|vol|memprocfs|sqlite3|MRC.*)\.exe$'
    $isOwnTool = ($subjectPath -match '(?i)\\IR[_-]?Toolkit\\tools\\') -or `
                 ($leaf -match $ownToolName -and $subjectPath -match '(?i)\\tools\\')

    # ----- definitive verdict from proof -----
    $valid    = ($file.SigStatus -eq 'Valid')
    # A "bad signature" is a genuinely INVALID one (tampered/revoked/untrusted) - a
    # strong malicious signal. 'NotSigned' is NOT bad: countless legit tools (sqlite3,
    # utilities, vendor helpers) ship unsigned, so it is only a weak/neutral signal.
    $badSig   = ($file.SigStatus -and $file.SigStatus -notin @('Valid','UnknownError','NotSigned'))
    $trusted  = ($file.Trust -eq 'Trusted-Location')
    $writable = ($file.Trust -eq 'User-Writable')
    $hasAbsPath = ($subjectPath -match '^[A-Za-z]:\\|^\\')
    $missing  = ($Live -and $file.Exists -eq $false -and $subjectPath -and $hasAbsPath)
    $hasCo    = [bool]$file.Company

    $verdict='Indeterminate'; $conf='Low'
    $yaraMemEarlyExit = $false
    $isYaraMemType = ($f.Type -in @('YARA Match (Memory)', 'Injected Code (memory YARA)'))
    if ($isYaraMemType) {
        if ($f.Details -match 'file-backed') {
            $verdict = 'Indeterminate'; $conf = 'Low'
            $notes.Add('YARA hit on file-backed mapped DLL -- fires on any process loading this library; not injection evidence into anonymous/injected memory')
            $yaraMemEarlyExit = $true
        } elseif ($f.Details -match '\banon\b' -and $f.Details -notmatch '\banon\s+\S*[Xx]') {
            $verdict = 'Indeterminate'; $conf = 'Low'
            $notes.Add('YARA hit on non-executable anonymous memory (heap or data) -- strings matched in process heap/data; not executable code injection evidence')
            $yaraMemEarlyExit = $true
        }
    }
    if (-not $yaraMemEarlyExit) {
    if ($Live -and $file.Exists) {
        # False Positive requires: valid signature AND trusted location AND no external network activity.
        # A binary that is validly signed, in a trusted path, but making public internet connections
        # cannot be cleared -- stolen/compromised certs (3CX, SolarWinds) pass the first two checks
        # while actively beaconing C2.
        if ($valid -and $trusted -and -not $publicNet) { $verdict='False Positive';        $conf='High' }
        elseif ($valid -and $trusted)    { $verdict='Likely False Positive'; $conf='Medium'; $notes.Add('valid cert and trusted path but public network activity observed -- stolen or compromised cert cannot be ruled out (3CX/SolarWinds-style supply chain)') }
        elseif ($valid -and $writable)   { $verdict='Indeterminate';         $conf='Medium'; $notes.Add('signed but in user-writable path - valid cert does not clear staging in Temp/AppData') }
        elseif ($valid)                  { $verdict='Likely False Positive'; $conf='Medium' }
        elseif ($badSig -and ($writable -or $publicNet)) { $verdict='True Positive'; $conf='High' }
        elseif ($badSig)                 { $verdict='Likely True Positive';  $conf='Medium' }
        else                             { $verdict='Likely True Positive';  $conf='Low' }
    }
    elseif ($missing)                    { $verdict='Likely True Positive';  $conf='Medium'; $notes.Add('referenced binary not on disk (staged/removed?)') }
    else {
        # No live proof - fall back to collected context (capped at "Likely").
        # Trusted-location + company name = Likely FP only; writable path stays Indeterminate.
        if ($trusted -and $hasCo)        { $verdict='Likely False Positive'; $conf='Medium' }
        elseif ($trusted)                { $verdict='Likely False Positive'; $conf='Low' }
        elseif ($writable -or $publicNet){ $verdict='Likely True Positive';  $conf='Medium' }
    }
    } # end if (-not $yaraMemEarlyExit)
    if ($publicNet) { $notes.Add('external network egress observed') }
    if ($net.Count) { $notes.Add('net: ' + ($net -join '; ')) }
    if (-not $pivots.Count) { $notes.Add('no artifact resolved from this finding') }

    # ----- path-confidence adjustment for known high-FP library paths --------
    # Security sensor tools (C2Sensor, DeepSensor, etc.) ship .NET assemblies with
    # build-pipeline timestamps, causing Timestomped findings at High confidence.
    # These paths are legitimately timestomped - reduce to Low so they don't inflate TP count.
    $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
    if ($f.Type -eq 'Timestomped File' -and $f.Target -match $LIB_NET_PATTERN) {
        if ($conf -ne 'Low') {
            $conf = 'Low'
            $notes.Add('ADJUSTED: Timestomped .NET library assembly path - build-pipeline timestamps are expected here; verify if path is unexpected')
        }
    }

    # ----- MSIX/WindowsApps: per-file Authenticode is not meaningful -------
    # OS validates MSIX package integrity at the package level during install.
    # Individual DLLs inside WindowsApps/SystemApps return NotSigned per-file by design.
    # unsigned-per-file is expected and not injection evidence in this path class.
    if ($f.Type -eq 'Suspicious Injected DLL' -and $f.Details -match 'MSIX/Store package-signed path') {
        if ($verdict -notin @('False Positive','Likely False Positive')) {
            $verdict = 'Likely False Positive'; $conf = 'Medium'
            $notes.Add('ADJUSTED: DLL in MSIX/Store package path -- OS validates package signature at install, not per-file Authenticode; unsigned-per-file is expected and not injection evidence in this path class. WindowsApps and SystemApps DLLs are package-signed.')
        }
    }

    # ----- override: a valid signature does NOT clear remote-access tooling or
    # LOLBins. These are the abuse vectors (T1219 / T1218) and are signed by design.
    $subjName = if ($subjectPath) { Split-Path -Leaf $subjectPath } else { '' }
    $rmmPat   = '(?i)(anydesk|teamviewer|screenconnect|connectwise|splashtop|rustdesk|client32|ateraagent|action1|logmein|lmiguardian|gotoassist|zohoassist|za_connect|winvnc|tvnserver|vncserver|uvnc|remoting_host|dwagent|supremo|meshagent|quickassist)'
    $lolPat   = '(?i)^(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|installutil|msbuild)\.exe$'
    # JIT-host processes: JVM, V8, .NET, Electron, and IDE runtimes generate private
    # executable regions and unbacked threads as a normal consequence of JIT compilation.
    # A Shellcode Thread or Injected Memory Region finding against one of these is a
    # strong FP candidate unless corroborated by other evidence (see cross-finding pass).
    $JitHostPattern = '(?i)\b(acrobatnotific|acrobatnotif|acrocef|acrord32|acrobat|msedgewebview2|msedge|chromium|chrome|firefox|brave|opera|vivaldi|webview2|smartscreen|java|javaw|javaws|node|electron|code|rider|idea|pycharm|clion|goland|webstorm|phpstorm|datagrip|rubymine|pwsh|dotnet)(\.exe)?(?=\W|$)'
    $isJitType  = ($f.Type -match '(?i)Shellcode Thread|Injected Memory Region')
    $isJitHost  = ($subjName -match $JitHostPattern) -or
                  (("$($f.Target) $($f.Details)") -match $JitHostPattern)
    $isRmmType = ($f.Type -match '(?i)Remote Access|ClickFix|RunMRU|LOLBin')
    # Script hosts (powershell/pwsh/cmd) run constantly for legit reasons (VS Code,
    # automation, the toolkit itself). They are abuse ONLY when the command line shows
    # it - encoded/hidden/download/base64/etc. Without that, a bare shell is not proof.
    # Detect a script host from the resolved binary OR the finding text (the binary is
    # often unresolved for historical/exited shells, leaving subjName empty).
    $shellHost = ($subjName -match '(?i)^(powershell|pwsh|cmd)\.exe$') -or
                 (("$($f.Target) $($f.Details)") -match '(?i)\b(powershell|pwsh|cmd)\.exe\b')
    # Genuine abuse indicators only. Deliberately NOT matching bare 'http://' or 'hidden'
    # (they appear in legit banners/paths) - require a real download cradle / encoding /
    # explicit hidden-window switch.
    $abusePat  = '(?i)(-enc\b|encodedcommand|\bIEX\b|Invoke-Expression|Download(String|File|Data)|FromBase64String|Net\.WebClient|Start-BitsTransfer|-w(indowstyle)?\s+hidden|\bbitsadmin\b|\bcertutil\b)'
    $lolAbuse  = (("$($f.Details) $cmdLine") -match $abusePat)
    if ($isRmmType -or ($subjName -match $rmmPat) -or ($subjName -match $lolPat)) {
        if ($shellHost -and -not $lolAbuse) {
            # Normal interactive/automation shell - do not elevate; cap if something
            # else raised it. Stays a pivot lead (review the command line if unexpected).
            if ($verdict -in 'Likely True Positive','True Positive') {
                $verdict = 'Indeterminate'; $conf = 'Low'
                $notes.Add('CAPPED: script-host (powershell/cmd) with no abuse indicators in command line - normal shell, pivot lead only')
            }
        }
        elseif ($verdict -in 'False Positive','Likely False Positive','Indeterminate') {
            $verdict = 'Likely True Positive'
            if ($conf -eq 'Low') { $conf = 'Medium' }
            $notes.Add('OVERRIDE: remote-access/LOLBin abuse class - signature does not clear it; verify connection logs / command line (T1219/T1218)')
        }
    }

    # ----- JIT-host annotation (no verdict change) --------------------------------
    # Chrome, Edge, Acrobat, JVM, Electron and similar runtimes produce legitimate
    # anonymous executable pages from JIT compilation -- this is also the reason
    # attackers inject into them (T1055): many tools exempt these processes. The
    # toolkit never downgrades findings based on process identity. The annotation
    # below surfaces the JIT context for the analyst without suppressing the signal;
    # named-malware YARA corroboration (cross-finding pass) will escalate to TP.
    if ($isJitType -and $isJitHost) {
        $notes.Add('JIT-host process -- legitimate JIT code produces anonymous executable regions; attackers inject here specifically because tools exempt these binaries (T1055); verify thread/region address against JIT heap range and corroborate with YARA or hook evidence before dismissing')
    }

    # ----- clearance: IR Toolkit's own staged tools are known-good ---------------
    # Authoritative - overrides everything above (it is literally our kit, not an
    # attack artifact). Generalizes to any host this toolkit is run from.
    if ($isOwnTool) {
        $verdict = 'False Positive'; $conf = 'High'
        $notes.Add("CLEARED: IR Toolkit's own staged tool (executed during collection) - not an attack artifact")
    }

    # ----- weak-standalone-signal cap -------------------------------------------
    # ShimCache/Amcache are HISTORICAL execution records and high entropy is a
    # by-design property of countless legit files (installers, compiled DLLs,
    # compressed assets). On their own these are PIVOT LEADS, not proof. Unless a
    # strong signal already corroborated them (bad signature, external egress, or
    # the RMM/LOLBin override), cap at Indeterminate so the final report holds only
    # beyond-doubt anomalies. They remain in the full adjudication output + the
    # separate pivot-leads log - nothing is dropped, investigations are not blinded.
    # A real UNC network-path execution stays strong; a \\?\ or \\.\ device-path form
    # is a LOCAL path mislabeled as network (older collections), so treat it as weak.
    $fakeNetPath = ($f.Target -match '^\\\\[?.]\\')
    $weakType  = ($f.Type -match '(?i)^(High Entropy File|ShimCache|Amcache|Timestomped)') -and
                 (($f.Type -notmatch '(?i)Network Path') -or $fakeNetPath)
    $hasStrong = $badSig -or $publicNet -or (($notes -join ' ') -match 'OVERRIDE')
    if ($weakType -and -not $hasStrong -and $verdict -eq 'Likely True Positive') {
        $verdict = 'Indeterminate'
        $conf    = if ($conf -eq 'High') { 'Medium' } else { 'Low' }
        $notes.Add('CAPPED: weak standalone signal (historical execution / entropy) with no corroboration - pivot lead, review only if path is unexpected')
    }

    # ----- acquire evidence for anything not cleared as a false positive -----
    $evDir = New-FindingEvidence -Finding $f -Index $rownum -Verdict $verdict -Confidence $conf `
                -File $file -Indicators $ind -ProcIds $ind.Pid -CommandLine $cmdLine
    if ($evDir) { $notes.Add("evidence: Evidence\$(Split-Path -Leaf $evDir)") }

    [PSCustomObject][ordered]@{
        Verdict     = $verdict
        Confidence  = $conf
        Type        = $f.Type
        Target      = $f.Target
        Details     = $f.Details
        MITRE       = $f.MITRE
        SubjectPath = $file.Path
        FileExists  = $file.Exists
        SigStatus   = $file.SigStatus
        Signer      = $file.Signer
        Company     = $file.Company
        PathTrust   = $file.Trust
        SHA256      = $file.Sha256
        CommandLine = $cmdLine
        Owner       = $owner
        ParentPid   = $parentPid
        ParentName  = $parentName
        StartTime   = $startTime
        Network     = ($net -join '; ')
        PublicEgress= $publicNet
        EvidenceDir = $evDir
        Pivots      = ($pivots | Select-Object -Unique) -join '; '
        Notes       = ($notes -join '; ')
    }
}

# ==============================================================================
# Cross-finding correlation pass (runs AFTER the per-finding loop)
# Escalates "Shellcode Thread" / "Injected Memory Region" findings that were
# left as Indeterminate when the same PID also has hard evidence (hook / PE /
# YARA hit). This implements TTP-001's planned corroboration path.
# ==============================================================================
$pidPidRe = [regex]'(?:PID[:\s]+)(\d+)'

# Index all results by every PID they reference
$byPid = @{}
foreach ($r in $results) {
    $searchText = "$($r.Target) $($r.Details)"
    foreach ($m in $pidPidRe.Matches($searchText)) {
        $k = $m.Groups[1].Value
        if (-not $byPid.ContainsKey($k)) { $byPid[$k] = [System.Collections.Generic.List[object]]::new() }
        $byPid[$k].Add($r)
    }
}

$softTypes = @('Shellcode Thread (Memory)', 'Injected Memory Region')
$hardTypes = @('Inline API Hook (Memory)', 'Manually-Mapped PE (Memory)', 'YARA Match', 'YARA Match (Memory)',
               'Injected Code (memory YARA)', 'Module Stomping Indicator (Memory)')

# Cross-finding corroboration: only YARA hits against anonymous or injected memory count
# as hard evidence. Hits on file-backed mapped DLLs (e.g., SHLWAPI.dll, CRYPT32.dll)
# fire on any process that loads those libraries -- they cannot distinguish code injection
# from normal Windows execution, regardless of which process is involved.
foreach ($pidKey in $byPid.Keys) {
    $group = $byPid[$pidKey]
    $hasSoft = $group | Where-Object { $_.Type -in $softTypes }
    $hasHard = $group | Where-Object { $_.Type -in $hardTypes }
    if (-not $hasSoft -or -not $hasHard) { continue }

    $yaraTypes = 'YARA Match','YARA Match (Memory)','Injected Code (memory YARA)'
    $effectiveHard = @($hasHard | Where-Object {
        if ($_.Type -notin $yaraTypes) { return $true }
        $_.Details -notmatch 'file-backed'
    })
    if (-not $effectiveHard) { continue }

    foreach ($r in $hasSoft) {
        if ($r.Verdict -ne 'Indeterminate') { continue }
        $r.Verdict    = 'True Positive'
        $r.Confidence = 'High'
        $hardEvidence = ($effectiveHard | Select-Object -ExpandProperty Type | Select-Object -Unique) -join ', '
        $corrobNote   = "CORROBORATED: hard evidence ($hardEvidence) in anonymous/injected memory for same PID - confidence escalated to High"
        if ($r.Notes) { $r.Notes = "$($r.Notes); $corrobNote" } else { $r.Notes = $corrobNote }
    }
}

# -- Outputs into the host folder ----------------------------------------------
$order   = @{ 'True Positive'=0; 'Likely True Positive'=1; 'Indeterminate'=2; 'Likely False Positive'=3; 'False Positive'=4 }
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonOut = Join-Path $HostFolder "Adjudication_$stamp.json"
$csvOut  = Join-Path $HostFolder "Adjudication_$stamp.csv"
$mdOut   = Join-Path $HostFolder "Adjudication_$stamp.md"
# Full record: every finding with its verdict (complete, nothing dropped).
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonOut -Encoding UTF8
$results | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8

# Split: beyond-doubt anomalies vs. lower-confidence pivot leads. The final .md
# report (and the incident report / attack graph downstream) hold only the former;
# the leads are written to their OWN log so the investigation is never blinded.
$TpClass  = @('True Positive','Likely True Positive')
$leads    = @($results | Where-Object { $_.Verdict -notin $TpClass })
$leadsOut = Join-Path $HostFolder "Adjudication_PivotLeads_$stamp.csv"
if ($leads.Count) {
    $leads | Sort-Object @{E={$order[$_.Verdict]}}, Type |
        Export-Csv -LiteralPath $leadsOut -NoTypeInformation -Encoding UTF8
}

# -- Run-to-run delta ----------------------------------------------------------
# Compare current findings against the most recent PREVIOUS Adjudication JSON.
# Identifies: NEW (first seen), RESOLVED (gone), CHANGED_VERDICT (verdict flipped).
# Analysts use this to track remediation progress across repeated collections.
$prevAdjFile = Get-ChildItem -Path $HostFolder -Filter 'Adjudication_*.json' -File `
    -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $jsonOut } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($prevAdjFile) {
    try {
        $prevFindings = Get-Content -LiteralPath $prevAdjFile.FullName -Raw | ConvertFrom-Json

        # Build lookup: (Type+Target) -> verdict
        $prevIndex = @{}
        foreach ($pf in @($prevFindings)) { $prevIndex["$($pf.Type)|$($pf.Target)"] = $pf.Verdict }
        $currIndex = @{}
        foreach ($cf in $results) { $currIndex["$($cf.Type)|$($cf.Target)"] = $cf.Verdict }

        $delta = [System.Collections.Generic.List[object]]::new()
        # New findings
        foreach ($cf in $results) {
            $k = "$($cf.Type)|$($cf.Target)"
            $status = if (-not $prevIndex.ContainsKey($k)) { 'NEW' }
                      elseif ($prevIndex[$k] -ne $cf.Verdict) { 'CHANGED_VERDICT' }
                      else { 'UNCHANGED' }
            if ($status -in 'NEW','CHANGED_VERDICT') {
                $delta.Add([PSCustomObject][ordered]@{
                    Status    = $status
                    Verdict   = $cf.Verdict
                    PrevVerdict = if ($prevIndex.ContainsKey($k)) { $prevIndex[$k] } else { $null }
                    Type      = $cf.Type
                    Target    = $cf.Target
                    RunStamp  = $stamp
                    PrevRun   = [System.IO.Path]::GetFileNameWithoutExtension($prevAdjFile.Name)
                })
            }
        }
        # Resolved (in previous, not in current)
        foreach ($k in $prevIndex.Keys) {
            if (-not $currIndex.ContainsKey($k)) {
                $parts = $k -split '\|', 2
                $delta.Add([PSCustomObject][ordered]@{
                    Status    = 'RESOLVED'
                    Verdict   = $null
                    PrevVerdict = $prevIndex[$k]
                    Type      = $parts[0]
                    Target    = if ($parts.Count -gt 1) { $parts[1] } else { '' }
                    RunStamp  = $stamp
                    PrevRun   = [System.IO.Path]::GetFileNameWithoutExtension($prevAdjFile.Name)
                })
            }
        }
        if ($delta.Count -gt 0) {
            $deltaOut = Join-Path $HostFolder "Delta_$stamp.json"
            $delta | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $deltaOut -Encoding UTF8
            Write-Host "[delta] $($delta.Count) change(s) vs $($prevAdjFile.Name) -> $(Split-Path -Leaf $deltaOut)" -ForegroundColor Cyan
        } else {
            Write-Host "[delta] No changes vs previous run ($($prevAdjFile.Name))" -ForegroundColor Gray
        }
    } catch {
        Write-Host "[delta] Could not compute delta: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Adjudication - $(Split-Path -Leaf $HostFolder)")
$md.Add(""); $md.Add("Source: ``$(Split-Path -Leaf $ReportPath)`` - $($results.Count) finding(s). Live proof: $([bool]$Live)")
$md.Add(""); $md.Add("## Verdicts")
foreach ($g in $results | Group-Object Verdict | Sort-Object { $order[$_.Name] }) { $md.Add("- **$($g.Name)**: $($g.Count)") }
$md.Add("")
# Final report = beyond-doubt anomalies only (true-positive class). Lower-confidence
# pivot leads are NOT detailed here - they live in the separate PivotLeads log.
$tpResults = @($results | Where-Object { $_.Verdict -in $TpClass })
$md.Add("## Highly-suspicious findings (investigate)")
$md.Add("")
if (-not $tpResults.Count) {
    $md.Add("_No true-positive-class anomalies. $($leads.Count) lower-confidence pivot lead(s) recorded in_ ``$(Split-Path -Leaf $leadsOut)`` _for optional review._")
    $md.Add("")
}
else {
    $md.Add("**$($tpResults.Count)** finding(s) require investigation. The remaining **$($leads.Count)** lower-confidence pivot lead(s) are in ``$(Split-Path -Leaf $leadsOut)`` - review only if they corroborate one of the below.")
    $md.Add("")
}
foreach ($e in $tpResults | Sort-Object @{E={$order[$_.Verdict]}}, Type) {
    $md.Add("### [$($e.Verdict)/$($e.Confidence)] $($e.Type) - $($e.Target)")
    $md.Add("- Details: $($e.Details)")
    if ($e.SubjectPath){ $md.Add("- Subject: ``$($e.SubjectPath)`` ($($e.PathTrust); exists=$($e.FileExists))") }
    if ($e.SigStatus)  { $md.Add("- Signature: $($e.SigStatus) - $($e.Signer)") }
    if ($e.Company)    { $md.Add("- Company: $($e.Company)") }
    if ($e.SHA256)     { $md.Add("- SHA256: $($e.SHA256)") }
    if ($e.CommandLine){ $md.Add("- CommandLine: $($e.CommandLine)") }
    if ($e.Owner)      { $md.Add("- Owner: $($e.Owner)") }
    if ($e.ParentName) { $md.Add("- Parent: $($e.ParentPid) -> $($e.ParentName)") }
    if ($e.Network)    { $md.Add("- Network: $($e.Network)") }
    if ($e.EvidenceDir){ $md.Add("- Evidence: ``Evidence\$(Split-Path -Leaf $e.EvidenceDir)``") }
    if ($e.Notes)      { $md.Add("- Notes: $($e.Notes)") }
    $md.Add("")
}
$md -join "`n" | Set-Content -LiteralPath $mdOut -Encoding UTF8
if ($cleanupRawDir -and $rawDir -and (Test-Path $rawDir)) { Remove-Item $rawDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "`n=== Adjudication summary ===" -ForegroundColor Green
$results | Group-Object Verdict | Sort-Object { $order[$_.Name] } |
    Select-Object @{N='Verdict';E={$_.Name}}, Count | Format-Table -AutoSize
$evCount = @($results | Where-Object { $_.EvidenceDir }).Count
Write-Host "[+] $jsonOut" -ForegroundColor Green
Write-Host "[+] $csvOut"  -ForegroundColor Green
Write-Host "[+] $mdOut"   -ForegroundColor Green
if ($evCount) { Write-Host "[+] Evidence bundles for $evCount finding(s): $EvidenceRoot" -ForegroundColor Green }

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOFJ0HoMYO8g5m
# VOaF9ud5kuleCYSVqChV9W3J04/206CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgS2lBoepoViqMSZNGFHApFP7BTU6PT9WlBwOB
# rK6d4CEwDQYJKoZIhvcNAQEBBQAEggEAimhe33Ju92AZcrOceihVawvv2tnImZy9
# rWMPL+IbZioDGkRPmtl2mcSB8HD1h6Ea3ZHlR8temRehNzuVHeeWkVUS091gn9sm
# B9uN87fUnsv+ZGxqIvCxFj13OB/b9476FfMizwOHCojPMfugfXSDMJZ6ib3vU8r2
# 6yhobGzyiz+uUnQFTZV2A0KrNnqm4j7mOtypxEM/5rFHlV6LvaeCZw2YTqO1ggQ9
# L5iiD8nPUFVHIlZ+2As+861r98PXtMUhg4NoxbuUTTDOrltaS3Lws7ORB+dYQ70X
# B39h2FacWBUQAZB8FvDgY1NvC9OTpPqBfSVTvo/bVpQBUVoETgbGeaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MjFaMC8GCSqGSIb3DQEJBDEiBCDe
# FZNH0zW0rpyIPCDy9olOil36+Mx0CBu6d8SXRBK42zANBgkqhkiG9w0BAQEFAASC
# AgAvo3cvAc+Ix6KV9WBT/OSsxue1ssTVwIma6sAtIWqsNOL3R3T/3ikpmBhUnBbB
# oftvoMvOX0PJTup2pUCoouY/Q5VUjOLHWViyYZ5A0fB6WQ1Eg5EIg4kODprTHtmh
# 5kwmou7uYbdxbwH09VPtwotIibxDThTkuLh8KobTxRHWTHZ3tyHnv+XN7HA3PNf5
# wn5JAe4tYmLCzgO1IbxBMyPgmihSO3QRCDjkgECDD+NivN2NuDLNBihihW8Lov9S
# 417+RXVNhd2I1z44T1NcjEhp7e4/QFU/3lWbnGiJsVwyNu6y7bJbne9zNi7eliSQ
# gBx7fPhfDaK21GEc4BvczI4+eZp21MdrZsEHwU0AS6/OFBvTxZTRqlC5cqyEtzyT
# okQ6w7DVJVF8SB9/eAt4PeMHzZ6+9FuCIq5aR42x4KjiRMyfrmD0Zm2cb8nglJNR
# pYa3DCb0WhH+TwRNuaN+cQvp3CaIOmOymVaCGlHp4TNRwRnSQmesmYT2miyzo1wi
# n5FKYKltPfTGttBwNAkVfOjtrN0CrKx/UtE8dvDAxstixMQ3OEXKP4leQrSKnEcT
# 47n17vGyczqmh0IQBDt2gYm9FhrKjmktm7rkxbXOIa0cP/oR5KStSf8iGuwBMD+P
# 2wQwx05KVILxLMTqhrER4MbWQlLP/OTOEeZlacrHz9R71g==
# SIG # End signature block
