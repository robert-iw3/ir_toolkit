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
if ($zip) {
    $rawDir = Join-Path ([System.IO.Path]::GetTempPath()) ("fctx_" + [guid]::NewGuid().ToString('N'))
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $rawDir -Force
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
    $missing  = ($Live -and $file.Exists -eq $false -and $subjectPath)
    $hasCo    = [bool]$file.Company

    $verdict='Indeterminate'; $conf='Low'
    if ($Live -and $file.Exists) {
        # False Positive ONLY when validly signed AND in a system/vendor-installed trusted location.
        # A valid signature in a user-writable path (Temp, AppData) is NOT a clearance -
        # signed malware, stolen certs, and living-off-the-land tools all have valid sigs.
        if ($valid -and $trusted)        { $verdict='False Positive';        $conf='High' }
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

    # ----- override: a valid signature does NOT clear remote-access tooling or
    # LOLBins. These are the abuse vectors (T1219 / T1218) and are signed by design.
    $subjName = if ($subjectPath) { Split-Path -Leaf $subjectPath } else { '' }
    $rmmPat   = '(?i)(anydesk|teamviewer|screenconnect|connectwise|splashtop|rustdesk|client32|ateraagent|action1|logmein|lmiguardian|gotoassist|zohoassist|za_connect|winvnc|tvnserver|vncserver|uvnc|remoting_host|dwagent|supremo|meshagent|quickassist)'
    $lolPat   = '(?i)^(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|installutil|msbuild)\.exe$'
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
if ($rawDir -and (Test-Path $rawDir)) { Remove-Item $rawDir -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "`n=== Adjudication summary ===" -ForegroundColor Green
$results | Group-Object Verdict | Sort-Object { $order[$_.Name] } |
    Select-Object @{N='Verdict';E={$_.Name}}, Count | Format-Table -AutoSize
$evCount = @($results | Where-Object { $_.EvidenceDir }).Count
Write-Host "[+] $jsonOut" -ForegroundColor Green
Write-Host "[+] $csvOut"  -ForegroundColor Green
Write-Host "[+] $mdOut"   -ForegroundColor Green
if ($evCount) { Write-Host "[+] Evidence bundles for $evCount finding(s): $EvidenceRoot" -ForegroundColor Green }

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACJnA3+tt1rfEj
# vLH/Eqjl5XSYh3SEdsFjD5Z5Z0q9Y6CCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
# rUKI1OYOaCvjMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjQyMjQ1MTNaFw0zMTA2MjQyMjU1MTNaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKCRMj2g7ekVueQgTeNVDV/Xz94PBbxt0/9qalo3
# ZcDg3e8VTErd0f6b8Ya8ibhn3tZ9zWKMpP3nuub3mlgEiO3Md4JhBx6N3bKukDN+
# Nb3uNGCoSbJTnI13pA1dkqtu41wagDdtnPDYSs5+cidAlPhZgBjxuXdoiWKzAUNw
# +dxDgaMmLxM0Qvp4z2kuOBes6C9Xd7twXNwi0Ov4pC1F0HAcKm7WCMtlRlX9i01k
# WmZkARKuPQ3eHWg0e08aC4CldRauFArRf2lO9MzquFinnD2s25q8F/PiEeyWALIe
# e/hE6L/bl/Z+5MR84dPFTfMXub9dsDsr++APaaYkZO04fTUCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQU6OnI
# wgtlYKR4+fSkiuhgK5MUVDANBgkqhkiG9w0BAQsFAAOCAQEAnw0GGGlgOpVP5ag3
# BvgHh4QYHOFColAEKbKGKDHMnvxsrlapVXCX69hnFv4701iiDn/DQirr/EUy1QRs
# v4BrQwh4EGvTU9AT8mOxRbi6svr1IKdab2iSkNqW8GTvSK6ZCyQkJn/+KAOY8u7E
# 9lO2+LM8DG2/1mgw/Ptg4jbVba/rPnLXkHnsydr2yhBw7miBEOIS9DBSul/wrxCV
# VTLcnbB1YRuJpV+dj6+YCnZT7pO6qOToHp++ueGyuw8ul/qCnhxiv89Hu/T++Pyh
# Qow09e6wDMKrbmdJD89KLTV8Zalq1sLskE8B4Q1TiWPknAr4f1V6rcJTH6BcoRMU
# 4eKB9TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBzF7sL9NkWtQojU5g5o
# K+MwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgsrvhGAKbUqpPRGao9whefg56f7AYJACW
# nE7+bQ2aGIYwDQYJKoZIhvcNAQEBBQAEggEADZw0S6kQG6SEEzIeS3HP9CB+qrEF
# XU0uPKxFWKTr38ZCuGITOl59/3XjksdLyrvIz2F/RrPDNRim4UjobRa/ebXMGhrb
# IlR4n6vN3W3klxy3rpEnksijqLDSjbAeFbW4ipjHlvtbIezjqqpJSW73x6LlLdJ2
# zdsuSvgTcBWll/rjlJI6gM39iQfFzI/SLmdV+8NVHXGDehjhwyS0xOAi5l2fxRb+
# Q/jH1INwhDdiZiX3xLb+suf6520dOO61twa/h/n7/JAX9GACdr9fbZDT1ihwJkrt
# 2EmduVfHOC+0VU8mocjxS8bnrYyOIXW6dxhldq7N3NHtty+vXugxvFK/jaGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1NDFaMC8GCSqGSIb3DQEJBDEi
# BCCkYhmXbwOhSmD26WtOF68vMqADO88v6CzDpRi4GHstozANBgkqhkiG9w0BAQEF
# AASCAgAOO2fQajXrtlHAbpxomimGlcEMdxe0tkg7Zz7ORmB3nwlHYk2z5MJtW9S4
# m2N6HWIUjEK+S9iUu3r8eCkE1db+36pL3LrTzpC5NMMf4BKSxRpj5ezwXzGfHNhg
# oruiAE6Ifkr8ae5WuFeAuUajnmAfP8P+qxRV3OZYkuywmihIsupd0kP5lj3K+DV/
# khwYYWVtX946VSvefTtOii3gDBhViNSdDgTI4tTYxG2Qc7FEULxIPvtXynuwcLRh
# +nMOmJR/ExrLldQBbpKVGonwA4uWGpsPIWdh+VhC4XgshX32GkXb2gkBHe9SU4Nl
# VHB+BBYlL4Ks3TlAQ3V6cE5H5kcyyMk/mqnoergCax0OcpwLhu3UNRe6pIFmnflz
# 0BfFa3YeEHo6UdeMLDXZ56SB89Tq7BADTuo0lMY6nPDNSTGDfleLXFa7ONOWLcZT
# E2gdxrQWn9AG8hhviIzd3eQw0omD8WibgGiPIRJSS+dGi1ewrh+djFZmLVsfCT56
# 0ziMo//J2TFtxxTqQb2mBAdvVKUjqZzqdKWHXhCBjVN6mUlUpEgeiVJfA29Jk/jc
# bbPDRj8CXRK8vbRfEDPq0NY+XS6yDyJM50hjbcD2BVU6CoLOFm7zzCoN27TWTNW/
# 1zcEnvsyUn+O3MVuOALKrrk5xIriBw9sAiTQecOIH+VDneIMVw==
# SIG # End signature block
