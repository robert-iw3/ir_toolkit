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
    foreach ($m in [regex]::Matches($Text,'\b\d{1,3}(?:\.\d{1,3}){3}\b'))              { $i.Ipv4 += $m.Value }
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

    # ----- definitive verdict from proof -----
    $valid    = ($file.SigStatus -eq 'Valid')
    $badSig   = ($file.SigStatus -and $file.SigStatus -ne 'Valid' -and $file.SigStatus -ne 'UnknownError')
    $trusted  = ($file.Trust -eq 'Trusted-Location')
    $writable = ($file.Trust -eq 'User-Writable')
    $missing  = ($Live -and $file.Exists -eq $false -and $subjectPath)
    $hasCo    = [bool]$file.Company

    $verdict='Indeterminate'; $conf='Low'
    if ($Live -and $file.Exists) {
        # False Positive ONLY when validly signed AND in a system/vendor-installed trusted location.
        # A valid signature in a user-writable path (Temp, AppData) is NOT a clearance —
        # signed malware, stolen certs, and living-off-the-land tools all have valid sigs.
        if ($valid -and $trusted)        { $verdict='False Positive';        $conf='High' }
        elseif ($valid -and $writable)   { $verdict='Indeterminate';         $conf='Medium'; $notes.Add('signed but in user-writable path — valid cert does not clear staging in Temp/AppData') }
        elseif ($valid)                  { $verdict='Likely False Positive'; $conf='Medium' }
        elseif ($badSig -and ($writable -or $publicNet)) { $verdict='True Positive'; $conf='High' }
        elseif ($badSig)                 { $verdict='Likely True Positive';  $conf='Medium' }
        else                             { $verdict='Likely True Positive';  $conf='Low' }
    }
    elseif ($missing)                    { $verdict='Likely True Positive';  $conf='Medium'; $notes.Add('referenced binary not on disk (staged/removed?)') }
    else {
        # No live proof — fall back to collected context (capped at "Likely").
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
    # These paths are legitimately timestomped — reduce to Low so they don't inflate TP count.
    $LIB_NET_PATTERN = '(?i)(\\lib\\net(462|471|472|48|standard|core)|\\bin\\Release\\|\\bin\\Debug\\|\\ref\\net|\\runtimes\\win)'
    if ($f.Type -eq 'Timestomped File' -and $f.Target -match $LIB_NET_PATTERN) {
        if ($conf -ne 'Low') {
            $conf = 'Low'
            $notes.Add('ADJUSTED: Timestomped .NET library assembly path — build-pipeline timestamps are expected here; verify if path is unexpected')
        }
    }

    # ----- override: a valid signature does NOT clear remote-access tooling or
    # LOLBins. These are the abuse vectors (T1219 / T1218) and are signed by design.
    $subjName = if ($subjectPath) { Split-Path -Leaf $subjectPath } else { '' }
    $rmmPat   = '(?i)(anydesk|teamviewer|screenconnect|connectwise|splashtop|rustdesk|client32|ateraagent|action1|logmein|lmiguardian|gotoassist|zohoassist|za_connect|winvnc|tvnserver|vncserver|uvnc|remoting_host|dwagent|supremo|meshagent|quickassist)'
    $lolPat   = '(?i)^(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|installutil|msbuild)\.exe$'
    $isRmmType = ($f.Type -match '(?i)Remote Access|ClickFix|RunMRU|LOLBin')
    if ($isRmmType -or ($subjName -match $rmmPat) -or ($subjName -match $lolPat)) {
        if ($verdict -in 'False Positive','Likely False Positive','Indeterminate') {
            $verdict = 'Likely True Positive'
            if ($conf -eq 'Low') { $conf = 'Medium' }
            $notes.Add('OVERRIDE: remote-access/LOLBin abuse class - signature does not clear it; verify connection logs / command line (T1219/T1218)')
        }
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
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonOut = Join-Path $HostFolder "Adjudication_$stamp.json"
$csvOut  = Join-Path $HostFolder "Adjudication_$stamp.csv"
$mdOut   = Join-Path $HostFolder "Adjudication_$stamp.md"
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonOut -Encoding UTF8
$results | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8

$order = @{ 'True Positive'=0; 'Likely True Positive'=1; 'Indeterminate'=2; 'Likely False Positive'=3; 'False Positive'=4 }
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Adjudication - $(Split-Path -Leaf $HostFolder)")
$md.Add(""); $md.Add("Source: ``$(Split-Path -Leaf $ReportPath)`` - $($results.Count) finding(s). Live proof: $([bool]$Live)")
$md.Add(""); $md.Add("## Verdicts")
foreach ($g in $results | Group-Object Verdict | Sort-Object { $order[$_.Name] }) { $md.Add("- **$($g.Name)**: $($g.Count)") }
$md.Add("")
foreach ($e in $results | Sort-Object @{E={$order[$_.Verdict]}}, Type) {
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
$evCount = ($results | Where-Object { $_.EvidenceDir }).Count
Write-Host "[+] $jsonOut" -ForegroundColor Green
Write-Host "[+] $csvOut"  -ForegroundColor Green
Write-Host "[+] $mdOut"   -ForegroundColor Green
if ($evCount) { Write-Host "[+] Evidence bundles for $evCount finding(s): $EvidenceRoot" -ForegroundColor Green }

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9OybtD7oxHRuH
# DNwe6F6Ba8D+IAzmPtqmjveth1X5LqCCFrQwggN2MIICXqADAgECAhBa5MQyEl22
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLpHTkAWJK/GM5y6E3Y+1c51YAvdAp8bQ
# 9KfQNarI+jowDQYJKoZIhvcNAQEBBQAEggEAMSgqvzuh8EQZ2ZIHQs7rUt3QStZ9
# cNbaACLWsa52ndtlao3lv9OUtgrHSK6qAkrAbUtvof4dvQH+4he3fsv5ow6U1Qnp
# dnBcgUQVADByCVWwUQjOdTvxHRiepcDL65Ec85yRcyf6dHkMVqs/KUIv0onkk0HP
# cGPTUZRpXiOd5CQQYrzHH2qDhzBxZ072nnaMIkcso2oBo6BW/7d3/Cneo8lhFUsX
# YB+lABFjOc8Xlp4wNqRwUrOKweLPABUb4zHxX+OO7vC7cfi6IOjpr2Jb2nLXi2Rr
# h/RHdyLH2wHt0YcpsUErrLEkBPyeBL2+9qc55h4NIDxEF6IkL2WQYz66D6GCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MzJaMC8GCSqGSIb3DQEJBDEi
# BCCfqxCyq+fXkYocSSD7h5luRedL1ZqDiORKvbFHLuLfTzANBgkqhkiG9w0BAQEF
# AASCAgBlJjJgW7qOhPMMG2IJj+Q4JWBSMwZt3ucovfjmjwCLsOrUnGzWBrFUuraE
# v81o2DgUUuxbtdiWlSjZec3FSKjyVXgmBdIJm4MOCvYVLRO6iKApEYR78IHWt5NG
# hSi6UBoQCNYwvI3Y3s6MwNyApvQYuUfxu45cujBISq3Ro6cWaVSGHXlgwL62JVGs
# UKeyv5rJoAT/ys6Dpj/UpgtlF4iHrSTMK9WRWqRkhfmh96pZO52n0CJ+gJul843D
# 1B0znlH8TYTO6c0h76KZAKCdq9UjaaAQQF1Wr4IMdDqZfXXmqNoM9d/G5c85X7g0
# XRi07FRdpQnl0qyK++o+h2HRyve9iMDXVOPOgEyf4xyxzxGusoVFtcFGp0KkVvZw
# jyGe/Qqi0TbKn0kv0U+xgjg0MDqSHhESOzJfi128cK5ENEyCiq39U8Aq84hC+pXt
# t0VhZsisG86TLPVLpKr80eLLnb+B7gw0qQTpzg1vCwylwCWuOIlTXD6hBYJOoLSt
# ZZAbsYuQUPtXk1XQD4UKxI/6//hruWUxfDIYDvV9+J47idLmJcS6sEkOmfTtBIgH
# tB1ggipIfTus6y09+Fe+zSRGw0apfjDZxPSu10vDRbIbWPigszGm3Z441C6q91rK
# +IefGrFMoHoxrdfI+0GXkmPcEAyaHc9SLyQ98HKXNeqN1U2SEg==
# SIG # End signature block
