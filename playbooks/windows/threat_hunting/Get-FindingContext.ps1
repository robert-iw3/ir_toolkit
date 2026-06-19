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

.PARAMETER HostFolder   The per-host collection folder (e.g. .\KIMBAP). Default: cwd.
.PARAMETER ReportPath   Explicit EDR_Report_*.json. Default: newest in HostFolder.
.PARAMETER Live         Gather live evidence (signatures, registry, command lines).

.EXAMPLE
    .\Get-FindingContext.ps1 -HostFolder .\KIMBAP -Live
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
$HashByPid = if ($Data.ContainsKey('process_hashes'))  { New-Index $Data['process_hashes'] 'Pid' }      else { @{} }
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
function Collect-FindingEvidence {
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
        if ($valid -and $trusted)        { $verdict='False Positive';        $conf='High' }
        elseif ($valid -and $writable)   { $verdict='Likely False Positive'; $conf='Medium'; $notes.Add('signed but in user-writable path') }
        elseif ($valid)                  { $verdict='Likely False Positive'; $conf='Medium' }
        elseif ($badSig -and ($writable -or $publicNet)) { $verdict='True Positive'; $conf='High' }
        elseif ($badSig)                 { $verdict='Likely True Positive';  $conf='Medium' }
        else                             { $verdict='Likely True Positive';  $conf='Low' }
    }
    elseif ($missing)                    { $verdict='Likely True Positive';  $conf='Medium'; $notes.Add('referenced binary not on disk (staged/removed?)') }
    else {
        # No live proof - fall back to collected context (capped at "Likely")
        if ($trusted -and $hasCo)        { $verdict='Likely False Positive'; $conf='Medium' }
        elseif ($trusted)                { $verdict='Likely False Positive'; $conf='Low' }
        elseif ($writable -or $publicNet){ $verdict='Likely True Positive';  $conf='Medium' }
    }
    if ($publicNet) { $notes.Add('external network egress observed') }
    if ($net.Count) { $notes.Add('net: ' + ($net -join '; ')) }
    if (-not $pivots.Count) { $notes.Add('no artifact resolved from this finding') }

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
    $evDir = Collect-FindingEvidence -Finding $f -Index $rownum -Verdict $verdict -Confidence $conf `
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
