<#
.SYNOPSIS
    Automated incident reporting + attack-graph correlation (native PowerShell).
.DESCRIPTION
    Windows-native twin of generate_reports.py. Consumes a completed per-host
    collection folder and emits, with no human authoring:
        Incident_Report.md   full IR report
        Attack_Graph.md      Mermaid attack graph correlated from the findings
        IOCs.json            machine-readable IOC bundle (C2 endpoints, hashes,
                             tools, ATT&CK) consumed by Invoke-Eradication.ps1
    No external dependency (so it runs on a bare Windows host). The Python twin is
    the canonical cross-platform/Linux generator and is what the pytest suite covers.
.EXAMPLE
    .\generate_reports.ps1 -HostFolder .\KIMBAP -IncidentId KIMBAP_20260618_125030
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HostFolder,
    [string]$IncidentId,
    [string]$Analyst = 'IR Automation',
    # Emit only IOCs.json (analysis stage) and return, so the eradication hand-off
    # does not depend on full report generation being run.
    [switch]$IocsOnly,
    # Emit only Principals.json (implicated accounts to revoke at eradication).
    [switch]$PrincipalsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$TpClass       = @('True Positive','Likely True Positive')
$VerdictOrder  = @('False Positive','Likely False Positive','Indeterminate','Likely True Positive','True Positive')
$RatTokens     = @('ScreenConnect','GoToAssist','AnyDesk','TeamViewer','Atera','ConnectWise','Splashtop','RemoteUtilities','RustDesk','NetSupport')

# Kill-chain tactics + the technique prefixes / type keywords that evidence each,
# so the attack graph is built from whatever findings exist (not a fixed template).
$TacticOrder = @('Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Command and Control','Exfiltration','Impact')
$TacticTech = @{
    'Initial Access'=@('T1566','T1190','T1078'); 'Execution'=@('T1204','T1059','T1218','T1569')
    'Persistence'=@('T1543','T1547','T1546','T1053','T1136','T1505'); 'Privilege Escalation'=@('T1068','T1055','T1134')
    'Defense Evasion'=@('T1562','T1014','T1070','T1112','T1027'); 'Credential Access'=@('T1003','T1110','T1555')
    'Discovery'=@('T1057','T1082','T1018'); 'Lateral Movement'=@('T1021','T1570')
    'Command and Control'=@('T1219','T1071','T1105','T1090'); 'Exfiltration'=@('T1041','T1567','T1048')
    'Impact'=@('T1486','T1490','T1489')
}
$TacticType = @{
    'Initial Access'=@('phish','browser','clickfix','lure','valid account','identity','spearphish','exploit public')
    'Execution'=@('lolbin','script','command','macro','interpreter'); 'Privilege Escalation'=@('privilege','escalat','sudo','setuid','token')
    'Persistence'=@('persistence','scheduled task','cron','systemd','registry','com hijack','bits','service','webshell','preload','launch','autostart','run key')
    'Defense Evasion'=@('defender','disable','hidden process','injection','rootkit','masquerad','obfusc','amsi','etw','tamper','anonymous exec')
    'Credential Access'=@('credential','lsass','mimikatz','password','hash dump','kerbero','secret'); 'Discovery'=@('discovery','recon','enumerat','port probe')
    'Lateral Movement'=@('lateral','psexec','smb','rdp','remote service'); 'Exfiltration'=@('exfil','upload','transfer out','data staged')
    'Command and Control'=@('remote access','c2','beacon','rat','tunnel','proxy','relay','cloud detection')
    'Impact'=@('ransom','encrypt','wipe','destroy','deface','miner','cryptojack','coinhive','xmrig')
}
$TacticStyle = @{
    'Initial Access'='#1e40af,#93c5fd'; 'Execution'='#5b21b6,#c4b5fd'; 'Persistence'='#9a3412,#fdba74'
    'Privilege Escalation'='#854d0e,#fde047'; 'Defense Evasion'='#92400e,#fcd34d'; 'Credential Access'='#9f1239,#fda4af'
    'Discovery'='#155e75,#67e8f9'; 'Lateral Movement'='#3f6212,#bef264'; 'Command and Control'='#7f1d1d,#fca5a5'
    'Exfiltration'='#701a75,#f0abfc'; 'Impact'='#7f1d1d,#fecaca'; 'Uncategorized'='#374151,#9ca3af'
}
function Get-GraphTactic($f) {
    $techs = [regex]::Matches((Field $f @('MITRE')),'T\d{4}(?:\.\d{3})?') | ForEach-Object { $_.Value }
    foreach ($t in $TacticOrder) { foreach ($p in $TacticTech[$t]) { if ($techs | Where-Object { $_ -like "$p*" }) { return $t } } }
    $blob = (((Field $f @('Type'))+' '+(Field $f @('Target'))+' '+(Field $f @('Details')))).ToLower()
    foreach ($t in $TacticOrder) { foreach ($k in $TacticType[$t]) { if ($blob.Contains($k)) { return $t } } }
    return 'Uncategorized'
}
function Format-GLabel($s) {
    if ($null -eq $s) { return '?' }
    $s = [string]$s
    foreach ($ch in '"','[',']','{','}','|','<','>','(',')') { $s = $s.Replace($ch,' ') }
    $s = ($s -replace '\s+',' ').Trim()
    if ($s.Length -gt 60) { $s = $s.Substring(0,60) }
    if (-not $s) { '?' } else { $s }
}
function Get-TacticClass($t) { 't_' + (($t.ToLower()) -replace '[^a-z]','') }

# Built-in accounts that must never be auto-disabled.
$ProtectedAccounts = @('system','local service','network service','administrator','guest',
    'defaultaccount','wdagutilityaccount','trustedinstaller','root','daemon','nobody')
function Get-ImplicatedPrincipals($tpFindings, $HostName) {
    $seen = @{}; $out = @()
    foreach ($f in $tpFindings) {
        $cands = @()
        foreach ($fld in 'Owner','User','UserName','Account','Principal') { $v = Field $f @($fld); if ($v) { $cands += $v } }
        $ftype = Field $f @('Type')
        if ($ftype -match '(?i)identity|iam|account|cloud detection') { $t = Field $f @('Target'); if ($t) { $cands += $t } }
        foreach ($raw in $cands) {
            $raw = [string]$raw; $domain=''; $user=$raw
            if ($raw -match '\\') { $p=$raw.Split('\',2); $domain=$p[0].Trim(); $user=$p[1].Trim() }
            elseif ($raw -match '@') { $p=$raw.Split('@',2); $user=$p[0].Trim(); $domain=$p[1].Trim() }
            if (-not $user -or $user -in @('','-')) { continue }
            # classify
            if ($raw -match '@' -and $raw.Split('@')[-1] -match '\.') { $ptype='cloud-identity'; $name=$raw.Trim(); $dom='' }
            elseif ($ftype -match '(?i)cloud|identity|iam') { $ptype='iam'; $name=$user; $dom='' }
            elseif ($domain -and $domain.ToLower() -eq $HostName.ToLower()) { $ptype='local'; $name=$user; $dom=$domain }
            elseif ($domain -and $domain.ToUpper() -notin @('NT AUTHORITY','BUILTIN','.','WORKGROUP')) { $ptype='domain'; $name=$user; $dom=$domain }
            else { $ptype='local'; $name=$user; $dom=$domain }
            $key = "$($dom.ToLower())|$($name.ToLower())"
            if ($seen.ContainsKey($key)) { continue }; $seen[$key]=$true
            $protected = $ProtectedAccounts -contains $name.ToLower()
            $out += [ordered]@{ name=$name; domain=$dom; type=$ptype; source=$ftype
                auto_revoke=(-not $protected)
                reason=$(if ($protected) {'built-in/system account - review only'} else {'implicated by a true-positive finding'}) }
        }
    }
    return ,$out
}

function Get-NewestJson([string]$Folder,[string]$Pattern) {
    Get-ChildItem -Path $Folder -Filter $Pattern -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
function Read-Findings([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $c = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if ($null -eq $c) { return @() }
        if ($c -isnot [System.Array]) { return @($c) }
        return $c
    } catch { return @() }
}
function Field($o,[string[]]$Names) {
    foreach ($n in $Names) { if ($o.PSObject.Properties[$n] -and $o.$n) { return [string]$o.$n } }
    return ''
}
function Test-Sanctioned([string]$HostName) { return [bool]($HostName -match '(^|\.)screenconnect\.com$') }

function Get-Relay([string]$Text) {
    if (-not $Text) { return $null }
    $h = [regex]::Match($Text,'[?&]h=([^&"\\\s]+)')
    $p = [regex]::Match($Text,'[?&]p=(\d{1,5})')
    if (-not ($h.Success -and $p.Success)) { return $null }
    $s = [regex]::Match($Text,'[?&]s=([0-9A-Fa-f-]{16,40})')
    $i = [regex]::Match($Text,'Client \(([0-9A-Fa-f]{8,})\)')
    [ordered]@{
        host=$h.Groups[1].Value; port=[int]$p.Groups[1].Value
        session_id=$(if($s.Success){$s.Groups[1].Value}else{$null})
        instance_id=$(if($i.Success){$i.Groups[1].Value}else{$null})
    }
}

if (-not (Test-Path -LiteralPath $HostFolder)) { throw "host folder not found: $HostFolder" }
$HostName = Split-Path -Leaf ($HostFolder.TrimEnd('\','/'))
if (-not $IncidentId) { $IncidentId = $HostName }

$adjPath = Get-NewestJson $HostFolder 'Adjudication_*.json'
$comPath = Get-NewestJson $HostFolder 'Combined_Findings_*.json'
$raPath  = Get-NewestJson $HostFolder 'RemoteAccess_Findings_*.json'

$findings = if ($adjPath) { Read-Findings $adjPath } elseif ($comPath) { Read-Findings $comPath } else { @() }
$remote   = if ($raPath) { Read-Findings $raPath } else { @() }
if (-not $remote.Count -and $comPath) {
    $remote = Read-Findings $comPath | Where-Object { (Field $_ @('Type')) -in @('Remote Access Tool','Defender Disabled','LOLBin Execution','Browser Artifact') }
}

# -- Correlate -----------------------------------------------------------------
$funnel = @{}
foreach ($f in $findings) { $v = Field $f @('Verdict'); if (-not $v) { $v='(unadjudicated)' }; $funnel[$v] = 1 + ($funnel[$v]) }
$tp = @($findings | Where-Object { (Field $_ @('Verdict')) -in $TpClass })

$techniques = [System.Collections.Specialized.OrderedDictionary]::new()
foreach ($f in $findings) {
    foreach ($m in [regex]::Matches((Field $f @('MITRE')),'T\d{4}(?:\.\d{3})?')) {
        if (-not $techniques.Contains($m.Value)) { $techniques.Add($m.Value,$true) }
    }
}

$rats = @(); $relays = @(); $hashes = [System.Collections.Specialized.OrderedDictionary]::new(); $defenderOff = $false
foreach ($f in $remote) {
    $ftype=Field $f @('Type'); $details=Field $f @('Details'); $target=Field $f @('Target')
    if ($ftype -eq 'Remote Access Tool' -or ($RatTokens | Where-Object { ($target+$details) -match [regex]::Escape($_) })) {
        $tool = ($RatTokens | Where-Object { ($target+' '+$details) -match [regex]::Escape($_) } | Select-Object -First 1)
        if (-not $tool) { $tool = $target }
        if ($rats.tool -notcontains $tool) { $rats += ,([ordered]@{tool=$tool;details=$details;target=$target}) }
    }
    if ($ftype -eq 'Defender Disabled' -or $details -match 'real-time protection is OFF') { $defenderOff=$true }
    $r = Get-Relay $details
    if ($r -and -not ($relays | Where-Object { $_.host -eq $r.host -and $_.port -eq $r.port })) { $relays += ,$r }
}
$ratSigner=$null
foreach ($f in $findings) {
    $subj=Field $f @('SubjectPath'); $sha=Field $f @('SHA256')
    if ($RatTokens | Where-Object { $subj -match [regex]::Escape($_) }) {
        if ($sha -and -not $hashes.Contains($sha.ToUpper())) { $hashes.Add($sha.ToUpper(),$subj) }
        if (-not $ratSigner) { $ratSigner = Field $f @('Signer') }
    }
    if ((Field $f @('MITRE')) -match 'T1562' -or (Field $f @('Type')) -match 'Defender Disabled') { $defenderOff=$true }
}

$hasCustomRelay = [bool]($relays | Where-Object { -not (Test-Sanctioned $_.host) })
$severity = if ($hasCustomRelay -or $rats.Count) { 'HIGH - confirmed unauthorized remote access' }
            elseif ($tp.Count) { 'MEDIUM - true-positive-class findings require review' }
            else { 'LOW - no true-positive-class findings' }

# -- IOCs.json -----------------------------------------------------------------
$c2 = foreach ($r in $relays) {
    [ordered]@{ host=$r.host; port=$r.port; sanctioned=(Test-Sanctioned $r.host); session_id=$r.session_id; instance_id=$r.instance_id }
}
[ordered]@{
    incident_id=$IncidentId; hostname=$HostName
    generated_utc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    c2_endpoints=@($c2)
    file_hashes_sha256=@($hashes.Keys)
    remote_access_tools=@($rats.tool)
    attack_techniques=@($techniques.Keys)
    defender_realtime_disabled=$defenderOff
} | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $HostFolder 'IOCs.json') -Encoding UTF8

# -- Principals.json (implicated accounts to revoke at eradication) ------------
$principals = Get-ImplicatedPrincipals $tp $HostName
[ordered]@{
    incident_id=$IncidentId; hostname=$HostName
    generated_utc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    principals=@($principals)
} | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $HostFolder 'Principals.json') -Encoding UTF8

if ($IocsOnly) {
    Write-Host "[+] IOCs.json  ($($relays.Count) C2 relay(s))" -ForegroundColor Green
    return
}
if ($PrincipalsOnly) {
    $autoN = @($principals | Where-Object { $_.auto_revoke }).Count
    Write-Host "[+] Principals.json  ($($principals.Count) principal(s), $autoN auto-revocable)" -ForegroundColor Green
    return
}

# -- Incident_Report.md --------------------------------------------------------
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Incident Response Report - $HostName"); $md.Add("")
$md.Add("| | |"); $md.Add("|---|---|")
$md.Add("| **Host** | $HostName |"); $md.Add("| **Incident** | $IncidentId |")
$md.Add("| **Date of analysis** | $(Get-Date -Format 'yyyy-MM-dd') |")
$md.Add("| **Analyst** | $Analyst |"); $md.Add("| **Severity** | **$severity** |")
$md.Add("| **Status** | Contained (host isolated) -> eradication pending/applied |"); $md.Add("")
$md.Add("> Auto-generated by ``generate_reports.ps1`` from the adjudicated findings."); $md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 1. Executive summary"); $md.Add("")
if ($rats.Count) {
    $tools = ($rats.tool | Sort-Object -Unique) -join ', '
    $custom = @($relays | Where-Object { -not (Test-Sanctioned $_.host) })
    $line = "Adjudication confirmed **unauthorized remote-access tooling ($tools)** on ``$HostName``."
    if ($custom.Count) { $line += " The client beacons to a **custom, adversary-operated relay ``$($custom[0].host):$($custom[0].port)``** - proof of an attacker deployment, not sanctioned IT support." }
    $md.Add($line)
    if ($defenderOff) { $md.Add(""); $md.Add("Microsoft Defender **real-time protection was disabled** (T1562.001).") }
} else {
    $md.Add("Adjudication produced **$($tp.Count)** true-positive-class finding(s) of **$($findings.Count)** raw findings on ``$HostName``.")
}
$md.Add(""); $md.Add("**$($findings.Count) raw findings -> $($tp.Count) true-positive-class.**"); $md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 2. Attack chain (MITRE ATT&CK)"); $md.Add("")
if ($techniques.Count) { foreach ($t in $techniques.Keys) { $md.Add("- **$t**") } } else { $md.Add("- No ATT&CK techniques associated.") }
$md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 3. True-positive-class findings"); $md.Add("")
if ($tp.Count) {
    $md.Add("| Verdict | Conf | Type | Target | Subject |"); $md.Add("|---|---|---|---|---|")
    foreach ($f in $tp) {
        $subj=(Field $f @('SubjectPath')) -replace '\|','\|'
        $md.Add("| $(Field $f @('Verdict')) | $(Field $f @('Confidence')) | $(Field $f @('Type')) | $(Field $f @('Target')) | ``$subj`` |")
    }
} else { $md.Add("No true-positive-class findings. **No eradication required.**") }
$md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 4. Adjudication funnel"); $md.Add(""); $md.Add("| Verdict | Count |"); $md.Add("|---|---:|")
foreach ($v in $VerdictOrder) { if ($funnel[$v]) { $md.Add("| $v | $($funnel[$v]) |") } }
foreach ($v in $funnel.Keys) { if ($VerdictOrder -notcontains $v) { $md.Add("| $v | $($funnel[$v]) |") } }
$md.Add("| **Total** | **$($findings.Count)** |"); $md.Add("")
$md.Add("Sources merged: EDR hunt + remote-access triage + persistence/config snapshot."); $md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 5. Resolution / eradication"); $md.Add("")
$md.Add("``````powershell")
$md.Add(".\Invoke-Eradication.ps1 -HostFolder .\$HostName -MinVerdict ""Likely True Positive""")
$md.Add(".\Invoke-Eradication.ps1 -HostFolder .\$HostName -MinVerdict ""Likely True Positive"" -Apply")
$md.Add("``````"); $md.Add("")
if ($relays.Count) {
    $md.Add("**Network containment kept after eradication (known-bad, do NOT unblock):**")
    foreach ($r in $relays) { $tag = if (Test-Sanctioned $r.host) {'sanctioned'} else {'adversary relay'}; $md.Add("- ``$($r.host):$($r.port)`` ($tag)") }
    $md.Add("")
}
$md.Add("**Manual follow-up:** re-enable Defender real-time protection; fully uninstall the remote-access client; rotate credentials; review for new/modified local accounts.")
$md.Add(""); $md.Add("---"); $md.Add("")
$md.Add("## 6. IOC appendix"); $md.Add(""); $md.Add("``````")
if ($rats.Count) { $md.Add("Tool        : " + (($rats.tool | Sort-Object -Unique) -join ', ')) }
if ($ratSigner) { $md.Add("Signer      : $ratSigner") }
foreach ($r in $relays) {
    $flag = if (Test-Sanctioned $r.host) {''} else {'   <-- attacker relay (custom)'}
    $md.Add("RELAY (C2)  : $($r.host) : $($r.port)/TCP$flag")
    if ($r.session_id) { $md.Add("SESSION ID  : s=$($r.session_id)") }
    if ($r.instance_id){ $md.Add("INSTANCE    : $($r.instance_id)") }
}
foreach ($h in $hashes.Keys) { $md.Add("SHA256      : $h") }
if ($techniques.Count) { $md.Add("ATT&CK      : " + (($techniques.Keys) -join ', ')) }
$md.Add("``````"); $md.Add("")
$md.Add("*Machine-readable IOC bundle: ``IOCs.json``. Attack correlation: ``Attack_Graph.md``.*")
$md -join "`n" | Out-File -FilePath (Join-Path $HostFolder 'Incident_Report.md') -Encoding UTF8

# -- Attack_Graph.md -----------------------------------------------------------
$g = [System.Collections.Generic.List[string]]::new()
$g.Add("# $HostName - Attack Graph"); $g.Add("")
$g.Add("**Incident:** $IncidentId - **Host:** $HostName - **Severity:** $severity"); $g.Add("")
$g.Add("The full chain of events from the adjudicated findings. Each node is one finding/event, ordered along the kill chain (and by time where known); colour = ATT&CK tactic. Unique to this incident."); $g.Add("")
$g.Add('```mermaid'); $g.Add('flowchart TD')
$g.Add('    classDef host fill:#0f766e,stroke:#5eead4,color:#fff;')
$g.Add('    classDef c2   fill:#991b1b,stroke:#fde047,color:#fff,stroke-width:3px;')
$g.Add('    classDef inferred fill:#1f2937,stroke:#9ca3af,color:#e5e7eb,stroke-dasharray:4 3;')
# Order every true-positive-class finding into one event chain (tactic, then time).
$evlist = @(); $i = 0
foreach ($f in $tp) {
    $t = Get-GraphTactic $f
    $ti = [array]::IndexOf($TacticOrder,$t); if ($ti -lt 0) { $ti = $TacticOrder.Count }
    $when = [datetime]::MaxValue
    foreach ($fld in 'StartTime','EventTime','Timestamp','FirstSeen') { $v = Field $f @($fld); if ($v) { try { $when = [datetime]$v; break } catch {} } }
    $evlist += [pscustomobject]@{ f=$f; tactic=$t; ti=$ti; when=$when; idx=$i }; $i++
}
$evlist = @($evlist | Sort-Object ti, when, idx)
$present = @(); foreach ($e in $evlist) { if ($present -notcontains $e.tactic) { $present += $e.tactic } }
foreach ($t in $present) { $st = $TacticStyle[$t]; if (-not $st) { $st='#374151,#9ca3af' }; $p=$st.Split(','); $g.Add("    classDef $(Get-TacticClass $t) fill:$($p[0]),stroke:$($p[1]),color:#fff;") }
$g.Add('')
$g.Add("    H([""HOST: $(Format-GLabel $HostName)""]):::host")
$edges=@(); $prev='H'; $prevTactic=$null; $c2anchor='H'; $n=0
foreach ($e in $evlist) {
    $n++; $nid="E$n"; $t=$e.tactic
    $label = (Format-GLabel (Field $e.f @('Type'))) + '<br/>' + (Format-GLabel (Field $e.f @('Target')))
    $techs = (([regex]::Matches((Field $e.f @('MITRE')),'T\d{4}(?:\.\d{3})?') | ForEach-Object { $_.Value }) | Select-Object -First 2) -join ', '
    $label += "<br/><i>$t$(if($techs){' - '+$techs})</i>"
    $g.Add("    $nid[""$label""]:::$(Get-TacticClass $t)")
    if ($prevTactic -and $t -ne $prevTactic) { $edges += "    $prev -->|$(Format-GLabel $t)| $nid" } else { $edges += "    $prev --> $nid" }
    if ($t -eq 'Command and Control') { $c2anchor=$nid }
    $prev=$nid; $prevTactic=$t
}
if (-not $evlist.Count) { $g.Add('    N0["No confirmed malicious activity<br/>(see Retrospective.md)"]:::inferred'); $edges += '    H --- N0' }
elseif ($c2anchor -eq 'H') { $c2anchor = $prev }
$ci=0
foreach ($r in $relays) {
    $tag = if (Test-Sanctioned $r.host) {'sanctioned'} else {'adversary-operated'}
    $port = if ($r.port) { " : $($r.port)/TCP" } else { '' }
    $g.Add("    C$ci([""C2 RELAY<br/><b>$(Format-GLabel $r.host)$port</b><br/>$tag""]):::c2")
    $edges += "    $c2anchor ==>|""egress""| C$ci"; $ci++
}
foreach ($e in $edges) { $g.Add($e) }
$g.Add('```'); $g.Add('')
$custom0 = @($relays | Where-Object { -not (Test-Sanctioned $_.host) })
if ($custom0.Count) {
    $r=$custom0[0]
    $g.Add("## RAT -> $($r.host) (the key path)"); $g.Add("")
    $g.Add("The remote-access client beacons to **``$($r.host):$($r.port)``** - a custom relay rather than a vendor-sanctioned endpoint, proving an **adversary-operated** deployment. Block it at egress before reconnecting the host."); $g.Add("")
}
$g.Add("## IOCs"); $g.Add(""); $g.Add('```')
foreach ($r in $relays) {
    $g.Add("RELAY (C2)  : $($r.host) : $($r.port)/TCP")
    if ($r.session_id) { $g.Add("SESSION ID  : s=$($r.session_id)") }
    if ($r.instance_id){ $g.Add("INSTANCE    : $($r.instance_id)") }
}
foreach ($h in $hashes.Keys) { $g.Add("SHA256      : $h") }
if ($techniques.Count) { $g.Add("ATT&CK      : " + (($techniques.Keys) -join ', ')) }
$g.Add('```')
$g -join "`n" | Out-File -FilePath (Join-Path $HostFolder 'Attack_Graph.md') -Encoding UTF8

# -- Retrospective.md (objective review + gap analysis) ------------------------
$Tactics = [ordered]@{
    'Initial Access'=@('T1566','T1190','T1078'); 'Execution'=@('T1204','T1059','T1218','T1053')
    'Persistence'=@('T1543','T1547','T1546','T1053','T1136'); 'Privilege Escalation'=@('T1068','T1055','T1134')
    'Defense Evasion'=@('T1562','T1014','T1070','T1112','T1027'); 'Credential Access'=@('T1003','T1110','T1555')
    'Discovery'=@('T1057','T1082','T1018'); 'Lateral Movement'=@('T1021','T1570')
    'Command and Control'=@('T1219','T1071','T1105','T1090'); 'Exfiltration'=@('T1041','T1567','T1048')
    'Impact'=@('T1486','T1490','T1489')
}
$fpCount = (@($funnel['False Positive']) + @($funnel['Likely False Positive']) | Measure-Object -Sum).Sum
$indet = [int]$funnel['Indeterminate']
$totalN = [Math]::Max($findings.Count,1)
$customC2 = @($relays | Where-Object { -not (Test-Sanctioned $_.host) }).Count
$rt = [System.Collections.Generic.List[string]]::new()
$rt.Add("# $HostName - Incident Retrospective & Gap Analysis"); $rt.Add("")
$rt.Add("**Incident:** $IncidentId - **Host:** $HostName"); $rt.Add("")
$rt.Add("Objective, data-driven review generated from the adjudicated findings."); $rt.Add("")
$rt.Add("## 1. Outcome"); $rt.Add("")
$rt.Add("- Raw findings triaged: **$($findings.Count)**")
$rt.Add("- True-positive-class (actioned): **$($tp.Count)**")
$rt.Add("- Unresolved (Indeterminate): **$indet**")
$rt.Add("- Cleared as false-positive: **$fpCount** ($([Math]::Round(100*$fpCount/$totalN))% of all findings)")
$rt.Add("- Confirmed remote-access C2: **$customC2**"); $rt.Add("")
$rt.Add("## 2. ATT&CK kill-chain coverage"); $rt.Add(""); $rt.Add("| Tactic | Evidence | Status |"); $rt.Add("|---|---|---|")
$gaps = @()
foreach ($tac in $Tactics.Keys) {
    $hit = @($techniques.Keys | Where-Object { $t=$_; ($Tactics[$tac] | Where-Object { $t -like "$_*" }) })
    if ($hit.Count) { $rt.Add("| $tac | $($hit -join ', ') | covered |") }
    else { $rt.Add("| $tac | - | no evidence collected |"); $gaps += $tac }
}
$rt.Add("")
$rt.Add("## 3. Detection & collection gaps"); $rt.Add("")
if ($gaps -contains 'Initial Access') { $rt.Add("- **Initial-access vector not captured.** Review browser history, RunMRU, and auth logs to confirm the entry point.") }
if ($gaps -contains 'Credential Access' -and $relays.Count) { $rt.Add("- **Credential exposure unquantified.** Assume credentials on this host are exposed; rotate them.") }
if ($gaps -contains 'Lateral Movement' -and $relays.Count) { $rt.Add("- **Lateral movement not assessed.** Enumerate peer connections from this host.") }
if (-not (Get-ChildItem -Path $HostFolder -Filter '*.raw' -ErrorAction SilentlyContinue) -and -not (Get-ChildItem -Path $HostFolder -Filter '*memory*' -ErrorAction SilentlyContinue)) {
    $rt.Add("- **No memory image captured.** Re-run collection with -CaptureMemory for fileless coverage.")
}
if ($indet) { $rt.Add("- **$indet finding(s) left Indeterminate.** Need analyst review.") }
if (-not $gaps.Count -and -not $indet) { $rt.Add("- No structural coverage gaps detected.") }
$rt.Add("")
$rt.Add("## 4. Recommendations"); $rt.Add("")
$rt.Add("1. Keep the adversary C2 blocked/sinkholed after restoration (wired via IOCs.json).")
$rt.Add("2. Close the collection gaps in section 3 before closing the incident.")
$rt.Add("3. Feed false-positive patterns back into tuning.")
$rt -join "`n" | Out-File -FilePath (Join-Path $HostFolder 'Retrospective.md') -Encoding UTF8

Write-Host "[+] Incident_Report.md  ($($findings.Count) findings, $($tp.Count) true-positive-class)" -ForegroundColor Green
Write-Host "[+] Attack_Graph.md" -ForegroundColor Green
Write-Host "[+] Retrospective.md" -ForegroundColor Green
Write-Host "[+] IOCs.json  ($($relays.Count) C2 relay(s))" -ForegroundColor Green
