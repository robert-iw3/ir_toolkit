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
    .\generate_reports.ps1 -HostFolder .\<HOSTNAME> -IncidentId <HOSTNAME>_20260618_125030
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

# Finding types that directly implicate an account in malicious activity.
# Process/file/registry findings do NOT warrant auto-revoking the owner account -
# they may belong to the machine itself. Require an explicit account-centric signal.
$AccountCentricTypes = @(
    'Explicit Credential Use',       # 4648 - someone used creds explicitly (pass-the-hash, runas)
    'Brute Force Attempt',           # 4625 repeated failures
    'New Account Created',           # 4720 - attacker created a backdoor account
    'Security Log Cleared',          # 1102 - attacker covered tracks
    'Suspicious Task Created',       # scheduled task with user context
    'Suspicious Task Modified',
    'Remote Access Tool',            # RMM / RAT with user session
    'Identity Anomaly',              # cloud identity risk signals
    'IAM Anomaly',
    'Risky User',
    'Cloud Detection'
)

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
            $protected       = $ProtectedAccounts -contains $name.ToLower()
            $accountCentric  = $AccountCentricTypes -contains $ftype
            # Auto-revoke only when the finding type directly implicates the account
            # (credential use, new account, RMM session, etc.). Process/file/registry
            # findings name an Owner but do not prove the account acted maliciously.
            $shouldRevoke    = (-not $protected) -and $accountCentric
            $reason = if ($protected)      { 'built-in/system account - review only' }
                      elseif ($accountCentric) { "implicated by $ftype finding" }
                      else                { "process/file finding - review before revoking (finding: $ftype)" }
            $out += [ordered]@{ name=$name; domain=$dom; type=$ptype; source=$ftype
                auto_revoke=$shouldRevoke
                reason=$reason }
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

# @(...) forces an array: an if-block that returns an empty @() otherwise collapses to
# $null, which makes .Count throw under StrictMode on a minimal/zero-finding folder
# (e.g. the analyst-box memory-only rollup).
$findings = @(if ($adjPath) { Read-Findings $adjPath } elseif ($comPath) { Read-Findings $comPath })
$remote   = @(if ($raPath) { Read-Findings $raPath })
if ($remote.Count -eq 0 -and $comPath) {
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
        if (-not ($rats | Where-Object { $_['tool'] -eq $tool })) { $rats += ,([ordered]@{tool=$tool;details=$details;target=$target}) }
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
    remote_access_tools=@($rats | ForEach-Object { $_['tool'] })
    attack_techniques=@($techniques.Keys)
    defender_realtime_disabled=$defenderOff
} | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $HostFolder 'IOCs.json') -Encoding UTF8

# -- ATT&CK Navigator layer (attck_navigator_layer.json) ----------------------
# Exports a Navigator v4.9 compatible JSON layer for the techniques observed.
# Open at https://mitre-attack.github.io/attack-navigator/ to visualise coverage.
$navTechniques = @($techniques.Keys | ForEach-Object {
    $tid = $_
    [ordered]@{
        techniqueID = $tid
        tactic      = $null          # Navigator resolves tactic from technique ID
        score       = 1              # 1 = observed
        color       = ''
        comment     = "Observed in $IncidentId"
        enabled     = $true
        metadata    = @()
        links       = @()
        showSubtechniques = $false
    }
})
[ordered]@{
    name        = "IR Toolkit - $IncidentId"
    versions    = [ordered]@{ attack = '14'; navigator = '4.9'; layer = '4.5' }
    domain      = 'enterprise-attack'
    description = "ATT&CK techniques observed during $IncidentId on $HostName. Generated $(((Get-Date).ToUniversalTime().ToString('s')) + 'Z')."
    filters     = [ordered]@{ platforms = @('Windows','Linux','macOS','Cloud') }
    sorting     = 0
    layout      = [ordered]@{ layout = 'side'; aggregateFunction = 'average'; showID = $true; showName = $true; showAggregateScores = $false; countUnscored = $false }
    hideDisabled = $false
    techniques  = $navTechniques
    gradient    = [ordered]@{ colors = @('#ff6666','#ffe766','#8ec843'); minValue = 0; maxValue = 1 }
    legendItems = @()
    metadata    = @()
    links       = @()
    showTacticRowBackground = $false
    tacticRowBackground     = '#dddddd'
    selectTechniquesAcrossTactics = $false
    selectSubtechniquesWithParent = $false
} | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $HostFolder 'attck_navigator_layer.json') -Encoding UTF8

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
    $tools = ($rats | ForEach-Object { $_['tool'] } | Sort-Object -Unique) -join ', '
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
# Memory YARA hits are OPEN LEADS until each is verified by the enriched follow-up (Phase 3b) -
# never report this host "clean / no eradication" while unverified memory leads exist.
$yaraMem = @($findings | Where-Object { (Field $_ @('Type')) -in @('YARA Match (Memory)','Injected Code (memory YARA)') })
$md.Add("## 3. True-positive-class findings"); $md.Add("")
if ($tp.Count) {
    $md.Add("| Verdict | Conf | Type | Target | Subject |"); $md.Add("|---|---|---|---|---|")
    foreach ($f in $tp) {
        $subj=(Field $f @('SubjectPath')) -replace '\|','\|'
        $md.Add("| $(Field $f @('Verdict')) | $(Field $f @('Confidence')) | $(Field $f @('Type')) | $(Field $f @('Target')) | ``$subj`` |")
    }
} elseif ($yaraMem.Count) {
    $md.Add("No findings cleared the **live** adjudication bar - but **$($yaraMem.Count) memory YARA hit(s) are OPEN LEADS**, not yet verified. This host is **NOT clean** until each is resolved: see *YARA matches by process* below and ``YARA_Pivot_Report.md`` (true-positive-class = review first), then run the enriched follow-up on every flagged PID (WORKFLOW-WINDOWS Phase 3b).")
} else { $md.Add("No true-positive-class findings. **No eradication required.**") }
$md.Add(""); $md.Add("---"); $md.Add("")

# -- Memory YARA matches, clustered per process (rule + VAD context per PID) ----
# A process can match several rules; collapse to one row per PID. Each rule carries
# the VAD context (anon-exec = injected/unbacked -> real; file-backed -> verify signature)
# so an injected-code hit is distinguishable from a rule grazing a loaded DLL.
if ($yaraMem.Count) {                                     # $yaraMem computed in section 3 above
    $clusters = [ordered]@{}
    foreach ($f in $yaraMem) {
        $tgt = Field $f @('Target')                       # "PID 1234 (proc.exe)"
        if (-not $clusters.Contains($tgt)) {
            $clusters[$tgt] = [System.Collections.Generic.List[string]]::new()
        }
        # Details = "Rule: <rule> | <n> match(es) | <context>"
        $d = Field $f @('Details')
        $rule = ([regex]::Match($d, 'Rule:\s*([^|]+?)\s*\|')).Groups[1].Value.Trim()
        $ctx  = ([regex]::Match($d, 'match\(es\)\s*\|\s*(.+)$')).Groups[1].Value.Trim()
        if (-not $rule) { $rule = ([regex]::Match($d, 'Rule:\s*(.+)$')).Groups[1].Value.Trim() }
        [void]$clusters[$tgt].Add($(if ($ctx) { "$rule ($ctx)" } else { $rule }))
    }
    $md.Add("## YARA matches by process (memory) - OPEN LEADS"); $md.Add("")
    $md.Add("$($yaraMem.Count) match(es) across $($clusters.Count) process(es), clustered per PID. Context: **anon-exec = injected/unbacked code** (real); file-backed = verify signature/hash."); $md.Add("")
    $md.Add("> **These are leads, not verdicts - nothing here is suppressed.** Each PID must be verified by the enriched follow-up before it is cleared or eradicated: ``YARA_Pivot_Report.md`` ranks them (true-positive-class = review first), then enrich each flagged PID and read its footprint -"); $md.Add("")
    $md.Add("``````powershell")
    $md.Add(".\tools\memprocfs\python\python.exe .\playbooks\windows\threat_hunting\memory_enrich.py <image> .\$HostName <pid1>,<pid2>")
    $md.Add("Get-Content .\$HostName\Memory_Enrichment.md   # recovered handles/regions/C2 per PID -> verdict")
    $md.Add("``````")
    $md.Add("See **WORKFLOW-WINDOWS.md Phase 3b** for how to read each PID's enrichment into a verdict (incl. tooling/self-reference traps)."); $md.Add("")
    $md.Add("| Process (PID) | Hits | Rule (VAD context) |"); $md.Add("|---|---:|---|")
    foreach ($k in ($clusters.Keys | Sort-Object { $clusters[$_].Count } -Descending)) {
        $rules = ($clusters[$k] | Select-Object -Unique) -join '; '
        $md.Add("| $k | $($clusters[$k].Count) | $rules |")
    }
    $md.Add(""); $md.Add("---"); $md.Add("")
}

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
if ($rats.Count) { $md.Add("Tool        : " + (($rats | ForEach-Object { $_['tool'] } | Sort-Object -Unique) -join ', ')) }
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

# -- YARA_Pivot_Report.md (separate report) ------------------------------------
# Pivot each memory YARA hit and rank by TRUE-POSITIVE confidence (parity with
# generate_reports.py correlate_yara_pivots): a named malware/APT-family signature, multiple
# distinct rules on one PID, or a hit in injected/unbacked memory each raise it; a lone generic
# rule (even with a path-spoof, which is FP-prone) stays 'investigate'. Nothing is suppressed.
$yaraTypes = @('YARA Match (Memory)','Injected Code (memory YARA)')
$injClass  = @('Injected Memory Region','Shellcode Thread (Memory)','Known Offensive Tool (Memory)','Hidden Process (Memory)')
$genericRuleRe = '(?i)^(LOLBin|Hunting|Suspicious|Generic|Anomaly|PUA|Indicator|Heuristic|Heur|Method|SUSP|Tool|Multi|Capability)[_.]'
$sevRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
$byPid = [ordered]@{}
foreach ($f in $findings) {
    $blob = "$(Field $f @('Target')) $(Field $f @('Details'))"
    $pm = [regex]::Match($blob, '\bPID (\d+)')
    if ($pm.Success) {
        $pid_ = $pm.Groups[1].Value
        if (-not $byPid.Contains($pid_)) { $byPid[$pid_] = [System.Collections.Generic.List[object]]::new() }
        [void]$byPid[$pid_].Add($f)
    }
}
$pivots = [System.Collections.Generic.List[object]]::new()
foreach ($pid_ in $byPid.Keys) {
    $group = $byPid[$pid_]
    $yara = @($group | Where-Object { (Field $_ @('Type')) -in $yaraTypes })
    if (-not $yara.Count) { continue }                     # only pivot on PIDs with a YARA hit
    $types = @($group | ForEach-Object { Field $_ @('Type') } | Sort-Object -Unique)
    $procM = [regex]::Match("$(Field $group[0] @('Target'))", '\bPID \d+ \(([^)]+)\)')
    $proc = if ($procM.Success) { $procM.Groups[1].Value } else { '' }
    $rules = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $yara) {
        $d = Field $f @('Details')
        $r = ([regex]::Match($d, 'Rule:\s*([^|]+?)\s*\|')).Groups[1].Value.Trim()
        if (-not $r) { $r = ([regex]::Match($d, 'Rule:\s*(.+)$')).Groups[1].Value.Trim() }
        if ($r -and -not $rules.Contains($r)) { [void]$rules.Add($r) }
    }
    $named = @($rules | Where-Object { $_ -notmatch $genericRuleRe })
    $injected = [bool](@($yara | Where-Object { (Field $_ @('Type')) -eq 'Injected Code (memory YARA)' -or (Field $_ @('Details')) -match 'anon-exec' }).Count)
    $injSig = @($types | Where-Object { $injClass -contains $_ })
    $otherStrong = @($types | Where-Object { $_ -notin $yaraTypes -and $injClass -notcontains $_ -and $_ -eq 'Process Path Spoofing (Memory)' })
    $signals = @($group | Where-Object { (Field $_ @('Type')) -notin $yaraTypes })
    # confidence score - what makes this a likely TRUE positive
    $score = 0; $reasons = [System.Collections.Generic.List[string]]::new()
    if ($named.Count)   { $score += 3; [void]$reasons.Add("named malware/APT signature ($($named -join ', '))") }
    if ($rules.Count -ge 2) { $score += 2; [void]$reasons.Add("$($rules.Count) distinct rules corroborate on one PID") }
    if ($injected)      { $score += 3; [void]$reasons.Add("hit lands in injected/unbacked executable memory") }
    if ($injSig.Count)  { $score += 3; [void]$reasons.Add("co-occurs with injection evidence ($($injSig -join ', '))") }
    if ($otherStrong.Count) { $score += 1; [void]$reasons.Add("co-occurs with $($otherStrong -join ', ')") }
    $isTp = ($score -ge 3)
    $pvSev = ($group | ForEach-Object { Field $_ @('Severity') } | Where-Object { $_ } |
            Sort-Object { $sevRank[$_] } | Select-Object -First 1)
    if (-not $pvSev) { $pvSev = 'High' }
    [void]$pivots.Add([pscustomobject]@{
        Pid = $pid_; Proc = $proc; Rules = $rules; Named = $named; Signals = $signals;
        Severity = $pvSev; Score = $score; Reasons = $reasons; TruePositive = $isTp
    })
}
if ($pivots.Count) {
    $pivots = @($pivots | Sort-Object @{E={if($_.TruePositive){0}else{1}}}, @{E={-$_.Score}}, @{E={$sevRank[$_.Severity]}})
    $tps = @($pivots | Where-Object { $_.TruePositive })
    $yp = [System.Collections.Generic.List[string]]::new()
    $yp.Add("# Memory YARA - Hit Pivot & Eradication Scope - $HostName"); $yp.Add("")
    $yp.Add("**Incident:** $IncidentId * **Host:** $HostName * **Generated:** $(Get-Date -Format 'yyyy-MM-dd')"); $yp.Add("")
    $yp.Add("$($pivots.Count) process(es) with a memory YARA hit * **$($tps.Count) true-positive-class** (review/eradicate first)."); $yp.Add("")
    $yp.Add("> Ranked by **true-positive confidence** from hit quality - a named malware/APT-family signature, multiple distinct rules on one PID, or a hit in injected/unbacked memory each raise it; a lone generic/LOLBin rule (even alongside a path-spoof, which is FP-prone) stays *investigate*. **Nothing is suppressed** - lower-confidence hits are ranked below, not hidden."); $yp.Add("")
    $yp.Add("---"); $yp.Add("")
    foreach ($p in $pivots) {
        $tag = if ($p.TruePositive) { " - **Likely True Positive**" } else { " - _investigate_" }
        $title = "PID $($p.Pid)" + $(if ($p.Proc) { " ($($p.Proc))" } else { "" })
        $yp.Add("## $title$tag"); $yp.Add("")
        $tier = if ($p.TruePositive) { 'true-positive-class' } else { 'investigate' }
        $yp.Add("- **Confidence:** $($p.Score) ($tier)  *  **Severity:** $($p.Severity)  *  **YARA rules:** $($p.Rules.Count)")
        $ruleList = if ($p.Rules.Count) { ($p.Rules | ForEach-Object { "``$_``" }) -join ', ' } else { '(unparsed)' }
        $namedTxt = if ($p.Named.Count) { "  *  **named:** " + (($p.Named | ForEach-Object { "``$_``" }) -join ', ') } else { '' }
        $yp.Add("- **Rules matched:** $ruleList$namedTxt"); $yp.Add("")
        if ($p.Reasons.Count) {
            if ($p.TruePositive) { $yp.Add("**Why true-positive-class:** $(($p.Reasons) -join '; ').") }
            else { $yp.Add("**Signal:** $(($p.Reasons) -join '; ') - not yet confirmed.") }
            $yp.Add("")
        }
        if ($p.Signals.Count) {
            $yp.Add("**Other memory signals on this PID:**"); $yp.Add("")
            $yp.Add("| Signal | Detail |"); $yp.Add("|---|---|")
            foreach ($s in $p.Signals) {
                $det = (Field $s @('Details')) -replace '\|','/'
                $yp.Add("| $(Field $s @('Type')) | $det |")
            }
            $yp.Add("")
        }
        if ($p.TruePositive) {
            $yp.Add("**Eradication scope - enrich this PID:** pull handles (dropped files, registry persistence, mutexes, named pipes), loaded/injected modules, network endpoints (C2 to block), process lineage, and carve the matched region for offline C2-config extraction. See ``Memory_Enrichment_*.json`` for this PID's full footprint."); $yp.Add("")
        }
        $yp.Add("---"); $yp.Add("")
    }
    $yp.Add("_Hit-context detail (region / perms / backing path / matched strings) is in ``Memory_Findings_*.json``; per-PID clustering is also summarized in ``Incident_Report.md`` section 5._"); $yp.Add("")
    $yp -join "`n" | Out-File -FilePath (Join-Path $HostFolder 'YARA_Pivot_Report.md') -Encoding UTF8
    Write-Host "[+] YARA_Pivot_Report.md  ($($pivots.Count) hit PID(s), $($tps.Count) true-positive-class)" -ForegroundColor Green
    # Machine-readable TP PID list so the workflow can auto-run per-PID memory enrichment.
    if ($tps.Count) {
        $tpOut = @($tps | ForEach-Object { [ordered]@{ pid = [int]$_.Pid; proc = $_.Proc; score = $_.Score; rules = @($_.Rules) } })
        ConvertTo-Json @($tpOut) -Depth 5 | Out-File -FilePath (Join-Path $HostFolder 'YARA_Pivot_TP.json') -Encoding UTF8
    }
}

# Refresh _status.json so the machine-readable status agrees with the report: memory YARA leads
# flagged true-positive-class still NEED INVESTIGATION (not clean) until each is verified by the
# enriched follow-up. Additive update ($pivots is always defined); the orchestrator owns the rest.
$needsInv = @($pivots | Where-Object { $_.TruePositive }).Count
$statusPath = Join-Path $HostFolder '_status.json'
if (Test-Path -LiteralPath $statusPath) {
    try {
        $st = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        $st | Add-Member -NotePropertyName needs_investigation -NotePropertyValue $needsInv -Force
        $st | ConvertTo-Json -Depth 6 | Out-File -FilePath $statusPath -Encoding UTF8
    } catch {}
}

# -- Attack_Graph.md -----------------------------------------------------------
# Design: cluster findings by LOCATION (parent directory or process family) so
# each node represents a coherent event. Findings are pre-filtered to focus on
# high-signal types. Clusters are scored, noise-filtered, and capped at 12 nodes.

# Finding types included in the graph (ordered by IR signal value).
# ADS without context (Zone.Identifier) is noise; only include ADS if in a
# high-risk location. Timestomped is only interesting in non-vendor paths.
$graphPriorityTypes = @(
    'LOLBin Execution','Remote Access Tool','Hidden Process',
    'AMSI Tampering','ETW Tampering','AMSI Disabled',
    'Suspicious BITS Job','WMI Persistence','IFEO Debugger Hijack',
    'AppInit_DLLs Hijack','Suspicious Service','Suspicious Registry Key',
    'Suspicious Scheduled Task','PendingFileRenameOperations',
    'COM Hijacking','Reflective DLL Injection','Suspicious Injected DLL',
    'Suspicious Command Line','Malicious PowerShell Script Block',
    'LOLBin Obfuscated Execution','Security Log Cleared','System Log Cleared',
    'New Account Created','Brute Force Attempt','Explicit Credential Use',
    'Suspicious Task Created','Suspicious Task Modified','Suspicious Service Install',
    'High Entropy File','Timestomped File','Alternate Data Stream','YARA Match'
)
# Attack graph cluster exclusions - ONLY paths that are impossible attack vectors.
# PRINCIPLE (tuning review 2026-06-21): supply chain paths (node_modules, site-packages,
# NuGet, $Recycle.Bin, .cargo, .nuget, chocolatey), GPU vendor dirs, IDE extension caches,
# and package manager trees are NOT filtered here - these are all real attack surfaces.
# Attackers actively use them for staging, supply-chain compromise, and LOLBin hijacking.
# The full finding set is always in Incident_Report.md; this filter only affects graph layout.
$noisePathPattern = '(?i)(' +
    # .NET SDK/runtime library trees - build-pipeline timestamps by design; CLR-managed
    '\\lib\\net(?:standard)?\d|\\ref\\net(?:standard)?\d|\\runtimes\\win|' +
    '\\dotnet\\shared\\|\\dotnet\\sdk\\|\\dotnet\\packs\\|' +
    # .NET Global Assembly Cache - CLR-managed; requires kernel-level access to tamper
    'Windows\\assembly\\|' +
    # Versioned framework locale subdirs: \4.8.1\de, \10.0.8\zh-Hans - locale resource DLLs
    '\\\d+\.\d+[\.\d]*\\[a-z]{2}(-[A-Za-z]{2,6})?$)'

# Score a cluster for analyst interest
function Get-ClusterScore {
    param([string]$Key, [System.Collections.Generic.List[object]]$Findings)
    $score = 0
    foreach ($f in $Findings) {
        $ftype = Field $f @('Type')
        $idx   = [array]::IndexOf($graphPriorityTypes, $ftype)
        # High-priority types score more; types not in list score 0
        if ($idx -ge 0) { $score += [math]::Max(1, $graphPriorityTypes.Count - $idx) }
    }
    # Location multipliers
    if ($Key -match '(?i)(Desktop|Downloads|Public|AppData\\Local\\Temp|Windows\\Temp)') { $score *= 4 }
    elseif ($Key -match '(?i)(AppData\\Roaming|AppData\\Local)') { $score *= 2 }
    elseif ($Key -match '(?i)(ProgramData\\(?!Microsoft))') { $score *= 3 }
    # Multiple distinct finding types = more interesting
    $distinct = @($Findings | ForEach-Object { Field $_ @('Type') } | Select-Object -Unique).Count
    if ($distinct -gt 1) { $score *= $distinct }
    return $score
}

# Derive a cluster key from a finding target.
# File-based: use the meaningful ancestor (2-3 levels from a known root).
function Get-ClusterKey([string]$Target, [string]$FType) {
    # Returns the FULL parent path (for noise-pattern matching and dedup).
    # Display shortening happens in the node-label building step, not here.
    if ($Target -match '^[A-Za-z]:\\' -or $Target -match '^\\\\') {
        try { return Split-Path $Target -Parent } catch { return $Target }
    } elseif ($Target -match 'PID:\s*\d+\s+\(([^)]+)\)') { return "PROC:$($Matches[1])" }
    elseif ($Target -match 'PID:\s*\d+')                  { return 'PROC:Unknown' }
    elseif ($Target -match '^\{[0-9A-Fa-f\-]{36}\}')      { return 'PERSIST:COM' }
    elseif ($Target -match '^Job:')                        { return 'PERSIST:BITS' }
    elseif ($Target -match '^Task:')                       { return 'PERSIST:Tasks' }
    elseif ($Target -match '^(WMI|Event)')                 { return 'PERSIST:WMI' }
    else                                                    { return $FType }
}

function Format-ClusterLabel([string]$Key) {
    # Shorten a full path to the last 2 meaningful components for Mermaid display.
    if ($Key -match '^(PROC:|PERSIST:|[A-Z]:)') {
        if ($Key -notmatch '^[A-Za-z]:\\') { return $Key -replace '^(PROC:|PERSIST:)','' }
        $parts = $Key.TrimEnd('\') -split '\\'
        if ($parts.Count -gt 3) { return '...\' + ($parts[-2..-1] -join '\') }
        return $Key
    }
    return $Key
}

# Pre-filter: only graph-worthy finding types; skip ADS that are just Zone.Identifier
$graphFindings = @($tp | Where-Object {
    $ftype   = Field $_ @('Type')
    $details = Field $_ @('Details')
    $target  = Field $_ @('Target')
    if ($ftype -notin $graphPriorityTypes) { return $false }
    # Suppress pure Zone.Identifier ADS - they're web download markers, not malicious
    if ($ftype -eq 'Alternate Data Stream' -and $details -match 'Zone.Identifier') { return $false }
    # Suppress ADS in VS Code / package manager paths
    if ($ftype -eq 'Alternate Data Stream' -and
        $target -match '(?i)(AppData\\Roaming\\Code|\.cargo|\.nuget|AppData\\Local\\Microsoft)') { return $false }
    return $true
})

# Build location clusters from the pre-filtered, graph-worthy findings
$clusters = [ordered]@{}
foreach ($f in $graphFindings) {
    $target     = Field $f @('Target')
    $ftype      = Field $f @('Type')
    $clusterKey = Get-ClusterKey -Target $target -FType $ftype

    if (-not $clusters.Contains($clusterKey)) {
        $clusters[$clusterKey] = [System.Collections.Generic.List[object]]::new()
    }
    $clusters[$clusterKey].Add($f)
}

# Score, filter noise, and select top 15 clusters
$maxNodes = 15
$scoredClusters = foreach ($key in $clusters.Keys) {
    $items = $clusters[$key]
    if ($key -match $noisePathPattern) { continue }   # drop known-noise paths
    $score  = Get-ClusterScore -Key $key -Findings $items
    $tactic = Get-GraphTactic $items[0]
    $ti     = [array]::IndexOf($TacticOrder, $tactic); if ($ti -lt 0) { $ti = $TacticOrder.Count }
    # Earliest timestamp across cluster members
    $earliest = [datetime]::MaxValue
    foreach ($item in $items) {
        $tv = Field $item @('Timestamp')
        if ($tv) { try { $t = [datetime]$tv; if ($t -lt $earliest) { $earliest = $t } } catch {} }
    }
    [pscustomobject]@{ Key=$key; Items=$items; Score=$score; Tactic=$tactic; TI=$ti; Earliest=$earliest }
}
$topClusters = @($scoredClusters | Sort-Object TI, @{E='Score';D=$true} | Select-Object -First $maxNodes)

# Build graph nodes and tactic subgraph map
$g = [System.Collections.Generic.List[string]]::new()
$g.Add("# $HostName - Attack Graph"); $g.Add("")
$g.Add("**Incident:** $IncidentId  |  **Host:** $HostName  |  **Severity:** $severity"); $g.Add("")
$g.Add("Each node = one correlated event cluster (location or process family). Edges show causal/temporal flow through the kill chain. Full findings in EDR_Report CSV/JSON."); $g.Add("")
$g.Add('```mermaid'); $g.Add('flowchart TD')
$g.Add('    classDef host fill:#0f766e,stroke:#5eead4,color:#fff;')
$g.Add('    classDef c2   fill:#991b1b,stroke:#fde047,color:#fff,stroke-width:3px;')
$g.Add('    classDef inferred fill:#1f2937,stroke:#9ca3af,color:#e5e7eb,stroke-dasharray:4 3;')

$presentTactics = @()
$tacticNodes    = [ordered]@{}
$nodeCounter    = 0
$c2anchor       = 'H'
$lastNodeId     = 'H'
$clusterNodeMap = @{}   # clusterKey -> nodeId (for edge building)

foreach ($cl in $topClusters) {
    $items  = $cl.Items
    $count  = $items.Count
    $tactic = $cl.Tactic
    $key    = $cl.Key

    # Distinct finding types in this cluster
    $types = @($items | ForEach-Object { Field $_ @('Type') } | Select-Object -Unique)

    # Human-readable display label - full key used for noise matching, shortened here
    $keyLabel = Format-ClusterLabel -Key $key

    # MITRE from most-represented type
    $topType = ($items | Group-Object { Field $_ @('Type') } | Sort-Object Count -Descending | Select-Object -First 1).Name
    $mitreSample = $items | Where-Object { (Field $_ @('Type')) -eq $topType } | Select-Object -First 1
    $mitre = (([regex]::Matches((Field $mitreSample @('MITRE')),'T\d{4}(?:\.\d{3})?') |
        ForEach-Object { $_.Value }) | Select-Object -First 2) -join '/'

    $typesSummary = if ($types.Count -gt 2) {
        "$($types[0]), $($types[1]) +$($types.Count - 2) more"
    } else { $types -join ', ' }

    $nodeLabel = "$(Format-GLabel $keyLabel)<br/>$count finding$(if($count -ne 1){'s'}): $(Format-GLabel $typesSummary)$(if($mitre){"<br/><i>$mitre</i>"})"
    $nodeCounter++
    $nid = "E$nodeCounter"
    $clusterNodeMap[$key] = $nid

    if (-not $tacticNodes.Contains($tactic)) { $tacticNodes[$tactic] = [System.Collections.Generic.List[string]]::new() }
    $tacticNodes[$tactic].Add("    $nid[""$nodeLabel""]:::$(Get-TacticClass $tactic)")
    if ($tactic -eq 'Command and Control') { $c2anchor = $nid }
    $lastNodeId = $nid
    if ($presentTactics -notcontains $tactic) { $presentTactics += $tactic }
}

# Emit tactic class styles
foreach ($t in $presentTactics) {
    $st = $TacticStyle[$t]; if (-not $st) { $st='#374151,#9ca3af' }
    $p = $st.Split(',')
    $g.Add("    classDef $(Get-TacticClass $t) fill:$($p[0]),stroke:$($p[1]),color:#fff;")
}
$g.Add('')
$g.Add("    H([""HOST: $(Format-GLabel $HostName)""]):::host")
$g.Add('')

# Emit subgraphs per tactic in kill-chain order
$subgraphAnchors = [ordered]@{}
foreach ($tactic in $TacticOrder) {
    if (-not $tacticNodes.Contains($tactic)) { continue }
    $safeId = 'SG_' + ($tactic -replace '[^a-zA-Z0-9]','_')
    $g.Add("    subgraph $safeId [""$tactic""]")
    $firstInGroup = $true
    foreach ($nodeLine in $tacticNodes[$tactic]) {
        $g.Add($nodeLine)
        if ($firstInGroup) {
            $nidMatch = [regex]::Match($nodeLine,'(E\d+)')
            if ($nidMatch.Success) { $subgraphAnchors[$tactic] = $nidMatch.Value }
            $firstInGroup = $false
        }
    }
    $g.Add("    end"); $g.Add('')
}

if (-not $topClusters.Count) {
    $g.Add('    N0["No confirmed findings - see Retrospective.md"]:::inferred')
    $g.Add('    H --- N0')
} else {
    # Connect HOST -> first tactic -> next tactic -> ... (kill-chain spine)
    $prevAnchor = 'H'
    foreach ($tactic in $TacticOrder) {
        if ($subgraphAnchors.Contains($tactic)) {
            $g.Add("    $prevAnchor --> $($subgraphAnchors[$tactic])")
            $prevAnchor = $subgraphAnchors[$tactic]
        }
    }
    # Connect clusters within the same tactic sequentially by time
    foreach ($tactic in $TacticOrder) {
        $clInTactic = @($topClusters | Where-Object { $_.Tactic -eq $tactic } | Sort-Object Earliest)
        for ($ci = 1; $ci -lt $clInTactic.Count; $ci++) {
            $prevId = $clusterNodeMap[$clInTactic[$ci-1].Key]
            $curId  = $clusterNodeMap[$clInTactic[$ci].Key]
            if ($prevId -and $curId) { $g.Add("    $prevId --> $curId") }
        }
    }
}

# Build narrative section from top clusters
$narrative = [System.Collections.Generic.List[string]]::new()
$narrative.Add("## Attack Narrative"); $narrative.Add("")
$step = 1
foreach ($cl in $topClusters | Sort-Object TI, @{E='Score';D=$true} | Select-Object -First 8) {
    $types    = @($cl.Items | ForEach-Object { Field $_ @('Type') } | Select-Object -Unique)
    $count    = $cl.Items.Count
    $key      = $cl.Key
    $tactic   = $cl.Tactic
    $keyShort = Format-ClusterLabel -Key $key
    $mitreSample = $cl.Items | Select-Object -First 1
    $mitre = (([regex]::Matches((Field $mitreSample @('MITRE')),'T\d{4}(?:\.\d{3})?') |
        ForEach-Object { $_.Value }) | Select-Object -First 1)
    $narrative.Add("**$step. $tactic$(if($mitre){" ($mitre)"})** - ``$keyShort``")
    $narrative.Add("$count finding$(if($count -ne 1){'s'}): $($types -join ', ')."); $narrative.Add("")
    $step++
}

# C2 relay nodes
if ($c2anchor -eq 'H') { $c2anchor = $lastNodeId }
$ci = 0
foreach ($r in $relays) {
    $tag  = if (Test-Sanctioned $r.host) { 'sanctioned' } else { 'adversary relay' }
    $port = if ($r.port) { ":$($r.port)/TCP" } else { '' }
    $g.Add("    C$ci([""C2$port<br/><b>$(Format-GLabel $r.host)</b><br/>$tag""]):::c2")
    $g.Add("    $c2anchor ==>|egress| C$ci")
    $ci++
}

$g.Add('```'); $g.Add('')

# Append narrative after the diagram
foreach ($line in $narrative) { $g.Add($line) }

$custom0 = @($relays | Where-Object { -not (Test-Sanctioned $_.host) })
if ($custom0.Count) {
    $r=$custom0[0]
    $g.Add("## C2 Path"); $g.Add("")
    $g.Add("The remote-access client beacons to **``$($r.host):$($r.port)``** - a custom relay rather than a vendor-sanctioned endpoint, proving an adversary-operated deployment. Block at egress before reconnecting the host."); $g.Add("")
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
Write-Host "[+] IOCs.json  ($($relays.Count) C2 relay(s))" -ForegroundColor Gree

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOgDt5TTFSoXep
# QLOaT9c8giM73RuwFH2UhkET4/Ub06CCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgXlwYVR0ydYOLLdbsUybP98nc3gwZl7xLiWYd
# UqbywBwwDQYJKoZIhvcNAQEBBQAEggEAbg4so9ayoQxOaftiMvKets2FMWHC8xvA
# PZNWGDhjOWAyPV3hilsw7bhFH2+nKIM4fT+qG5tbeAmQEDoqTkpN7mh9LDkt5hEE
# T15Lb1C2+DA0IeltAwxJ7WF+Me2c7pvg+elUSI/cgwtBlytrzf0/RwM7Nv8Uf4vG
# Hh/3JAWpiTyelXJd/KVS3xZjWD2zjOHLDgkSrbBsW5Cy5ZK6EVXllJUFbKOhm5rk
# 862XAkoX8oPdwPap1L3j1TnGa2rwK9mQCRB5KwehUy8st16Rlihp24d4eqSWRNS2
# Rref/VI7KZr4OTSHH5VZxHqbcuPjPs3TTxrGhupDIoeCXJNG/4Pg/6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MTZaMC8GCSqGSIb3DQEJBDEiBCBd
# Qy45/uNg2dYz0lpIIusUXU4jehdSNwmv+XsP6phm3jANBgkqhkiG9w0BAQEFAASC
# AgBZ5u1NFzcu5w86SSgn1Z/sr5zNjg+Osvu2eGiNYws5J6uThXqDBpD3w8ughmwg
# UUdHuI17gEe8CCFmxyvrgoebBXTbAgE/9ft2HZAYbjThyA/nMoWRQrLYph4LkKiP
# 1ezFKIeCE5+zc3h/tu1ULNW2/QcsTzWvSCpo0SpB9fvSsFbMEihiTaQHWVniKWQJ
# qh9hJRQRqqXavCiE6Q3Cgt1cG+wOZ7oGSfiPkr9BQs3X6fabvn4yJA98CABRJGgF
# SlTsqQJHfim0Ya4uYpBnOCb9yJJCuWU872WYREUiyaPGuxHtxPUTrSY8JYpblJlT
# 5eWbpAEfK/QyqCOUQMzdPzYDsda0BIFRtyNGV/uNrclL23i7e/E8BLC5e+eOJSWv
# D56964EMWxuhEfz//nN4DofwRPSVJ7gTwaxFlp27lbw5wijghrOSAUgSNMOGVatE
# aCnM97USOfWo6TCxe/mWQGyoloa1q71SnGv4aAcVw4Or+d5KbW+pBDRtpFClxxvF
# bHoDo9HR9IK2IsCI2C/P9oyfpsvhPRc5UKoOtKfmUP4PWVNUS3FrChKssKYdgpc9
# EeS/7zYElUS/WUZ/ZMHgwTDC/pOPHpTjij3lKpsNlUH2O6B+g+N7qkAec0lGJK4B
# LAYfjMjjvZpmlMrjCMMFD8n21QXP+K+d+AQMANmlcCrgxA==
# SIG # End signature block
