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
$md.Add("## 3. True-positive-class findings"); $md.Add("")
if ($tp.Count) {
    $md.Add("| Verdict | Conf | Type | Target | Subject |"); $md.Add("|---|---|---|---|---|")
    foreach ($f in $tp) {
        $subj=(Field $f @('SubjectPath')) -replace '\|','\|'
        $md.Add("| $(Field $f @('Verdict')) | $(Field $f @('Confidence')) | $(Field $f @('Type')) | $(Field $f @('Target')) | ``$subj`` |")
    }
} else { $md.Add("No true-positive-class findings. **No eradication required.**") }
$md.Add(""); $md.Add("---"); $md.Add("")

# -- Memory YARA matches, clustered per process (rule + VAD context per PID) ----
# A process can match several rules; collapse to one row per PID. Each rule carries
# the VAD context (anon-exec = injected/unbacked -> real; file-backed -> verify signature)
# so an injected-code hit is distinguishable from a rule grazing a loaded DLL.
$yaraMem = @($findings | Where-Object { (Field $_ @('Type')) -in @('YARA Match (Memory)','Injected Code (memory YARA)') })
if ($yaraMem.Count) {
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
    $md.Add("## YARA matches by process (memory)"); $md.Add("")
    $md.Add("$($yaraMem.Count) match(es) across $($clusters.Count) process(es), clustered per PID. Context: **anon-exec = injected/unbacked code** (real); file-backed = verify signature/hash."); $md.Add("")
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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDveRfD9POeniob
# N5zQzgG34akFkdNN+tx3ouF8n0ixwKCCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg5seL9IPD2ed1y2KmkMy7OhVD8HF1Bsb5
# oU1bhYi4iXIwDQYJKoZIhvcNAQEBBQAEggEAi6BGTF4Ij23Hoh3gjpw9gLE0a5ZJ
# +hCnn3yRx5fwvgnm+qF0w2bQPQBf+9SuCbyjzOBLvIT3mEqfmG3mQO56VYD072pQ
# 8HjPZa1h/5Fav+2ipZ4CJnpAymfj6AmwKLD9KdmKjRZEBRCu1d72wj+xuknjAEZi
# Mi/22VxkOJNrA3ycPhOotKkKQYOILdfM4G/oOgiHduuCwnrD4I1w6xUkXL3vxG+q
# ILYwIsTYgoirqFPoljFrkphIiHaEA4qfRjYKPZmSZDhAPq82HCxpNJKv85fTOWLa
# EXkpR97F+ySZJaszSw+Cd1fMyTwdDuDRH/Cn7oub/W0QvZ7Bu+icA525u6GCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1MjFaMC8GCSqGSIb3DQEJBDEi
# BCAYw11zOCOsn2//J/FwTMgLZUmeR4JgYgw+7x6aZXUV8DANBgkqhkiG9w0BAQEF
# AASCAgCkQyOOuURuuzVp0QhLAminz3XmFtL3x5iQq71Qc5qf75NWTo2Ptgn2PV4W
# +uBZWDHQ0szVe7Vu0/+KD0JdmvbaOwgDPS8M3gvvYu3Jp2STy2saE43uGx1r9zZw
# h++2CfDH4KJFnHiYy10Vpoie5sjLiYCYr7e5Ewwl5LUdU30v/5s0CyteDS1tPez+
# tElH6pkV9ohuc4Idzh8HptVRNP0sidBFZmrnV6cogi/tb4CyU9XDNCuqK9SB8cZ2
# AnNzQ/J2ZQ1SKVeExOMHBSiUAX2yPZw684s6mTONmjf6aYtcP+YgX7oMgaC5kj96
# J9ii+WiMi6iPWwngzXG442sx6+VNwZQZ3us+TRj3lv2Izxe9rFRaJQFxkjO8x35d
# Bv/Kn13tigvSkng/wSyOZVNG4/IVFbUa5dBZ0ocAPgTuaZBIvLdUy1OpRE21uvt7
# xsRVN/7sbETWftDmqR+taqEUXQCeDNvOTzck7MC3Q5nCxBWTYRW1YcZlM1HGep0Z
# MKnWoUxCGZhqYxh5W8cvUIfFnbuFhTRxA6VF3JUYxzbekrV+XUuL60IpH0COXcpw
# chxeVmWcP5BOC0NA/6cNa7glW516vQQKk+HwbdVcSeVNkRgdDQRTDltqXcfjxww7
# oKj8KOKx7qyqG8br6bscD9ZyzG04HxKbOz93rNRz6czhyqr9Pg==
# SIG # End signature block
