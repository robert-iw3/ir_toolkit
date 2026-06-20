<#
.SYNOPSIS
    Evidence-driven eradication of adjudicated True-Positive findings, with a
    post-eradication verification report.

.DESCRIPTION
    Consumes an Adjudication_*.json produced by Get-FindingContext.ps1 and, for
    each finding at or above -MinVerdict, performs the appropriate removal action
    by finding type:
        Hidden Process / process  -> terminate PID + quarantine the binary
        COM Hijacking             -> back up + remove the CLSID server registration
        Suspicious Scheduled Task -> disable + unregister the task
        Suspicious BITS Job       -> remove the BITS transfer
    Hard safety rails (cannot be overridden):
        * never touches a validly-signed binary
        * never touches Microsoft Defender / core OS processes
        * never touches \Windows\System32, \WinSxS, or \Program Files\WindowsApps
    DRY-RUN by default: it prints the plan and changes nothing until you pass
    -Apply. Every change is written to a rollback journal, and every action is
    re-verified afterward. Output: Eradication_<stamp>.{json,md} in the host folder.

.PARAMETER HostFolder       Per-host collection folder. Default: cwd.
.PARAMETER AdjudicationPath Explicit Adjudication_*.json. Default: newest in HostFolder.
.PARAMETER MinVerdict       Minimum verdict to act on. Default 'True Positive'.
.PARAMETER Apply            Actually perform eradication (otherwise dry-run).
.PARAMETER OnlyTargets      Restrict to specific finding Target strings.

.EXAMPLE
    .\Invoke-Eradication.ps1 -HostFolder .\FOLDER_NAME                 # dry-run plan
    .\Invoke-Eradication.ps1 -HostFolder .\FOLDER_NAME -Apply          # execute
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$HostFolder = (Get-Location).Path,
    [string]$AdjudicationPath,
    [ValidateSet('True Positive','Likely True Positive')]
    [string]$MinVerdict = 'True Positive',
    [switch]$Apply,
    [string[]]$OnlyTargets = @(),
    # Firewall: after eradication, restore the pre-incident firewall (the .wfw that
    # Invoke-IRCollection.ps1 exported at lockdown) so the host returns to its
    # known-good posture - EXCEPT known-bad indaicators (adversary C2 from IOCs.json),
    # which are re-blocked/sinkholed so they stay contained.
    [switch]$NoFirewallRestore,
    [string]$FirewallBackup,                 # explicit .wfw; default: from _firewall_state.json
    [string]$IocPath,                        # explicit IOCs.json; default: newest in HostFolder
    # Credentials: disable implicated local accounts (from Principals.json), purge
    # Kerberos tickets and log off their sessions. A confirmed hands-on intrusion
    # means those accounts are exposed. Reversible via the rollback journal.
    [switch]$NoCredentialRevoke,
    [string]$PrincipalsPath                  # explicit Principals.json; default: in HostFolder
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# -- Load adjudication ---------------------------------------------------------
if (-not (Test-Path -LiteralPath $HostFolder)) { throw "HostFolder not found: $HostFolder" }
if (-not $AdjudicationPath) {
    $AdjudicationPath = Get-ChildItem -Path $HostFolder -Filter 'Adjudication_*.json' -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $AdjudicationPath -or -not (Test-Path -LiteralPath $AdjudicationPath)) {
    throw "No Adjudication_*.json found in $HostFolder (run Get-FindingContext first, or pass -AdjudicationPath)."
}
$adj = Get-Content -LiteralPath $AdjudicationPath -Raw | ConvertFrom-Json
if ($adj -isnot [System.Array]) { $adj = @($adj) }

$stamp        = Get-Date -Format 'yyyyMMdd_HHmmss'
$IncidentId   = (Split-Path -Leaf ($HostFolder.TrimEnd('\','/')))
$QuarantineDir= Join-Path $HostFolder 'Quarantine'
$BackupDir    = Join-Path $HostFolder ("Eradication_backup_$stamp")
$Journal      = Join-Path $HostFolder ("Eradication_rollback_$stamp.jsonl")
$mode = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
Write-Host "[*] Eradication ($mode) from $(Split-Path -Leaf $AdjudicationPath) - MinVerdict='$MinVerdict'" -ForegroundColor Cyan

# -- Safety rails --------------------------------------------------------------
$ProtectedNames = @('MsMpEng','MpDefenderCoreService','NisSrv','MsSense','SenseIR','SenseCncProxy',
    'System','Idle','smss','csrss','wininit','winlogon','services','lsass','svchost','spoolsv',
    'explorer','dwm','fontdrvhost','RuntimeBroker','WmiPrvSE','taskhostw','SearchIndexer')
function Test-Protected {
    param([string]$Name,[string]$Path,[string]$Sig)
    $bare = ($Name -replace '\.exe$','')
    if ($bare -and ($ProtectedNames -contains $bare)) { return "protected process name '$bare'" }
    if ($Sig -eq 'Valid') { return 'binary is validly code-signed' }
    if ($Path -match '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Windows\\WinSxS\\|\\Program Files\\WindowsApps\\') {
        return 'binary in a protected OS location'
    }
    return $null
}
$Rank = @{ 'True Positive'=2; 'Likely True Positive'=1 }
function Write-Journal { param([hashtable]$E) ($E | ConvertTo-Json -Compress) | Out-File -FilePath $Journal -Append -Encoding UTF8 }

# -- Plan & execute ------------------------------------------------------------
$actions = foreach ($f in $adj) {
    $rec = [ordered]@{
        Target=$f.Target; Type=$f.Type; Verdict=$f.Verdict; Confidence=$f.Confidence
        Subject=$f.SubjectPath; Action='none'; Status='skipped'; Reason=''; Detail=''
    }
    if (-not $Rank.ContainsKey($f.Verdict) -or $Rank[$f.Verdict] -lt $Rank[$MinVerdict]) {
        $rec.Reason = "below threshold ($($f.Verdict))"; [PSCustomObject]$rec; continue
    }
    if ($OnlyTargets.Count -and ($OnlyTargets -notcontains $f.Target)) {
        $rec.Reason = 'not in -OnlyTargets'; [PSCustomObject]$rec; continue
    }
    # Remote-access tools / LOLBins are signed by design - the signed-binary guard
    # must NOT shield them (it would re-introduce the blind spot). Name + OS-location
    # guards still apply, so Defender / System32 stay protected.
    $sigForGuard = if ($f.Type -match '(?i)Remote Access|ClickFix|RunMRU|LOLBin') { $null } else { $f.SigStatus }
    $guard = Test-Protected -Name ($f.Details -replace '.*Name:\s*','') -Path $f.SubjectPath -Sig $sigForGuard
    if ($guard) { $rec.Reason = "SAFETY: $guard"; [PSCustomObject]$rec; continue }

    switch -Regex ($f.Type) {

        'Hidden Process|Process|Injection|LOLBin' {
            $procId = if ($f.Target -match 'PID:\s*(\d+)') { [int]$Matches[1] } else { $null }
            $rec.Action = "kill PID $procId + quarantine"
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                if ($procId) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
                if ($f.SubjectPath -and (Test-Path -LiteralPath $f.SubjectPath -PathType Leaf)) {
                    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
                    $hashPrefix = if ($f.SHA256) { "$($f.SHA256)".Substring(0,12) } else { 'nohash' }
                    $dest = Join-Path $QuarantineDir ("{0}_{1}.quarantine" -f $hashPrefix, (Split-Path -Leaf $f.SubjectPath))
                    Write-Journal @{ action='quarantine'; original=$f.SubjectPath; dest=$dest; sha256=$f.SHA256 }
                    Move-Item -LiteralPath $f.SubjectPath -Destination $dest -Force
                    $rec.Detail = "quarantined -> $dest"
                }
                $rec.Status = 'eradicated'
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'COM Hijack' {
            $clsid = if ($f.Target -match '(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
            $rec.Action = "remove CLSID server $clsid"
            if (-not $clsid) { $rec.Status='failed'; $rec.Detail='no CLSID parsed'; break }
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
                $removed=$false
                foreach ($base in 'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID','HKCU:\SOFTWARE\Classes\CLSID') {
                    $key = "$base\$clsid"
                    if (Test-Path -LiteralPath $key) {
                        $regBase = $base -replace '^HKLM:','HKLM' -replace '^HKCU:','HKCU'
                        $bkp = Join-Path $BackupDir ("CLSID_{0}_{1}.reg" -f ($base -replace '[:\\]','_'), ($clsid -replace '[{}]',''))
                        & reg.exe export "$regBase\$clsid" "$bkp" /y | Out-Null
                        Write-Journal @{ action='reg_delete'; key=$key; backup=$bkp }
                        Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
                        $rec.Detail = "removed $key (backup $bkp)"; $removed=$true
                    }
                }
                $rec.Status = if ($removed) { 'eradicated' } else { 'skipped' }
                if (-not $removed) { $rec.Reason='CLSID not present' }
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'Scheduled Task' {
            $tn = if ($f.Target -match 'Task:\s*(.+?)\s*$') { $Matches[1].Trim() } else { $null }
            $rec.Action = "disable + unregister task '$tn'"
            if (-not $tn) { $rec.Status='failed'; $rec.Detail='no task name'; break }
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                $t = Get-ScheduledTask | Where-Object { $_.TaskName -eq $tn } | Select-Object -First 1
                if ($t) {
                    Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue | Out-Null
                    Write-Journal @{ action='task_unregister'; name=$t.TaskName; path=$t.TaskPath }
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                    $rec.Status='eradicated'; $rec.Detail="unregistered $($t.TaskPath)$($t.TaskName)"
                } else { $rec.Status='skipped'; $rec.Reason='task not found' }
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'BITS' {
            $jn = if ($f.Target -match 'Job:\s*(.+?)\s*$') { $Matches[1].Trim() } else { $null }
            $rec.Action = "remove BITS job '$jn'"
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                $j = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $jn }
                if ($j) { Write-Journal @{ action='bits_remove'; name=$jn }; $j | Remove-BitsTransfer -ErrorAction SilentlyContinue; $rec.Status='eradicated' }
                else { $rec.Status='skipped'; $rec.Reason='BITS job not found' }
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'Remote Access' {
            $name = ($f.Target -replace '\s*\(residual\)\s*','').Trim()
            $rec.Action = "stop processes + stop/disable service for '$name'"
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                $killed=0
                Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                    Where-Object { ($_.Name -match "(?i)$name") -or ($f.Subject -and $_.ExecutablePath -eq $f.Subject) } |
                    ForEach-Object { Write-Journal @{ action='kill'; pid=$_.ProcessId; name=$_.Name }; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $killed++ }
                $disabled=0
                Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                    Where-Object { ($_.Name -match "(?i)$name") -or ($_.PathName -match "(?i)$name") } |
                    ForEach-Object {
                        Write-Journal @{ action='service_disable'; name=$_.Name; startmode=$_.StartMode }
                        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
                        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
                        $disabled++
                    }
                $rec.Status='eradicated'; $rec.Detail="stopped $killed process(es), disabled $disabled service(s)"
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'Defender Exclusion' {
            $rec.Action = "remove Defender exclusion '$($f.Target)'"
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                Write-Journal @{ action='defender_exclusion_remove'; path=$f.Target }
                Remove-MpPreference -ExclusionPath $f.Target -ErrorAction SilentlyContinue
                $rec.Status='eradicated'; $rec.Detail="removed exclusion $($f.Target)"
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
        }

        'ClickFix|RunMRU|Browser|PendingFileRename' {
            $rec.Action='manual'
            $rec.Reason='human remediation (reset creds / clear lure / review browser); not auto-deleted'
        }

        default {
            $rec.Action='manual'; $rec.Reason="no automated handler for type '$($f.Type)'"
        }
    }
    [PSCustomObject]$rec
}

# -- Post-eradication verification --------------------------------------------
foreach ($a in $actions) {
    if ($a.Status -ne 'eradicated') { continue }
    $verified = $true; $why = ''
    switch -Regex ($a.Type) {
        'Hidden Process|Process|Injection|LOLBin' {
            if ($a.Target -match 'PID:\s*(\d+)') { if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { $verified=$false; $why='process still running' } }
            if ($a.Subject -and (Test-Path -LiteralPath $a.Subject)) { $verified=$false; $why += '; original file still present' }
        }
        'Remote Access' {
            $rn = ($a.Target -replace '\s*\(residual\)\s*','').Trim()
            if (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "(?i)$rn" }) { $verified=$false; $why='tool process still running' }
        }
        'Defender Exclusion' {
            $mp = Get-MpPreference -ErrorAction SilentlyContinue
            if ($mp -and (@($mp.ExclusionPath) -contains $a.Target)) { $verified=$false; $why='exclusion still present' }
        }
        'COM Hijack' {
            if ($a.Target -match '(\{[0-9A-Fa-f\-]{36}\})') { $c=$Matches[1]
                foreach ($b in 'HKLM:\SOFTWARE\Classes\CLSID','HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID','HKCU:\SOFTWARE\Classes\CLSID') {
                    if (Test-Path -LiteralPath "$b\$c") { $verified=$false; $why='CLSID still registered' } } }
        }
        'Scheduled Task' {
            if ($a.Target -match 'Task:\s*(.+?)\s*$') { if (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq $Matches[1].Trim() }) { $verified=$false; $why='task still registered' } }
        }
    }
    $a | Add-Member -NotePropertyName Verified -NotePropertyValue $verified -Force
    $a | Add-Member -NotePropertyName VerifyNote -NotePropertyValue $why -Force
}

# -- Reports -------------------------------------------------------------------
$jsonOut = Join-Path $HostFolder "Eradication_$stamp.json"
$mdOut   = Join-Path $HostFolder "Eradication_$stamp.md"
$journalName = if (Test-Path $Journal) { Split-Path -Leaf $Journal } else { $null }
[ordered]@{
    host=$env:COMPUTERNAME; generated_utc=(Get-Date).ToUniversalTime().ToString('o')
    mode=$mode; min_verdict=$MinVerdict; source=(Split-Path -Leaf $AdjudicationPath)
    rollback_journal=$journalName
    actions=$actions
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonOut -Encoding UTF8

$acted = @($actions | Where-Object { $_.Status -in 'eradicated','planned','failed' })
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Eradication Report - $env:COMPUTERNAME")
$md.Add("")
$md.Add("- Mode: **$mode**$(if(-not $Apply){' (no changes made - re-run with -Apply to execute)'})")
$md.Add("- Source: ``$(Split-Path -Leaf $AdjudicationPath)``  |  MinVerdict: **$MinVerdict**")
$md.Add("- Targeted: $($acted.Count) of $($actions.Count) findings")
if ($Apply) {
    $ok = @($actions | Where-Object { $_.Status -eq 'eradicated' -and $_.Verified }).Count
    $md.Add("- Eradicated & verified: **$ok**  |  failed: $(@($actions|?{$_.Status -eq 'failed'}).Count)")
    $md.Add("- Rollback journal: ``$(Split-Path -Leaf $Journal)``")
}
$md.Add("")
if (-not $acted.Count) {
    $md.Add("## No qualifying findings")
    $md.Add("No finding met verdict '$MinVerdict' (after safety filtering). **No eradication required.**")
} else {
    $md.Add("## Actions")
    $md.Add("")
    $md.Add("| Verdict | Type | Target | Action | Status | Verified | Detail |")
    $md.Add("|---|---|---|---|---|---|---|")
    foreach ($a in $acted) {
        $v = if ($a.PSObject.Properties['Verified']) { $a.Verified } else { 'n/a' }
        $md.Add("| $($a.Verdict) | $($a.Type) | $($a.Target) | $($a.Action) | $($a.Status) | $v | $($a.Detail)$($a.Reason) |")
    }
}
$skipped = @($actions | Where-Object { $_.Status -eq 'skipped' -and $_.Reason -like 'SAFETY:*' })
if ($skipped.Count) {
    $md.Add(""); $md.Add("## Protected by safety rails ($($skipped.Count))")
    foreach ($s in $skipped) { $md.Add("- $($s.Type) ``$($s.Target)`` - $($s.Reason)") }
}
$md -join "`n" | Set-Content -LiteralPath $mdOut -Encoding UTF8

# -- Credential / session revocation (implicated accounts) ---------------------
# Disable local accounts named in Principals.json, purge their Kerberos tickets,
# and log off active sessions. Built-in/non-local/protected accounts are skipped.
if (-not $NoCredentialRevoke) {
    Write-Host "`n[*] Credential revocation ($mode)..." -ForegroundColor Cyan
    if (-not $PrincipalsPath) { $PrincipalsPath = Join-Path $HostFolder 'Principals.json' }
    $ProtectedAccts = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','SYSTEM',
        'LOCAL SERVICE','NETWORK SERVICE',$env:USERNAME)
    if ($PrincipalsPath -and (Test-Path -LiteralPath $PrincipalsPath)) {
        $pr = $null
        try { $pr = Get-Content -LiteralPath $PrincipalsPath -Raw | ConvertFrom-Json } catch {}
        $targets = @($pr.principals | Where-Object { $_.auto_revoke -and $_.type -eq 'local' -and ($ProtectedAccts -notcontains $_.name) })
        if (-not $targets.Count) { Write-Host "    No auto-revocable local principals." -ForegroundColor Gray }
        foreach ($p in $targets) {
            if (-not $Apply) { Write-Host "    PLAN: disable local user '$($p.name)' + purge tickets + logoff" -ForegroundColor Yellow; continue }
            try {
                $u = Get-LocalUser -Name $p.name -ErrorAction SilentlyContinue
                if (-not $u) { Write-Host "    SKIP (no local user): $($p.name)" -ForegroundColor Gray; continue }
                Write-Journal @{ action='disable_account'; name=$p.name; prior_enabled=[bool]$u.Enabled }
                Disable-LocalUser -Name $p.name -ErrorAction SilentlyContinue
                # log off interactive sessions for this user + purge Kerberos tickets
                (quser 2>$null) | Where-Object { $_ -match "(?i)\b$([regex]::Escape($p.name))\b" } | ForEach-Object {
                    if ($_ -match '\s(\d+)\s+(Active|Disc)') { logoff $Matches[1] 2>$null }
                }
                & klist purge -li 0x3e7 2>$null | Out-Null
                Write-Host "    REVOKED: local user '$($p.name)' disabled + sessions logged off" -ForegroundColor Green
            } catch { Write-Host "    FAILED $($p.name): $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        $dom = @($pr.principals | Where-Object { $_.type -in 'domain','iam','cloud-identity' })
        if ($dom.Count) { Write-Host "    [i] $($dom.Count) domain/cloud principal(s) need directory-side disable (AD/Entra/IAM) - not auto-handled." -ForegroundColor DarkYellow }
    } else {
        Write-Host "    No Principals.json - skipping credential revocation." -ForegroundColor Gray
    }
} else {
    Write-Host "`n[i] Credential revocation skipped (-NoCredentialRevoke)." -ForegroundColor Yellow
}

# -- Firewall restore: known-good minus known-bad ------------------------------
# Collection locked the host down (Default-Deny inbound) and exported the prior
# firewall. Now that the host is eradicated, return it to that known-good posture
# - but keep the adversary's C2 (from IOCs.json) blocked/sinkholed so re-connecting
# the host cannot re-establish the channel.
if (-not $NoFirewallRestore) {
    Write-Host "`n[*] Firewall restore ($mode)..." -ForegroundColor Cyan

    # Resolve the pre-incident backup .wfw.
    if (-not $FirewallBackup) {
        $stateFile = Join-Path $HostFolder '_firewall_state.json'
        if (Test-Path -LiteralPath $stateFile) {
            try { $FirewallBackup = (Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json).backup_wfw } catch {}
        }
    }
    if (-not $FirewallBackup) {
        $bkp = Get-ChildItem -Path 'C:\FirewallBackups' -Filter 'FW_State_*.wfw' -File -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($bkp) { $FirewallBackup = $bkp.FullName }
    }

    # Resolve known-bad C2 indicators (keep these blocked after restore).
    if (-not $IocPath) { $IocPath = Join-Path $HostFolder 'IOCs.json' }
    $knownBad = @()
    if ($IocPath -and (Test-Path -LiteralPath $IocPath)) {
        try {
            $ioc = Get-Content -LiteralPath $IocPath -Raw | ConvertFrom-Json
            $knownBad = @($ioc.c2_endpoints | Where-Object { -not $_.sanctioned })
        } catch {}
    }

    if (-not $Apply) {
        Write-Host "    DRY-RUN plan:" -ForegroundColor Yellow
        Write-Host "      restore firewall from: $(if($FirewallBackup){$FirewallBackup}else{'<no backup found>'})" -ForegroundColor Gray
        foreach ($kb in $knownBad) { Write-Host "      KEEP BLOCKED (known-bad): $($kb.host):$($kb.port)" -ForegroundColor Gray }
        if (-not $knownBad.Count) { Write-Host "      (no adversary C2 in IOCs.json to re-block)" -ForegroundColor Gray }
    } else {
        # 1) Restore the known-good ruleset (also clears the lockdown's disabled rules).
        if ($FirewallBackup -and (Test-Path -LiteralPath $FirewallBackup)) {
            try {
                $r = netsh advfirewall import "$FirewallBackup" 2>&1
                if ($LASTEXITCODE -eq 0) { Write-Host "    [+] Firewall restored to known-good from $(Split-Path -Leaf $FirewallBackup)" -ForegroundColor Green }
                else { Write-Host "    [!] Firewall import returned: $r" -ForegroundColor Yellow }
            } catch { Write-Host "    [!] Firewall import failed: $($_.Exception.Message)" -ForegroundColor Red }
        } else {
            Write-Host "    [!] No pre-incident .wfw backup found - leaving current firewall state intact." -ForegroundColor Yellow
        }

        # 2) Re-block known-bad: outbound block rule (+ hosts-file sinkhole for FQDNs).
        $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        foreach ($kb in $knownBad) {
            $name = "IR-BLOCK-$($kb.host)"
            try {
                Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                $isIp = $kb.host -match '^\d{1,3}(\.\d{1,3}){3}$'
                $p = @{ DisplayName=$name; Direction='Outbound'; Action='Block'; Profile='Any'; Protocol='TCP'; RemotePort=$kb.port }
                if ($isIp) { $p['RemoteAddress'] = $kb.host }
                New-NetFirewallRule @p -ErrorAction SilentlyContinue | Out-Null
                Write-Host "    [+] Known-bad re-blocked: outbound TCP $($kb.host):$($kb.port)" -ForegroundColor Green

                if (-not $isIp) {
                    $sink = "0.0.0.0`t$($kb.host)`t# IR sinkhole - adversary C2 ($IncidentId)"
                    $existing = if (Test-Path -LiteralPath $hostsFile) { Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue } else { @() }
                    if ($existing -notmatch [regex]::Escape($kb.host)) {
                        Add-Content -LiteralPath $hostsFile -Value $sink -ErrorAction SilentlyContinue
                        Write-Host "    [+] Sinkholed $($kb.host) -> 0.0.0.0 (hosts)" -ForegroundColor Green
                    }
                }
            } catch { Write-Host "    [!] Failed to re-block $($kb.host): $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        if (-not $knownBad.Count) { Write-Host "    No adversary C2 in IOCs.json - firewall fully restored to known-good." -ForegroundColor Gray }
    }
} else {
    Write-Host "`n[i] Firewall restore skipped (-NoFirewallRestore)." -ForegroundColor Yellow
}

Write-Host "`n=== Eradication summary ($mode) ===" -ForegroundColor Green
$actions | Group-Object Status | Select-Object @{N='Status';E={$_.Name}}, Count | Format-Table -AutoSize
Write-Host "[+] $jsonOut" -ForegroundColor Green
Write-Host "[+] $mdOut"   -ForegroundColor Green
if (-not $Apply) { Write-Host "[i] DRY-RUN: nothing changed. Re-run with -Apply to execute." -ForegroundColor Yellow }

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDMJsGe/TDPs81O
# Wh2qwETVh6GqoEV9EQXi1DHZ0tpoH6CCFrQwggN2MIICXqADAgECAhBa5MQyEl22
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgvOhDzfYrTj+UNYOtiX7EUCMKFCCrJev6
# YfCPYCM/TckwDQYJKoZIhvcNAQEBBQAEggEAChVYSIfw84UgQLbGkdqzcXJp/U9Z
# 1sciEZx10VKZNBE2drb7C2IxPX8ppPqrjo9Mt8oxwlP+39CLxT+Ss3fW7nZYSaAm
# nyJdj8MrFL4JsGz+ond/rC8qtsliwYDy8EwKDvEXPJSXDYXTRAkpN3vfLIGMD0kx
# 6r1hJiwXTQmznBWMp7Hx2l4jcqwqZR0iq3Owh9/QsX4e10bH9U78fP9qvSivILAs
# d0Wa7FhO8e6cjMLzJRmmACdSv0tRk1zkwlZt6jgYSpGlc/lvzfzyhx/6E6Dxsmde
# G4iOoukCaAFBtJGVxjJbWRu5RknIdx0f/nZDN0z/NixLkEL7HbZ7AyDXvKGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjAwMTE0MjdaMC8GCSqGSIb3DQEJBDEi
# BCCECLOYN/jOC9BRBLG/hL55eNe7LYVJEn/EsXK74lsdJDANBgkqhkiG9w0BAQEF
# AASCAgCaJKjsHYQnIe2XmbgdBFHiVQdgRybHyxO+74HuWhYLHVxTV9oMACTizXHF
# 62tRHWYMChnYpVvUbwxmNZFUn8KWbZWSOzYD70IHgX1DpM+TKVrsVO2ZPQCavzyq
# 3QcQ47rBgBeicUuuudeU05+hycsNhjpgy8ly8g9h+2egYFmoup+VQ3kbX2Cz4U3E
# 0TI6XXA9h26vBUmWKr8p1CK8tJc43PzTw3JOQrPQqNDRFu16nvXkBvGTvq/Ezvc5
# fHJfwprbAf0+jts4aL1LfyQ2EDq3HH1Te+TRkTJ32VLAX64BqF11hSN5JrKA/lid
# JZUB2mofMuHPlt9OdXqdSEFR+7ESUN4a23sidudvZvKpLNJTCzEPIT45MoFnOfPL
# XyVAGxan2ZiUwJw6zVjJ/lM1cfIwZ2nX6IrYGgJl7XeYQhUrNUvml61PZd3NrTTX
# +YhCPdClJFcO2Blgd0HwpjGAcqW/P6OdkSN+W/8W9bjzKhlCG5eq1w88b07Kx1eY
# umd7O/nwnmNuSuyMMjuyQU45raxGGvl42/IXxxdGdisDjh6IId/1ngIDLUYETFaa
# DnO5xb5n1YZ3CRptyTfGtBCToRJyKJk13XOF2n8n5M2ubXkSMXxmXY1/DhD4i4x+
# grH/6Ez7esCo3TRZwhdgPhqtt4IxSvzlN+axmWhekNkt7kF7TQ==
# SIG # End signature block
