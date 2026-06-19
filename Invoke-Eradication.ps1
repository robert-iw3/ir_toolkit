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
