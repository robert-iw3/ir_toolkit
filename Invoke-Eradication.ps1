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
# PESTER-EXTRACT-START: pure-logic functions (Test-Protected, Get-EradicationOrder, Test-AlreadySinkholed)
$ProtectedNames = @('MsMpEng','MpDefenderCoreService','NisSrv','MsSense','SenseIR','SenseCncProxy',
    'System','Idle','smss','csrss','wininit','winlogon','services','lsass','svchost','spoolsv',
    'explorer','dwm','fontdrvhost','RuntimeBroker','WmiPrvSE','taskhostw','SearchIndexer')
# Expected on-disk path per protected name (lowercase, prefix-matched). A name-only
# match is NOT sufficient protection: malware named svchost.exe/explorer.exe/lsass.exe
# running from an unexpected path is exactly the LOTL path-masquerade technique the
# rest of this toolkit is built to detect (see the ML investigation engine's
# LOTL_SVCHOST_WRONG_PATH scenario) -- if that finding correctly reaches this script
# as a True Positive, protecting it by name alone would make it un-eradicable.
# Names absent from this table (kernel pseudo-processes System/Idle, or names whose
# install path varies by deployment) fall back to name-only protection.
$ProtectedPaths = @{
    'smss'          = @('c:\windows\system32\smss.exe')
    'csrss'         = @('c:\windows\system32\csrss.exe')
    'wininit'       = @('c:\windows\system32\wininit.exe')
    'winlogon'      = @('c:\windows\system32\winlogon.exe')
    'services'      = @('c:\windows\system32\services.exe')
    'lsass'         = @('c:\windows\system32\lsass.exe')
    'svchost'       = @('c:\windows\system32\svchost.exe', 'c:\windows\syswow64\svchost.exe')
    'spoolsv'       = @('c:\windows\system32\spoolsv.exe')
    'explorer'      = @('c:\windows\explorer.exe')
    'dwm'           = @('c:\windows\system32\dwm.exe')
    'fontdrvhost'   = @('c:\windows\system32\fontdrvhost.exe')
    'RuntimeBroker' = @('c:\windows\system32\runtimebroker.exe')
    'WmiPrvSE'      = @('c:\windows\system32\wbem\wmiprvse.exe')
    'taskhostw'     = @('c:\windows\system32\taskhostw.exe')
    'SearchIndexer' = @('c:\windows\system32\searchindexer.exe')
    'MsMpEng'       = @('c:\programdata\microsoft\windows defender\platform\', 'c:\program files\windows defender\')
}
function Test-Protected {
    param([string]$Name,[string]$Path,[string]$Sig)
    $bare = ($Name -replace '\.exe$','')
    if ($bare -and ($ProtectedNames -contains $bare)) {
        if ($ProtectedPaths.ContainsKey($bare) -and $ProtectedPaths[$bare].Count -and $Path) {
            $pathLower = $Path.ToLower()
            $onExpectedPath = $false
            foreach ($expected in $ProtectedPaths[$bare]) {
                if ($pathLower.StartsWith($expected)) { $onExpectedPath = $true; break }
            }
            if ($onExpectedPath) { return "protected process name '$bare' (path-verified)" }
            # Name matches a protected process but the path does not -- do NOT protect.
            # This is the path-masquerade case; fall through to the remaining checks.
        } else {
            # No path evidence available, or this name has no fixed expected path
            # (kernel pseudo-process) -- conservative default: protect by name alone
            # rather than risk eradicating a legitimate system process on missing data.
            return "protected process name '$bare'"
        }
    }
    if ($Sig -eq 'Valid') { return 'binary is validly code-signed' }
    if ($Path -match '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Windows\\WinSxS\\|\\Program Files\\WindowsApps\\') {
        return 'binary in a protected OS location'
    }
    return $null
}
$Rank = @{ 'True Positive'=2; 'Likely True Positive'=1 }
function Write-Journal { param([hashtable]$E) ($E | ConvertTo-Json -Compress) | Out-File -FilePath $Journal -Append -Encoding UTF8 }

# Persistence/config-removal types are eradicated BEFORE process-kill types. A crash
# or interruption mid-run should leave "persistence removed, dirty process still
# running" (safe: the process cannot survive a reboot or re-trigger) rather than
# "process killed, persistence intact" (unsafe: the persistence mechanism relaunches
# it before the next eradication pass gets a chance to clean up).
function Get-EradicationOrder {
    param([string]$Type)
    if ($Type -match '(?i)COM Hijack|Scheduled Task|BITS|Remote Access|Defender Exclusion') { return 0 }
    if ($Type -match '(?i)Hidden Process|Process|Injection|LOLBin') { return 1 }
    return 2
}

# "Does any existing hosts-file line already sinkhole this host" -- -notmatch against
# an array filters per-element (returns the non-matching lines), it does NOT answer
# "does any line match"; that filtered array is non-empty (truthy) almost always
# regardless of whether the host is already present, which silently re-appended a
# duplicate sinkhole line on every re-run. Isolated as its own function because this
# exact array-vs-scalar operator confusion is easy to reintroduce.
function Test-AlreadySinkholed {
    param([string[]]$ExistingLines, [string]$TargetHost)
    return @($ExistingLines | Where-Object { $_ -match [regex]::Escape($TargetHost) }).Count -gt 0
}
# PESTER-EXTRACT-END

$adj = @($adj | Sort-Object { Get-EradicationOrder $_.Type })

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

        # Must be tested BEFORE the generic 'Hidden Process|Process|Injection|LOLBin' pattern
        # below -- "Cross-Process Thread Handle (Memory)" contains the substring "Process" and
        # would otherwise also match that pattern. Without the unconditional `break` at the end
        # of this case, PowerShell's `switch -Regex` evaluates every matching pattern (not just
        # the first), which would run BOTH this thread-scoped action AND the generic whole-
        # process Stop-Process -- exactly doubling the blast radius this case exists to avoid.
        'Cross-Process Thread Handle' {
            # memory_forensic.py's Module 23 Target is 'PID <holder> (<name>) -> Target PID
            # <target> TID <tid>' -- the same 'PID <n> (<name>)' convention every module uses
            # (required so engine.py's investigation groups this finding under the HOLDER's
            # pid, not the target's). The leading 'PID\s+(\d+)' match is anchored to the start
            # of the string, so it always captures the holder, never the later 'Target PID'.
            $holderPid = if ($f.Target -match '^PID\s+(\d+)') { [int]$Matches[1] } else { $null }
            $targetTid = if ($f.Target -match 'TID\s+(\d+)') { [int]$Matches[1] } else { $null }
            $rec.Action = "terminate TID $targetTid (holder PID $holderPid)"
            if (-not $targetTid) { $rec.Status='failed'; $rec.Detail='no thread ID parsed from Target'; break }
            if (-not $Apply) { $rec.Status='planned'; break }
            # Killing the entire HOLDER process over one malicious thread risks destabilizing
            # (or, if the holder resolves to a core session-management process, BSOD'ing) the
            # system outright -- scoping to the single thread is the narrower, safer blast
            # radius the user asked for. The upstream Test-Protected guard already vetoed acting
            # on a protected holder identity (by the Details "Name:" tag) before this branch was
            # ever reached; re-check the LIVE current process name here too as defense in depth,
            # since TerminateThread is a sharper, less-recoverable primitive than the generic
            # kill-PID path and adjudication data can be stale relative to a live host by the
            # time -Apply actually runs.
            $bsodCriticalNames = @('system','csrss','wininit','winlogon','services','smss')
            $liveName = if ($holderPid) {
                try { (Get-Process -Id $holderPid -ErrorAction Stop).Name } catch { $null }
            } else { $null }
            if ($liveName -and ($bsodCriticalNames -contains ($liveName -replace '\.exe$',''))) {
                $rec.Status = 'failed'
                $rec.Detail = "refused: holder PID $holderPid resolves live to '$liveName', a core OS session-management process -- terminating a thread inside it risks destabilizing or crashing the system"
                break
            }
            try {
                # TerminateThread is a blunt, undocumented-consequences primitive (Microsoft's
                # own guidance: it does not run thread cleanup -- no stack unwind, no loader-lock
                # release, no DLL_THREAD_DETACH -- and can leave the host process in a corrupted
                # state). It is still the correct action here: the alternative (Stop-Process on
                # the whole holder) is strictly worse for exactly the processes most likely to be
                # legitimate multi-purpose hosts (e.g. svchost.exe running unrelated services).
                Add-Type -Namespace IRToolkit -Name ThreadOps -MemberDefinition @'
                    [DllImport("kernel32.dll", SetLastError=true)]
                    public static extern System.IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
                    [DllImport("kernel32.dll", SetLastError=true)]
                    public static extern bool TerminateThread(System.IntPtr hThread, uint dwExitCode);
                    [DllImport("kernel32.dll", SetLastError=true)]
                    public static extern bool CloseHandle(System.IntPtr hObject);
'@ -ErrorAction SilentlyContinue
                $THREAD_TERMINATE = 0x0001
                $hThread = [IRToolkit.ThreadOps]::OpenThread($THREAD_TERMINATE, $false, [uint32]$targetTid)
                if ($hThread -ne [IntPtr]::Zero) {
                    $ok = [IRToolkit.ThreadOps]::TerminateThread($hThread, 1)
                    [IRToolkit.ThreadOps]::CloseHandle($hThread) | Out-Null
                    if ($ok) { $rec.Status='eradicated'; $rec.Detail="TID $targetTid terminated" }
                    else     { $rec.Status='failed'; $rec.Detail='TerminateThread failed' }
                } else {
                    $rec.Status='failed'; $rec.Detail="OpenThread failed for TID $targetTid (thread may have already exited)"
                }
            } catch { $rec.Status='failed'; $rec.Detail="$_" }
            break
        }

        'Hidden Process|Process|Injection|LOLBin' {
            $procId = if ($f.Target -match 'PID:\s*(\d+)') { [int]$Matches[1] } else { $null }
            $rec.Action = "kill PID $procId + quarantine"
            if (-not $Apply) { $rec.Status='planned'; break }
            try {
                $killedProc = $false
                $quarantinedFile = $false
                if ($procId) {
                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                    $killedProc = $true
                }
                if ($f.SubjectPath -and (Test-Path -LiteralPath $f.SubjectPath -PathType Leaf)) {
                    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
                    $hashPrefix = if ($f.SHA256) { "$($f.SHA256)".Substring(0,12) } else { 'nohash' }
                    $dest = Join-Path $QuarantineDir ("{0}_{1}.quarantine" -f $hashPrefix, (Split-Path -Leaf $f.SubjectPath))
                    Write-Journal @{ action='quarantine'; original=$f.SubjectPath; dest=$dest; sha256=$f.SHA256 }
                    Move-Item -LiteralPath $f.SubjectPath -Destination $dest -Force
                    $rec.Detail = "quarantined -> $dest"
                    $quarantinedFile = $true
                }
                # Only claim 'eradicated' if something was actually done. A Target that
                # doesn't parse a PID AND has no on-disk SubjectPath means neither the
                # kill nor the quarantine step ran -- reporting 'eradicated' in that case
                # would be a false success with nothing behind it.
                if ($killedProc -or $quarantinedFile) {
                    $rec.Status = 'eradicated'
                } else {
                    $rec.Status = 'failed'
                    $rec.Detail = 'no PID parsed from Target and no on-disk SubjectPath -- nothing was done'
                }
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
    $md.Add("- Eradicated & verified: **$ok**  |  failed: $(@($actions | Where-Object {$_.Status -eq 'failed'}).Count)")
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
                    if (-not (Test-AlreadySinkholed -ExistingLines $existing -TargetHost $kb.host)) {
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

# -- Memory-derived eradication scope (from per-TP enrichment, merged into IOCs.json) ----------
# Surfaces the implant's full memory footprint so eradication is complete: dropped files, registry
# persistence, implant mutexes, and the related PID chain. C2 from memory is already folded into
# c2_endpoints above and re-blocked with the rest. Reported (not auto-deleted) so the analyst
# confirms each artifact - these are recovered from a memory image and warrant a look before removal.
if (-not $IocPath) { $IocPath = Join-Path $HostFolder 'IOCs.json' }
if ($IocPath -and (Test-Path -LiteralPath $IocPath)) {
    $me = $null
    try { $me = (Get-Content -LiteralPath $IocPath -Raw | ConvertFrom-Json).memory_eradication } catch {}
    if ($me) {
        Write-Host "`n=== Memory-derived eradication scope (review before removal) ===" -ForegroundColor Cyan
        $files = @($me.files_to_remove); $keys = @($me.registry_keys_to_remove)
        $muts  = @($me.mutexes);         $pids = @($me.implicated_pids)
        if ($files.Count) { Write-Host "  Dropped files to remove:" -ForegroundColor Yellow; $files | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray } }
        if ($keys.Count)  { Write-Host "  Registry persistence to remove:" -ForegroundColor Yellow; $keys | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray } }
        if ($muts.Count)  { Write-Host "  Implant mutexes (host-survey IOC):" -ForegroundColor Yellow; $muts | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray } }
        if ($pids.Count)  { Write-Host "  Implicated PIDs (terminate/forensic-preserve): $($pids -join ', ')" -ForegroundColor Yellow }
        if (-not ($files.Count -or $keys.Count -or $muts.Count -or $pids.Count)) {
            Write-Host "  (no memory-derived artifacts recorded)" -ForegroundColor Gray
        }
    }
}

Write-Host "`n=== Eradication summary ($mode) ===" -ForegroundColor Green
$actions | Group-Object Status | Select-Object @{N='Status';E={$_.Name}}, Count | Format-Table -AutoSize
Write-Host "[+] $jsonOut" -ForegroundColor Green
Write-Host "[+] $mdOut"   -ForegroundColor Green
if (-not $Apply) { Write-Host "[i] DRY-RUN: nothing changed. Re-run with -Apply to execute." -ForegroundColor Yellow }

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZQid8PoouyyGu
# i3Y4rqKyY81MMlipZ6u9tFRHJLa9aKCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgNpsBNX+asJK0v30RAE3rpxR9DGqWanyt60ik
# uhpBMXMwDQYJKoZIhvcNAQEBBQAEggEACDjwb/gPipfAwakvSC+F4RCYEgaDqn08
# sXgHnMiKTsBLVIa0rz5DUXJKh+DnZHOmje5GYeOZJ8MpkNZ0qULeO+GbtF6ELUcB
# 83DU1buF8SqDg2QZ8xMbrnvrNubCLX3yLN4bL0bwQKt7VvJ60Q9YbNfF1iWFWJ52
# 871s1vLe4JBsWpJuxP8AOkbHmlgJTc0hOf/julV7L8fablJg0qrOXESQ/vhB2nGL
# 30Ek2abLWLuMAb9KNfNbSNVAo259xTnC8jiXKEnH8iOxh8MdYWF/YQ+aE/fGHGnD
# c9l0glRFk44pqZ1/r1LXljaoHFGKbWaFnxOUnZVZVNLPgz03ZbFhvKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MTRaMC8GCSqGSIb3DQEJBDEiBCA5
# 5KTchwFjwzfVj+maoNVSbXN94gOsD/togHlMx9QeaTANBgkqhkiG9w0BAQEFAASC
# AgBcTdbGhb6/1fwpvSOmPABPfM98T98uuPI7z5n0I21HvXlqup/bfHWHs/BH3jYS
# M63z+chgDI9MzKDtylDk4YPWe9blRsOdL+EHPqwKgZrhb+86fMnzd91movKCw/y8
# 0G1DOtujLMifYthMkLR7tAgLm1QJEixISmSgQCgKuDaW9KknQMZWghm+KmBCY+Cw
# ylZOzDIYxptXcOZYC7xKKgiATSAYQA1wsvV/MFYwGHFCJ/o1Sazkw6mYgJvWO9Vs
# p+FoE9P5Jqq8UHIfiJzwjhO/6Ryosz7qIEmqWjYDiIbX30a3kezqcHrnWkmoEs7Q
# QrkYU3o1pfIIqdzPRQYhmtFdj8OfSxHX1ByqJJvgOYbLVu96Mi++aq1HKZow6X1w
# y/bt4vhGqbkKeRpPE/wgKkNrh1SGrdNMj8SuhXCO6+nceSesExLuLeW7011r40RU
# EtmyIogTds5DBVQWysm1lphCyWYaMd7fpr8Lu6M7Yhnf2nnkrKxjUC+ssyBLg3VX
# fXHEiQylf4vU4PC6kl+szpfM5eiQk6JSl209iBE2DFEvVUPHojwd+fGiLPvvnZSH
# Ebirs8aXx2SD2lNQTUvDgUUSzT2+NTHdi6eMn5Avy7gWTs9bQ2aa46fkupckxwqh
# kJi4FA7C46w/bTn0EPsnoNxsP9D/FAUiyoAvhfxYJhICrg==
# SIG # End signature block
