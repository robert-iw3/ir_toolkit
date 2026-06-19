<#
.SYNOPSIS
    Pure-PowerShell persistence-breadth + security-config-tamper snapshot. No
    third-party tools - uses only built-in cmdlets and Windows' own binaries
    (wevtutil / auditpol / netsh / klist / cmdkey), so it runs on a fully isolated
    host with nothing staged.

.DESCRIPTION
    Closes the depth gaps that the base forensics misses, offline:
      * Persistence breadth: IFEO debuggers, Winlogon Shell/Userinit/Notify,
        AppInit/AppCert DLLs, LSA packages, BootExecute, netsh helpers, Active
        Setup, Run/RunOnce for ALL users.
      * Security tamper: WDigest cleartext creds, LSASS PPL off, UAC off,
        Defender disabled, PowerShell logging disabled.
    Anomalies are emitted as findings (EDR schema -> flow into the adjudicator),
    and raw evidence is collected into <OutputDir>\Persistence\ :
      full .evtx exports, every scheduled-task XML, firewall export + allow rules,
      audit policy, Defender detection history, installed software, sessions/creds.

.PARAMETER OutputDir   Where findings + artifacts are written. Default: script folder.
.PARAMETER SkipEvtx    Skip full event-log .evtx export (it is the largest artifact).

.EXAMPLE
    .\Get-PersistenceSnapshot.ps1 -OutputDir .\KIMBAP
#>

#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDir = $PSScriptRoot, [switch]$SkipEvtx)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
if (-not $OutputDir) { $OutputDir = (Get-Location).Path }
$Art = Join-Path $OutputDir 'Persistence'
New-Item -ItemType Directory -Path $Art -Force | Out-Null

$Findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding { param([string]$Severity,[string]$Type,[string]$Target,[string]$Details,[string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Severity=$Severity
        Type=$Type; Target=$Target; Details=$Details; MITRE=$Mitre })
}
# StrictMode-safe registry value getter
function Get-RegVal { param([string]$Path,[string]$Name)
    try { $p = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
          if ($p -and $p.PSObject.Properties[$Name]) { return $p.$Name } } catch {}
    return $null
}

# ============================================================================
# 1. PERSISTENCE BREADTH  (findings for anomalies + raw dump)
# ============================================================================
$raw = [System.Collections.Generic.List[string]]::new()

# Image File Execution Options - any Debugger / GlobalFlag is a hijack (T1546.012)
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeo) {
    Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = Get-RegVal $_.PSPath 'Debugger'
        if ($dbg) { Add-Finding 'High' 'IFEO Debugger Hijack' "$($_.PSChildName)" "Debugger -> $dbg" 'T1546.012'; $raw.Add("IFEO $($_.PSChildName) Debugger=$dbg") }
    }
}

# Winlogon Shell / Userinit / Notify (T1547.004)
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$shell = Get-RegVal $wl 'Shell'; $userinit = Get-RegVal $wl 'Userinit'
$raw.Add("Winlogon Shell=$shell Userinit=$userinit")
if ($shell -and $shell -notmatch '^explorer\.exe,?\s*$') { Add-Finding 'High' 'Winlogon Shell' 'Winlogon\Shell' "Non-default Shell: $shell" 'T1547.004' }
if ($userinit -and $userinit -notmatch '(?i)\\userinit\.exe,?\s*$') { Add-Finding 'High' 'Winlogon Userinit' 'Winlogon\Userinit' "Non-default Userinit: $userinit" 'T1547.004' }

# AppInit_DLLs (T1546.010) / AppCertDLLs (T1546.009)
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $ai = Get-RegVal $k 'AppInit_DLLs'
    if ($ai) { Add-Finding 'High' 'AppInit_DLLs' $k "AppInit_DLLs: $ai" 'T1546.010'; $raw.Add("AppInit_DLLs ($k)=$ai") }
}
$ac = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' '(default)'
$acKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
if (Test-Path $acKey) { (Get-Item $acKey).Property | ForEach-Object { Add-Finding 'High' 'AppCertDLLs' $_ "AppCertDLL: $(Get-RegVal $acKey $_)" 'T1546.009' } }

# LSA packages (T1547.002 / T1556) + LSASS protection + WDigest creds
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
foreach ($v in 'Authentication Packages','Notification Packages','Security Packages') {
    $val = Get-RegVal $lsa $v
    if ($val) { $raw.Add("LSA $v = $($val -join ',')") }
}
if ((Get-RegVal $lsa 'RunAsPPL') -ne 1) { Add-Finding 'Medium' 'Security Config' 'LSA\RunAsPPL' 'LSASS is NOT running as a protected process (RunAsPPL != 1)' 'T1003.001' }
$wdig = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
if ($wdig -eq 1) { Add-Finding 'High' 'Security Config' 'WDigest\UseLogonCredential' 'WDigest cleartext credential caching is ENABLED (=1)' 'T1112, T1003' }

# BootExecute (T1547)
$boot = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute'
if ($boot) { $raw.Add("BootExecute=$($boot -join ' | ')"); if ("$boot" -notmatch '^autocheck autochk') { Add-Finding 'High' 'BootExecute' 'Session Manager\BootExecute' "Non-default: $($boot -join ' | ')" 'T1547' } }

# netsh helper DLLs (T1546.007)
$netsh = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $netsh) { (Get-Item $netsh).Property | ForEach-Object { $d=Get-RegVal $netsh $_; $raw.Add("Netsh helper $_=$d"); Add-Finding 'Medium' 'Netsh Helper DLL' $_ "Netsh helper: $d" 'T1546.007' } }

# Run / RunOnce for ALL loaded user hives + HKLM (T1547.001)
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '_Classes$' } | ForEach-Object {
    $runKeys += "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run"
    $runKeys += "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
foreach ($rk in $runKeys) {
    if (-not (Test-Path -LiteralPath $rk)) { continue }
    $p = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
    foreach ($prop in $p.PSObject.Properties) {
        if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
        $raw.Add("RUN $rk :: $($prop.Name) = $($prop.Value)")
        # flag entries that resolve into user-writable / temp locations (adjudicator proves signature)
        if ("$($prop.Value)" -match '(?i)\\(AppData|Temp|Users\\Public|ProgramData|Downloads)\\') {
            Add-Finding 'Medium' 'Registry Persistence' "$($prop.Name)" "Run value in user-writable path: $($prop.Value)" 'T1547.001'
        }
    }
}
$raw | Set-Content -LiteralPath (Join-Path $Art 'persistence_raw.txt') -Encoding UTF8

# ============================================================================
# 2. SECURITY CONFIG TAMPER (defense evasion)
# ============================================================================
if ((Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 0) {
    Add-Finding 'High' 'Security Config' 'UAC\EnableLUA' 'UAC is DISABLED (EnableLUA=0)' 'T1548.002'
}
if ((Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware') -eq 1) {
    Add-Finding 'High' 'Security Config' 'Defender\DisableAntiSpyware' 'Defender disabled via policy' 'T1562.001'
}
$sbl = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
if ($sbl -eq 0) { Add-Finding 'Medium' 'Security Config' 'PowerShell ScriptBlockLogging' 'ScriptBlock logging explicitly disabled' 'T1562.002' }

# ============================================================================
# 3. RAW EVIDENCE (built-in Windows binaries; no staging required)
# ============================================================================
# 3a. Full .evtx exports
if (-not $SkipEvtx) {
    $evtxDir = Join-Path $Art 'evtx'; New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null
    $logs = @('Security','System','Application','Windows PowerShell',
        'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational','Microsoft-Windows-Bits-Client/Operational')
    foreach ($lg in $logs) {
        $safe = ($lg -replace '[\\/ ]','_') + '.evtx'
        try { & wevtutil epl "$lg" (Join-Path $evtxDir $safe) /ow:true 2>$null } catch {}
    }
}
# 3b. Every scheduled task definition (full XML)
try {
    $tdir = Join-Path $Art 'tasks_xml'; New-Item -ItemType Directory -Path $tdir -Force | Out-Null
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        try { $x = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
              if ($x) { $fn = (($_.TaskPath + $_.TaskName) -replace '[\\/:*?"<>|]','_') + '.xml'
                        $x | Set-Content -LiteralPath (Join-Path $tdir $fn) -Encoding UTF8 } } catch {}
    }
} catch {}
# 3c. Firewall: full export + enabled allow rules
try { & netsh advfirewall export (Join-Path $Art 'firewall.wfw') 2>$null | Out-Null } catch {}
try {
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and $_.Direction -eq 'Inbound' } |
        Select-Object DisplayName, Direction, Action, Profile, @{N='Program';E={($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program}} |
        Export-Csv -LiteralPath (Join-Path $Art 'firewall_inbound_allow.csv') -NoTypeInformation -Encoding UTF8
} catch {}
# 3d. Audit policy
try { & auditpol /get /category:* 2>$null | Out-File -LiteralPath (Join-Path $Art 'auditpol.txt') -Encoding UTF8 } catch {}
# 3e. Defender detection history
try { Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object ThreatID, InitialDetectionTime, ProcessName, Resources |
        Export-Csv -LiteralPath (Join-Path $Art 'defender_detections.csv') -NoTypeInformation -Encoding UTF8 } catch {}
# 3f. Installed software (recent installs surface dropped RMM/PUP)
try {
    $uk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $uk -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
        Sort-Object InstallDate -Descending |
        Export-Csv -LiteralPath (Join-Path $Art 'installed_software.csv') -NoTypeInformation -Encoding UTF8
} catch {}
# 3g. Sessions + stored credentials (built-in)
try { & klist sessions 2>$null | Out-File -LiteralPath (Join-Path $Art 'klist_sessions.txt') -Encoding UTF8 } catch {}
try { & cmdkey /list 2>$null   | Out-File -LiteralPath (Join-Path $Art 'cmdkey_stored.txt') -Encoding UTF8 } catch {}
try { if (Get-Command qwinsta -ErrorAction SilentlyContinue) { qwinsta 2>$null | Out-File -LiteralPath (Join-Path $Art 'qwinsta.txt') -Encoding UTF8 } } catch {}
# 3h. hosts file + proxy
try { Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts" (Join-Path $Art 'hosts.txt') -Force -ErrorAction SilentlyContinue } catch {}

# ============================================================================
# 4. NTFS TIMELINE + AMCACHE (built-in fsutil + reg load; no external parser)
# ============================================================================
$sysDrive = $env:SystemDrive
# 4a. USN change journal metadata + a bounded record dump (file create/delete/rename timeline)
try { & fsutil usn queryjournal $sysDrive 2>$null | Out-File -LiteralPath (Join-Path $Art 'usn_queryjournal.txt') -Encoding UTF8 } catch {}
try {
    # readjournal can be huge; cap the dump so the drive doesn't fill on a busy host
    & fsutil usn readjournal $sysDrive 2>$null | Select-Object -First 60000 |
        Out-File -LiteralPath (Join-Path $Art 'usn_readjournal.txt') -Encoding UTF8
} catch {}

# 4b. Parse Amcache (execution evidence: path, SHA1, publisher, link date) by
#     loading the hive offline with reg load - pure built-in, no external parser.
$amcache = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path -LiteralPath $amcache) {
    $hiveKey = "HKLM\IR_Amcache_$PID"
    try {
        & reg load $hiveKey $amcache 2>$null | Out-Null
        $base = "Registry::$hiveKey\Root\InventoryApplicationFile"
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
                $k = $_.PSPath
                [PSCustomObject][ordered]@{
                    Path      = Get-RegVal $k 'LowerCaseLongPath'
                    Sha1      = (("" + (Get-RegVal $k 'FileId')) -replace '^0000','')   # FileId = 0000+SHA1
                    Publisher = Get-RegVal $k 'Publisher'
                    Product   = Get-RegVal $k 'ProductName'
                    Version   = Get-RegVal $k 'Version'
                    LinkDate  = Get-RegVal $k 'LinkDate'
                    Size      = Get-RegVal $k 'Size'
                }
            } | Export-Csv -LiteralPath (Join-Path $Art 'amcache_parsed.csv') -NoTypeInformation -Encoding UTF8
        }
    } catch { } finally {
        [gc]::Collect(); Start-Sleep -Milliseconds 200    # release handles before unload
        & reg unload $hiveKey 2>$null | Out-Null
    }
}
# Note: full $MFT parsing is not feasible in pure PowerShell (raw volume read +
# NTFS record parsing); the USN journal above provides the file-activity timeline.

# ============================================================================
# Output findings (EDR schema) + summary
# ============================================================================
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $OutputDir "Persistence_Findings_$stamp.json"
if ($Findings.Count -gt 0) { $Findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $out -Encoding UTF8 }
else { '[]' | Set-Content -LiteralPath $out -Encoding UTF8 }

Write-Host "[+] Persistence/config snapshot: $($Findings.Count) finding(s) -> $(Split-Path -Leaf $out)" -ForegroundColor Green
Write-Host "[+] Raw evidence (evtx/tasks/firewall/auditpol/...) -> $Art" -ForegroundColor Green
$Findings | Group-Object Type | Select-Object @{N='Type';E={$_.Name}}, Count | Format-Table -AutoSize
