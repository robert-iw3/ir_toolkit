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
    .\Get-PersistenceSnapshot.ps1 -OutputDir .\<HOSTNAME>
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
# The registry values under HKLM:\SOFTWARE\Microsoft\Netsh are short names
# (e.g. "authfwcfg", "dhcpcsvc") not DLL paths. Resolve the actual DLL via the
# matching service/DLL key before emitting a finding, and skip Windows-signed helpers.
$netsh = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $netsh) {
    (Get-Item $netsh).Property | ForEach-Object {
        $helperName = $_
        $helperVal  = Get-RegVal $netsh $helperName
        # helperVal is usually a short name like "authfwcfg"; try to resolve to full DLL path.
        $dllPath = $null
        # Check if value IS already a path
        if ($helperVal -and $helperVal -match '\\') {
            $dllPath = $helperVal
        } else {
            # Look up the DLL via the NetBT/Netsh service DLL registration
            $svcKey = "HKLM:\SYSTEM\CurrentControlSet\services\$helperVal\Parameters"
            $altKey = "HKLM:\SYSTEM\CurrentControlSet\services\$helperVal"
            foreach ($k in @($svcKey, $altKey)) {
                $candidate = Get-RegVal $k 'ServiceDll'
                if (-not $candidate) { $candidate = Get-RegVal $k 'DLL' }
                if ($candidate) { $dllPath = [System.Environment]::ExpandEnvironmentVariables($candidate); break }
            }
            # Fallback: search system32 for <name>.dll
            if (-not $dllPath -and $helperVal) {
                $guess = Join-Path $env:SystemRoot "System32\$helperVal.dll"
                if (Test-Path -LiteralPath $guess) { $dllPath = $guess }
            }
        }
        $displayPath = if ($dllPath) { $dllPath } else { "(unresolved: $helperVal)" }
        $raw.Add("Netsh helper $helperName=$displayPath")

        # Skip Windows-signed helpers - only flag unsigned or unknown-path entries.
        $isSigned = $false
        if ($dllPath -and (Test-Path -LiteralPath $dllPath)) {
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $dllPath -ErrorAction SilentlyContinue
                $isSigned = $sig -and $sig.Status -eq 'Valid' -and
                            $sig.SignerCertificate.Subject -match 'Microsoft'
            } catch {}
        } elseif (-not $dllPath) {
            # Can't resolve path - flag as indeterminate rather than skipping
            $isSigned = $false
        }

        if (-not $isSigned) {
            Add-Finding 'Medium' 'Netsh Helper DLL' $helperName "Netsh helper '$helperName' -> $displayPath" 'T1546.007'
        }
    }
}

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
# 3f. Installed software - query each hive separately (array wildcard paths silently
# fail when a hive doesn't exist). HKCU catches per-user installs: RMM tools and
# stealers often install there to avoid a UAC prompt.
try {
    $uninstallHives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $allSoftware = foreach ($hive in $uninstallHives) {
        if (Test-Path $hive) {
            Get-ChildItem -LiteralPath $hive -ErrorAction SilentlyContinue |
                ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } |
                Where-Object { $_.DisplayName }
        }
    }
    @($allSoftware) |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation,
            @{N='Scope';E={ if ($_.PSPath -match 'HKEY_CURRENT_USER') { 'User' } else { 'Machine' } }} |
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

# 4b. ShimCache - AppCompatCache binary blob from registry.
#     Exported as-is for Invoke-AmcacheParser.ps1 to decode.
$shimKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
try {
    $shimBlob = (Get-ItemProperty -LiteralPath $shimKey -ErrorAction Stop).AppCompatCache
    if ($shimBlob) {
        [System.IO.File]::WriteAllBytes((Join-Path $Art 'shimcache.bin'), $shimBlob)
    }
} catch {}

# 4c. Amcache - execution history hive. Amcache.hve is locked by the Application
#     Experience service; use robocopy /B (backup mode) to read the locked file,
#     then reg load the copy. Requires SeBackupPrivilege (present in admin sessions).
$amcache = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
$amcacheCopy = Join-Path ([System.IO.Path]::GetTempPath()) "IR_Amcache_$PID.hve"
$hiveKey     = "HKLM\IR_Amcache_$PID"
$amcacheOk   = $false
try {
    # robocopy /B = backup mode (bypasses ACL/lock via SeBackupPrivilege).
    # /R:1 /W:1 = retry once, wait 1s - WITHOUT these, robocopy defaults to
    # 1,000,000 retries x 30s wait and hangs forever on a locked/unreadable hive.
    & robocopy (Split-Path $amcache) ([System.IO.Path]::GetTempPath()) (Split-Path $amcache -Leaf) `
        /B /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP 2>$null | Out-Null
    if (Test-Path -LiteralPath $amcacheCopy) { $amcacheOk = $true }
} catch {}

if ($amcacheOk) {
    try {
        & reg load $hiveKey $amcacheCopy 2>$null | Out-Null
        $base = "Registry::$hiveKey\Root\InventoryApplicationFile"
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
                $k = $_.PSPath
                [PSCustomObject][ordered]@{
                    Path      = Get-RegVal $k 'LowerCaseLongPath'
                    SHA1      = (("" + (Get-RegVal $k 'FileId')) -replace '^0000','')
                    Publisher = Get-RegVal $k 'Publisher'
                    Product   = Get-RegVal $k 'ProductName'
                    Version   = Get-RegVal $k 'Version'
                    LinkDate  = Get-RegVal $k 'LinkDate'
                    Size      = Get-RegVal $k 'Size'
                }
            } | Export-Csv -LiteralPath (Join-Path $Art 'amcache_parsed.csv') -NoTypeInformation -Encoding UTF8
        }
    } catch { } finally {
        [gc]::Collect(); Start-Sleep -Milliseconds 200
        & reg unload $hiveKey 2>$null | Out-Null
        Remove-Item -LiteralPath $amcacheCopy -Force -ErrorAction SilentlyContinue
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

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9Ufkg2WYapYd4
# biVdZOwPCrs04if+ONiA0KvwMzpZgqCCFrQwggN2MIICXqADAgECAhBj3Isegven
# qEj21ds5AZieMA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjMxNDE2NTlaFw0zMTA2MjMxNDI2NTlaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAM3b6zgkW9zzqQraVSnj+a4zp1l4KkWs2NKNqvPP
# p9Pyjhif7sY2FZyXnXbkKElZkNveSR84IkSBjIBC/9Q2gum1eM9nDmbnj2v5L+Nu
# llMOkOjUC913DYNHmHdk/8FDJwAjl6mtsAWZwTvc7FUpyqGiD09yILSywsivvkDV
# nE/qWzKgMRGflBJreqDUR5o0l0hLhowxG58ywKqElIJpwV+N1ngcfYIpJPO4XEHB
# 6sSe0fkZralmnZdZ+sw6LRUpE7nMxmy6ZktNz51jXnm/oR7N9VbHUBOMtBLAFmny
# CFddkOEV4z4Pz3yC0SOcgJXvoJ3yfPLzug7t5W+kRcNGmrECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQQFW0G
# zu1Gz5VThEyg9LLMhDsLlDANBgkqhkiG9w0BAQsFAAOCAQEAGVSgMDhKb7EDBXTH
# 3pTUUxUoQNNByOzeSepp+Wq5HpPEO7lS204uZSljF1a6QNjya4SsVE3o4+TR9CJm
# uXqRvesj578tf9DQSl0iflg2rz9UGCXRVTazH8xMWOpt8fMlXbUf3xfYS4Wqena2
# dl5JhRwvaDUmO5EJixsQwTiYS+vS5sG0TzMIT2N0dyCrA4eRinORCiUzTn3zYZe4
# osCBOkhKbaiX6YkjzWhFGEarCNYwAYhleymgIy88BowoBYgwn1vx9G14hS9cEcHp
# d/oHA9RE3wgiiYW2VCYWv+8GWrBv+WCruhrzagOTl6RURC1ctkiRl6MbQ9XENvQF
# HPfs5TCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEGPcix6C96eoSPbV2zkB
# mJ4wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgdrT8+mWU8nNAgGYJngdCYttjspmJ8tjz
# vN0uf6o9rQMwDQYJKoZIhvcNAQEBBQAEggEAaiHJPBoGd5w0n+pJrX2EBScskbwq
# yKF8XPXoYJZ2wJwHNyJYeow07qf/jjnFDwcaxAwNAOyX+Z+D0U0j5wSZjVWKZmlU
# EW5yqLmX6DsHAE9rHyBSwD/JBxDzl9aVwv2WTfenHEivZ6kMJjDIKE6yHh6StXyC
# 5KVW/NRgxqSngpfjGDM/O1T/I5/cPgsAc1JYe+rhW8xLYBTowLdQDrQxCvGhV372
# rKUgBskHqNu2HZt3CSk86jzm/dN2GLM21YYisZxOWT/1CJLjetFZf5QOARVkcLSU
# 7v9jK+/cX1zQuj2EpjnDJbUDvxjK9W2ifn4P0jqkSE3jxHvVkXNZJ54EVaGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjMxNDI3MTRaMC8GCSqGSIb3DQEJBDEi
# BCDYcZ4GT4wbWBfk0Hriz69IVG8prLaf6hCBoGocPCmfgTANBgkqhkiG9w0BAQEF
# AASCAgCI9eKwpdxgpTS6ejbaZC15Xq+mjwkRmDo9JxlnoqxZiZMukX8voT1M9lFu
# 4FMEh9VXeCiaJut25L7F4qfi2tPXungen9EFNx3HWJfl9oe3iCmKNHrr1wxM8+xR
# J1rVo+xFl0NLHX+FKTZ+EF0iBIZqzjCXAYZw2g2xhydqi3vCePMdX7xF0Kl9FDLA
# O/0XUrHo6TgRew+e9hVshVhF44KjfkghW10LkNF9bIUOf7N/av/LrieDeEsDUyBL
# Nblc6r/KI6Ps1PQi8Gl79oSjXQpaO/7wVCRVDyDxKmfWJdQrDLI7oBv0T3vhCgfB
# SXBHkUS/6edpBi7y7dKrY9rBF4sHcfs0vBXmnh61d5kh3VERMasiaRIAv+/1CDCc
# gkSDGO6Uq6afWab10ocKf280sZ1WeEfPB1z/Rvfc2VxFJD435sl+xxnKUqp/AIYw
# YNA0NuoL29dCdAdWqf+kWcl8v3QP9PDBXuFzIxbkW6Le7MhQuXrBehBqpstNgG+b
# SlOgoChAzkzMsJcNOA6SC7nASZfBIjkX848dzDc7/oMHLXmFiMs3rK6fsLcnPSPA
# YJ1CcZY/pR11U15KvN1cH5Kxi15dPogXzIzuopXVlhp0JQitt+HJjieDgKfGbnFC
# UACBsbIOkulGr55WAx8SSxxy4TNu09NbBLPoaWzIdFzFOiHiQA==
# SIG # End signature block
