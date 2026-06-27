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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9Ufkg2WYapYd4
# biVdZOwPCrs04if+ONiA0KvwMzpZgqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgdrT8+mWU8nNAgGYJngdCYttjspmJ8tjzvN0u
# f6o9rQMwDQYJKoZIhvcNAQEBBQAEggEAca8aNJ0hZNPonUjewlLbLBXduL7K2egw
# 57UILZ9ndkhcGucTVReYNYAJkNeiCAO9vBSb7wv8SHPMHZrDbimY5NgWJg+KMY5M
# JpHYGvfNUssA/cJGKZhqnGeYkZIdZpPvd93OOZmf25s9Qj941Ni7HEMmiTlClYTj
# esBK+gccGR+YPHDQZiMA4DdA7lq8YyyMf0V2PF6ohLeD/f0NZnR6t5odWjTnhDzR
# QB1ee4wcwdDsie2OWqmBYHZ1D08qoTYGqCKRbW5YrPIoJGd0ydnG488gVW2QFbZ4
# wdwhUiRXy/z9JqOCfg0Rslmjq+VMs0LZk2UM3VA0K+S4782EZ0PUU6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYyMzI3MjFaMC8GCSqGSIb3DQEJBDEiBCAN
# cdAZEuZxCBGr4/6nXmNhs97kKj3JYnJDu9p1VXOFOzANBgkqhkiG9w0BAQEFAASC
# AgDPGG+0xHwShZam7Gww9cqdOq1EbBgzf8fHWf0ytRQQd+HqU/QcbKcExA3GBBQy
# xi+Z5+IIh8VH61jLzYcmGAgB5ZiVlObZKjCHhPRD4zF/zRb/a06H7QCB1mILSlKi
# V0eL9UOoSPeBxCUrwgLiprNTASpC5MWd5Eo2KfDJI9ABw7aiFVclg0ZgSOsLN01G
# MRKSWAUjTA5cdCqiUQM90lmWPJg884dGmXPvKfYGWg0vh9vJTmQWKc+HI8MGemJu
# d5Idy9/4lTDcsvKs9+v+DU493Lha5MPIFAqP1MZkp4EQB4gBO0ddi6ztbYV503Re
# YsuaJNgleiJ22kw8ZonbdPAPyBHQm+yI/kSUqlolHB81d84aQXasLJu0qXKPLcpH
# YRIKmMvsm0jiNZltd8mYLqAr+k63kVUunbDw4N8BZwgCtMe7VkBm8BKA/4wNgpiD
# nbJwB4+ZThXF8nnKrIhfyMtkmUy7QNQLnZzDS8sRcQI03PFugxUNR7phZsDMT8gI
# HLbhimnUYb3An57TGjXWnTdcAcla6bWm4cFgnnel600ZmPIx4hV+Tys3WKsy6G2R
# gJkmcYZcVKxi9Er9Cw1NY0ePVewNeG25xjFYplWU4++kW4kw9E2EMni+9GmxMqvD
# shLgnhjQQtn4BXOYLj9fzFbrotQX+Wws9mPsPqcCvuSb9A==
# SIG # End signature block
