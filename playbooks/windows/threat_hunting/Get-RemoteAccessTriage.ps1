<#
.SYNOPSIS
    Triage for interactive-remote-control compromise: RMM/remote-access tooling,
    ClickFix / fake-update execution lures, browser artifacts, and active sessions.

.DESCRIPTION
    Targets the gap that process/persistence hunts miss: a signed remote-access tool
    + a social-engineering lure (e.g. a fake full-screen "Windows Update" page with a
    cursor moving on its own). Emits findings in the SAME schema as EDR_Toolkit
    (Timestamp/Severity/Type/Target/Details/MITRE) so they flow into the adjudicator
    and eradicator, and copies raw artifacts (RMM connection logs, browser history,
    RunMRU) into <OutputDir>\RemoteAccess\ for manual review.

.PARAMETER OutputDir   Where findings + artifacts are written. Default: script folder.
.EXAMPLE
    .\Get-RemoteAccessTriage.ps1 -OutputDir .\<HOSTNAME>
#>

#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDir = $PSScriptRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
if (-not $OutputDir) { $OutputDir = (Get-Location).Path }
$ArtRoot = Join-Path $OutputDir 'RemoteAccess'
New-Item -ItemType Directory -Path $ArtRoot -Force | Out-Null

$Findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Severity,[string]$Type,[string]$Target,[string]$Details,[string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity; Type = $Type; Target = $Target; Details = $Details; MITRE = $Mitre
    })
}
function Copy-Artifact { param([string]$Src,[string]$DestName)
    try { if (Test-Path -LiteralPath $Src) { Copy-Item -LiteralPath $Src -Destination (Join-Path $ArtRoot $DestName) -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}

# ============================================================================
# 1. Remote-access / RMM tooling (MITRE T1219). Catalog of name + log hints.
# ============================================================================
$RMM = @(
    @{ N='AnyDesk';            P='anydesk';        Logs=@("$env:ProgramData\AnyDesk\connection_trace.txt","$env:ProgramData\AnyDesk\ad.trace","$env:APPDATA\AnyDesk\connection_trace.txt") }
    @{ N='TeamViewer';         P='teamviewer';     Logs=@("$env:ProgramData\TeamViewer\Connections_incoming.txt","${env:ProgramFiles(x86)}\TeamViewer\Connections_incoming.txt","$env:ProgramFiles\TeamViewer\Connections_incoming.txt") }
    @{ N='ScreenConnect';      P='screenconnect';  Logs=@("$env:ProgramData\ScreenConnect Client") }
    @{ N='ConnectWiseControl'; P='connectwise';    Logs=@() }
    @{ N='Splashtop';          P='splashtop|srservice|srmanager'; Logs=@("$env:ProgramData\Splashtop\Temp\log") }
    @{ N='RustDesk';           P='rustdesk';       Logs=@("$env:APPDATA\RustDesk\log","$env:ProgramData\RustDesk\log") }
    @{ N='NetSupport';         P='client32|pcicfgui'; Logs=@("$env:ProgramFiles\NetSupport","${env:ProgramFiles(x86)}\NetSupport") }
    @{ N='Atera';              P='ateraagent';     Logs=@() }
    @{ N='Action1';            P='action1';        Logs=@() }
    @{ N='LogMeIn';            P='logmein|lmiguardiansvc'; Logs=@() }
    @{ N='GoToAssist';         P='gotoassist|g2';  Logs=@() }
    @{ N='ZohoAssist';         P='zaservice|zohomeeting|za_connect'; Logs=@() }
    @{ N='VNC';                P='winvnc|tvnserver|vncserver|uvnc'; Logs=@() }
    @{ N='ChromeRemoteDesktop';P='remoting_host';  Logs=@() }
    @{ N='DWAgent';            P='dwagent';        Logs=@() }
    @{ N='Supremo';            P='supremo';        Logs=@() }
    @{ N='MeshAgent';          P='meshagent';      Logs=@() }
    @{ N='QuickAssist';        P='quickassist';    Logs=@() }
    @{ N='RemoteAssistance';   P='msra';           Logs=@() }
)
$procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
$svcs  = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
foreach ($tool in $RMM) {
    $hitProc = $procs | Where-Object { $_.Name -match "(?i)$($tool.P)" }
    $hitSvc  = $svcs  | Where-Object { ($_.Name -match "(?i)$($tool.P)") -or ($_.PathName -match "(?i)$($tool.P)") }
    if ($hitProc -or $hitSvc) {
        if ($hitProc) {
            $first = @($hitProc) | Select-Object -First 1
            $where = "running (PID $($first.ProcessId))"
            $path  = $first.ExecutablePath
        } else {
            $firstSvc = @($hitSvc) | Select-Object -First 1
            $where = "service: $($firstSvc.Name)"
            $path  = $firstSvc.PathName
        }
        Add-Finding 'High' 'Remote Access Tool' "$($tool.N)" "Detected $where; path: $path" 'T1219 (Remote Access Software)'
        foreach ($lg in $tool.Logs) { if ($lg -and (Test-Path -LiteralPath $lg)) { Copy-Artifact $lg ("rmm_{0}_{1}" -f $tool.N, (Split-Path -Leaf $lg)) } }
    } else {
        # not running, but capture connection logs if the tool was ever installed
        foreach ($lg in $tool.Logs) {
            if ($lg -and (Test-Path -LiteralPath $lg)) {
                Add-Finding 'Medium' 'Remote Access Tool' "$($tool.N) (residual)" "Not running, but connection log present: $lg" 'T1219 (Remote Access Software)'
                Copy-Artifact $lg ("rmm_{0}_{1}" -f $tool.N, (Split-Path -Leaf $lg))
            }
        }
    }
}

# ============================================================================
# 2. ClickFix / fake-update lure: RunMRU (Win+R history) across loaded users.
# ============================================================================
$badCmd = '(?i)(mshta|powershell|pwsh|cmd(\.exe)?\s|/c\s|curl|certutil|bitsadmin|msiexec\s+/i\s+http|iwr|invoke-webrequest|iex|invoke-expression|frombase64|-enc|hidden|\\\\|http)'
$runMru = [System.Collections.Generic.List[string]]::new()
try {
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '_Classes$' } | ForEach-Object {
        $k = "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (Test-Path -LiteralPath $k) {
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -match '^[a-z]$' -and $prop.Value) {
                    $runMru.Add("$($_.Name) | $($prop.Name) = $($prop.Value)")
                    if ($prop.Value -match $badCmd) {
                        Add-Finding 'High' 'ClickFix / RunMRU' "Win+R: $($prop.Name)" "Suspicious Run command: $($prop.Value)" 'T1204.001 (User Execution), T1059'
                    }
                }
            }
        }
    }
} catch {}
if ($runMru.Count) { $runMru | Set-Content -LiteralPath (Join-Path $ArtRoot 'runmru.txt') -Encoding UTF8 }

# Live LOLBin processes with network/encoded args (active lure execution)
foreach ($p in $procs) {
    $cl = "$($p.CommandLine)"
    if ($p.Name -match '(?i)^(mshta|powershell|pwsh|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\.exe$' -and $cl -match $badCmd) {
        Add-Finding 'High' 'LOLBin Execution' "$($p.Name) PID $($p.ProcessId)" "Command line: $cl" 'T1059, T1218'
    }
}

# ============================================================================
# 3. Browser artifacts (the fake "update" page lives here). Copy for review.
# ============================================================================
$browsers = @(
    @{ N='Edge';    H="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History";  E="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" }
    @{ N='Chrome';  H="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History";   E="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" }
)
foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    foreach ($b in $browsers) {
        $h = $b.H -replace [regex]::Escape($env:LOCALAPPDATA), "$($u.FullName)\AppData\Local"
        $e = $b.E -replace [regex]::Escape($env:LOCALAPPDATA), "$($u.FullName)\AppData\Local"
        if (Test-Path -LiteralPath $h) {
            Copy-Artifact $h ("browser_{0}_{1}_History.sqlite" -f $u.Name, $b.N)
            Add-Finding 'Low' 'Browser Artifact' "$($u.Name)/$($b.N)" "History DB collected for review: $h" 'T1204 (User Execution)'
        }
        if (Test-Path -LiteralPath $e) {
            try { (Get-ChildItem -LiteralPath $e -Directory -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime) |
                Out-File -LiteralPath (Join-Path $ArtRoot ("browser_{0}_{1}_extensions.txt" -f $u.Name, $b.N)) -Encoding UTF8 } catch {}
        }
    }
    # Firefox places.sqlite
    $ff = Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ff) {
        Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $places = Join-Path $_.FullName 'places.sqlite'
            if (Test-Path -LiteralPath $places) { Copy-Artifact $places ("browser_{0}_Firefox_places.sqlite" -f $u.Name) }
        }
    }
}

# ============================================================================
# 4. Active / interactive sessions (who was at the console when it moved).
# ============================================================================
try {
    if (Get-Command qwinsta -ErrorAction SilentlyContinue) {
        qwinsta 2>$null | Out-File -LiteralPath (Join-Path $ArtRoot 'sessions_qwinsta.txt') -Encoding UTF8
    }
} catch {}
try {
    Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -in 2,10,11 } |   # interactive / remote-interactive / cached-interactive
        Select-Object LogonId, LogonType, StartTime |
        Export-Csv -LiteralPath (Join-Path $ArtRoot 'interactive_logon_sessions.csv') -NoTypeInformation -Encoding UTF8
} catch {}

# ============================================================================
# 5. Defender tamper (attacker-added exclusions / disabled protection).
# Paths added by this IR toolkit's pre-flight are annotated as IR-origin rather
# than suppressed - they are accurate findings that an analyst should see, but
# the context note avoids them being treated as attacker activity.
# ============================================================================
# Detect IR toolkit own paths so we can label them accurately
$irtoolkitMarkers = @('IR_Toolkit','autorunsc','yara64','winpmem','procdump','sigcheck')
function Test-IRToolkitPath([string]$Path) {
    return ($irtoolkitMarkers | Where-Object { $Path -like "*$_*" }).Count -gt 0
}
try {
    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mp) {
        foreach ($ex in @($mp.ExclusionPath)) {
            if (-not $ex) { continue }
            $isIR = Test-IRToolkitPath $ex
            $detail = if ($isIR) {
                "Defender path exclusion: $ex [NOTE: matches IR toolkit path - verify this was added by responder, not attacker]"
            } else {
                "Defender path exclusion present (attacker staging paths hide here): $ex"
            }
            $sev = if ($isIR) { 'Low' } else { 'Medium' }
            Add-Finding $sev 'Defender Exclusion' "$ex" $detail 'T1562.001 (Impair Defenses)'
        }
    }
    $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($st -and (-not $st.RealTimeProtectionEnabled)) {
        Add-Finding 'Medium' 'Defender Disabled' 'RealTimeProtection' `
            "Defender real-time protection is OFF - verify this was disabled by IR toolkit pre-flight, not attacker (T1562.001)" `
            'T1562.001 (Impair Defenses)'
    }
} catch {}

# ============================================================================
# Output findings (EDR-compatible schema) + summary
# ============================================================================
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $OutputDir "RemoteAccess_Findings_$stamp.json"
if ($Findings.Count -gt 0) { $Findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $out -Encoding UTF8 }
else { '[]' | Set-Content -LiteralPath $out -Encoding UTF8 }

Write-Host "[+] Remote-access triage: $($Findings.Count) finding(s) -> $(Split-Path -Leaf $out)" -ForegroundColor Green
Write-Host "[+] Artifacts -> $ArtRoot" -ForegroundColor Green
$Findings | Group-Object Type | Select-Object @{N='Type';E={$_.Name}}, Count | Format-Table -AutoSize

# SIG # Begin signature block
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1Antn05CaYEAn
# rdNlTvHnzxhdyVCEyXTT9nOAGOfs6qCCFrQwggN2MIICXqADAgECAhAcxe7C/TZF
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
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgJmuMALqLaLTiPAAoPmncxhoBX18jHIlP
# vGOL9uTUJ1AwDQYJKoZIhvcNAQEBBQAEggEAVuguGX9DeviCnlX92q0Wk+KvsvqL
# KeA3Td1GxHW6OViHE8yrK3HgKVuBl5DzU/atRdMd5vhRdazBMiMMnDR90DKblvjw
# jenUvDIHkLj2AVwpmzSRcLtVxhaCJloK7HaCLDVMtQgRmG4WqC+QZimGyrVpPWVI
# WiGu6xEs0ioDL4tJnMCtxUU+MrcB4oncKlyqJuypFFtbEflICUEvjNDocy3NWlm6
# Bn1u1/mKtBBEOZGkPpkHu2eXGVDKI28POpO+DllbHK5LpmGXs2zPj8teymsg3xy3
# eW4aEw9jEF1iYPfUnPUOUNiFJV3Wx8vx6al0YRqOVX3JnFZlCUXPSDNga6GCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjQyMjU1NDJaMC8GCSqGSIb3DQEJBDEi
# BCBXQDvW7dKis1eE2hmrb0GlbzClFS1P33ILgkmkvLkZjjANBgkqhkiG9w0BAQEF
# AASCAgCiibhPpzj3uSMPa1pwiMnaEJgCleIg6QhYx/8Iqtbv09yNOuB0fyOt1SCX
# KimGrsoGoKc7touqnzl6IC1INZ+YdJwdPeZo1DtHZtWkFlLbihC7t8joyO8Kd1pU
# 5uq+x1qIemmlXF/MBA7u5flNDGEwCfUl9ysloUn9zrUUy1X+NpwgVePU3v4+NFQJ
# 3Gpy12HLDUyoGQVTRZPHcAX0d1REJCTT/M0TibhUnSGg/QeVlELUEwoL1XGFGp5P
# Xjt/YTnPmddeQ2VAanJUYJyufjiAwFA94ijAxdis7yUJb3e56F83CxuK9969/4tu
# ZWyOaEXSr31LpfacWlIeT3wa/4s6xlJzsedLWqRq6w5ZrPPZVkMuctv58868Fz1F
# 6GzH+VoMJPD3KHQuuT1Wx8YsA4Kza5SLEnL9PNJnJoOjyvsWnZRov7YBSrV+1CqD
# zG66Q4vcUdhbi0Uuru/qnY/F9u8VIsCPpgoZXjbYx1K9UmqIMI7tWFGKEpyTctDS
# smMZM2lCTcoMDDjbtb5djI+7onUtzn0ZRyfOg3q1eQozAJPyidUYEVd8DH2gfnGg
# 7aAxXP7m7/qw4oy43Be5OzuYHtjvqbNoH8FCpIyRNxZO9O+xX9PX9h4wz6FGpkpd
# juHtTFeE9Mtcw9IcWPJEy4WD4p4ndmdaDxHWQ5DGMwvjAakk4A==
# SIG # End signature block
