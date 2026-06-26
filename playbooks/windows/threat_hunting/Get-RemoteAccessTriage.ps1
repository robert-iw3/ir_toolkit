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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1Antn05CaYEAn
# rdNlTvHnzxhdyVCEyXTT9nOAGOfs6qCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgJmuMALqLaLTiPAAoPmncxhoBX18jHIlPvGOL
# 9uTUJ1AwDQYJKoZIhvcNAQEBBQAEggEAPYYTc+jrPeI5UOPSBEbjlXormWu5IXEI
# yoHlQqpzEyDZI/zHvYOMqbSXN/5JdQgbL3KoKygAT4gjvm4laxMcKVFe4e1pD8Nk
# Qc9zXK7OWmKctHvPfUn3Vr105NQmxEOpECCJMtm2vD/JqkhQuBo9nNdy1RikXNM8
# s3xoMwsm8y4dgzv0Jbcrp7QACdk0BGhr/fmA1q44U69UY24aSFiciumxMVN0Tx+c
# WKodgAmrP7TkbiKRj5xPm5JM6IF3LWp5j2tdFhxrZyBqUsR+z5MXcl65DeZW7ron
# Z8s0JyZWfYY7ojNCDcmpxw/y8ggP8qElQ51BhGl8puh0+Jir2i63wqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MjJaMC8GCSqGSIb3DQEJBDEiBCAE
# i02Q4KKzPVCs8HmDRExpVSmO6Hq4KKiIGv5QW5JKfjANBgkqhkiG9w0BAQEFAASC
# AgCd8Ii5ixEgWi/hLykhUrrpk6gDKTCb/HgR58xPIhuAY/pZ+J7CPoSlrLZ1l0YT
# r6RY+aM4MPiPhWkbTyQvQ1ZrZPue+UoIpPPxS1oVf+k1D0ZtNlE7QfKu6GVc/N2X
# 7iB6EEBD/xFgvKsq//OIkgIng2w2KHUVpvpP+g1dHND+PuN4LsV5HZYF9FZbyqE1
# 0jAeySbDKkUkJzPWh+Q0YCAWfAzYbhrU0MmkKlbckDvT3UKe4WuQJl7uKgSV49ok
# g/IVsY3QA43W5cylqtFJWlf4hnKpgKFRT9wiHUKt1mbrsxqLHI1+XhrOAEqxVvsf
# QwL01lnoR30zShsYWauElgEC6HXx9S/ULYNwBu293z+aovGCsMBQ+b734y5qL4mU
# f9LEjitUO3yJXCmm29w5swxoHeQoGTwjTHZIjHEpnocSuwmkBNq6D7izjiRCdMS+
# u66kc7EGFhS2cAwtG5qNj748wMqWX2a5AjyBPS0Twmpr9sQ6ahy71LBIRXmnLyRI
# CENzBUiACzVttoTh9ltND8tErB/6OHz9f9GqdjvzZbhl50EpLDTLd+SJDonEW9W5
# yIIrDST8PoDIbr6Y8N3QX/G+lE9jH7te0NZKisTE5PY3RrCjXBAh2oEnQ9UxGgfR
# qnJjLxM/p2G45+vYThz/Rh6EYJKJ/MGR/J6Y7hEV3RJPtA==
# SIG # End signature block
