<#
.SYNOPSIS
    Parse Amcache and ShimCache execution artifacts into adjudicable findings.

.DESCRIPTION
    Reads artifacts written by Get-PersistenceSnapshot.ps1:
      amcache_parsed.csv  - programme execution history (path, SHA1, publisher, link date)
      shimcache.bin       - AppCompatCache binary blob (executed-file evidence)

    Emits findings in the canonical EDR schema for executables that:
      - Ran from user-writable or suspicious paths (AppData, Temp, Downloads, Public)
      - Match known LOLBin names but from non-system directories
      - Have no publisher (unsigned) and ran from a non-Microsoft path
      - Ran from network paths (\\server\share)

    Output: findings_amcache_<stamp>.json in -OutputDir.

.PARAMETER InputDir   Folder containing amcache_parsed.csv / shimcache.bin.
                       Defaults to the Persistence sub-folder of OutputDir.
.PARAMETER OutputDir  Where to write findings JSON. Defaults to InputDir.

.EXAMPLE
    .\Invoke-AmcacheParser.ps1 -InputDir .\reports\HOST\Persistence -OutputDir .\reports\HOST
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InputDir  = '',
    [string]$OutputDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not $InputDir)  { $InputDir  = $PSScriptRoot }
if (-not $OutputDir) { $OutputDir = $InputDir }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$Stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutFile  = Join-Path $OutputDir "findings_amcache_$Stamp.json"
$Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param([string]$Severity, [string]$Type, [string]$Target, [string]$Details, [string]$Mitre)
    $Findings.Add([PSCustomObject][ordered]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $Severity
        Type      = $Type
        Target    = $Target
        Details   = $Details
        MITRE     = $Mitre
    })
}

# -- Detection patterns --------------------------------------------------------
# Suspicious execution paths - user-writable or unusual locations
$SuspiciousPathRE = '(?i)(\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\Downloads\\|' +
                    '\\ProgramData\\(?!Microsoft\\Windows\\|Microsoft\\Windows Defender\\|Microsoft\\VisualStudio\\|Microsoft\\Edge|Package Cache)|' +
                    '\\Desktop\\|\\Documents\\|\\Music\\|\\Videos\\)'

# Network path execution (UNC \\server\share). Excludes the Win32 device-namespace
# prefixes \\?\ and \\.\ , which are LOCAL long-path forms (e.g. \\?\C:\Windows\...),
# not network shares - treating them as network paths flags local System32 binaries.
$NetworkPathRE = '^\\\\(?![?.]\\)[^\\]+'

# LOLBin names that should NOT run from user-writable locations.
# A LOLBin copy ANYWHERE outside System32/SysWOW64 is a finding - no exceptions.
$LolBinRE = '(?i)^(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|' +
             'installutil|msbuild|regasm|regsvcs|odbcconf|cmstp|msiexec|' +
             'appsync|syncappvpublishingserver)\.exe$'

function Test-SafePath { param([string]$path)
    # Only suppress LOLBin findings when the binary is in Windows' own binary directories.
    # These are the only locations where LOLBins are expected to live.
    # Everything else - including Program Files, SoftwareDistribution, ProgramData - gets flagged.
    return $path -match '(?i)^(C:\\Windows\\(System32|SysWOW64|WinSxS)\\)'
}

# ==============================================================================
# 1. Amcache CSV (written by Get-PersistenceSnapshot.ps1)
# ==============================================================================
$amcacheCsv = Join-Path $InputDir 'amcache_parsed.csv'
if (Test-Path -LiteralPath $amcacheCsv) {
    Write-Host "[*] Amcache: $amcacheCsv" -ForegroundColor Cyan
    try {
        $entries = Import-Csv -LiteralPath $amcacheCsv -ErrorAction Stop
        $flagged = 0
        foreach ($e in $entries) {
            $path = if ($e.PSObject.Properties['Path'] -and $e.Path) { [string]$e.Path } else { '' }
            if (-not $path) { continue }
            $name = [System.IO.Path]::GetFileName($path)
            $pub  = if ($e.PSObject.Properties['Publisher'] -and $e.Publisher) { [string]$e.Publisher } else { '' }

            # Rule 1: Suspicious execution path - surface ALL executions regardless of publisher.
            # A Microsoft-signed binary in AppData is still suspicious. Adjudicator adds context.
            if ($path -match $SuspiciousPathRE) {
                # High: Temp dirs and AppData\Roaming (primary malware staging locations)
                # Medium: Desktop, Downloads, Documents (accessible but less common)
                $sev = if ($path -match '(?i)\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\Temp\\') { 'High' } else { 'Medium' }
                Add-Finding $sev 'Amcache: Execution from Suspicious Path' $path `
                    "Publisher='$pub'  SHA1=$($e.SHA1)  LinkDate=$($e.LinkDate)" `
                    'T1036 (Masquerading), T1059 (Command and Scripting Interpreter)'
                $flagged++
            }
            # Rule 2: Network path execution
            elseif ($path -match $NetworkPathRE) {
                Add-Finding 'High' 'Amcache: Execution from Network Path' $path `
                    "Publisher='$pub'  SHA1=$($e.SHA1)" `
                    'T1021 (Remote Services), T1570 (Lateral Tool Transfer)'
                $flagged++
            }
            # Rule 3: LOLBin outside System32
            elseif ($name -match $LolBinRE -and -not (Test-SafePath $path)) {
                Add-Finding 'High' 'Amcache: LOLBin Executed from Non-System Path' $path `
                    "LOLBin '$name' executed from unexpected location. Publisher='$pub'" `
                    'T1218 (System Binary Proxy Execution)'
                $flagged++
            }
        }
        Write-Host "    $($entries.Count) entries, $flagged flagged" -ForegroundColor Gray
    } catch {
        Write-Host "    Parse error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] amcache_parsed.csv not found - skipping Amcache analysis" -ForegroundColor Gray
    Write-Host "    (Collection may have failed: Amcache.hve requires backup privilege)" -ForegroundColor Gray
}

# ==============================================================================
# 2. ShimCache binary (AppCompatCache registry export)
# ==============================================================================
$shimBin = Join-Path $InputDir 'shimcache.bin'
if (Test-Path -LiteralPath $shimBin) {
    Write-Host "[*] ShimCache: $shimBin" -ForegroundColor Cyan
    try {
        $raw     = [System.IO.File]::ReadAllBytes($shimBin)
        $flagged = 0

        # Windows 10/11 AppCompatCache (ShimCache) entry structure:
        #   +0  "10ts" tag (4 bytes)
        #   +4  FILETIME last-modified (8 bytes)
        #   +12 path length in bytes (2 bytes, UTF-16LE so chars = bytes/2)
        #   +14 path (UTF-16LE, pathlen bytes)
        #   +14+pathlen: variable extra data until next "10ts"
        # Each entry starts with "10ts" - scan for all markers then extract paths.
        $magic      = [BitConverter]::ToUInt32($raw, 0)
        $entryCount = [BitConverter]::ToUInt32($raw, 4)
        Write-Host "    magic=0x$($magic.ToString('X8'))  declared_entries=$entryCount  raw=$($raw.Length) bytes" -ForegroundColor Gray

        # Single-pass: collect all "10ts" marker offsets
        $markerOffsets = [System.Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $raw.Length - 14; $i++) {
            if ($raw[$i] -eq 0x31 -and $raw[$i+1] -eq 0x30 -and $raw[$i+2] -eq 0x74 -and $raw[$i+3] -eq 0x73) {
                $markerOffsets.Add($i)
            }
        }
        Write-Host "    '10ts' markers found: $($markerOffsets.Count)" -ForegroundColor Gray

        $parsed = 0
        foreach ($o in $markerOffsets) {
          # Per-entry guard: a single malformed/misaligned record must never abort
          # the whole ShimCache scan (binary offset drift can yield garbage paths).
          try {
            $pathLen = [BitConverter]::ToUInt16($raw, $o + 12)
            if ($pathLen -eq 0 -or $pathLen -gt 2000) { continue }
            $pathStart = $o + 14
            if ($pathStart + $pathLen -gt $raw.Length) { continue }

            $path = [System.Text.Encoding]::Unicode.GetString($raw, $pathStart, $pathLen)
            # Skip records that don't look like a real Windows path (offset drift / garbage).
            # A valid ShimCache path starts with a drive letter, \\UNC, or \??\ / \SystemRoot.
            if ($path -notmatch '(?i)^([a-z]:\\|\\\\|\\\?\?\\|\\SystemRoot\\|SYSVOL\\)') { continue }
            # Safe filename extraction - GetFileName throws on illegal chars, so split manually.
            $name = ($path -split '\\')[-1]
            $parsed++

            if ($path -match $SuspiciousPathRE) {
                $sev = if ($path -match '(?i)\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\Temp\\') { 'High' } else { 'Medium' }
                Add-Finding $sev 'ShimCache: Execution from Suspicious Path' $path `
                    'Recorded in AppCompatCache - executed from user-writable path. Pivot: check Amcache for SHA1, Event 4688 for cmdline.' `
                    'T1036 (Masquerading), T1059 (Command and Scripting Interpreter)'
                $flagged++
            } elseif ($path -match $NetworkPathRE) {
                Add-Finding 'High' 'ShimCache: Execution from Network Path' $path `
                    'AppCompatCache records execution from network share. Pivot: check lateral movement indicators, 4648/4624 logon events.' `
                    'T1021 (Remote Services), T1570 (Lateral Tool Transfer)'
                $flagged++
            } elseif ($name -match $LolBinRE -and -not (Test-SafePath $path)) {
                Add-Finding 'High' 'ShimCache: LOLBin Executed from Non-System Path' $path `
                    "LOLBin '$name' recorded in ShimCache outside System32. Pivot: check Event 4688 cmdline for encoded/downloaded payload." `
                    'T1218 (System Binary Proxy Execution)'
                $flagged++
            }
          } catch { continue }   # skip this malformed entry, keep scanning the rest
        }
        Write-Host "    $parsed entries parsed, $flagged flagged" -ForegroundColor Gray
    } catch {
        Write-Host "    ShimCache parse error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[i] shimcache.bin not found - skipping ShimCache analysis" -ForegroundColor Gray
    Write-Host "    (Run Get-PersistenceSnapshot.ps1 to collect ShimCache)" -ForegroundColor Gray
}

# ==============================================================================
# Output
# ==============================================================================
$count = $Findings.Count
if ($count -gt 0) {
    $Findings | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Host "`n[+] $count finding(s) -> $(Split-Path $OutFile -Leaf)" -ForegroundColor Green
    $Findings | Group-Object Severity | Sort-Object @{E={@('Critical','High','Medium','Low').IndexOf($_.Name)}} |
        ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor $(
            switch ($_.Name) { 'Critical'{'Red'} 'High'{'DarkRed'} 'Medium'{'Yellow'} default{'Cyan'} }
        ) }
} else {
    Write-Host "`n[+] No suspicious Amcache/ShimCache entries detected." -ForegroundColor Green
    '[]' | Out-File -FilePath $OutFile -Encoding UTF8
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDRIIzgQJGvhGuP
# HZ8fsfEdsv3BvPcvFGL0dM0YzuqgaqCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg3F3BaxGypcTkXPwPoYr1NcHu2E51hDbQH7PE
# Etkqw2MwDQYJKoZIhvcNAQEBBQAEggEAFylUFhfBSyKRLfDVQzCsxG2RByixugE7
# eGpRJh+7fgQEIQGc2wgm18wUljMNLKXoLI1sKQu1l5s8YzItPS1pHzu+4dPULzLp
# wRgC+F4iJx7AFDf6Xd8ZJU1ltifpqv4rMmeQGzQiYAzL4uKHfBzc2UsceLw1GCWx
# dSE3XZjwTQjTQRP9NPD1x2bKm5pbPQsFVkCHYDeSSDq2lCQ/xY+fFuL5mtmuTGeh
# Ku5CVdkeZHgqb2TlOsK+VsBMbGqEzj1HKe5ccMf9bRO5S1+imw1ExU9derDf0q6l
# n/8wMpSYExWiDy1+yfRFjZfcVf+nHXTmH0K7FmnMmDHCoElkhaXKraGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MjJaMC8GCSqGSIb3DQEJBDEiBCAD
# aTLYhaHTf88Hvs5YtZYpROTaWw5HUbUAAMNS9/zMDTANBgkqhkiG9w0BAQEFAASC
# AgBWgzwuNbb3aSeWEC7BhdELXD1atRHbgqDaQC17tR0naRfIeWg5Yg7TG0OIM0ou
# bxikTlGdZ++6mCCA3/dsdeNFgZ2vxuVSYyGXK3zeL7fiusaygnVARykFmDCvfRiC
# PS45JMwCpsA1eBNwRUXMo7d+Xir25PHmIrINAHGXA36M9RyKvIDW0ltzvSxW9pl+
# MDJSMBBzy5dXI0SPtTE50d8SaLBm2gmyGjwABQSdZy28E/gErVy34eIsKJ/WJqT1
# +eDavWipc6LWwyLeA2KKcgMifEoMj3VuaCGmRMesUHn+3lTpyLbG15ARcvXVnwPG
# KpC1s28mD1c4AqKZ6B11nZsQ+bld6aa5u0xe64rcJCyYze5Ds97sWw+f2tTQoGM2
# qXLYJXMMustwmCgqfgu/UdEXNWSNhNFOwTBGLg5iQ9qYb2idjtCAi3J9IJCJ6aWJ
# NvNI+bRzwu576Onl6yUk/bPfxmmeldAHNZ08ISq3NqWAGgDmfFCVXPyf5Pfh/mRU
# e3oeyJHTw1VD4OOYs7dM+GrzLEBq88UaIRW1rIqHDDeEWIpPFqn8kie9bLV5soKf
# QUFyVQfXBDYP6Y+zR4D+YAwQhzykX5+eBEMSSGXjYGuAi6Y5F4lBU53yJ/uDE0oz
# Z96j0xAQA3KKtqKoINX6EikhlBrsMdh7IaVPfM9X51c8kA==
# SIG # End signature block
