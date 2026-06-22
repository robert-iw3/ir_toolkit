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
            # Safe filename extraction — GetFileName throws on illegal chars, so split manually.
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
# MIIcoQYJKoZIhvcNAQcCoIIckjCCHI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbMC600cxpNvZw
# EdEQwdxB21ceQHIVmUa/cQpq7sM/M6CCFrQwggN2MIICXqADAgECAhAbL3xr3F9b
# nkbveZC/LiR8MA0GCSqGSIb3DQEBCwUAMFMxGjAYBgNVBAsMEUluY2lkZW50IFJl
# c3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0MSAwHgYDVQQDDBdJUiBUb29sa2l0
# IENvZGUgU2lnbmluZzAeFw0yNjA2MjIwNDI0NDVaFw0zMTA2MjIwNDM0NDVaMFMx
# GjAYBgNVBAsMEUluY2lkZW50IFJlc3BvbnNlMRMwEQYDVQQKDApJUiBUb29sa2l0
# MSAwHgYDVQQDDBdJUiBUb29sa2l0IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKuTSorzjXf0qc4qX04KtYn2ErVj9RAkn/1f/9YN
# llrRj0s3urh/LnWmHn4vUjPrDTzHXUx4udOclWNlv52uCMAfXKZR3qD73OCHHQ2l
# +1s4JqrAdGhr6QPyIhCDwl7wqQUfekQtBep+SqbM0vkbvup3WKgol+c3fIUxvM8E
# bPLg5CcNWug6Twj+Wn1FJidJihmYARSKT5PFv32BLbffUpuvdWXxzRIRv8c4EE+S
# bWs3lTiCGrp1X33mXYiMRNAiF5ofrCJwRA7LESh4TCqXWDSvs+KFBi1ZxEnLxmUk
# 1Wrzq11umlIzoJhnEN0VyBvLK6X40uTF50piU+5kGy9kZlkCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSpc1pf
# XTSlgxdtXKDrlumz7H67TjANBgkqhkiG9w0BAQsFAAOCAQEAdPAxdgyk/YzF72lK
# 4P1I3Lwjice2yAR0aoXSEP5gO/xnAvuqCiAcdPfJhqMrrfq5iFLqTuWSfz+k9irn
# hjzyWgmo2GUrQ8BVRoNAw7HpTJo7Rw8+FfDzyy+stq9UKWrkflHqwb7oBD+aBs/5
# ZccFKZi8oeV79CCTGdwXKYgE+xYbV//Twr7rpMbVUqbchEDdZXEzT2GdEUd5B02L
# bDGJ4Gjz8AtCFcSXWQlLnAQxd5CJVFHDkyfkEs2VvBPtR/MBCF3NiNufb8HgClhS
# ZHayqVVZhUd+NS7/orBY5M1Ioc0/kGiNO3nlWf1IlAPk/jsILweFZkUO0wBTot/O
# b18zszCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
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
# MB4GA1UEAwwXSVIgVG9vbGtpdCBDb2RlIFNpZ25pbmcCEBsvfGvcX1ueRu95kL8u
# JHwwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLcbXzqXYZRtu224/F+hNbRjKSYBtIHQw
# rJ53ktuHWqAwDQYJKoZIhvcNAQEBBQAEggEARWvdZrdHco0MWnEOlyvKvBRPEjKT
# dKKKEGB0/xvmS3pkhgWitcGe8ZH6OXKX3DZxJ+CNeK3T+4n1YvJBTaYIGr5KjJdg
# tI8m5wQQ+2/9/qcaR4uSCAikmD76yRiZVHZ/BX0Z13eYKsaPp9yfwE/v6BzvMvWW
# jy7huYMPEx4lrLmiIAiiBEDwfyYWzajuxpx+YivOMmA+WKN1t3II3oE9okIesWWH
# 1BHfrLG8SHr0mVLE13IHfeLgVZGhjcIfvMISzOPHxsPiFNV/ete0gCfelLRxMvb2
# eFCm+s8DSIpSYmRUr9zyWiCgDbof+1YBhPECzNwHstvvsntpsTpJdtBSyqGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MjIwNDM0NTVaMC8GCSqGSIb3DQEJBDEi
# BCA4LILbfC2WWV37ntKFP3uIBN1VYmTqnvyC45JA5jLyfjANBgkqhkiG9w0BAQEF
# AASCAgCars0fnDHGNkzQWLV2AvLsqJ4AztZldHWfoX6YNG/cslm7EMkLihhGOkZo
# 8WmAYhBMbScZT2jFHRSvrSsvu6inSOvNxERr5CbuOXaAH0kI7eGbN0+6ic7JXojm
# OvZJIxaeA5lSnJvPrm7QPRwE16x9dWjNfqyPTfzRja+Z71D8Jh05oZBTPp1+JONT
# 0of2WMnHuZT/VBa+6LM4m/Xo5L0h/i316o2z7N2MLemBzg/GPKgXR3pJKBM+tD7z
# DzpaSVQ6x2aizB9r6qxONXNRpb+V9F/SaldsVF1jPNw1UxiFCODQ6sHfhrOv+Pud
# NXbI+Hwu0n46qEkdh2nh+F3dEoqnSh6v71krcXe/hiF2iz2/40+9w33VjKSPVzUi
# OBoc3kB1mlF9mZ2A8+jrz0bI/wNtulS2eS5nJdadKJDhAWz+N0K1uU9A2PVt2UZu
# jKYj1XkuFXweHZcZ/ezuLe4F/r3KWPncbeMucpPUTiK5wbMwA/mIUVY12awZbf8X
# lzkIwDUGBpPehh8QUMvpZqtJd+lPFpHr98MZOpJzQWMblbq7FhHnCPZvrkuevLa2
# 6rctLQAlBi2RzVZs+hzdMD5zmXFCtQgScHPgUFGBNEc9ZX/QhIrBSNgvFqEZ66pL
# qdW/nq+B2X2klMS6ezAx9JVzVYfOdURXouvLZrUiPjryvCV/xQ==
# SIG # End signature block
