<#
.SYNOPSIS
    Standalone orchestrator for the Windows RESPONSE playbooks (contain / eradicate /
    block-C2 / acquire / restore). Completely separate from the collection workflow
    (Invoke-IRCollection.ps1) - this one CHANGES the host.
.DESCRIPTION
    Runs the playbooks in playbooks\windows\ in canonical IR order, feeding each its
    inputs via the IR_* environment variables the scripts expect. Each playbook
    runs in its own powershell process and its output is logged to a Response folder.

    These actions are DESTRUCTIVE (kill processes, isolate the network, quarantine
    files, sinkhole domains). The orchestrator therefore:
      * runs nothing unless you both pass -Phases AND -Confirm (otherwise it prints
        the plan and exits - a dry run),
      * refuses Contain without -MgmtIPs (would sever remote access),
      * always runs phases in safe order regardless of the order you list them.

.PARAMETER Phases   Which playbooks to run: Collect, Contain, EradicateProcess,
                    EradicatePersistence, BlockC2, Acquire, Restore.
.PARAMETER Confirm  Required to actually execute. Without it: dry-run plan only.
.EXAMPLE
    # Dry-run plan:
    .\Invoke-WindowsPlaybooks.ps1 -Phases EradicateProcess,BlockC2 -MaliciousPids 6624 -C2IPs 8.8.8.8
.EXAMPLE
    # Execute containment + eradication:
    .\Invoke-WindowsPlaybooks.ps1 -Phases Contain,EradicateProcess,BlockC2 `
        -MgmtIPs 10.0.0.5 -MaliciousProcesses anydesk -C2IPs 45.61.2.3 -Confirm
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Collect','Contain','EradicateProcess','EradicatePersistence','BlockC2','Acquire','Restore')]
    [string[]]$Phases,
    [string]$IncidentId,
    [string]$OutputRoot = $PSScriptRoot,
    # Inputs consumed by the playbooks (comma-separated where plural):
    [string]$MgmtIPs,
    [string]$MaliciousPids,
    [string]$MaliciousProcesses,
    [string]$MaliciousHashes,
    [string]$MaliciousPaths,
    [string]$C2IPs,
    [string]$C2Domains,
    [string]$TargetPath,
    [string]$QuarantineUri,
    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $IncidentId) { $IncidentId = "$($env:COMPUTERNAME)_$RunStamp" }
if (-not $OutputRoot) { $OutputRoot = (Get-Location).Path }
$OutDir = Join-Path $OutputRoot ("Response_" + $IncidentId)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$RunLog = Join-Path $OutDir "_response_$RunStamp.log"

function Write-Log { param([string]$M,[string]$C='Gray')
    $line="[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $M"; Write-Host $line -ForegroundColor $C
    $line | Out-File -FilePath $RunLog -Append -Encoding UTF8
}

# Canonical phase order + script mapping. (00 is param-based; 01-06 read IR_* env.)
$PhaseDefs = [ordered]@{
    Collect              = @{ Order=0; Script='windows\00_Collect-Forensics.ps1';     Destructive=$false }
    Contain              = @{ Order=1; Script='windows\01_Contain-Host.ps1';          Destructive=$true  }
    EradicateProcess     = @{ Order=2; Script='windows\02_Eradicate-Process.ps1';     Destructive=$true  }
    EradicatePersistence = @{ Order=3; Script='windows\03_Eradicate-Persistence.ps1'; Destructive=$true }
    BlockC2              = @{ Order=4; Script='windows\04_Block-C2.ps1';              Destructive=$true  }
    Acquire              = @{ Order=5; Script='windows\05_Acquire-Artifact.ps1';      Destructive=$false }
    Restore              = @{ Order=6; Script='windows\06_Restore-Host.ps1';          Destructive=$true  }
}

if (-not $Phases) {
    Write-Host "No -Phases specified. Available (canonical order):" -ForegroundColor Yellow
    $PhaseDefs.Keys | ForEach-Object { Write-Host "  - $_" }
    Write-Host "Re-run with -Phases <...> (and -Confirm to execute)." -ForegroundColor Yellow
    return
}

# Map inputs to the IR_* env vars the playbooks read (set once; children inherit).
$env:IR_INCIDENT_ID = $IncidentId
if ($PSBoundParameters.ContainsKey('MgmtIPs'))            { $env:IR_MGMT_IPS            = $MgmtIPs }
if ($PSBoundParameters.ContainsKey('MaliciousPids'))      { $env:IR_MALICIOUS_PIDS      = $MaliciousPids }
if ($PSBoundParameters.ContainsKey('MaliciousProcesses')) { $env:IR_MALICIOUS_PROCESSES = $MaliciousProcesses }
if ($PSBoundParameters.ContainsKey('MaliciousHashes'))    { $env:IR_MALICIOUS_HASHES    = $MaliciousHashes }
if ($PSBoundParameters.ContainsKey('MaliciousPaths'))     { $env:IR_MALICIOUS_PATHS     = $MaliciousPaths }
if ($PSBoundParameters.ContainsKey('C2IPs'))              { $env:IR_C2_IPS              = $C2IPs }
if ($PSBoundParameters.ContainsKey('C2Domains'))          { $env:IR_C2_DOMAINS          = $C2Domains }
if ($PSBoundParameters.ContainsKey('TargetPath'))         { $env:IR_TARGET_PATH         = $TargetPath }
if ($PSBoundParameters.ContainsKey('QuarantineUri'))      { $env:IR_QUARANTINE_URI      = $QuarantineUri }

# Resolve + order the requested phases.
$plan = $Phases | Select-Object -Unique | Sort-Object { $PhaseDefs[$_].Order }

# Safety preconditions
$abort = $false
if (($plan -contains 'Contain') -and -not $MgmtIPs) {
    Write-Log "REFUSED: Contain requires -MgmtIPs (otherwise you isolate yourself out)." 'Red'; $abort = $true
}
if (($plan -contains 'Acquire') -and -not $TargetPath) {
    Write-Log "REFUSED: Acquire requires -TargetPath." 'Red'; $abort = $true
}
if ($abort) { return }

$mode = if ($Confirm) { 'EXECUTE' } else { 'DRY-RUN' }
Write-Log "===================================================" 'Green'
Write-Log " WINDOWS RESPONSE PLAYBOOKS ($mode) | incident=$IncidentId" 'Green'
Write-Log " plan: $($plan -join ' -> ')" 'Green'
Write-Log " output -> $OutDir" 'Green'
Write-Log "===================================================" 'Green'

$PSExe = (Get-Process -Id $PID).Path
if (-not $PSExe) { $PSExe = Join-Path $PSHOME 'powershell.exe' }

$results = foreach ($name in $plan) {
    $def = $PhaseDefs[$name]
    $script = Join-Path $PSScriptRoot $def.Script
    $rec = [ordered]@{ Phase=$name; Script=$def.Script; Destructive=$def.Destructive; Status='' }
    if (-not (Test-Path -LiteralPath $script)) { Write-Log "SKIP $name - not found: $script" 'Yellow'; $rec.Status='missing'; [PSCustomObject]$rec; continue }

    $tag = if ($def.Destructive) { '[DESTRUCTIVE]' } else { '' }
    if (-not $Confirm) {
        Write-Log "WOULD RUN: $name $tag -> $($def.Script)" 'Yellow'; $rec.Status='planned'; [PSCustomObject]$rec; continue
    }

    Write-Log "==== RUN: $name $tag ====" 'Cyan'
    $phaseLog = Join-Path $OutDir ("_{0}_{1}.log" -f $name, $RunStamp)
    $argList  = @('-ExecutionPolicy','Bypass','-NoProfile','-File', $script)
    if ($name -eq 'Collect') { $argList += @('-OutputDir', $OutDir, '-IncidentId', $IncidentId) }
    try {
        & $PSExe @argList *>&1 | Tee-Object -FilePath $phaseLog -Append
        Write-Log "  $name complete (log: $(Split-Path -Leaf $phaseLog))" 'Green'; $rec.Status='ran'
    } catch { Write-Log "  ERROR in ${name}: $($_.Exception.Message)" 'Red'; $rec.Status='error' }
    [PSCustomObject]$rec
}

[ordered]@{
    incident_id=$IncidentId; host=$env:COMPUTERNAME; mode=$mode
    generated_utc=(Get-Date).ToUniversalTime().ToString('o'); plan=$plan; results=$results
} | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $OutDir "response_summary_$RunStamp.json") -Encoding UTF8

Write-Log "===================================================" 'Green'
Write-Log " RESPONSE $mode COMPLETE" 'Green'
if (-not $Confirm) { Write-Log " DRY-RUN: nothing changed. Add -Confirm to execute." 'Yellow' }
Write-Log " $OutDir" 'Green'
Write-Log "===================================================" 'Green'

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALCUW6maRV7hyf
# GuH6fgZpVdPvlM3yDI7yiLT9Y9L9IKCCFlIwggMUMIIB/KADAgECAhAfQMjwyAWn
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgcTV5ijzb1jnqEHAcaCCp9W1Vx5dlRm62RPhJ
# 7KwE0/QwDQYJKoZIhvcNAQEBBQAEggEAhOwjJInY9TRZB/aCM4GqBZowkSg6T/fs
# CkWBbovFjobp6IUw8uqN8Om2ppkqFwjmcbG8CeCeIE2ML2sXy7/8Ji6vviQvv5x1
# 7EfBSmpNryVly2Ha4YB/oSeE1jwXpWEXGQIAlgn8fs+pb2EkYyfc0XWGKF7fqdOO
# GT4nprnEDUHwH+5ejgGk/jNfYZ+FZqpxYBxizdN+1DrZk/TQk1EaHMbofkfDY8UN
# VkkOuamMutC4WjQ/nHXNwdOadc8CjYe1+NDr2gtPytu3VYZq4o5P8oEujXzxualK
# UaIagF+HY9dI+z7FRcbEmYMUHfWHqnymX/O0wyeDkp0cQHyV1csC56GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjA2MjYwMjM4MTZaMC8GCSqGSIb3DQEJBDEiBCAu
# Y+XE0+5JMkqJ4OyEgyVFaxH3cGVj84845DTU3wor2jANBgkqhkiG9w0BAQEFAASC
# AgAy9prT6eSB3avDyCglrlnQRUvHBicpHoF7xq9Uo/SoZf9s3GKeckD0inlAt5eU
# lKf71w5MfgtjVqG5gePK7EIZXOLchvwQiWcpp+GzuogTnbrPRd59ruQXkBCQuixo
# uwSiCWUTBOvUUUtWxG1cJdNuDrH58ZGimm1mdZZ5qo8+01YXS6QGICJKq7bEvAxx
# UGR6UWDPSeHUVkeyYHKp2h/L4mfwKC27nGRnGy0YgbSMEUnBjEM5Br2Lt08lcUD/
# Ei6VMRAXVU6NrNFaqRHoHMnItv1VXyApZyqq1bNr/FrUiAepH9y27BGdJ1bGe1qR
# EJM95HUJYhzQSYPN2g+3n+gCW4if8MeO3wu8f/c5scj+ILuLQ85twBRLeZ3vwYwb
# PvtWbmPeXmI/H//NfrLHPMVz4YyPefJPdNB9HDj6hTM8yC2MqjMNa1P8kbj0Xu4d
# 4znZPnKwldZiFiOQZMzq5JnyN6TjYmHhEslZaj/htOab6vO2yOwGAnsj9fSLKBC/
# FsJ69ieC0suP2gbQ5WF8HnytKA7YP9Bgsu1r2Vo2WVghn/4tyRn5NEGaw3LRSqre
# BhZBzAwHAhhHN1uVAPwVBjQqAFRlTCnQkKDVWRUhv2wSA9Deo0Urtso2scbdEU8X
# hQOcynqhVvVImI9gL5hrlvtHqCIlv/S+gTOlSsG16s5hcQ==
# SIG # End signature block
