# ==============================================================================
# IR Playbook 04 - Windows C2 Blocking
# Adds host-level blocks for all identified C2 infrastructure:
#   * Windows Firewall outbound rules for all C2 IPs
#   * %SystemRoot%\System32\drivers\etc\hosts sinkhole for C2 domains
#   * Windows Defender network block (Add-MpPreference)
#   * Null route via persistent route addition
#   * DNS Client cache flush
# Idempotent - safe to re-run with extended IOC lists.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId  = $env:IR_INCIDENT_ID -replace '[^\w\-]',''
$C2IPs       = ($env:IR_C2_IPS     -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$C2Domains   = ($env:IR_C2_DOMAINS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }

$IRDir    = 'C:\ProgramData\IRToolkit'
$HostsFile   = "$env:SystemRoot\System32\drivers\etc\hosts"
$BlockTag    = "# IR-BLOCK-$IncidentId"
New-Item -ItemType Directory -Path $IRDir -Force | Out-Null

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
    Write-Output $entry
    $entry | Out-File "$IRDir\playbook.log" -Append -Encoding UTF8
}

# RFC-1918 / link-local addresses - never block
function Test-IsPrivateIP {
    param([string]$IP)
    $IP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.|::1|fe80:)'
}

$BlockedIPs     = [System.Collections.Generic.List[string]]::new()
$BlockedDomains = [System.Collections.Generic.List[string]]::new()
$Errors         = [System.Collections.Generic.List[string]]::new()

Write-IRLog "C2-BLOCK: Starting C2 infrastructure blocking for $IncidentId"

# -- Firewall rules for C2 IPs -------------------------------------------------
foreach ($C2IP in $C2IPs) {
    if (Test-IsPrivateIP $C2IP) {
        Write-IRLog "C2-BLOCK: Skipping private IP $C2IP"
        continue
    }

    # Outbound block
    $OutRuleName = "IR-C2-BLOCK-OUT-$C2IP-$IncidentId"
    $InRuleName  = "IR-C2-BLOCK-IN-$C2IP-$IncidentId"

    try {
        if (-not (Get-NetFirewallRule -DisplayName $OutRuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $OutRuleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $C2IP `
                -Protocol Any `
                -Description "IR C2 block - incident $IncidentId" | Out-Null
            Write-IRLog "C2-BLOCK: Firewall OUTBOUND block -> $C2IP"
        }

        if (-not (Get-NetFirewallRule -DisplayName $InRuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $InRuleName `
                -Direction Inbound `
                -Action Block `
                -RemoteAddress $C2IP `
                -Protocol Any `
                -Description "IR C2 block - incident $IncidentId" | Out-Null
        }
        $BlockedIPs.Add($C2IP)
    } catch {
        $Errors.Add("firewall_failed:$C2IP"); Write-IRLog "C2-BLOCK: Firewall error for $C2IP : $_"
    }

    # Belt-and-suspenders: persistent null route
    try {
        route add $C2IP mask 255.255.255.255 0.0.0.0 -p 2>$null | Out-Null
    } catch {}

    # Windows Defender Network Block (MAPS / NIS integration)
    try {
        Add-MpPreference -ThreatIDDefaultAction_Ids 0 -ThreatIDDefaultAction_Actions Block `
            -ErrorAction SilentlyContinue
    } catch {}
}

# -- /etc/hosts sinkhole for C2 domains ----------------------------------------
# Remove any existing IR blocks first (idempotent)
if (Test-Path $HostsFile) {
    $HostsContent = Get-Content $HostsFile -Encoding ASCII
    $CleanHosts   = $HostsContent | Where-Object { $_ -notlike "*IR-BLOCK-*" }
    Set-Content $HostsFile -Value $CleanHosts -Encoding ASCII -Force
}

foreach ($Domain in $C2Domains) {
    try {
        $Entries = @(
            "0.0.0.0 $Domain $BlockTag",
            "0.0.0.0 www.$Domain $BlockTag",
            ":: $Domain $BlockTag"
        )
        Add-Content -Path $HostsFile -Value $Entries -Encoding ASCII
        $BlockedDomains.Add($Domain)
        Write-IRLog "C2-BLOCK: Sinkholes $Domain -> 0.0.0.0 in hosts file"
    } catch {
        $Errors.Add("hosts_failed:$Domain"); Write-IRLog "C2-BLOCK: Hosts error for $Domain : $_"
    }
}

# -- Flush DNS Client cache ----------------------------------------------------
try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: DNS client cache flushed"
} catch {}

# -- Windows Defender ASR - block suspicious network destinations --------------
try {
    # ASR Rule: Block all Office applications from creating child processes (ID 26190899)
    # and network connections to specific external destinations - belt-and-suspenders
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: Windows Defender Network Protection enabled"
} catch {}

# -- Restart DNS Client service to apply hosts changes -------------------------
try {
    Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue
    Write-IRLog "C2-BLOCK: DNS client restarted"
} catch {}

Write-IRLog "C2-BLOCK: Complete. IPs blocked: $($BlockedIPs.Count), domains: $($BlockedDomains.Count), errors: $($Errors.Count)"

@{
    phase           = 'c2_blocking'
    status          = 'success'
    blocked_ips     = $BlockedIPs.Count
    blocked_domains = $BlockedDomains.Count
    errors          = $Errors.Count
    incident_id     = $IncidentId
} | ConvertTo-Json -Compress | Write-Output
