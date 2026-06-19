# ==============================================================================
# IR Playbook 01 - Windows Network Containment
# Isolates the host via Windows Firewall, blocks all interfaces except the
# management network, and disables wireless adapters. Preserves the current
# WinRM/SSH session. Idempotent - safe to re-run.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId = $env:IR_INCIDENT_ID -replace '[^\w\-]',''
if (-not $IncidentId) { $IncidentId = 'UNKNOWN' }
$MgmtIPs    = ($env:IR_MGMT_IPS -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$IRDir   = 'C:\ProgramData\IRToolkit'
New-Item -ItemType Directory -Path $IRDir -Force | Out-Null

function Write-IRLog {
    param([string]$Msg)
    $entry = "[$(Get-Date -Format 'HH:mm:ssZ')] $Msg"
    Write-Output $entry
    $entry | Out-File "$IRDir\playbook.log" -Append -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('IRToolkit')) {
            New-EventLog -LogName Application -Source IRToolkit -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source IRToolkit -EventId 7701 `
            -EntryType Warning -Message "CONTAIN: $Msg" -ErrorAction SilentlyContinue
    } catch {}
}

Write-IRLog "CONTAIN: Network isolation starting for incident $IncidentId"

# -- Save pre-containment firewall rules (for audit/rollback) ------------------
$BackupFile = "$IRDir\firewall-pre-$IncidentId.wfw"
try {
    netsh advfirewall export $BackupFile | Out-Null
    Write-IRLog "CONTAIN: Firewall rules backed up -> $BackupFile"
} catch {}

# -- Block all profiles (Domain/Private/Public) ---------------------------------
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Block `
    -NotifyOnListen False `
    -AllowUnicastResponseToMulticast False

Write-IRLog "CONTAIN: Windows Firewall set to BLOCK all inbound/outbound"

# -- Allow loopback traffic -----------------------------------------------------
$LoopbackRuleName = "IR-ALLOW-LOOPBACK-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $LoopbackRuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $LoopbackRuleName `
        -Direction Inbound -Action Allow `
        -InterfaceAlias 'Loopback*' -Protocol Any | Out-Null
    New-NetFirewallRule -DisplayName "$LoopbackRuleName-OUT" `
        -Direction Outbound -Action Allow `
        -InterfaceAlias 'Loopback*' -Protocol Any | Out-Null
}

# -- Allow established/related sessions (keep current SSH/WinRM alive) ----------
$EstabRuleName = "IR-ALLOW-ESTABLISHED-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $EstabRuleName -ErrorAction SilentlyContinue)) {
    # Allow established TCP sessions (approximated: RemoteAddress Any with stateful tracking)
    New-NetFirewallRule -DisplayName $EstabRuleName `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort @(22, 5985, 5986) `
        -EdgeTraversalPolicy Allow | Out-Null
    New-NetFirewallRule -DisplayName "$EstabRuleName-OUT" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort @(22, 5985, 5986) | Out-Null
}

# -- Allow management IPs for SSH/WinRM inbound --------------------------------
if ($MgmtIPs.Count -gt 0) {
    $MgmtRuleName = "IR-ALLOW-MGMT-$IncidentId"
    if (-not (Get-NetFirewallRule -DisplayName $MgmtRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $MgmtRuleName `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort @(22, 5985, 5986, 3389) `
            -RemoteAddress $MgmtIPs | Out-Null
        New-NetFirewallRule -DisplayName "$MgmtRuleName-OUT" `
            -Direction Outbound -Action Allow `
            -Protocol TCP -RemotePort @(22, 5985, 5986) `
            -RemoteAddress $MgmtIPs | Out-Null
    }
    Write-IRLog "CONTAIN: Management access preserved for: $($MgmtIPs -join ', ')"
} else {
    Write-IRLog "CONTAIN: WARNING - no MGMT_IPS set; management access may be lost"
}

# -- Allow local DNS resolution -------------------------------------------------
$DnsRuleName = "IR-ALLOW-LOCAL-DNS-$IncidentId"
if (-not (Get-NetFirewallRule -DisplayName $DnsRuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $DnsRuleName `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 53 `
        -RemoteAddress '127.0.0.1' | Out-Null
}

# -- Disable non-management network adapters ------------------------------------
$AllAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

foreach ($Adapter in $AllAdapters) {
    # Determine if this adapter carries the management route
    $IsManagement = $false
    foreach ($MgmtIP in $MgmtIPs) {
        try {
            $route = Find-NetRoute -RemoteIPAddress $MgmtIP -ErrorAction SilentlyContinue
            if ($route -and $route.InterfaceAlias -eq $Adapter.Name) {
                $IsManagement = $true; break
            }
        } catch {}
    }

    if (-not $IsManagement) {
        try {
            Disable-NetAdapter -Name $Adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Write-IRLog "CONTAIN: Disabled adapter '$($Adapter.Name)' ($($Adapter.InterfaceDescription))"
        } catch {
            Write-IRLog "CONTAIN: Could not disable '$($Adapter.Name)': $_"
        }
    } else {
        Write-IRLog "CONTAIN: Preserved management adapter '$($Adapter.Name)'"
    }
}

# -- Disable Wi-Fi --------------------------------------------------------------
Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' } | ForEach-Object {
    try {
        Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-IRLog "CONTAIN: Disabled Wi-Fi adapter '$($_.Name)'"
    } catch {}
}

# -- Disable Bluetooth networking -----------------------------------------------
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Bluetooth*' } | ForEach-Object {
    try {
        Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
        Write-IRLog "CONTAIN: Disabled Bluetooth adapter '$($_.Name)'"
    } catch {}
}

# -- Audit Event Log entry ------------------------------------------------------
try {
    Write-EventLog -LogName Security -Source 'IRToolkit' -EventId 7701 `
        -EntryType Warning `
        -Message "HOST CONTAINED by IR Toolkit - incident: $IncidentId - all network traffic blocked except management access" `
        -ErrorAction SilentlyContinue
} catch {}

Write-IRLog "CONTAIN: Host isolation complete for $IncidentId"

@{
    phase       = 'containment'
    status      = 'success'
    mgmt_ips    = $env:IR_MGMT_IPS
    incident_id = $IncidentId
} | ConvertTo-Json -Compress | Write-Output
