<#
.SYNOPSIS
    Enforces a strict Default Deny (Block) inbound Windows Firewall posture with binary state rollback.

.DESCRIPTION
    Safely transitions the Windows Defender Firewall to a strict 'Block Inbound' default.
    Generates a full binary export of the firewall state prior to mutation.
    Includes built-in validation to ensure pre-existing explicit 'Allow' rules continue to function.

.PARAMETER Rollback
    Switch. Triggers the restoration of a previous firewall state.

.PARAMETER BackupPath
    String. The absolute path to the .wfw backup file to restore (Required if -Rollback is used).

.EXAMPLE
    # Enforce strict policy (Auto-creates backup in C:\FirewallBackups)
    .\Enforce-StrictFirewall.ps1

.EXAMPLE
    # Rollback to a known good state
    .\Enforce-StrictFirewall.ps1 -Rollback -BackupPath "C:\FirewallBackups\FW_State_20260417_1300.wfw"

.NOTES
    Enforcing a strict "Default Deny" inbound firewall posture physically neutralizes an adversary's ability to
    establish listening posts or execute lateral movement across the network. By eliminating these quiet,
    peer-to-peer pathways, we force the attacker to rely exclusively on outbound beaconing to maintain command
    and control. Pairing this inbound lockdown with the ML-driven outbound C2 sensor creates a strategic,
    unavoidable chokepoint. We operate under the "Assume Breach" paradigm: by denying horizontal movement, we
    force the adversary's traffic vertically into our behavioral analytics engine, ensuring rapid, mathematical
    detection of evasive tradecraft.

@RW
#>

param (
    [switch]$Rollback,
    [string]$BackupPath,
    # True inbound lockdown: also DISABLE all enabled inbound Allow rules so that
    # nothing inbound is permitted (DefaultInboundAction=Block alone does not do this).
    [switch]$FullInboundLockdown,
    # Optional management pinhole kept open during full lockdown (e.g. 3389 for RDP,
    # 5985/5986 for WinRM) so a remote responder is not locked out.
    [int[]]$AllowInboundPort = @(),
    [string[]]$AllowInboundRemoteAddress = @()
)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = "Windows Firewall State Manager"

# ==============================================================================
# 1. ELEVATION CHECK
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[CRITICAL FATAL] This script requires NT AUTHORITY\SYSTEM or High Integrity Administrator privileges."
    Exit
}

# ==============================================================================
# 2. ROLLBACK EXECUTION PATH
# ==============================================================================
if ($Rollback) {
    Write-Host "[*] INITIATING FIREWALL STATE ROLLBACK..." -ForegroundColor Yellow
    if ([string]::IsNullOrWhiteSpace($BackupPath) -or -not (Test-Path $BackupPath)) {
        Write-Error "[CRITICAL] Rollback aborted. Invalid or missing backup file: $BackupPath"
        Exit
    }

    try {
        Write-Host "    -> Restoring binary state from: $BackupPath" -ForegroundColor Cyan
        $importResult = netsh advfirewall import $BackupPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw $importResult }

        Write-Host "[SUCCESS] Firewall state successfully rolled back to exact backup configuration." -ForegroundColor Green
    } catch {
        Write-Error "[CRITICAL FATAL] Failed to import firewall state. Exception: $($_.Exception.Message)"
    }
    Exit
}

# ==============================================================================
# 3. ENFORCEMENT EXECUTION PATH
# ==============================================================================
Write-Host "[*] INITIATING STRICT INBOUND ENFORCEMENT..." -ForegroundColor Cyan

$BackupDir = "C:\FirewallBackups"
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$ActiveBackupPath = Join-Path $BackupDir "FW_State_$Timestamp.wfw"
# First-write-wins baseline pointer: prevents a second lockdown from capturing the
# already-isolated state as "known-good" (which would make restoration restore an
# isolated host). Mirrors playbooks/lib/fw_baseline.sh::ir_baseline_record.
$BaselineMarker = Join-Path $BackupDir "baseline.txt"

try {
    # --- A. BINARY STATE BACKUP (first-write-wins) ---
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }

    if ((Test-Path $BaselineMarker) -and (Test-Path (Get-Content -LiteralPath $BaselineMarker -Raw).Trim())) {
        $ActiveBackupPath = (Get-Content -LiteralPath $BaselineMarker -Raw).Trim()
        Write-Host "    -> [1/4] Baseline already recorded; REUSING known-good $ActiveBackupPath (not re-exporting)." -ForegroundColor Gray
    } else {
        Write-Host "    -> [1/4] Exporting active state to $ActiveBackupPath" -ForegroundColor Gray
        $exportResult = netsh advfirewall export $ActiveBackupPath 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ActiveBackupPath)) {
            throw "Binary export failed or file not created. Halting to prevent data loss."
        }
        Set-Content -LiteralPath $BaselineMarker -Value $ActiveBackupPath -Encoding ASCII
    }

    # --- B. INBOUND POSTURE ---
    if ($FullInboundLockdown) {
        # DefaultInboundAction=Block only drops UNMATCHED inbound; existing enabled
        # Allow rules still permit traffic. For a true "nothing in" posture we must
        # disable those Allow rules too. (Reversible via the .wfw backup / -Rollback.)
        Write-Host "    -> [2/4] FULL LOCKDOWN: disabling all enabled inbound Allow rules..." -ForegroundColor Yellow
        $inAllow = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue
        $cnt = @($inAllow).Count
        if ($cnt -gt 0) { $inAllow | Disable-NetFirewallRule -ErrorAction SilentlyContinue }
        Write-Host "       Disabled $cnt inbound Allow rule(s). Loopback remains (Windows-implicit)." -ForegroundColor Gray

        if (@($AllowInboundPort).Count -gt 0) {
            $p = @{ DisplayName = "IR-MGMT-PINHOLE"; Direction = 'Inbound'; Action = 'Allow'
                    Protocol = 'TCP'; LocalPort = $AllowInboundPort }
            if (@($AllowInboundRemoteAddress).Count -gt 0) { $p['RemoteAddress'] = $AllowInboundRemoteAddress }
            New-NetFirewallRule @p | Out-Null
            Write-Host "       Management pinhole kept open: TCP $($AllowInboundPort -join ',') from $(@($AllowInboundRemoteAddress) -join ',')" -ForegroundColor Gray
        }
    } else {
        # Default-deny mode: unmatched inbound drops, but existing Allow rules remain.
        Write-Host "    -> [2/4] Verifying Core Networking rules are explicitly permitted..." -ForegroundColor Gray
        Enable-NetFirewallRule -DisplayGroup "Core Networking" -ErrorAction SilentlyContinue
    }

    # --- C. ENFORCE DEFAULT DENY ---
    Write-Host "    -> [3/4] Mutating DefaultInboundAction to 'Block' across all profiles..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

    # --- D. STATE VALIDATION ---
    Write-Host "    -> [4/4] Validating state enforcement..." -ForegroundColor Gray
    # -All returns the Domain, Private and Public profiles. ('Any' is not a valid
    # profile name and throws "No MSFT_NetFirewallProfile objects found ... 'Any'".)
    $profiles = Get-NetFirewallProfile -All

    foreach ($fwProfile in $profiles) {
        if ($fwProfile.DefaultInboundAction -ne 'Block') {
            throw "State Mismatch: $($fwProfile.Name) profile is currently set to $($fwProfile.DefaultInboundAction). Expected: Block."
        }
    }

    $remaining = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue).Count
    Write-Host "`n[SUCCESS] DefaultInboundAction = Block on all profiles." -ForegroundColor Green
    if ($FullInboundLockdown) {
        $note = if (@($AllowInboundPort).Count -gt 0) { " (management pinhole only)" } else { " - nothing inbound is permitted" }
        Write-Host "[INFO] Full inbound lockdown: $remaining enabled inbound Allow rule(s) remaining$note." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Default-deny is active, but $remaining enabled inbound Allow rule(s) STILL PERMIT matching inbound traffic." -ForegroundColor Yellow
        Write-Host "[WARN] Re-run with -FullInboundLockdown to disable those and allow nothing inbound." -ForegroundColor Yellow
    }
    Write-Host "[INFO] Backup safely stored at: $ActiveBackupPath" -ForegroundColor DarkGray

} catch {
    Write-Host "`n[!] CRITICAL ERROR DURING ENFORCEMENT" -ForegroundColor Red
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The firewall state may be inconsistent. It is highly recommended to rollback using the previous backup." -ForegroundColor Yellow
}