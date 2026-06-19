# ==============================================================================
# IR Playbook 06 - Windows False-Positive Restore (rollback)
# Reverses the containment/eradication applied during an investigation that the
# swarm later judged a FALSE POSITIVE:
#   * imports the firewall backup saved by 01_Contain-Host.ps1 (this also removes
#     any 04_Block-C2 rules),
#   * restores each quarantined binary to its original path AFTER verifying its
#     sha256 against the rollback journal written by 02_Eradicate-Process.ps1.
# Non-destructive: it only un-isolates and puts files back.
# ==============================================================================
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$IncidentId = ($env:IR_INCIDENT_ID -replace '[^\w\-]','')
if (-not $IncidentId) { $IncidentId = 'UNKNOWN' }
$IRDir        = 'C:\ProgramData\IRToolkit'
$BackupFile      = "$IRDir\firewall-pre-$IncidentId.wfw"
$RollbackJournal = "$IRDir\rollback\$IncidentId.jsonl"
$Restored = 0; $Skipped = 0; $Errors = 0

function Write-RLog([string]$Msg) {
    "[$(Get-Date -Format 'HH:mm:ssZ')] RESTORE: $Msg" | Tee-Object -FilePath "$IRDir\playbook.log" -Append
}

# -- 1. Un-isolate: import the firewall backup captured before containment -----
if (Test-Path -LiteralPath $BackupFile) {
    netsh advfirewall import $BackupFile | Out-Null
    Write-RLog "firewall ruleset restored from $BackupFile"
} else {
    Write-RLog "no firewall backup for $IncidentId; skipping un-isolate"
}

# -- 2. Restore quarantined files (sha256-verified) from the rollback journal --
if (Test-Path -LiteralPath $RollbackJournal) {
    foreach ($line in Get-Content -LiteralPath $RollbackJournal) {
        if (-not $line.Trim()) { continue }
        try { $e = $line | ConvertFrom-Json } catch { continue }
        if ($e.action -ne 'quarantine') { continue }
        if (-not (Test-Path -LiteralPath $e.dest)) { $Skipped++; continue }
        $actual = (Get-FileHash -LiteralPath $e.dest -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne ($e.sha256).ToLower()) { $Skipped++; continue }   # never restore tampered bytes
        $parent = Split-Path -Parent $e.original
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        try {
            Move-Item -LiteralPath $e.dest -Destination $e.original -Force
            $Restored++; Write-RLog "restored $($e.original)"
        } catch { $Errors++ }
    }
} else {
    Write-RLog "no rollback journal at $RollbackJournal; nothing to restore"
}

[ordered]@{ phase='restore'; status='completed'; incident_id=$IncidentId;
            restored=$Restored; skipped=$Skipped; errors=$Errors } | ConvertTo-Json -Compress
