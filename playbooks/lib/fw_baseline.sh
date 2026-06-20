#!/usr/bin/env bash
# First-write-wins baseline pointer for containment.
#
# Containment exports the pre-incident firewall to a backup, then locks the host
# down. Running collection twice must NOT overwrite that baseline with the
# already-locked-down state, or restoration would "restore" to an isolated host.
#
# ir_baseline_record MARKER_FILE CANDIDATE_PATH
#   First call: records CANDIDATE_PATH in MARKER_FILE and echoes it.
#   Later calls: ignores CANDIDATE_PATH and echoes the originally recorded baseline.
# Invoke-IRCollection.ps1 / Enforce-StrictFirewall.ps1 implement the same contract.

ir_baseline_record() {
    local marker="$1" candidate="$2"
    if [[ -s "$marker" ]]; then
        cat "$marker"
        return 0
    fi
    printf '%s' "$candidate" > "$marker"
    printf '%s' "$candidate"
}
