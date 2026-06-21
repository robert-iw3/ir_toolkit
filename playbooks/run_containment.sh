#!/usr/bin/env bash
# ==============================================================================
# IR Toolkit — Playbook Containment Runner
# Runs containment and eradication playbooks
# against the affected endpoint or cloud workload.
# Returns a JSON result summary to stdout.
#
# Usage:
#   run_containment.sh <TARGET> <INCIDENT_ID> <PLATFORM> \
#     [C2_IPS] [MGMT_IPS] [MALICIOUS_PIDS] [MALICIOUS_PROCESSES] \
#     [MALICIOUS_HASHES] [MALICIOUS_PATHS] [C2_DOMAINS]
#
# Platform:
#   "linux"   — SSH to TARGET, run playbooks/linux/*.sh
#   "windows" — SSH → PowerShell to TARGET, run playbooks/windows/*.ps1
#   "cloud"   — Run playbooks/cloud/*.sh LOCALLY (no SSH) using cloud CLIs
#               Requires: IR_CLOUD_PROVIDER=aws|azure|gcp
#               AWS extra: IR_AWS_REGION, IR_AWS_VPC_ID
#               Azure extra: IR_AZURE_SUBSCRIPTION, IR_AZURE_RESOURCE_GROUP
#               GCP extra: IR_GCP_PROJECT, IR_GCP_NETWORK, IR_GCP_ZONE
# ==============================================================================

set -uo pipefail

TARGET="${1:?TARGET required}"
INCIDENT_ID="${2:?INCIDENT_ID required}"
PLATFORM="${3:-linux}"
C2_IPS="${4:-}"
MGMT_IPS="${5:-}"
MALICIOUS_PIDS="${6:-}"
MALICIOUS_PROCESSES="${7:-}"
MALICIOUS_HASHES="${8:-}"
MALICIOUS_PATHS="${9:-}"
C2_DOMAINS="${10:-}"

PLAYBOOK_DIR="${PLAYBOOK_DIR:-/playbooks}"
SSH_KEY="${SSH_KEY_PATH:-/ir-ssh/id_ecdsa}"
SSH_USER="${IR_SSH_USER:-ir-responder}"
RUNNER_TIMEOUT="${RUNNER_TIMEOUT:-120}"

# ── SSH options shared across all phases ──────────────────────────────────────
SSH_OPTS=(
    -i "${SSH_KEY}"
    -o StrictHostKeyChecking=accept-new
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=3
)

# Environment block to export on the remote host (sanitise single-quotes)
_sanitize() { printf '%s' "${1}" | sed "s/'/'\\''/g"; }

REMOTE_ENV="
export IR_INCIDENT_ID='$(_sanitize "${INCIDENT_ID}")';
export IR_C2_IPS='$(_sanitize "${C2_IPS}")';
export IR_MGMT_IPS='$(_sanitize "${MGMT_IPS}")';
export IR_MALICIOUS_PIDS='$(_sanitize "${MALICIOUS_PIDS}")';
export IR_MALICIOUS_PROCESSES='$(_sanitize "${MALICIOUS_PROCESSES}")';
export IR_MALICIOUS_HASHES='$(_sanitize "${MALICIOUS_HASHES}")';
export IR_MALICIOUS_PATHS='$(_sanitize "${MALICIOUS_PATHS}")';
export IR_C2_DOMAINS='$(_sanitize "${C2_DOMAINS}")';
"

# ── Tracking ──────────────────────────────────────────────────────────────────
declare -A PHASE_RESULTS
PHASES_ORDER=()

emit_phase() {
    local phase="$1"
    local status="$2"
    local detail="${3:-}"
    PHASE_RESULTS["${phase}"]="${status}"
    PHASES_ORDER+=("${phase}")
    echo "[$(date -u +%H:%M:%SZ)] [${phase}] ${status}${detail:+ — ${detail}}" >&2
}

# ── Core SSH executor ─────────────────────────────────────────────────────────
# run_linux_playbook SCRIPT_FILE PHASE_NAME [TIMEOUT_SECS]
run_linux_playbook() {
    local script="${PLAYBOOK_DIR}/linux/${1}"
    local phase="${2}"
    local timeout="${3:-${RUNNER_TIMEOUT}}"
    local output

    if [[ ! -f "${script}" ]]; then
        emit_phase "${phase}" "skipped" "script not found: ${script}"
        return 0
    fi

    if output=$(timeout "${timeout}" ssh "${SSH_OPTS[@]}" \
            "${SSH_USER}@${TARGET}" \
            "${REMOTE_ENV} bash -s" \
            < "${script}" 2>&1); then
        emit_phase "${phase}" "success" "$(echo "${output}" | tail -1)"
        return 0
    else
        emit_phase "${phase}" "failed" "exit=$? output=$(echo "${output}" | tail -2 | tr '\n' ' ')"
        return 1
    fi
}

# run_windows_playbook SCRIPT_FILE PHASE_NAME [TIMEOUT_SECS]
run_windows_playbook() {
    local script="${PLAYBOOK_DIR}/windows/${1}"
    local phase="${2}"
    local timeout="${3:-${RUNNER_TIMEOUT}}"
    local output

    if [[ ! -f "${script}" ]]; then
        emit_phase "${phase}" "skipped" "script not found: ${script}"
        return 0
    fi

    # Windows env exports via CMD-style SET commands embedded in the PS1 stdin stream
    local win_env
    win_env="
\$env:IR_INCIDENT_ID = '$(_sanitize "${INCIDENT_ID}")'
\$env:IR_C2_IPS = '$(_sanitize "${C2_IPS}")'
\$env:IR_MGMT_IPS = '$(_sanitize "${MGMT_IPS}")'
\$env:IR_MALICIOUS_PIDS = '$(_sanitize "${MALICIOUS_PIDS}")'
\$env:IR_MALICIOUS_PROCESSES = '$(_sanitize "${MALICIOUS_PROCESSES}")'
\$env:IR_MALICIOUS_HASHES = '$(_sanitize "${MALICIOUS_HASHES}")'
\$env:IR_MALICIOUS_PATHS = '$(_sanitize "${MALICIOUS_PATHS}")'
\$env:IR_C2_DOMAINS = '$(_sanitize "${C2_DOMAINS}")'
"
    # Prepend env block to script and pipe via SSH → PowerShell stdin
    if output=$( (printf '%s\n' "${win_env}"; cat "${script}") | \
            timeout "${timeout}" ssh "${SSH_OPTS[@]}" \
            "${SSH_USER}@${TARGET}" \
            "powershell -NonInteractive -ExecutionPolicy Bypass -" 2>&1 ); then
        emit_phase "${phase}" "success" "$(echo "${output}" | tail -1)"
        return 0
    else
        emit_phase "${phase}" "failed" "exit=$? output=$(echo "${output}" | tail -2 | tr '\n' ' ')"
        return 1
    fi
}

# ── Cloud playbook executor — runs scripts LOCALLY (no SSH) ──────────────────
# Cloud containment scripts use the aws/az/gcloud CLIs inside this container.
# The IR_CLOUD_PROVIDER, IR_TARGET, and provider-specific vars must be
# exported in the environment before calling run_containment.sh cloud.
run_cloud_playbook() {
    local script="${PLAYBOOK_DIR}/cloud/${1}"
    local phase="${2}"
    local timeout="${3:-${RUNNER_TIMEOUT}}"
    local output

    if [[ ! -f "${script}" ]]; then
        emit_phase "${phase}" "skipped" "script not found: ${script}"
        return 0
    fi

    # Export all IR vars for the cloud script
    if output=$(timeout "${timeout}" env \
            IR_INCIDENT_ID="${INCIDENT_ID}" \
            IR_C2_IPS="${C2_IPS}" \
            IR_MGMT_IPS="${MGMT_IPS}" \
            IR_MALICIOUS_PIDS="${MALICIOUS_PIDS}" \
            IR_MALICIOUS_PROCESSES="${MALICIOUS_PROCESSES}" \
            IR_MALICIOUS_HASHES="${MALICIOUS_HASHES}" \
            IR_MALICIOUS_PATHS="${MALICIOUS_PATHS}" \
            IR_C2_DOMAINS="${C2_DOMAINS}" \
            IR_TARGET="${TARGET}" \
            IR_CLOUD_PROVIDER="${IR_CLOUD_PROVIDER:-aws}" \
            IR_AWS_REGION="${IR_AWS_REGION:-us-east-1}" \
            IR_AWS_VPC_ID="${IR_AWS_VPC_ID:-}" \
            IR_AZURE_SUBSCRIPTION="${IR_AZURE_SUBSCRIPTION:-}" \
            IR_AZURE_RESOURCE_GROUP="${IR_AZURE_RESOURCE_GROUP:-}" \
            IR_GCP_PROJECT="${IR_GCP_PROJECT:-}" \
            IR_GCP_NETWORK="${IR_GCP_NETWORK:-default}" \
            IR_GCP_ZONE="${IR_GCP_ZONE:-us-east1-b}" \
            bash "${script}" 2>&1); then
        emit_phase "${phase}" "success" "$(echo "${output}" | tail -1)"
        return 0
    else
        emit_phase "${phase}" "failed" "exit=$? output=$(echo "${output}" | tail -2 | tr '\n' ' ')"
        return 1
    fi
}

# ── Phase dispatcher ──────────────────────────────────────────────────────────
run_phase() {
    local phase="$1"
    local script_base="$2"
    local timeout="${3:-${RUNNER_TIMEOUT}}"
    local rc=0

    if [[ "${PLATFORM}" == "windows" ]]; then
        run_windows_playbook "${script_base}" "${phase}" "${timeout}" || rc=$?
    elif [[ "${PLATFORM}" == "cloud" ]]; then
        run_cloud_playbook "${script_base}" "${phase}" "${timeout}" || rc=$?
    else
        run_linux_playbook "${script_base}" "${phase}" "${timeout}" || rc=$?
    fi
    return ${rc}
}

# ── Phase execution ───────────────────────────────────────────────────────────
echo "=== IR Playbook Runner: ${INCIDENT_ID} / ${TARGET} / ${PLATFORM} ===" >&2

if [[ "${PLATFORM}" == "windows" ]]; then
    run_phase "forensics"           "00_Collect-Forensics.ps1"       90  || true
    run_phase "containment"         "01_Contain-Host.ps1"            60  || true
    run_phase "process_eradication" "02_Eradicate-Process.ps1"       90  || true
    run_phase "persistence_removal" "03_Eradicate-Persistence.ps1"   120 || true
    run_phase "c2_blocking"         "04_Block-C2.ps1"                60  || true
elif [[ "${PLATFORM}" == "cloud" ]]; then
    # Cloud playbooks run locally using cloud provider CLIs.
    # IR_CLOUD_PROVIDER must be set to: aws | azure | gcp
    echo "=== Cloud provider: ${IR_CLOUD_PROVIDER:-aws} ===" >&2
    run_phase "forensics"           "00_collect_forensics.sh"        90  || true
    run_phase "containment"         "01_contain_host.sh"             120 || true
    run_phase "process_eradication" "02_eradicate_process.sh"        90  || true
    run_phase "persistence_removal" "03_eradicate_persistence.sh"    120 || true
    run_phase "c2_blocking"         "04_block_c2.sh"                 60  || true
else
    run_phase "forensics"           "00_collect_forensics.sh"        90  || true
    run_phase "containment"         "01_contain_host.sh"             60  || true
    run_phase "process_eradication" "02_eradicate_process.sh"        90  || true
    run_phase "persistence_removal" "03_eradicate_persistence.sh"    120 || true
    run_phase "c2_blocking"         "04_block_c2.sh"                 60  || true
fi

# ── JSON result summary ───────────────────────────────────────────────────────
python3 - << PYEOF
import json, sys

phases = [$(for p in "${PHASES_ORDER[@]}"; do echo "\"${p}\"," ; done)]
results = {$(for p in "${PHASES_ORDER[@]}"; do echo "\"${p}\": \"${PHASE_RESULTS[${p}]}\"," ; done)}

succeeded = [p for p in phases if results.get(p) == "success"]
failed    = [p for p in phases if results.get(p) == "failed"]
skipped   = [p for p in phases if results.get(p) == "skipped"]

overall = "CONTAINED" if not failed else ("PARTIAL_FAILURE" if succeeded else "FAILED")

print(json.dumps({
    "incident_id":  "${INCIDENT_ID}",
    "target":       "${TARGET}",
    "platform":     "${PLATFORM}",
    "status":       overall,
    "phase_results": results,
    "succeeded":    len(succeeded),
    "failed":       len(failed),
    "skipped":      len(skipped),
}))
PYEOF
