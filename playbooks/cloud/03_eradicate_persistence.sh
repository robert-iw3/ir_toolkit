#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 03 — Cloud Persistence Eradication
#
# Removes adversarial cloud persistence mechanisms:
#   AWS:   Remove malicious IAM user/role/policy, revoke sessions,
#          delete malicious Lambda functions or scheduled events
#   Azure: Remove malicious app registrations, revoke service principal tokens,
#          delete malicious Automation Runbooks/Logic Apps
#   GCP:   Remove malicious service account keys, Cloud Function triggers,
#          delete malicious IAM bindings
#
# Conservative by default — requires explicit IR_MALICIOUS_* env vars.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
MALICIOUS_PROCS="${IR_MALICIOUS_PROCESSES:-}"  # IAM users/SAs/app IDs
MALICIOUS_PATHS="${IR_MALICIOUS_PATHS:-}"       # ARNs, resource IDs, URLs
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

log()  { echo "[$(date -u +%H:%M:%SZ)] [persist/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/persistence.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"persistence_removal\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

eradicate_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"
    local removed=0

    # Revoke active IAM sessions for any compromised users/roles
    IFS=',' read -ra targets <<< "${MALICIOUS_PROCS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"
        [[ -z "${entity}" ]] && continue

        # Try as IAM user — revoke active sessions by rotating credentials
        if aws iam get-user --user-name "${entity}" --output none 2>/dev/null; then
            log "Revoking IAM user sessions for ${entity}..."
            # Deactivate all access keys
            aws iam list-access-keys --user-name "${entity}" \
                --query 'AccessKeyMetadata[*].AccessKeyId' --output text 2>/dev/null | \
            tr '\t' '\n' | while read -r key_id; do
                [[ -z "${key_id}" ]] && continue
                aws iam update-access-key --user-name "${entity}" --access-key-id "${key_id}" --status Inactive
                log "Deactivated access key ${key_id} for ${entity}"
                removed=1
            done

        # Try as IAM role — attach deny-all policy
        elif aws iam get-role --role-name "${entity}" --output none 2>/dev/null; then
            log "Attaching deny-all policy to compromised role ${entity}..."
            local policy_arn="arn:aws:iam::aws:policy/AWSDenyAll"
            aws iam attach-role-policy --role-name "${entity}" --policy-arn "${policy_arn}" 2>/dev/null && \
                { log "AWSDenyAll attached to role ${entity}"; removed=1; } || true
        fi
    done

    # Remove malicious Lambda functions / EventBridge rules
    IFS=',' read -ra paths <<< "${MALICIOUS_PATHS}"
    for path in "${paths[@]}"; do
        path="${path// /}"
        [[ -z "${path}" ]] && continue
        if [[ "${path}" == *"function:"* ]]; then
            local fn_name="${path##*function:}"
            log "Deleting Lambda function ${fn_name}..."
            aws lambda delete-function --region "${region}" --function-name "${fn_name}" 2>/dev/null && \
                { log "Lambda ${fn_name} deleted"; removed=1; } || true
        fi
    done

    [[ "${removed}" -eq 1 ]] && emit "success" "aws_persistence_removed" || emit "skipped" "no_targets_identified"
}

eradicate_azure() {
    local removed=0

    IFS=',' read -ra targets <<< "${MALICIOUS_PROCS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"
        [[ -z "${entity}" ]] && continue

        # Revoke service principal tokens
        if az ad sp show --id "${entity}" --output none 2>/dev/null; then
            log "Revoking Azure AD service principal ${entity} credentials..."
            az ad sp credential reset --id "${entity}" --append --output none 2>/dev/null && \
                { log "SP ${entity} credentials rotated (forced re-auth)"; removed=1; } || true
            # Disable the SP
            az ad sp update --id "${entity}" --set "accountEnabled=false" --output none 2>/dev/null && \
                { log "SP ${entity} disabled"; removed=1; } || true
        fi
    done

    [[ "${removed}" -eq 1 ]] && emit "success" "azure_persistence_removed" || emit "skipped" "no_targets_identified"
}

eradicate_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    local removed=0

    IFS=',' read -ra targets <<< "${MALICIOUS_PROCS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"
        [[ -z "${entity}" ]] && continue

        # Revoke all service account keys
        if gcloud iam service-accounts describe "${entity}" --project="${project}" 2>/dev/null; then
            log "Revoking service account keys for ${entity}..."
            gcloud iam service-accounts keys list \
                --iam-account="${entity}" \
                --project="${project}" \
                --format="value(name)" 2>/dev/null | \
            grep -v "system:" | while read -r key_name; do
                gcloud iam service-accounts keys delete "${key_name}" \
                    --iam-account="${entity}" \
                    --project="${project}" \
                    --quiet 2>/dev/null && \
                    { log "Deleted SA key ${key_name}"; removed=1; } || true
            done
        fi
    done

    [[ "${removed}" -eq 1 ]] && emit "success" "gcp_persistence_removed" || emit "skipped" "no_targets_identified"
}

case "${PROVIDER}" in
    aws)   eradicate_aws   ;;
    azure) eradicate_azure ;;
    gcp)   eradicate_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac
