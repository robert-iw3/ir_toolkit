#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 01-identity - Identity Containment + Session Revocation
#
# In the cloud, isolating a host is half the job: the attacker logged in with a
# credential, and that credential keeps working until the identity is contained.
# This neutralises the implicated principal AND revokes its already-issued sessions
# (deactivating a key does NOT kill live STS/refresh tokens):
#
#   AWS:   attach AWSDenyAll + put an AWSRevokeOlderSessions inline policy
#          (denies any token issued before now) on the user/role
#   Azure: disable the user/service principal + revokeSignInSessions (Graph)
#   GCP:   disable the service account (invalidates its tokens)
#
# DRY-RUN by default (mutates only when IR_DRY_RUN=0). Every reversible action is
# written to the same rollback journal 03 uses, so 05_restore_host.sh can undo it
# if the verdict is later overturned.
#
# Principals come from IR_CONTAIN_PRINCIPALS (fallback IR_MALICIOUS_PROCESSES):
# comma-separated IAM users/roles, Entra users/SP app-ids, or GCP SA emails.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
PRINCIPALS="${IR_CONTAIN_PRINCIPALS:-${IR_MALICIOUS_PROCESSES:-}}"
DRY_RUN="${IR_DRY_RUN:-1}"
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"
ROLLBACK_JOURNAL="${ARTIFACT_DIR}/persistence_rollback.jsonl"
journal() { echo "$1" >> "${ROLLBACK_JOURNAL}"; }

log()  { echo "[$(date -u +%H:%M:%SZ)] [contain-id/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/identity_containment.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"identity_containment\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

[[ -z "${PRINCIPALS}" ]] && { log "No principals to contain (set IR_CONTAIN_PRINCIPALS)"; emit "skipped" "no_principals"; exit 0; }

# ISO-8601 'now' - any session token issued before this instant is denied.
NOW_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
REVOKE_DOC="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"IRRevokeOlderSessions\",\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"${NOW_ISO}\"}}}]}"

contain_aws() {
    local denyall="arn:aws:iam::aws:policy/AWSDenyAll" contained=0
    IFS=',' read -ra targets <<< "${PRINCIPALS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"; [[ -z "${entity}" ]] && continue

        if aws iam get-user --user-name "${entity}" --output none 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would attach AWSDenyAll + revoke sessions on IAM user ${entity}"; contained=1
            else
                aws iam attach-user-policy --user-name "${entity}" --policy-arn "${denyall}" 2>/dev/null && {
                    journal "{\"action\":\"iam_user_deny\",\"user\":\"${entity}\",\"policy_arn\":\"${denyall}\"}"
                    log "AWSDenyAll attached to user ${entity}"; contained=1; } || true
                aws iam put-user-policy --user-name "${entity}" \
                    --policy-name "IRRevokeOlderSessions" --policy-document "${REVOKE_DOC}" 2>/dev/null && {
                    journal "{\"action\":\"iam_revoke_sessions\",\"entity_type\":\"user\",\"entity\":\"${entity}\"}"
                    log "Sessions revoked (older-than-now) for user ${entity}"; contained=1; } || true
            fi

        elif aws iam get-role --role-name "${entity}" --output none 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would attach AWSDenyAll + revoke sessions on IAM role ${entity}"; contained=1
            else
                aws iam attach-role-policy --role-name "${entity}" --policy-arn "${denyall}" 2>/dev/null && {
                    journal "{\"action\":\"iam_role_deny\",\"role\":\"${entity}\",\"policy_arn\":\"${denyall}\"}"
                    log "AWSDenyAll attached to role ${entity}"; contained=1; } || true
                aws iam put-role-policy --role-name "${entity}" \
                    --policy-name "IRRevokeOlderSessions" --policy-document "${REVOKE_DOC}" 2>/dev/null && {
                    journal "{\"action\":\"iam_revoke_sessions\",\"entity_type\":\"role\",\"entity\":\"${entity}\"}"
                    log "Sessions revoked (older-than-now) for role ${entity}"; contained=1; } || true
            fi
        else
            log "WARN: ${entity} is neither an IAM user nor role - skipping"
        fi
    done
    [[ "${contained}" -eq 1 ]] && emit "success" "aws_identity_contained" || emit "skipped" "no_targets_identified"
}

contain_azure() {
    local contained=0
    IFS=',' read -ra targets <<< "${PRINCIPALS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"; [[ -z "${entity}" ]] && continue

        if az ad sp show --id "${entity}" --output none 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would disable Azure SP ${entity}"; contained=1
            else
                az ad sp update --id "${entity}" --set "accountEnabled=false" --output none 2>/dev/null && {
                    journal "{\"action\":\"azure_sp_disable\",\"sp\":\"${entity}\"}"
                    log "SP ${entity} disabled"; contained=1; } || true
            fi
        elif az ad user show --id "${entity}" --output none 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would disable Azure user ${entity} + revoke sign-in sessions"; contained=1
            else
                az ad user update --id "${entity}" --account-enabled false --output none 2>/dev/null && {
                    journal "{\"action\":\"azure_user_disable\",\"user\":\"${entity}\"}"
                    log "User ${entity} disabled"; contained=1; } || true
                # revokeSignInSessions invalidates all refresh tokens (one-way; reversal = re-enable).
                az rest --method post \
                    --url "https://graph.microsoft.com/v1.0/users/${entity}/revokeSignInSessions" \
                    --output none 2>/dev/null && log "Sign-in sessions revoked for ${entity}" || true
            fi
        else
            log "WARN: ${entity} is neither an Entra SP nor user - skipping"
        fi
    done
    [[ "${contained}" -eq 1 ]] && emit "success" "azure_identity_contained" || emit "skipped" "no_targets_identified"
}

contain_gcp() {
    local project="${IR_GCP_PROJECT:-}" contained=0
    IFS=',' read -ra targets <<< "${PRINCIPALS}"
    for entity in "${targets[@]}"; do
        entity="${entity// /}"; [[ -z "${entity}" ]] && continue
        if gcloud iam service-accounts describe "${entity}" --project="${project}" 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would disable GCP service account ${entity} (invalidates its tokens)"; contained=1
            else
                gcloud iam service-accounts disable "${entity}" --project="${project}" --quiet 2>/dev/null && {
                    journal "{\"action\":\"gcp_sa_disable\",\"sa\":\"${entity}\"}"
                    log "Service account ${entity} disabled"; contained=1; } || true
            fi
        else
            log "WARN: ${entity} is not a GCP service account - skipping"
        fi
    done
    [[ "${contained}" -eq 1 ]] && emit "success" "gcp_identity_contained" || emit "skipped" "no_targets_identified"
}

case "${PROVIDER}" in
    aws)   contain_aws   ;;
    azure) contain_azure ;;
    gcp)   contain_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac
