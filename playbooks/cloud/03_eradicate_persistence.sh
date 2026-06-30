#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 03 - Cloud Persistence Eradication
#
# Removes adversarial cloud persistence mechanisms. Identity targets come from
# IR_MALICIOUS_PROCESSES (IAM users/roles, service principals, service-account emails);
# resource targets from IR_MALICIOUS_PATHS as prefixed tokens:
#   AWS:   function:<name> (Lambda), rule:<name> (EventBridge) - deleted after backup;
#          IAM users (keys deactivated), roles (AWSDenyAll), sessions revoked.
#   Azure: app:<appId> (SP disabled), logicapp:<resourceId> (disabled),
#          runbook:<account>/<name> (deleted after export); SP creds rotated + disabled.
#   GCP:   function:<name> (Cloud Function), scheduler:<name> (Cloud Scheduler) - deleted
#          after backup; binding:<member>=<role> removed; SA keys deleted.
#
# Conservative + DRY-RUN by default (mutates only when IR_DRY_RUN=0). Every reversible
# action is journaled so 05_restore_host.sh can undo it; irreversible deletes are backed
# up first and flagged for manual recreate on restore.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
MALICIOUS_PROCS="${IR_MALICIOUS_PROCESSES:-}"    # IAM users/SAs/app IDs
MALICIOUS_PATHS="${IR_MALICIOUS_PATHS:-}"        # ARNs, resource IDs, URLs
DRY_RUN="${IR_DRY_RUN:-1}"                       # safe by default (mutates only when 0)
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"
# Rollback journal: one JSON line per REVERSIBLE action so the analyst can undo a revocation if
# the verdict is later overturned (key reactivate, role policy detach, SP re-enable).
ROLLBACK_JOURNAL="${ARTIFACT_DIR}/persistence_rollback.jsonl"
journal() { echo "$1" >> "${ROLLBACK_JOURNAL}"; }

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

        # Try as IAM user - revoke active sessions by rotating credentials
        if aws iam get-user --user-name "${entity}" --output none 2>/dev/null; then
            log "Revoking IAM user sessions for ${entity}..."
            # Deactivate all access keys
            aws iam list-access-keys --user-name "${entity}" \
                --query 'AccessKeyMetadata[*].AccessKeyId' --output text 2>/dev/null | \
            tr '\t' '\n' | while read -r key_id; do
                [[ -z "${key_id}" ]] && continue
                if [[ "${DRY_RUN}" == "1" ]]; then
                    log "[DRY-RUN] would deactivate access key ${key_id} for ${entity}"
                else
                    aws iam update-access-key --user-name "${entity}" --access-key-id "${key_id}" --status Inactive
                    journal "{\"action\":\"iam_key_deactivate\",\"user\":\"${entity}\",\"key_id\":\"${key_id}\"}"
                    log "Deactivated access key ${key_id} for ${entity} (reversible: --status Active)"
                fi
                removed=1
            done

        # Try as IAM role - attach deny-all policy
        elif aws iam get-role --role-name "${entity}" --output none 2>/dev/null; then
            local policy_arn="arn:aws:iam::aws:policy/AWSDenyAll"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would attach AWSDenyAll to role ${entity}"; removed=1
            else
                log "Attaching deny-all policy to compromised role ${entity}..."
                aws iam attach-role-policy --role-name "${entity}" --policy-arn "${policy_arn}" 2>/dev/null && {
                    journal "{\"action\":\"iam_role_deny\",\"role\":\"${entity}\",\"policy_arn\":\"${policy_arn}\"}"
                    log "AWSDenyAll attached to role ${entity}"; removed=1; } || true
            fi
        fi
    done

    # Remove malicious resource-based persistence (IR_MALICIOUS_PATHS): Lambda functions
    # (function:<name>) and EventBridge scheduled-execution rules (rule:<name>).
    IFS=',' read -ra paths <<< "${MALICIOUS_PATHS}"
    for path in "${paths[@]}"; do
        path="${path// /}"
        [[ -z "${path}" ]] && continue
        if [[ "${path}" == function:* ]]; then
            local fn_name="${path#function:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would back up + delete Lambda function ${fn_name}"; removed=1
            else
                # Lambda delete is IRREVERSIBLE - back up config + code location first for recreate.
                local bak="${ARTIFACT_DIR}/lambda_${fn_name//[^A-Za-z0-9]/_}.json"
                aws lambda get-function --region "${region}" --function-name "${fn_name}" \
                    --output json > "${bak}" 2>/dev/null \
                    && { journal "{\"action\":\"lambda_delete\",\"function\":\"${fn_name}\",\"backup\":\"${bak}\"}"
                         log "Backed up Lambda ${fn_name} config → ${bak}"; } \
                    || log "WARN: could not back up Lambda ${fn_name} before delete"
                log "Deleting Lambda function ${fn_name}..."
                aws lambda delete-function --region "${region}" --function-name "${fn_name}" 2>/dev/null && \
                    { log "Lambda ${fn_name} deleted"; removed=1; } || true
            fi
        elif [[ "${path}" == rule:* ]]; then
            local rule_name="${path#rule:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would back up + delete EventBridge rule ${rule_name} (and its targets)"; removed=1
            else
                # EventBridge delete is IRREVERSIBLE - back up the rule + its targets first.
                local bak="${ARTIFACT_DIR}/eventbridge_${rule_name//[^A-Za-z0-9]/_}.json"
                { aws events describe-rule --region "${region}" --name "${rule_name}" --output json 2>/dev/null
                  aws events list-targets-by-rule --region "${region}" --rule "${rule_name}" --output json 2>/dev/null; } \
                    > "${bak}" 2>/dev/null || true
                journal "{\"action\":\"eventbridge_delete\",\"rule\":\"${rule_name}\",\"backup\":\"${bak}\"}"
                # Targets must be removed before the rule can be deleted.
                local tids
                tids=$(aws events list-targets-by-rule --region "${region}" --rule "${rule_name}" \
                    --query 'Targets[].Id' --output text 2>/dev/null)
                # shellcheck disable=SC2086
                [[ -n "${tids}" && "${tids}" != "None" ]] && \
                    aws events remove-targets --region "${region}" --rule "${rule_name}" --ids ${tids} 2>/dev/null || true
                aws events delete-rule --region "${region}" --name "${rule_name}" 2>/dev/null && \
                    { log "EventBridge rule ${rule_name} deleted"; removed=1; } || true
            fi
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
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would rotate credentials + disable Azure SP ${entity}"; removed=1
            else
                log "Revoking Azure AD service principal ${entity} credentials..."
                az ad sp credential reset --id "${entity}" --append --output none 2>/dev/null && \
                    { log "SP ${entity} credentials rotated (forced re-auth)"; removed=1; } || true
                # Disable the SP (reversible: accountEnabled=true)
                az ad sp update --id "${entity}" --set "accountEnabled=false" --output none 2>/dev/null && {
                    journal "{\"action\":\"azure_sp_disable\",\"sp\":\"${entity}\"}"
                    log "SP ${entity} disabled"; removed=1; } || true
            fi
        fi
    done

    # Resource-based persistence (IR_MALICIOUS_PATHS): Logic Apps (logicapp:<resourceId>,
    # disabled - reversible), Automation Runbooks (runbook:<account>/<name>, deleted after
    # export), and app registrations (app:<appId>, its SP disabled - reversible).
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"
    IFS=',' read -ra paths <<< "${MALICIOUS_PATHS}"
    for path in "${paths[@]}"; do
        path="${path// /}"
        [[ -z "${path}" ]] && continue
        if [[ "${path}" == logicapp:* ]]; then
            local la_id="${path#logicapp:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would disable Logic App ${la_id}"; removed=1
            else
                az resource update --ids "${la_id}" --set "properties.state=Disabled" --output none 2>/dev/null && {
                    journal "{\"action\":\"azure_logicapp_disable\",\"id\":\"${la_id}\"}"
                    log "Logic App ${la_id} disabled (reversible)"; removed=1; } || true
            fi
        elif [[ "${path}" == runbook:* ]]; then
            local rb="${path#runbook:}"; local acct="${rb%%/*}"; local name="${rb##*/}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would export + delete Automation runbook ${name}"; removed=1
            else
                local bak="${ARTIFACT_DIR}/runbook_${name//[^A-Za-z0-9]/_}.json"
                az automation runbook show --automation-account-name "${acct}" --resource-group "${rg}" \
                    --name "${name}" --output json > "${bak}" 2>/dev/null || true
                journal "{\"action\":\"azure_runbook_delete\",\"name\":\"${name}\",\"backup\":\"${bak}\"}"
                az automation runbook delete --automation-account-name "${acct}" --resource-group "${rg}" \
                    --name "${name}" --yes --output none 2>/dev/null && \
                    { log "Automation runbook ${name} deleted"; removed=1; } || true
            fi
        elif [[ "${path}" == app:* ]]; then
            local app_id="${path#app:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would disable app registration ${app_id} (disable its service principal)"; removed=1
            else
                az ad sp update --id "${app_id}" --set "accountEnabled=false" --output none 2>/dev/null && {
                    journal "{\"action\":\"azure_sp_disable\",\"sp\":\"${app_id}\"}"
                    log "App registration ${app_id} SP disabled (reversible)"; removed=1; } || true
            fi
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
                if [[ "${DRY_RUN}" == "1" ]]; then
                    log "[DRY-RUN] would delete SA key ${key_name} for ${entity}"; removed=1
                else
                    gcloud iam service-accounts keys delete "${key_name}" \
                        --iam-account="${entity}" \
                        --project="${project}" \
                        --quiet 2>/dev/null && \
                        { log "Deleted SA key ${key_name}"; removed=1; } || true
                fi
            done
        fi
    done

    # Resource-based persistence (IR_MALICIOUS_PATHS): Cloud Functions (function:<name>) and
    # Cloud Scheduler jobs (scheduler:<name>) deleted after backup; IAM bindings
    # (binding:<member>=<role>) removed (reversible).
    IFS=',' read -ra paths <<< "${MALICIOUS_PATHS}"
    for path in "${paths[@]}"; do
        path="${path// /}"
        [[ -z "${path}" ]] && continue
        if [[ "${path}" == function:* ]]; then
            local fn="${path#function:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would back up + delete Cloud Function ${fn}"; removed=1
            else
                local bak="${ARTIFACT_DIR}/gcp_function_${fn//[^A-Za-z0-9]/_}.json"
                gcloud functions describe "${fn}" --project="${project}" --format=json > "${bak}" 2>/dev/null || true
                journal "{\"action\":\"gcp_function_delete\",\"function\":\"${fn}\",\"backup\":\"${bak}\"}"
                gcloud functions delete "${fn}" --project="${project}" --quiet 2>/dev/null && \
                    { log "Cloud Function ${fn} deleted"; removed=1; } || true
            fi
        elif [[ "${path}" == scheduler:* ]]; then
            local job="${path#scheduler:}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would back up + delete Cloud Scheduler job ${job}"; removed=1
            else
                local bak="${ARTIFACT_DIR}/gcp_scheduler_${job//[^A-Za-z0-9]/_}.json"
                gcloud scheduler jobs describe "${job}" --project="${project}" --format=json > "${bak}" 2>/dev/null || true
                journal "{\"action\":\"gcp_scheduler_delete\",\"job\":\"${job}\",\"backup\":\"${bak}\"}"
                gcloud scheduler jobs delete "${job}" --project="${project}" --quiet 2>/dev/null && \
                    { log "Cloud Scheduler job ${job} deleted"; removed=1; } || true
            fi
        elif [[ "${path}" == binding:* ]]; then
            local b="${path#binding:}"; local member="${b%%=*}"; local role="${b##*=}"
            if [[ "${DRY_RUN}" == "1" ]]; then
                log "[DRY-RUN] would remove IAM binding ${member} -> ${role}"; removed=1
            else
                gcloud projects remove-iam-policy-binding "${project}" \
                    --member="${member}" --role="${role}" --quiet 2>/dev/null && {
                    journal "{\"action\":\"gcp_binding_remove\",\"member\":\"${member}\",\"role\":\"${role}\"}"
                    log "Removed IAM binding ${member} -> ${role} (reversible)"; removed=1; } || true
            fi
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
