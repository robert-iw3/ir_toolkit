#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 05 - Cloud Host Restoration (Release Quarantine)
#
# Reverses the isolation applied by 01_contain_host.sh:
#   AWS:   Restores original Security Groups from saved tags; removes quarantine SG
#   Azure: Deletes IR-DENY NSG rules for the incident
#   GCP:   Deletes ir-deny-* firewall rules for the incident
#
# Run ONLY after the threat has been eradicated and the incident is closed.
# Reads restoration artifacts saved by 01_contain_host.sh when available.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
DRY_RUN="${IR_DRY_RUN:-1}"                       # safe by default
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
ROLLBACK_JOURNAL="${ARTIFACT_DIR}/persistence_rollback.jsonl"   # written by 03_eradicate_persistence.sh

log()  { echo "[$(date -u +%H:%M:%SZ)] [restore/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/restore.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"restore\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

# Reverse the REVERSIBLE IAM revocations 03 journaled, on a false-positive verdict.
reverse_iam_revocations() {
    [[ -f "${ROLLBACK_JOURNAL}" ]] || { log "no persistence rollback journal - no IAM revocations to reverse"; return 0; }
    PY="$(command -v python3 || command -v python)"
    while IFS=$'\t' read -r action a b; do
        case "${action}" in
            iam_key_deactivate)   # a=user b=key_id  -> reactivate
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would reactivate key ${b} for ${a}"
                else aws iam update-access-key --user-name "${a}" --access-key-id "${b}" --status Active 2>/dev/null \
                        && log "reactivated key ${b} for ${a}" || log "WARN: could not reactivate key ${b}"; fi ;;
            iam_role_deny)        # a=role b=policy_arn -> detach
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would detach ${b} from role ${a}"
                else aws iam detach-role-policy --role-name "${a}" --policy-arn "${b}" 2>/dev/null \
                        && log "detached ${b} from role ${a}" || log "WARN: could not detach policy from ${a}"; fi ;;
            iam_user_deny)        # a=user b=policy_arn -> detach
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would detach ${b} from user ${a}"
                else aws iam detach-user-policy --user-name "${a}" --policy-arn "${b}" 2>/dev/null \
                        && log "detached ${b} from user ${a}" || log "WARN: could not detach policy from ${a}"; fi ;;
            iam_revoke_sessions)  # a=entity_type b=entity -> delete the IRRevokeOlderSessions inline policy
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would remove session-revoke policy from ${a} ${b}"
                elif [[ "${a}" == "role" ]]; then aws iam delete-role-policy --role-name "${b}" --policy-name IRRevokeOlderSessions 2>/dev/null \
                        && log "removed session-revoke policy from role ${b}" || log "WARN: could not remove session-revoke policy from ${b}"
                else aws iam delete-user-policy --user-name "${b}" --policy-name IRRevokeOlderSessions 2>/dev/null \
                        && log "removed session-revoke policy from user ${b}" || log "WARN: could not remove session-revoke policy from ${b}"; fi ;;
            azure_sp_disable)     # a=sp -> re-enable
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would re-enable Azure SP ${a}"
                else az ad sp update --id "${a}" --set "accountEnabled=true" --output none 2>/dev/null \
                        && log "re-enabled Azure SP ${a}" || log "WARN: could not re-enable SP ${a}"; fi ;;
            azure_user_disable)   # a=user -> re-enable
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would re-enable Azure user ${a}"
                else az ad user update --id "${a}" --account-enabled true --output none 2>/dev/null \
                        && log "re-enabled Azure user ${a}" || log "WARN: could not re-enable user ${a}"; fi ;;
            gcp_sa_disable)       # a=sa -> re-enable
                if [[ "${DRY_RUN}" == "1" ]]; then log "[DRY-RUN] would re-enable GCP service account ${a}"
                else gcloud iam service-accounts enable "${a}" --project="${IR_GCP_PROJECT:-}" --quiet 2>/dev/null \
                        && log "re-enabled service account ${a}" || log "WARN: could not re-enable SA ${a}"; fi ;;
            lambda_delete)        # a=function b=backup -> cannot auto-recreate; point at the backup
                log "MANUAL: Lambda ${a} was deleted - recreate from backup ${b} (aws lambda create-function)" ;;
        esac
    done < <("${PY}" -c "
import json,sys
for ln in open('${ROLLBACK_JOURNAL}'):
    try: e=json.loads(ln)
    except Exception: continue
    a=e.get('action','')
    if a=='iam_key_deactivate':   print('\t'.join([a,e.get('user',''),e.get('key_id','')]))
    elif a=='iam_role_deny':      print('\t'.join([a,e.get('role',''),e.get('policy_arn','')]))
    elif a=='iam_user_deny':      print('\t'.join([a,e.get('user',''),e.get('policy_arn','')]))
    elif a=='iam_revoke_sessions':print('\t'.join([a,e.get('entity_type',''),e.get('entity','')]))
    elif a=='azure_sp_disable':   print('\t'.join([a,e.get('sp',''),'']))
    elif a=='azure_user_disable': print('\t'.join([a,e.get('user',''),'']))
    elif a=='gcp_sa_disable':     print('\t'.join([a,e.get('sa',''),'']))
    elif a=='lambda_delete':      print('\t'.join([a,e.get('function',''),e.get('backup','')]))
")
}

[[ -z "${TARGET}" ]] && { log "ERROR: IR_TARGET not set"; emit "failed" "no_target"; exit 1; }

restore_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"

    # Find instance
    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --region "${region}" \
        --filters "Name=private-ip-address,Values=${TARGET}" \
        --query 'Reservations[0].Instances[0].InstanceId' \
        --output text 2>/dev/null)
    [[ "${instance_id}" == "None" || -z "${instance_id}" ]] && \
        { log "No instance found for ${TARGET}"; emit "skipped" "instance_not_found"; return 0; }

    # Read original SGs from saved tag
    local original_sgs
    original_sgs=$(aws ec2 describe-instances \
        --region "${region}" \
        --instance-ids "${instance_id}" \
        --query 'Reservations[0].Instances[0].Tags[?Key==`ir:pre-isolation-sgs`].Value | [0]' \
        --output text 2>/dev/null)

    # Fall back to artifact file if tag not set
    if [[ "${original_sgs}" == "None" || -z "${original_sgs}" ]]; then
        local artifact="${ARTIFACT_DIR}/original_sgs_${instance_id}.txt"
        if [[ -f "${artifact}" ]]; then
            original_sgs=$(cat "${artifact}" | tr '\t' ',')
        fi
    fi

    if [[ -z "${original_sgs}" || "${original_sgs}" == "None" ]]; then
        log "WARN: No pre-isolation SG record for ${instance_id} - manual restore required"
        emit "partial" "no_pre_isolation_sgs_saved"
        return 0
    fi

    log "Restoring SGs ${original_sgs} on ${instance_id}..."
    # Convert comma/space-separated list to space-separated for --groups
    local sg_list
    sg_list=$(echo "${original_sgs}" | tr ',' ' ' | tr '\t' ' ')
    # shellcheck disable=SC2086
    aws ec2 modify-instance-attribute \
        --region "${region}" \
        --instance-id "${instance_id}" \
        --groups ${sg_list}

    # Remove isolation tags
    aws ec2 delete-tags \
        --region "${region}" \
        --resources "${instance_id}" \
        --tags "Key=ir:isolated" "Key=ir:pre-isolation-sgs" 2>/dev/null || true

    log "RESTORED: ${instance_id} SGs restored to ${sg_list}"
    emit "success" "ec2_${instance_id}_restored"
}

restore_azure() {
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"

    local safe_target
    safe_target=$(echo "${TARGET}" | tr '.' '-')
    local rule_name_pattern="IR-DENY-${safe_target}"

    log "Removing IR deny rules matching ${rule_name_pattern}* from NSGs in ${rg}..."
    local removed=0

    local nsgs
    nsgs=$(az network nsg list --resource-group "${rg}" --query '[].name' --output tsv 2>/dev/null)

    while IFS= read -r nsg_name; do
        [[ -z "${nsg_name}" ]] && continue
        # List and delete IR-DENY rules for this target
        local rules
        rules=$(az network nsg rule list \
            --resource-group "${rg}" \
            --nsg-name "${nsg_name}" \
            --query "[?starts_with(name,'${rule_name_pattern}')].name" \
            --output tsv 2>/dev/null)
        while IFS= read -r rule; do
            [[ -z "${rule}" ]] && continue
            log "Deleting NSG rule ${rule} from ${nsg_name}..."
            az network nsg rule delete \
                --resource-group "${rg}" \
                --nsg-name "${nsg_name}" \
                --name "${rule}" \
                --output none 2>/dev/null && removed=1 || true
        done <<< "${rules}"
    done <<< "${nsgs}"

    [[ "${removed}" -eq 1 ]] && emit "success" "azure_isolation_rules_removed" || emit "skipped" "no_ir_rules_found"
}

restore_gcp() {
    local project="${IR_GCP_PROJECT:-}"

    local safe_ip
    safe_ip=$(echo "${TARGET}" | tr '.' '-' | tr '[:upper:]' '[:lower:]')
    local rule_prefix="ir-deny-${safe_ip}"

    log "Removing VPC firewall rules matching ${rule_prefix}* (project=${project})..."
    local removed=0

    local rules
    rules=$(gcloud compute firewall-rules list \
        --project="${project}" \
        --filter="name~'^${rule_prefix}'" \
        --format="value(name)" 2>/dev/null)

    while IFS= read -r rule; do
        [[ -z "${rule}" ]] && continue
        log "Deleting firewall rule ${rule}..."
        gcloud compute firewall-rules delete "${rule}" \
            --project="${project}" \
            --quiet 2>/dev/null && removed=1 || true
    done <<< "${rules}"

    [[ "${removed}" -eq 1 ]] && emit "success" "gcp_fw_rules_removed" || emit "skipped" "no_ir_rules_found"
}

case "${PROVIDER}" in
    aws)   restore_aws   ;;
    azure) restore_azure ;;
    gcp)   restore_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac

# Also reverse any journaled IAM revocations (key reactivate / role detach / SP re-enable).
reverse_iam_revocations
