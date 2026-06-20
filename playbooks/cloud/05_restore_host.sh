#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 05 — Cloud Host Restoration (Release Quarantine)
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
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"

log()  { echo "[$(date -u +%H:%M:%SZ)] [restore/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/restore.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"restore\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

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
        log "WARN: No pre-isolation SG record for ${instance_id} — manual restore required"
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
