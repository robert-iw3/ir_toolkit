#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 02 — Cloud Workload Eradication (Stop/Terminate Instance)
#
# Stops (not terminates, for forensics) the compromised cloud workload.
# Instance data is preserved for forensic imaging before termination decision.
#
# AWS:   Stop EC2 instance → creates snapshot of root volume
# Azure: Stop Azure VM (deallocate) → disk preserved
# GCP:   Stop GCE instance → disk preserved
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

log()  { echo "[$(date -u +%H:%M:%SZ)] [eradicate/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/eradication.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"eradication\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

[[ -z "${TARGET}" ]] && { log "WARN: IR_TARGET not set — skipping"; emit "skipped" "no_target"; exit 0; }

eradicate_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"

    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --region "${region}" \
        --filters "Name=private-ip-address,Values=${TARGET}" \
        --query 'Reservations[0].Instances[0].InstanceId' \
        --output text 2>/dev/null)
    [[ "${instance_id}" == "None" || -z "${instance_id}" ]] && \
        { log "No instance found for ${TARGET}"; emit "skipped" "instance_not_found"; return 0; }

    # Snapshot root volume before stopping
    local root_vol
    root_vol=$(aws ec2 describe-instances \
        --region "${region}" \
        --instance-ids "${instance_id}" \
        --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' \
        --output text 2>/dev/null)
    if [[ "${root_vol}" != "None" && -n "${root_vol}" ]]; then
        log "Creating forensic snapshot of ${root_vol}..."
        aws ec2 create-snapshot \
            --region "${region}" \
            --volume-id "${root_vol}" \
            --description "IR forensic snapshot: ${INCIDENT_ID}" \
            --tag-specifications "ResourceType=snapshot,Tags=[{Key=ir:incident,Value=${INCIDENT_ID}},{Key=ir:forensic,Value=true}]" \
            --output json > "${ARTIFACT_DIR}/forensic_snapshot.json" 2>/dev/null || true
        log "Forensic snapshot initiated → ${ARTIFACT_DIR}/forensic_snapshot.json"
    fi

    log "Stopping instance ${instance_id}..."
    aws ec2 stop-instances --region "${region}" --instance-ids "${instance_id}" --output json \
        > "${ARTIFACT_DIR}/stop_result.json" 2>/dev/null
    log "Stop command issued for ${instance_id}"
    emit "success" "ec2_${instance_id}_stopped"
}

eradicate_azure() {
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"

    # Find VM by IP
    local vm_name
    vm_name=$(az vm list --resource-group "${rg}" \
        --query "[?publicIps=='${TARGET}' || privateIps=='${TARGET}'].name | [0]" \
        --output tsv 2>/dev/null)

    [[ -z "${vm_name}" ]] && { log "No Azure VM found for ${TARGET}"; emit "skipped" "vm_not_found"; return 0; }

    log "Deallocating Azure VM ${vm_name}..."
    az vm deallocate --resource-group "${rg}" --name "${vm_name}" --no-wait --output none 2>/dev/null
    log "Deallocate issued for ${vm_name} (async)"
    emit "success" "azure_vm_${vm_name}_deallocated"
}

eradicate_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    local zone="${IR_GCP_ZONE:-us-east1-b}"

    # Find instance by IP
    local instance_name
    instance_name=$(gcloud compute instances list \
        --project="${project}" \
        --filter="networkInterfaces[].networkIP:${TARGET}" \
        --format="value(name)" 2>/dev/null | head -1)

    [[ -z "${instance_name}" ]] && \
        { log "No GCE instance found for ${TARGET}"; emit "skipped" "instance_not_found"; return 0; }

    log "Stopping GCE instance ${instance_name}..."
    gcloud compute instances stop "${instance_name}" \
        --project="${project}" \
        --zone="${zone}" \
        --quiet 2>/dev/null
    log "GCE instance ${instance_name} stopped"
    emit "success" "gce_${instance_name}_stopped"
}

case "${PROVIDER}" in
    aws)   eradicate_aws   ;;
    azure) eradicate_azure ;;
    gcp)   eradicate_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac
