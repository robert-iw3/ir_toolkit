#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 01 - Cloud Host Containment (Network Isolation)
#
# Runs inside the n8n container. Isolates the affected cloud workload by:
#   AWS:   Attaching a quarantine Security Group (deny-all except mgmt CIDR)
#   Azure: Adding deny-all NSG inbound/outbound rules for the target IP
#   GCP:   Creating deny-all ingress/egress VPC firewall rule for the target IP
#
# Idempotent - safe to re-run. Preserves management access.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
MGMT_CIDR="${IR_MGMT_IPS:-10.0.0.0/8}"
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

log()  { echo "[$(date -u +%H:%M:%SZ)] [contain/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/containment.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"containment\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\",\"target\":\"${TARGET}\"}"; }

[[ -z "${TARGET}" ]] && { log "ERROR: IR_TARGET not set"; emit "failed" "no_target"; exit 1; }

# ==============================================================================
# AWS: Quarantine Security Group
# ==============================================================================
contain_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"
    log "Isolating ${TARGET} via quarantine SG in ${region}"

    # Find the instance by private or public IP
    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --region "${region}" \
        --filters "Name=private-ip-address,Values=${TARGET}" \
        --query 'Reservations[0].Instances[0].InstanceId' \
        --output text 2>/dev/null)
    if [[ "${instance_id}" == "None" || -z "${instance_id}" ]]; then
        instance_id=$(aws ec2 describe-instances \
            --region "${region}" \
            --filters "Name=ip-address,Values=${TARGET}" \
            --query 'Reservations[0].Instances[0].InstanceId' \
            --output text 2>/dev/null)
    fi
    [[ "${instance_id}" == "None" || -z "${instance_id}" ]] && \
        { log "WARN: No EC2 instance found for ${TARGET} - skipping SG isolation"; emit "skipped" "instance_not_found"; return 0; }

    local vpc_id
    vpc_id=$(aws ec2 describe-instances \
        --region "${region}" \
        --instance-ids "${instance_id}" \
        --query 'Reservations[0].Instances[0].VpcId' \
        --output text 2>/dev/null)

    # Get or create quarantine SG
    local qsg_name="IR-QUARANTINE-${vpc_id}"
    local qsg_id
    qsg_id=$(aws ec2 describe-security-groups \
        --region "${region}" \
        --filters "Name=group-name,Values=${qsg_name}" "Name=vpc-id,Values=${vpc_id}" \
        --query 'SecurityGroups[0].GroupId' \
        --output text 2>/dev/null)

    if [[ "${qsg_id}" == "None" || -z "${qsg_id}" ]]; then
        log "Creating quarantine SG ${qsg_name}..."
        qsg_id=$(aws ec2 create-security-group \
            --region "${region}" \
            --group-name "${qsg_name}" \
            --description "IR quarantine - deny-all except management (${INCIDENT_ID})" \
            --vpc-id "${vpc_id}" \
            --query 'GroupId' --output text)

        # Remove default outbound allow-all
        aws ec2 revoke-security-group-egress \
            --region "${region}" \
            --group-id "${qsg_id}" \
            --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

        # Allow management CIDR inbound SSH/WinRM
        aws ec2 authorize-security-group-ingress \
            --region "${region}" \
            --group-id "${qsg_id}" \
            --ip-permissions "[
              {\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"${MGMT_CIDR}\",\"Description\":\"IR mgmt SSH\"}]},
              {\"IpProtocol\":\"tcp\",\"FromPort\":5985,\"ToPort\":5986,\"IpRanges\":[{\"CidrIp\":\"${MGMT_CIDR}\",\"Description\":\"IR mgmt WinRM\"}]}
            ]" 2>/dev/null || true

        # Allow management egress
        aws ec2 authorize-security-group-egress \
            --region "${region}" \
            --group-id "${qsg_id}" \
            --ip-permissions "[{\"IpProtocol\":\"-1\",\"IpRanges\":[{\"CidrIp\":\"${MGMT_CIDR}\",\"Description\":\"IR mgmt egress\"}]}]" 2>/dev/null || true

        log "Quarantine SG created: ${qsg_id}"
    fi

    # Save original SGs for restore
    local original_sgs
    original_sgs=$(aws ec2 describe-instances \
        --region "${region}" \
        --instance-ids "${instance_id}" \
        --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' \
        --output text 2>/dev/null)
    echo "${original_sgs}" > "${ARTIFACT_DIR}/original_sgs_${instance_id}.txt"
    log "Original SGs saved: ${original_sgs}"

    # Tag instance
    aws ec2 create-tags \
        --region "${region}" \
        --resources "${instance_id}" \
        --tags "Key=ir:isolated,Value=true" \
               "Key=ir:incident,Value=${INCIDENT_ID}" \
               "Key=ir:pre-isolation-sgs,Value=$(echo "${original_sgs}" | tr '\t' ',')" 2>/dev/null || true

    # Replace SGs with quarantine SG
    aws ec2 modify-instance-attribute \
        --region "${region}" \
        --instance-id "${instance_id}" \
        --groups "${qsg_id}"

    log "CONTAINED: ${instance_id} isolated via quarantine SG ${qsg_id}"
    emit "success" "ec2_${instance_id}_isolated_sg_${qsg_id}"
}

# ==============================================================================
# Azure: NSG Deny Rules
# ==============================================================================
contain_azure() {
    local subscription="${IR_AZURE_SUBSCRIPTION:-}"
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"
    log "Isolating ${TARGET} via NSG deny rule (subscription=${subscription} rg=${rg})"

    # Find NSG(s) in the resource group
    local nsgs
    nsgs=$(az network nsg list --resource-group "${rg}" --query '[].name' --output tsv 2>/dev/null)

    if [[ -z "${nsgs}" ]]; then
        log "WARN: No NSGs found in resource group ${rg}"
        emit "skipped" "no_nsg_found"
        return 0
    fi

    local rule_name="IR-DENY-$(echo "${TARGET}" | tr '.' '-')-${INCIDENT_ID}"
    local contained=0

    while IFS= read -r nsg_name; do
        log "Adding deny rules to NSG: ${nsg_name}"

        # Deny inbound from attacker IP
        az network nsg rule create \
            --resource-group "${rg}" \
            --nsg-name "${nsg_name}" \
            --name "${rule_name}-IN" \
            --priority 100 \
            --direction Inbound \
            --access Deny \
            --protocol '*' \
            --source-address-prefixes "${TARGET}" \
            --source-port-ranges '*' \
            --destination-address-prefixes '*' \
            --destination-port-ranges '*' \
            --description "IR auto-isolation: ${INCIDENT_ID}" \
            --output none 2>/dev/null && contained=1 || true

        # Deny outbound to attacker IP
        az network nsg rule create \
            --resource-group "${rg}" \
            --nsg-name "${nsg_name}" \
            --name "${rule_name}-OUT" \
            --priority 100 \
            --direction Outbound \
            --access Deny \
            --protocol '*' \
            --source-address-prefixes '*' \
            --source-port-ranges '*' \
            --destination-address-prefixes "${TARGET}" \
            --destination-port-ranges '*' \
            --description "IR auto-isolation: ${INCIDENT_ID}" \
            --output none 2>/dev/null || true

    done <<< "${nsgs}"

    if [[ "${contained}" -eq 1 ]]; then
        log "CONTAINED: deny rules added for ${TARGET} in ${rg}"
        emit "success" "nsg_deny_rules_added"
    else
        emit "failed" "nsg_rule_creation_failed"
    fi
}

# ==============================================================================
# GCP: VPC Firewall Deny Rules
# ==============================================================================
contain_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    local network="${IR_GCP_NETWORK:-default}"
    log "Isolating ${TARGET} via VPC firewall deny rule (project=${project} network=${network})"

    local safe_ip
    safe_ip=$(echo "${TARGET}" | tr '.' '-')
    local rule_in="ir-deny-${safe_ip}-in-${INCIDENT_ID:0:8}"
    local rule_out="ir-deny-${safe_ip}-out-${INCIDENT_ID:0:8}"
    # GCP firewall rule names must be ≤63 chars, lowercase, hyphens only
    rule_in=$(echo "${rule_in}" | tr '[:upper:]' '[:lower:]' | cut -c1-63)
    rule_out=$(echo "${rule_out}" | tr '[:upper:]' '[:lower:]' | cut -c1-63)

    # Deny ingress from attacker IP
    gcloud compute firewall-rules create "${rule_in}" \
        --project="${project}" \
        --network="${network}" \
        --direction=INGRESS \
        --action=DENY \
        --rules=all \
        --source-ranges="${TARGET}/32" \
        --priority=900 \
        --description="IR auto-isolation: ${INCIDENT_ID}" \
        --quiet 2>/dev/null || \
    log "WARN: Ingress rule may already exist - continuing"

    # Deny egress to attacker IP
    gcloud compute firewall-rules create "${rule_out}" \
        --project="${project}" \
        --network="${network}" \
        --direction=EGRESS \
        --action=DENY \
        --rules=all \
        --destination-ranges="${TARGET}/32" \
        --priority=900 \
        --description="IR auto-isolation: ${INCIDENT_ID}" \
        --quiet 2>/dev/null || \
    log "WARN: Egress rule may already exist - continuing"

    log "CONTAINED: VPC firewall deny rules created for ${TARGET}"
    emit "success" "vpc_fw_rules_${rule_in}_${rule_out}"
}

# -- Dispatch -------------------------------------------------------------------
case "${PROVIDER}" in
    aws)   contain_aws   ;;
    azure) contain_azure ;;
    gcp)   contain_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac
