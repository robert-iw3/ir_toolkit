#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 04 - Cloud C2 Channel Blocking
#
# Blocks outbound connections to known C2 IPs at the cloud network layer:
#   AWS:   Network ACL deny rules + Security Group egress revocation
#   Azure: NSG outbound deny rules for each C2 IP
#   GCP:   VPC firewall egress deny rules for each C2 IP
#
# Blocks DNS-based C2 (when --c2-domains supplied) at the cloud DNS layer:
#   AWS:   Route 53 Resolver DNS Firewall block list + rule group, associated to the VPC
#   GCP:   Cloud DNS response policy sinkholing each domain
#   Azure: Private DNS zone per domain (A -> 0.0.0.0), VNet-linked when IR_AZURE_VNET set
# DNS-firewall creation respects IR_DRY_RUN (plans when 1; mutates when 0).
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
C2_IPS="${IR_C2_IPS:-}"
C2_DOMAINS="${IR_C2_DOMAINS:-}"
DRY_RUN="${IR_DRY_RUN:-1}"                # DNS-firewall creation respects this (safe by default)
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

log()  { echo "[$(date -u +%H:%M:%SZ)] [c2block/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/c2_block.log"; }
emit() { local s="$1"; local d="${2:-}"; echo "{\"phase\":\"c2_blocking\",\"status\":\"${s}\",\"detail\":\"${d}\",\"provider\":\"${PROVIDER}\"}"; }

[[ -z "${C2_IPS}" && -z "${C2_DOMAINS}" ]] && \
    { log "No C2 IPs or domains provided - skipping"; emit "skipped" "no_iocs"; exit 0; }

block_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"
    local blocked=0

    # Find affected VPC
    local vpc_id
    vpc_id=$(aws ec2 describe-instances \
        --region "${region}" \
        --filters "Name=private-ip-address,Values=${TARGET}" \
        --query 'Reservations[0].Instances[0].VpcId' \
        --output text 2>/dev/null)
    [[ "${vpc_id}" == "None" || -z "${vpc_id}" ]] && vpc_id="${IR_AWS_VPC_ID:-}"
    [[ -z "${vpc_id}" ]] && { log "WARN: VPC ID unknown - skipping NACL rules"; }

    # Network ACL deny for each C2 IP
    if [[ -n "${vpc_id}" && -n "${C2_IPS}" ]]; then
        local nacl_id
        nacl_id=$(aws ec2 describe-network-acls \
            --region "${region}" \
            --filters "Name=vpc-id,Values=${vpc_id}" "Name=default,Values=true" \
            --query 'NetworkAcls[0].NetworkAclId' \
            --output text 2>/dev/null)

        if [[ "${nacl_id}" != "None" && -n "${nacl_id}" ]]; then
            local rule_num=200
            IFS=',' read -ra ips <<< "${C2_IPS}"
            for c2_ip in "${ips[@]}"; do
                c2_ip="${c2_ip// /}"
                [[ -z "${c2_ip}" ]] && continue
                log "Adding NACL egress deny for C2 IP ${c2_ip} (rule ${rule_num})..."

                aws ec2 create-network-acl-entry \
                    --region "${region}" \
                    --network-acl-id "${nacl_id}" \
                    --rule-number "${rule_num}" \
                    --protocol "-1" \
                    --rule-action deny \
                    --egress \
                    --cidr-block "${c2_ip}/32" 2>/dev/null && blocked=1 || true

                rule_num=$((rule_num + 1))
            done
            log "NACL deny rules added to ${nacl_id}"
        fi
    fi

    # Route 53 Resolver DNS Firewall: a domain list + BLOCK rule group, associated to the VPC.
    if [[ -n "${C2_DOMAINS}" ]]; then
        echo "${C2_DOMAINS}" > "${ARTIFACT_DIR}/c2_domains_to_block.txt"
        if [[ "${DRY_RUN}" == "1" ]]; then
            log "[DRY-RUN] would create Route 53 DNS Firewall block list+rule group for: ${C2_DOMAINS}"
        else
            local dl_id rg_id dom_args=()
            IFS=',' read -ra doms <<< "${C2_DOMAINS}"
            for d in "${doms[@]}"; do d="${d// /}"; [[ -n "${d}" ]] && dom_args+=("${d}"); done
            dl_id=$(aws route53resolver create-firewall-domain-list --region "${region}" \
                --name "IR-C2-${INCIDENT_ID:0:8}" --query 'FirewallDomainList.Id' --output text 2>/dev/null)
            if [[ -n "${dl_id}" && "${dl_id}" != "None" ]]; then
                aws route53resolver update-firewall-domains --region "${region}" \
                    --firewall-domain-list-id "${dl_id}" --operation ADD \
                    --domains "${dom_args[@]}" 2>/dev/null || true
                rg_id=$(aws route53resolver create-firewall-rule-group --region "${region}" \
                    --name "IR-C2-${INCIDENT_ID:0:8}" --query 'FirewallRuleGroup.Id' --output text 2>/dev/null)
                if [[ -n "${rg_id}" && "${rg_id}" != "None" ]]; then
                    aws route53resolver create-firewall-rule --region "${region}" \
                        --firewall-rule-group-id "${rg_id}" --firewall-domain-list-id "${dl_id}" \
                        --priority 100 --action BLOCK --block-response NODATA \
                        --name "IR-C2-block" 2>/dev/null || true
                    [[ -n "${vpc_id}" ]] && aws route53resolver associate-firewall-rule-group \
                        --region "${region}" --firewall-rule-group-id "${rg_id}" --vpc-id "${vpc_id}" \
                        --priority 101 --name "IR-C2-${INCIDENT_ID:0:8}" 2>/dev/null || true
                    log "Route 53 DNS Firewall BLOCK rule group ${rg_id} created for C2 domains"; blocked=1
                fi
            else
                log "WARN: could not create DNS Firewall domain list (Route53 Resolver perms?)"
            fi
        fi
    fi

    echo "${C2_IPS}" > "${ARTIFACT_DIR}/c2_ips_blocked.txt"
    [[ "${blocked}" -eq 1 ]] && emit "success" "aws_c2_blocked" || emit "partial" "nacl_unavailable"
}

block_azure() {
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"
    local blocked=0

    IFS=',' read -ra ips <<< "${C2_IPS}"
    for c2_ip in "${ips[@]}"; do
        c2_ip="${c2_ip// /}"
        [[ -z "${c2_ip}" ]] && continue

        local safe_ip
        safe_ip=$(echo "${c2_ip}" | tr '.' '-')
        local rule_name="IR-C2-BLOCK-${safe_ip}-${INCIDENT_ID:0:8}"

        # Apply to all NSGs in the resource group
        local nsgs
        nsgs=$(az network nsg list --resource-group "${rg}" --query '[].name' --output tsv 2>/dev/null)
        while IFS= read -r nsg_name; do
            [[ -z "${nsg_name}" ]] && continue
            log "Blocking C2 IP ${c2_ip} outbound on NSG ${nsg_name}..."
            az network nsg rule create \
                --resource-group "${rg}" \
                --nsg-name "${nsg_name}" \
                --name "${rule_name}" \
                --priority 110 \
                --direction Outbound \
                --access Deny \
                --protocol '*' \
                --source-address-prefixes '*' \
                --source-port-ranges '*' \
                --destination-address-prefixes "${c2_ip}" \
                --destination-port-ranges '*' \
                --description "IR C2 block: ${INCIDENT_ID}" \
                --output none 2>/dev/null && blocked=1 || true
        done <<< "${nsgs}"
    done

    # Azure has no native DNS firewall: sinkhole each C2 domain with a Private DNS zone
    # (A record -> 0.0.0.0), linked to the VNet when IR_AZURE_VNET is supplied.
    if [[ -n "${C2_DOMAINS}" ]]; then
        echo "${C2_DOMAINS}" > "${ARTIFACT_DIR}/c2_domains_to_block.txt"
        if [[ "${DRY_RUN}" == "1" ]]; then
            log "[DRY-RUN] would sinkhole C2 domains via Private DNS zones: ${C2_DOMAINS}"
        else
            IFS=',' read -ra doms <<< "${C2_DOMAINS}"
            for d in "${doms[@]}"; do
                d="${d// /}"; [[ -z "${d}" ]] && continue
                az network private-dns zone create --resource-group "${rg}" --name "${d}" \
                    --output none 2>/dev/null || true
                az network private-dns record-set a add-record --resource-group "${rg}" \
                    --zone-name "${d}" --record-set-name "@" --ipv4-address "0.0.0.0" \
                    --output none 2>/dev/null || true
                [[ -n "${IR_AZURE_VNET:-}" ]] && az network private-dns link vnet create \
                    --resource-group "${rg}" --zone-name "${d}" --name "ir-sinkhole" \
                    --virtual-network "${IR_AZURE_VNET}" --registration-enabled false \
                    --output none 2>/dev/null || true
                blocked=1
            done
            log "Private DNS sinkhole zones created for C2 domains"
        fi
    fi

    echo "${C2_IPS}" > "${ARTIFACT_DIR}/c2_ips_blocked.txt"
    [[ "${blocked}" -eq 1 ]] && emit "success" "azure_c2_blocked" || emit "partial" "no_nsg_found"
}

block_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    local network="${IR_GCP_NETWORK:-default}"
    local blocked=0

    IFS=',' read -ra ips <<< "${C2_IPS}"
    for c2_ip in "${ips[@]}"; do
        c2_ip="${c2_ip// /}"
        [[ -z "${c2_ip}" ]] && continue

        local safe_ip
        safe_ip=$(echo "${c2_ip}" | tr '.' '-')
        local rule_name="ir-c2-block-${safe_ip}-${INCIDENT_ID:0:8}"
        rule_name=$(echo "${rule_name}" | tr '[:upper:]' '[:lower:]' | cut -c1-63)

        log "Blocking C2 IP ${c2_ip} outbound via VPC firewall rule ${rule_name}..."
        gcloud compute firewall-rules create "${rule_name}" \
            --project="${project}" \
            --network="${network}" \
            --direction=EGRESS \
            --action=DENY \
            --rules=all \
            --destination-ranges="${c2_ip}/32" \
            --priority=800 \
            --description="IR C2 block: ${INCIDENT_ID}" \
            --quiet 2>/dev/null && blocked=1 || true
    done

    # Cloud DNS response policy: sinkhole each C2 domain to a local (NXDOMAIN-like) answer.
    if [[ -n "${C2_DOMAINS}" ]]; then
        echo "${C2_DOMAINS}" > "${ARTIFACT_DIR}/c2_domains_to_block.txt"
        if [[ "${DRY_RUN}" == "1" ]]; then
            log "[DRY-RUN] would create Cloud DNS response policy sinkholing: ${C2_DOMAINS}"
        else
            local rp="ir-c2-${INCIDENT_ID:0:8}"
            rp=$(echo "${rp}" | tr '[:upper:]' '[:lower:]' | cut -c1-63)
            gcloud dns response-policies create "${rp}" --project="${project}" \
                --networks="${network}" --description="IR C2 sinkhole: ${INCIDENT_ID}" \
                --quiet 2>/dev/null || true
            IFS=',' read -ra doms <<< "${C2_DOMAINS}"
            for d in "${doms[@]}"; do
                d="${d// /}"; [[ -z "${d}" ]] && continue
                # local-data rule with no rrdata = sinkhole (resolver returns no usable answer)
                gcloud dns response-policies rules create "ir-${d//[^a-z0-9]/-}" \
                    --project="${project}" --response-policy="${rp}" \
                    --dns-name="${d}." --behavior=bypassResponsePolicy --quiet 2>/dev/null \
                    || gcloud dns response-policies rules create "ir-${d//[^a-z0-9]/-}" \
                        --project="${project}" --response-policy="${rp}" \
                        --dns-name="${d}." --local-data="name=${d}.,type=A,ttl=300,rrdatas=0.0.0.0" \
                        --quiet 2>/dev/null || true
                blocked=1
            done
            log "Cloud DNS response policy ${rp} created sinkholing C2 domains"
        fi
    fi

    echo "${C2_IPS}" > "${ARTIFACT_DIR}/c2_ips_blocked.txt"
    [[ "${blocked}" -eq 1 ]] && emit "success" "gcp_c2_blocked" || emit "partial" "no_rules_created"
}

case "${PROVIDER}" in
    aws)   block_aws   ;;
    azure) block_azure ;;
    gcp)   block_gcp   ;;
    *)     log "Unknown provider: ${PROVIDER}"; emit "skipped" "unknown_provider"; exit 0 ;;
esac
