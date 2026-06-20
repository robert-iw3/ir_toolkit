#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 00 — Cloud Forensic Collection
#
# Runs inside the n8n container (not via SSH). Pulls telemetry from cloud
# provider APIs for the incident window and writes artifacts to /tmp/ir/.
#
# Supports: AWS, Azure, GCP (auto-detected from IR_CLOUD_PROVIDER)
#
# Environment variables (injected by run_containment.sh):
#   IR_INCIDENT_ID          Incident ID for artifact naming
#   IR_CLOUD_PROVIDER       aws | azure | gcp
#   IR_TARGET               IP address or cloud resource identifier
#   IR_C2_IPS               Comma-separated attacker IPs
#   IR_AWS_REGION           (AWS only)
#   IR_AZURE_SUBSCRIPTION   (Azure only)
#   IR_AZURE_RESOURCE_GROUP (Azure only)
#   IR_GCP_PROJECT          (GCP only)
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
C2_IPS="${IR_C2_IPS:-}"
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"

mkdir -p "${ARTIFACT_DIR}"

log() { echo "[$(date -u +%H:%M:%SZ)] [forensics/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/forensics.log"; }
emit_json() { local phase="$1"; local status="$2"; echo "{\"phase\":\"${phase}\",\"status\":\"${status}\",\"incident\":\"${INCIDENT_ID}\",\"provider\":\"${PROVIDER}\"}"; }

# ── Window: last 2 hours ───────────────────────────────────────────────────────
WINDOW_START=$(date -u -d '2 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
               date -u -v-2H '+%Y-%m-%dT%H:%M:%SZ')   # macOS fallback
WINDOW_END=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

log "Collecting cloud forensics for incident ${INCIDENT_ID} window ${WINDOW_START} → ${WINDOW_END}"

# ══════════════════════════════════════════════════════════════════════════════
# AWS
# ══════════════════════════════════════════════════════════════════════════════
collect_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"
    log "AWS region=${region} target=${TARGET}"

    # GuardDuty findings for the window
    log "Pulling GuardDuty findings..."
    if aws guardduty list-detectors --region "${region}" --query 'DetectorIds[0]' --output text \
            > "${ARTIFACT_DIR}/gd_detector_id.txt" 2>/dev/null; then
        local detector_id
        detector_id=$(cat "${ARTIFACT_DIR}/gd_detector_id.txt")
        aws guardduty get-findings \
            --region "${region}" \
            --detector-id "${detector_id}" \
            --finding-ids $(aws guardduty list-findings \
                --region "${region}" \
                --detector-id "${detector_id}" \
                --finding-criteria "{\"Criterion\":{\"updatedAt\":{\"GreaterThanOrEqual\":$(date -d "${WINDOW_START}" +%s 2>/dev/null || echo 0000000000)}}}" \
                --query 'FindingIds' --output text 2>/dev/null | head -c 500) \
            > "${ARTIFACT_DIR}/guardduty_findings.json" 2>/dev/null || true
        log "GuardDuty findings → ${ARTIFACT_DIR}/guardduty_findings.json"
    fi

    # CloudTrail events for the incident window
    log "Pulling CloudTrail events..."
    aws cloudtrail lookup-events \
        --region "${region}" \
        --start-time "${WINDOW_START}" \
        --end-time   "${WINDOW_END}" \
        --lookup-attributes "AttributeKey=EventName,AttributeValue=StopInstances" \
                            "AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute" \
                            "AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress" \
        --output json \
        > "${ARTIFACT_DIR}/cloudtrail_events.json" 2>/dev/null || true
    log "CloudTrail events → ${ARTIFACT_DIR}/cloudtrail_events.json"

    # EC2 instance details if TARGET is an IP
    if [[ -n "${TARGET}" ]]; then
        log "Pulling EC2 instance details for ${TARGET}..."
        aws ec2 describe-instances \
            --region "${region}" \
            --filters "Name=private-ip-address,Values=${TARGET}" \
            --output json \
            > "${ARTIFACT_DIR}/ec2_instance.json" 2>/dev/null || \
        aws ec2 describe-instances \
            --region "${region}" \
            --filters "Name=ip-address,Values=${TARGET}" \
            --output json \
            >> "${ARTIFACT_DIR}/ec2_instance.json" 2>/dev/null || true
        log "EC2 instance details → ${ARTIFACT_DIR}/ec2_instance.json"
    fi

    # Disk-snapshot acquisition — evidence preservation BEFORE any eradication.
    # Opt-in (creates billable EBS snapshots): enabled by --snapshot-disks -> IR_SNAPSHOT_DISKS=1.
    if [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]]; then
        log "Acquiring EBS disk snapshots for ${TARGET}..."
        local iid
        iid=$(aws ec2 describe-instances --region "${region}" \
                --filters "Name=private-ip-address,Values=${TARGET}" \
                --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null | head -n1)
        [[ -z "${iid}" || "${iid}" == "None" ]] && iid=$(aws ec2 describe-instances --region "${region}" \
                --filters "Name=ip-address,Values=${TARGET}" \
                --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null | head -n1)
        {
            echo "{\"instance\":\"${iid}\",\"snapshots\":["
            local first=1 vol snap
            for vol in $(aws ec2 describe-instances --region "${region}" --instance-ids "${iid}" \
                    --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' \
                    --output text 2>/dev/null); do
                [[ -z "${vol}" || "${vol}" == "None" ]] && continue
                snap=$(aws ec2 create-snapshot --region "${region}" --volume-id "${vol}" \
                    --description "IR ${INCIDENT_ID} ${vol}" \
                    --tag-specifications "ResourceType=snapshot,Tags=[{Key=ir:incident,Value=${INCIDENT_ID}}]" \
                    --query 'SnapshotId' --output text 2>/dev/null)
                [[ -z "${snap}" || "${snap}" == "None" ]] && continue
                [[ ${first} -eq 1 ]] && first=0 || echo ','
                printf '{"volume":"%s","snapshot":"%s"}' "${vol}" "${snap}"
                log "  EBS snapshot ${snap} of volume ${vol}" >&2
            done
            echo ']}'
        } > "${ARTIFACT_DIR}/ebs_snapshots.json" 2>/dev/null || true
        log "EBS snapshots → ${ARTIFACT_DIR}/ebs_snapshots.json"
    fi

    log "Collecting current security group rules..."
    aws ec2 describe-security-groups \
        --region "${region}" \
        --output json \
        > "${ARTIFACT_DIR}/security_groups.json" 2>/dev/null || true

    # VPC Flow Logs for the incident window — network egress evidence / C2 confirmation.
    log "Pulling VPC flow logs..."
    aws ec2 describe-flow-logs --region "${region}" --output json \
        > "${ARTIFACT_DIR}/aws_flow_log_config.json" 2>/dev/null || true
    local flgrp
    flgrp=$(aws ec2 describe-flow-logs --region "${region}" \
        --query 'FlowLogs[0].LogGroupName' --output text 2>/dev/null)
    if [[ -n "${flgrp}" && "${flgrp}" != "None" ]]; then
        aws logs filter-log-events --region "${region}" --log-group-name "${flgrp}" \
            --start-time "$(( $(date -d "${WINDOW_START}" +%s 2>/dev/null || echo 0) * 1000 ))" \
            --output json > "${ARTIFACT_DIR}/aws_vpc_flow_logs.json" 2>/dev/null || true
        log "VPC flow logs → ${ARTIFACT_DIR}/aws_vpc_flow_logs.json"
    fi

    log "AWS forensic collection complete"
    emit_json "forensics" "success"
}

# ══════════════════════════════════════════════════════════════════════════════
# Azure
# ══════════════════════════════════════════════════════════════════════════════
collect_azure() {
    local subscription="${IR_AZURE_SUBSCRIPTION:-}"
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"
    log "Azure subscription=${subscription} resource_group=${rg} target=${TARGET}"

    [[ -z "${subscription}" ]] && { log "WARN: IR_AZURE_SUBSCRIPTION not set"; }

    # Azure Monitor activity log
    log "Pulling Azure Activity Log..."
    az monitor activity-log list \
        --subscription "${subscription}" \
        --start-time "${WINDOW_START}" \
        --end-time   "${WINDOW_END}" \
        --output json \
        > "${ARTIFACT_DIR}/azure_activity_log.json" 2>/dev/null || true
    log "Activity log → ${ARTIFACT_DIR}/azure_activity_log.json"

    # NSG rules for affected resource group
    if [[ -n "${rg}" ]]; then
        log "Pulling NSG rules for RG ${rg}..."
        az network nsg list \
            --resource-group "${rg}" \
            --output json \
            > "${ARTIFACT_DIR}/azure_nsg_rules.json" 2>/dev/null || true
        log "NSG rules → ${ARTIFACT_DIR}/azure_nsg_rules.json"
    fi

    # NSG flow-log configuration (the flow records themselves live in a storage account /
    # Log Analytics — collecting the config points the analyst at where the egress data is).
    log "Pulling NSG flow-log configuration..."
    az network watcher flow-log list --location "${IR_AZURE_LOCATION:-eastus}" --output json \
        > "${ARTIFACT_DIR}/azure_flow_logs.json" 2>/dev/null || true

    # Entra ID sign-in logs for suspicious activity
    log "Pulling recent Entra ID sign-in risk events..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$top=20" \
        --output json \
        > "${ARTIFACT_DIR}/azure_risky_users.json" 2>/dev/null || true

    # SaaS / identity (Entra + M365): the high-value identity-attack artifacts.
    # OAuth delegated grants — illicit consent grant attack (mailbox/file/tenant reach).
    log "Pulling OAuth consent grants..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$top=100" \
        --output json \
        > "${ARTIFACT_DIR}/azure_oauth_grants.json" 2>/dev/null || true

    # Entra directory audit — SP credential adds, app consents, role grants, MFA/CA changes.
    log "Pulling Entra directory audit log..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$top=200" \
        --output json \
        > "${ARTIFACT_DIR}/azure_directory_audit.json" 2>/dev/null || true

    # Mailbox inbox rules — BEC auto-forward/redirect. Per-user via Graph; best-effort
    # across the first page of users (full-tenant sweep is an analyst follow-up).
    log "Pulling mailbox inbox forwarding rules (best-effort)..."
    : > "${ARTIFACT_DIR}/azure_inbox_rules.json"
    {
        echo '{"value": ['
        _first=1
        for _uid in $(az rest --method get \
                --url "https://graph.microsoft.com/v1.0/users?\$select=id,userPrincipalName&\$top=50" \
                --query 'value[].id' --output tsv 2>/dev/null); do
            _rules=$(az rest --method get \
                --url "https://graph.microsoft.com/v1.0/users/${_uid}/mailFolders/inbox/messageRules" \
                --query 'value' --output json 2>/dev/null)
            # splice each user's rules array into the combined value[] list
            if [[ -n "${_rules}" && "${_rules}" != "[]" && "${_rules}" != "null" ]]; then
                _inner=$(echo "${_rules}" | sed -e 's/^\[//' -e 's/\]$//')
                [[ -n "${_inner// /}" ]] || continue
                [[ ${_first} -eq 1 ]] && _first=0 || echo ','
                printf '%s' "${_inner}"
            fi
        done
        echo ']}'
    } > "${ARTIFACT_DIR}/azure_inbox_rules.json" 2>/dev/null || true

    # Disk-snapshot acquisition — evidence preservation BEFORE eradication (opt-in).
    if [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]]; then
        log "Acquiring Azure managed-disk snapshots for ${TARGET}..."
        local rg_arg=(); [[ -n "${rg}" ]] && rg_arg=(--resource-group "${rg}")
        {
            echo "{\"vm\":\"${TARGET}\",\"snapshots\":["
            local first=1 disk sname sid
            for disk in $(az vm show --name "${TARGET}" "${rg_arg[@]}" \
                    --query '[storageProfile.osDisk.managedDisk.id, storageProfile.dataDisks[].managedDisk.id][]' \
                    --output tsv 2>/dev/null); do
                [[ -z "${disk}" || "${disk}" == "null" ]] && continue
                sname="irsnap-$(basename "${disk}")-$(date -u +%H%M%S)"
                sid=$(az snapshot create "${rg_arg[@]}" --name "${sname}" --source "${disk}" \
                    --tags "ir:incident=${INCIDENT_ID}" --query 'id' --output tsv 2>/dev/null)
                [[ -z "${sid}" || "${sid}" == "null" ]] && continue
                [[ ${first} -eq 1 ]] && first=0 || echo ','
                printf '{"disk":"%s","snapshot":"%s"}' "${disk}" "${sid}"
                log "  Azure snapshot ${sname}" >&2
            done
            echo ']}'
        } > "${ARTIFACT_DIR}/azure_disk_snapshots.json" 2>/dev/null || true
        log "Azure disk snapshots → ${ARTIFACT_DIR}/azure_disk_snapshots.json"
    fi

    log "Azure forensic collection complete"
    emit_json "forensics" "success"
}

# ══════════════════════════════════════════════════════════════════════════════
# GCP
# ══════════════════════════════════════════════════════════════════════════════
collect_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    log "GCP project=${project} target=${TARGET}"

    [[ -z "${project}" ]] && { log "WARN: IR_GCP_PROJECT not set"; }

    # Cloud Audit Logs
    log "Pulling Cloud Audit Logs..."
    gcloud logging read \
        "timestamp>=\"${WINDOW_START}\" AND timestamp<=\"${WINDOW_END}\" AND logName:\"cloudaudit\"" \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_audit_log.json" 2>/dev/null || true
    log "Audit logs → ${ARTIFACT_DIR}/gcp_audit_log.json"

    # Security Command Center findings
    log "Pulling Security Command Center findings..."
    gcloud scc findings list "projects/${project}" \
        --filter="state=ACTIVE AND eventTime>\"${WINDOW_START}\"" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_scc_findings.json" 2>/dev/null || true
    log "SCC findings → ${ARTIFACT_DIR}/gcp_scc_findings.json"

    # VPC firewall rules
    log "Pulling VPC firewall rules..."
    gcloud compute firewall-rules list \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_firewall_rules.json" 2>/dev/null || true

    # VPC Flow Logs (Cloud Logging) for the window — network egress evidence / C2 confirmation.
    log "Pulling VPC flow logs..."
    gcloud logging read \
        "timestamp>=\"${WINDOW_START}\" AND timestamp<=\"${WINDOW_END}\" AND logName:\"vpc_flows\"" \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_vpc_flow_logs.json" 2>/dev/null || true
    log "VPC flow logs → ${ARTIFACT_DIR}/gcp_vpc_flow_logs.json"

    # Disk-snapshot acquisition — evidence preservation BEFORE eradication (opt-in).
    if [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]]; then
        log "Acquiring GCP disk snapshots for ${TARGET}..."
        local zone_arg=(); [[ -n "${IR_GCP_ZONE:-}" ]] && zone_arg=(--zone "${IR_GCP_ZONE}")
        {
            echo "{\"instance\":\"${TARGET}\",\"snapshots\":["
            local first=1 disk dname sname
            for disk in $(gcloud compute instances describe "${TARGET}" "${zone_arg[@]}" \
                    --project="${project}" --format='value(disks[].source)' 2>/dev/null | tr ';' '\n'); do
                [[ -z "${disk}" ]] && continue
                dname=$(basename "${disk}")
                sname="irsnap-${dname}-$(date -u +%H%M%S)"
                gcloud compute disks snapshot "${dname}" "${zone_arg[@]}" \
                    --project="${project}" --snapshot-names="${sname}" 2>/dev/null || continue
                [[ ${first} -eq 1 ]] && first=0 || echo ','
                printf '{"disk":"%s","snapshot":"%s"}' "${dname}" "${sname}"
                log "  GCP snapshot ${sname}" >&2
            done
            echo ']}'
        } > "${ARTIFACT_DIR}/gcp_disk_snapshots.json" 2>/dev/null || true
        log "GCP disk snapshots → ${ARTIFACT_DIR}/gcp_disk_snapshots.json"
    fi

    log "GCP forensic collection complete"
    emit_json "forensics" "success"
}

# ── Dispatch ───────────────────────────────────────────────────────────────────
case "${PROVIDER}" in
    aws)   collect_aws   ;;
    azure) collect_azure ;;
    gcp)   collect_gcp   ;;
    *)     log "Unknown cloud provider: ${PROVIDER}"; emit_json "forensics" "skipped"; exit 0 ;;
esac

# Write artifact index
ls -lh "${ARTIFACT_DIR}/" > "${ARTIFACT_DIR}/artifact_index.txt" 2>/dev/null || true
log "Artifacts written to ${ARTIFACT_DIR}/"
emit_json "forensics" "success"
