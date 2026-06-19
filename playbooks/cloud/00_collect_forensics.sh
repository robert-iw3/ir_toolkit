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

    # VPC Flow Logs query (if CloudWatch Logs is available)
    log "Collecting current security group rules..."
    aws ec2 describe-security-groups \
        --region "${region}" \
        --output json \
        > "${ARTIFACT_DIR}/security_groups.json" 2>/dev/null || true

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

    # Entra ID sign-in logs for suspicious activity
    log "Pulling recent Entra ID sign-in risk events..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$top=20" \
        --output json \
        > "${ARTIFACT_DIR}/azure_risky_users.json" 2>/dev/null || true

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
