# shellcheck shell=bash
# ==============================================================================
# collect/aws.sh - AWS forensic collection + logging pre-flight.
# Sourced by 00_collect_forensics.sh; relies on helpers from collect/lib.sh.
# ==============================================================================

preflight_aws() {
    local region="${IR_AWS_REGION:-us-east-1}" v
    v=$(aws cloudtrail describe-trails --region "${region}" --query 'trailList[].Name' --output text 2>/dev/null)
    [[ -n "${v}" && "${v}" != "None" ]] && record_log_source "CloudTrail" true "${v}" \
        || record_log_source "CloudTrail" false "no CloudTrail trail found in ${region}"
    v=$(aws guardduty list-detectors --region "${region}" --query 'DetectorIds[0]' --output text 2>/dev/null)
    [[ -n "${v}" && "${v}" != "None" ]] && record_log_source "GuardDuty" true "detector ${v}" \
        || record_log_source "GuardDuty" false "no GuardDuty detector in ${region}"
    v=$(aws ec2 describe-flow-logs --region "${region}" --query 'FlowLogs[0].FlowLogId' --output text 2>/dev/null)
    [[ -n "${v}" && "${v}" != "None" ]] && record_log_source "VPCFlowLogs" true "${v}" \
        || record_log_source "VPCFlowLogs" false "no VPC flow logs in ${region}"
}

# GuardDuty findings for the window, merged across all swept regions.
_aws_collect_guardduty() {  # regions...
    log "Pulling GuardDuty findings..."
    : > "${ARTIFACT_DIR}/_gd_pages.jsonl"
    local r detector_id
    for r in "$@"; do
        if aws guardduty list-detectors --region "${r}" --query 'DetectorIds[0]' --output text \
                > "${ARTIFACT_DIR}/gd_detector_id.txt" 2>/dev/null; then
            detector_id=$(cat "${ARTIFACT_DIR}/gd_detector_id.txt")
            [[ -z "${detector_id}" || "${detector_id}" == "None" ]] && continue
            aws guardduty get-findings \
                --region "${r}" \
                --detector-id "${detector_id}" \
                --finding-ids $(aws guardduty list-findings \
                    --region "${r}" \
                    --detector-id "${detector_id}" \
                    --finding-criteria "{\"Criterion\":{\"updatedAt\":{\"GreaterThanOrEqual\":$(date -d "${WINDOW_START}" +%s 2>/dev/null || echo 0000000000)}}}" \
                    --query 'FindingIds' --output text 2>/dev/null | tr '\t' '\n' | head -n 50) \
                >> "${ARTIFACT_DIR}/_gd_pages.jsonl" 2>/dev/null || true
            echo >> "${ARTIFACT_DIR}/_gd_pages.jsonl"
        fi
    done
    merge_pages "${ARTIFACT_DIR}/_gd_pages.jsonl" "${ARTIFACT_DIR}/guardduty_findings.json" "Findings" \
        || cp -f "${ARTIFACT_DIR}/_gd_pages.jsonl" "${ARTIFACT_DIR}/guardduty_findings.json" 2>/dev/null || true
    rm -f "${ARTIFACT_DIR}/_gd_pages.jsonl" 2>/dev/null || true
    log "GuardDuty findings → ${ARTIFACT_DIR}/guardduty_findings.json"
}

# Full CloudTrail management events (no event-name filter), paged + merged across regions.
# The behavioral analyzer keys on eventName, so a narrow filter would blind it to
# IAM/STS/defense-evasion TTPs.
_aws_collect_cloudtrail() {  # regions...
    log "Pulling CloudTrail management events (full window, paginated)..."
    local r ct_token ct_page=0
    : > "${ARTIFACT_DIR}/_ct_pages.jsonl"
    for r in "$@"; do
        ct_token=""
        while :; do
            if [[ -n "${ct_token}" ]]; then
                aws cloudtrail lookup-events --region "${r}" \
                    --start-time "${WINDOW_START}" --end-time "${WINDOW_END}" \
                    --max-results 50 --next-token "${ct_token}" --output json \
                    > "${ARTIFACT_DIR}/_ct_page.json" 2>/dev/null || break
            else
                aws cloudtrail lookup-events --region "${r}" \
                    --start-time "${WINDOW_START}" --end-time "${WINDOW_END}" \
                    --max-results 50 --output json \
                    > "${ARTIFACT_DIR}/_ct_page.json" 2>/dev/null || break
            fi
            cat "${ARTIFACT_DIR}/_ct_page.json" >> "${ARTIFACT_DIR}/_ct_pages.jsonl"
            echo >> "${ARTIFACT_DIR}/_ct_pages.jsonl"
            ct_page=$((ct_page + 1))
            ct_token=$(PY_PAGE="${ARTIFACT_DIR}/_ct_page.json" "${PY:-python3}" -c \
                'import json,os;d=json.load(open(os.environ["PY_PAGE"]));print(d.get("NextToken") or "")' \
                2>/dev/null || echo "")
            [[ -z "${ct_token}" || "${ct_token}" == "None" || ${ct_page} -ge 40 ]] && break
        done
    done
    merge_pages "${ARTIFACT_DIR}/_ct_pages.jsonl" "${ARTIFACT_DIR}/cloudtrail_events.json" "Events" \
        || cp -f "${ARTIFACT_DIR}/_ct_page.json" "${ARTIFACT_DIR}/cloudtrail_events.json" 2>/dev/null || true
    rm -f "${ARTIFACT_DIR}/_ct_pages.jsonl" "${ARTIFACT_DIR}/_ct_page.json" 2>/dev/null || true
    log "CloudTrail events (${ct_page} page(s)) → ${ARTIFACT_DIR}/cloudtrail_events.json"
}

# S3 data events (object-level GetObject/CopyObject) for data-plane exfil detection.
# CloudTrail lookup-events returns only MANAGEMENT events, so data events must come from the
# trail's data-event sink: a CloudWatch Logs group (set IR_S3_DATAEVENT_LOG_GROUP). Best-effort -
# absent config leaves an empty file and the analyzer simply finds nothing (no FP).
_aws_collect_s3_data_events() {  # region
    local region="$1" grp="${IR_S3_DATAEVENT_LOG_GROUP:-}"
    : > "${ARTIFACT_DIR}/aws_s3_data_events.json"
    [[ -z "${grp}" ]] && { log "S3 data-event log group not set (IR_S3_DATAEVENT_LOG_GROUP) - skipping data-plane pull"; return 0; }
    log "Pulling S3 data events from ${grp}..."
    aws logs filter-log-events --region "${region}" --log-group-name "${grp}" \
        --start-time "$(( $(date -d "${WINDOW_START}" +%s 2>/dev/null || echo 0) * 1000 ))" \
        --output json > "${ARTIFACT_DIR}/aws_s3_data_events.json" 2>/dev/null || true
    log "S3 data events → ${ARTIFACT_DIR}/aws_s3_data_events.json"
}

# EBS disk snapshots before any eradication (opt-in; creates billable snapshots).
_aws_snapshot_disks() {  # region
    local region="$1"
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
}

collect_aws() {
    local region="${IR_AWS_REGION:-us-east-1}"
    # Attackers pivot to regions nobody watches. --all-regions (IR_ALL_REGIONS=1) sweeps every
    # enabled region for GuardDuty + CloudTrail; default is the single target region.
    local regions="${region}"
    if [[ "${IR_ALL_REGIONS:-0}" == "1" ]]; then
        regions=$(aws ec2 describe-regions --region "${region}" \
            --query 'Regions[].RegionName' --output text 2>/dev/null)
        [[ -z "${regions}" || "${regions}" == "None" ]] && regions="${region}"
    fi
    log "AWS region(s)=${regions} target=${TARGET}"

    # shellcheck disable=SC2086
    _aws_collect_guardduty ${regions}
    # shellcheck disable=SC2086
    _aws_collect_cloudtrail ${regions}

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

    [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]] && _aws_snapshot_disks "${region}"

    _aws_collect_s3_data_events "${region}"

    # IAM identity posture - credential report (key age / MFA / console / root key) and
    # Access Analyzer external-access findings. Adjudicated by cloud_iam.py.
    log "Collecting IAM credential report..."
    aws iam generate-credential-report >/dev/null 2>&1 || true
    aws iam get-credential-report --output json \
        > "${ARTIFACT_DIR}/aws_iam_credential_report.json" 2>/dev/null || true
    local aa_arn
    aa_arn=$(aws accessanalyzer list-analyzers --region "${region}" \
        --query 'analyzers[0].arn' --output text 2>/dev/null)
    if [[ -n "${aa_arn}" && "${aa_arn}" != "None" ]]; then
        log "Pulling Access Analyzer findings..."
        aws accessanalyzer list-findings --region "${region}" --analyzer-arn "${aa_arn}" \
            --output json > "${ARTIFACT_DIR}/aws_access_analyzer.json" 2>/dev/null || true
    fi

    log "Collecting current security group rules..."
    aws ec2 describe-security-groups \
        --region "${region}" \
        --output json \
        > "${ARTIFACT_DIR}/security_groups.json" 2>/dev/null || true

    # Public-bucket exposure sweep - which S3 buckets are reachable by anyone.
    log "Checking S3 buckets for public access..."
    {
        echo '{"buckets": ['
        _first=1
        for _b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null); do
            [[ -z "${_b}" ]] && continue
            _pab=$(aws s3api get-public-access-block --bucket "${_b}" \
                --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text 2>/dev/null)
            _status=$(aws s3api get-bucket-policy-status --bucket "${_b}" \
                --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)
            # public when the policy is public AND public access is not blocked
            _public=false
            [[ "${_status}" == "True" && "${_pab}" != "True" ]] && _public=true
            [[ ${_first} -eq 1 ]] && _first=0 || echo ','
            printf '{"name":"%s","public":%s}' "${_b}" "${_public}"
        done
        echo ']}'
    } > "${ARTIFACT_DIR}/aws_public_buckets.json" 2>/dev/null || true

    # Public disk-image exposure: EBS snapshots restorable by any account, and public AMIs.
    log "Checking for public snapshots / AMIs..."
    aws ec2 describe-snapshots --region "${region}" --owner-ids self \
        --restorable-by-user-ids all --output json \
        > "${ARTIFACT_DIR}/aws_public_snapshots.json" 2>/dev/null || true
    aws ec2 describe-images --region "${region}" --owners self \
        --filters "Name=is-public,Values=true" --output json \
        > "${ARTIFACT_DIR}/aws_public_amis.json" 2>/dev/null || true

    # IMDSv1 exposure: instances that accept metadata requests without a token (SSRF cred theft).
    log "Checking instance metadata (IMDSv1) posture..."
    aws ec2 describe-instances --region "${region}" \
        --query 'Reservations[].Instances[].{InstanceId:InstanceId,HttpTokens:MetadataOptions.HttpTokens}' \
        --output json 2>/dev/null | "${PY:-python3}" -c \
        'import json,sys
try: rows=json.load(sys.stdin)
except Exception: rows=[]
json.dump({"instances": rows if isinstance(rows,list) else []}, open(sys.argv[1],"w"))' \
        "${ARTIFACT_DIR}/aws_imds.json" 2>/dev/null || true

    # VPC Flow Logs for the incident window - network egress evidence / C2 confirmation.
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
