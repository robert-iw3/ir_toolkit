# shellcheck shell=bash
# ==============================================================================
# collect/gcp.sh - GCP forensic collection + logging pre-flight.
# Sourced by 00_collect_forensics.sh; relies on helpers from collect/lib.sh.
# ==============================================================================

preflight_gcp() {
    local project="${IR_GCP_PROJECT:-}" v
    v=$(gcloud logging sinks list --project="${project}" --format='value(name)' 2>/dev/null)
    [[ -n "${v}" ]] && record_log_source "LoggingSinks" true "${v}" \
        || record_log_source "LoggingSinks" false "no Cloud Logging sinks"
}

# GCE disk snapshots before eradication (opt-in).
_gcp_snapshot_disks() {  # project
    local project="$1"
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
}

collect_gcp() {
    local project="${IR_GCP_PROJECT:-}"
    log "GCP project=${project} target=${TARGET}"
    [[ -z "${project}" ]] && { log "WARN: IR_GCP_PROJECT not set"; }

    # Cloud Audit Logs - admin-activity, data-access, AND system-event streams (all under
    # cloudaudit). data_access carries SA-key use and object reads; --limit raised so a
    # multi-day window is not truncated. Analyzed by normalize_gcp_audit.
    log "Pulling Cloud Audit Logs (admin + data-access + system-event)..."
    gcloud logging read \
        "timestamp>=\"${WINDOW_START}\" AND timestamp<=\"${WINDOW_END}\" AND logName:\"cloudaudit.googleapis.com\"" \
        --project="${project}" \
        --format=json \
        --limit=5000 \
        > "${ARTIFACT_DIR}/gcp_audit_log.json" 2>/dev/null || \
    gcloud logging read \
        "timestamp>=\"${WINDOW_START}\" AND timestamp<=\"${WINDOW_END}\" AND logName:\"cloudaudit\"" \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_audit_log.json" 2>/dev/null || true
    log "Audit logs → ${ARTIFACT_DIR}/gcp_audit_log.json"

    log "Pulling Security Command Center findings..."
    gcloud scc findings list "projects/${project}" \
        --filter="state=ACTIVE AND eventTime>\"${WINDOW_START}\"" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_scc_findings.json" 2>/dev/null || true
    log "SCC findings → ${ARTIFACT_DIR}/gcp_scc_findings.json"

    log "Pulling VPC firewall rules..."
    gcloud compute firewall-rules list \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_firewall_rules.json" 2>/dev/null || true

    # VPC Flow Logs (Cloud Logging) for the window - network egress evidence / C2 confirmation.
    log "Pulling VPC flow logs..."
    gcloud logging read \
        "timestamp>=\"${WINDOW_START}\" AND timestamp<=\"${WINDOW_END}\" AND logName:\"vpc_flows\"" \
        --project="${project}" \
        --format=json \
        > "${ARTIFACT_DIR}/gcp_vpc_flow_logs.json" 2>/dev/null || true
    log "VPC flow logs → ${ARTIFACT_DIR}/gcp_vpc_flow_logs.json"

    # IAM identity posture - project IAM policy (public bindings) + user-managed SA-key
    # inventory (long-lived credential / persistence risk). Adjudicated by cloud_iam.py.
    log "Pulling project IAM policy..."
    gcloud projects get-iam-policy "${project}" --format=json \
        > "${ARTIFACT_DIR}/gcp_iam_policy.json" 2>/dev/null || true

    log "Inventorying service-account keys..."
    {
        echo '{"keys": ['
        _first=1
        for _sa in $(gcloud iam service-accounts list --project="${project}" \
                --format='value(email)' 2>/dev/null); do
            for _k in $(gcloud iam service-accounts keys list --iam-account="${_sa}" \
                    --project="${project}" --managed-by=user \
                    --format='value(name,validAfterTime)' 2>/dev/null | tr '\t' '|'); do
                _name="${_k%%|*}"; _after="${_k##*|}"
                [[ -z "${_name}" ]] && continue
                [[ ${_first} -eq 1 ]] && _first=0 || echo ','
                printf '{"serviceAccount":"%s","name":"%s","keyType":"USER_MANAGED","validAfterTime":"%s"}' \
                    "${_sa}" "${_name}" "${_after}"
            done
        done
        echo ']}'
    } > "${ARTIFACT_DIR}/gcp_sa_keys.json" 2>/dev/null || true

    [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]] && _gcp_snapshot_disks "${project}"

    log "GCP forensic collection complete"
    emit_json "forensics" "success"
}
