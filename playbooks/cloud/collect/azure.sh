# shellcheck shell=bash
# ==============================================================================
# collect/azure.sh - Azure / Entra forensic collection + logging pre-flight.
# Sourced by 00_collect_forensics.sh; relies on helpers from collect/lib.sh.
# ==============================================================================

preflight_azure() {
    local v
    v=$(az monitor diagnostic-settings subscription list 2>/dev/null)
    [[ -n "${v}" && "${v}" != "[]" && "${v}" != "{}" ]] && record_log_source "DiagnosticSettings" true "configured" \
        || record_log_source "DiagnosticSettings" false "no subscription diagnostic settings"
    v=$(az monitor activity-log list --max-events 1 --output json 2>/dev/null)
    [[ -n "${v}" && "${v}" != "[]" ]] && record_log_source "ActivityLog" true "available" \
        || record_log_source "ActivityLog" false "activity log returned no events"
}

# Entra/M365 identity artifacts via Microsoft Graph (risky users, sign-ins, OAuth grants,
# directory audit, inbox rules). Inbox-rule collection is best-effort across the first page
# of users; a full-tenant sweep is an analyst follow-up.
_azure_collect_identity() {
    log "Pulling recent Entra ID sign-in risk events..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?\$top=20" \
        --output json \
        > "${ARTIFACT_DIR}/azure_risky_users.json" 2>/dev/null || true

    log "Pulling Entra sign-in logs..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$top=200" \
        --output json \
        > "${ARTIFACT_DIR}/azure_signin_logs.json" 2>/dev/null || true

    log "Pulling OAuth consent grants..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$top=100" \
        --output json \
        > "${ARTIFACT_DIR}/azure_oauth_grants.json" 2>/dev/null || true

    log "Pulling Entra directory audit log..."
    az rest --method get \
        --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$top=200" \
        --output json \
        > "${ARTIFACT_DIR}/azure_directory_audit.json" 2>/dev/null || true

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
}

# Azure managed-disk snapshots before eradication (opt-in).
_azure_snapshot_disks() {  # resource_group
    local rg="$1"
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
}

collect_azure() {
    local subscription="${IR_AZURE_SUBSCRIPTION:-}"
    local rg="${IR_AZURE_RESOURCE_GROUP:-}"
    log "Azure subscription=${subscription} resource_group=${rg} target=${TARGET}"
    [[ -z "${subscription}" ]] && { log "WARN: IR_AZURE_SUBSCRIPTION not set"; }

    log "Pulling Azure Activity Log..."
    az monitor activity-log list \
        --subscription "${subscription}" \
        --start-time "${WINDOW_START}" \
        --end-time   "${WINDOW_END}" \
        --output json \
        > "${ARTIFACT_DIR}/azure_activity_log.json" 2>/dev/null || true
    log "Activity log → ${ARTIFACT_DIR}/azure_activity_log.json"

    if [[ -n "${rg}" ]]; then
        log "Pulling NSG rules for RG ${rg}..."
        az network nsg list \
            --resource-group "${rg}" \
            --output json \
            > "${ARTIFACT_DIR}/azure_nsg_rules.json" 2>/dev/null || true
        log "NSG rules → ${ARTIFACT_DIR}/azure_nsg_rules.json"
    fi

    # NSG flow-log configuration (the flow records themselves live in a storage account /
    # Log Analytics - collecting the config points the analyst at where the egress data is).
    log "Pulling NSG flow-log configuration..."
    az network watcher flow-log list --location "${IR_AZURE_LOCATION:-eastus}" --output json \
        > "${ARTIFACT_DIR}/azure_flow_logs.json" 2>/dev/null || true

    _azure_collect_identity

    [[ "${IR_SNAPSHOT_DISKS:-0}" == "1" && -n "${TARGET}" ]] && _azure_snapshot_disks "${rg}"

    log "Azure forensic collection complete"
    emit_json "forensics" "success"
}
