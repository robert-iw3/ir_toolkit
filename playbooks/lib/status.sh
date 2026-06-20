#!/usr/bin/env bash
# Shared phase-status contract for the IR orchestrators.
#
# Every orchestrator records each phase outcome and writes a _status.json with a
# uniform shape so a SOAR can gate on one field regardless of platform:
#   {incident_id, hostname, platform, status, phases:{name:outcome}, tp_count}
# status: COMPLETED (no phase failed) | PARTIAL (some failed) | FAILED (all failed).

IR_PHASE_NAMES=()
IR_PHASE_STATUS=()

ir_record() {  # name, outcome(success|failed|skipped)
    IR_PHASE_NAMES+=("$1")
    IR_PHASE_STATUS+=("$2")
}

ir_overall_status() {
    local total=${#IR_PHASE_STATUS[@]} ok=0 failed=0 s
    for s in "${IR_PHASE_STATUS[@]:-}"; do
        [[ "$s" == "success" ]] && ok=$((ok+1))
        [[ "$s" == "failed"  ]] && failed=$((failed+1))
    done
    if [[ $failed -eq 0 ]]; then echo "COMPLETED"
    elif [[ $ok -gt 0 ]];   then echo "PARTIAL"
    else echo "FAILED"; fi
}

ir_status_write() {  # file, incident, host, platform, tp_count
    local file="$1" incident="$2" host="$3" platform="$4" tp="${5:-0}"
    local overall; overall="$(ir_overall_status)"
    {
        printf '{\n'
        printf '  "incident_id": "%s",\n' "$incident"
        printf '  "hostname": "%s",\n' "$host"
        printf '  "platform": "%s",\n' "$platform"
        printf '  "status": "%s",\n' "$overall"
        printf '  "tp_count": %s,\n' "$tp"
        printf '  "phases": {'
        local i first=1
        for i in "${!IR_PHASE_NAMES[@]}"; do
            [[ $first -eq 0 ]] && printf ','
            printf '\n    "%s": "%s"' "${IR_PHASE_NAMES[$i]}" "${IR_PHASE_STATUS[$i]}"
            first=0
        done
        printf '\n  }\n}\n'
    } > "$file"
    echo "$overall"
}
