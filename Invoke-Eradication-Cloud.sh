#!/usr/bin/env bash
# ==============================================================================
# Invoke-Eradication-Cloud.sh - cloud eradication + restoration orchestrator.
#
# Runs the cloud eradication playbooks against the provider, then (with --restore)
# releases containment. Reads C2 IOCs from the collection folder's IOCs.json so the
# known-bad endpoints are blocked before the workload is restored.
#
#   eradicate:  cloud/02_eradicate_process.sh, 03_eradicate_persistence.sh, 04_block_c2.sh
#   restore:    cloud/05_restore_host.sh                                   (only with --restore)
#
# DRY-RUN by default: prints the plan and changes nothing until you pass --apply.
#
# Usage:
#   ./Invoke-Eradication-Cloud.sh --provider aws --target <ip|id> \
#       [--host-folder DIR] [--c2-ips a,b] [--apply] [--restore]
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="${SCRIPT_DIR}/playbooks/cloud"

PROVIDER="aws"; TARGET=""; INCIDENT_ID=""; HOST_FOLDER=""; C2_IPS=""
C2_DOMAINS=""; REGION="us-east-1"; APPLY=0; RESTORE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)    PROVIDER="$2"; shift 2 ;;
        --target)      TARGET="$2"; shift 2 ;;
        --incident-id) INCIDENT_ID="$2"; shift 2 ;;
        --host-folder) HOST_FOLDER="$2"; shift 2 ;;
        --c2-ips)      C2_IPS="$2"; shift 2 ;;
        --c2-domains)  C2_DOMAINS="$2"; shift 2 ;;
        --region)      REGION="$2"; shift 2 ;;
        --apply)       APPLY=1; shift ;;
        --restore)     RESTORE=1; shift ;;
        -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$TARGET" ]] && { echo "ERROR: --target required" >&2; exit 2; }
[[ -z "$INCIDENT_ID" ]] && INCIDENT_ID="${PROVIDER}-${TARGET//[^A-Za-z0-9]/_}"
PY="$(command -v python3 || command -v python)"

# Pull known-bad C2 from the collection folder's IOCs.json when not given explicitly.
if [[ -z "$C2_IPS" && -n "$HOST_FOLDER" && -f "${HOST_FOLDER}/IOCs.json" ]]; then
    C2_IPS="$("$PY" - "${HOST_FOLDER}/IOCs.json" <<'PYIOC'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8-sig"))
print(",".join(e["host"] for e in d.get("c2_endpoints", []) if not e.get("sanctioned")))
PYIOC
)"
fi

# Implicated IAM principals (from Principals.json) -> revoked by 03_eradicate_persistence.sh.
PRINCIPALS=""
if [[ -n "$HOST_FOLDER" && -f "${HOST_FOLDER}/Principals.json" ]]; then
    PRINCIPALS="$("$PY" - "${HOST_FOLDER}/Principals.json" <<'PYPR'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8-sig"))
print(",".join(p["name"] for p in d.get("principals", [])
                if p.get("auto_revoke") and p.get("type") in ("iam", "cloud-identity")))
PYPR
)"
fi

export IR_INCIDENT_ID="$INCIDENT_ID" IR_CLOUD_PROVIDER="$PROVIDER" IR_TARGET="$TARGET"
export IR_C2_IPS="$C2_IPS" IR_C2_DOMAINS="$C2_DOMAINS" IR_AWS_REGION="$REGION"
export IR_MALICIOUS_PROCESSES="$PRINCIPALS"      # IAM users/SAs/app-ids for 03 to revoke

mode=$([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)
echo "=== Cloud eradication ($mode) | ${PROVIDER} | ${TARGET} | known-bad C2: ${C2_IPS:-none} | IAM revoke: ${PRINCIPALS:-none} ==="

run_pb() {  # phase, script
    local script="${CLOUD_DIR}/$2"
    [[ ! -f "$script" ]] && { echo "[skip] $2 not found"; return 0; }
    if [[ $APPLY -eq 0 ]]; then echo "[plan] would run $2"; return 0; fi
    # IR_DRY_RUN=0 tells the module to execute; modules default to dry-run when invoked directly,
    # so a stray direct run never mutates the cloud account.
    echo "[run] $2"; IR_DRY_RUN=0 bash "$script" || echo "[warn] $2 returned non-zero"
}

# -- Contain identity first (the credential is what re-creates everything else) --
# Implicated principals come from IR_MALICIOUS_PROCESSES (sourced from Principals.json);
# 01_contain_identity disables them + revokes live sessions, journaled for rollback.
run_pb "identity_containment" "01_contain_identity.sh"

# -- Eradicate -----------------------------------------------------------------
run_pb "process_eradication" "02_eradicate_process.sh"
run_pb "persistence_removal" "03_eradicate_persistence.sh"
run_pb "c2_blocking"         "04_block_c2.sh"

# -- Restore (known-bad stays blocked by 04 above) -----------------------------
if [[ $RESTORE -eq 1 ]]; then
    echo "--- Restoration: releasing containment (C2 remains blocked from 04) ---"
    run_pb "restore" "05_restore_host.sh"
else
    echo "[i] Restoration skipped (pass --restore to release containment)."
fi

[[ $APPLY -eq 0 ]] && echo "[i] DRY-RUN: nothing changed. Re-run with --apply to execute."
exit 0
