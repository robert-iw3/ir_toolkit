#!/usr/bin/env bash
# ==============================================================================
# Invoke-IRCollection-Cloud.sh - cloud IR collection orchestrator.
#
# Runs the cloud forensics (and optionally containment) playbooks against a cloud
# provider, copies the telemetry into a per-incident folder in the project root
# (like the Linux/Windows orchestrators), synthesises findings from the supplied
# C2 IOCs, and generates the Incident_Report / Attack_Graph / Retrospective / IOCs.
#
#   Phase 0  Containment ....... cloud/01_contain_host.sh   (only with --contain)
#   Phase 1  Forensics ......... cloud/00_collect_forensics.sh -> cloud_forensics/
#   -        Findings .......... C2 IOCs -> Combined_Findings_*.json
#   Phase 5  Reporting ......... reporting/generate_reports.py
#   -        Manifest .......... SHA256 of every artifact -> _manifest_*.json
#
# Usage:
#   ./Invoke-IRCollection-Cloud.sh --provider aws|azure|gcp --target <ip|id> \
#       [--incident-id ID] [--c2-ips a,b] [--c2-domains x,y] [--mgmt-ips CIDR] \
#       [--region R] [--contain] [--skip-reports] [--output-root DIR]
# Provider auth (aws/az/gcloud CLI) must already be configured in the environment.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="${SCRIPT_DIR}/playbooks/cloud"
REPORT_PY="${SCRIPT_DIR}/playbooks/reporting/generate_reports.py"

PROVIDER="aws"; TARGET=""; INCIDENT_ID=""; C2_IPS=""; C2_DOMAINS=""
MGMT_IPS="10.0.0.0/8"; REGION="us-east-1"; CONTAIN=0; SKIP_REPORTS=0
OUTPUT_ROOT="${SCRIPT_DIR}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)     PROVIDER="$2"; shift 2 ;;
        --target)       TARGET="$2"; shift 2 ;;
        --incident-id)  INCIDENT_ID="$2"; shift 2 ;;
        --c2-ips)       C2_IPS="$2"; shift 2 ;;
        --c2-domains)   C2_DOMAINS="$2"; shift 2 ;;
        --mgmt-ips)     MGMT_IPS="$2"; shift 2 ;;
        --region)       REGION="$2"; shift 2 ;;
        --contain)      CONTAIN=1; shift ;;
        --skip-reports) SKIP_REPORTS=1; shift ;;
        --output-root)  OUTPUT_ROOT="$2"; shift 2 ;;
        -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$TARGET" ]] && { echo "ERROR: --target required" >&2; exit 2; }
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$INCIDENT_ID" ]] && INCIDENT_ID="${PROVIDER}-${TARGET//[^A-Za-z0-9]/_}_${RUN_STAMP}"
HOST_LABEL="${PROVIDER}-${TARGET//[^A-Za-z0-9]/_}"
OUT_DIR="${OUTPUT_ROOT}/${HOST_LABEL}"
mkdir -p "${OUT_DIR}/cloud_forensics"
RUN_LOG="${OUT_DIR}/_runtime_${RUN_STAMP}.log"
PY="$(command -v python3 || command -v python)"

log() { local m="[$(date '+%Y-%m-%d %H:%M:%S')] $*"; echo "$m"; echo "$m" >> "$RUN_LOG"; }

# shellcheck source=playbooks/lib/status.sh
source "${SCRIPT_DIR}/playbooks/lib/status.sh"

# All IR_* vars the cloud playbooks read.
export IR_INCIDENT_ID="$INCIDENT_ID" IR_CLOUD_PROVIDER="$PROVIDER" IR_TARGET="$TARGET"
export IR_C2_IPS="$C2_IPS" IR_C2_DOMAINS="$C2_DOMAINS" IR_MGMT_IPS="$MGMT_IPS"
export IR_AWS_REGION="$REGION" IR_AZURE_SUBSCRIPTION="${IR_AZURE_SUBSCRIPTION:-}"
export IR_AZURE_RESOURCE_GROUP="${IR_AZURE_RESOURCE_GROUP:-}" IR_GCP_PROJECT="${IR_GCP_PROJECT:-}"

run_phase() {  # name, command...
    local name="$1"; shift
    log "==== PHASE: ${name} ===="
    local plog="${OUT_DIR}/_${name}_${RUN_STAMP}.log"
    if "$@" >>"$plog" 2>&1; then log "  ${name} complete (log: $(basename "$plog"))."; ir_record "$name" success
    else log "  ${name} returned non-zero (continuing; see $(basename "$plog"))."; ir_record "$name" failed; fi
}

log "==================================================="
log " CLOUD IR COLLECTION | provider=${PROVIDER} | target=${TARGET}"
log " incident=${INCIDENT_ID} | output -> ${OUT_DIR}"
log "==================================================="

# --- Phase 0: containment (optional; mutates cloud infra) ---------------------
if [[ $CONTAIN -eq 1 ]]; then
    run_phase "Containment" bash "${CLOUD_DIR}/01_contain_host.sh"
else
    log "Containment skipped (pass --contain to isolate the workload)."
fi

# --- Phase 1: cloud forensics -------------------------------------------------
run_phase "Forensics" bash "${CLOUD_DIR}/00_collect_forensics.sh"
# Cloud playbooks write to /tmp/ir/<incident>; copy into the project folder.
if [[ -d "/tmp/ir/${INCIDENT_ID}" ]]; then
    cp -a "/tmp/ir/${INCIDENT_ID}/." "${OUT_DIR}/cloud_forensics/" 2>/dev/null || true
    log "  Cloud forensics -> cloud_forensics/"
fi

# --- Analysis: normalize provider telemetry + operator IOCs, adjudicate -------
COMBINED="${OUT_DIR}/Combined_Findings_${RUN_STAMP}.json"
ADJ_CLOUD="${CLOUD_DIR}/adjudicate_cloud.py"
run_phase "Adjudication" "$PY" "$ADJ_CLOUD" --forensics-dir "${OUT_DIR}/cloud_forensics" \
    --out "$COMBINED" --provider "$PROVIDER" --c2-ips "$C2_IPS" --c2-domains "$C2_DOMAINS"
# Cloud findings already carry verdicts; expose them as the adjudication artifact too.
cp -f "$COMBINED" "${OUT_DIR}/Adjudication_${RUN_STAMP}.json" 2>/dev/null || true
log "  Findings -> $(basename "$COMBINED")"

# --- Analysis-stage IOC + principal bundles (independent of reporting) --------
BUILD_IOCS="${SCRIPT_DIR}/playbooks/reporting/build_iocs.py"
EXTRACT_PRINC="${SCRIPT_DIR}/playbooks/reporting/extract_principals.py"
[[ -f "$BUILD_IOCS" ]] && run_phase "IOCs" "$PY" "$BUILD_IOCS" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID" --quiet
[[ -f "$EXTRACT_PRINC" ]] && run_phase "Principals" "$PY" "$EXTRACT_PRINC" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID" --quiet

# --- Phase 5: automated reporting --------------------------------------------
if [[ $SKIP_REPORTS -eq 0 && -f "$REPORT_PY" ]]; then
    run_phase "Reporting" "$PY" "$REPORT_PY" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID"
    log "  Reports -> Incident_Report.md, Attack_Graph.md, Retrospective.md, IOCs.json"
fi

# --- Manifest -----------------------------------------------------------------
"$PY" - "$OUT_DIR" "$RUN_LOG" "$INCIDENT_ID" "$HOST_LABEL" "$RUN_STAMP" <<'PYMAN' >>"$RUN_LOG" 2>&1 || true
import json, os, hashlib, sys, datetime
out_dir, run_log, incident, host, stamp = sys.argv[1:6]
def sha(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
        return h.hexdigest()
    except Exception: return None
arts = []
for root, _, files in os.walk(out_dir):
    for f in files:
        fp = os.path.join(root, f)
        if fp == run_log: continue
        arts.append({"path": os.path.relpath(fp, out_dir),
                     "size_bytes": os.path.getsize(fp) if os.path.exists(fp) else 0, "sha256": sha(fp)})
man = {"incident_id": incident, "hostname": host, "provider": os.environ.get("IR_CLOUD_PROVIDER"),
       "collected_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "output_dir": out_dir, "artifact_count": len(arts), "artifacts": arts}
with open(os.path.join(out_dir, f"_manifest_{stamp}.json"), "w") as fh:
    json.dump(man, fh, indent=2)
print(f"manifest: {len(arts)} artifact(s)")
PYMAN

# --- Status contract ----------------------------------------------------------
TP_COUNT=0
if [[ -f "$COMBINED" ]]; then
    TP_COUNT="$("$PY" -c "import json,sys;d=json.load(open(sys.argv[1],encoding='utf-8-sig'));print(sum(1 for f in d if f.get('Verdict') in ('True Positive','Likely True Positive')))" "$COMBINED" 2>/dev/null || echo 0)"
fi
OVERALL="$(ir_status_write "${OUT_DIR}/_status.json" "$INCIDENT_ID" "$HOST_LABEL" "cloud" "$TP_COUNT")"

ART_COUNT="$(find "$OUT_DIR" -type f | wc -l)"
log "==================================================="
log " CLOUD COLLECTION ${OVERALL} - ${ART_COUNT} artifact(s), ${TP_COUNT} true-positive-class"
log " ${OUT_DIR}"
log "==================================================="
