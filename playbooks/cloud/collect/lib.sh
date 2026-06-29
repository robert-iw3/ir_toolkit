# shellcheck shell=bash
# ==============================================================================
# collect/lib.sh - shared setup + helpers for the cloud forensic collectors.
# Sourced by 00_collect_forensics.sh before a per-provider module; defines the
# artifact dir, logging, the logging-status recorder, and the incident window.
# ==============================================================================
INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
PROVIDER="${IR_CLOUD_PROVIDER:-aws}"
TARGET="${IR_TARGET:-}"
C2_IPS="${IR_C2_IPS:-}"
ARTIFACT_DIR="/tmp/ir/${INCIDENT_ID}"
mkdir -p "${ARTIFACT_DIR}"

PY="$(command -v python3 || command -v python)"

log() { echo "[$(date -u +%H:%M:%SZ)] [forensics/${PROVIDER}] $*" | tee -a "${ARTIFACT_DIR}/forensics.log"; }
emit_json() { local phase="$1"; local status="$2"; echo "{\"phase\":\"${phase}\",\"status\":\"${status}\",\"incident\":\"${INCIDENT_ID}\",\"provider\":\"${PROVIDER}\"}"; }

# Record one logging source's enablement into logging_status.json. The adjudicator turns
# any source reported disabled into a visibility-gap finding - the first question in cloud
# IR is "do we even have the logs", and a source switched off can itself be the attack.
LOGGING_STATUS="${ARTIFACT_DIR}/logging_status.json"
record_log_source() {  # name  enabled(true|false)  detail
    "${PY:-python3}" - "$LOGGING_STATUS" "$PROVIDER" "$1" "$2" "${3:-}" <<'PYLS' 2>/dev/null || true
import json, os, sys
path, provider, name, enabled, detail = sys.argv[1:6]
doc = {"provider": provider, "sources": []}
if os.path.exists(path):
    try: doc = json.load(open(path))
    except Exception: pass
doc.setdefault("sources", [])
doc["sources"] = [s for s in doc["sources"] if s.get("name") != name]
doc["sources"].append({"name": name, "enabled": enabled.lower() == "true", "detail": detail})
json.dump(doc, open(path, "w"), indent=2)
PYLS
}

# Merge a JSONL file of paged API responses into {"<key>":[...]} at <out>.
# Used to stitch CloudTrail / GuardDuty pages (possibly across regions) into one document.
merge_pages() {  # pages_file  out_file  array_key
    "${PY:-python3}" -c 'import json,sys
key=sys.argv[3]; items=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    try: items.extend((json.loads(line) or {}).get(key, []))
    except Exception: pass
json.dump({key: items}, open(sys.argv[2], "w"))' "$1" "$2" "$3" 2>/dev/null
}

# -- Incident window ------------------------------------------------------------
# Explicit IR_WINDOW_START/END win; otherwise look back IR_LOOKBACK_HOURS (default 2h
# for a direct run, 168h when driven by the collector). Real incidents surface days
# late, so the window must be configurable rather than a fixed couple of hours.
LOOKBACK_HOURS="${IR_LOOKBACK_HOURS:-2}"
if [[ -n "${IR_WINDOW_START:-}" ]]; then
    WINDOW_START="${IR_WINDOW_START}"
else
    WINDOW_START=$(date -u -d "${LOOKBACK_HOURS} hours ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
                   date -u -v-"${LOOKBACK_HOURS}"H '+%Y-%m-%dT%H:%M:%SZ')   # macOS fallback
fi
WINDOW_END="${IR_WINDOW_END:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

log "Collecting cloud forensics for incident ${INCIDENT_ID} window ${WINDOW_START} → ${WINDOW_END}"
