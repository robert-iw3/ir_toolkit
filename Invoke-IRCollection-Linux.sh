#!/usr/bin/env bash
# ==============================================================================
# Invoke-IRCollection-Linux.sh — offline IR collection orchestrator (Linux).
#
# Single-command, read-only collection + enrichment. Runs every phase off one
# invocation and drops ALL artifacts into a folder named after the hostname,
# created in the project root (next to this script). Nothing is written to the
# system outside that folder; no network calls.
#
#   Phase 1  Forensics snapshot ..... process/network/persistence state -> forensics/
#   Phase 2  Fileless/evasion hunt .. threat_hunting/edr_hunt.py -> EDR_Report_*.json
#   Phase 2b Remote-access triage ... threat_hunting/remote_access_triage.py
#   -        Merge findings ......... EDR + remote-access -> Combined_Findings_*.json
#   Phase 3  Adjudication ........... threat_hunting/adjudicate.py (verdicts +
#                                     Evidence/ bundles for true-positive class)
#   -        Manifest ............... SHA256 of every artifact -> _manifest_*.json
#
# Usage:
#   ./Invoke-IRCollection-Linux.sh [--output-root DIR] [--incident-id ID]
#                                  [--skip-forensics] [--skip-hunt] [--deep]
# Run as root for full visibility (shadow, all /proc, every cron); degrades
# gracefully as a normal user.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HUNT_DIR="${SCRIPT_DIR}/playbooks/linux/threat_hunting"
FORENSICS_SCRIPT="${SCRIPT_DIR}/playbooks/linux/00_collect_forensics.sh"

OUTPUT_ROOT="${SCRIPT_DIR}"      # artifact collection lives in the project root
INCIDENT_ID=""
SKIP_FORENSICS=0
SKIP_HUNT=0
SKIP_REPORTS=0
DEEP=0
CAPTURE_MEMORY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)   OUTPUT_ROOT="$2"; shift 2 ;;
        --incident-id)   INCIDENT_ID="$2"; shift 2 ;;
        --skip-forensics) SKIP_FORENSICS=1; shift ;;
        --skip-hunt)     SKIP_HUNT=1; shift ;;
        --skip-reports)  SKIP_REPORTS=1; shift ;;
        --capture-memory) CAPTURE_MEMORY=1; shift ;;   # needs STAGED tools/avml
        --deep)          DEEP=1; shift ;;
        -h|--help)       grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_S="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
[[ -z "$INCIDENT_ID" ]] && INCIDENT_ID="${HOSTNAME_S}_${RUN_STAMP}"
OUT_DIR="${OUTPUT_ROOT}/${HOSTNAME_S}"
mkdir -p "${OUT_DIR}/forensics"
RUN_LOG="${OUT_DIR}/_runtime_${RUN_STAMP}.log"
PY="$(command -v python3 || command -v python)"

log() { local m="[$(date '+%Y-%m-%d %H:%M:%S')] $*"; echo "$m"; echo "$m" >> "$RUN_LOG"; }

# shellcheck source=playbooks/lib/status.sh
source "${SCRIPT_DIR}/playbooks/lib/status.sh"

run_phase() {  # name, description, command...
    local name="$1"; shift
    log "==== PHASE: ${name} ===="
    local plog="${OUT_DIR}/_${name}_${RUN_STAMP}.log"
    if "$@" >>"$plog" 2>&1; then
        log "  ${name} complete (log: $(basename "$plog"))."
        ir_record "$name" success
    else
        log "  ${name} returned non-zero (continuing; see $(basename "$plog"))."
        ir_record "$name" failed
    fi
}

log "==================================================="
log " IR COLLECTION | host=${HOSTNAME_S} | incident=${INCIDENT_ID}"
log " output -> ${OUT_DIR}"
[[ "$(id -u)" -ne 0 ]] && log " NOTE: not root — some artifacts will be limited."
log "==================================================="

# --- Phase 1: forensics snapshot (read-only system state) ---------------------
if [[ $SKIP_FORENSICS -eq 0 ]]; then
    log "==== PHASE: Forensics ===="
    F="${OUT_DIR}/forensics"
    { ps auxf; echo; ps -eo pid,ppid,user,stat,comm,args; } > "${F}/processes.txt" 2>/dev/null || true
    { ss -tulpanm 2>/dev/null || netstat -tulpan 2>/dev/null; } > "${F}/sockets.txt" || true
    ss -tpnH state established > "${F}/connections_established.txt" 2>/dev/null || true
    { ip addr; echo; ip route; echo; ip neigh; } > "${F}/network.txt" 2>/dev/null || true
    lsmod > "${F}/kernel_modules.txt" 2>/dev/null || true
    { mount; echo; cat /proc/mounts; } > "${F}/mounts.txt" 2>/dev/null || true
    systemctl list-units --all --no-pager > "${F}/systemd_units.txt" 2>/dev/null || true
    systemctl list-unit-files --no-pager > "${F}/systemd_unit_files.txt" 2>/dev/null || true
    cp -a /etc/passwd /etc/group "${F}/" 2>/dev/null || true
    [[ "$(id -u)" -eq 0 ]] && cp -a /etc/shadow "${F}/" 2>/dev/null || true
    { crontab -l 2>/dev/null; for u in /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [[ -f "$u" ]] && { echo "=== $u ==="; cat "$u"; }; done; } > "${F}/crontabs.txt" 2>/dev/null || true
    ls -la /etc/cron.* /etc/crontab 2>/dev/null > "${F}/cron_system.txt" || true
    cat /etc/ld.so.preload > "${F}/ld_so_preload.txt" 2>/dev/null || true
    last -50 > "${F}/logins.txt" 2>/dev/null || true
    log "  Forensics snapshot -> forensics/"
    ir_record "Forensics" success

    # Optional volatile-memory capture via STAGED tools/avml (Build-OfflineToolkit-Linux.sh).
    if [[ $CAPTURE_MEMORY -eq 1 ]]; then
        AVML="${SCRIPT_DIR}/tools/avml"
        if [[ -x "$AVML" ]]; then
            log "==== PHASE: Memory (staged avml) ===="
            if "$AVML" "${OUT_DIR}/memory_${HOSTNAME_S}.raw" >>"$RUN_LOG" 2>&1; then
                log "  Memory image -> memory_${HOSTNAME_S}.raw"; ir_record "Memory" success
            else
                log "  avml capture returned non-zero."; ir_record "Memory" failed
            fi
        else
            log "  --capture-memory set but tools/avml not staged (run Build-OfflineToolkit-Linux.sh --include-memory)."
        fi
    fi

    # Optional exhaustive collector (root recommended; writes its own archive).
    if [[ $DEEP -eq 1 && -f "$FORENSICS_SCRIPT" ]]; then
        run_phase "Forensics_Deep" env IR_INCIDENT_ID="$INCIDENT_ID" bash "$FORENSICS_SCRIPT"
        find /var/ir -name "ir-forensics-${INCIDENT_ID}.tar.gz" -exec cp {} "${OUT_DIR}/" \; 2>/dev/null || true
    fi
else
    log "Skipping forensics (--skip-forensics)."
fi

# --- Phase 2: hunt + triage + merge + adjudication ----------------------------
if [[ $SKIP_HUNT -eq 0 ]]; then
    run_phase "EDR_Hunt" "$PY" "${HUNT_DIR}/edr_hunt.py" --report-dir "$OUT_DIR" --stamp "$RUN_STAMP" --quiet
    run_phase "RemoteAccess" "$PY" "${HUNT_DIR}/remote_access_triage.py" --report-dir "$OUT_DIR" --stamp "$RUN_STAMP" --quiet

    EDR_JSON="${OUT_DIR}/EDR_Report_${RUN_STAMP}.json"
    RA_JSON="${OUT_DIR}/RemoteAccess_Findings_${RUN_STAMP}.json"
    COMBINED="${OUT_DIR}/Combined_Findings_${RUN_STAMP}.json"

    "$PY" - "$EDR_JSON" "$RA_JSON" "$COMBINED" <<'PYMERGE' >>"$RUN_LOG" 2>&1 || true
import json, sys
merged = []
for p in sys.argv[1:-1]:
    try:
        with open(p) as fh:
            data = json.load(fh)
        merged += data if isinstance(data, list) else [data]
    except Exception:
        pass
with open(sys.argv[-1], "w") as fh:
    json.dump(merged, fh, indent=2)
print(f"merged {len(merged)} finding(s)")
PYMERGE
    log "  Merged findings -> $(basename "$COMBINED")"

    if [[ -s "$COMBINED" ]] && [[ "$("$PY" -c "import json;print(len(json.load(open('$COMBINED'))))" 2>/dev/null || echo 0)" != "0" ]]; then
        run_phase "Adjudication" "$PY" "${HUNT_DIR}/adjudicate.py" \
            --host-folder "$OUT_DIR" --report "$COMBINED" --stamp "$RUN_STAMP"
    else
        log "No findings — skipping adjudication."
    fi

    # --- Analysis-stage IOC + principal bundles (independent of reporting) ----
    BUILD_IOCS="${SCRIPT_DIR}/playbooks/reporting/build_iocs.py"
    EXTRACT_PRINC="${SCRIPT_DIR}/playbooks/reporting/extract_principals.py"
    if [[ -f "$BUILD_IOCS" ]]; then
        run_phase "IOCs" "$PY" "$BUILD_IOCS" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID" --quiet
    fi
    if [[ -f "$EXTRACT_PRINC" ]]; then
        run_phase "Principals" "$PY" "$EXTRACT_PRINC" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID" --quiet
    fi

    # --- Automated reporting: Incident_Report.md, Attack_Graph.md, IOCs.json ---
    REPORT_PY="${SCRIPT_DIR}/playbooks/reporting/generate_reports.py"
    if [[ $SKIP_REPORTS -eq 0 && -f "$REPORT_PY" ]]; then
        run_phase "Reporting" "$PY" "$REPORT_PY" --host-folder "$OUT_DIR" --incident-id "$INCIDENT_ID"
        log "  Reports -> Incident_Report.md, Attack_Graph.md, IOCs.json"
    else
        [[ $SKIP_REPORTS -eq 1 ]] && log "Skipping automated reports (--skip-reports)."
    fi
else
    log "Skipping hunt + triage + adjudication (--skip-hunt)."
fi

# --- Manifest: SHA256 of every collected artifact -----------------------------
"$PY" - "$OUT_DIR" "$RUN_LOG" "$INCIDENT_ID" "$HOSTNAME_S" "$RUN_STAMP" <<'PYMAN' >>"$RUN_LOG" 2>&1 || true
import json, os, hashlib, sys, datetime
out_dir, run_log, incident, host, stamp = sys.argv[1:6]
def sha(p):
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for c in iter(lambda: fh.read(1 << 20), b""): h.update(c)
        return h.hexdigest()
    except Exception:
        return None
arts = []
for root, _, files in os.walk(out_dir):
    for f in files:
        fp = os.path.join(root, f)
        if fp == run_log: continue
        arts.append({"path": os.path.relpath(fp, out_dir),
                     "size_bytes": os.path.getsize(fp) if os.path.exists(fp) else 0,
                     "sha256": sha(fp)})
man = {"incident_id": incident, "hostname": host,
       "collected_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "output_dir": out_dir, "artifact_count": len(arts), "artifacts": arts}
with open(os.path.join(out_dir, f"_manifest_{stamp}.json"), "w") as fh:
    json.dump(man, fh, indent=2)
print(f"manifest: {len(arts)} artifact(s)")
PYMAN

# --- Status contract: uniform _status.json for SOAR gating --------------------
TP_COUNT=0
ADJ="$(ls -1t "${OUT_DIR}"/Adjudication_*.json 2>/dev/null | head -1)"
if [[ -n "$ADJ" ]]; then
    TP_COUNT="$("$PY" -c "import json,sys;d=json.load(open(sys.argv[1],encoding='utf-8-sig'));print(sum(1 for f in d if f.get('Verdict') in ('True Positive','Likely True Positive')))" "$ADJ" 2>/dev/null || echo 0)"
fi
OVERALL="$(ir_status_write "${OUT_DIR}/_status.json" "$INCIDENT_ID" "$HOSTNAME_S" "linux" "$TP_COUNT")"

ART_COUNT="$(find "$OUT_DIR" -type f | wc -l)"
log "==================================================="
log " COLLECTION ${OVERALL} — ${ART_COUNT} artifact(s), ${TP_COUNT} true-positive-class"
log " ${OUT_DIR}"
log "==================================================="
