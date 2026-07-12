#!/usr/bin/env bash
# ==============================================================================
# Invoke-Eradication-Linux.sh - adjudication-driven eradication orchestrator.
#
# Closes the IR loop: reads the Adjudication_<stamp>.json produced by
# Invoke-IRCollection-Linux.sh, extracts indicators from the true-positive-class
# findings, and drives the eradication playbooks:
#
#   true-positive findings ─┬─ PIDs / process names / hashes ─→ 02_eradicate_process.sh
#                           ├─ persistence file paths        ─→ 03_eradicate_persistence.sh
#                           └─ C2 IPs / domains              ─→ 04_block_c2.sh
#
# DRY-RUN by default - prints the plan and the derived indicators, changes
# nothing. Pass --apply to execute. Writes Eradication_<stamp>.{json,md}.
#
# Usage:
#   ./Invoke-Eradication-Linux.sh --host-folder ./<hostname> \
#       [--min-verdict "Likely True Positive"] [--apply]
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PB_DIR="${SCRIPT_DIR}/playbooks/linux"
PY="$(command -v python3 || command -v python)"

HOST_FOLDER=""
MIN_VERDICT="Likely True Positive"
APPLY=0
ISOLATE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host-folder) HOST_FOLDER="$2"; shift 2 ;;
        --min-verdict) MIN_VERDICT="$2"; shift 2 ;;
        --isolate)     ISOLATE=1; shift ;;     # run 01_contain_host.sh (full network isolation) first
        --apply)       APPLY=1; shift ;;
        -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -z "$HOST_FOLDER" || ! -d "$HOST_FOLDER" ]] && { echo "ERROR: --host-folder <dir> required" >&2; exit 2; }

ADJ="$(ls -1t "${HOST_FOLDER}"/Adjudication_*.json 2>/dev/null | head -1)"
[[ -z "$ADJ" ]] && { echo "ERROR: no Adjudication_*.json in ${HOST_FOLDER}" >&2; exit 2; }
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
INCIDENT_ID="$(basename "$HOST_FOLDER")_${RUN_STAMP}"

# --- Extract indicators from the true-positive-class findings ------------------
# SECURITY: finding content (process names, paths, C2 hosts) is attacker-influenceable, so it is
# NEVER shell-eval'd. Python prints 7 newline-delimited values; bash `read`s them as literal
# strings - no eval. Each value is stripped of newlines/commas so it stays one safe data line.
{
    read -r PIDS; read -r PROCS; read -r HASHES
    read -r PATHS; read -r C2_IPS; read -r C2_DOMAINS; read -r TP_COUNT
} < <("$PY" - "$ADJ" "$MIN_VERDICT" <<'PYX'
import json, re, sys
adj, min_verdict = sys.argv[1], sys.argv[2]
RANK = {"False Positive":0,"Likely False Positive":1,"Indeterminate":2,
        "Likely True Positive":3,"True Positive":4}
floor = RANK.get(min_verdict, 3)
data = json.load(open(adj))
PERSIST = {"Cron Persistence","Systemd Persistence","Shell Init Backdoor",
           "Webshell","Library Preload Hijack"}
pids, procs, hashes, paths, ips, domains = set(), set(), set(), set(), set(), set()
for f in data:
    if RANK.get(f.get("Verdict",""),0) < floor:
        continue
    t = f.get("Type","")
    if f.get("Pid"):                pids.add(str(f["Pid"]))
    if f.get("SHA256"):             hashes.add(f["SHA256"])
    cmd = f.get("CommandLine") or ""
    m = re.search(r"comm=(\S+)", f.get("Details","") or "")
    if m:                           procs.add(m.group(1))
    elif cmd:                       procs.add(cmd.split()[0].split("/")[-1])
    if t in PERSIST and f.get("SubjectPath"):
        paths.add(f["SubjectPath"])
    if t == "Remote Access Tool":
        r = re.search(r"relay=([\w.\-]+)", f.get("Details","") or "")
        if r:
            host = r.group(1)
            (ips if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else domains).add(host)
    if t in ("External Connection", "External Connection (memory)"):
        m = re.match(r"(\d+\.\d+\.\d+\.\d+):", f.get("Target","") or "")
        if m:                       ips.add(m.group(1))
# Defang separators/newlines so each value is exactly one safe data line for `read`.
def q(items):
    out = [re.sub(r"[\r\n,]", " ", str(x)).strip() for x in items]
    return ",".join(sorted({x for x in out if x}))
tp = sum(1 for f in data if RANK.get(f.get("Verdict",""),0) >= floor)
for v in (q(pids), q(procs), q(hashes), q(paths), q(ips), q(domains), str(tp)):
    print(v)
PYX
)
# Defaults so `set -u` holds even if extraction printed fewer lines.
: "${PIDS:=}"; : "${PROCS:=}"; : "${HASHES:=}"; : "${PATHS:=}"
: "${C2_IPS:=}"; : "${C2_DOMAINS:=}"; : "${TP_COUNT:=0}"

echo "=================================================================="
echo " ERADICATION PLAN | incident=${INCIDENT_ID}"
echo " source: ${ADJ}"
echo " min-verdict: ${MIN_VERDICT}  →  ${TP_COUNT} actionable finding(s)"
echo " mode: $([[ $APPLY -eq 1 ]] && echo 'APPLY (changes WILL be made)' || echo 'DRY-RUN (no changes)')"
echo "------------------------------------------------------------------"
printf ' %-22s %s\n' "Process eradication:" "PIDs=[${PIDS}]  procs=[${PROCS}]  hashes=[$(echo "$HASHES" | cut -c1-40)...]"
printf ' %-22s %s\n' "Persistence removal:" "paths=[${PATHS}]"
printf ' %-22s %s\n' "C2 blocking:" "ips=[${C2_IPS}]  domains=[${C2_DOMAINS}]"
echo "=================================================================="

run_pb() {  # human-name, script, env assignments...
    local name="$1" script="$2"; shift 2
    if [[ $APPLY -eq 0 ]]; then
        echo "[DRY-RUN] would run ${name}: ${script}"
        return 0
    fi
    echo "[APPLY] ${name}"
    # IR_DRY_RUN=0 tells the module to actually execute; modules default to dry-run when invoked
    # directly (no orchestrator) so they are never destructive by accident.
    env "$@" IR_INCIDENT_ID="$INCIDENT_ID" IR_DRY_RUN=0 bash "${PB_DIR}/${script}"
}

RESULTS_JSON="["
sep=""
record() { RESULTS_JSON+="${sep}$1"; sep=","; }

# Scan a playbook's captured stdout from the end for the last line that parses as valid JSON
# -- that's the playbook's own summary print. Robust against trailing/interleaved non-JSON
# stdout (a stray echo, a warning printed to stdout instead of stderr) that a naive `tail -1`
# would otherwise hand straight to record(), silently corrupting playbook_results to []
# in the final report (2026-06-21 eradication review finding #9). "{}" if nothing parses,
# so RESULTS_JSON always stays valid JSON even when a playbook produced no JSON at all.
extract_json_line() {
    "$PY" -c '
import json, sys
for line in reversed(sys.stdin.read().splitlines()):
    line = line.strip()
    if not line:
        continue
    try:
        json.loads(line)
    except Exception:
        continue
    print(line)
    break
else:
    print("{}")
'
}

# ORDER: contain → cut C2 → eradicate. Block the attacker's channel BEFORE killing processes so a
# kill can't trip a dead-man's-switch and a re-spawn can't phone home mid-eradication.
if [[ $ISOLATE -eq 1 ]]; then
    out="$(run_pb "Network isolation" 01_contain_host.sh)"
    echo "$out"; [[ $APPLY -eq 1 ]] && record "$(echo "$out" | extract_json_line)"
fi
if [[ -n "$C2_IPS$C2_DOMAINS" ]]; then
    out="$(run_pb "C2 blocking" 04_block_c2.sh \
        IR_C2_IPS="$C2_IPS" IR_C2_DOMAINS="$C2_DOMAINS")"
    echo "$out"; [[ $APPLY -eq 1 ]] && record "$(echo "$out" | extract_json_line)"
fi
if [[ -n "$PIDS$PROCS$HASHES" ]]; then
    out="$(run_pb "Process eradication" 02_eradicate_process.sh \
        IR_MALICIOUS_PIDS="$PIDS" IR_MALICIOUS_PROCESSES="$PROCS" IR_MALICIOUS_HASHES="$HASHES")"
    echo "$out"; [[ $APPLY -eq 1 ]] && record "$(echo "$out" | extract_json_line)"
fi
if [[ -n "$PATHS$HASHES$PROCS" ]]; then
    out="$(run_pb "Persistence removal" 03_eradicate_persistence.sh \
        IR_MALICIOUS_PATHS="$PATHS" IR_MALICIOUS_HASHES="$HASHES" IR_MALICIOUS_PROCESSES="$PROCS")"
    echo "$out"; [[ $APPLY -eq 1 ]] && record "$(echo "$out" | extract_json_line)"
fi
# Credential / session revocation for implicated accounts (Principals.json).
PRINC="${HOST_FOLDER}/Principals.json"
if [[ -f "$PRINC" ]]; then
    echo "[*] Credential revocation from $(basename "$PRINC")"
    cred_args=(--principals "$PRINC" --journal "${HOST_FOLDER}/Eradication_cred_${RUN_STAMP}.jsonl")
    [[ $APPLY -eq 1 ]] && cred_args+=(--apply)
    IR_INCIDENT_ID="$INCIDENT_ID" bash "${PB_DIR}/07_revoke_credentials.sh" "${cred_args[@]}" || true
fi
RESULTS_JSON+="]"

# --- Report -------------------------------------------------------------------
REPORT_JSON="${HOST_FOLDER}/Eradication_${RUN_STAMP}.json"
REPORT_MD="${HOST_FOLDER}/Eradication_${RUN_STAMP}.md"
"$PY" - "$REPORT_JSON" "$INCIDENT_ID" "$ADJ" "$MIN_VERDICT" "$APPLY" "$TP_COUNT" \
    "$PIDS" "$PROCS" "$HASHES" "$PATHS" "$C2_IPS" "$C2_DOMAINS" "$RESULTS_JSON" <<'PYR'
import json, sys
(out, incident, adj, mv, apply, tp, pids, procs, hashes, paths, ips, doms, results) = sys.argv[1:14]
try: res = json.loads(results)
except Exception: res = []
rep = {"incident_id": incident, "source_adjudication": adj, "min_verdict": mv,
       "mode": "apply" if apply == "1" else "dry-run", "actionable_findings": int(tp),
       "indicators": {"pids": pids.split(",") if pids else [],
                      "processes": procs.split(",") if procs else [],
                      "hashes": hashes.split(",") if hashes else [],
                      "persistence_paths": paths.split(",") if paths else [],
                      "c2_ips": ips.split(",") if ips else [],
                      "c2_domains": doms.split(",") if doms else []},
       "playbook_results": res}
json.dump(rep, open(out, "w"), indent=2)
PYR

{
    echo "# Eradication report - ${INCIDENT_ID}"
    echo
    echo "| | |"; echo "|---|---|"
    echo "| Source | \`$(basename "$ADJ")\` |"
    echo "| Min verdict | ${MIN_VERDICT} |"
    echo "| Actionable findings | ${TP_COUNT} |"
    echo "| Mode | $([[ $APPLY -eq 1 ]] && echo 'APPLY' || echo 'DRY-RUN') |"
    echo
    echo "## Indicators acted on"
    echo "- **PIDs:** ${PIDS:-none}"
    echo "- **Processes:** ${PROCS:-none}"
    echo "- **Hashes:** ${HASHES:-none}"
    echo "- **Persistence paths:** ${PATHS:-none}"
    echo "- **C2 IPs:** ${C2_IPS:-none}"
    echo "- **C2 domains:** ${C2_DOMAINS:-none}"
    echo
    [[ $APPLY -eq 0 ]] && echo "> DRY-RUN - no changes made. Re-run with \`--apply\` to execute. Rollback journal enables \`06_restore.sh\` if a verdict is later overturned."
} > "$REPORT_MD"

echo
echo "Report: ${REPORT_MD}"
echo "        ${REPORT_JSON}"
[[ $APPLY -eq 0 ]] && echo "DRY-RUN complete - nothing changed. Add --apply to execute."
