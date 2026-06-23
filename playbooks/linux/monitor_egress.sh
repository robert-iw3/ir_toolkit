#!/usr/bin/env bash
# ==============================================================================
# IR Playbook — Linux Egress Observation Sensor + Deferred Outbound Blackhole
#
# WHY THIS EXISTS
#   Inbound is locked down during containment, but outbound is deliberately left
#   OPEN during the analysis window so we can SEE where the implant beacons /
#   exfils to. C2 beacons jitter and can dwell for HOURS, so a single point-in-
#   time `ss`/`netstat` snapshot at collection time routinely misses them. This
#   sensor polls the connection table on a cadence over an extended window
#   (default 24h), appends every external egress flow to an append-only evidence
#   log, then AUTOMATICALLY blackholes outbound when the window closes.
#
#   This changes the workflow: after collection the responder LEAVES the sensor
#   running and RETURNS later to (1) collect the egress evidence log and (2)
#   confirm the blackhole fired. See WORKFLOW-LINUX.md "Egress observation".
#
#   OPTIONAL. Observation tolerates continued exfil during the window. For a
#   DATA-SENSITIVE host, do NOT observe — fully isolate the network stack first
#   (01_contain_host.sh = inbound+outbound) and skip this (--no-egress-monitor):
#   eliminating further data loss outranks mapping the C2 when the data matters.
#
# USAGE
#   monitor_egress.sh --start [--window-hours 24] [--interval-min 1]
#                     [--incident ID] [--mgmt-ips a,b]
#   monitor_egress.sh --status    [--incident ID]
#   monitor_egress.sh --collect   [--incident ID]  # bundle the evidence log
#   monitor_egress.sh --blackhole [--incident ID]  # blackhole outbound NOW
#   monitor_egress.sh --stop      [--incident ID]  # tear sensor down (no blackhole)
#   monitor_egress.sh --tick      --incident ID    # internal (called by cron)
#
# Reversible: the pre-blackhole firewall ruleset is saved in the incident dir and
# can be restored with playbooks/linux/06_restore.sh.
# ==============================================================================
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
WINDOW_HOURS=24
INTERVAL_MIN=1
MGMT_IPS="${IR_MGMT_IPS:-}"
ACTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --start)        ACTION="start"; shift ;;
        --tick)         ACTION="tick"; shift ;;
        --blackhole)    ACTION="blackhole"; shift ;;
        --stop)         ACTION="stop"; shift ;;
        --status)       ACTION="status"; shift ;;
        --collect)      ACTION="collect"; shift ;;
        --window-hours) WINDOW_HOURS="$2"; shift 2 ;;
        --interval-min) INTERVAL_MIN="$2"; shift 2 ;;
        --incident)     INCIDENT_ID="$2"; shift 2 ;;
        --mgmt-ips)     MGMT_IPS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

STATE_DIR="/var/ir/egress-${INCIDENT_ID}"
META="${STATE_DIR}/meta.env"
LOG="${STATE_DIR}/egress-${INCIDENT_ID}.log"
CRON_FILE="/etc/cron.d/ir-egress-${INCIDENT_ID}"
DONE_MARKER="${STATE_DIR}/blackhole.done"

_json() { python3 -c "import json,sys;print(json.dumps(dict(a.split('=',1) for a in sys.argv[1:])))" "$@" 2>/dev/null; }

# External = not loopback / RFC1918 / link-local / multicast / mgmt. Keeps the
# evidence log focused on real egress destinations.
_is_external() {
    local ip="$1"
    case "$ip" in
        127.*|10.*|192.168.*|169.254.*|::1|fe80:*|ff*|224.*|0.0.0.0|"") return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    esac
    IFS=',' read -ra _m <<< "${MGMT_IPS}"
    for m in "${_m[@]}"; do [[ -n "${m// /}" && "$ip" == "${m// /}" ]] && return 1; done
    return 0
}

snapshot() {
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Prefer conntrack (sees short-lived flows that ss can miss between polls); fall back to ss.
    if command -v conntrack &>/dev/null; then
        conntrack -L -p tcp 2>/dev/null | while read -r line; do
            local dst; dst="$(grep -oE 'dst=[0-9a-f.:]+' <<< "$line" | head -1 | cut -d= -f2)"
            local dport; dport="$(grep -oE 'dport=[0-9]+' <<< "$line" | head -1 | cut -d= -f2)"
            _is_external "$dst" && printf '%s | tcp | -> %s:%s | conntrack\n' "$ts" "$dst" "$dport" >> "$LOG"
        done
    fi
    # ss adds the owning PID/process — invaluable attribution for the beacon.
    if command -v ss &>/dev/null; then
        ss -Htunp state established 2>/dev/null | while read -r proto _ _ _ local peer procinfo; do
            local dip="${peer%:*}" dport="${peer##*:}"
            dip="${dip#[}"; dip="${dip%]}"
            _is_external "$dip" && printf '%s | %s | %s -> %s:%s | %s\n' \
                "$ts" "$proto" "$local" "$dip" "$dport" "${procinfo:-?}" >> "$LOG"
        done
    fi
}

case "$ACTION" in
start)
    [[ $EUID -ne 0 ]] && { echo "must run as root to install the cron sensor" >&2; exit 1; }
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    { echo "START_EPOCH=$(date +%s)"; echo "WINDOW_HOURS=${WINDOW_HOURS}";
      echo "INTERVAL_MIN=${INTERVAL_MIN}"; echo "MGMT_IPS=${MGMT_IPS}"; } > "$META"
    : > "$LOG"; echo "# IR egress observation — incident ${INCIDENT_ID} — started $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
    # one cron entry every minute drives both polling and window-expiry/blackhole
    printf '* * * * * root %s --tick --incident %s >> %s/cron.err 2>&1\n' \
        "$SELF" "$INCIDENT_ID" "$STATE_DIR" > "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    logger -t ir-playbook "EGRESS: observation started for ${INCIDENT_ID} (window ${WINDOW_HOURS}h, every ${INTERVAL_MIN}m); auto-blackhole at window close"
    snapshot
    _json phase=egress_observation status=started incident_id="$INCIDENT_ID" \
          window_hours="$WINDOW_HOURS" log="$LOG"
    ;;

tick)
    [[ -f "$META" ]] || exit 0
    # shellcheck disable=SC1090
    source "$META"
    now=$(date +%s)
    last_file="${STATE_DIR}/.last_snapshot"
    last=$(cat "$last_file" 2>/dev/null || echo 0)
    if (( now - last >= INTERVAL_MIN * 60 )); then
        snapshot
        echo "$now" > "$last_file"
    fi
    if (( now - START_EPOCH >= WINDOW_HOURS * 3600 )) && [[ ! -f "$DONE_MARKER" ]]; then
        "$SELF" --blackhole --incident "$INCIDENT_ID"
        rm -f "$CRON_FILE"     # stop polling; window is closed
    fi
    ;;

blackhole)
    [[ $EUID -ne 0 ]] && { echo "must run as root to blackhole egress" >&2; exit 1; }
    [[ -f "$DONE_MARKER" ]] && { echo "egress already blackholed for ${INCIDENT_ID}"; exit 0; }
    mkdir -p "$STATE_DIR"
    [[ -f "$META" ]] && { source "$META"; }
    if command -v iptables &>/dev/null && iptables -L &>/dev/null 2>&1; then
        iptables-save > "${STATE_DIR}/iptables-pre-blackhole.rules" 2>/dev/null || true
        # Keep loopback + local DNS + management reachability; DROP all other egress
        # (cuts the beacon's established C2 too — the point of the blackhole).
        iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o lo -j ACCEPT
        iptables -A OUTPUT -d 127.0.0.0/8 -p udp --dport 53 -j ACCEPT
        IFS=',' read -ra _m <<< "${MGMT_IPS}"
        for m in "${_m[@]}"; do [[ -n "${m// /}" ]] && iptables -A OUTPUT -d "${m// /}" -j ACCEPT; done
        iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IR-EGRESS-BH: " --log-level 4
        iptables -A OUTPUT -j DROP
        iptables -P OUTPUT DROP
        BACKEND=iptables
    elif command -v nft &>/dev/null; then
        nft list ruleset > "${STATE_DIR}/nftables-pre-blackhole.rules" 2>/dev/null || true
        nft add table inet ir_egress_bh 2>/dev/null || true
        nft 'add chain inet ir_egress_bh output { type filter hook output priority 0; policy drop; }' 2>/dev/null || true
        nft add rule inet ir_egress_bh output oifname "lo" accept 2>/dev/null || true
        nft add rule inet ir_egress_bh output ip daddr 127.0.0.0/8 udp dport 53 accept 2>/dev/null || true
        IFS=',' read -ra _m <<< "${MGMT_IPS}"
        for m in "${_m[@]}"; do [[ -n "${m// /}" ]] && nft add rule inet ir_egress_bh output ip daddr "${m// /}" accept 2>/dev/null || true; done
        nft add rule inet ir_egress_bh output limit rate 5/minute log prefix '"IR-EGRESS-BH: "' drop 2>/dev/null || true
        BACKEND=nftables
    else
        echo "no firewall backend" >&2; exit 1
    fi
    touch "$DONE_MARKER"
    logger -t ir-playbook "EGRESS: outbound BLACKHOLED for ${INCIDENT_ID} (backend ${BACKEND}); pre-blackhole rules saved in ${STATE_DIR}"
    _json phase=egress_blackhole status=success backend="${BACKEND:-none}" incident_id="$INCIDENT_ID" \
          evidence_log="$LOG" pre_blackhole_rules="${STATE_DIR}/${BACKEND}-pre-blackhole.rules"
    ;;

stop)
    rm -f "$CRON_FILE"
    logger -t ir-playbook "EGRESS: observation stopped for ${INCIDENT_ID} (no blackhole)"
    _json phase=egress_observation status=stopped incident_id="$INCIDENT_ID"
    ;;

collect)
    # Print where the evidence is so the returning responder can bundle it.
    if [[ -f "$LOG" ]]; then
        flows=$(grep -cv '^#' "$LOG" 2>/dev/null || echo 0)
        uniq_dst=$(grep -oE '\-> [0-9a-f.:]+:' "$LOG" 2>/dev/null | sort -u | wc -l)
        bh="pending"; [[ -f "$DONE_MARKER" ]] && bh="done"
        _json phase=egress_observation status=collect incident_id="$INCIDENT_ID" \
              evidence_log="$LOG" flows_logged="$flows" unique_destinations="$uniq_dst" blackhole="$bh"
    else
        echo "no egress log found for ${INCIDENT_ID} at ${LOG}" >&2; exit 1
    fi
    ;;

status)
    if [[ -f "$META" ]]; then
        source "$META"; now=$(date +%s); elapsed=$(( (now - START_EPOCH) / 60 ))
        remaining=$(( WINDOW_HOURS * 60 - elapsed )); (( remaining < 0 )) && remaining=0
        bh="pending"; [[ -f "$DONE_MARKER" ]] && bh="done"
        _json phase=egress_observation status=running incident_id="$INCIDENT_ID" \
              elapsed_min="$elapsed" remaining_min="$remaining" blackhole="$bh" log="$LOG"
    else
        echo "no egress observation active for ${INCIDENT_ID}" >&2; exit 1
    fi
    ;;
*) echo "specify an action: --start|--status|--collect|--blackhole|--stop" >&2; exit 2 ;;
esac
