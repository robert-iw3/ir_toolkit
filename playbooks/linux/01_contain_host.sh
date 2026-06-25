#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 01 - Linux Network Containment
# Isolates the host by dropping all traffic except management network SSH access.
# Idempotent: safe to re-run. Preserves the current SSH session.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
MGMT_IPS="${IR_MGMT_IPS:-}"  # Comma-separated management CIDRs/IPs

# State dir must exist before saving the pre-containment ruleset, or 06_restore.sh
# has nothing to roll back to.
mkdir -p /var/ir 2>/dev/null || true

logger -t ir-playbook "CONTAIN: Network isolation starting for ${INCIDENT_ID}"

errors=()

# -- Determine firewall backend ------------------------------------------------
if command -v iptables &>/dev/null && iptables -L &>/dev/null 2>&1; then
    BACKEND="iptables"
elif command -v nft &>/dev/null; then
    BACKEND="nftables"
else
    logger -t ir-playbook "CONTAIN: ERROR - no firewall backend found"
    python3 -c "import json; print(json.dumps({'phase':'containment','status':'failed','error':'no_firewall_backend','incident_id':'${INCIDENT_ID}'}))"
    exit 1
fi

logger -t ir-playbook "CONTAIN: Using ${BACKEND} for ${INCIDENT_ID}"

# -- Parse management IPs ------------------------------------------------------
declare -a MGMT_LIST=()
IFS=',' read -ra _mgmt <<< "${MGMT_IPS}"
for m in "${_mgmt[@]}"; do
    m="${m// /}"
    [[ -n "${m}" ]] && MGMT_LIST+=("${m}")
done

if [[ "${#MGMT_LIST[@]}" -eq 0 ]]; then
    logger -t ir-playbook "CONTAIN: WARNING - no MGMT_IPS set; SSH access will be lost after isolation"
fi

# -- iptables path -------------------------------------------------------------
if [[ "${BACKEND}" == "iptables" ]]; then
    # Save pre-containment rules for audit / rollback
    iptables-save > "/var/ir/iptables-pre-${INCIDENT_ID}.rules" 2>/dev/null || true

    # Flush all chains
    for table in filter nat mangle; do
        iptables -t "${table}" -F 2>/dev/null || true
        iptables -t "${table}" -X 2>/dev/null || true
    done

    # Allow loopback (never block localhost)
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow already-established sessions (keeps the current SSH session alive)
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS resolution to localhost only (avoids breaking system tools)
    iptables -A OUTPUT -d 127.0.0.53 -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d 127.0.0.1  -p udp --dport 53 -j ACCEPT

    # Grant SSH access from each management IP/CIDR
    for mgmt in "${MGMT_LIST[@]}"; do
        iptables -A INPUT  -s "${mgmt}" -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
        iptables -A OUTPUT -d "${mgmt}" -p tcp --sport 22 -j ACCEPT
        logger -t ir-playbook "CONTAIN: Management access preserved from ${mgmt}"
    done

    # Log all drops before the final DROP rules (rate-limited to avoid log flooding)
    iptables -A INPUT  -m limit --limit 5/min -j LOG --log-prefix "IR-CONTAIN-IN:  " --log-level 4
    iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IR-CONTAIN-OUT: " --log-level 4

    # Drop everything else
    iptables -A INPUT   -j DROP
    iptables -A OUTPUT  -j DROP
    iptables -A FORWARD -j DROP

    # Set default policies
    iptables -P INPUT   DROP
    iptables -P OUTPUT  DROP
    iptables -P FORWARD DROP

    # Make rules persistent if iptables-save tooling is available
    if command -v iptables-save &>/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

# -- nftables path -------------------------------------------------------------
else
    nft list ruleset > "/var/ir/nftables-pre-${INCIDENT_ID}.rules" 2>/dev/null || true

    nft flush ruleset
    nft add table inet ir_containment

    nft add chain inet ir_containment input  \
        '{ type filter hook input  priority 0; policy drop; }'
    nft add chain inet ir_containment output \
        '{ type filter hook output priority 0; policy drop; }'
    nft add chain inet ir_containment forward \
        '{ type filter hook forward priority 0; policy drop; }'

    # Loopback
    nft add rule inet ir_containment input  iifname "lo" accept
    nft add rule inet ir_containment output oifname "lo" accept

    # Established sessions
    nft add rule inet ir_containment input  ct state established,related accept
    nft add rule inet ir_containment output ct state established,related accept

    # Local DNS
    nft add rule inet ir_containment output ip daddr 127.0.0.0/8 udp dport 53 accept

    # Management IPs
    for mgmt in "${MGMT_LIST[@]}"; do
        nft add rule inet ir_containment input  ip saddr "${mgmt}" tcp dport 22 ct state new accept
        nft add rule inet ir_containment output ip daddr "${mgmt}" tcp sport 22 accept
        logger -t ir-playbook "CONTAIN: Management access preserved from ${mgmt}"
    done

    # Log drops
    nft add rule inet ir_containment input  limit rate 5/minute log prefix '"IR-CONTAIN-IN: "'  drop
    nft add rule inet ir_containment output limit rate 5/minute log prefix '"IR-CONTAIN-OUT: "' drop

    # Persist nftables rules
    if command -v nft &>/dev/null; then
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
    fi
fi

# -- Secondary isolation measures ----------------------------------------------
# Disable auto-connecting wireless interfaces
if command -v nmcli &>/dev/null; then
    nmcli radio wifi off 2>/dev/null || true
    nmcli radio wwan off 2>/dev/null || true
fi

# Prevent USB networking bypass (if usbguard is present)
if command -v usbguard &>/dev/null; then
    usbguard block-device --permanent 2>/dev/null || true
fi

# Disable unused network interfaces (skip lo and the management interface)
if [[ "${#MGMT_LIST[@]}" -gt 0 ]] && command -v ip &>/dev/null; then
    # Identify which interface carries the management IP route
    mgmt_iface=$(ip route get "${MGMT_LIST[0]}" 2>/dev/null | awk '/dev/{print $3; exit}')
    for iface in $(ip -br link show | awk '$1 != "lo" && $1 != "'"${mgmt_iface}"'" {print $1}'); do
        ip link set "${iface}" down 2>/dev/null || true
        logger -t ir-playbook "CONTAIN: Interface ${iface} brought down"
    done
fi

logger -t ir-playbook "CONTAIN: Host isolation complete for ${INCIDENT_ID} (backend: ${BACKEND})"

python3 -c "
import json
print(json.dumps({
    'phase': 'containment',
    'status': 'success',
    'backend': '${BACKEND}',
    'mgmt_ips': '${MGMT_IPS}',
    'incident_id': '${INCIDENT_ID}'
}))
"
