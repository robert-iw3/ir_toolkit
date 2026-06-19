#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 04 — Linux C2 Blocking
# Adds host-level blocks for all known C2 infrastructure:
#   • iptables/nftables rules DROP outbound connections to C2 IPs
#   • /etc/hosts entries redirect C2 domains to 0.0.0.0
#   • systemd-resolved / dnsmasq overrides for C2 domain sinkholes
# Idempotent: safe to re-run with the same or extended IOC lists.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
C2_IPS="${IR_C2_IPS:-}"
C2_DOMAINS="${IR_C2_DOMAINS:-}"

logger -t ir-playbook "C2-BLOCK: Starting C2 infrastructure blocking for ${INCIDENT_ID}"

blocked_ips=()
blocked_domains=()
errors=()

HOSTS_FILE="/etc/hosts"
IR_BLOCK_TAG="# IR-BLOCK-${INCIDENT_ID}"

# -- Parse IOC lists -----------------------------------------------------------
declare -a IP_LIST=()
IFS=',' read -ra _ips <<< "${C2_IPS}"
for ip in "${_ips[@]}"; do
    ip="${ip// /}"
    # Validate IPv4 or IPv6 format, skip RFC-1918 private ranges (never block internal)
    [[ -z "${ip}" ]] && continue
    if [[ "${ip}" =~ ^10\. || "${ip}" =~ ^192\.168\. || "${ip}" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        logger -t ir-playbook "C2-BLOCK: Skipping private IP ${ip} (RFC-1918)"
        continue
    fi
    IP_LIST+=("${ip}")
done

declare -a DOMAIN_LIST=()
IFS=',' read -ra _domains <<< "${C2_DOMAINS}"
for domain in "${_domains[@]}"; do
    domain="${domain// /}"
    [[ -z "${domain}" ]] && continue
    DOMAIN_LIST+=("${domain}")
done

# -- Determine firewall backend ------------------------------------------------
USE_IPTABLES=false
USE_NFTABLES=false
if command -v iptables &>/dev/null && iptables -L &>/dev/null 2>&1; then
    USE_IPTABLES=true
elif command -v nft &>/dev/null; then
    USE_NFTABLES=true
fi

# -- Block C2 IPs at firewall level --------------------------------------------
for c2_ip in "${IP_LIST[@]}"; do
    if $USE_IPTABLES; then
        # Idempotent: check before adding
        if ! iptables -C OUTPUT -d "${c2_ip}" -j DROP 2>/dev/null; then
            iptables -A OUTPUT -d "${c2_ip}" -j DROP \
                -m comment --comment "IR-C2-${INCIDENT_ID}" 2>/dev/null && \
                blocked_ips+=("${c2_ip}") && \
                logger -t ir-playbook "C2-BLOCK: iptables DROP output → ${c2_ip}" || \
                errors+=("iptables_failed:${c2_ip}")
        fi
        if ! iptables -C INPUT -s "${c2_ip}" -j DROP 2>/dev/null; then
            iptables -A INPUT -s "${c2_ip}" -j DROP \
                -m comment --comment "IR-C2-${INCIDENT_ID}" 2>/dev/null || true
        fi

    elif $USE_NFTABLES; then
        # Add to the ir_containment table if it exists, or the main filter
        TABLE="ir_containment"
        nft list table inet "${TABLE}" &>/dev/null 2>&1 || TABLE="filter"

        if ! nft list ruleset 2>/dev/null | grep -q "daddr ${c2_ip}"; then
            nft add rule inet "${TABLE}" output ip daddr "${c2_ip}" drop 2>/dev/null && \
                blocked_ips+=("${c2_ip}") && \
                logger -t ir-playbook "C2-BLOCK: nftables DROP output → ${c2_ip}" || \
                errors+=("nftables_failed:${c2_ip}")
        fi
    else
        # Fallback: use tc (traffic control) to blackhole if no iptables/nft
        if command -v ip &>/dev/null; then
            ip route add blackhole "${c2_ip}/32" 2>/dev/null && \
                blocked_ips+=("${c2_ip}:route") || \
                errors+=("route_failed:${c2_ip}")
        fi
    fi

    # Also add a null route as belt-and-suspenders
    ip route add blackhole "${c2_ip}/32" 2>/dev/null || true
done

# Persist iptables rules if possible
if $USE_IPTABLES && command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# -- Block C2 domains via /etc/hosts sinkhole ----------------------------------
# Remove any existing IR blocks first (idempotent)
if grep -q "IR-BLOCK-" "${HOSTS_FILE}" 2>/dev/null; then
    sed -i '/IR-BLOCK-/d' "${HOSTS_FILE}"
fi

for c2_domain in "${DOMAIN_LIST[@]}"; do
    # Sinkhole the domain and common subdomains to 0.0.0.0
    echo "0.0.0.0 ${c2_domain} ${IR_BLOCK_TAG}" >> "${HOSTS_FILE}"
    echo "0.0.0.0 www.${c2_domain} ${IR_BLOCK_TAG}" >> "${HOSTS_FILE}"
    echo "# IR C2 block ${c2_domain} — incident: ${INCIDENT_ID} — $(date -u)" >> "${HOSTS_FILE}"
    blocked_domains+=("${c2_domain}")
    logger -t ir-playbook "C2-BLOCK: Sinkholes ${c2_domain} → 0.0.0.0 in /etc/hosts"
done

# -- systemd-resolved NXDOMAIN override ---------------------------------------
if command -v resolvectl &>/dev/null && systemctl is-active systemd-resolved &>/dev/null; then
    RESOLVED_OVERRIDE_DIR="/etc/systemd/resolved.conf.d"
    mkdir -p "${RESOLVED_OVERRIDE_DIR}"
    {
        echo "[Resolve]"
        echo "# IR C2 domain blocks for incident ${INCIDENT_ID}"
        for c2_domain in "${DOMAIN_LIST[@]}"; do
            printf 'DNSSECNegativeTrustAnchors=%s\n' "${c2_domain}"
        done
    } > "${RESOLVED_OVERRIDE_DIR}/ir-c2-block.conf"
    systemctl restart systemd-resolved 2>/dev/null || true
fi

# -- dnsmasq sinkhole ----------------------------------------------------------
if command -v dnsmasq &>/dev/null && systemctl is-active dnsmasq &>/dev/null; then
    DNSMASQ_CONF="/etc/dnsmasq.d/ir-c2-block-${INCIDENT_ID}.conf"
    {
        echo "# IR C2 sinkhole — incident ${INCIDENT_ID} — $(date -u)"
        for c2_domain in "${DOMAIN_LIST[@]}"; do
            printf 'address=/%s/0.0.0.0\n' "${c2_domain}"
        done
    } > "${DNSMASQ_CONF}"
    systemctl reload dnsmasq 2>/dev/null || kill -HUP "$(pidof dnsmasq)" 2>/dev/null || true
fi

# -- Flush DNS cache -----------------------------------------------------------
# Ensure cached C2 resolutions are purged
resolvectl flush-caches 2>/dev/null || \
    systemd-resolve --flush-caches 2>/dev/null || \
    nscd -i hosts 2>/dev/null || true

logger -t ir-playbook "C2-BLOCK: Complete. IPs blocked: ${#blocked_ips[@]}, domains sinkholes: ${#blocked_domains[@]}, errors: ${#errors[@]}"

python3 -c "
import json
print(json.dumps({
    'phase': 'c2_blocking',
    'status': 'success',
    'blocked_ips': ${#blocked_ips[@]},
    'blocked_domains': ${#blocked_domains[@]},
    'errors': ${#errors[@]},
    'incident_id': '${INCIDENT_ID}'
}))
"
