#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 06 — Linux False-Positive Restore (rollback)
# Reverses the containment/eradication applied during an investigation that the
# swarm later judged a FALSE POSITIVE:
#   • restores the pre-containment firewall ruleset saved by 01_contain_host.sh
#     (this also removes any 04_block_c2 DROP rules),
#   • restores each quarantined binary to its original path AFTER verifying its
#     sha256 against the rollback journal written by 02_eradicate_process.sh.
# Non-destructive: it only un-isolates and puts files back; it deletes no data.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
ROLLBACK_JOURNAL="/var/ir/rollback/${INCIDENT_ID}.jsonl"
IPT_BACKUP="/var/ir/iptables-pre-${INCIDENT_ID}.rules"
NFT_BACKUP="/var/ir/nftables-pre-${INCIDENT_ID}.rules"
restored=(); skipped=(); errors=()

log() { logger -t ir-playbook "RESTORE: $*"; echo "RESTORE: $*"; }

# -- 1. Un-isolate: restore the firewall ruleset captured before containment ---
if [[ -f "${IPT_BACKUP}" ]] && command -v iptables-restore &>/dev/null; then
    iptables-restore < "${IPT_BACKUP}" && log "iptables ruleset restored from ${IPT_BACKUP}" \
        || errors+=("iptables_restore_failed")
elif [[ -f "${NFT_BACKUP}" ]] && command -v nft &>/dev/null; then
    nft flush ruleset && nft -f "${NFT_BACKUP}" && log "nftables ruleset restored from ${NFT_BACKUP}" \
        || errors+=("nft_restore_failed")
else
    log "no firewall backup found for ${INCIDENT_ID}; skipping un-isolate"
fi

# -- 2. Reverse file actions (sha256-verified) from the rollback journal -------
# action=quarantine -> move the binary back and restore its original mode;
# action=chmod       -> reapply the original mode to a file that was chmod 000'd in place.
if [[ -f "${ROLLBACK_JOURNAL}" ]]; then
    while IFS=$'\t' read -r action original dest sha256 orig_mode; do
        if [[ "${action}" == "chmod" ]]; then
            [[ -f "${original}" ]] || { skipped+=("${original}:missing"); continue; }
            actual=$(sha256sum "${original}" 2>/dev/null | awk '{print $1}')
            [[ -n "${sha256}" && "${actual}" != "${sha256}" ]] && { skipped+=("${original}:sha_mismatch"); continue; }
            chmod "${orig_mode:-755}" "${original}" 2>/dev/null \
                && { restored+=("${original}"); log "restored mode ${orig_mode} on ${original}"; } \
                || errors+=("restore_chmod_failed:${original}")
            continue
        fi
        # quarantine
        [[ -z "${dest}" || ! -f "${dest}" ]] && { skipped+=("${original}:missing_quarantine"); continue; }
        actual=$(sha256sum "${dest}" 2>/dev/null | awk '{print $1}')
        if [[ "${actual}" != "${sha256}" ]]; then
            skipped+=("${original}:sha_mismatch")     # never restore tampered bytes
            continue
        fi
        mkdir -p "$(dirname "${original}")"
        if mv "${dest}" "${original}" 2>/dev/null; then
            chmod "${orig_mode:-755}" "${original}" 2>/dev/null || true   # original mode, not blanket +rwx
            restored+=("${original}")
            log "restored ${original}"
        else
            errors+=("restore_move_failed:${original}")
        fi
    done < <(python3 -c "
import json,sys
for ln in open('${ROLLBACK_JOURNAL}'):
    try: e=json.loads(ln)
    except Exception: continue
    a=e.get('action','')
    if a in ('quarantine','chmod'):
        print('\t'.join([a, e.get('original') or e.get('path',''), e.get('dest',''),
                         e.get('sha256',''), str(e.get('orig_mode',''))]))
")
else
    log "no rollback journal at ${ROLLBACK_JOURNAL}; nothing to restore"
fi

python3 -c "import json;print(json.dumps({'phase':'restore','status':'completed','incident_id':'${INCIDENT_ID}','restored':${#restored[@]},'skipped':${#skipped[@]},'errors':${#errors[@]}}))"
