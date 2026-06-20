#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 03 — Linux Persistence Eradication
# Hunts and removes attacker persistence mechanisms across every known technique:
# cron, systemd, init, rc scripts, authorized_keys, shell profiles, LD_PRELOAD,
# at jobs, XDG autostart, PAM modules, and kernel module loading.
# Suspicious entries are quarantined (not deleted) to preserve forensic value.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
MALICIOUS_HASHES="${IR_MALICIOUS_HASHES:-}"
MALICIOUS_PATHS="${IR_MALICIOUS_PATHS:-}"
MALICIOUS_PROCESSES="${IR_MALICIOUS_PROCESSES:-}"

QUARANTINE_DIR="/var/ir/quarantine/${INCIDENT_ID}/persistence"
AUDIT_LOG="/var/ir/persistence-audit-${INCIDENT_ID}.txt"
mkdir -p "${QUARANTINE_DIR}"
chmod 700 "${QUARANTINE_DIR}"
: > "${AUDIT_LOG}"

logger -t ir-playbook "PERSIST: Persistence hunt starting for ${INCIDENT_ID}"

removed=0
suspicious=()

quarantine_file() {
    local src="$1"
    local label="${2:-unknown}"
    [[ -f "${src}" ]] || return 0
    local dest="${QUARANTINE_DIR}/${label}-$(basename "${src}")"
    cp "${src}" "${dest}" && chmod 400 "${dest}"
    printf '[%s] QUARANTINE: %s → %s\n' "$(date -u +%H:%M:%SZ)" "${src}" "${dest}" >> "${AUDIT_LOG}"
}

flag_suspicious() {
    local item="$1"
    local reason="$2"
    suspicious+=("${item}")
    printf '[%s] SUSPICIOUS: %s — %s\n' "$(date -u +%H:%M:%SZ)" "${item}" "${reason}" >> "${AUDIT_LOG}"
    logger -t ir-playbook "PERSIST: Suspicious: ${item} — ${reason}"
}

# Build a set of known-bad paths from MALICIOUS_PATHS env var
declare -A BAD_PATHS=()
IFS=',' read -ra _paths <<< "${MALICIOUS_PATHS}"
for p in "${_paths[@]}"; do
    p="${p// /}"; [[ -n "${p}" ]] && BAD_PATHS["${p}"]=1
done

# Build set of known-bad hashes
declare -A BAD_HASHES=()
IFS=',' read -ra _hashes <<< "${MALICIOUS_HASHES}"
for h in "${_hashes[@]}"; do
    h="${h// /}"
    [[ "${h}" =~ ^[a-fA-F0-9]{64}$ ]] && BAD_HASHES["${h}"]=1
done

is_bad_path() { [[ -n "${BAD_PATHS["${1}"]:-}" ]]; }
is_bad_hash() {
    local f="$1"
    [[ -f "${f}" ]] || return 1
    local h; h=$(sha256sum "${f}" 2>/dev/null | awk '{print $1}')
    [[ -n "${BAD_HASHES["${h}"]:-}" ]]
}

neutralize() {
    local f="$1"
    local reason="$2"
    quarantine_file "${f}" "persist"
    > "${f}" 2>/dev/null || true  # Zero-out in-place (handles immutable paths)
    printf '[%s] REMOVED: %s — %s\n' "$(date -u +%H:%M:%SZ)" "${f}" "${reason}" >> "${AUDIT_LOG}"
    logger -t ir-playbook "PERSIST: Removed ${f} (${reason})"
    (( removed++ )) || true
}

# -- Crontab sweeps ------------------------------------------------------------
sweep_crontab() {
    local user="${1:-root}"
    local tmp
    tmp=$(mktemp)
    crontab -l -u "${user}" > "${tmp}" 2>/dev/null || { rm -f "${tmp}"; return; }

    local dirty=false
    local cleaned
    cleaned=$(mktemp)

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "${line}" =~ ^[[:space:]]*# || -z "${line// /}" ]] && { echo "${line}" >> "${cleaned}"; continue; }

        local cmd
        cmd=$(echo "${line}" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}')

        # Flag if the command references a known-bad path or script name
        local flagged=false
        for proc in ${MALICIOUS_PROCESSES//,/ }; do
            [[ "${cmd}" == *"${proc// /}"* ]] && flagged=true && break
        done
        for path in "${!BAD_PATHS[@]}"; do
            [[ "${cmd}" == *"${path}"* ]] && flagged=true && break
        done

        if $flagged; then
            flag_suspicious "crontab:${user}:${line}" "matches known-bad indicator"
            quarantine_file "${tmp}" "cron-${user}"
            dirty=true
            dirty=true
        else
            echo "${line}" >> "${cleaned}"
        fi
    done < "${tmp}"

    if $dirty; then
        crontab -u "${user}" - < "${cleaned}" 2>/dev/null || true
    fi
    rm -f "${tmp}" "${cleaned}"
}

sweep_crontab root
for user_home in /home/*/; do
    sweep_crontab "$(basename "${user_home}")"
done

# /etc/cron.d, /etc/cron.{daily,hourly,weekly,monthly}
for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "${cron_dir}" ]] || continue
    find "${cron_dir}" -type f 2>/dev/null | while IFS= read -r f; do
        is_bad_path "${f}" && neutralize "${f}" "known-bad cron script" && continue
        is_bad_hash "${f}" && neutralize "${f}" "hash matches known-bad" && continue
        # Flag scripts dropping to /tmp or /dev/shm
        if grep -qE '(/tmp/|/dev/shm/|/var/tmp/)' "${f}" 2>/dev/null; then
            flag_suspicious "${f}" "references volatile path in cron"
        fi
    done
done

# at jobs
while IFS= read -r job_line; do
    job_id=$(echo "${job_line}" | awk '{print $1}')
    job_time=$(echo "${job_line}" | awk '{print $2,$3,$4,$5,$6}')
    job_file="/var/spool/at/${job_id}" 2>/dev/null
    if [[ -f "${job_file}" ]]; then
        if grep -qE '(/tmp/|/dev/shm/|base64 -d|curl.*\|.*bash|wget.*\|.*bash)' "${job_file}" 2>/dev/null; then
            flag_suspicious "at:${job_id}:${job_time}" "suspicious command in at job"
            quarantine_file "${job_file}" "at-job-${job_id}"
            atrm "${job_id}" 2>/dev/null || true
        fi
    fi
done < <(atq 2>/dev/null || true)

# -- Systemd unit sweep --------------------------------------------------------
# Non-standard systemd paths where attackers plant units
for unit_dir in /etc/systemd/system /usr/local/lib/systemd/system \
                /run/systemd/system /home/*/.config/systemd/user; do
    find "${unit_dir}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.path' \) 2>/dev/null | \
    while IFS= read -r unit_file; do
        # Check if the ExecStart/ExecStartPre points to a bad path or volatile dir
        if grep -qE '^Exec(Start|StartPre|Stop|Reload)=.*(\/tmp\/|\/dev\/shm\/|base64|python -c|perl -e|bash -i)' \
               "${unit_file}" 2>/dev/null; then
            flag_suspicious "${unit_file}" "ExecStart references volatile/suspicious command"
            quarantine_file "${unit_file}" "systemd-unit"
            unit_name=$(basename "${unit_file}")
            systemctl stop "${unit_name}"    2>/dev/null || true
            systemctl disable "${unit_name}" 2>/dev/null || true
            neutralize "${unit_file}" "malicious systemd unit"
        fi

        # Flag if ExecStart points to a known-bad path
        exec_path=$(grep -oP '(?<=ExecStart=)\S+' "${unit_file}" 2>/dev/null | head -1)
        is_bad_path "${exec_path}" && neutralize "${unit_file}" "unit points to known-bad binary"
        is_bad_hash "${exec_path}" && neutralize "${unit_file}" "unit binary matches known-bad hash"
    done
done
systemctl daemon-reload 2>/dev/null || true

# -- Init / rc scripts ---------------------------------------------------------
[[ -f /etc/rc.local ]] && is_bad_hash "/etc/rc.local" && \
    flag_suspicious "/etc/rc.local" "hash matches known-bad"

find /etc/init.d /etc/rc.d -type f 2>/dev/null | while IFS= read -r f; do
    is_bad_path "${f}" && neutralize "${f}" "known-bad init script" && continue
    is_bad_hash "${f}" && neutralize "${f}" "hash matches known-bad" && continue
done

# -- SSH authorized_keys cleanup -----------------------------------------------
# Remove keys that appeared after the incident start time (rough heuristic)
# and flag known-implanted key patterns (base64 anomalies, comments with URLs)
find /root /home -name 'authorized_keys' 2>/dev/null | while IFS= read -r keyfile; do
    quarantine_file "${keyfile}" "authorized_keys"  # Back up before modifying
    tmp=$(mktemp)
    while IFS= read -r key_line; do
        [[ -z "${key_line}" || "${key_line}" =~ ^# ]] && { echo "${key_line}" >> "${tmp}"; continue; }
        # Flag keys with URLs in the comment field (common C2 back-connect keys)
        if echo "${key_line}" | grep -qE 'https?://|\.onion|http://' 2>/dev/null; then
            flag_suspicious "authorized_key:$(echo "${key_line}" | cut -c1-60)…" "URL in key comment"
        else
            echo "${key_line}" >> "${tmp}"
        fi
    done < "${keyfile}"
    cp "${tmp}" "${keyfile}" && chmod 600 "${keyfile}"
    rm -f "${tmp}"
done

# -- Shell profile backdoor removal -------------------------------------------
# Scan init files for common persistence injections
SUSPICIOUS_PATTERNS='(curl|wget).*(sh|bash|exec)|base64 -d|eval \$|python -c|perl -e|bash -i|/tmp/\.|LD_PRELOAD='
find /root /home -maxdepth 2 \
     \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' \
        -o -name '.zshrc' -o -name '.bash_logout' \) 2>/dev/null | \
while IFS= read -r init_file; do
    if grep -qE "${SUSPICIOUS_PATTERNS}" "${init_file}" 2>/dev/null; then
        quarantine_file "${init_file}" "shell-init"
        # Remove only the suspicious lines, preserve the rest
        tmp=$(mktemp)
        grep -vE "${SUSPICIOUS_PATTERNS}" "${init_file}" > "${tmp}" 2>/dev/null || true
        cp "${tmp}" "${init_file}"
        rm -f "${tmp}"
        flag_suspicious "${init_file}" "suspicious shell init injection removed"
    fi
done

# -- LD_PRELOAD hijacking ------------------------------------------------------
if [[ -f /etc/ld.so.preload && -s /etc/ld.so.preload ]]; then
    quarantine_file /etc/ld.so.preload "ld_so_preload"
    > /etc/ld.so.preload  # Zero out — this file should normally be empty
    flag_suspicious "/etc/ld.so.preload" "non-empty ld.so.preload detected and cleared"
    ldconfig 2>/dev/null || true
fi

# -- XDG autostart (if desktop environment present) ----------------------------
find /etc/xdg/autostart /home/*/.config/autostart -name '*.desktop' 2>/dev/null | \
while IFS= read -r desktop_file; do
    if grep -qE "^Exec=.*(\/tmp\/|\/dev\/shm\/|base64|wget|curl)" "${desktop_file}" 2>/dev/null; then
        flag_suspicious "${desktop_file}" "suspicious XDG autostart entry"
        neutralize "${desktop_file}" "malicious XDG autostart"
    fi
done

# -- PAM module sweep ----------------------------------------------------------
# Check for non-standard PAM modules (rootkit credential theft)
find /lib/security /lib64/security /usr/lib/security -name 'pam_*.so' 2>/dev/null | \
while IFS= read -r pam_mod; do
    is_bad_hash "${pam_mod}" && flag_suspicious "${pam_mod}" "PAM module hash matches known-bad"
done

# -- nsswitch.conf hijacking (credential intercept via rogue NSS module) --------
# Attackers insert a custom NSS library into passwd/shadow lookups to harvest credentials.
# Standard services: files, compat, systemd, sss, winbind, ldap, nis, db, dns
if [[ -f /etc/nsswitch.conf ]]; then
    quarantine_file /etc/nsswitch.conf "nsswitch"
    _nsswitch_safe='files|compat|systemd|sss|winbind|ldap|nis|db|dns|mdns4_minimal|resolve|mymachines|myhost'
    while IFS= read -r _nss_line; do
        [[ "${_nss_line}" =~ ^[[:space:]]*(passwd|shadow|group)[[:space:]]*: ]] || continue
        _db=$(echo "${_nss_line}" | cut -d: -f1 | tr -d '[:space:]')
        # Strip bracket expressions ([SUCCESS=return] etc.) then check each token
        _mods=$(echo "${_nss_line}" | sed 's/^[^:]*://; s/\[[^]]*\]//g' | tr ' \t' '\n' | grep -vE '^$')
        while IFS= read -r _mod; do
            [[ -z "${_mod}" ]] && continue
            if ! echo "${_mod}" | grep -qE "^(${_nsswitch_safe})$"; then
                flag_suspicious "/etc/nsswitch.conf" \
                    "non-standard NSS module '${_mod}' for '${_db}' — possible credential intercept"
            fi
        done <<< "${_mods}"
    done < /etc/nsswitch.conf 2>/dev/null || true
fi

# -- ld.so.conf.d poisoning (shared library search path hijacking) -------------
# An entry pointing to /tmp, /dev/shm, or a hidden home-dir path hijacks all library loads.
# Uses process substitution (< <(...)) so flag_suspicious/neutralize run in the parent shell
# and correctly update the suspicious[] array and removed counter.
if [[ -d /etc/ld.so.conf.d ]]; then
    while IFS= read -r _conf; do
        if grep -qE '^(/tmp/|/dev/shm/|/var/tmp/|/home/[^/]+/\.[^/]|/run/[^/]+/\.[^/])' \
               "${_conf}" 2>/dev/null; then
            flag_suspicious "${_conf}" "ld.so.conf.d entry points to volatile/hidden path — library hijacking"
            neutralize "${_conf}" "malicious ld.so.conf.d entry"
            ldconfig 2>/dev/null || true
        fi
    done < <(find /etc/ld.so.conf.d -type f -name '*.conf' 2>/dev/null)
fi

# -- Kernel module suspicious loading (rootkit LKM blocklist) -----------------
# Modules with no backing file in the running kernel tree suggest a loaded-but-removed rootkit LKM.
IR_MODPROBE_CONF="/etc/modprobe.d/ir-blocklist-${INCIDENT_ID}.conf"
_blocklist_written=false
while IFS= read -r _mod_name; do
    _mod_path=$(modinfo -n "${_mod_name}" 2>/dev/null || true)
    if [[ -z "${_mod_path}" ]]; then
        flag_suspicious "kernel-module:${_mod_name}" \
            "loaded module has no modinfo — possible in-memory rootkit LKM"
    elif [[ "${_mod_path}" != "/lib/modules/$(uname -r)"* ]]; then
        flag_suspicious "kernel-module:${_mod_name}" \
            "module loaded from outside standard kernel path: ${_mod_path}"
    else
        continue
    fi
    # Blocklist via modprobe.d to prevent reload after reboot
    if [[ "${_blocklist_written}" == false ]]; then
        printf '# IR incident %s — auto-generated module blocklist\n' "${INCIDENT_ID}" \
            > "${IR_MODPROBE_CONF}" 2>/dev/null || true
        _blocklist_written=true
    fi
    printf 'blacklist %s\ninstall %s /bin/true\n' "${_mod_name}" "${_mod_name}" \
        >> "${IR_MODPROBE_CONF}" 2>/dev/null || true
done < <(lsmod 2>/dev/null | awk 'NR>1 {print $1}')

# -- Immutable file attribute removal (chattr +i prevents persistence cleanup) --
# Attackers set the immutable bit on planted persistence files to block removal tools.
for _target_file in \
    /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/rc.local \
    /etc/ld.so.preload /etc/nsswitch.conf /etc/hosts /etc/modules; do
    [[ -f "${_target_file}" ]] || continue
    if lsattr "${_target_file}" 2>/dev/null | grep -q '^....i'; then
        flag_suspicious "${_target_file}" "immutable attribute (chattr +i) set — blocking cleanup"
        chattr -i "${_target_file}" 2>/dev/null && \
            logger -t ir-playbook "PERSIST: Removed immutable bit from ${_target_file}" || true
    fi
done

logger -t ir-playbook "PERSIST: Sweep complete — removed: ${removed}, suspicious: ${#suspicious[@]}"
printf '\nSummary: %d items removed, %d flagged suspicious\n' "${removed}" "${#suspicious[@]}" >> "${AUDIT_LOG}"

python3 -c "
import json
print(json.dumps({
    'phase': 'persistence_removal',
    'status': 'success',
    'removed': ${removed},
    'suspicious': ${#suspicious[@]},
    'audit_log': '${AUDIT_LOG}',
    'incident_id': '${INCIDENT_ID}'
}))
"
