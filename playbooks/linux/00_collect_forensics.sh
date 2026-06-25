#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 00 - Linux Forensics Collection
# Captures a full system snapshot before any eradication action disturbs state.
# Must run FIRST in every engagement. Output: compressed archive in /var/ir/.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
ARCHIVE_DIR="/var/ir/forensics"
WORK_DIR="${ARCHIVE_DIR}/incident-${INCIDENT_ID}"
ARCHIVE="${ARCHIVE_DIR}/ir-forensics-${INCIDENT_ID}.tar.gz"

mkdir -p "${WORK_DIR}"
logger -t ir-playbook "FORENSICS: Collection started for incident ${INCIDENT_ID}"

# -- Process state -------------------------------------------------------------
ps auxf                                      > "${WORK_DIR}/process_tree.txt"        2>/dev/null || true
ps -eo pid,ppid,user,stat,comm,args          > "${WORK_DIR}/process_full.txt"        2>/dev/null || true

# Hash every running process binary - fast indicator cross-reference
while IFS= read -r pid; do
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || continue
    [[ -f "${exe}" ]] || continue
    printf '%s  %s\n' "$(sha256sum "${exe}" 2>/dev/null | cut -d' ' -f1)" "${exe}"
done < <(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null) \
    > "${WORK_DIR}/running_binary_hashes.txt" 2>/dev/null || true

# Command-lines and open file descriptors for all processes
for pid in $(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null); do
    {
        printf '\n=== PID %s ===\n' "${pid}"
        tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null; echo
        printf 'CWD: '; readlink -f "/proc/${pid}/cwd" 2>/dev/null; echo
        ls -la "/proc/${pid}/fd/" 2>/dev/null | head -30
        tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null | grep -E 'PATH|HOME|USER|LD_' || true
    }
done > "${WORK_DIR}/proc_details.txt" 2>/dev/null || true

# -- Network state -------------------------------------------------------------
ss -tulpanm                                  > "${WORK_DIR}/sockets.txt"             2>/dev/null || \
    netstat -tulpan                          > "${WORK_DIR}/sockets.txt"             2>/dev/null || true
ss -anp  --tcp                               > "${WORK_DIR}/tcp_connections.txt"     2>/dev/null || true
ip route show                                > "${WORK_DIR}/routing_table.txt"       2>/dev/null || true
ip neigh show                                > "${WORK_DIR}/arp_table.txt"           2>/dev/null || true
iptables-save                                > "${WORK_DIR}/iptables_pre.rules"      2>/dev/null || true
nft list ruleset                             > "${WORK_DIR}/nftables_pre.rules"      2>/dev/null || true

# DNS client config
cat /etc/resolv.conf                         > "${WORK_DIR}/resolv_conf.txt"         2>/dev/null || true
cat /etc/hosts                               > "${WORK_DIR}/etc_hosts.txt"           2>/dev/null || true

# -- Persistence mechanisms ----------------------------------------------------
# Crontabs
crontab -l                                   > "${WORK_DIR}/cron_root.txt"           2>/dev/null || true
for user_home in /home/*/; do
    username=$(basename "${user_home}")
    crontab -l -u "${username}"              >> "${WORK_DIR}/cron_users.txt"         2>/dev/null || true
done
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron \
     -type f 2>/dev/null | xargs ls -la      > "${WORK_DIR}/cron_files.txt"          2>/dev/null || true
cat /etc/crontab                             >> "${WORK_DIR}/cron_files.txt"         2>/dev/null || true

# Systemd units - all states, highlight non-standard paths
systemctl list-units --all --no-pager        > "${WORK_DIR}/systemd_units.txt"       2>/dev/null || true
systemctl list-unit-files --no-pager         > "${WORK_DIR}/systemd_unit_files.txt"  2>/dev/null || true
find /etc/systemd /usr/local/lib/systemd /home -name '*.service' -o -name '*.timer'  2>/dev/null \
                                             > "${WORK_DIR}/custom_systemd_files.txt"             || true

# Init / rc scripts
ls -la /etc/init.d/                          > "${WORK_DIR}/initd.txt"               2>/dev/null || true
cat /etc/rc.local                            > "${WORK_DIR}/rc_local.txt"            2>/dev/null || true

# SSH authorized_keys for every user
find /root /home -name 'authorized_keys' 2>/dev/null | while IFS= read -r keyfile; do
    printf '\n=== %s ===\n' "${keyfile}"
    cat "${keyfile}"
done > "${WORK_DIR}/authorized_keys.txt" 2>/dev/null || true

# Shell init files (backdoor injection common here)
find /root /home -maxdepth 2 \
     \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' \
        -o -name '.zshrc' -o -name '.bash_logout' \) 2>/dev/null | \
while IFS= read -r f; do
    printf '\n=== %s ===\n' "${f}"; cat "${f}"
done > "${WORK_DIR}/shell_init_files.txt" 2>/dev/null || true

# LD_PRELOAD / shared library hijacking
cat /etc/ld.so.preload                       > "${WORK_DIR}/ld_so_preload.txt"        2>/dev/null || true
ldconfig -p                                  > "${WORK_DIR}/ldconfig_cache.txt"       2>/dev/null || true

# SUID/SGID binaries (quick check - compare with baseline in full investigation)
find / -perm /6000 -type f 2>/dev/null       > "${WORK_DIR}/suid_sgid_files.txt"                || true

# -- File system artifacts -----------------------------------------------------
# Recently modified files in volatile/writable locations (last 24h)
find /tmp /var/tmp /dev/shm /run /var/run \
     -type f -newer /proc/1 2>/dev/null      > "${WORK_DIR}/recently_modified.txt"               || true
# Hidden files in home directories
find /root /home -maxdepth 3 -name '.*' -type f 2>/dev/null \
                                             > "${WORK_DIR}/hidden_files.txt"                     || true
# World-writable executables (common implant locations)
find /usr /opt /var -perm -o+w -type f 2>/dev/null \
                                             > "${WORK_DIR}/world_writable_exec.txt"              || true

# -- Authentication and logs ---------------------------------------------------
tail -500 /var/log/auth.log                  > "${WORK_DIR}/auth_log.txt"            2>/dev/null || \
    journalctl -u sshd -n 500 --no-pager     >> "${WORK_DIR}/auth_log.txt"           2>/dev/null || true
# Structured journal export (consumed by journal_analysis.py for offline re-analysis).
# Bounded by time + line cap so a multi-GB journal can't stall collection.
journalctl -o json --no-pager --since "14 days ago" -n 300000 \
                                             > "${WORK_DIR}/journal.json"            2>/dev/null || true
last -500 -F                                 > "${WORK_DIR}/last_logins.txt"         2>/dev/null || true
lastb -100                                   > "${WORK_DIR}/failed_logins.txt"       2>/dev/null || true
who                                          > "${WORK_DIR}/current_sessions.txt"    2>/dev/null || true

# At jobs
atq                                          > "${WORK_DIR}/at_jobs.txt"             2>/dev/null || true
find /var/spool/at -type f 2>/dev/null | \
    xargs -r cat                             >> "${WORK_DIR}/at_jobs.txt"            2>/dev/null || true

# Kernel modules (rootkit check)
lsmod                                        > "${WORK_DIR}/kernel_modules.txt"      2>/dev/null || true
# Flag modules without a corresponding file in the standard kernel module tree (in-memory rootkit indicator)
{
    echo "=== Kernel modules with no file on disk (rootkit LKM indicator) ==="
    lsmod 2>/dev/null | awk 'NR>1 {print $1}' | while IFS= read -r _mod; do
        _path=$(modinfo -n "${_mod}" 2>/dev/null || true)
        if [[ -z "${_path}" ]]; then
            printf 'NO_FILE: %s\n' "${_mod}"
        elif [[ "${_path}" != "/lib/modules/$(uname -r)"* ]]; then
            printf 'OUTSIDE_TREE: %s  PATH: %s\n' "${_mod}" "${_path}"
        fi
    done
} >> "${WORK_DIR}/kernel_modules.txt" 2>/dev/null || true

# -- ELF entropy scan (high-entropy = packed/encrypted implants) ---------------
# Shannon entropy > 7.2 on an ELF binary strongly suggests packing or encryption
{
    printf 'entropy\tsize_bytes\tpath\n'
    for _scan_dir in /tmp /var/tmp /dev/shm /run /home /root /opt /var/www; do
        [[ -d "${_scan_dir}" ]] || continue
        find "${_scan_dir}" -maxdepth 4 -type f -executable 2>/dev/null | while IFS= read -r _f; do
            file "${_f}" 2>/dev/null | grep -q 'ELF' || continue
            _size=$(stat -c%s "${_f}" 2>/dev/null) || continue
            [[ "${_size}" -lt 64 || "${_size}" -gt 52428800 ]] && continue
            _entropy=$(python3 -c "
import sys, math, collections
try:
    d = open(sys.argv[1], 'rb').read(65536)
    if d:
        c = collections.Counter(d); t = len(d)
        print(f'{-sum((v/t)*math.log2(v/t) for v in c.values() if v):.2f}')
except: pass
" "${_f}" 2>/dev/null) || continue
            [[ -z "${_entropy}" ]] && continue
            awk "BEGIN{exit(\"${_entropy}\"+0>7.2?0:1)}" 2>/dev/null && \
                printf '%s\t%s\t%s\n' "${_entropy}" "${_size}" "${_f}"
        done
    done
} > "${WORK_DIR}/high_entropy_elf.txt" 2>/dev/null || true

# -- Hidden PID detection (rootkit indicator) ----------------------------------
# Rootkits hook getdents64() to hide entries from readdir but /proc/[pid]/maps still exists
{
    echo "=== PIDs readable via /proc/[pid]/maps but hidden from directory listing ==="
    for _pid_maps in /proc/[0-9]*/maps; do
        _pid=$(basename "$(dirname "${_pid_maps}")")
        [[ "${_pid}" =~ ^[0-9]+$ ]] || continue
        if ! ls "/proc/${_pid}" &>/dev/null 2>&1; then
            _comm=$(tr '\0' ' ' < "/proc/${_pid}/cmdline" 2>/dev/null | head -c 100 || true)
            printf 'HIDDEN PID: %s  CMDLINE: %s\n' "${_pid}" "${_comm}"
        fi
    done
} > "${WORK_DIR}/hidden_pids.txt" 2>/dev/null || true

# -- Anonymous executable memory mappings (shellcode/injection indicators) ------
# r-xp mappings with device 00:00 and inode 0 = no backing file = injected shellcode
{
    echo "=== Processes with anonymous executable memory regions ==="
    for _pid in $(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null); do
        _maps="/proc/${_pid}/maps"
        [[ -r "${_maps}" ]] || continue
        if grep -qP '^[0-9a-f]+-[0-9a-f]+ r.xp 00000000 00:00 0\s+$' "${_maps}" 2>/dev/null; then
            _comm=$(cat "/proc/${_pid}/comm" 2>/dev/null || echo "unknown")
            _exe=$(readlink "/proc/${_pid}/exe" 2>/dev/null || echo "unknown")
            printf 'PID: %s  COMM: %s  EXE: %s\n' "${_pid}" "${_comm}" "${_exe}"
            grep -P '^[0-9a-f]+-[0-9a-f]+ r.xp 00000000 00:00 0\s+$' "${_maps}" 2>/dev/null | head -5
        fi
    done
} > "${WORK_DIR}/anon_exec_maps.txt" 2>/dev/null || true

# -- Immutable file attributes (chattr +i blocks cleanup) ---------------------
lsattr /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/rc.local \
       /etc/ld.so.preload /etc/nsswitch.conf /etc/hosts 2>/dev/null \
    > "${WORK_DIR}/lsattr_critical.txt" 2>/dev/null || true

# -- nsswitch.conf and sudoers (privilege escalation / credential intercept) ---
cat /etc/nsswitch.conf                       > "${WORK_DIR}/nsswitch_conf.txt"       2>/dev/null || true
cat /etc/sudoers                             > "${WORK_DIR}/sudoers.txt"             2>/dev/null || true
find /etc/sudoers.d -type f 2>/dev/null | xargs -r cat >> "${WORK_DIR}/sudoers.txt"              || true

# -- Compress and clean up -----------------------------------------------------
tar czf "${ARCHIVE}" -C "${ARCHIVE_DIR}" "incident-${INCIDENT_ID}/" 2>/dev/null
rm -rf "${WORK_DIR}"
chmod 600 "${ARCHIVE}"

logger -t ir-playbook "FORENSICS: Archive saved → ${ARCHIVE}"

python3 -c "
import json
print(json.dumps({
    'phase': 'forensics',
    'status': 'success',
    'archive': '${ARCHIVE}',
    'incident_id': '${INCIDENT_ID}'
}))
"
