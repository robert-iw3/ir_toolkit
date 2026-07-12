#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 02 - Linux Process Eradication
# Terminates malicious processes identified by the swarm. Kills by PID first
# (precise), then by name (broader sweep), then quarantines binaries by hash.
# Never targets PID 1 or critical system processes.
#
# Thread-precise suspension (IR_TARGET_TIDS): a process is a group of
# independently-schedulable threads, not one unit. Ptrace-based injection
# typically compromises a single thread while the rest of the process stays
# legitimate. When IR_TARGET_TIDS names the specific compromised thread(s)
# for a PID, and killing the whole process would be destabilizing (protected
# daemon, or highly multi-threaded), the script suspends only those threads
# via threat_hunting/suspend_thread.py (ptrace-based, holds the suspension
# for as long as its daemon process runs) instead of killing the process.
# Signal-based termination cannot target one thread: a fatal signal's
# default action is process-wide regardless of which thread receives it.
# This path is strictly additive -- with IR_TARGET_TIDS unset (the default),
# every existing invocation takes the same whole-process path as before.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
MALICIOUS_PIDS="${IR_MALICIOUS_PIDS:-}"
MALICIOUS_PROCESSES="${IR_MALICIOUS_PROCESSES:-}"
MALICIOUS_HASHES="${IR_MALICIOUS_HASHES:-}"
# Safe by default: when invoked directly (not via the orchestrator) nothing is changed unless
# IR_DRY_RUN=0 is set. The orchestrator passes IR_DRY_RUN=0 only under --apply.
DRY_RUN="${IR_DRY_RUN:-1}"

# "pid:tid,pid:tid,..." -- the SPECIFIC thread(s) known to be running injected/
# malicious code for a given PID (e.g. from a "Ptrace Injection - Thread IP in
# Injected Memory (memory)" finding, or thread_inventory.py's "Traced Thread
# Detail" finding). When set for a PID, kill_tree() suspends ONLY these
# threads instead of the whole process, if the process is protected or highly
# multi-threaded. Empty by default -- no behavior change unless supplied.
TARGET_TIDS="${IR_TARGET_TIDS:-}"
# Thread-count threshold above which precise per-thread suspension is
# preferred over a whole-process kill when a specific malicious TID is known.
MULTI_THREAD_INSTABILITY_THRESHOLD="${IR_MULTI_THREAD_THRESHOLD:-4}"
# Force whole-process termination even when a precise-thread alternative is
# available. Off by default.
FORCE_WHOLE_PROCESS="${IR_FORCE_WHOLE_PROCESS_KILL:-0}"

QUARANTINE_DIR="/var/ir/quarantine/${INCIDENT_ID}"
mkdir -p "${QUARANTINE_DIR}"
chmod 700 "${QUARANTINE_DIR}"

# Rollback journal -- one JSON line per reversible action so 06_restore.sh can undo
# this eradication if the investigation later returns a FALSE POSITIVE verdict.
ROLLBACK_DIR="/var/ir/rollback"
ROLLBACK_JOURNAL="${ROLLBACK_DIR}/${INCIDENT_ID}.jsonl"
mkdir -p "${ROLLBACK_DIR}"; chmod 700 "${ROLLBACK_DIR}"
journal() { echo "$1" >> "${ROLLBACK_JOURNAL}"; }

logger -t ir-playbook "ERADICATE-PROC: Starting process eradication for ${INCIDENT_ID}"

killed_pids=()
killed_procs=()
quarantined_files=()
errors=()

# Protected processes - never kill these regardless of input
PROTECTED_PROCS=(init systemd sshd auditd rsyslogd udevd dbus-daemon networkd)

is_protected() {
    local name="$1"
    for p in "${PROTECTED_PROCS[@]}"; do
        [[ "${name}" == "${p}" ]] && return 0
    done
    return 1
}

# -- Thread inventory + precise per-thread suspension -------------------------
# A process is a group of threads, not one task. Every kill path enumerates
# and journals the full TID set before acting, whether or not the
# precise-thread path is used.
list_tids() {
    local pid="$1"
    ls "/proc/${pid}/task/" 2>/dev/null || true
}

# Look up the analyst/orchestrator-supplied target TID(s) for one PID from
# IR_TARGET_TIDS ("pid:tid,pid:tid,..."). Empty if none given for this PID.
target_tids_for_pid() {
    local want_pid="$1" pair pid tid
    local out=()
    IFS=',' read -ra _pairs <<< "${TARGET_TIDS}"
    for pair in "${_pairs[@]}"; do
        pid="${pair%%:*}"; tid="${pair##*:}"
        [[ "${pid}" == "${want_pid}" && "${tid}" =~ ^[0-9]+$ ]] && out+=("${tid}")
    done
    echo "${out[@]:-}"
}

# Suspend exactly ONE thread, leaving the rest of the process running.
# Signal delivery cannot do this: a fatal signal's default action tears down
# the whole thread group regardless of which thread receives it. This uses
# ptrace (suspend_thread.py) instead -- see that script for the mechanism.
# The suspension is held by a long-lived daemon process; its PID is journaled
# so 06_restore.sh can reverse it (kill the daemon -> thread resumes).
SUSPEND_HELPER="$(dirname "${BASH_SOURCE[0]}")/threat_hunting/suspend_thread.py"

kill_thread() {
    local tgid="$1" tid="$2"
    [[ "${tgid}" =~ ^[0-9]+$ && "${tid}" =~ ^[0-9]+$ ]] || return 1
    [[ -d "/proc/${tgid}/task/${tid}" ]] || { errors+=("tid_not_found:${tgid}:${tid}"); return 1; }

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY-RUN] would suspend TID ${tid} of PID ${tgid} only -- rest of process left running"
        logger -t ir-playbook "ERADICATE-PROC: [DRY-RUN] would suspend TID ${tid} of PID ${tgid}"
        return 0
    fi

    local result daemon_pid
    result=$(python3 "${SUSPEND_HELPER}" --tgid "${tgid}" --tid "${tid}" --incident-id "${INCIDENT_ID}" 2>/dev/null)
    daemon_pid=$(echo "${result}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('daemon_pid',''))" 2>/dev/null)

    if [[ -n "${daemon_pid}" ]]; then
        logger -t ir-playbook "ERADICATE-PROC: Suspended TID ${tid} of PID ${tgid} (tracer PID ${daemon_pid}) -- process left running"
        killed_pids+=("${tgid}:${tid}")
        journal "{\"action\":\"suspend_thread\",\"pid\":${tgid},\"tid\":${tid},\"tracer_pid\":${daemon_pid}}"
        return 0
    else
        errors+=("suspend_thread_failed:${tgid}:${tid}")
        logger -t ir-playbook "ERADICATE-PROC: FAILED to suspend TID ${tid} of PID ${tgid}: ${result}"
        return 1
    fi
}

# -- Kill by PID (and full process tree) --------------------------------------
# Single choke point for EVERY kill path (by-PID, by-name, by-hash, fileless/hidden/anon-rwx
# sweeps). Enforces the protected-process guard and IR_DRY_RUN here so no path can bypass them.
kill_tree() {
    local root_pid="$1"
    [[ "${root_pid}" =~ ^[0-9]+$ ]] || return 1
    [[ "${root_pid}" -le 1       ]] && return 1

    local rcomm
    rcomm=$(cat "/proc/${root_pid}/comm" 2>/dev/null || true)

    # Always journal the full thread inventory at kill time -- forensic record
    # of every task that existed on this PID, whether or not the precise-thread
    # path below ends up being taken.
    local tids tid_count
    tids=$(list_tids "${root_pid}")
    tid_count=$(wc -w <<< "${tids}")
    journal "{\"action\":\"thread_inventory\",\"pid\":${root_pid},\"comm\":\"${rcomm}\",\"tids\":\"${tids//$'\n'/,}\"}"

    # Precise-thread path: if IR_TARGET_TIDS names specific thread(s) for this
    # PID, and a whole-process kill would be destabilizing (protected process,
    # or highly multi-threaded), suspend only those threads instead. Overridden
    # by IR_FORCE_WHOLE_PROCESS_KILL=1.
    local wanted_tids
    wanted_tids=$(target_tids_for_pid "${root_pid}")
    if [[ -n "${wanted_tids}" && "${FORCE_WHOLE_PROCESS}" != "1" ]]; then
        local would_destabilize=0
        if [[ -n "${rcomm}" ]] && is_protected "${rcomm}"; then
            would_destabilize=1
        elif [[ "${tid_count}" -ge "${MULTI_THREAD_INSTABILITY_THRESHOLD}" ]]; then
            would_destabilize=1
        fi
        if [[ "${would_destabilize}" == "1" ]]; then
            local ok=0
            for tid in ${wanted_tids}; do
                kill_thread "${root_pid}" "${tid}" && ok=1
            done
            [[ "${ok}" == "1" ]] && return 0
            # Suspension failed (e.g. TIDs already gone) -- fall through to
            # the whole-process path below rather than silently no-op.
        fi
    fi

    # Protected-process guard by PID (resolve comm) - applies to all callers, not just by-name.
    if [[ -n "${rcomm}" ]] && is_protected "${rcomm}"; then
        errors+=("refused_protected_pid:${root_pid}:${rcomm}")
        local refusal_msg="ERADICATE-PROC: Refused to kill protected ${rcomm} (PID ${root_pid})"
        [[ -n "${wanted_tids}" ]] && refusal_msg+=" (precise-thread alternative was attempted and did not succeed)"
        logger -t ir-playbook "${refusal_msg}"
        return 1
    fi

    # Recursively kill children first (depth-first)
    local children
    children=$(pgrep -P "${root_pid}" 2>/dev/null || true)
    for child in ${children}; do
        kill_tree "${child}" || true
    done

    if kill -0 "${root_pid}" 2>/dev/null; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            echo "[DRY-RUN] would kill PID ${root_pid} (${rcomm})"
            logger -t ir-playbook "ERADICATE-PROC: [DRY-RUN] would kill PID ${root_pid} (${rcomm})"
            return 0
        fi
        # Try SIGTERM first for graceful shutdown, then SIGKILL
        kill -TERM "${root_pid}" 2>/dev/null || true
        sleep 0.5
        if kill -0 "${root_pid}" 2>/dev/null; then
            kill -KILL "${root_pid}" 2>/dev/null && \
                logger -t ir-playbook "ERADICATE-PROC: Killed PID ${root_pid} (SIGKILL)" || true
        else
            logger -t ir-playbook "ERADICATE-PROC: Killed PID ${root_pid} (SIGTERM)"
        fi
        killed_pids+=("${root_pid}")
    fi
}

IFS=',' read -ra PID_LIST <<< "${MALICIOUS_PIDS}"
for pid in "${PID_LIST[@]}"; do
    pid="${pid// /}"
    [[ -z "${pid}" ]] && continue
    [[ "${pid}" =~ ^[0-9]+$ ]] || { errors+=("invalid_pid:${pid}"); continue; }
    [[ "${pid}" -le 1 ]] && { errors+=("refused_init:${pid}"); continue; }

    # Log the command line before killing (forensic value)
    cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 200 || true)
    logger -t ir-playbook "ERADICATE-PROC: Targeting PID ${pid}: ${cmdline}"
    kill_tree "${pid}" || errors+=("kill_failed:${pid}")
done

# -- Kill by Process Name ------------------------------------------------------
IFS=',' read -ra PROC_LIST <<< "${MALICIOUS_PROCESSES}"
for proc_name in "${PROC_LIST[@]}"; do
    proc_name="${proc_name// /}"
    [[ -z "${proc_name}" ]] && continue

    if is_protected "${proc_name}"; then
        errors+=("refused_protected:${proc_name}")
        logger -t ir-playbook "ERADICATE-PROC: Refused to kill protected process ${proc_name}"
        continue
    fi

    matching_pids=$(pgrep -x "${proc_name}" 2>/dev/null || pgrep "${proc_name}" 2>/dev/null || true)
    if [[ -n "${matching_pids}" ]]; then
        for mpid in ${matching_pids}; do
            kill_tree "${mpid}" || true
        done
        killed_procs+=("${proc_name}")
        logger -t ir-playbook "ERADICATE-PROC: Killed processes matching '${proc_name}'"
    fi
done

# -- Quarantine binaries by SHA256 hash ----------------------------------------
# Search common implant staging locations - avoid scanning entire filesystem
SEARCH_PATHS=(/tmp /var/tmp /dev/shm /home /root /opt /var/www /srv
              /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin)

IFS=',' read -ra HASH_LIST <<< "${MALICIOUS_HASHES}"
for bad_hash in "${HASH_LIST[@]}"; do
    bad_hash="${bad_hash// /}"
    [[ -z "${bad_hash}" ]] && continue
    # Only accept valid SHA256 hex strings
    [[ "${bad_hash}" =~ ^[a-fA-F0-9]{64}$ ]] || { errors+=("invalid_hash:${bad_hash:0:16}"); continue; }

    while IFS= read -r -d '' candidate; do
        actual_hash=$(sha256sum "${candidate}" 2>/dev/null | awk '{print $1}') || continue
        if [[ "${actual_hash}" == "${bad_hash}" ]]; then
            # Kill any processes running this binary before quarantine
            running_pids=$(fuser "${candidate}" 2>/dev/null || true)
            for rpid in ${running_pids}; do
                kill_tree "${rpid}" || true
            done
            # Move to quarantine (preserves binary for forensics)
            dest="${QUARANTINE_DIR}/$(basename "${candidate}")-${bad_hash:0:12}"
            orig_mode=$(stat -c %a "${candidate}" 2>/dev/null || echo "")
            if [[ "${DRY_RUN}" == "1" ]]; then
                echo "[DRY-RUN] would quarantine ${candidate} (sha256 ${bad_hash:0:16}…)"
                quarantined_files+=("${candidate}:dry-run")
            elif mv "${candidate}" "${dest}" 2>/dev/null; then
                chmod 400 "${dest}"
                quarantined_files+=("${candidate}")
                journal "{\"action\":\"quarantine\",\"original\":\"${candidate}\",\"dest\":\"${dest}\",\"orig_mode\":\"${orig_mode}\",\"sha256\":\"${actual_hash}\"}"
                logger -t ir-playbook "ERADICATE-PROC: Quarantined ${candidate} (hash: ${bad_hash:0:16}…)"
            else
                # mv failed (e.g. cross-filesystem): make non-executable, but JOURNAL the original
                # mode first so 06_restore.sh can reverse it on a false-positive verdict.
                journal "{\"action\":\"chmod\",\"path\":\"${candidate}\",\"orig_mode\":\"${orig_mode}\",\"sha256\":\"${actual_hash}\"}"
                chmod 000 "${candidate}" 2>/dev/null || true
                quarantined_files+=("${candidate}:chmod000")
            fi
        fi
    done < <(find "${SEARCH_PATHS[@]}" -xdev -type f -print0 2>/dev/null)
done

# Whether this invocation supplied at least one indicator to hunt for. The anon-rwx and
# fileless sweeps below have no way to distinguish genuine injected/fileless malware from an
# ordinary JIT runtime's anon+exec memory (gnome-shell/firefox/gjs/node/java all look
# identical from /proc/*/maps alone) -- their only "suspect" signal is a name/hash match
# against caller-supplied indicators. With none supplied, a full-host scan just flags every
# JIT process into errors[] as pure noise for no investigative gain. Tied to indicators per
# the 2026-06-21 eradication review (finding #6, "unconditional sweeps + JIT noise") -- this
# gates the SWEEP itself, not just the kill, since flagging benign JIT is itself the noise.
# The hidden-PID sweep below is deliberately NOT gated the same way: a process visible via
# /proc/*/maps but absent from directory listing is a structural rootkit-hiding signal, not
# a "does this look like a JIT" heuristic -- worth surfacing even with zero indicators.
HAS_INDICATORS=false
[[ -n "${MALICIOUS_PIDS}" || -n "${MALICIOUS_PROCESSES}" || -n "${MALICIOUS_HASHES}" ]] && HAS_INDICATORS=true

# -- Memory-only process detection (fileless) ----------------------------------
# Check all running processes for deleted-on-disk executables (common in fileless malware)
if ${HAS_INDICATORS}; then
while IFS= read -r pid; do
    exe_path=$(readlink "/proc/${pid}/exe" 2>/dev/null) || continue
    if [[ "${exe_path}" == *"(deleted)"* ]]; then
        # Only kill if the process name matches a known-bad name
        comm=$(cat "/proc/${pid}/comm" 2>/dev/null || true)
        for proc_name in "${PROC_LIST[@]}"; do
            proc_name="${proc_name// /}"
            [[ "${comm}" == "${proc_name}" ]] || continue
            logger -t ir-playbook "ERADICATE-PROC: Killing fileless process PID ${pid} (${comm}) - deleted-on-disk indicator"
            kill_tree "${pid}" || true
        done
    fi
done < <(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null)
fi

# -- Hidden PID detection and eradication (rootkit hook evasion) ---------------
# Rootkits hook getdents64() to hide from readdir while /proc/[pid]/maps still exists.
# Processes visible via /proc/*/maps but absent from directory listing are rootkit-hidden.
for _pid_maps in /proc/[0-9]*/maps; do
    _pid=$(basename "$(dirname "${_pid_maps}")")
    [[ "${_pid}" =~ ^[0-9]+$ ]] || continue
    [[ "${_pid}" -le 1 ]] && continue
    if ! ls "/proc/${_pid}" &>/dev/null 2>&1; then
        # RACE GUARD: a process exiting mid-scan also looks "hidden". Re-verify after a beat -
        # if maps is gone it was merely exiting (not a rootkit), so skip.
        sleep 0.2
        [[ -e "/proc/${_pid}/maps" ]] || continue
        ls "/proc/${_pid}" &>/dev/null 2>&1 && continue
        _comm=$(tr '\0' ' ' < "/proc/${_pid}/cmdline" 2>/dev/null | head -c 80 || true)
        _basecomm=$(cat "/proc/${_pid}/comm" 2>/dev/null || true)
        # ADJUDICATION GATE: only auto-kill a hidden PID whose comm matches a known-bad indicator
        # from the adjudicated findings. An unattributed hidden PID is FLAGGED for the analyst,
        # never autonomously killed (consistent with the anon-rwx sweep below).
        _hidden_bad=false
        for _pn in "${PROC_LIST[@]}"; do
            _pn="${_pn// /}"
            [[ -n "${_pn}" && "${_basecomm}" == "${_pn}" ]] && _hidden_bad=true && break
        done
        if ${_hidden_bad}; then
            logger -t ir-playbook "ERADICATE-PROC: Rootkit-hidden PID ${_pid} matches known-bad '${_basecomm}' - killing"
            kill_tree "${_pid}" || errors+=("hidden_pid_kill_failed:${_pid}")
        else
            logger -t ir-playbook "ERADICATE-PROC: Rootkit-hidden PID ${_pid} (${_comm}) - FLAGGED for analyst (not auto-killed)"
            errors+=("hidden_pid_flagged:${_pid}")
        fi
    fi
done

# -- Anonymous RWX memory mapping detection (shellcode / process injection) ----
# r-xp pages with device 00:00 and inode 0 mean no backing file - injected shellcode or reflective DLL.
# Kill only if the process already matches a known-bad indicator; otherwise log for analyst.
# Gated on HAS_INDICATORS (see comment above the fileless sweep) -- every JIT runtime on the
# host has an anon+exec map indistinguishable from injected shellcode by this check alone.
if ${HAS_INDICATORS}; then
while IFS= read -r _pid; do
    _maps="/proc/${_pid}/maps"
    [[ -r "${_maps}" ]] || continue
    grep -qP '^[0-9a-f]+-[0-9a-f]+ r.xp 00000000 00:00 0\s+$' "${_maps}" 2>/dev/null || continue

    _comm=$(cat "/proc/${_pid}/comm" 2>/dev/null || echo "unknown")
    _exe=$(readlink "/proc/${_pid}/exe" 2>/dev/null || echo "unknown")
    _is_suspect=false

    # Suspect if comm matches a known-bad process name
    for _proc_name in "${PROC_LIST[@]}"; do
        _proc_name="${_proc_name// /}"
        [[ "${_comm}" == "${_proc_name}" ]] && _is_suspect=true && break
    done
    # Suspect if backing executable is already deleted on disk (fileless + injected)
    [[ "${_exe}" == *"(deleted)"* ]] && _is_suspect=true

    if ${_is_suspect}; then
        logger -t ir-playbook "ERADICATE-PROC: Killing PID ${_pid} (${_comm}) - anonymous rwx map + known-bad indicator"
        kill_tree "${_pid}" || true
    else
        logger -t ir-playbook "ERADICATE-PROC: Anonymous rwx mapping in PID ${_pid} (${_comm} / ${_exe}) - flagged for analyst"
        errors+=("anon_rwx:${_pid}:${_comm}")
    fi
done < <(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null)
fi

logger -t ir-playbook "ERADICATE-PROC: Complete. Killed PIDs: ${#killed_pids[@]}, procs: ${#killed_procs[@]}, quarantined: ${#quarantined_files[@]}, errors: ${#errors[@]}"

python3 -c "
import json
print(json.dumps({
    'phase': 'process_eradication',
    'status': 'success',
    'killed_pids': ${#killed_pids[@]},
    'killed_procs': ${#killed_procs[@]},
    'quarantined_files': ${#quarantined_files[@]},
    'errors': ${#errors[@]},
    'incident_id': '${INCIDENT_ID}'
}))
"
