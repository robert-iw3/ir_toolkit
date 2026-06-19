#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 07 — Linux Credential / Session Revocation
#
# For each implicated account (from Principals.json, or --user), locks the
# password, expires the account, terminates live sessions, and removes
# unauthorized SSH authorized_keys. Turns the manual "rotate credentials" step
# into an automated, reversible action.
#
# DRY-RUN (plan) by default — prints what it would do and changes nothing until
# --apply. Records prior state to a rollback journal so 06_restore.sh can re-enable
# a falsely-disabled account. Built-in/system accounts are never touched.
#
# Usage:
#   07_revoke_credentials.sh [--principals Principals.json] [--user NAME ...] \
#       [--journal FILE] [--apply]
# ==============================================================================
set -uo pipefail

PRINCIPALS=""; USERS=(); JOURNAL=""; APPLY=0
INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --principals) PRINCIPALS="$2"; shift 2 ;;
        --user)       USERS+=("$2"); shift 2 ;;
        --journal)    JOURNAL="$2"; shift 2 ;;
        --apply)      APPLY=1; shift ;;
        -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

PY="$(command -v python3 || command -v python)"
[[ -z "$JOURNAL" ]] && JOURNAL="/var/ir/rollback/${INCIDENT_ID}.cred.jsonl"
mkdir -p "$(dirname "$JOURNAL")" 2>/dev/null || JOURNAL="$(mktemp)"

# Never lock out these or the responder's own account.
PROTECTED="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc nobody sshd systemd-network messagebus"
SELF="${SUDO_USER:-$USER}"

is_protected() {
    local u="$1"
    [[ "$u" == "$SELF" ]] && return 0
    for p in $PROTECTED; do [[ "$u" == "$p" ]] && return 0; done
    # also protect every UID < 1000 (system accounts)
    local uid; uid="$(id -u "$u" 2>/dev/null || echo 1000)"
    [[ "$uid" -lt 1000 ]] && return 0
    return 1
}

# Gather target users: explicit --user plus auto-revocable local/ssh principals.
if [[ -n "$PRINCIPALS" && -f "$PRINCIPALS" ]]; then
    while IFS= read -r u; do [[ -n "$u" ]] && USERS+=("$u"); done < <(
        "$PY" - "$PRINCIPALS" <<'PYP'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8-sig"))
for p in d.get("principals", []):
    if p.get("auto_revoke") and p.get("type") in ("local", "ssh", "domain"):
        print(p["name"])
PYP
    )
fi

mode=$([[ $APPLY -eq 1 ]] && echo APPLY || echo PLAN)
echo "[*] Credential revocation ($mode) — ${#USERS[@]} candidate(s) — journal: $JOURNAL"
revoked=0; skipped=0

for u in "${USERS[@]}"; do
    if is_protected "$u"; then
        echo "    SKIP (protected/system/self): $u"; skipped=$((skipped+1)); continue
    fi
    if [[ $APPLY -eq 0 ]]; then
        echo "    PLAN: passwd -l $u; chage -E0 $u; loginctl terminate-user $u; prune authorized_keys"
        continue
    fi
    if ! id "$u" &>/dev/null; then
        echo "    SKIP (no such local user): $u"; skipped=$((skipped+1)); continue
    fi
    # record prior state for rollback
    prior="$(passwd -S "$u" 2>/dev/null | awk '{print $2}')"
    echo "{\"action\":\"disable_account\",\"name\":\"$u\",\"prior_status\":\"${prior:-unknown}\"}" >> "$JOURNAL"
    passwd -l "$u" >/dev/null 2>&1 || true          # lock password
    chage -E0 "$u" >/dev/null 2>&1 || true          # expire account
    pkill -KILL -u "$u" >/dev/null 2>&1 || true     # kill processes/sessions
    loginctl terminate-user "$u" >/dev/null 2>&1 || true
    # quarantine the user's authorized_keys (do not delete — move aside, journaled)
    ak="$(eval echo ~"$u")/.ssh/authorized_keys"
    if [[ -f "$ak" ]]; then
        mv "$ak" "${ak}.ir-revoked" 2>/dev/null && \
            echo "{\"action\":\"authorized_keys_moved\",\"name\":\"$u\",\"path\":\"$ak\"}" >> "$JOURNAL"
    fi
    echo "    REVOKED: $u (locked, expired, sessions killed)"; revoked=$((revoked+1))
done

echo "[+] $mode complete: revoked=$revoked skipped=$skipped"
[[ $APPLY -eq 0 ]] && echo "[i] PLAN only — re-run with --apply to enforce."
exit 0
