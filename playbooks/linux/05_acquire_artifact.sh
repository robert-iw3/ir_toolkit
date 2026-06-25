#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 05 - Linux Artifact Acquisition
# Delivered to the endpoint over SSH (ssh_playbook_v1). Given a confirmed-TP file
# path, it ACQUIRES the file for detonation: hashes it (chain of custody), zips it
# for safe transport, writes a manifest, and uploads to the quarantine bucket.
# It NEVER executes the sample. Mirrors det_chamber/agents/acquire_core.py.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
TARGET_PATH="${IR_TARGET_PATH:-}"
HOSTNAME_N="${IR_HOST:-$(hostname)}"
QUARANTINE_URI="${IR_QUARANTINE_URI:-}"     # e.g. s3://ir-quarantine
MAX_SIZE="${IR_MAX_ACQUIRE_BYTES:-104857600}"  # 100 MB cap
WORK_DIR="/var/ir/acquire/${INCIDENT_ID}"

logger -t ir-playbook "ACQUIRE: incident ${INCIDENT_ID} target ${TARGET_PATH}"

# -- Path safety: refuse OS-critical files, traversal, wildcards ---------------
DENY=("/etc/shadow" "/etc/gshadow" "/etc/sudoers" "/etc/ssh/" "/proc/" "/sys/" "/dev/" "/boot/" "/root/.ssh/")
fail() { echo "ACQUIRE-REFUSED: $1" >&2; logger -t ir-playbook "ACQUIRE-REFUSED: $1"; exit 2; }

[[ -z "${TARGET_PATH}" ]] && fail "no target path"
[[ "${TARGET_PATH}" == *"*"* || "${TARGET_PATH}" == *"?"* ]] && fail "wildcard not allowed"
[[ "${TARGET_PATH}" == *".."* ]] && fail "path traversal not allowed"
REAL_PATH="$(readlink -f -- "${TARGET_PATH}" 2>/dev/null || echo "${TARGET_PATH}")"
for d in "${DENY[@]}"; do
    [[ "${REAL_PATH}" == "${d}"* || "${REAL_PATH}" == *"${d}"* ]] && fail "OS-critical path ${d}"
done
[[ -f "${REAL_PATH}" ]] || fail "not a regular file: ${REAL_PATH}"

# -- Size cap ------------------------------------------------------------------
SIZE="$(stat -c%s -- "${REAL_PATH}")"
(( SIZE > MAX_SIZE )) && fail "file exceeds size cap (${SIZE} > ${MAX_SIZE})"

mkdir -p "${WORK_DIR}"
FILENAME="$(basename -- "${REAL_PATH}")"
SHA256="$(sha256sum -- "${REAL_PATH}" | cut -d' ' -f1)"

# -- Package (zip) for safe transport - the sample is read/copied, never run ---
ARTIFACT="${WORK_DIR}/${FILENAME}.zip"
zip -j -q "${ARTIFACT}" "${REAL_PATH}"

# -- Manifest (the chain-of-custody record the intake service verifies) --------
MANIFEST="${WORK_DIR}/manifest.json"
cat > "${MANIFEST}" <<JSON
{
  "incident_id": "${INCIDENT_ID}",
  "host": "${HOSTNAME_N}",
  "src_path": "${REAL_PATH}",
  "filename": "${FILENAME}",
  "sha256": "${SHA256}",
  "size": ${SIZE},
  "os_family": "linux",
  "acquired_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

# -- Upload to the quarantine bucket (if configured) ---------------------------
if [[ -n "${QUARANTINE_URI}" ]] && command -v aws >/dev/null 2>&1; then
    aws s3 cp "${ARTIFACT}" "${QUARANTINE_URI}/${INCIDENT_ID}/${FILENAME}.zip" --only-show-errors
    aws s3 cp "${MANIFEST}" "${QUARANTINE_URI}/${INCIDENT_ID}/manifest.json"   --only-show-errors
fi

echo "ACQUIRE-OK: ${ARTIFACT} sha256=${SHA256} size=${SIZE}"
logger -t ir-playbook "ACQUIRE-OK: ${FILENAME} sha256=${SHA256}"
