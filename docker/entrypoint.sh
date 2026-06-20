#!/usr/bin/env bash
# Entrypoint for the ephemeral cloud-IR container. Translates the templated IR_*
# configuration (env / --env-file) into an Invoke-IRCollection-Cloud.sh invocation,
# runs the collection, and (when evidence shipped to cloud storage) wipes local scratch
# so the container leaves no trace behind.
set -euo pipefail

TOOLKIT="${IR_TOOLKIT_DIR:-/opt/ir-toolkit}"
COLLECTOR="${TOOLKIT}/Invoke-IRCollection-Cloud.sh"

: "${IR_PROVIDER:?set IR_PROVIDER=aws|azure|gcp}"
: "${IR_TARGET:?set IR_TARGET=<instance ip / name / id>}"

WORKDIR="${IR_WORKDIR:-/work}"

args=(--provider "$IR_PROVIDER" --target "$IR_TARGET" --output-root "$WORKDIR")
[[ -n "${IR_REGION:-}" ]]                  && args+=(--region "$IR_REGION")
[[ -n "${IR_INCIDENT_ID:-}" ]]             && args+=(--incident-id "$IR_INCIDENT_ID")
[[ -n "${IR_C2_IPS:-}" ]]                  && args+=(--c2-ips "$IR_C2_IPS")
[[ -n "${IR_C2_DOMAINS:-}" ]]              && args+=(--c2-domains "$IR_C2_DOMAINS")
[[ "${IR_CONTAIN:-0}" == "1" ]]            && args+=(--contain)
[[ "${IR_SNAPSHOT_DISKS:-0}" == "1" ]]     && args+=(--snapshot-disks)
[[ -n "${IR_EVIDENCE_BUCKET:-}" ]]         && args+=(--evidence-bucket "$IR_EVIDENCE_BUCKET")
[[ "${IR_PROVISION_EVIDENCE:-0}" == "1" ]] && args+=(--provision-evidence)
[[ -n "${IR_EVIDENCE_RETENTION_DAYS:-}" ]] && args+=(--evidence-retention-days "$IR_EVIDENCE_RETENTION_DAYS")
[[ -n "${IR_EVIDENCE_CONTAINER:-}" ]]      && args+=(--evidence-container "$IR_EVIDENCE_CONTAINER")
[[ "${IR_LLM_REVIEW:-0}" == "1" ]]         && args+=(--llm-review)
[[ "${IR_SKIP_REPORTS:-0}" == "1" ]]       && args+=(--skip-reports)

# Dry run: print the exact command (quoted) and exit. Used by tests and for review.
if [[ "${IR_DRY_RUN:-0}" == "1" ]]; then
    printf 'bash %s' "$COLLECTOR"
    printf ' %q' "${args[@]}"
    printf '\n'
    exit 0
fi

mkdir -p "$WORKDIR"
echo "[entrypoint] cloud IR: provider=${IR_PROVIDER} target=${IR_TARGET} " \
     "evidence=${IR_EVIDENCE_BUCKET:-<none>}"
set +e
bash "$COLLECTOR" "${args[@]}"
rc=$?
set -e

# Ephemeral hygiene: once evidence is in locked-down cloud storage, wipe the local
# scratch so nothing collection-related remains in the (throwaway) container layer.
if [[ -n "${IR_EVIDENCE_BUCKET:-}" && "${IR_WIPE_WORKDIR:-1}" == "1" ]]; then
    rm -rf "${WORKDIR:?}/"* 2>/dev/null || true
    echo "[entrypoint] local scratch wiped — traces remain only in cloud storage."
fi
exit "$rc"
