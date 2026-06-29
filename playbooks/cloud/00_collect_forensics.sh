#!/usr/bin/env bash
# ==============================================================================
# IR Cloud Playbook 00 - Cloud Forensic Collection (dispatcher)
#
# Pulls telemetry from cloud provider APIs for the incident window and writes
# artifacts to /tmp/ir/. The per-provider logic lives in collect/<provider>.sh and
# the shared helpers in collect/lib.sh, so no single file is a monolith.
#
# Supports: AWS, Azure, GCP (auto-detected from IR_CLOUD_PROVIDER)
#
# Environment variables:
#   IR_INCIDENT_ID          Incident ID for artifact naming
#   IR_CLOUD_PROVIDER       aws | azure | gcp
#   IR_TARGET               IP address or cloud resource identifier
#   IR_C2_IPS               Comma-separated attacker IPs
#   IR_LOOKBACK_HOURS / IR_WINDOW_START / IR_WINDOW_END   incident window
#   IR_ALL_REGIONS          AWS: sweep every enabled region (1)
#   IR_AWS_REGION           (AWS)         IR_GCP_PROJECT  (GCP)
#   IR_AZURE_SUBSCRIPTION / IR_AZURE_RESOURCE_GROUP       (Azure)
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT_DIR="${SCRIPT_DIR}/collect"

# shellcheck source=collect/lib.sh
source "${COLLECT_DIR}/lib.sh"

# -- Dispatch: source the provider module, run its pre-flight then collection ----
case "${PROVIDER}" in
    aws)
        # shellcheck source=collect/aws.sh
        source "${COLLECT_DIR}/aws.sh";   preflight_aws;   collect_aws   ;;
    azure)
        # shellcheck source=collect/azure.sh
        source "${COLLECT_DIR}/azure.sh"; preflight_azure; collect_azure ;;
    gcp)
        # shellcheck source=collect/gcp.sh
        source "${COLLECT_DIR}/gcp.sh";   preflight_gcp;   collect_gcp   ;;
    *)
        log "Unknown cloud provider: ${PROVIDER}"; emit_json "forensics" "skipped"; exit 0 ;;
esac

# Write artifact index
ls -lh "${ARTIFACT_DIR}/" > "${ARTIFACT_DIR}/artifact_index.txt" 2>/dev/null || true
log "Artifacts written to ${ARTIFACT_DIR}/"
emit_json "forensics" "success"
