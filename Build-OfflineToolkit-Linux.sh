#!/usr/bin/env bash
# ==============================================================================
# Build-OfflineToolkit-Linux.sh — stage OPTIONAL third-party tools for the Linux
# and cloud IR workflow BEFORE going to an isolated host. Run on an
# INTERNET-CONNECTED machine. The Linux twin of Build-OfflineToolkit.ps1.
#
# The core workflow (Invoke-IRCollection-Linux.sh) needs only python3 + coreutils
# and runs fully offline. This stages the DEPTH tools the isolated host can't fetch:
#
#   AVML            -> Linux volatile-memory acquisition (single static binary),
#                      used by --capture-memory in the Linux collector
#   LOLDrivers list -> vulnerable-driver catalog (offline-usable)
#   cloud CLIs      -> aws / az / gcloud are required for the CLOUD workflow; they
#                      are too large to bundle, so their presence + version is
#                      RECORDED here and install hints emitted if missing
#
# Everything lands in <toolkit>/tools/ with a sha256 manifest. The workflow
# auto-detects and uses what is present and silently skips what is not.
#
# Usage:
#   ./Build-OfflineToolkit-Linux.sh [--tools-dir DIR] [--include-memory]
#                                   [--include-cloud] [--check-only]
#   --check-only   record presence/versions + write the manifest WITHOUT downloading
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"
INCLUDE_MEMORY=0
INCLUDE_CLOUD=0
CHECK_ONLY=0
AVML_URL="https://github.com/microsoft/avml/releases/latest/download/avml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tools-dir)     TOOLS_DIR="$2"; shift 2 ;;
        --include-memory) INCLUDE_MEMORY=1; shift ;;
        --include-cloud) INCLUDE_CLOUD=1; shift ;;
        --check-only)    CHECK_ONLY=1; shift ;;
        --avml-url)      AVML_URL="$2"; shift 2 ;;
        -h|--help)       grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$TOOLS_DIR"
MANIFEST="${TOOLS_DIR}/STAGED_MANIFEST.json"
FETCH="$(command -v curl >/dev/null 2>&1 && echo curl || echo wget)"
_entries=()

record() {  # name, source, file(or-empty), status
    local name="$1" source="$2" file="$3" status="$4" sha="" bytes=""
    if [[ -n "$file" && -f "$file" ]]; then
        sha="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
        bytes="$(stat -c%s "$file" 2>/dev/null || echo 0)"
    fi
    _entries+=("$(printf '{"name":"%s","source":"%s","file":"%s","sha256":"%s","bytes":"%s","status":"%s"}' \
        "$name" "$source" "$(basename "${file:-}")" "$sha" "$bytes" "$status")")
    echo "[*] ${name}: ${status}"
}

download() {  # url, dest
    if [[ "$FETCH" == "curl" ]]; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi
}

# --- AVML: Linux memory acquisition -------------------------------------------
if [[ $INCLUDE_MEMORY -eq 1 ]]; then
    dst="${TOOLS_DIR}/avml"
    if [[ $CHECK_ONLY -eq 1 ]]; then
        [[ -f "$dst" ]] && record "AVML" "$AVML_URL" "$dst" "present" || record "AVML" "$AVML_URL" "" "not-staged"
    elif download "$AVML_URL" "$dst" 2>/dev/null; then
        chmod +x "$dst"; record "AVML" "$AVML_URL" "$dst" "ok"
    else
        record "AVML" "$AVML_URL" "" "failed"
    fi
fi

# --- LOLDrivers vulnerable-driver list ----------------------------------------
dst="${TOOLS_DIR}/loldrivers.json"
if [[ $CHECK_ONLY -eq 1 ]]; then
    [[ -f "$dst" ]] && record "LOLDrivers" "loldrivers.io" "$dst" "present" || record "LOLDrivers" "loldrivers.io" "" "not-staged"
elif download "https://www.loldrivers.io/api/drivers.json" "$dst" 2>/dev/null; then
    record "LOLDrivers" "loldrivers.io/api/drivers.json" "$dst" "ok"
else
    record "LOLDrivers" "loldrivers.io" "" "failed"
fi

# --- Cloud CLIs: required for the cloud workflow; record presence + versions --
if [[ $INCLUDE_CLOUD -eq 1 || $CHECK_ONLY -eq 1 ]]; then
    for cli in aws az gcloud; do
        if command -v "$cli" >/dev/null 2>&1; then
            ver="$("$cli" --version 2>&1 | head -1 | tr -d '"' | cut -c1-40)"
            record "cloud:${cli}" "system" "" "present (${ver})"
        else
            record "cloud:${cli}" "system" "" "MISSING — install before running the cloud workflow"
        fi
    done
fi

# --- Manifest -----------------------------------------------------------------
{
    printf '{\n  "generated_utc": "%s",\n  "tools_dir": "%s",\n  "tools": [\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TOOLS_DIR"
    for i in "${!_entries[@]}"; do
        printf '    %s%s\n' "${_entries[$i]}" "$([[ $i -lt $((${#_entries[@]}-1)) ]] && echo ,)"
    done
    printf '  ]\n}\n'
} > "$MANIFEST"

echo "=== Linux toolkit staging complete -> ${TOOLS_DIR} ==="
echo "[i] Core Linux workflow runs offline WITHOUT these; they enable optional depth."
echo "[i] Cloud workflow REQUIRES aws/az/gcloud (see manifest for presence)."
