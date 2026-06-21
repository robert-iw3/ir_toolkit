#!/usr/bin/env bash
# ==============================================================================
# Analyze-Memory-Linux.sh — single-run Linux memory analysis.
#
# Spins up an EPHEMERAL Python venv with Volatility 3, builds the kernel symbol
# table (ISF), runs analyze_memory_linux.py against the image, writes
# Memory_Findings_<stamp>.json (optionally merging into Combined_Findings and
# re-adjudicating), then TEARS the whole analysis environment down — leaving only
# the findings behind.
#
# Usage:
#   Analyze-Memory-Linux.sh --image PATH [--host-folder DIR] [--symbols DIR]
#                           [--kernel VER] [--yara] [--adjudicate]
#                           [--keep-env] [--dry-run] [--quiet]
#
#   --symbols DIR   use a prebuilt ISF dir (skip building)
#   --kernel VER    target kernel for symbol build (default: uname -r — set this if the
#                   image is from a different kernel than the analyst box)
#   --fetch-symbols acquire kernel debug symbols cross-distro: debuginfod (any distro) then
#                   the distro package manager (apt/dnf/zypper). Alias: --install-dbgsym.
#   --build-id HEX  kernel build-id for debuginfod when analyzing another host's image
#   --yara          YARA-scan memory with the staged tools/yara_rules
#   --adjudicate    merge findings into the newest Combined_Findings + re-run adjudicate.py
#   --keep-env      do NOT tear down the venv/symbols (for debugging)
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/analyze_memory_linux.py"
SYM_BUILDER="${SCRIPT_DIR}/Build-LinuxSymbols.sh"
ADJUDICATOR="${SCRIPT_DIR}/adjudicate.py"

IMAGE=""; HOST_FOLDER=""; SYMBOLS=""; KERNEL="$(uname -r)"; BUILD_ID=""; DBGD_URLS=""
YARA=0; ADJUDICATE=0; KEEP=0; DRYRUN=0; QUIET=0; FETCH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)       IMAGE="$2"; shift 2 ;;
        --host-folder) HOST_FOLDER="$2"; shift 2 ;;
        --symbols)     SYMBOLS="$2"; shift 2 ;;
        --kernel)      KERNEL="$2"; shift 2 ;;
        --build-id)    BUILD_ID="$2"; shift 2 ;;            # kernel build-id for debuginfod (cross-host images)
        --debuginfod-urls) DBGD_URLS="$2"; shift 2 ;;
        --yara)        YARA=1; shift ;;
        --adjudicate)  ADJUDICATE=1; shift ;;
        --fetch-symbols|--install-dbgsym) FETCH=1; shift ;;  # debuginfod + distro pkg mgr (sudo)
        --keep-env)    KEEP=1; shift ;;
        --dry-run)     DRYRUN=1; shift ;;
        --quiet)       QUIET=1; shift ;;
        -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

log() { [[ $QUIET -eq 1 ]] || echo "[mem-analysis] $*"; }

[[ -z "$IMAGE" ]] && { echo "ERROR: --image required" >&2; exit 2; }
[[ -f "$IMAGE" ]] || { echo "ERROR: image not found: $IMAGE" >&2; exit 2; }
case "$(basename "$IMAGE")" in
    INVALID_*) echo "ERROR: refusing to analyze a truncated INVALID_ image" >&2; exit 2 ;;
esac
HOST_FOLDER="${HOST_FOLDER:-$(dirname "$IMAGE")}"
PY="$(command -v python3 || command -v python)"
STAMP="$(date +%Y%m%d_%H%M%S)"

WORKENV=""; SYMTMP=""
cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        log "--keep-env: leaving venv=${WORKENV:-none} symbols=${SYMTMP:-none}"
        return
    fi
    [[ -n "$WORKENV" && -d "$WORKENV" ]] && rm -rf "$WORKENV"
    [[ -n "$SYMTMP"  && -d "$SYMTMP"  ]] && rm -rf "$SYMTMP"
    log "analysis environment torn down (findings retained)."
}
trap cleanup EXIT INT TERM

log "image=${IMAGE} -> ${HOST_FOLDER} | kernel=${KERNEL} | yara=${YARA}"

if [[ $DRYRUN -eq 1 ]]; then
    log "DRY RUN — plan:"
    log "  1. python -m venv <tmp>; pip install volatility3 yara-python"
    log "  2. ${SYM_BUILDER} --kernel ${KERNEL}  (unless --symbols given)"
    log "  3. ${ANALYZER} --image ${IMAGE} --output-dir ${HOST_FOLDER} --stamp ${STAMP}$([[ $YARA -eq 1 ]] && echo ' --yara')"
    [[ $ADJUDICATE -eq 1 ]] && log "  4. merge -> Combined_Findings + ${ADJUDICATOR}"
    log "  5. teardown venv + temp symbols"
    echo "${HOST_FOLDER}/Memory_Findings_${STAMP}.json"
    exit 0
fi

# -- 1. ephemeral venv + Volatility 3 --
WORKENV="$(mktemp -d /tmp/ir-mem-venv.XXXXXX)"
log "creating venv -> ${WORKENV}"
"$PY" -m venv "$WORKENV" || { echo "venv creation failed" >&2; exit 1; }
# shellcheck disable=SC1091
source "${WORKENV}/bin/activate"
pip install --quiet --upgrade pip >/dev/null 2>&1 || true
WHEELS="${SCRIPT_DIR}/../../../tools/vol3_wheels"
if compgen -G "${WHEELS}/*.whl" >/dev/null 2>&1; then
    log "installing volatility3 from staged wheels (offline)…"
    pip install --quiet --no-index --find-links "$WHEELS" volatility3 yara-python >/dev/null 2>&1 \
        || pip install --quiet volatility3 yara-python >/dev/null 2>&1
else
    log "installing volatility3 (+ yara-python) from PyPI — this can take a minute…"
    pip install --quiet volatility3 yara-python >/dev/null 2>&1
fi
if ! python -c "import volatility3" 2>/dev/null; then
    echo "volatility3 not installed (no staged wheels and no internet)" >&2
    exit 1
fi
VOL="$(command -v vol || command -v volatility3 || true)"
log "volatility: ${VOL:-(module) python -m volatility3}"

# -- 2. kernel symbols (ISF) --
# Prefer a symbol dir pre-staged offline by Build-OfflineToolkit-Linux.sh --stage-symbols.
STAGED_SYMS="${SCRIPT_DIR}/../../../tools/symbols"
if [[ -z "$SYMBOLS" ]] && compgen -G "${STAGED_SYMS}/linux/*.json" >/dev/null 2>&1; then
    SYMBOLS="$(cd "$STAGED_SYMS" && pwd)"
    log "using staged offline symbols -> ${SYMBOLS}"
fi
if [[ -z "$SYMBOLS" ]]; then
    SYMTMP="$(mktemp -d /tmp/ir-mem-syms.XXXXXX)"
    log "building kernel symbols for ${KERNEL}..."
    SB_ARGS=(--kernel "$KERNEL" --out "$SYMTMP")
    [[ $FETCH -eq 1 ]] && SB_ARGS+=(--fetch-symbols)
    [[ -n "$BUILD_ID" ]] && SB_ARGS+=(--build-id "$BUILD_ID")
    [[ -n "$DBGD_URLS" ]] && SB_ARGS+=(--debuginfod-urls "$DBGD_URLS")
    [[ $QUIET -eq 1 ]] && SB_ARGS+=(--quiet)
    if built="$(bash "$SYM_BUILDER" "${SB_ARGS[@]}" | tail -1)" \
       && [[ -n "$built" && -d "$built" ]]; then
        SYMBOLS="$built"
        log "symbols -> ${SYMBOLS}"
    else
        log "symbol build failed — continuing; Volatility will try its bundled ISF cache."
        log "If linux.pslist reports 'no suitable symbols', install linux-image-${KERNEL}-dbgsym and re-run."
        SYMBOLS=""
    fi
fi

# -- 3. analyze (inside the venv) --
ARGS=(--image "$IMAGE" --output-dir "$HOST_FOLDER" --stamp "$STAMP")
[[ -n "$SYMBOLS" ]] && ARGS+=(--symbols "$SYMBOLS")
[[ $YARA -eq 1 ]] && ARGS+=(--yara)
[[ $QUIET -eq 1 ]] && ARGS+=(--quiet)
log "running analyzer..."
python "$ANALYZER" "${ARGS[@]}" || log "analyzer returned non-zero (see output)."
MEM_FINDINGS="${HOST_FOLDER}/Memory_Findings_${STAMP}.json"
deactivate 2>/dev/null || true

# -- 4. optional: merge into Combined_Findings + re-adjudicate (system python) --
if [[ $ADJUDICATE -eq 1 && -f "$MEM_FINDINGS" ]]; then
    COMBINED="$(ls -1t "${HOST_FOLDER}"/Combined_Findings_*.json 2>/dev/null | head -1)"
    if [[ -n "$COMBINED" ]]; then
        log "merging memory findings into $(basename "$COMBINED") + re-adjudicating..."
        "$PY" - "$COMBINED" "$MEM_FINDINGS" <<'PYMERGE'
import json, sys
combined, mem = sys.argv[1], sys.argv[2]
def load(p):
    try:
        with open(p, encoding="utf-8-sig") as fh:
            d = json.load(fh); return d if isinstance(d, list) else [d]
    except Exception: return []
merged = load(combined) + load(mem)
with open(combined, "w") as fh: json.dump(merged, fh, indent=2)
print(f"merged {len(merged)} finding(s)")
PYMERGE
        if [[ -f "$ADJUDICATOR" ]]; then
            "$PY" "$ADJUDICATOR" --host-folder "$HOST_FOLDER" --report "$COMBINED" \
                --stamp "$STAMP" >/dev/null 2>&1 \
                && log "re-adjudicated -> Adjudication_${STAMP}.json" || log "adjudication failed."
        fi
    fi
fi

log "done -> ${MEM_FINDINGS}"
echo "$MEM_FINDINGS"
# trap cleanup tears the environment down on exit
