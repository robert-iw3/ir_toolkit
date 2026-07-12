#!/usr/bin/env bash
# ==============================================================================
# Analyze-Memory-Linux.sh - single-run Linux memory analysis.
#
# Spins up an EPHEMERAL Python venv with Volatility 3, builds the kernel symbol
# table (ISF), runs analyze_memory_linux.py against the image, writes
# Memory_Findings_<stamp>.json (optionally merging into Combined_Findings and
# re-adjudicating), then TEARS the whole analysis environment down - leaving only
# the findings behind.
#
# Usage:
#   Analyze-Memory-Linux.sh --image PATH [--host-folder DIR] [--symbols DIR]
#                           [--kernel VER] [--yara] [--yara-engine native|vol]
#                           [--yara-broad] [--yara-proc-timeout S] [--carve] [--adjudicate]
#                           [--keep-env] [--dry-run] [--quiet]
#
#   --symbols DIR   use a prebuilt ISF dir (skip building)
#   --kernel VER    target kernel for symbol build (default: uname -r - set this if the
#                   image is from a different kernel than the analyst box)
#   --fetch-symbols acquire kernel debug symbols cross-distro: debuginfod (any distro) then
#                   the distro package manager (apt/dnf/zypper). Alias: --install-dbgsym.
#   --allow-closest-symbols   if the EXACT target kernel's debug-symbols package isn't
#                   published yet, use the closest available point-release instead of
#                   failing. Opt-in only: symbol ADDRESSES may not exactly match the
#                   analyzed kernel, so symbol-address-dependent findings (syscall/
#                   proto-handler hook checks, hidden-process comparisons) may include
#                   false positives -- corroborate independently. The sidecar
#                   _symbols_<stamp>.json records "approximate": true plus both the
#                   requested and actually-used kernel version when this fires.
#   --build-id HEX  kernel build-id for debuginfod when analyzing another host's image
#   --yara          YARA-scan memory with the staged tools/yara_rules (Linux-applicable rules only)
#   --yara-engine   native (default) = fast full-image scan, full physical coverage, no per-PID;
#                   vol = per-process worker, PER-PID attribution + per-process timeout + rolling
#                   resumable JSONL (slower; scans mapped process memory). Both write a live
#                   rolling _yara_results_<stamp>.jsonl + a _yara_results_<stamp>.json summary.
#   --yara-broad    also include platform-generic rules (broader but noisier). Default: Linux-only.
#   --yara-proc-timeout S   vol engine: per-process scan timeout in seconds (default 180)
#   --carve         KEEP carved true-positive injected regions in tools/binja/data/<stamp>/ for
#                   Binary Ninja RE. Injected (anon+exec) regions are ALWAYS carved + string-scanned
#                   for C2/exfil/crypto/cred IOCs (memory_enrich); without --carve the raw bytes are
#                   DELETED after enrichment (they are potential live malware).
#   --adjudicate    merge findings into the newest Combined_Findings + re-run adjudicate.py
#   --keep-env      do NOT tear down the venv/symbols (for debugging)
#   --identify-kernel   don't analyze -- scan the image for kernel version banners
#                   (vol's banners.Banners: works without ANY symbols, exactly for this
#                   bootstrapping problem) and print candidates sorted by offset, then
#                   exit. The analyst machine and the compromised host are essentially
#                   always different systems in real IR work, so --kernel's default
#                   (this machine's own `uname -r`) is very often wrong for a real
#                   target image -- use this first to find the actual value, review the
#                   candidates yourself (lowest offset is typically the running kernel;
#                   this is a strong heuristic, not proof -- e.g. a stale /boot/vmlinuz-*
#                   file sitting in page cache produces a plausible-looking but WRONG
#                   entry too), then pass the confirmed version via --kernel explicitly.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/analyze_memory_linux.py"
SYM_BUILDER="${SCRIPT_DIR}/Build-LinuxSymbols.sh"
ADJUDICATOR="${SCRIPT_DIR}/adjudicate.py"

IMAGE=""; HOST_FOLDER=""; SYMBOLS=""; KERNEL="$(uname -r)"; KERNEL_EXPLICIT=0; BUILD_ID=""; DBGD_URLS=""
YARA=0; ADJUDICATE=0; KEEP=0; DRYRUN=0; QUIET=0; FETCH=0; YARA_SCOPE=""; YARA_TIMEOUT=""
YARA_ENGINE=""; YARA_BROAD=0; YARA_PROC_TIMEOUT=""; CARVE=0; CARVE_DIR=""; IDENTIFY_KERNEL=0
ALLOW_CLOSEST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)       IMAGE="$2"; shift 2 ;;
        --host-folder) HOST_FOLDER="$2"; shift 2 ;;
        --symbols)     SYMBOLS="$2"; shift 2 ;;
        --kernel)      KERNEL="$2"; KERNEL_EXPLICIT=1; shift 2 ;;
        --identify-kernel) IDENTIFY_KERNEL=1; shift ;;
        --build-id)    BUILD_ID="$2"; shift 2 ;;             # kernel build-id for debuginfod (cross-host images)
        --debuginfod-urls) DBGD_URLS="$2"; shift 2 ;;
        --yara)        YARA=1; shift ;;
        --yara-engine) YARA_ENGINE="$2"; shift 2 ;;          # native (default, fast) | vol (attributed)
        --yara-broad)  YARA_BROAD=1; shift ;;                # also scan platform-generic rules (slower)
        --yara-scope)  YARA_SCOPE="$2"; shift 2 ;;           # vol engine: process | full
        --yara-timeout) YARA_TIMEOUT="$2"; shift 2 ;;
        --yara-proc-timeout) YARA_PROC_TIMEOUT="$2"; shift 2 ;;  # vol engine: per-process timeout (s)
        --carve)       CARVE=1; shift ;;                     # KEEP carved TP regions for Binary Ninja
        --carve-dir)   CARVE_DIR="$2"; shift 2 ;;            # override carve output dir
        --adjudicate)  ADJUDICATE=1; shift ;;
        --fetch-symbols|--install-dbgsym) FETCH=1; shift ;;  # debuginfod + distro pkg mgr (sudo)
        --allow-closest-symbols) ALLOW_CLOSEST=1; shift ;;   # opt-in closest-point-release fallback
        --keep-env)    KEEP=1; shift ;;
        --dry-run)     DRYRUN=1; shift ;;
        --quiet)       QUIET=1; shift ;;
        -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

log() { [[ $QUIET -eq 1 ]] || echo "[mem-analysis] $*"; }

# Sort banners.Banners' "<hex-offset>\t<banner text>" TSV rows numerically by offset
# (ascending -- lowest first). Plain `sort` on a hex string is lexicographic, not
# numeric, and gives the wrong order once offsets have different digit counts; bash's
# own `printf %d` parses a "0x..." string correctly and portably (no gawk dependency
# for strtonum()). Reads stdin, writes stdin unchanged, only reordered.
_sort_banners_by_offset() {
    while IFS=$'\t' read -r off banner; do
        printf '%020d\t%s\t%s\n' "$off" "$off" "$banner"
    done | sort -n | cut -f2-
}

# Resolve a staged offline ISF dir against the EXACT target kernel (Build-LinuxSymbols.sh
# names its output "<staged_syms>/linux/<kernel>.json") -- a kernel-version mismatch here
# does not error out, it silently produces false rootkit findings (see the caller's
# comment). Prints two lines: the resolved symbols dir (empty if no exact match), then the
# basename of a stale/mismatched staged file if one was found and ignored (empty if none).
_resolve_staged_symbols() {
    local staged_syms="$1" kernel="$2"
    if [[ -f "${staged_syms}/linux/${kernel}.json" ]]; then
        (cd "$staged_syms" && pwd)
        echo ""
    elif compgen -G "${staged_syms}/linux/*.json" >/dev/null 2>&1; then
        echo ""
        basename "$(ls "${staged_syms}"/linux/*.json 2>/dev/null | head -1)"
    else
        echo ""
        echo ""
    fi
}

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
if [[ $KERNEL_EXPLICIT -eq 0 && $IDENTIFY_KERNEL -eq 0 ]]; then
    log "WARNING: --kernel not given -- defaulting to THIS machine's own kernel (${KERNEL})."
    log "         In real IR work the analyst machine and the compromised host are almost"
    log "         always different systems, so this default is very often WRONG for a real"
    log "         target image and will silently produce false rootkit-shaped findings"
    log "         (see DETAILED-FOLLOW-ON-LINUX.md's FP-pattern table). Run with"
    log "         --identify-kernel first if you don't already know the target's kernel."
fi

if [[ $DRYRUN -eq 1 ]]; then
    log "DRY RUN - plan:"
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
    log "installing volatility3 (+ yara-python) from PyPI - this can take a minute…"
    pip install --quiet volatility3 yara-python >/dev/null 2>&1
fi
if ! python -c "import volatility3" 2>/dev/null; then
    echo "volatility3 not installed (no staged wheels and no internet)" >&2
    exit 1
fi
VOL="$(command -v vol || command -v volatility3 || true)"
log "volatility: ${VOL:-(module) python -m volatility3}"

if [[ $IDENTIFY_KERNEL -eq 1 ]]; then
    log "scanning ${IMAGE} for kernel version banners (no symbols needed for this)…"
    echo "Offset          Banner  (lowest offset first -- typically the running kernel; VERIFY, don't assume)"
    "${VOL:-python -m volatility3}" -f "$IMAGE" banners.Banners 2>/dev/null | tail -n +2 | _sort_banners_by_offset
    log "pick the confirmed version and re-run with --kernel <version> [--fetch-symbols]."
    exit 0
fi

# -- 2. kernel symbols (ISF) --
# Prefer a symbol dir pre-staged offline by Build-OfflineToolkit-Linux.sh --stage-symbols --
# but ONLY if it actually matches the target kernel (Build-LinuxSymbols.sh names its output
# exactly "<KVER>.json"). A real bug found live: this used to accept ANY staged ISF
# regardless of kernel version, so a box patched since the symbols were last staged (e.g.
# staged for 6.17.0-35-generic, now running 6.17.0-40-generic) silently analyzed a FRESH
# capture with a WRONG kernel's symbol table -- --fetch-symbols/--kernel never even ran,
# because this block set SYMBOLS first. Struct-layout-based plugins (pslist/malfind) mostly
# still worked (layouts are often stable across point releases); symbol-ADDRESS-dependent
# plugins (check_syscall, check_afinfo, the pidhashtable-vs-pslist hidden-process compare)
# produced dozens of false rootkit-shaped findings, because the exact addresses baked into
# the stale ISF don't match the running kernel's actual binary.
STAGED_SYMS="${SCRIPT_DIR}/../../../tools/symbols"
if [[ -z "$SYMBOLS" ]]; then
    mapfile -t _resolved < <(_resolve_staged_symbols "$STAGED_SYMS" "$KERNEL")
    SYMBOLS="${_resolved[0]:-}"
    stale="${_resolved[1]:-}"
    if [[ -n "$SYMBOLS" ]]; then
        log "using staged offline symbols for ${KERNEL} -> ${SYMBOLS}"
    elif [[ -n "$stale" ]]; then
        log "WARNING: staged symbols present (${stale}) do NOT match target kernel ${KERNEL} -- ignoring; will fetch/build fresh symbols for ${KERNEL} instead."
    fi
fi
if [[ -z "$SYMBOLS" ]]; then
    [[ $FETCH -eq 0 && -n "${stale:-}" ]] && log "NOTE: no matching staged symbols and --fetch-symbols was not given -- add it (or --symbols/--kernel) to fetch ${KERNEL}'s debug symbols now."
    SYMTMP="$(mktemp -d /tmp/ir-mem-syms.XXXXXX)"
    log "building kernel symbols for ${KERNEL}..."
    SB_ARGS=(--kernel "$KERNEL" --out "$SYMTMP")
    [[ $FETCH -eq 1 ]] && SB_ARGS+=(--fetch-symbols)
    [[ $ALLOW_CLOSEST -eq 1 ]] && SB_ARGS+=(--allow-closest-symbols)
    [[ -n "$BUILD_ID" ]] && SB_ARGS+=(--build-id "$BUILD_ID")
    [[ -n "$DBGD_URLS" ]] && SB_ARGS+=(--debuginfod-urls "$DBGD_URLS")
    [[ $QUIET -eq 1 ]] && SB_ARGS+=(--quiet)
    if built="$(bash "$SYM_BUILDER" "${SB_ARGS[@]}" | tail -1)" \
       && [[ -n "$built" && -d "$built" ]]; then
        SYMBOLS="$built"
        log "symbols -> ${SYMBOLS}"
    else
        log "symbol build failed - continuing; Volatility will try its bundled ISF cache."
        log "If linux.pslist reports 'no suitable symbols', install linux-image-${KERNEL}-dbgsym and re-run."
        SYMBOLS=""
    fi
fi

# Build-LinuxSymbols.sh names its ISF after the kernel version it ACTUALLY used, which
# only differs from $KERNEL when --allow-closest-symbols substituted a closest-available
# point-release (never mislabeled as an exact match -- see its own comments). Detect that
# here from the ISF filename so the substitution is recorded, not just logged to a
# terminal this script's own trap tears down right after.
ACTUAL_KERNEL="$KERNEL"
if [[ -n "$SYMBOLS" && -d "${SYMBOLS}/linux" ]]; then
    _isf="$(ls "${SYMBOLS}/linux"/*.json 2>/dev/null | head -1)"
    [[ -n "$_isf" ]] && ACTUAL_KERNEL="$(basename "$_isf" .json)"
fi
APPROXIMATE="false"
if [[ "$ACTUAL_KERNEL" != "$KERNEL" ]]; then
    APPROXIMATE="true"
    log "WARNING: analyzing with CLOSEST-AVAILABLE kernel ${ACTUAL_KERNEL}, not the requested"
    log "         ${KERNEL} -- symbol addresses may not exactly match; expect possible false"
    log "         positives from symbol-address-dependent findings. Corroborate independently."
fi

# Persist which kernel/symbols this run actually used -- previously only visible in
# terminal output at run time, and this script tears its own environment down after,
# so an analyst re-checking a run's validity later had no record to check. Same
# provenance idea as the YARA canary/_yara_results_<stamp>.json.
mkdir -p "$HOST_FOLDER"
cat > "${HOST_FOLDER}/_symbols_${STAMP}.json" <<EOF
{"kernel": "${KERNEL}", "actual_kernel": "${ACTUAL_KERNEL}", "approximate": ${APPROXIMATE}, "symbols_dir": "${SYMBOLS:-}", "stale_staged_ignored": "${stale:-}"}
EOF

# -- 3. analyze (inside the venv) --
ARGS=(--image "$IMAGE" --output-dir "$HOST_FOLDER" --stamp "$STAMP")
[[ -n "$SYMBOLS" ]] && ARGS+=(--symbols "$SYMBOLS")
[[ $YARA -eq 1 ]] && ARGS+=(--yara)
[[ -n "$YARA_ENGINE" ]] && ARGS+=(--yara-engine "$YARA_ENGINE")
[[ $YARA_BROAD -eq 1 ]] && ARGS+=(--yara-broad)
[[ -n "$YARA_SCOPE" ]] && ARGS+=(--yara-scope "$YARA_SCOPE")
[[ -n "$YARA_TIMEOUT" ]] && ARGS+=(--yara-timeout "$YARA_TIMEOUT")
[[ -n "$YARA_PROC_TIMEOUT" ]] && ARGS+=(--yara-proc-timeout "$YARA_PROC_TIMEOUT")
[[ $CARVE -eq 1 ]] && ARGS+=(--carve)
[[ -n "$CARVE_DIR" ]] && ARGS+=(--carve-dir "$CARVE_DIR")
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
        # Idempotent, content-deduped merge - re-running analysis no longer bloats Combined.
        "$PY" "${SCRIPT_DIR}/../../reporting/merge_findings.py" "$COMBINED" "$MEM_FINDINGS" \
            | sed 's/^/  /' || log "merge failed."
        if [[ -f "$ADJUDICATOR" ]]; then
            "$PY" "$ADJUDICATOR" --host-folder "$HOST_FOLDER" --report "$COMBINED" \
                --stamp "$STAMP" >/dev/null 2>&1 \
                && log "re-adjudicated -> Adjudication_${STAMP}.json" || log "adjudication failed."
        fi
        # Regenerate IOCs + reports so memory/YARA findings reach IOCs.json, Incident_Report.md,
        # and Attack_Graph.md - not just the adjudication. (system python; no venv deps)
        RID="$(basename "$HOST_FOLDER")_${STAMP}"
        REP="${SCRIPT_DIR}/../../reporting"
        [[ -f "${REP}/build_iocs.py" ]] && \
            "$PY" "${REP}/build_iocs.py" --host-folder "$HOST_FOLDER" --incident-id "$RID" --quiet >/dev/null 2>&1 || true
        [[ -f "${REP}/extract_principals.py" ]] && \
            "$PY" "${REP}/extract_principals.py" --host-folder "$HOST_FOLDER" --incident-id "$RID" --quiet >/dev/null 2>&1 || true
        if [[ -f "${REP}/generate_reports.py" ]]; then
            "$PY" "${REP}/generate_reports.py" --host-folder "$HOST_FOLDER" --incident-id "$RID" >/dev/null 2>&1 \
                && log "regenerated Incident_Report + Attack_Graph + IOCs (memory/YARA included)." \
                || log "report regeneration failed."
        fi
    fi
fi

log "done -> ${MEM_FINDINGS}"
echo "$MEM_FINDINGS"
# trap cleanup tears the environment down on exit
