#!/usr/bin/env bash
# ==============================================================================
# Build-OfflineToolkit-Linux.sh - stage OPTIONAL third-party tools for the Linux
# and cloud IR workflow BEFORE going to an isolated host. Run on an
# INTERNET-CONNECTED machine. The Linux twin of Build-OfflineToolkit.ps1.
#
# The core workflow (Invoke-IRCollection-Linux.sh) needs only python3 + coreutils
# and runs fully offline. This stages the DEPTH tools the isolated host can't fetch:
#
#   AVML            -> Linux volatile-memory acquisition (single static binary),
#                      used by --capture-memory in the Linux collector
#   avml-convert    -> decompress snappy LiME images (--compress) for Volatility
#   dwarf2json      -> build the Volatility 3 Linux ISF from a debug vmlinux
#   volatility3     -> memory analyzer wheels (+ yara-python) vendored for an
#                      OFFLINE analyst venv (pip install --no-index)
#   yara_rules      -> rule set used by the memory analyzer's --yara scan (recorded)
#   capa + FLOSS    -> capabilities/ATT&CK + deobfuscated strings, auto-run by
#                      memory_enrich.py over each carved true-positive region
#   LOLDrivers list -> vulnerable-driver catalog (offline-usable)
#   cloud CLIs      -> aws / az / gcloud are required for the CLOUD workflow; they
#                      are too large to bundle, so their presence + version is
#                      RECORDED here and install hints emitted if missing
#
#   --include-memory stages avml + avml-convert + dwarf2json + volatility3 wheels
#                    + capa + FLOSS + the YARA rule packs.
#
# Everything lands in <toolkit>/tools/ with a sha256 manifest. The workflow
# auto-detects and uses what is present and silently skips what is not.
#
# Usage:
#   ./Build-OfflineToolkit-Linux.sh [--tools-dir DIR] [--include-memory]
#                                   [--include-cloud] [--check-only]
#                                   [--stage-symbols [--symbols-kernel VER]]
#   --check-only     record presence/versions + write the manifest WITHOUT downloading
#   --stage-symbols  build the Volatility 3 Linux ISF for a kernel (default: running)
#                    into tools/symbols/ so OFFLINE memory analysis has it (needs the
#                    matching debug vmlinux/dbgsym reachable while still connected)
#
# Every dependency - staged binary, vendored wheel, OR assumed-present system tool -
# is recorded in tools/STAGED_MANIFEST.json so the offline host's inventory is explicit.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"
INCLUDE_MEMORY=0
INCLUDE_CLOUD=0
CHECK_ONLY=0
STAGE_SYMBOLS=0
SYM_KERNEL=""
AVML_URL=""   # default resolved arch-aware after parse; --avml-url overrides

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tools-dir)      TOOLS_DIR="$2"; shift 2 ;;
        --include-memory) INCLUDE_MEMORY=1; shift ;;
        --include-cloud)  INCLUDE_CLOUD=1; shift ;;
        --check-only)     CHECK_ONLY=1; shift ;;
        --stage-symbols)  STAGE_SYMBOLS=1; INCLUDE_MEMORY=1; shift ;;
        --symbols-kernel) SYM_KERNEL="$2"; shift 2 ;;
        --avml-url)       AVML_URL="$2"; shift 2 ;;
        -h|--help)        grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# Arch-aware release asset names (avml + dwarf2json publish per-arch binaries).
case "$(uname -m)" in
    x86_64|amd64)  AV_SFX="";          D2J_ASSET="dwarf2json-linux-amd64" ;;
    aarch64|arm64) AV_SFX="-aarch64";  D2J_ASSET="dwarf2json-linux-arm64" ;;
    *)             AV_SFX="";          D2J_ASSET="dwarf2json-linux-amd64" ;;
esac
AVML_REL="https://github.com/microsoft/avml/releases/latest/download"
AVML_URL="${AVML_URL:-${AVML_REL}/avml${AV_SFX}}"
AVMLCONV_URL="${AVML_REL}/avml-convert${AV_SFX}"
D2J_URL="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/${D2J_ASSET}"
# capa (capabilities/ATT&CK) + FLOSS (deobfuscated strings) — memory_enrich.py auto-runs them over
# each carved true-positive region. Linux standalone release zips (capa bundles its own rules).
CAPA_URL="https://github.com/mandiant/capa/releases/download/v7.4.0/capa-v7.4.0-linux.zip"
FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip"

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

stage_bin() {  # name, url, dest - download + chmod + record (honours --check-only)
    local name="$1" url="$2" dest="$3"
    if [[ $CHECK_ONLY -eq 1 ]]; then
        [[ -f "$dest" ]] && record "$name" "$url" "$dest" "present" || record "$name" "$url" "" "not-staged"
    elif download "$url" "$dest" 2>/dev/null; then
        chmod +x "$dest"; record "$name" "$url" "$dest" "ok"
    else
        record "$name" "$url" "" "failed"
    fi
}

stage_zip_bin() {  # name, url, out_subdir, binary - download zip + unzip + chmod the named binary
    local name="$1" url="$2" subdir="$3" binary="$4"
    local dest="${TOOLS_DIR}/${subdir}/${binary}"
    if [[ $CHECK_ONLY -eq 1 ]]; then
        [[ -f "$dest" ]] && record "$name" "$url" "$dest" "present" || record "$name" "$url" "" "not-staged"
        return
    fi
    if ! command -v unzip >/dev/null 2>&1; then record "$name" "$url" "" "failed (need unzip)"; return; fi
    mkdir -p "${TOOLS_DIR}/${subdir}"
    local zip="${TOOLS_DIR}/${subdir}/.dl.zip"
    if download "$url" "$zip" 2>/dev/null && unzip -o -q "$zip" -d "${TOOLS_DIR}/${subdir}/" 2>/dev/null; then
        rm -f "$zip"; [[ -f "$dest" ]] && chmod +x "$dest"
        [[ -f "$dest" ]] && record "$name" "$url" "$dest" "ok" || record "$name" "$url" "" "failed (binary not in zip)"
    else
        rm -f "$zip"; record "$name" "$url" "" "failed"
    fi
}

# --- Memory acquisition + analysis toolchain ----------------------------------
# avml (capture) + avml-convert (decompress --compress LiME) + dwarf2json (build
# the Volatility 3 Linux ISF) + volatility3 wheels (offline analyzer venv).
if [[ $INCLUDE_MEMORY -eq 1 ]]; then
    stage_bin "AVML"         "$AVML_URL"     "${TOOLS_DIR}/avml"
    stage_bin "avml-convert" "$AVMLCONV_URL" "${TOOLS_DIR}/avml-convert"
    stage_bin "dwarf2json"   "$D2J_URL"      "${TOOLS_DIR}/dwarf2json"
    # capa + FLOSS — memory_enrich.py runs them over carved true-positive regions for
    # capabilities/ATT&CK + deobfuscated strings (encoded C2 plain strings miss).
    stage_zip_bin "capa"  "$CAPA_URL"  "capa"  "capa"
    stage_zip_bin "floss" "$FLOSS_URL" "floss" "floss"

    wheeldir="${TOOLS_DIR}/vol3_wheels"
    if [[ $CHECK_ONLY -eq 1 ]]; then
        if compgen -G "${wheeldir}/*.whl" >/dev/null 2>&1; then
            record "volatility3-wheels" "pypi" "" "present ($(ls "${wheeldir}"/*.whl 2>/dev/null | wc -l) wheels)"
        else
            record "volatility3-wheels" "pypi" "" "not-staged"
        fi
    elif command -v python3 >/dev/null 2>&1 && mkdir -p "$wheeldir" \
         && python3 -m pip download -q volatility3 yara-python -d "$wheeldir" >/dev/null 2>&1; then
        record "volatility3-wheels" "pypi" "" "ok ($(ls "${wheeldir}"/*.whl 2>/dev/null | wc -l) wheels)"
    else
        record "volatility3-wheels" "pypi" "" "failed (analyzer can pip-install online at runtime)"
    fi
fi

# --- YARA rules: community packs + abuse.ch yaraify, staged for the memory --yara scan ---------
# The analyzer (linux_yara.py) filters these to Linux/generic rules and compiles them with the
# externals declared (so they actually load - see analyze_memory_linux.py).
yrules="${TOOLS_DIR}/yara_rules"
stage_yara_pack() {  # name, url, subdir, within(substr filter, "" = flat zip like yaraify)
    local name="$1" url="$2" subdir="$3" within="$4"
    local dest="${yrules}/${subdir}"
    if [[ $CHECK_ONLY -eq 1 ]]; then
        compgen -G "${dest}/*.yar*" >/dev/null 2>&1 \
            && record "yara:${name}" "$url" "" "present ($(find "$dest" \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | wc -l))" \
            || record "yara:${name}" "$url" "" "not-staged"
        return
    fi
    command -v unzip >/dev/null 2>&1 || { record "yara:${name}" "$url" "" "skipped (no unzip)"; return; }
    local zip ex; zip="$(mktemp --suffix=.zip)"; ex="$(mktemp -d)"
    mkdir -p "$dest"
    if download "$url" "$zip" 2>/dev/null && unzip -qo "$zip" -d "$ex" 2>/dev/null; then
        local n=0
        while IFS= read -r -d '' f; do
            [[ -n "$within" && "$f" != *"$within"* ]] && continue
            cp -f "$f" "${dest}/$(basename "$f")" 2>/dev/null && n=$((n+1))
        done < <(find "$ex" \( -name '*.yar' -o -name '*.yara' \) -print0 2>/dev/null)
        record "yara:${name}" "$url" "" "ok (${n} rules)"
    else
        record "yara:${name}" "$url" "" "failed"
    fi
    rm -rf "$zip" "$ex" 2>/dev/null || true
}
if [[ $INCLUDE_MEMORY -eq 1 ]]; then
    stage_yara_pack "abusech-yaraify" "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip" "abusech" ""
    stage_yara_pack "neo23x0" "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip" "neo23x0" "/yara/"
    stage_yara_pack "elastic" "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip" "elastic" "/yara/"
    stage_yara_pack "reversinglabs" "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip" "reversinglabs" "/yara/"
fi
# Overall presence record
if compgen -G "${yrules}/**/*.yar*" >/dev/null 2>&1 || compgen -G "${yrules}/*.yar*" >/dev/null 2>&1; then
    record "yara_rules" "tools/yara_rules" "" "present ($(find "$yrules" \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | wc -l) rules)"
else
    record "yara_rules" "tools/yara_rules" "" "not-staged (use --include-memory to fetch, or add .yar rules)"
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

# --- Kernel symbols (ISF): the one dependency that is kernel-EXACT and can't be
# --- pre-bundled generically. Build it while connected so offline analysis has it. -
if [[ $STAGE_SYMBOLS -eq 1 && $CHECK_ONLY -eq 0 ]]; then
    kv="${SYM_KERNEL:-$(uname -r)}"
    symdir="${TOOLS_DIR}/symbols"
    SYMBUILD="${SCRIPT_DIR}/playbooks/linux/threat_hunting/Build-LinuxSymbols.sh"
    if built="$(bash "$SYMBUILD" --kernel "$kv" --out "$symdir" --fetch-symbols \
                     --dwarf2json "${TOOLS_DIR}/dwarf2json" 2>/dev/null | tail -1)" \
       && [[ -n "$built" && -d "$built" ]]; then
        record "symbols:${kv}" "Build-LinuxSymbols" "$(ls "$symdir"/linux/*.json 2>/dev/null | head -1)" "ok"
    else
        record "symbols:${kv}" "Build-LinuxSymbols" "" "failed (need debug vmlinux/dbgsym for ${kv} while connected)"
    fi
elif [[ $CHECK_ONLY -eq 1 ]]; then
    compgen -G "${TOOLS_DIR}/symbols/linux/*.json" >/dev/null 2>&1 \
        && record "symbols" "tools/symbols" "" "present ($(ls "${TOOLS_DIR}"/symbols/linux/*.json 2>/dev/null | wc -l) ISF)" \
        || record "symbols" "tools/symbols" "" "not-staged (use --stage-symbols; or fetch at analysis time)"
fi

# --- Cloud CLIs: required for the cloud workflow; record presence + versions --
if [[ $INCLUDE_CLOUD -eq 1 || $CHECK_ONLY -eq 1 ]]; then
    for cli in aws az gcloud kubectl terraform tofu; do
        if command -v "$cli" >/dev/null 2>&1; then
            case "$cli" in
                kubectl)           vcmd=(version --client) ;;
                terraform|tofu)    vcmd=(version) ;;
                *)                 vcmd=(--version) ;;
            esac
            ver="$("$cli" "${vcmd[@]}" 2>&1 | head -1 | tr -d '"' | cut -c1-40)"
            record "cloud:${cli}" "system" "" "present (${ver})"
        else
            record "cloud:${cli}" "system" "" "MISSING - install before the cloud workflow (or use the Docker image)"
        fi
    done
fi

# --- System dependency INVENTORY: the toolkit's own Python is stdlib-only; these are
# --- OS tools the workflows shell out to. Recorded so the offline host's needs are explicit. -
if [[ $CHECK_ONLY -eq 1 || $INCLUDE_MEMORY -eq 1 ]]; then
    probe() {  # binary, role
        command -v "$1" >/dev/null 2>&1 \
            && record "sys:$1" "host" "" "present - $2" \
            || record "sys:$1" "host" "" "absent - $2 (install on target if that capability is needed)"
    }
    probe python3   "core: every analyzer/report (stdlib only - no pip deps)"
    probe bash      "core: collection + eradication scripts"
    probe ip        "containment: network isolation"
    probe nft       "containment: firewall (nftables)"
    probe iptables  "containment: firewall (legacy)"
    probe usbguard  "containment: USB device control"
    probe dpkg      "triage: package verification (Debian/Ubuntu)"
    probe rpm       "triage: package verification (RHEL/SUSE)"
    probe debsums   "triage: changed-file detection (Debian)"
    probe getcap    "triage: file capability audit (libcap)"
    if [[ $INCLUDE_MEMORY -eq 1 || $CHECK_ONLY -eq 1 ]]; then
        probe debuginfod-find "memory: universal ISF fetch (elfutils; connected staging)"
        probe dpkg-deb  "memory: extract dbgsym vmlinux without root"
    fi
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
