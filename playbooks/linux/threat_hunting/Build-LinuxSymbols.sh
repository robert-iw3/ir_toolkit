#!/usr/bin/env bash
# ==============================================================================
# Build-LinuxSymbols.sh - generate a Volatility 3 Linux symbol table (ISF) for a
# kernel, so analyze_memory_linux.py can parse a Linux memory image.
#
# Unlike Windows (Volatility auto-fetches PDBs), Linux needs an ISF JSON matching
# the EXACT target-kernel build (struct offsets + symbol addresses + banner). A
# generic vmlinux.h (eBPF CO-RE / BTF header) does NOT work - those types are
# relocated at load time, not version-pinned. dwarf2json cannot read BTF either,
# so we need a DWARF vmlinux. This acquires one across the major distros:
#
#   1. an already-present debug vmlinux (any known path)
#   2. debuginfod  - universal, distro-agnostic fetch by kernel build-id
#   3. the distro package manager (apt/dnf/zypper/apk) debug-symbol package
#
# Usage:
#   Build-LinuxSymbols.sh [--kernel VER] [--out DIR] [--vmlinux PATH]
#                         [--dwarf2json PATH] [--build-id HEX]
#                         [--fetch-symbols|--install-dbgsym] [--debuginfod-urls URLS]
#                         [--quiet]
# Prints the symbol DIRECTORY on the LAST stdout line (point Volatility at it with -s).
# Exit non-zero if no ISF could be produced.
# ==============================================================================
set -uo pipefail

KVER="$(uname -r)"
OUT=""
VMLINUX=""
D2J=""
BUILD_ID=""
DBGD_URLS=""
FETCH=0
QUIET=0

# Distro debuginfod federation (the elfutils server federates many). Respects an
# existing $DEBUGINFOD_URLS (distros set one in /etc/profile.d/debuginfod.sh).
DEFAULT_DEBUGINFOD="https://debuginfod.elfutils.org/ https://debuginfod.ubuntu.com/ \
https://debuginfod.fedoraproject.org/ https://debuginfod.debian.net/ \
https://debuginfod.opensuse.org/ https://debuginfod.archlinux.org/"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)            KVER="$2"; shift 2 ;;
        --out)               OUT="$2"; shift 2 ;;
        --vmlinux)           VMLINUX="$2"; shift 2 ;;
        --dwarf2json)        D2J="$2"; shift 2 ;;
        --build-id)          BUILD_ID="$2"; shift 2 ;;
        --debuginfod-urls)   DBGD_URLS="$2"; shift 2 ;;
        --fetch-symbols|--install-dbgsym) FETCH=1; shift ;;
        --quiet)             QUIET=1; shift ;;
        -h|--help)           grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log() { [[ $QUIET -eq 1 ]] || echo "[symbols] $*" >&2; }
PLAN="${IR_SYMBOLS_PLAN:-0}"   # test seam: print what would run instead of doing it

OUT="${OUT:-$(mktemp -d /tmp/ir-linux-isf.XXXXXX)}"
mkdir -p "${OUT}/linux"

# -- distro detection (no sourcing untrusted file - grep KEY=value) --
OSREL="${IR_OS_RELEASE:-/etc/os-release}"
osrel_get() { awk -F= -v k="$1" '$1==k{gsub(/^"|"$/,"",$2);print $2;exit}' "$OSREL" 2>/dev/null; }
DISTRO_ID="$(osrel_get ID)"
DISTRO_LIKE="$(osrel_get ID_LIKE)"
CODENAME="$(osrel_get VERSION_CODENAME)"

distro_family() {
    local s="${DISTRO_ID} ${DISTRO_LIKE}"
    case " $s " in
        *debian*|*ubuntu*)                              echo debian ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)   echo rhel ;;
        *suse*|*sles*|*opensuse*)                       echo suse ;;
        *arch*)                                         echo arch ;;
        *alpine*)                                       echo alpine ;;
        *) echo unknown ;;
    esac
}
FAMILY="$(distro_family)"
log "distro=${DISTRO_ID:-?} family=${FAMILY} kernel=${KVER}"

# BTF is the kernel-exact type source, but dwarf2json/Volatility can't consume it.
[[ -f /sys/kernel/btf/vmlinux ]] && \
    log "note: /sys/kernel/btf/vmlinux present (kernel-exact) but unusable by dwarf2json - need DWARF."

# -- debug-vmlinux discovery (Debian, RHEL, SUSE, custom build trees) --
find_vmlinux() {
    for c in \
        "/usr/lib/debug/boot/vmlinux-${KVER}" \
        "/usr/lib/debug/boot/vmlinux-${KVER}.debug" \
        "/usr/lib/debug/lib/modules/${KVER}/vmlinux" \
        "/usr/lib/debug/usr/lib/modules/${KVER}/vmlinux" \
        "/usr/lib/debug/lib/modules/${KVER}/vmlinux.debug" \
        "/boot/vmlinux-${KVER}" \
        "/lib/modules/${KVER}/build/vmlinux" \
        "/usr/src/linux-${KVER}/vmlinux"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

# -- running-kernel build-id (NT_GNU_BUILD_ID note), for debuginfod-find --
local_build_id() {
    [[ "$KVER" == "$(uname -r)" && -r /sys/kernel/notes ]] || return 1
    python3 - <<'PY' 2>/dev/null
import struct, sys
try:
    data = open("/sys/kernel/notes", "rb").read()
except OSError:
    sys.exit(1)
off = 0
while off + 12 <= len(data):
    namesz, descsz, ntype = struct.unpack_from("<III", data, off); off += 12
    name = data[off:off+namesz]; off += (namesz + 3) & ~3
    desc = data[off:off+descsz]; off += (descsz + 3) & ~3
    if ntype == 3 and name.rstrip(b"\0") == b"GNU":
        print(desc.hex()); break
PY
}

# -- universal path: debuginfod (any distro with a build-id + network) --
fetch_debuginfod() {
    local bid="${BUILD_ID:-$(local_build_id || true)}"
    if [[ -z "$bid" ]]; then
        log "debuginfod: no kernel build-id (image from another kernel? pass --build-id) - skipping."
        return 1
    fi
    if [[ "$PLAN" == "1" ]]; then
        log "PLAN[debuginfod]: DEBUGINFOD_URLS=<federation> debuginfod-find debuginfo ${bid}"; return 1
    fi
    command -v debuginfod-find >/dev/null 2>&1 || {
        log "debuginfod-find absent (install elfutils debuginfod client) - skipping debuginfod."
        return 1
    }
    export DEBUGINFOD_URLS="${DBGD_URLS:-${DEBUGINFOD_URLS:-$DEFAULT_DEBUGINFOD}}"
    log "debuginfod: fetching debuginfo for build-id ${bid:0:16}…"
    local p
    p="$(debuginfod-find debuginfo "$bid" 2>/dev/null)" && [[ -s "$p" ]] && { echo "$p"; return 0; }
    return 1
}

# -- distro package manager: install the kernel debug-symbol package --
install_debug_pkg() {
    case "$FAMILY" in
        debian)
            local cn="${CODENAME:-$(command -v lsb_release >/dev/null 2>&1 && lsb_release -cs)}"
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[debian]: enable ddebs(${cn:-?}) + apt-get install linux-image-${KVER}-dbgsym"; return 1
            fi
            command -v apt-get >/dev/null 2>&1 || return 1
            [[ -z "$cn" ]] && { log "debian: cannot determine codename"; return 1; }
            log "debian/ubuntu: enabling ddebs + installing linux-image-${KVER}-dbgsym (sudo)…"
            { printf 'deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n' "$cn"
              printf 'deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\n' "$cn"
            } | sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null
            sudo apt-get install -y ubuntu-dbgsym-keyring >/dev/null 2>&1 || true
            sudo apt-get update >/dev/null 2>&1 || true
            sudo apt-get install -y "linux-image-${KVER}-dbgsym" >/dev/null 2>&1
            ;;
        rhel)
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[rhel]: dnf -y --enablerepo='*debug*' debuginfo-install kernel-${KVER}"; return 1
            fi
            local DNF; DNF="$(command -v dnf || command -v yum)" || return 1
            log "rhel/fedora: installing kernel-debuginfo-${KVER} (sudo)…"
            sudo "$DNF" -y --enablerepo='*debug*' debuginfo-install "kernel-${KVER}" >/dev/null 2>&1 \
              || sudo "$DNF" -y --enablerepo='*debug*' install "kernel-debuginfo-${KVER}" >/dev/null 2>&1
            ;;
        suse)
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[suse]: zypper -n install kernel-default-debuginfo (matching ${KVER})"; return 1
            fi
            command -v zypper >/dev/null 2>&1 || return 1
            log "suse: installing kernel-default-debuginfo (sudo)…"
            sudo zypper --non-interactive install -y kernel-default-debuginfo >/dev/null 2>&1
            ;;
        arch)
            log "arch: no official kernel debug package - use debuginfod (debuginfod.archlinux.org)."
            [[ "$PLAN" == "1" ]] && log "PLAN[arch]: (debuginfod only)"
            return 1
            ;;
        alpine)
            log "alpine: kernel DWARF generally unavailable via apk - use debuginfod or a build-tree vmlinux."
            [[ "$PLAN" == "1" ]] && log "PLAN[alpine]: (debuginfod only)"
            return 1
            ;;
        *)
            log "unknown distro family - pass --vmlinux or use --build-id + debuginfod."
            return 1
            ;;
    esac
}

# -- 1. acquire a debug vmlinux --
if [[ -z "$VMLINUX" ]]; then
    VMLINUX="$(find_vmlinux || true)"
fi
if [[ -z "$VMLINUX" && $FETCH -eq 1 ]]; then
    VMLINUX="$(fetch_debuginfod || true)"          # universal first (non-mutating)
    if [[ -z "$VMLINUX" ]]; then
        install_debug_pkg && VMLINUX="$(find_vmlinux || true)"
    fi
fi

if [[ -z "$VMLINUX" || ! -f "$VMLINUX" ]]; then
    log "no debug vmlinux for ${KVER}. Options:"
    log "  • re-run with --fetch-symbols (debuginfod + distro package manager)"
    case "$FAMILY" in
        debian) log "  • Ubuntu/Debian: enable ddebs + apt-get install linux-image-${KVER}-dbgsym" ;;
        rhel)   log "  • RHEL/Fedora:   dnf debuginfo-install kernel-${KVER}" ;;
        suse)   log "  • SUSE:          zypper install kernel-default-debuginfo" ;;
        arch|alpine) log "  • ${FAMILY}: use debuginfod (--fetch-symbols) or a build-tree vmlinux" ;;
    esac
    log "  • any distro:    --build-id <hex> with debuginfod, or --vmlinux <path-with-DWARF>"
    exit 3
fi
log "vmlinux: ${VMLINUX}"

# -- 2. obtain dwarf2json (Go binary from the Volatility Foundation) --
if [[ -z "$D2J" ]]; then
    if command -v dwarf2json >/dev/null 2>&1; then
        D2J="$(command -v dwarf2json)"
    elif [[ -x "${SCRIPT_DIR}/../../../tools/dwarf2json" ]]; then
        D2J="${SCRIPT_DIR}/../../../tools/dwarf2json"
    elif command -v go >/dev/null 2>&1; then
        log "installing dwarf2json via go…"
        GOBIN="${OUT}/bin" go install github.com/volatilityfoundation/dwarf2json@latest >/dev/null 2>&1 \
            && D2J="${OUT}/bin/dwarf2json"
    fi
fi
if [[ -z "$D2J" || ! -x "$D2J" ]]; then
    arch="$(uname -m)"; [[ "$arch" == "x86_64" ]] && arch="amd64"
    url="https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-${arch}"
    log "fetching dwarf2json release binary…"
    if command -v curl >/dev/null 2>&1 && curl -fsSL "$url" -o "${OUT}/dwarf2json" 2>/dev/null; then
        chmod +x "${OUT}/dwarf2json"; D2J="${OUT}/dwarf2json"
    fi
fi
if [[ -z "$D2J" || ! -x "$D2J" ]]; then
    log "dwarf2json not found and could not be obtained. Stage tools/dwarf2json or install Go."
    exit 4
fi
log "dwarf2json: ${D2J}"

# -- 3. generate the ISF (DWARF types + System.map symbols when available) --
SYSMAP="/boot/System.map-${KVER}"
ISF="${OUT}/linux/${KVER}.json"
D2J_ARGS=(linux --elf "$VMLINUX")
# System.map is an OPTIONAL extra symbol source; the debug vmlinux's own .symtab suffices.
# Only add it when actually READABLE (/boot/System.map-* is often root-only mode 600).
if [[ -r "$SYSMAP" ]]; then
    D2J_ARGS+=(--system-map "$SYSMAP")
elif [[ -f "$SYSMAP" ]]; then
    log "System.map present but not readable (root-only) - using vmlinux symbols only."
fi
log "generating ISF -> ${ISF}"
if ! "$D2J" "${D2J_ARGS[@]}" > "$ISF" 2>/dev/null || [[ ! -s "$ISF" ]]; then
    log "dwarf2json failed to produce a symbol table."
    exit 5
fi
log "ISF ready ($(stat -c %s "$ISF" 2>/dev/null || echo 0) bytes)."

# Volatility 3 takes the symbol DIRECTORY (it indexes by banner). Print it last.
echo "$OUT"
