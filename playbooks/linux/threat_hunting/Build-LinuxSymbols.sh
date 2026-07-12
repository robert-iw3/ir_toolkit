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
DISTRO_OVERRIDE=""
ALLOW_CLOSEST=0
ACTUAL_KVER=""   # set when a --allow-closest-symbols substitution was used; empty otherwise

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
        --distro)            DISTRO_OVERRIDE="$2"; shift 2 ;;
        --allow-closest-symbols) ALLOW_CLOSEST=1; shift ;;
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

distro_family() {  # classify $1 (default: this machine's own os-release ID+ID_LIKE)
    local s="${1:-${DISTRO_ID} ${DISTRO_LIKE}}"
    case " $s " in
        *debian*|*ubuntu*)                              echo debian ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)   echo rhel ;;
        *suse*|*sles*|*opensuse*)                       echo suse ;;
        *arch*)                                         echo arch ;;
        *alpine*)                                       echo alpine ;;
        *) echo unknown ;;
    esac
}
NATIVE_FAMILY="$(distro_family)"
# --distro overrides auto-detection -- for a REAL investigation the analyst machine and
# the compromised target are essentially always different systems (you don't fetch
# anything on a system under investigation), so "this machine's own /etc/os-release"
# is frequently NOT the target's distro at all. The override only helps when the
# target's package manager is actually usable from here though (same family, or a
# family whose CLI happens to be installed) -- for a genuinely different family (e.g.
# targeting RHEL from a Debian/Ubuntu analyst box), dnf/zypper simply aren't
# installable as a drop-in the way apt is, and debuginfod (--build-id, distro-agnostic)
# is the only mechanism that was ever going to work cross-family. install_debug_pkg()
# below still checks for the actual binary and fails with that guidance rather than a
# bare "not found" if the override names a family this machine can't act as.
if [[ -n "$DISTRO_OVERRIDE" ]]; then
    FAMILY="$(distro_family "$DISTRO_OVERRIDE")"
    if [[ "$FAMILY" != "$NATIVE_FAMILY" ]]; then
        log "NOTE: --distro ${DISTRO_OVERRIDE} (family=${FAMILY}) differs from this machine's own family (${NATIVE_FAMILY}) -- the package-manager path below only works if that family's CLI is actually installed here. If it's a genuinely different distro family than this machine, --build-id + debuginfod (distro-agnostic) is the reliable path, not the package manager."
    fi
else
    FAMILY="$NATIVE_FAMILY"
fi
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

# Distinguish "the debug-symbols package for this exact kernel isn't published yet"
# (a real, common condition -- a fast-moving release's ddebs archive lags behind its
# main kernel-package updates by several point-releases; confirmed live: this box's
# running 6.17.0-40-generic had no dbgsym anywhere in Ubuntu's ddebs archive while
# .35 was still the newest published) from other failure classes (network down, repo
# unreachable, auth) that get the raw error tail instead. Checked against $1's log text.
_symbols_pkg_not_published_msg() {
    local errtext="$1"
    case "$errtext" in
        *"Unable to locate package"*|*"No package"*"available"*|*"not found"*)
            echo "the debug-symbols package for kernel ${KVER} is not published in this distro's archive yet (a fast-moving release's ddebs/debuginfo build often lags several point-releases behind the running kernel) -- wait for it to be published, or target an available version with --kernel"
            return 0 ;;
        *) return 1 ;;
    esac
}

# -- rootless fallback (Debian/Ubuntu): apt-get download + dpkg-deb -x. No sudo, no
# system apt-source changes -- a temporary source list + cache dir the current user
# already owns. Prints the extracted vmlinux path on success, nothing on failure.
# `dpkg-deb` was already probed as staged ("extract dbgsym vmlinux without root" in
# Build-OfflineToolkit-Linux.sh's manifest) but never actually wired to a real path
# until now. Unauthenticated (no ubuntu-dbgsym-keyring, which itself needs sudo to
# install) -- acceptable here: the package's DATA (debug symbols) is parsed by
# dwarf2json, never executed.
install_debug_pkg_rootless_debian() {
    local cn="$1"
    command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1 || return 1
    local tmp; tmp="$(mktemp -d)"
    { printf 'deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n' "$cn"
      printf 'deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\n' "$cn"
    } > "${tmp}/ddebs.list"
    mkdir -p "${tmp}/lists/partial" "${tmp}/archives/partial" "${tmp}/extract"
    local apt_opts=(-o "Dir::Etc::sourcelist=${tmp}/ddebs.list" -o "Dir::Etc::sourceparts=/dev/null"
                    -o "Dir::State::lists=${tmp}/lists" -o "Dir::Cache::Archives=${tmp}/archives"
                    -o "APT::Get::AllowUnauthenticated=true")
    local errlog="${tmp}/apt.err"
    log "debian/ubuntu: trying rootless download (apt-get download + dpkg-deb, no sudo)…"
    if ! apt-get "${apt_opts[@]}" update >"$errlog" 2>&1; then
        log "rootless index refresh failed: $(tail -3 "$errlog" | tr '\n' ' ')"
        rm -rf "$tmp"; return 1
    fi
    local want_pkg="linux-image-${KVER}-dbgsym" use_kver="$KVER"
    if ! ( cd "$tmp" && apt-get "${apt_opts[@]}" download "$want_pkg" >"$errlog" 2>&1 ); then
        local msg
        if ! msg="$(_symbols_pkg_not_published_msg "$(cat "$errlog")")"; then
            log "rootless download failed: $(tail -3 "$errlog" | tr '\n' ' ')"
            rm -rf "$tmp"; return 1
        fi
        if [[ $ALLOW_CLOSEST -ne 1 ]]; then
            log "$msg"
            rm -rf "$tmp"; return 2   # confirmed not published -- distinct from "other failure"
        fi
        # --allow-closest-symbols: search the SAME kernel series (major.minor.patch +
        # flavor, e.g. "6.17.0-*-generic") in the index apt-get update already fetched,
        # and use the highest available point-release instead. Struct layouts are
        # typically stable within a series; symbol ADDRESSES are not guaranteed to be --
        # this is a deliberate, LOGGED approximation, never a silent one.
        local series flavor pattern candidate
        if [[ "$KVER" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+-(.+)$ ]]; then
            series="${BASH_REMATCH[1]}"; flavor="${BASH_REMATCH[2]}"
            pattern="^Package: linux-image-${series}-[0-9]+-${flavor}-dbgsym\$"
            candidate="$(grep -Eho "$pattern" "${tmp}"/lists/*Packages* 2>/dev/null \
                        | sed 's/^Package: //' | sort -Vu | tail -1)"
        fi
        if [[ -z "${candidate:-}" ]]; then
            log "no --allow-closest-symbols candidate found for series ${KVER} in this archive either."
            rm -rf "$tmp"; return 2
        fi
        use_kver="$(echo "$candidate" | sed -E 's/^linux-image-(.+)-dbgsym$/\1/')"
        log "requested kernel ${KVER} has no published debug-symbols package; using CLOSEST"
        log "available instead: ${use_kver}. Symbol ADDRESSES may not exactly match the"
        log "analyzed kernel -- findings from symbol-address-dependent checks (syscall/"
        log "network-proto-handler hook detection, hidden-process pidhashtable compare) may"
        log "include false positives from this mismatch alone; corroborate independently"
        log "before treating any such finding as confirmed."
        want_pkg="$candidate"
        errlog="${tmp}/apt2.err"
        if ! ( cd "$tmp" && apt-get "${apt_opts[@]}" download "$want_pkg" >"$errlog" 2>&1 ); then
            log "closest-match download failed too: $(tail -3 "$errlog" | tr '\n' ' ')"
            rm -rf "$tmp"; return 1
        fi
    fi
    local ddeb; ddeb="$(ls "${tmp}"/linux-image-*-dbgsym*.*deb 2>/dev/null | head -1)"
    if [[ -z "$ddeb" ]]; then
        log "rootless download produced no package file."
        rm -rf "$tmp"; return 1
    fi
    if ! dpkg-deb -x "$ddeb" "${tmp}/extract" 2>"$errlog"; then
        log "dpkg-deb extraction failed: $(tail -3 "$errlog" | tr '\n' ' ')"
        rm -rf "$tmp"; return 1
    fi
    local vmlinux; vmlinux="$(find "${tmp}/extract" -type f \( -name "vmlinux-${use_kver}" -o -name vmlinux \) 2>/dev/null | head -1)"
    if [[ -z "$vmlinux" ]]; then
        log "rootless package extracted but no vmlinux found inside it."
        rm -rf "$tmp"; return 1
    fi
    # 2 lines always: vmlinux path, then the kernel version actually used (equals
    # $KVER unless --allow-closest-symbols substituted a different point-release).
    echo "$vmlinux"
    echo "$use_kver"
}

# -- distro package manager: install the kernel debug-symbol package. Prints a
# vmlinux path on stdout if the rootless path found one; otherwise returns 0/1 and
# the caller re-scans find_vmlinux() (the sudo-based system install lands the
# vmlinux at a standard path, no need to track it here). --
install_debug_pkg() {
    case "$FAMILY" in
        debian)
            local cn="${CODENAME:-$(command -v lsb_release >/dev/null 2>&1 && lsb_release -cs)}"
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[debian]: rootless apt-get download, else enable ddebs(${cn:-?}) + apt-get install linux-image-${KVER}-dbgsym"; return 1
            fi
            command -v apt-get >/dev/null 2>&1 || return 1
            [[ -z "$cn" ]] && { log "debian: cannot determine codename"; return 1; }
            local rootless rootless_rc=0
            rootless="$(install_debug_pkg_rootless_debian "$cn")" || rootless_rc=$?
            if [[ -n "$rootless" ]]; then
                echo "$rootless"; return 0
            fi
            if [[ $rootless_rc -eq 2 ]]; then
                # Confirmed not published (not a network/auth/repo issue) -- the sudo-based
                # system install would hit the exact same "not found" from the exact same
                # archive, so don't waste a sudo password prompt on a guaranteed failure.
                return 1
            fi
            log "debian/ubuntu: rootless path unavailable; falling back to system apt-get install (sudo)…"
            local errlog; errlog="$(mktemp)"
            { printf 'deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n' "$cn"
              printf 'deb http://ddebs.ubuntu.com %s-updates main restricted universe multiverse\n' "$cn"
            } | sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null
            sudo apt-get install -y ubuntu-dbgsym-keyring >"$errlog" 2>&1 || true
            sudo apt-get update >"$errlog" 2>&1 || log "apt-get update reported issues: $(tail -3 "$errlog" | tr '\n' ' ')"
            if ! sudo apt-get install -y "linux-image-${KVER}-dbgsym" >"$errlog" 2>&1; then
                local msg
                if msg="$(_symbols_pkg_not_published_msg "$(cat "$errlog")")"; then
                    log "$msg"
                else
                    log "apt-get install failed: $(tail -5 "$errlog" | tr '\n' ' ')"
                fi
                rm -f "$errlog"; return 1
            fi
            rm -f "$errlog"
            ;;
        rhel)
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[rhel]: dnf -y --enablerepo='*debug*' debuginfo-install kernel-${KVER}"; return 1
            fi
            local DNF; DNF="$(command -v dnf || command -v yum)" || return 1
            log "rhel/fedora: installing kernel-debuginfo-${KVER} (sudo)…"
            local errlog; errlog="$(mktemp)"
            if ! sudo "$DNF" -y --enablerepo='*debug*' debuginfo-install "kernel-${KVER}" >"$errlog" 2>&1 \
              && ! sudo "$DNF" -y --enablerepo='*debug*' install "kernel-debuginfo-${KVER}" >"$errlog" 2>&1; then
                local msg
                if msg="$(_symbols_pkg_not_published_msg "$(cat "$errlog")")"; then
                    log "$msg"
                else
                    log "dnf install failed: $(tail -5 "$errlog" | tr '\n' ' ')"
                fi
                rm -f "$errlog"; return 1
            fi
            rm -f "$errlog"
            ;;
        suse)
            if [[ "$PLAN" == "1" ]]; then
                log "PLAN[suse]: zypper -n install kernel-default-debuginfo (matching ${KVER})"; return 1
            fi
            command -v zypper >/dev/null 2>&1 || return 1
            log "suse: installing kernel-default-debuginfo (sudo)…"
            local errlog; errlog="$(mktemp)"
            if ! sudo zypper --non-interactive install -y kernel-default-debuginfo >"$errlog" 2>&1; then
                local msg
                if msg="$(_symbols_pkg_not_published_msg "$(cat "$errlog")")"; then
                    log "$msg"
                else
                    log "zypper install failed: $(tail -5 "$errlog" | tr '\n' ' ')"
                fi
                rm -f "$errlog"; return 1
            fi
            rm -f "$errlog"
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
        # install_debug_pkg prints a vmlinux path (+ the kernel version actually used,
        # on a 2nd line -- differs from $KVER only when --allow-closest-symbols
        # substituted a different point-release) when the rootless (no-sudo) extraction
        # succeeded; otherwise it returns 0/1 and a system install (if it happened)
        # lands the vmlinux at a standard path find_vmlinux() re-scans for. Command
        # substitution runs in a subshell, so this has to come back over stdout, not a
        # global variable assignment inside install_debug_pkg.
        _pkg_out="$(install_debug_pkg || true)"
        VMLINUX="$(sed -n '1p' <<<"$_pkg_out")"
        _pkg_kver="$(sed -n '2p' <<<"$_pkg_out")"
        if [[ -z "$VMLINUX" ]]; then
            VMLINUX="$(find_vmlinux || true)"
        elif [[ -n "$_pkg_kver" && "$_pkg_kver" != "$KVER" ]]; then
            ACTUAL_KVER="$_pkg_kver"
        fi
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
if [[ -n "$ACTUAL_KVER" ]]; then
    log "*** using CLOSEST-AVAILABLE kernel ${ACTUAL_KVER} in place of requested ${KVER} ***"
    log "*** ISF written as ${ACTUAL_KVER}.json, NOT ${KVER}.json, so a future exact-match"
    log "*** staged-symbols check for the real ${KVER} will correctly miss it (forcing a fresh"
    log "*** closest-match decision) instead of silently reusing this approximation as exact."
    log "*** Expect possible false positives from symbol-address-dependent findings (syscall/"
    log "*** proto-handler hook checks, hidden-process comparisons); corroborate independently."
fi

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
# Labeled by the kernel version ACTUALLY used, never the originally-requested one --
# a substituted closest-match ISF must never masquerade as an exact match for $KVER
# (that's exactly the silent-mislabeling bug class Analyze-Memory-Linux.sh's
# _resolve_staged_symbols() exact-filename check exists to catch). Volatility itself
# matches by the ISF's internal banner metadata, not filename, so this labeling only
# affects OUR OWN staged-symbols reuse/provenance bookkeeping, not the actual scan.
ISF="${OUT}/linux/${ACTUAL_KVER:-$KVER}.json"
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
